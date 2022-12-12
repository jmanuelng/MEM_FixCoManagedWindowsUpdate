<#
.SYNOPSIS
    Fix Windows Update in Co-managed environment.

.DESCRIPTION
    For use as Detection script via Intune "Proactive Remediation"
    Looks for Automatic Updates (AU) configuration on a device, if Value "NoAutoUpdates = 1" exits with "issue".
    Fix or remediate script will enable Automatic Updates, wipe clean WSUS configuration if it.

    Based primarly on code from Ben Whitmore (w:@byteben) and Andrew Johnson (tw:@AndrewJNet)
    Blogs: 
        https://byteben.com/bb/using-memcm-to-fix-legacy-gpo-settings-that-prevent-co-managed-clients-getting-updates-from-intune/
        https://www.andrewj.net/blog/troubleshooting-wufb-workload/
    Code:
        https://github.com/byteben/Windows-10/blob/master/Detect_EnableAutomaticUpdates.ps1

    


.NOTES
    
    Based primarly on code from Ben Whitmore (tw:@byteben) and Andrew Johnson (tw:@AndrewJNet)
    Blogs: 
        https://byteben.com/bb/using-memcm-to-fix-legacy-gpo-settings-that-prevent-co-managed-clients-getting-updates-from-intune/
        https://www.andrewj.net/blog/troubleshooting-wufb-workload/
    Code:
        https://github.com/byteben/Windows-10/blob/master/Detect_EnableAutomaticUpdates.ps1
    
    
    Main modifications:
        - Detection script summary for additional info on Agentexecutor Log and PR dashboard.

    Other consulted sources:    
    https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/co-management-of-windows-updates-workloads/ba-p/922378
    https://www.cloud-boy.be/portfolio/windows-updates-not-installing/
    https://p0w3rsh3ll.wordpress.com/2013/01/09/get-windows-update-client-configuration/
    https://oceanleaf.ch/windows-update-for-business-reports-former-update-compliance/

    Still trying to decide on removing, or not the following Registry Keys,
    as per suggested in Tim Hermie's (tw:@_Cloud_boy) blog.
    https://www.cloud-boy.be/portfolio/windows-updates-not-installing/

    That's why I'm gathering info on existing, or not, WU Registry properties.
    
#>

#Region Initialize

$error.Clear()
$result = 0
$message = ""
$detectSummary = ""
$psV = $PSVersionTable.PSVersion
$psVer = "$($psV.Major).$($psV.Minor).$($psV.Build).$($psV.Revision)"

#New lines, easier to read Agentexecutor Log file.
Write-Host "`n`n"

#Endregion Initialize

#Region Functions

Function Test-RegKeyIfExistWithValue {
    param (
        [Parameter(Mandatory)]
        [Object]$regNames,
        [Parameter(Mandatory)]
        $regValue
    )

    $message = ""
    $fReturn = @{
        keyHasValue = $false
        summary = ""
    }

    foreach ($regName in $regNames) {
    
        $regPath = $regName | Split-Path -Parent
        $regProperty = $regName | Split-Path -Leaf
        $regExists = (Get-ItemProperty -LiteralPath $regPath -ErrorAction SilentlyContinue).PSObject.Properties.Name -contains $regProperty

        if (!$regExists) {

            # Didn't find it, next!.
            $message = "Property ""$regProperty"" not found. "
            $fReturn.summary += $message
            
            Write-Host $message

        }
        else {

            # Found! verify/compare value to $regValue

            # Before modifying get info of current value 
            $regCurrentValue = Get-ItemPropertyValue -LiteralPath $regPath -Name $regProperty -ErrorAction SilentlyContinue

            $message = "Found ""$regProperty"" = $regCurrentValue. "

            if ($regCurrentValue -eq $regValue) {
                $fReturn.keyHasValue = $true
            }

            # Update status on terminal
            Write-Host $message
            
            # Add message as part of the Proactive remediation summary. Output is not readable in PR console.
            $fReturn.summary += $message

        }

    }

    Return $fReturn
    
}

#Endregion Functions

#Region Main

$auPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
$wuPath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"

$verifyNames = @(
    "$auPath\NoAutoUpdate",
    "$wuPath\DisableDualScan"
)
$verifyValue = 1


$wuProperties = @(
    "$wuPath\DoNotConnectToWindowsUpdateInternetLocations",
    "$wuPath\SetPolicyDrivenUpdateSourceForDriverUpdates",
    "$wuPath\SetPolicyDrivenUpdateSourceForOtherUpdates",
    "$wuPath\SetPolicyDrivenUpdateSourceForQualityUpdates",
    "$wuPath\DisableWindowsUpdateAccess",
    "$wuPath\WUServer",
    "$wuPath\TargetGroup",
    "$wuPath\WUStatusServer",
    "$wuPath\TargetGroupEnable",
    "$auPath\UseWUServer"
)
$wuValue = 9 #just a random number, only interested in documenting current values.

# Verify if NoAutoUpdate = 1. Not good if it is.
$testAuResult = Test-RegKeyIfExistWithValue $verifyNames $verifyValue
$result = $testAuResult.keyHasValue
$detectSummary += $testAuResult.summary

# Since we are already here, lets audit some Windows Update Registry keys.
$testWuResult = Test-RegKeyIfExistWithValue $wuProperties $wuValue
$detectSummary += $testWuResult.summary

#Add PSVersion details
$detectSummary += "PS Ver.= $psVer. "


#New lines, easier to read Agentexecutor Log file.
Write-Host "`n`n"

#Return result
if ($result) {

    Write-Host "WARNING $([datetime]::Now) : $detectSummary"
    Exit 1
}
else {
    Write-Host "OK $([datetime]::Now) : $detectSummary"
    Exit 0
}

#Endregion Main