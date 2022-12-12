<#
.SYNOPSIS
    Fix Windows Update in Co-managed environment.

.DESCRIPTION
    This script is for use as Remediation script via Intune "Proactive Remediation"
    Looks for WSUS configuration on a device, exits with "issue".
    Fix or remediate scrtips will enable Automatic Updates, wipe clean WSUS configuration.

    Based primarly on code from Ben Whitmore | MVP (@byteben) and Andrew Johnson (@AndrewJNet)
    Blogs: 
        https://byteben.com/bb/using-memcm-to-fix-legacy-gpo-settings-that-prevent-co-managed-clients-getting-updates-from-intune/
        https://www.andrewj.net/blog/troubleshooting-wufb-workload/
    Code:
        https://github.com/byteben/Windows-10/blob/master/Detect_EnableAutomaticUpdates.ps1

    


.NOTES
    
    Based primarly on code from Ben Whitmore | MVP (@byteben) and Andrew Johnson (@AndrewJNet)
    Blogs: 
        https://byteben.com/bb/using-memcm-to-fix-legacy-gpo-settings-that-prevent-co-managed-clients-getting-updates-from-intune/
        https://www.andrewj.net/blog/troubleshooting-wufb-workload/
    Code:
        https://github.com/byteben/Windows-10/blob/master/Detect_EnableAutomaticUpdates.ps1
    
    
    Main modifications:
        - Double check on Windows Update configration.
        - Detection script summary for additional info on Agentexecutor Log and PR console.

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
$message = ""
$detectSummary = ""

#New lines, easier to find and read in Agentexecutor Log file.
Write-Host "`n`n"


#Endregion Initialize

#region Functions

Function Test-IsAdmin {

    $fReturn = @{
        isAdmin = $false
        summary = ""
    }


    If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {

        # Does not have Admin privileges
        $message = "Script needs to run with Administrative privileges. "
        $fReturn.summary = "WARNING : $message"
        Write-Warning $message

    }
    else {

        #Has Admin rights
        $fReturn.isAdmin = $true
        $message = "OK: Adminitrator rights have been confirmed. "
        $fReturn.summary = $message
        Write-Host $message
    
    }

    Return $fReturn
    
}

Function Update-RegKeyIfExistToValue {
    param (
        [Parameter(Mandatory)]
        [Object]$regNames,
        [Parameter(Mandatory)]
        [Object]$regType,
        [Parameter(Mandatory)]
        $regValue
    )

    foreach ($regName in $regNames) {
    
        $regPath = $regName | Split-Path -Parent
        $regProperty = $regName | Split-Path -Leaf
        $regExists = (Get-ItemProperty -LiteralPath $regPath).PSObject.Properties.Name -contains $regProperty

        if (!$regExists) {

            #If not found, notify, move on.
            $message = "Property ""$regProperty"" not found. "
            $summary += $message
            
            Write-Host $message

        }
        else {

            #If found, change value to $regValue

            # Before modifying get info of current value 
            $regCurrentValue = Get-ItemPropertyValue -LiteralPath $regPath -Name $regProperty

            try {

                Set-ItemProperty -Path $regPath -Name $regProperty -Type $regType -Value $regValue -Force -ErrorAction Stop
                
                $message = "Found ""$regProperty"", updated from $regCurrentValue to $regValue. "
                
            }
            catch {
            
                $message = "ERROR: Found ""$regProperty"" with value $regCurrentValue, but unable to update . "
                
            }

            # Update status on terminal
            Write-Host $message
            
            # Add message as part of the Proactive remediation summary. Output is not readable in PR console.
            $summary += $message

        }

    }

    Return $summary
    
}

function Find-AUupdates {
    param ()

    $objAU = New-Object -ComObject Microsoft.Update.AutoUpdate
    try {
    
        # Detect any available updates
        $objAU.DetectNow()  
        
        $message = "Successfully executed Automatic Updates detection. "
        Write-Host $message
    
    }
    catch {
    
        $message = "WARNING: Error while trying to search for updates. "
        Write-Host $message
    
    }

    Return $message
    
}

#EndRegion Functions

#Region Main

$adminRole = Test-IsAdmin
if (!($adminRole.isAdmin)) {
    $detectSummary = $adminRole.summary
}
else {

    $auPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    $wuPath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"

    $regProperties = @(
        "$wuPath\DoNotConnectToWindowsUpdateInternetLocations",
        "$wuPath\DisableDualScan",
        "$wuPath\SetPolicyDrivenUpdateSourceForDriverUpdates",
        "$wuPath\SetPolicyDrivenUpdateSourceForOtherUpdates",
        "$wuPath\SetPolicyDrivenUpdateSourceForQualityUpdates",
        "$wuPath\DisableWindowsUpdateAccess",
        "$auPath\NoAutoUpdate"
    )
    $regPropertyType = "DWORD"
    $regPropertyValue = 0

    #Set all Registry properties if they exist
    $detectSummary = Update-RegKeyIfExistToValue $regProperties $regPropertyType $regPropertyValue

    #Check for updates
    $detectSummary += Find-AUupdates

}

#New lines, easier to find and read Agentexecutor Log file.
Write-Host "`n`n"

# Add info about AU detection to summary
Write-Host "$([datetime]::Now) : $detectSummary"


#Endregion Main