########################################################################################################################################
# Set Network MTU Setting
# Created by James Hinders and David Brinton, ITID, 03/27/15
# The purpose of this script is to set the MTU setting of a system by checking for the existance of a reg key, if it exists set it to 
#   the value in the reg key, otherwise set it to the enterprise standard of 1372
# The script also changes the Power Saving feature of the NIC OFF (if it exists)
########################################################################################################################################
# Global Variables
########################################################################################################################################
$ScriptVer = "1.0"
$ScriptName = "Set Network MTU Setting Script"
$LogName = "FBI Logs"
$OSVersion = (Get-WMIObject Win32_OperatingSystem).Version
$OSVersion = ($OSVersion.Split(".")[0]) + "." + ($OSVersion.Split(".")[1]) # Get OS Version and change it to a decimal for version comparison
$PSVersion = $PSVersionTable.PSVersion #Get Powershell version
$DefaultMTU = "1372"

#################################################################################################################################
# Ensure that OS Version is Windows and greater than Vista or Exit
# Ensure that PowerShell Version is greater than 3.0 or Exit
#################################################################################################################################
if ([decimal]$OSVersion -lt 6) {
    Write-EventLog -LogName $LogName -Source "EnterpriseManagement" -EntryType Error -EventId 3101 -Message "Windows Vista or higher not detected, exiting `n$ScriptName $ScriptVer" 
    Exit
}
if ($PSVersion.Major -lt 3) {
    Write-EventLog -LogName $LogName -Source "EnterpriseManagement" -EntryType Error -EventId 3101 -Message "PowerShell v3 or higher not detected, exiting `n$ScriptName $ScriptVer"
    Exit
}

######### Check for Event Log and Sources, create if not found
$logFileExists = Get-EventLog -list | Where-Object {$_.logdisplayname -eq $LogName} 
if (! $logFileExists) {
    New-EventLog -LogName $LogName -Source EnterpriseManagement,TrackLogonDuration,TimeAppDuration,DesktopImaging,ProblemManagement,GenericSource
    Limit-EventLog -LogName $LogName -MaximumSize 1024kb -OverFlowAction OverwriteAsNeeded
    Write-EventLog -LogName $LogName -Source EnterpriseManagement -EventId 9000 -entrytype Information -message "FBI Logs Created, All Sources Created - $ScriptName $ScriptVer"
}

if ([System.Diagnostics.EventLog]::SourceExists("EnterpriseManagement") -eq $false) {
    [System.Diagnostics.EventLog]::CreateEventSource("EnterpriseManagement", $LogName)
    Write-EventLog -LogName $LogName -Source EnterpriseManagement -EventId 9001 -entrytype Information -message "EnterpriseManagement Source Created - $ScriptName $ScriptVer"
}

######### Get Domain, if no supported domain found, exit script
$Path = $Null
$DomainName = (Get-WMIObject Win32_ComputerSystem).Domain
Switch ($DomainName)
{
"fbinet.fbi" {$Path = "HKLM:\SOFTWARE\FBINET"}
"FBI.GOV" {$Path = "HKLM:\SOFTWARE\UNET"}
"scinet.fbi.ic.gov" {$Path = "HKLM:\SOFTWARE\SCINET"}
"wan.tnc" {$Path = "HKLM:\SOFTWARE\BLACKNET"}
}

If ($Path -eq $Null) {
    Write-EventLog -LogName $LogName -Source "EnterpriseManagement" -EntryType Information -EventId 4636 -Message "Standard Domain not detected, exiting script `n$ScriptName $ScriptVer"
    Exit
}

######### Get MTU setting from registry
$MTUSize = $Null
$CheckRegPath = Test-Path $Path
if ($CheckRegPath -eq $True) {
    $FBIMTU = Get-ItemProperty $Path
    $MTUSize = $FBIMTU.FBIMTU
}
if ($CheckRegPath -eq $False -or $MTUSize -eq $Null) {
    $MTUSize = $DefaultMTU
}

######## Sets Property of a regkey and logs item to event log
Function SetProperty([string]$Path, [string]$Key, [string]$Value) {
    $OldValue = (Get-ItemProperty -path $Path).$key
    Set-ItemProperty -path $Path -name $Key -Type DWORD -Value $Value
    $NewValue = (Get-ItemProperty -path $Path).$key
    Write-EventLog -LogName $LogName -Source "EnterpriseManagement" -EntryType Information -EventId 4635 -Message "Value for $Path\$Key changed from $OldValue to $NewValue `n$ScriptName $ScriptVer"
    $data = "$path\$key=$oldValue" 
    #Add-Content $LogName $data
    #Write-Output "Value for $path\$key changed from $oldValue to $newValue"
}


#Interfaces\<adapter ID>\MTU -> 1450-1500, test for maximum value that will pass on each interface using PING -f -l <MTU Size> <Interface Gateway Address>, pick the value that works across all interfaces
$RegistryEntries = Get-ItemProperty -path "HKLM:\system\currentcontrolset\services\tcpip\parameters\interfaces\*"
ForEach ( $iface in $RegistryEntries ) { 
    $IP = $iface.DhcpIpAddress
    if ( $ip -ne $null ) { $childName = $iface.PSChildName}
    else {
        $IP = $iface.IPAddress
        if ($IP -ne $null) { $childName = $iface.PSChildName }
    }
    $Interface = Get-ItemProperty -path "HKLM:\system\currentcontrolset\services\tcpip\parameters\interfaces\$childName"
    $Path = $Interface.PSPath
    $Temp = (Get-ItemProperty -Path $Path -Name MTU).MTU
    If ($Temp -ne $MTUSize) {
        SetProperty $Path MTU $MTUSize
    }
}

$Keys = Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}" -ErrorAction SilentlyContinue
ForEach($Key in $Keys) {
    $Temp2 = (Get-ItemProperty $Key.PSPath -Name NetCfgInstanceID).NetCfgInstanceID
    If ($Temp2 -eq $childName) {
        If (Get-ItemProperty $key.PSPath -Name PnPCapabilities -ErrorAction SilentlyContinue ){
            $Temp3 = (Get-ItemProperty $key.PSPath -Name PnPCapabilities -ErrorAction SilentlyContinue ).PnPCapabilities
            If ($Temp3 -ne 280) {
                SetProperty $key.pspath PNPCapabilities 280
            }
        }
        Else {Write-EventLog -LogName $LogName -Source "EnterpriseManagement" -EntryType Warning -EventId 4635 -Message "NIC PnP Capabilities not found `n$Key`n$ScriptName $ScriptVer"}
    }
}    