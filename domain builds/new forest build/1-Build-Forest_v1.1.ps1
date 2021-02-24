<###################################################################################
Required information before executing:
    New FOREST fully qualified domain name (FQDN).
    Desired location of the AD DB, logs, and SYSVOL.
        If they will not be located on C:\, 
            modify the "User modifiable variables" section 

Requirements:
    FBI custom Windows Server 2016 image version 1.03.20180410 or later.

Execution:
    1-Build-Forest.ps1 -fqdn <FQDN>

This will perform the following actions:
    - Checks to see if the machine is Server 2016, is standalone, and is built with the 
        'GENERIC' branded image, if not, script aborts.
    - Checks to see if AD DS role is installed, if not, it gets installed.
    - Creates a new forest, named based on the input of <FQDN>.
    - Server is rebooted when the configuration is complete.

Created by Theron Howton, MCS
    04/17/2018

Modified: 
v1.1  - Theron Howton  - 09/24/2018
    - Modified 'image' build check to use '\Software\FBI\' registry key vs. 'GENERIC' image value.

###################################################################################>

param (
 [Parameter(Mandatory=$True)][string]$fqdn
)

$ErrorActionPreference = "Stop"

# Global Variables

# Splits the FQDN at '.'
    $split = $fqdn.split('.')
# NetBIOS name of domain
    $netBios = $split[0]
# OS version and domain role
    $osVer = (gwmi win32_operatingsystem).version
    $dRole = (gwmi win32_computersystem).domainrole

###################################################################################
# User modifiable variables

# AD file locations
    $db = "C:\Windows\NTDS"
    $log = "c:\Windows\NTDS"
    $sysvol = "c:\Windows\SYSVOL"
# Image build 
    $image = Test-Path -Path "HKLM:\Software\FBI\"

###################################################################################

# Verify the correct image was used.
 
If ($image -eq $false) {
        Write-Host "This server is not branded correctly or is missing the appropriate FBI registry key and values. Verifiy it is approved for use." -ForegroundColor Red
        Write-Host "Rectify the issue and try again. No changes have been made by this script." -ForegroundColor Red
       }

Else {

# Check to see if AD DS role is installed, if not, install it.
# Then build forest.

    If ($osVer -like '10*' -and $dRole -eq '2'){
        If (!(Get-WindowsFeature AD-Domain-Services).installed){
            Install-WindowsFeature -Name AD-Domain-Services
       }
        If (!(Get-WindowsFeature RSAT-ADDS).installed){
            Install-WindowsFeature -Name RSAT-ADDS
       }

# Configure new forest AD DS and reboot server.

    Import-Module ADDSDeployment
    Install-ADDSForest `
        -CreateDnsDelegation:$false `
        -DatabasePath $db `
        -DomainMode "WinThreshold" `
        -DomainName "$fqdn" `
        -DomainNetbiosName "$netBIOS" `
        -ForestMode "WinThreshold" `
        -InstallDns:$true `
        -LogPath $log `
        -NoRebootOnCompletion:$false `
        -SysvolPath $sysvol `
        -Force:$true

}

    Else {
        Write-Host "This is not Windows Server 2016 or above, or is not a stand-alone server" -ForegroundColor Red
        Write-Host "The script has stopped." -ForegroundColor Red
       }
}