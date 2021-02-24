<###################################################################################
Required information before executing:
    - FQDN of the domain you wish to add a DC to.
    - AD Site that DC will reside in.
    - Desired location of the AD DB, logs, and SYSVOL.
        If they will not be located on C:\, 
            modify the "AD Files Location" section 

Requirements:
    - FBI custom Windows Server 2016 image version 1.03.20180410 or later.
    - This server must be a member of the <FQDN> domain prior to executing this script.

Execution:
    2-Build-Add_DC.ps1 -fqdn <FQDN> -adsite <ADSite>

If an error is encountered, the script will stop.

This will perform the following actions:
    - Checks to see if the machine is Server 2016, is a domain member, and is built with the 'GENERIC' image, if not, script aborts.
    - Checks to see if DFS role is installed, if not, it gets installed.
    - Configures the server as a DFS-Namespace server for 'Public'.
    - Checks to see if AD DS role is installed, if not, it gets installed.
    - Promotes the server to a DC in the domain based on the input of <FQDN>.
    - Server is rebooted when the configuration is complete.

v1.0 Created by Theron Howton, MCS
    04/17/2018

Modified: 
v1.1 - Theron Howton - 09/24/2018 
    - Modified 'image' build check to use '\Software\FBI\' registry key vs. 'GENERIC' image value.

###################################################################################>

param (
 [Parameter(Mandatory=$True)][string]$fqdn,
 [Parameter(Mandatory=$True)][string]$adSite
)


$ErrorActionPreference = "Stop"

# Global Variables

# Domain Information
    $dName = $env:USERDNSDOMAIN
# OS Version and domain role
    $osVer = (gwmi win32_operatingsystem).version
    $dRole = (gwmi win32_computersystem).domainrole
# Local computer name
    $cName = $env:COMPUTERNAME

###################################################################################
# User modifiable variables

# AD file locations
    $db = "C:\Windows\NTDS"
    $log = "c:\Windows\NTDS"
    $sysvol = "c:\Windows\SYSVOL"
# DFS roots folder for DFS-Namespaces
    $dfsRoots = "c:\DFSRoots"
# DFS-Namespaces
    $public = "$dfsRoots\Public"
# Image build 
    $image = Test-Path -Path "HKLM:\Software\FBI\"

###################################################################################
# Domain Name and AD Site check

If (!($fqdn -eq $dname)){
    Write-host "The FQDN you entered does not match the FQDN of the domain in which this server is a member of. Please check your input and try again." -ForegroundColor Red
    Break
}
Else {}


If (!(Get-WindowsFeature -Name RSAT-AD-PowerShell).InstallState -eq 'Installed'){

    Add-WindowsFeature -Name RSAT-AD-PowerShell
    }
Else {}

Try {Get-ADReplicationSite -Identity $adSite}
Catch {Write-Host "The AD Site you entered does not exist. Please check your input and try again." -ForegroundColor Red
        Break
 }


###################################################################################


# Verify the correct image was used.
 
If ($image -eq $false) {
        Write-Host "This server is not branded correctly or is missing the appropriate registry values. Verifiy it is approved for use." -ForegroundColor Red
        Write-Host "Rectify the issue and try again. No changes have been made by this script." -ForegroundColor Red
        Break     
       }

Else {}


###################################################################################

# Check to see server is 2016 and a member of the intended domain.

If ($osVer -like '10*' -and $dRole -eq '3'){
            If (!(Get-WindowsFeature AD-Domain-Services).installed){
                Install-WindowsFeature -Name AD-Domain-Services
           }
            If (!(Get-WindowsFeature RSAT-ADDS).installed){
                Install-WindowsFeature -Name RSAT-ADDS
           }


   # Confiugure new DC and reboot server.
        Import-Module ADDSDeployment
        Install-ADDSDomainController `
            -NoGlobalCatalog:$false `
            -CreateDnsDelegation:$false `
            -CriticalReplicationOnly:$true `
            -DatabasePath $db `
            -DomainName "$fqdn" `
            -InstallDns:$true `
            -LogPath $logs `
            -NoRebootOnCompletion:$true `
            -SiteName $adSite `
            -SysvolPath $sysvol `
            -Force:$true

# Configure 'Pubic' DFS-Namespace

        Write-Host "Configuring DFS-Namespaces." -ForegroundColor Green

        If (!(Get-WindowsFeature FS-DFS-Namespace).installed){
                    Install-WindowsFeature -Name FS-DFS-Namespace -IncludeManagementTools
        }

        If (!(Test-Path -Path "$dfsRoots")){
            New-Item -Path "$dfsRoots" -ItemType "Directory"
            New-Item -Path "$public" -ItemType "Directory"
            New-SmbShare -Path "$public" -ReadAccess Everyone -Name Public
            Set-DfsnServerConfiguration -ComputerName $cName -UseFqdn $true
            Restart-Service dfs            
            New-DfsnRootTarget -Path \\$fqdn\Public -TargetPath \\$cname\Public -ErrorAction Ignore
        }

        Else {Write-Host "The $dfsRoots folder already exists. Make sure this server wasn't previously provisioned for DFS Namespaces." -ForegroundColor Red}

shutdown -r -t 15
    
    }

Else {
Write-Host ""
    Write-Host "This is not Windows Server 2016 or above, or is not a domain member of '$fqdn'. " -ForegroundColor Red
Write-Host ""
    Write-Host "The script has stopped, and no changes have been made." -ForegroundColor Red
Write-Host ""

}