  <###################################################################################
Required information before executing:

    - NetBIOS name of domain with the trust you wish to create Domain Local groups for

Requirements:
    - A '<NetBIOS>/Enterprise Administrators/Administrative Groups' OU must exist.

Execution:
    5-Create-TrustDomainGroups.ps1 

If an error is encountered, the script will pause and ask for input.

This script will perform the following actions:

    - Asks for input of NetBIOS name of the domain with the trust.
    - Creates Domain Local groups based on the given input.
    - Creates delegations for ‘Configuration’ and ‘Public Key Services’ containers.

v1.0 Created by Theron Howton, MCS
    09/27/2018

Modified:
v1.1 - Theron Howton - 03/27/2019
    - Incorporated use of a CSV for group creation.
    - Added AD delegation code for 'Configuration' and 'Public Key Services' containers.

###################################################################################> 
param (
 [Parameter(Mandatory=$True)][string]$fqdn
)
    $ErrorActionPreference = "Inquire" 

# Global Variables
   
    $dInfo = Get-ADDomain
    $dn = $dInfo.distinguishedname
    $cn = "CN=Configuration,$dn"
    $pki = "CN=Public Key Services,CN=Services,$cn"
    $nbN = $dInfo.NetBIOSName
    $nbN = $nbN.ToUpper()

# Domain with trust to configure groups for
    $dom = Read-Host "Enter the NetBIOS name of the domain that has a trust with $nbN"
# Changes NetBIOS name to upper characters
    $uDom = $dom.toupper()

# OUs
    $domAdmin = "OU=Domain Administration,OU=$nbN,$dn"
    $adminAccts = "OU=Administrative Accounts,$domAdmin"
    $adminGrps = "OU=Administrative Groups,$domAdmin"
    $delRgtsGrps = "OU=Delegated Rights Groups,$adminGrps"

# Groups
    $csv = Get-Content .\_Input-Files\Trust-DomainGroups.csv
    $csv = $csv -replace "udom",$udom -replace "nbN",$nbN
    $csv | Out-File .\_Input-Files\New-Trust-DomainGroups.csv
    $newCSV = Import-Csv .\_Input-Files\New-Trust-DomainGroups.csv

###################################################################################
# Create AD Groups
Import-Module activedirectory

        Write-Host "***Create AD Groups***" -ForegroundColor Cyan
        Write-Host ""

        If (Get-ADOrganizationalUnit -Filter 'Name -eq "Administrative Groups"'){
                
                
                foreach ($line in $Newcsv) {
                    If ($line.path -eq "adminGrps"){
                        Try {New-ADGroup -Name $line.Name -GroupCategory Security -GroupScope $line.Type -Description $line.Description -Path "$adminGrps"
                               Write-Host ""$line.name" group created" -ForegroundColor Green
                             }
                        Catch{Write-Host ""$line.name" group already exists." -ForegroundColor Yellow
                        }
                     }
                    
                    If ($line.path -eq "delRgtsGrps"){
                        Try {New-ADGroup -Name $line.Name -GroupCategory Security -GroupScope $line.Type -Description $line.Description -Path "$delRgtsGrps"
                               Write-Host ""$line.name" group created" -ForegroundColor Green
                             }
                        Catch {Write-Host ""$line.name" group already exists." -ForegroundColor Yellow
                        }
                     }
                 }
              }

        Else {Write-Host "'Administrative Groups' OU does not exist. Creation of groups was not performed.." -ForegroundColor Red}

        Write-Host ""

###################################################################################
# Delegations

        Write-Host "***Configure AD Delegations***" -ForegroundColor Cyan
        Write-Host ""

   # Grants Domain Admin level rights to 'Configuration' container to $uDom-Admins-AD-ENG

      If($grp1 = Get-ADGroup -Filter 'name -like "*-Admins-AD-ENG"'){
            $securityDescriptor = Get-Acl ad:"$cn"
            $newSID = (get-adgroup -Identity "$grp1").sid
            $addSDDL = "(A;CIIO;CCLCSWRPWPLOCRSDRCWDWO;;;$newSID)"
            $s = ($securityDescriptor).sddl + $addSDDL
            $securityDescriptor.setSecurityDescriptorSddlForm($s)
            Set-Acl -Path ad:"$cn" -AclObject $securityDescriptor
            Write-Host "'Configuration' container delegated to" $grp1.name -ForegroundColor Green
        }
      Else {Write-Host $grp.name "does not exist." -for Red}


   # Grants Domain Admin level rights to 'Public Key Services' container to $uDom-Admins-PKI
   
      If($grp2 = Get-ADGroup -Filter 'name -like "*-Admins-PKI"'){
            $securityDescriptor = Get-Acl ad:"$pki"
            $newSID = (get-adgroup -Identity "$grp2").sid
            $addSDDL = "(A;CIIO;CCLCSWRPWPLOCRSDRCWDWO;;;$newSID)"
            $s = ($securityDescriptor).sddl + $addSDDL
            $securityDescriptor.setSecurityDescriptorSddlForm($s)
            Set-Acl -Path ad:"$pki" -AclObject $securityDescriptor
            Write-Host "'Public Key Services' container delegated to" $grp2.name -ForegroundColor Green
            
            Add-ADGroupMember -Identity "Cert Publishers" -Members $grp2        
        
        }
      Else {Write-Host $grp2.name "does not exist." -for Red}


    # DNS Admins
      If($grp3 = Get-ADGroup -Filter 'name -like "*-Admins-DNS"'){
            Add-ADGroupMember -Identity DnsAdmins -Members $grp3
        }


       