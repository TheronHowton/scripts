  <###################################################################################
Required information before executing:

    - FQDN of domain with the trust you wish to create Domain Local groups for

Requirements:
    - This must be executed in the 'Trusted' domain'.

Execution:
    6-Create-TrustedDomainGlobalGroups.ps1 <fqdn>

If an error is encountered, the script will pause and ask for input.

This script will perform the following actions:

    - Asks for FQDN of the 'Trusting' domain.
    - Prompts for credentials of a 'Trusting' domain administrator.
    - Creates OUs if needed. 
    - Creates domain security groups based on the input files.
    - Nests the created groups into coorsponding groups in the 'Trusting domain.
    
v1.0 Created by Theron Howton, MCS and Kevin Crowe, ECS
    02/06/2020

Modified:
v1.1 - Name - Date
    - Description of changes.

###################################################################################> 
param (
 [Parameter(Mandatory=$True)][string]$fqdn
)
    $ErrorActionPreference = "Inquire" 

# Global Variables
   
    $dInfo = Get-ADDomain
    $dn = $dInfo.distinguishedname
    $nbN = $dInfo.NetBIOSName
    $nbN = $nbN.ToUpper()
    If($nbN -eq "FBI"){$nbN = "UNET"}
    $dc = (Get-ADDomainController -DomainName $fqdn -Discover).Name

# Domain with trust to configure groups for
    $dom = Read-Host "Enter the FQDN name of the domain that has a trust with $nbN"
    $cred = Get-Credential
    $TDInfo = Get-ADDomain $dom
    $TDdn = $TDInfo.distinguishedname
    $TDnbN = $TDInfo.NetBIOSName
    $TDnbN = $TDnbN.ToUpper()
    $uDom = $TDnbN
    $TDdc = (Get-ADDomainController -DomainName $dom -Discover).Name
    
# OUs
    $domAdminOU = "OU=Domain Administration,OU=$udom,OU=TrustedForests,OU=_Domain Groups,OU=$nbN,$dn"
    $delRgtsGrps = "OU=Delegated Rights Groups,OU=$uDom,OU=TrustedForests,OU=_Domain Groups,OU=$nbN,$dn"

# Groups
    $csv = Get-Content .\_Input-Files\Trust-GlobalGroups.csv
    $csv = $csv -replace "udom",$udom
    $csv | Out-File .\_Input-Files\New-Trust-GlobalGroups.csv
    $newCSV = Import-Csv .\_Input-Files\New-Trust-GlobalGroups.csv

    $ouCSV = Get-Content .\_Input-Files\OUs-TrustedForest.csv
    $ouCSV = $ouCSV -replace "Trusted-nbn",$uDom
    $ouCSV | Out-File .\_Input-Files\New-OUs-TrustedForest.csv


    $newouCSV = Import-Csv .\_Input-Files\New-OUs-TrustedForest.csv

Import-Module ActiveDirectory

###################################################################################
# Configure OU structure based on input file.

Write-Host "Creating OU structure..." -ForegroundColor Gray

ForEach ($OU in $newouCSV) {
                  $ouPath = "OU=$nbN,$dn"
                  $allOU = ''
                  $ous = (Split-Path $OU.OUs -Parent).Split('\')
                  [array]::Reverse($ous)
                  $ous | Foreach-Object {
                    if ($_.Length -eq 0) {
                      return
                    }
                    $allOU = $allOU + 'OU=' + $_ + ','
                  }
                  $allOU += $ouPath
                  $newOU = Split-Path $OU.OUs -Leaf
                  $newOUdn = "OU=$newOU,"
                  $newOUdn += $allOU
                  $ouI = $null
                  Try{$ouI = Get-ADOrganizationalUnit "$newOUdn" -Server $dc}
                  Catch{}
                 
                  If((!$ouI)){
                        New-ADOrganizationalUnit -Name "$newOU" -Path "$allOU" -ProtectedFromAccidentalDeletion $false -Server $dc -PassThru -ErrorAction SilentlyContinue | Out-Null
                        Write-Host "'$newOUdn' created." -ForegroundColor Green}
                  Else{Write-Host "'$newOUdn' already exists. No action taken." -ForegroundColor Gray
                        Write-Host ""}
                                
               }
Write-Host ""

###################################################################################
# Create AD Groups

Write-Host "***Create AD Groups***" -ForegroundColor Cyan
Write-Host ""

If (Get-ADOrganizationalUnit $domAdminOU){
                               
                foreach ($line in $Newcsv) {                  
                    If ($line.path -eq "domAdmin"){
                        Try {New-ADGroup -Name $line.Name -GroupCategory Security -GroupScope $line.Type -Description $line.Description -Path "$domAdminOU" -Server $dc
                               Write-Host ""$line.name" group created" -ForegroundColor Green
                               Write-Host ""
                              }
                        
                        Catch {Write-Host ""$line.name" group already exists." -ForegroundColor Yellow
                                }
                             
                        If($trustedGrp = (Get-ADGroup -Identity $line.name).Name){
                             $trustedGrp = $trustedGrp -replace "$udom", "$nbN"
                             $trustingGrp = Get-ADGroup -Identity $trustedGrp -Server $TDdc +"."+ $dom -Credential $cred
                             
                             Try{Add-ADGroupMember -Identity $trustingGrp -Members $trustedGrp -Server $TDdc +"."+ $fdom -Credential $cred
                                    Write-Host ""$line.name" was nested in $trustingGrp." -ForegroundColor Green
                                    Write-Host "" }
                             
                             Catch{Write-Host ""$line.name" was not nested in $trustingGrp." -ForegroundColor Cyan
                                    Write-Host ""}
                             
                             }
                        }
                        
                     
                 }
              }

Else {Write-Host "'Domain Administration' OU does not exist. Creation of groups was not performed.." -ForegroundColor Red}

If (Get-ADOrganizationalUnit $delRgtsGrps){
                
                foreach ($line in $Newcsv) {                   
                    If ($line.path -eq "delRgtsGrps"){
                        Try {New-ADGroup -Name $line.Name -GroupCategory Security -GroupScope $line.Type -Description $line.Description -Path "$delRgtsGrps" -Server $dc
                               Write-Host ""$line.name" group created" -ForegroundColor Green
                             Write-Host ""
                              }
                        
                        Catch {Write-Host ""$line.name" group already exists." -ForegroundColor Yellow
                                }
                             
                        If($trustedGrp = (Get-ADGroup -Identity $line.name).Name){
                             $trustedGrp = $trustedGrp -replace "$udom", "$nbN"
                             $trustingGrp = Get-ADGroup -Identity $trustedGrp -Server $TDdc +"."+ $dom -Credential $cred
                             
                             Try{Add-ADGroupMember -Identity $trustingGrp -Members $trustedGrp -Server $TDdc +"."+ $dom -Credential $cred
                                    Write-Host ""$line.name" was nested in $trustingGrp." -ForegroundColor Green
                                    Write-Host "" }
                             
                             Catch{Write-Host ""$line.name" was not nested in $trustingGrp." -ForegroundColor Cyan
                                    Write-Host ""}
                             
                             }
                        }
                        
                     
                 }
              }

Else {Write-Host "'Delegated Rights Groups' OU does not exist. Creation of groups was not performed.." -ForegroundColor Red}

Write-Host ""

  