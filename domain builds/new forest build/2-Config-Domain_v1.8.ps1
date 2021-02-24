<######################/############################################################
Required information before executing:

    - FQDN of domain being configured.
    - IP subnets of any DNS reverse zones to be optionally created.
    - IP addresses of any DNS forwarders to be optionally created.
    - Names of any additional AD sites to be optionally created.
    - IP subnets of AD subnets to be optionally created.
    - OUs.txt located in the same directory this script is executed from.
    - The following directories located in the root of the same directory this script is executed from.
        - AdmPwd.ps
        - ADMX
        - GPOs

Execution:
    2-Config-Domain.ps1 -fqdn <FQDN>

If an error is encountered, the script will pause and ask for input.

This script will perform the following actions:

    - Checks to see if the <FQDN> input matches the domain.
    - Checks to see if a break-glass DA account exists.
        - Option to reset its password, if it does.
        - Otherwise, creates the account and prompts for a password.
    - Option to configure DNS reverse zone lookup.
    - Option to configure DNS forwarders.
    - Create and configure AD sites, site links, and AD subnets. 
        - Option to create additional AD sites.
    - Configures DNS server scavenging.
    - Configures OU structure based on .\OUs.txt input file.
    - Moves break-glass DA account to appropriate OU.
    - Configures 'Public' DFS-Namespace.
    - Creates and populates the Central Store.
    - Creates AD groups.
    - Enables the use of MSA/gMSAs.
    - Configures AD for LAPS.
    - Redirects Users and Computers containers to OUs.
    - Creates and imports and GPOs in the .\GPOs directory.
    - Links GPOs to specific OUs.
    - Renames 'FBI Domain Policy' to '<NETBIOSNAME> Domain Policy'.
    - Links WMI filters.
    - Configures domain to use 'Lastname, Firstname Initial' in the DisplayName field.

v1.0 Created by Theron Howton, MCS
    04/17/2018

Modified:
v1.1 - Theron Howton - 09/10/2018 
    - Removed the 'description' field for newly created AD sites.
    - Added a checks in the AD Sites section, to prevent error reports.
    - Added GPO links for IE11 policies to the DCs OU.

v1.2 - Theron Howton - 09/21/2018
    - Modified the code which imports GPOs and removed hardcoded folder paths.
    - Added Get-GPLink function - (Credit to Thomas Bouchereau for the code)
    - Added user's initial to the DisplayName field.
    - Added WMI filter import and setting for GPOs.
    - Added prompt for enabling 'Change Notifications' on AD site links.

v1.3 - Theron Howton - 10/22/2018
    - Modified RSA No Challenge groups.
        - Made them Domain Local and nested Domain Users in each.

v1.4 - Theron Howton - 10/31/2018
    - Added steps to add executing user account to Schema Admins to ensure LAPS configuration will succeed.
        - Account is removed after LAPS is configured.
    - Added section to enable AD Recycle Bin.

v1.5 - Theron Howton - 02/28/2019
    - Modified OUs.txt file used to create OU structure.
        - Added "_Archive", "Computers-Orphaned", "Enterprise Administrators\Administrative Groups\Delegaated Rights Groups"

v1.6 - Theron Howton - 09/18/2019
    - Minor changes to DFS-Namespace and Central Store creation code.

v1.7 - Theron Howton - 11/19/2019
    - Added support for Server 2019 GPO import and linking.

v1.8 - Theron Howton - 02/05/2020
    - Added logic for creating !ADMX-Versions.txt file in the Central Store local location ($csLoc).
    - Added logic to change the name of 'FBI Domain Policy' to '<NETBIOSNAME> Domain Policy'.

###################################################################################>
param (
 [Parameter(Mandatory=$True)][string]$fqdn
)
$ErrorActionPreference = "Inquire"

###################################################################################
# User modifiable variables

# DFS roots folder for DFS-Namespaces
    $dfsRoots = "c:\DFSRoots"
# DFS-Namespaces
    $public = "$dfsRoots\Public"
# Break-glass Admin account password
    $bgPwd = ConvertTo-SecureString "Br3@kGl@ssAdm1n" -AsPlainText -Force


###################################################################################
# Global Variables
    
    $date = Get-Date -Format "MM/dd/yyyy"
    
# Local computer name
    $cName = $env:COMPUTERNAME
# Splits local computer name at '-'    
    $split = $cName.split('-')
# Used to rename Default-First-Site-Name
    $fADSite = $split[0]
# Domain Information
    $dInfo = Get-ADDomain
    $dName = $dInfo.dnsroot
    $pdcE = $dInfo.pdcemulator
    $dn = $dInfo.distinguishedname
    $nbN = $dInfo.NetBIOSName
# Current User Information
    $cUsr = $env:USERNAME
    $usr = (Get-ADUser $cUsr).Name
# Changes NetBIOS name to upper characters
    $nb = $nbN.toupper()
# Central store local path
    $csLoc = "c:\Windows\SYSVOL\sysvol\$dName\Policies"
# Directory
    $inputFiles = "_Input-Files"
    $tmpDir = "C:\Temp"
# Schema Admins
    Add-ADGroupMember -Identity "Schema Admins" -Members $cUsr -Server $pdcE
    $SA = Get-ADGroupMember -Identity "Schema Admins" -Recursive -Server $pdcE | Select -ExpandProperty samaccountName
# Break-glass Admin account
    $bgAdmin = "Admin-$nb"
# OUs
    $domAdmin = "OU=Domain Administration,OU=$nbN,$dn"
    $adminAccts = "OU=Administrative Accounts,$domAdmin"
    $adminGrps = "OU=Administrative Groups,$domAdmin"
    $delRgtsGrps = "OU=Delegated Rights Groups,$adminGrps"
    $domOps = "OU=Domain Operation,OU=$nbN,$dn"
    $secGrps = "OU=Security Groups,$domOps"

# Groups
    $csv = Get-Content .\$inputFiles\DomainGroups.csv
    $csv = $csv -replace "nbN",$nbN
    $csv | Out-File .\$inputFiles\New-DomainGroups.csv
    $newCSV = Import-Csv .\$inputFiles\New-DomainGroups.csv

###################################################################################

# Domain Name check

If (!($fqdn -eq $dname)){
    Write-host "The FQDN you entered does not match the FQDN of the domain in which this server is a domain controller of. Please check your input and try again." -ForegroundColor Red
    Break
}

Else {}

###################################################################################
# Create break-glass DA account
Write-Host ""
Write-Host "***Break-Glass Administrator Account***" -ForegroundColor Cyan

Try {Get-ADUser -Identity $bgAdmin | Out-Null
     Write-Host "The break-glass administrator account, $bgAdmin already exists." -ForegroundColor Yellow
     
     $ask = ""
        While ($ask -notmatch "[Y|N]"){
            $ask = Read-Host "Do you want to reset the password for the $bgAdmin break-glass DA account? (Y/N)"
            }
            Write-Host ""

           If ($ask -eq "Y"){

                $choices = [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes","&No")
                While ( $true ) {
                   
                   Write-Host ""
                   Set-ADAccountPassword -Identity $bgAdmin -Reset | Out-Null
                   Set-ADUser -Identity $bgAdmin -Enabled $true | Out-Null
                   Write-Host "Password for $bgAdmin has been reset." -ForegroundColor Green
          
                If ( $choices -ne 0 ) {
                      Break
                    }
            }
         }
               
     }

Catch {
    Write-Host "Creating break-glass administrator account..." -ForegroundColor Gray
    New-ADUser -Name $bgAdmin -DisplayName $bgAdmin -SamAccountName $bgAdmin -UserPrincipalName $bgAdmin@$fqdn -PasswordNeverExpires $true -Description "Break-glass DA account that should remain enabled. IMSU maintains the password." -Enabled $False -Server $pdcE
    Set-ADAccountPassword -Identity $bgAdmin -Reset -NewPassword $bgPwd -Server $pdcE    
    Set-ADUser -Identity $bgAdmin -Enabled $True -Server $pdce
    Add-ADGroupMember -Identity "Domain Admins" -Members $bgAdmin -server $pdcE
    Write-Host "Break-glass administrator account created and added to Domain Admins group." -ForegroundColor Green
    
}
    Write-Host ""

###################################################################################
# Configure Reverse Lookup Zone

Write-Host "***DNS Reverse Lookup Zones***" -ForegroundColor Cyan

        $ask = ""
        While ($ask -notmatch "[Y|N]"){
            $ask = Read-Host "Do you want to configure additional DNS reverse lookup zones? NOTE: 10.0.0.0/8 will be created automatically. (Y/N)"
            }
            Write-Host ""

           If ($ask -eq "Y"){

                $choices = [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes","&No")
                While ( $true ) {
                  $sNet = Read-Host "Enter IP Subnet of the new Reverse zone, in CIDR notation (i.e. 192.168.1.0/24)"
                        $ipAddress = $sNet
                        $ipAddress1 = $ipAddress -split "/" | Select-Object -First 1
                        $ipAddressParts = $ipAddress1.Split('.')
                        [array]::Reverse($ipAddressParts)
                        $importantIpAddressParts = $ipAddressParts | Select-Object -Last 3
                        $zone = [string]::Join('.',$importantIpAddressParts) + '.in-addr.arpa'
                        
                        If (Get-DnsServerZone $zone -ErrorAction SilentlyContinue){
                          Write-Host "$zone already exists." -ForegroundColor Yellow
                         }
                        Else {Add-DnsServerPrimaryZone -NetworkId $sNet -ReplicationScope Forest
                           }
                        
                        If (Get-DnsServerZone $zone -ErrorAction SilentlyContinue){
                            Write-Host "$sNet reverse lookup zone created." -ForegroundColor Green
                         }
                        Else {}                   
          
                  $choice = $Host.UI.PromptForChoice("Create another reverse lookup zone?","",$choices,0)
  
                  If ( $choice -ne 0 ) {
                      break
                    }
                  }
                }

# Create default 10.0.0.0/8 zone

Try{Add-DnsServerPrimaryZone -NetworkId "10.0.0.0/8" -ReplicationScope Forest -ErrorAction Ignore
  }
Catch {}
    
    Write-Host ""

###################################################################################
# Configure DNS forwarders

Write-Host "***DNS Forwarders***" -ForegroundColor Cyan

        $ask = ""
        While ($ask -notmatch "[Y|N]"){
            $ask = Read-Host "Do you want to configure DNS forwarders? (Y/N)"
            }
            
           If ($ask -eq "Y"){

            $dFwdIPs = (Get-DnsServerForwarder).IPAddress
           foreach ($dFwdIP in $dFwdIPs){
                Remove-DnsServerForwarder "$dFwdIP" -Force -WarningAction SilentlyContinue
            }

                $choices = [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes","&No")
                While ( $true ) {
    
                  $fwdIP = Read-Host "Enter a single forwarder IP address and press enter" 
                  $eFWDip = Get-DnsServerForwarder | Out-Null
                  If ($eFWDip.ipaddress -eq $fwdIP){
                    Write-Host "Forwarder $fwdIP already exists."}
                  
                  Else {Add-DnsServerForwarder -IPAddress $fwdIP -PassThru | Out-Null}
                  If ((Get-DnsServerForwarder).IPAddress -eq $fwdIP){
                        Write-Host "$fwdIP forwarder created." -ForegroundColor Green}
                  Else {}
          
                  $choice = $Host.UI.PromptForChoice("Configure another DNS forwarder?","",$choices,0)
            
                  If ( $choice -ne 0 ) {
                        break
                    }
                  }
                }

        Write-Host ""

###################################################################################
# Configure AD Sites

        Get-ADObject -SearchBase (Get-ADRootDSE).ConfigurationNamingContext -filter "objectclass -eq 'site'" | Rename-ADObject -NewName $fADSite -ErrorAction SilentlyContinue

# Create additional AD sites.

Write-Host "***Active Directory Sites***" -ForegroundColor Cyan
        $ask = ""
        While ($ask -notmatch "[Y|N]"){
            $ask = read-host "Do you want to create additional AD sites? NOTE: The 'STAGING' and '$fADSite' sites will be created automatically. (Y/N)"
            }
            
           If ($ask -eq "Y"){

                $choices = [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes","&No")
                While ( $true ) {
  
                  $aADsite = Read-Host "Enter the addtional AD site name" 
                  Try {Get-ADReplicationSite $aADsite | Out-Null
                    Write-Host "AD Site $aADsite already exists." -ForegroundColor Yellow
                    }
                  
                  Catch {$sCost = Read-Host "Enter the site link (to 'Default-First-Site-Name') cost"
                  $ask2 = ""
                  While ($ask2 -notmatch "[Y/N]"){
                    $ask2 = Read-Host "Do you want to enable 'Change Notifications' for this link?"
                    }
                  New-ADReplicationSite -Name "$aADSite" 
                  New-ADReplicationSiteLink -Name "$fADSite-$aADsite" -SitesIncluded $fADSite,$aADSite -Cost $sCost -ReplicationFrequencyInMinutes 15 -InterSiteTransportProtocol IP
                
                    If ($ask2 -eq "Y"){
                        Set-ADReplicationSiteLink $fADSite-$aADsite -replace @{'options'=1} -Description "Change Notifications enabled"
                    }
                    Else{}
                        
                  Write-Host "$aADsite site created." -ForegroundColor Green}
  
               $choice = $Host.UI.PromptForChoice("Create another AD site?","",$choices,0)
               If ( $choice -ne 0 ) {
                        break
                    }
                  }
                }

# Create Staging site and link it to the first AD site.
# -OtherAttributes @{'options'=1} enables 'change notification

Try{New-ADReplicationSite -Name "STAGING" -Description "Staging site for DC promotion" -ErrorAction Continue
    New-ADReplicationSiteLink -Name "STAGING-$fADSite" -SitesIncluded STAGING,$fADSite -Cost 100 `
        -ReplicationFrequencyInMinutes 15 -InterSiteTransportProtocol IP -OtherAttributes @{'options'=1} -Description "Change Notifications enabled" -ErrorAction Continue
}
Catch {}
        
# Remove DEFAULTIPSITELINK        
Try{Remove-ADReplicationSiteLink "DEFAULTIPSITELINK" -Confirm:$false -ErrorAction Continue
}
Catch {}


# Create 'Tertiary' site link and add all created sites to it.
Try{
        $sites = (Get-ADReplicationSite -filter *).Name

        New-ADReplicationSiteLink -Name "Tertiary Link" -SitesIncluded STAGING,$fADSite -Description "All sites must be a member of this link." -Cost 600 -ReplicationFrequencyInMinutes 15 -InterSiteTransportProtocol IP

        Foreach ($site in $sites){
            Set-ADReplicationSiteLink "Tertiary Link" -SitesIncluded @{Add=$site} 

        }
}
Catch {}

Write-Host ""

# Create IP subnets and assign to sites.

Try{New-ADReplicationSubnet -Name "10.0.0.0/8" -Site $fADSite
}
Catch {}

Write-Host "***Active Directory Subnets***" -ForegroundColor Cyan
        $ask = ""
        While ($ask -notmatch "[Y|N]"){
            $ask = read-host "Do you want to create AD IP subnets? 10.0.0.0/8 will be created automatically. (Y/N)"
            }
            Write-Host ""

           If ($ask -eq "Y"){

                $choices = [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes","&No")
                While ( $true ) {
  
                  $subnet = Read-Host "Enter the desired IP subnet in CIDR notation (i.e. 192.168.1.0/24)" 
                      
                  Try{ Get-ADReplicationSubnet $subnet | Out-Null
                        Write-Host "The subnet $subnet already exists." -ForegroundColor Yellow
                    }
                                   
                  
                  Catch{ $site = Read-Host "Enter the site associated with this subnet"
                            Try{Get-ADReplicationSite $site | Out-Null 
                                    If($site){New-ADReplicationSubnet -Name $subnet -Site $site | Out-Null
                                                Write-Host "Subnet $subnet created and associated with $site." -ForegroundColor Green
                                            }
                                    Else{}
                                }
                  
                            Catch{ Write-Host "The site does not exist." -ForegroundColor Red
                                }
                       }
          
                  $choice = $Host.UI.PromptForChoice("Create another AD subnet?","",$choices,0)
  
                 If ( $choice -ne 0 ) {
                        break
                    }
                  }
                }

# Create default 10.0.0.0/8 subnet and assign it to the first AD site.

    Write-Host ""

###################################################################################
# Configure DNS server scavenging.
        
        Write-Host "Configuring DNS server scavenging..." -ForegroundColor Gray
        Set-DnsServerScavenging -ComputerName $pdcE -RefreshInterval 7.00:00:00 -ScavengingInterval 7.00:00:00 -ScavengingState $true -ApplyOnAllZones -PassThru | Out-Null
        Write-Host "DNS server scavenging configured." -ForegroundColor Green
        Write-Host ""

###################################################################################
# Configure OU structure based on .\OUs.txt input file
        
Write-Host "Creating OU structure..." -ForegroundColor Gray
Try{
        If (!(Get-ADOrganizationalUnit -Filter 'Name -like $nb'))
            {
                New-ADOrganizationalUnit -Name $nb -Path $dn | Out-Null
        }


        If (Test-Path ".\$inputFiles\OUs.txt"){
                Get-Content .\$inputFiles\OUs.txt | Foreach-Object {
                  $dom = "ou=$nbn,$dn"
                  $allOU = ''
                  $ous = (Split-Path $_ -Parent).Split('\')
                  [array]::Reverse($ous)
                  $ous | Foreach-Object {
                    if ($_.Length -eq 0) {
                      return
                    }
                    $allOU = $allOU + 'OU=' + $_ + ','
                  }
                  $allOU += $dom
                  $newOU = Split-Path $_ -Leaf

                  New-ADOrganizationalUnit -Name "$newOU" -Path "$allOU" -ProtectedFromAccidentalDeletion $true -PassThru | Out-Null
                  
                }
           Write-Host "OU structure created." -ForegroundColor Green
        }

        Else {Write-Host "OUs.txt file cannot be found. Make sure this script is being executed from the correct location." -ForegroundColor Red
        }
}
Catch {}

        Write-Host ""

###################################################################################
# Move break-glass DA account to appropriate OU

    Try {$ua = (Get-ADUser -Identity $bgAdmin ).DistinguishedName 
        Move-ADObject -Identity $ua -TargetPath "$adminAccts"
        }
    Catch {}

###################################################################################
# Configure 'Pubic' DFS-Namespace

Write-Host "Creating DFS-Namespaces..." -ForegroundColor Gray

        If (!(Get-WindowsFeature FS-DFS-Namespace).installed){
                    Install-WindowsFeature -Name FS-DFS-Namespace -IncludeManagementTools | Out-Null
        }

        If (!(Test-Path -Path "$dfsRoots")){
            New-Item -Path "$dfsRoots" -ItemType "Directory" | Out-Null
            New-Item -Path "$public" -ItemType "Directory" | Out-Null
            New-SmbShare -Path "$public" -ReadAccess Everyone -Name Public | Out-Null
            New-DfsnRoot -TargetPath "\\$cName\Public"-Type DomainV2 -Path "\\$dName\Public" -EnableInsiteReferrals $false -EnableRootScalability $true -EnableSiteCosting $true -EnableTargetFailback $true | Out-Null
            Write-Host "DFS-Namespace \\$dName\Public created." -ForegroundColor Green
        }

        Else {Write-Host "The $dfsRoots folder already exists. Make sure this server wasn't preveously provisioned for DFS Namespaces." -ForegroundColor Red}

        Write-Host ""

###################################################################################
# Create central store and add ADMX/ADML files from servers PolicyDefinitions folder and from .\ADMX.

        If (!(Test-Path -Path $csLoc\PolicyDefinitions)){
            Write-Host "Creating Central Store..." -ForegroundColor Gray
            $admxLoc = Get-Item .\ADMX-*
            $admxVer = ($admxLoc.Name).Split("{-}")[1]
            
            Copy-Item "C:\Windows\PolicyDefinitions" -Destination "$csLoc\" -Recurse -Force
            Copy-Item "$admxLoc\*.*" -Destination "$csLoc\PolicyDefinitions" -Recurse -Force
            Copy-Item "$admxLoc\en-US\*.*" -Destination "$csLoc\PolicyDefinitions\en-US" -Recurse -Force
                        
            New-Item $csLoc\!ADMX-Versions.txt -ItemType file -Value "Known current and past versions of ADMX/ADML files deployed:`r`n`r`n$date`r`nWindows - $admxVer" -Force
            
            
            Write-Host "Central store created." -ForegroundColor Green

        }

        Write-Host ""

###################################################################################
# Create AD Groups

Write-Host "Creating AD security groups..." -ForegroundColor Gray


      If (Get-ADOrganizationalUnit -Filter 'Name -eq "Security Groups"'){
          
          foreach ($line in $Newcsv) {
             If ($line.path -eq "secGrps"){
                   Try {New-ADGroup -Name $line.Name -GroupCategory Security -GroupScope $line.Type -Description $line.Description -Path "$secGrps"
                         Write-Host ""$line.Name" group created" -ForegroundColor Green
                        
                        If($line.name -eq "PKI-Servers"){
                            Add-ADGroupMember -Identity "Cert Publishers" -Members $line.name -Server $pdcE
                           }
                                               
                     }
                   Catch {Write-Host ""$line.Name" group already exists." -ForegroundColor Yellow
                   }
                 }
            }
        }
        
      Else {Write-Host "'Security Groups' OU does not exist. Creation of groups was not performed.." -ForegroundColor Red}

       If (Get-ADOrganizationalUnit -Filter 'Name -eq "Administrative Groups"'){
                                
           foreach ($line in $Newcsv) {
              If ($line.path -eq "adminGrps"){
                   Try {New-ADGroup -Name $line.Name -GroupCategory Security -GroupScope $line.Type -Description $line.Description -Path "$adminGrps"
                         Write-Host ""$line.Name" group created" -ForegroundColor Green
                         If($line.name -eq "Admins-AD-ENG"){
                            Add-ADGroupMember -Identity "Domain Admins" -Members $line.name -Server $pdcE
                            }
                     }
                   Catch{Write-Host ""$line.Name" group already exists." -ForegroundColor Yellow
                   }
                 }
              If ($line.path -eq "delRgtsGrps"){
                   Try {New-ADGroup -Name $line.Name -GroupCategory Security -GroupScope $line.Type -Description $line.Description -Path "$delRgtsGrps"
                         Write-Host ""$line.Name" group created" -ForegroundColor Green
                      }
                   Catch {Write-Host ""$line.Name" group already exists." -ForegroundColor Yellow
                   }
                }
            } 
          }

      Else {Write-Host "'Administrative Groups' OU does not exist. Creation of groups was not performed." -ForegroundColor Red}



        Write-Host ""

###################################################################################
# Configure forest's use of MSA/gMSA

        If ($SA -contains $cusr) {
            Write-Host "Configuring domain for MSA/gMSA use..." -ForegroundColor Gray
            Add-KdsRootKey -EffectiveImmediately | Out-Null
            Write-Host "Domain configurd for MSA/gMSA use." -ForegroundColor Green
           } 
 
        Else {
            Write-Host "The user account used to execute this script is not a member of 'Schema Admin's. The KDS Root Key was not created." -ForegroundColor Red
           }
    
        Write-Host""
        
###################################################################################
# Configure LAPS

        If (!(Test-Path -Path "c:\windows\system32\WindowsPowershell\v1.0\Modules\AdmPwd.PS")){
            Copy-Item ".\AdmPwd.PS" -Destination "c:\windows\system32\WindowsPowershell\v1.0\Modules" -Recurse
            }
        Else {}

        If (Test-Path -Path "c:\windows\system32\WindowsPowershell\v1.0\Modules\AdmPwd.PS"){
            Import-Module AdmPwd.PS
            Write-Host "Configuring LAPS..." -ForegroundColor Gray
                      
            If ($SA -contains $cusr){
                Try{Update-AdmPwdADSchema | Out-Null}
                    Catch{}
                Set-AdmPwdComputerSelfPermission -Identity $dn | Out-Null

                # Configure LAPS auditing (EventID 4662 is generated when the password is read from AD.)

                $wOUs = (Get-ADOrganizationalUnit -Filter 'Name -like "*Workstation*"').distinguishedname

                Foreach ($wOU in $wOUs){
                    Set-AdmPwdAuditing -Identity $wOU -AuditedPrincipals "$nbn\Domain Users" | Out-Null
                }

                $sOUs = (Get-ADOrganizationalUnit -Filter 'Name -like "*Server*"').distinguishedname

                Foreach ($sOU in $sOUs){
                    Set-AdmPwdAuditing -Identity $sOU -AuditedPrincipals "$nbn\Domain Users" | Out-Null
                }
          
                Write-Host "LAPS is configured." -ForegroundColor Green
              
              
              }
        
            Else{
                Write-Host "The user account used to execute this script is not a member of 'Schema Admin's. The schema was not updated for LAPS." -ForegroundColor Red
               }
        
                    
        }
          
          
       Else{
           Write-Host "The AdmPwd.PS module can not be imported. Verify it is located in c:\windows\system32\WindowsPowershell\v1.0\Modules\. LAPS can not be configured." -ForegroundColor Red
          }
   
# Remove user from Schema Admins group

        Remove-ADGroupMember -Identity "Schema Admins" -Members $cUsr -Confirm:$false
               
        Write-Host ""

###################################################################################
# Redirect Users and Computers to OUs vs. default containers

        If ($rcOu= (Get-ADOrganizationalUnit -Filter 'Name -eq "Computers-Orphaned"').distinguishedname){
                Write-Host "Redirecting Computers to $rcou." -ForegroundColor Green
                redircmp.exe $rcOU
        }

        If ($ruOU= (Get-ADOrganizationalUnit -Filter 'Name -eq "Endusers"').distinguishedname){
                Write-Host "Redirecting Users to $ruOU." -ForegroundColor Green
                redirusr.exe $ruOU
        }

# Move Computers container to Computers-Orphaned OU

        If (Get-ADOrganizationalUnit -Filter 'Name -eq "Computers-Orphaned"'){
            Try {Move-ADObject -Identity "cn=Computers,$dn" -TargetPath $rcou
            Write-Host "Computer container has been moved to the 'Computers-Orphaned' OU." -ForegroundColor Green}
            Catch {}
         
          } 
        Write-Host ""

###################################################################################
# Import any GPOs that reside in the .\GPOs directory


       If (Test-Path "$tmpDir\GPOs") {}

        Else { New-Item -Path "$tmpDir\GPOs" -ItemType "Directory" | Out-Null
            }


        If (Test-Path $tmpDir\GPOs){
           Copy-Item -Path ".\GPOs" -Destination "$tmpDir" -Recurse -Force
   
        $gpoFolder = "$tmpDir\GPOs"    
        $gpo = (get-childitem $gpoFolder -Recurse | Where-Object {$_.Name -eq "gpreport.xml"}).FullName
        Write-Host "Importing GPOs..." -ForegroundColor Gray
        Foreach ($i in $gpo){
                   $path = Split-Path $i -Parent | Split-Path -Parent
                   $name = Split-Path (Split-Path $i -Parent) -Leaf
        
                   [xml]$gpname = get-content $i
                   
                   Import-GPO -BackupId $name -TargetName $gpname.gpo.name -Path $path -CreateIfNeeded | Out-Null
                   Write-host $gpname.gpo.name "GPO imported" -ForegroundColor Green
                   
                }
               Write-Host "GPOs imported." -ForegroundColor Green
         
                   
            }
        
        
        
        Else {Write-Host "GPO backup files are missing. Make sure this script is being executed from the correct location." -ForegroundColor Red }

        Write-Host ""

###################################################################################
# Import any WMI filters that reside in the .\GPOs and .\GPOs\WMI directories
        
        $wmiFolder = "$tmpDir\GPOs\"
        $uWmiFolder = "$tmpDir\GPOs\WMI\"

       If (Test-Path $wmiFolder){
            Write-Host "Importing WMI filters..." -ForegroundColor Gray
            $filters = (Get-ChildItem $tmpDir -File -Recurse | Where-Object {$_.Name -like "*.mof"})
            $author = 'Author = "'+ $usr + '"'
            $domain = 'Domain = "'+ $fqdn + '"'
            foreach ($filter in $filters){
                   (Get-Content $filter.fullname) | ForEach {$_ -replace 'Author = "SECAdmin@security.local"', $author `
                                                               -replace 'Domain = "security.local"', $domain `
                                                               } | Set-Content $wmiFolder\$filter
                 
                    # Modify 2016 Member Server WMI to add Product Type 2 (DC)
                    $filter = ""
                    $filter = (Get-ChildItem $wmiFolder -File | Where-Object {$_.Name -like "Windows Server 2016 Member Server*"})
   
                    If($filter.name -like "*2016 Member*"){
                        (Get-Content $filter.fullname).Replace('Query = "SELECT Version,ProductType FROM Win32_OperatingSystem WHERE Version LIKE \"10.0.14393\" AND ProductType = \"3\""', `
                        'Query = "SELECT Version,ProductType FROM Win32_OperatingSystem WHERE Version LIKE \"10.0.14393\" AND (ProductType = \"2\" OR ProductType = \"3\")"') `
                        | Set-Content $wmiFolder\$filter
                      }
                    
                    # Modify 2019 Member Server WMI to add Product Type 2 (DC)
                    $filter = ""
                    $filter = (Get-ChildItem $wmiFolder -File | Where-Object {$_.Name -like "Windows Server 2019 Member Server*"})

                    If($filter -like "*2019 Member*"){
                        (Get-Content $filter.fullname).Replace('Query = "SELECT Version,ProductType FROM Win32_OperatingSystem WHERE Version LIKE \"10.0.17763\" AND ProductType = \"3\""', `
                        'Query = "SELECT Version,ProductType FROM Win32_OperatingSystem WHERE Version LIKE \"10.0.17763\" AND (ProductType = \"2\" OR ProductType = \"3\")"') `
                        | Set-Content $wmiFolder\$filter
                     }
                 }

           $uFilters = (Get-ChildItem $WmiFolder -File | Where-Object {$_.Name -like "*.mof"}).FullName 
            foreach ($uFilter in $uFilters){
                  $uFilterName = $uFilter -split "\\" | Select-Object -Last 1
                  mofcomp.exe -N:root\Policy "$uFilter" | Out-Null
                  Write-Host "$uFilterName WMI filter imported" -ForegroundColor Green
                }  
            #Write-Host "WMI filters imported." -ForegroundColor Green
           }    
        Else {}
    
###################################################################################
# Set WMI filters for GPOs.

function Set-GPOWmiFilter
{
<#
----------------------------------------
Version: 1.0.6.0
Author: Tore Groneng
-----------------------------------------
#>
[cmdletbinding()]
Param(
    [Parameter(
        ValueFromPipeline,
        ParameterSetName='ByWMIFilterObject')]
    [Microsoft.GroupPolicy.WmiFilter]$WMIfilter
    ,
    [Parameter(ParameterSetName='ByWMIFilterName')]
    [Parameter(ParameterSetName='FilterByPolicyName')]
    [Parameter(ParameterSetName='FilterByPolicyGUID')]
    [string]$WMIFilterName
    ,
    
    [Parameter(ParameterSetName='FilterByPolicyName')]
    [Parameter(ParameterSetName='ByWMIFilterObject')]
    [string]$GroupPolicyName
    ,
    
    [Parameter(ParameterSetName='FilterByPolicyGUID')]
    [Parameter(ParameterSetName='ByWMIFilterObject')]
    [guid]$GroupPolicyGUID
)
BEGIN
{
    $f = $MyInvocation.InvocationName
    Write-Verbose -Message "$f - START"

    Write-Verbose -Message "$f - Loading required module GroupPolicy"

    if(-not (Get-Module -Name GroupPolicy))
    {
        Import-Module -Name GroupPolicy -ErrorAction Stop -Verbose:$false
    }
    $GPdomain = New-Object Microsoft.GroupPolicy.GPDomain
    $SearchFilter = New-Object Microsoft.GroupPolicy.GPSearchCriteria

    Write-Verbose -Message "$f - Searching for WmiFilters"
    $allWmiFilters = $GPdomain.SearchWmiFilters($SearchFilter)
}

PROCESS
{    
    if($WMIFilterName)
    {
        Write-Verbose -Message "$f - Finding WMI-filter with name $WMIFilterName"
        $WMIfilter = $allWmiFilters | Where-Object Name -eq $WMIFilterName
        if(-not $WMIfilter)
        {
            $msg = "Did not find a WMIfilter with name '$WMIFilterName'"
            Write-Verbose -Message "$f - ERROR - $msg"
            Write-Error -Message $msg -ErrorAction Stop
        }
    }

    $GroupPolicyObject = $null

    if($GroupPolicyName)
    {
        Write-Verbose -Message "$f - Finding Group Policy with name '$GroupPolicyName'"
        $GroupPolicyObject = Get-GPO -Name $GroupPolicyName
        if(-not $GroupPolicyObject)
        {
            $msg = "Unable to find GPO with Name '$GroupPolicyName'"
            Write-Verbose -Message "$f - ERROR - $msg"
            Write-Error -Message $msg -ErrorAction Stop
        }
    }

    if($GroupPolicyGUID)
    {
        Write-Verbose -Message "$f - Finding Group Policy with GUID '$GroupPolicyGUID'"
        $GroupPolicyObject = Get-GPO -Guid $GroupPolicyGUID
        if(-not $GroupPolicyObject)
        {
            $msg = "Unable to find GPO with GUID '$GroupPolicyGUID'"
            Write-Verbose -Message "$f - ERROR - $msg"
            Write-Error -Message $msg -ErrorAction Stop
        }
    }

    Write-Verbose -Message "$f - Applying filter with name '$($WMIfilter.Name)' to GPO '$($GroupPolicyObject.DisplayName)'"

    try
    {
        $GroupPolicyObject.WmiFilter = $WMIfilter
    }
    catch
    {
        $ex = $_.Exception
        Write-Verbose -Message "$f - EXCEPTION - $($ex.Message)"
        throw $ex
    }
}

END
{
    Write-Verbose -Message "$f - END"
}
}

        $gpos = (Get-GPO -all).DisplayName
        $filters = Get-ADObject -Filter 'objectClass -eq "msWMI-Som"' -Properties "msWMI-Name","msWMI-Parm1","msWMI-Parm2"

Write-Host "Applying WMI filters to GPOs..." -ForegroundColor Gray

        # Server 2016
        foreach($gpo in $gpos){
            if(($gpo -like "*2016*") -or ($gpo -like "*Member Server*" -and $gpo -like "*2016*")){
                $filter = $filters | Where msWMI-Name -Like "*2016 Member*"
                Set-GPOWmiFilter -WMIFilterName $filter.'msWMI-Name' -GroupPolicyName $gpo
            }
        }

        # Server 2016 DC
        foreach($gpo in $gpos){
            if(($gpo -like "*2016*") -and ($gpo -like "*Domain Controller*" -or $gpo -like "*DC*")){
                $filter = $filters | Where msWMI-Name -Like "*2016 Domain Controller*"
                Set-GPOWmiFilter -WMIFilterName $filter.'msWMI-Name' -GroupPolicyName $gpo
            }
        }

        # Server 2019
        foreach($gpo in $gpos){
            if(($gpo -like "*2019*") -or ($gpo -like "*Member Server*" -and $gpo -like "*2019*")){
                $filter = $filters | Where msWMI-Name -Like "*2019 Member*"
                Set-GPOWmiFilter -WMIFilterName $filter.'msWMI-Name' -GroupPolicyName $gpo
            }
        }

        # Server 2019 DC
        foreach($gpo in $gpos){
            if(($gpo -like "*2019*") -and ($gpo -like "*Domain Controller*" -or $gpo -like "*DC*")){
                $filter = $filters | Where msWMI-Name -Like "*2019 Domain Controller*"
                Set-GPOWmiFilter -WMIFilterName $filter.'msWMI-Name' -GroupPolicyName $gpo
            }
        }

        # Authoritative Time Source
        foreach($gpo in $gpos){
            if($gpo -like "*AuthTimeSource*") {
                $filter = $filters | Where msWMI-Name -Like "*PDCe*"
                Set-GPOWmiFilter -WMIFilterName $filter.'msWMI-Name' -GroupPolicyName $gpo
            }
        }

        # Windows 10
        foreach($gpo in $gpos){
            if(($gpo -like "*Windows 10*") -or ($gpo -like "*Win10*")){
                $filter = $filters | Where msWMI-Name -Like "*Windows 10*"
                Set-GPOWmiFilter -WMIFilterName $filter.'msWMI-Name' -GroupPolicyName $gpo
            }
        }        


        # Internet Explorer 11
        foreach($gpo in $gpos){
            if(($gpo -like "*Internet Explorer 11*") -or ($gpo -like "*IE11*")){
                $filter = $filters | Where msWMI-Name -Like "*Internet Explorer 11*"
                Set-GPOWmiFilter -WMIFilterName $filter.'msWMI-Name' -GroupPolicyName $gpo
            }
        }

        # Google Chrome
        foreach($gpo in $gpos){
            if($gpo -like "*Chrome*"){
                $filter = $filters | Where msWMI-Name -Like "*Chrome*"
                Set-GPOWmiFilter -WMIFilterName $filter.'msWMI-Name' -GroupPolicyName $gpo
            }
        }
    Write-Host "WMI filters linked." -ForegroundColor Green

    Write-Host ""

###################################################################################
# Get GPLinks function:
function Get-Gplink  {
<#
----------------------------------------
Version: 1.3
Author: Thomas Bouchereau
-----------------------------------------
#>

[cmdletBinding()]
param ([string]$path,[string]$server,[string]$site)

#Import AD and GPO modules
Import-Module activedirectory
Import-Module grouppolicy
# get the DN to te configuration partition
$configpart=(Get-ADRootDSE).configurationNamingContext

#get content of attribut gplink on site object or OU
if ($site)
    {
        $gplink=Get-ADObject -Filter {distinguishedname -eq $site} -searchbase $configpart -Properties gplink
        $target=$site
    }
elseif ($path)
    {
        switch ($server)
            {
             "" {$gplink=Get-ADObject -Filter {distinguishedname -eq $path} -Properties gplink}
             default {$gplink=Get-ADObject -Filter {distinguishedname -eq $path} -Properties gplink -server $server     
                      }
            }
    $target=$path
    }

    

#if DN is not valid return" Invalide DN" error

if ($gplink -eq $null)
    {
        write-host "Either Invalide DN in the current domain, specify a DC of the target DN domain or no GPOlinked to this DN"
    }

# test if glink is not null or only containes white space before continuing. 

if (!((($gplink.gplink) -like "") -or (($gplink.gplink) -like " ")))
    {

        #set variale $o to define link order
        $o=0    
    
        #we split the gplink string in order to seperate the diffent GPO linked

        $split=$gplink.gplink.split("]")
    
        #we need to do a reverse for to get the proper link order

         for ($s=$split.count-1;$s -gt -1;$s--)
            {
          
                #since the last character in the gplink string is a "]" the last split is empty we need to ignore it
           
                if ($split[$s].length -gt 0)
                    {
                        $o++
                        $order=$o            
                        $gpoguid=$split[$s].substring(12,36)
			            $gpodomainDN=($split[$s].substring(72)).split(";")
			            $domain=($gpodomaindn[0].substring(3)).replace(",DC=",".")
			   			$checkdc=(get-addomaincontroller -domainname $domain -discover).name
            			                     
                        #we test if the $gpoguid is a valid GUID in the domain if not we return a "Oprhaned GpLink or External GPO" in the $gponname
                        
			
			
				        $mygpo=get-gpo -guid $gpoguid -domain $domain -server "$($checkdc).$($domain)" 2> $null
                    
				        if ($mygpo -ne $null )
					              {
					               $gponame=$MyGPO.displayname
					               $gpodomain=$domain	
					              }	
    				              
    				        else
    					          {
					              $gponame="Orphaned GPLink" 
                        	      $gpodomain=$domain   
    					          }
    				
			
                        #we test the last 2 charaters of the split do determine the status of the GPO link
           
    
                        if (($split[$s].endswith(";0")))
                            {
                                $enforced= "No"
                                $enabled= "Yes"
                            }
                        elseif (($split[$s].endswith(";1")))
                            {
                                $enabled= "No"
                                $enforced="No"
                            }
                        elseif (($split[$s].endswith(";2")))
                            {
                                $enabled="Yes"
                                $enforced="Yes"
                            }
                        elseif (($split[$s].endswith(";3")))
                            {
                                $enabled="No"
                                $enforced="Yes"
                            }

                         #we create an object representing each GPOs, its links status and link order

                        $return = New-Object psobject 
                        $return | Add-Member -membertype NoteProperty -Name "Target" -Value $target 
                        $return | Add-Member -membertype NoteProperty -Name "GPOID" -Value $gpoguid
                        $return | Add-Member -membertype NoteProperty -Name "DisplayName" -Value $gponame 
			            $return | Add-Member -membertype NoteProperty -Name "Domain" -Value $gpodomain 
                        $return | Add-Member -membertype NoteProperty -Name "Enforced" -Value $enforced
                        $return | Add-Member -membertype NoteProperty -Name "Enabled" -Value $enabled
                        $return | Add-Member -membertype NoteProperty -Name "Order" -Value $order
                        $return
                    }
         
            }
         
    }
  }

# Link GPOs

        $gpos = Get-GPO -All -Domain $dName
        $cmpSTIGs = $gpos | Where-Object {($_.DisplayName -like "*STIG*")-and ($_.DisplayName -like "*Computer*")} 
        $usrSTIGs = $gpos | Where-Object {($_.DisplayName -like "*STIG*")-and ($_.DisplayName -like "*User*")} 
        $fwSTIGs =  $gpos | Where-Object {($_.DisplayName -like "*STIG*")-and ($_.DisplayName -like "*Firewall*")}
        $dcSTIGs =$gpos | Where-Object {($_.DisplayName -notlike "*Domain Controller*")}
        $cstGpos = $gpos | Where-Object {($_.DisplayName -like "*FBI*")} 
        $dCstGPO = $cstGpos | Where-Object {($_.DisplayName -like "*Domain Policy*")}
        $cmpOrph = $cstGpos | Where-Object {($_.DisplayName -like "*Orphaned*")}

 
 Write-Host "Linking GPOs..." -ForegroundColor Gray

##################################       
# Link custom domain policy to domain root and set its order       
        New-GPLink -Name $dCstGPO.DisplayName -Target $dn -Order 1 -ErrorAction SilentlyContinue | Out-Null

# Link ALL 'computer' STIGS and specific custom policies to Computers-Orphaned OU
       
       # Custom 2016      
        ForEach ($cstGpo in $cstGpos | Where-Object {($_.DisplayName -like "*2016*") -and ($_.DisplayName -like "*CMP*") -and ($_.DisplayName -notlike "*DC*") -and ($_.DisplayName -notlike "*Domain Controller*")}){
    
            New-GPLink -Name $cstGpo.DisplayName -Target $rcOu -ErrorAction SilentlyContinue | Out-Null
 
         }

       # Custom 2019      
        ForEach ($cstGpo in $cstGpos | Where-Object {($_.DisplayName -like "*2019*") -and ($_.DisplayName -like "*CMP*") -and ($_.DisplayName -notlike "*DC*") -and ($_.DisplayName -notlike "*Domain Controller*")}){
    
            New-GPLink -Name $cstGpo.DisplayName -Target $rcOu -ErrorAction SilentlyContinue | Out-Null
 
         }
       
     # ALL STIGs  
       ForEach ($cmpSTIG in $cmpSTIGs | Where-Object {$_.DisplayName -notlike "*Domain Controller*"}){
                
            New-GPLink -Name $cmpSTIG.DisplayName -Target $rcOu -ErrorAction SilentlyContinue | Out-Null
 
         }
     

    # Firewall
       #New-GPLink -Name $fwSTIGs.DisplayName -Target $rcOu

    # Computer-Orphaned
       New-GPLink -Name $cmpOrph.DisplayName -Target $rcOu -Order 1 -ErrorAction SilentlyContinue | Out-Null

##################################
# Link 2016 computer, STIGS and custom policies to Server\2016 OU
        
    # Custom 2016      
        ForEach ($cstGpo in $cstGpos | Where-Object {($_.DisplayName -like "*2016*") -and ($_.DisplayName -like "*CMP*") -and ($_.DisplayName -notlike "*DC*") -and ($_.DisplayName -notlike "*Domain Controller*")}){
    
            New-GPLink -Name $cstGpo.DisplayName -Target "OU=2016,OU=Servers,OU=$nBn,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }

    # STIGS 2016
        ForEach ($cmpSTIG in $cmpSTIGs | Where-Object {($_.DisplayName -like "*2016*") -and ($_.DisplayName -notlike "*Domain Controller*") }){
    
            New-GPLink -Name $cmpSTIG.DisplayName -Target "OU=2016,OU=Servers,OU=$nBn,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }

##################################
# Link 2019 computer, STIGS and custom policies to Server\2019 OU
        
    # Custom 2019      
        ForEach ($cstGpo in $cstGpos | Where-Object {($_.DisplayName -like "*2019*") -and ($_.DisplayName -like "*CMP*") -and ($_.DisplayName -notlike "*DC*") -and ($_.DisplayName -notlike "*Domain Controller*")}){
    
            New-GPLink -Name $cstGpo.DisplayName -Target "OU=2019,OU=Servers,OU=$nBn,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }

    # STIGS 2019
        ForEach ($cmpSTIG in $cmpSTIGs | Where-Object {($_.DisplayName -like "*2019*") -and ($_.DisplayName -notlike "*Domain Controller*") }){
    
            New-GPLink -Name $cmpSTIG.DisplayName -Target "OU=2019,OU=Servers,OU=$nBn,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }

##################################
# Link STIGS and custom policies to DC OU

    # Custom PDCe for Time
        ForEach ($cstGpo in $cstGpos | Where-Object {($_.DisplayName -like "*Time*") -and ($_.DisplayName -like "*CMP*") -and ($_.DisplayName -like "*DC*")}){
    
            New-GPLink -Name $cstGpo.DisplayName -Target "OU=Domain Controllers,$dn" -ErrorAction SilentlyContinue | Out-Null
        }

    # Custom IE11
        ForEach ($cstGpo in $cstGpos | Where-Object {($_.DisplayName -like "*IE11*") -and ($_.DisplayName -like "*CMP*")}){
     
            New-GPLink -Name $cstGpo.DisplayName -Target "OU=Domain Controllers,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }
    
    # Custom 2016 DC
        ForEach ($cstGpo in $cstGpos | Where-Object {($_.DisplayName -like "*2016*") -and ($_.DisplayName -like "*CMP*") -and ($_.DisplayName -like "*DC*")}){
    
            New-GPLink -Name $cstGpo.DisplayName -Target "OU=Domain Controllers,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }
    
    # Custom 2016
        ForEach ($cstGpo in $cstGpos | Where-Object {($_.DisplayName -like "*2016*") -and ($_.DisplayName -like "*CMP*") -and ($_.DisplayName -notlike "*DC*")}){
     
            New-GPLink -Name $cstGpo.DisplayName -Target "OU=Domain Controllers,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }

    # Custom 2019 DC
         ForEach ($cstGpo in $cstGpos | Where-Object {($_.DisplayName -like "*2019*") -and ($_.DisplayName -like "*CMP*") -and ($_.DisplayName -like "*DC*")}){
    
            New-GPLink -Name $cstGpo.DisplayName -Target "OU=Domain Controllers,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }

    # Custom 2019
        ForEach ($cstGpo in $cstGpos | Where-Object {($_.DisplayName -like "*2019*") -and ($_.DisplayName -like "*CMP*") -and ($_.DisplayName -notlike "*DC*")}){
     
            New-GPLink -Name $cstGpo.DisplayName -Target "OU=Domain Controllers,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }

     
    # STIGS
        
         ForEach ($cmpSTIG in $cmpSTIGs | Where-Object {($_.DisplayName -like "*Internet Explorer*")}){
    
            New-GPLink -Name $cmpSTIG.DisplayName -Target "OU=Domain Controllers,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }
    
       # Firewall 
        #New-GPLink -Name $fwSTIGs.DisplayName -Target "OU=Domain Controllers,$dn"

        <#ForEach ($usrSTIG in $usrSTIGs | Where-Object {($_.DisplayName -like "*2016*") -and ($_.DisplayName -like "*Domain Controller*") }){
    
            New-GPLink -Name $usrSTIG.DisplayName -Target "OU=Domain Controllers,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }#>
  
        ForEach ($cmpSTIG in $cmpSTIGs | Where-Object {($_.DisplayName -like "*2016*") -and ($_.DisplayName -like "*Domain Controller*") }){
    
            New-GPLink -Name $cmpSTIG.DisplayName -Target "OU=Domain Controllers,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }

         ForEach ($cmpSTIG in $cmpSTIGs | Where-Object {($_.DisplayName -like "*2019*") -and ($_.DisplayName -like "*Domain Controller*") }){
    
            New-GPLink -Name $cmpSTIG.DisplayName -Target "OU=Domain Controllers,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }

##################################
# Set 'Default Domain Controllers Policy's' link order


        $gpLinks = GPLink -path "OU=Domain Controllers,$dn"
        $gpOrder = $gpLinks.order.Length
        Set-GPLink -Name "Default Domain Controllers Policy" -Target "OU=Domain Controllers,$dn" -Order $gpOrder | Out-Null

##################################
# Link Windows 10 computer, STIGS and custom policies to Workstations\Win10\Workstation_Stnd OU

    # Custom
       ForEach ($cstGpo in $cstGpos | Where-Object {($_.DisplayName -like "*Win10*") -and ($_.DisplayName -like "*CMP*")}){
    
            New-GPLink -Name $cstGpo.DisplayName -Target "OU=Workstations_Stnd,OU=WIN_10,OU=Workstations,OU=$nBn,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }
    
    # STIGS         
       ForEach ($cmpSTIG in $cmpSTIGs | Where-Object {($_.DisplayName -like "*Windows 10*")}){
    
            New-GPLink -Name $cmpSTIG.DisplayName -Target "OU=Workstations_Stnd,OU=WIN_10,OU=Workstations,OU=$nBn,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }

##################################
# Link Windows 10 user GPOs, STIGS and custom policies to Users_and_Groups\Endusers OU

    # Custom
       ForEach ($cstGpo in $cstGpos | Where-Object {($_.DisplayName -like "*Win10*") -and ($_.DisplayName -like "*USR*")}){
    
            New-GPLink -Name $cstGpo.DisplayName -Target "OU=Endusers,OU=Users_And_Groups,OU=$nBn,$dn" -ErrorAction SilentlyContinue | Out-Null
  
         }

    # STIGS          
       ForEach ($usrSTIG in $usrSTIGs | Where-Object {($_.DisplayName -like "*Windows 10*")}){
    
            New-GPLink -Name $usrSTIG.DisplayName -Target "OU=Endusers,OU=Users_And_Groups,OU=$nBn,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }
                  

##################################
# Link IE/Chrome and Firewall to Servers, Workstations, and all User OUs

    # Servers
    # Custom
        ForEach ($cstGpo in $cstGpos | Where-Object {($_.DisplayName -like "*IE11*") -and ($_.DisplayName -like "*CMP*")}){
    
            New-GPLink -Name $cstGpo.DisplayName -Target "OU=Servers,OU=$nBn,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }

        ForEach ($cstGpo in $cstGpos | Where-Object {($_.DisplayName -like "*Chrome*")}){
    
            New-GPLink -Name $cstGpo.DisplayName -Target "OU=Servers,OU=$nBn,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }

    # STIGS       
        ForEach ($cmpSTIG in $cmpSTIGs | Where-Object {($_.DisplayName -like "*Internet Explorer*")}){
    
            New-GPLink -Name $cmpSTIG.DisplayName -Target "OU=Servers,OU=$nBn,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }
    
        ForEach ($cmpSTIG in $cmpSTIGs | Where-Object {($_.DisplayName -like "*Chrome*")}){
    
            New-GPLink -Name $cmpSTIG.DisplayName -Target "OU=Servers,OU=$nBn,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }
    
    
    # Custom
        ForEach ($cstGpo in $cstGpos | Where-Object {($_.DisplayName -like "*Firewall*")}){
    
            New-GPLink -Name $cstGpo.DisplayName -Target "OU=Servers,OU=$nBn,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }

    # STIGS
        New-GPLink -Name $fwSTIGs.DisplayName -Target "OU=Servers,OU=$nBn,$dn" -ErrorAction SilentlyContinue | Out-Null

    # Workstations
    # Custom
        ForEach ($cstGpo in $cstGpos | Where-Object {($_.DisplayName -like "*IE11*") -and ($_.DisplayName -like "*CMP*")}){
    
            New-GPLink -Name $cstGpo.DisplayName -Target "OU=Workstations,OU=$nBn,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }

        ForEach ($cstGpo in $cstGpos | Where-Object {($_.DisplayName -like "*Chrome*")}){
    
            New-GPLink -Name $cstGpo.DisplayName -Target "OU=Workstations,OU=$nBn,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }

    # STIGS
        ForEach ($cmpSTIG in $cmpSTIGs | Where-Object {($_.DisplayName -like "*Internet Explorer*")}){
    
            New-GPLink -Name $cmpSTIG.DisplayName -Target "OU=Workstations,OU=$nBn,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }
    
        ForEach ($cmpSTIG in $cmpSTIGs | Where-Object {($_.DisplayName -like "*Chrome*")}){
     
            New-GPLink -Name $cmpSTIG.DisplayName -Target "OU=Workstations,OU=$nBn,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }

    # Firewall
    # Custom
        ForEach ($cstGpo in $cstGpos | Where-Object {($_.DisplayName -like "*Firewall*")}){
    
            New-GPLink -Name $cstGpo.DisplayName -Target "OU=Workstations,OU=$nBn,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }
    
    # STIGS
        #New-GPLink -Name $fwSTIGs.DisplayName -Target "OU=Workstations,OU=$nBn,$dn" | Out-Null

   
    # End Users
    # Custom
        ForEach ($cstGpo in $cstGpos | Where-Object {($_.DisplayName -like "*IE11*") -and ($_.DisplayName -like "*USR*")}){
    
            New-GPLink -Name $cstGpo.DisplayName -Target "OU=Endusers,OU=Users_And_Groups,OU=$nBn,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }

        
    
    # STIGS
        ForEach ($usrSTIG in $usrSTIGs | Where-Object {($_.DisplayName -like "*Internet Explorer*")}){
    
            New-GPLink -Name $usrSTIG.DisplayName -Target "OU=Endusers,OU=Users_And_Groups,OU=$nBn,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }
    
       
    
    # Admin Users
    # Custom
        ForEach ($cstGpo in $cstGpos | Where-Object {($_.DisplayName -like "*IE11*") -and ($_.DisplayName -like "*USR*")}){
    
            New-GPLink -Name $cstGpo.DisplayName -Target "OU=Administrative Accounts,OU=Domain Administration,OU=$nBn,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }

        

    # STIGS
        ForEach ($usrSTIG in $usrSTIGs | Where-Object {($_.DisplayName -like "*Internet Explorer*")}){
    
            New-GPLink -Name $usrSTIG.DisplayName -Target "OU=Administrative Accounts,OU=Domain Administration,OU=$nBn,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }
    
        

        <#ForEach ($usrSTIG in $usrSTIGs | Where-Object {($_.DisplayName -like "*2012*") -and ($_.DisplayName -notlike "*Domain Controller*") }){
    
            New-GPLink -Name $usrSTIG.DisplayName -Target "OU=Administrative Accounts,OU=Domain Administration,OU=$nBn,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }

        ForEach ($usrSTIG in $usrSTIGs | Where-Object {($_.DisplayName -like "*2016*") -and ($_.DisplayName -notlike "*Domain Controller*") }){
    
            New-GPLink -Name $usrSTIG.DisplayName -Target "OU=Administrative Accounts,OU=Domain Administration,OU=$nBn,$dn" -ErrorAction SilentlyContinue | Out-Null
 
         }#>


        Write-Host "GPOs linked to appropriate OUs." -ForegroundColor Green
        Write-Host ""

###################################################################################
# Rename FBI Domain Policy   
            	
    $dGPO = Get-GPO -Name "FBI Domain Policy"
	$nbDP = Rename-GPO -Name $dGPO.DisplayName -TargetName "$nb Domain Policy"


###################################################################################
# Configure domain to use 'Lastname, Firstname MI' in the Displayname field.

Set-ADObject "CN=user-Display,CN=409,CN=DisplaySpecifiers,CN=Configuration,$dn" -Replace @{CreateDialog="%<sn>, %<givenName> %<initials>"}


###################################################################################
# Enable AD Recycle Bin

    Try {Get-ADOptionalFeature 'Recycle Bin Feature' | Out-Null}
    Catch { Write-Host "Configuring AD Recycle Bin..." -ForegroundColor Gray
        Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $dName -Confirm:$false | Out-Null
      }
        Write-Host "AD Recycle Bin is enabled." -ForegroundColor Green
    Write-Host ""


###################################################################################
# End

        Write-Host "Domain configuration complete." -ForegroundColor Green
        Write-Host ""a

        Write-Host "Please review the outputs provided above before proceeding." -ForegroundColor Yellow
        Write-Host ""
        
        $ask = ""
        While ($ask -notmatch "[Y|N]"){
            $ask = Read-Host "Would you like to restart this server? (Y/N)"
            }
            Write-Host ""

           If ($ask -eq "Y"){

                $choices = [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes","&No")
                While ( $true ) {
                
                shutdown -r -t 5
                                                  
                If ( $choices -ne 0 ) { 
                      Break
                    }
                }
            }
         
        Else {Write-Host "Please reboot this server before making any additional configurations." -ForegroundColor Yellow}
        
        Write-Host ""