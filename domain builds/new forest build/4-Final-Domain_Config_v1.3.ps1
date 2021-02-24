<###################################################################################
Required information before executing:

    - Employee IDs for new DA accounts.

Execution:
    4-Final-Domain_Config.ps1 -fqdn <FQDN> 

If an error is encountered, the script will stop.

This script will perform the following actions:

    - Option to create additional Domain Admin accounts.
        - Option to set the account's password. If yes, it enables the account.
        - Option to set the Employee ID.
        - Moves the accounts to the Administrative Accounts OU.
    - Checks to see if the break-glass DA account is enabled. 
        - If it is, renames and disables the domain's built-in administrator account
    - Empties the Enterprise Admins and Schema Admins groups.

v1.0 Created by Theron Howton, MCS
    04/17/2018

Modified:
v1.1 - Theron Howton - 09/27/2018
    - Updated the rename of the builtin Administrator account code.

v1.2 - Theron Howton - 10/22/2018
    - Made new admins a member of Admins-AD-ENG vs. Domain Admins.

v1.3 - Theron Howton - 04/01/2019
    - Added logic to ensure an acceptable password is entered during account optional creation.
    
###################################################################################>

param (
 [Parameter(Mandatory=$True)][string]$fqdn
)

$ErrorActionPreference = "SilentlyContinue"


# Global variables

# Domain Information
    $dInfo = Get-ADDomain
    $dName = $dInfo.DNSRoot
    $pdcE = $dInfo.pdcemulator
    $dn = $dInfo.distinguishedname
    $nbN = $dInfo.NetBIOSName
    $dns = $dInfo.DNSRoot

# OUs
    $domAdmin = "Domain Administration"
    $adminAccts = "Administrative Accounts"
    $adminGrps = "Administrative Groups"

# Changes NetBIOS name to upper characters
    $nb = $nbN.toupper()

# Domain's built-in administrator account
    $biAdmin = Try {(Get-ADUser -Identity Administrator -Server $pdcE).DistinguishedName} catch {}
    $newBIadminName = "BI-Admin-DISABLED" 
# Break-glass DA account
    $bgAdmin = Get-ADUser -Identity "Admin-$nbn" -Properties Enabled -Server $pdcE

###################################################################################
# Domain Name check

If (!($fqdn -eq $dname)){
    Write-host "The FQDN you entered does not match the FQDN of the domain in which this server is a domain controller of. Please check your input and try again." -ForegroundColor Red
    Break
}

Else {}
####################################################################################

# Create additional DA accounts
Write-Host ""
Write-Host "***Additional Domain Admin Accounts***" -ForegroundColor Cyan
Write-Host ""

$ask = ""
        While ($ask -notmatch "[Y|N]"){
            $ask = Read-Host "Do you want to create additional Domain Admin accounts? (Y/N)"
            }
            Write-Host ""

           If ($ask -eq "Y"){

                $choices = [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes","&No")
                While ( $true ) {

                        Do {
                            $da = Read-Host "Enter the account name to be created in the form of ADM-<UserName> or press CTRL + C to cancel"
                        
                        
                            Try {
                                $userOK = $false
                                Get-ADUser -Identity $da -Server $pdcE
                         
                                Write-Host "$da already exists." -ForegroundColor Red
                            
                                                                                    
                             }
                        
                            Catch {
                                $userOK = $true
                                $emp = Read-Host "Enter the user's First and Last name"
                                $split = $emp.split(" ")
                                $sn = $split[1]
                                $gn = $split[0]
                                $eID = Read-Host "Enter $emp's Employee ID or leave blank if it is unknown"
                            
                                New-ADUser -Name $da -SamAccountName $da -UserPrincipalName $da@$fqdn -GivenName $gn -Surname $sn -DisplayName "$sn, $gn" -Description "Member has Domain Admins rights." -EmployeeID $eID -Server $pdcE -Enabled $false

                                }
                       
                            }
                        Until ($userOK)

                        Write-Host ""
                       
                    $ask = ""
                    $err = ""
                       $ask = Read-Host "Do you want to set a password for $da ?  (Y/N)"
                                
                        If ($ask -eq "Y"){
                                Write-Host ""
                                Write-Host "Password must be at least 14 characters." -ForegroundColor Yellow
                                Write-Host ""

                                Do{Set-ADAccountPassword -Identity $da -Reset -Server $pdcE -ErrorVariable err
                                    If($err.Count -ne 0){Write-Host "The password supplied does not meet complexity requirements." -ForegroundColor Red}}
                                While($err.Count -ne 0)
                                                   
                                If (Get-ADUser -Identity $da -Properties PasswordLastSet,PasswordNeverExpires -Server $pdcE){
                                    Set-ADUser -Identity $da -Enabled $true -Server $pdcE
                                  }
                            }
                                                
                         Else {
                            Write-Host "Because a password is not defined, the account for $fn will be created, but will remain disabled." -ForegroundColor Yellow
                          }
                         
                         Write-Host ""

                         $daDN = (Get-ADUser -Identity $da -Server $pdcE).DistinguishedName
                            
                            Move-ADObject -Identity $daDN -TargetPath "OU=$adminAccts,OU=$domAdmin,OU=$nBn,$dn" -Server $pdcE
                            Add-ADGroupMember -Identity "Admins-AD-ENG" -Members $da -Server $pdcE
                            Write-Host "$da was created and moved to OU=OU=$adminAccts,OU=$domAdmin,OU=$nBn,$dn" -ForegroundColor Green

                         Write-Host ""

                         $choice = $Host.UI.PromptForChoice("Create another Domain Admin account?","",$choices,0)
                    
                        If ( $choice -ne 0 ) {
                        Break
                    }
                
                
                 }
                     
               } 
                
    
    Write-Host ""

###################################################################################
# Rename and disable domain's built-in administrator account

  
    If (($bgAdmin).Enabled -eq $true) {
        
        If ($biAdmin){
            Set-ADUser -Identity $biAdmin -Replace @{samaccountname=$newBIadminName;UserPrincipalName=$newBIadminName} -Description "**Do NOT enable this account.** Built-in account for administering the computer/domain" -Server $pdcE -Enabled 0
            Rename-ADObject -Identity $biAdmin -NewName "BI-Admin-DISABLED" -Server $pdcE
            Write-Host "The built-in administrator account has been renamed and disabled." -ForegroundColor Yellow
            Write-Host "Please use "$bgAdmin.name" or another account to logon in the future." -ForegroundColor Yellow
            }
        Else {Write-Host "The built-in administrator account has been renamed and disabled." -ForegroundColor Yellow
            Write-Host "Please use "$bgAdmin.name" or another account to logon in the future." -ForegroundColor Yellow}
      }

    Else {Write-Host "The "$bgAdmin.name" account is not enabled. The Built-In Admininistrator account will not be renamed nor disabled." -ForegroundColor Red 
            Write-Host "Ensure a password is set for "$bgAdmin.name" and enable it, then re-run this script to complete the above actions." -ForegroundColor Yellow
       }
    Write-Host ""

###################################################################################
# Empty the EA and SA groups

Write-Host "***Empty Enterpise and Schema Admins Groups***" -ForegroundColor Cyan
Write-Host ""
    
    If ($eas = Get-ADGroupMember -Identity "Enterprise Admins"){
    
        ForEach ($ea in $eas){
        Remove-ADGroupMember -Identity "Enterprise Admins" -Members $ea -Confirm:$false
    
    }
    
        Write-Host "Enterprise Admins group emptied." -ForegroundColor Green
        Write-Host ""
    }
    Else{Write-Host "Enterprise Admins group emptied." -ForegroundColor Green}

    If ($sas = Get-ADGroupMember -Identity "Schema Admins"){
    
        ForEach ($sa in $sas){
            Remove-ADGroupMember -Identity "Schema Admins" -Members $sa -Confirm:$false
        }
    
        Write-Host "Schema Admins group emptied." -ForegroundColor Green
        Write-Host ""
            }
    Else{Write-Host "Schema Admins group emptied." -ForegroundColor Green}
Write-Host ""
# End

        
        