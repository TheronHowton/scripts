
<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>

####################################################

function Get-AuthToken {

<#
.SYNOPSIS
This function is used to authenticate with the Graph API REST interface
.DESCRIPTION
The function authenticate with the Graph API Interface with the tenant name
.EXAMPLE
Get-AuthToken
Authenticates you with the Graph API interface
.NOTES
NAME: Get-AuthToken
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    $User
)

$userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User

$tenant = $userUpn.Host

Write-Host "Checking for AzureAD module..."

    $AadModule = Get-Module -Name "AzureAD" -ListAvailable

    if ($AadModule -eq $null) {

        Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
        $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable

    }

    if ($AadModule -eq $null) {
        write-host
        write-host "AzureAD Powershell module not installed..." -f Red
        write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
        write-host "Script can't continue..." -f Red
        write-host
        exit
    }

# Getting path to ActiveDirectory Assemblies
# If the module count is greater than 1 find the latest version

    if($AadModule.count -gt 1){

        $Latest_Version = ($AadModule | select version | Sort-Object)[-1]

        $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }

            # Checking if there are multiple versions of the same module found

            if($AadModule.count -gt 1){

            $aadModule = $AadModule | select -Unique

            }

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

    else {

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

[System.Reflection.Assembly]::LoadFrom($adal) | Out-Null

[System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null

$clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"

$redirectUri = "urn:ietf:wg:oauth:2.0:oob"

$resourceAppIdURI = "https://graph.microsoft.us"

$authority = "https://login.microsoftonline.us/$Tenant"

    try {

    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

    # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
    # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession

    $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"

    $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")

    $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result

        # If the accesstoken is valid then create the authentication header

        if($authResult.AccessToken){

        # Creating header for Authorization token

        $authHeader = @{
            'Content-Type'='application/json'
            'Authorization'="Bearer " + $authResult.AccessToken
            'ExpiresOn'=$authResult.ExpiresOn
            }

        return $authHeader

        }

        else {

        Write-Host
        Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
        Write-Host
        break

        }

    }

    catch {

    write-host $_.Exception.Message -f Red
    write-host $_.Exception.ItemName -f Red
    write-host
    break

    }

}

####################################################

Function Add-DeviceConfigurationPolicy(){

<#
.SYNOPSIS
This function is used to add an device configuration policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a device configuration policy
.EXAMPLE
Add-DeviceConfigurationPolicy -JSON $JSON
Adds a device configuration policy in Intune
.NOTES
NAME: Add-DeviceConfigurationPolicy
#>

[cmdletbinding()]

param
(
    $JSON
)

$graphApiVersion = "Beta"
$DCP_resource = "deviceManagement/deviceConfigurations"
Write-Verbose "Resource: $DCP_resource"

    try {

        if($JSON -eq "" -or $JSON -eq $null){

        write-host "No JSON specified, please specify valid JSON for the Android Policy..." -f Red

        }

        else {

        Test-JSON -JSON $JSON

        $uri = "https://graph.microsoft.us/$graphApiVersion/$($DCP_resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"

        }

    }

    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}

####################################################

Function Test-JSON(){

<#
.SYNOPSIS
This function is used to test if the JSON passed to a REST Post request is valid
.DESCRIPTION
The function tests if the JSON passed to the REST Post is valid
.EXAMPLE
Test-JSON -JSON $JSON
Test if the JSON is valid before calling the Graph REST interface
.NOTES
NAME: Test-AuthHeader
#>

param (

$JSON

)

    try {

    $TestJSON = ConvertFrom-Json $JSON -ErrorAction Stop
    $validJson = $true

    }

    catch {

    $validJson = $false
    $_.Exception

    }

    if (!$validJson){

    Write-Host "Provided JSON isn't in valid JSON format" -f Red
    break

    }

}

####################################################

#region Authentication

write-host

# Checking if authToken exists before running authentication
if($global:authToken){

    # Setting DateTime to Universal time to work in all timezones
    $DateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

        if($TokenExpires -le 0){

        write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
        write-host

            # Defining User Principal Name if not present

            if($User -eq $null -or $User -eq ""){

            $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            Write-Host

            }

        $global:authToken = Get-AuthToken -User $User

        }
}

# Authentication doesn't exist, calling Get-AuthToken function

else {

    if($User -eq $null -or $User -eq ""){

    $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
    Write-Host

    }

# Getting the authorization token
$global:authToken = Get-AuthToken -User $User

}

#endregion

$name = Read-Host "Enter Name of new Endpoint Protection Policy"
$desc = Read-Host "Enter a description for '$name'"
####################################################
$EndpointProtection = @"
{
    "@odata.type":  "#microsoft.graph.windows10EndpointProtectionConfiguration",
    "description":  "For testing. See Theron.",
    "displayName":  "$name",
    "dmaGuardDeviceEnumerationPolicy":  "deviceDefault",
    "xboxServicesEnableXboxGameSaveTask":  false,
    "xboxServicesAccessoryManagementServiceStartupMode":  "manual",
    "xboxServicesLiveAuthManagerServiceStartupMode":  "manual",
    "xboxServicesLiveGameSaveServiceStartupMode":  "manual",
    "xboxServicesLiveNetworkingServiceStartupMode":  "manual",
    "localSecurityOptionsBlockMicrosoftAccounts":  false,
    "localSecurityOptionsBlockRemoteLogonWithBlankPassword":  false,
    "localSecurityOptionsDisableAdministratorAccount":  false,
    "localSecurityOptionsAdministratorAccountName":  null,
    "localSecurityOptionsDisableGuestAccount":  false,
    "localSecurityOptionsGuestAccountName":  null,
    "localSecurityOptionsAllowUndockWithoutHavingToLogon":  false,
    "localSecurityOptionsBlockUsersInstallingPrinterDrivers":  false,
    "localSecurityOptionsBlockRemoteOpticalDriveAccess":  false,
    "localSecurityOptionsFormatAndEjectOfRemovableMediaAllowedUser":  "notConfigured",
    "localSecurityOptionsMachineInactivityLimit":  null,
    "localSecurityOptionsMachineInactivityLimitInMinutes":  null,
    "localSecurityOptionsDoNotRequireCtrlAltDel":  false,
    "localSecurityOptionsHideLastSignedInUser":  false,
    "localSecurityOptionsHideUsernameAtSignIn":  false,
    "localSecurityOptionsLogOnMessageTitle":  null,
    "localSecurityOptionsLogOnMessageText":  null,
    "localSecurityOptionsAllowPKU2UAuthenticationRequests":  false,
    "localSecurityOptionsAllowRemoteCallsToSecurityAccountsManagerHelperBool":  false,
    "localSecurityOptionsAllowRemoteCallsToSecurityAccountsManager":  null,
    "localSecurityOptionsMinimumSessionSecurityForNtlmSspBasedClients":  "none",
    "localSecurityOptionsMinimumSessionSecurityForNtlmSspBasedServers":  "none",
    "lanManagerAuthenticationLevel":  "lmAndNltm",
    "lanManagerWorkstationDisableInsecureGuestLogons":  false,
    "localSecurityOptionsClearVirtualMemoryPageFile":  false,
    "localSecurityOptionsAllowSystemToBeShutDownWithoutHavingToLogOn":  false,
    "localSecurityOptionsAllowUIAccessApplicationElevation":  false,
    "localSecurityOptionsVirtualizeFileAndRegistryWriteFailuresToPerUserLocations":  false,
    "localSecurityOptionsOnlyElevateSignedExecutables":  false,
    "localSecurityOptionsAdministratorElevationPromptBehavior":  "notConfigured",
    "localSecurityOptionsStandardUserElevationPromptBehavior":  "notConfigured",
    "localSecurityOptionsSwitchToSecureDesktopWhenPromptingForElevation":  false,
    "localSecurityOptionsDetectApplicationInstallationsAndPromptForElevation":  false,
    "localSecurityOptionsAllowUIAccessApplicationsForSecureLocations":  false,
    "localSecurityOptionsUseAdminApprovalMode":  false,
    "localSecurityOptionsUseAdminApprovalModeForAdministrators":  false,
    "localSecurityOptionsInformationShownOnLockScreen":  "notConfigured",
    "localSecurityOptionsInformationDisplayedOnLockScreen":  "notConfigured",
    "localSecurityOptionsDisableClientDigitallySignCommunicationsIfServerAgrees":  false,
    "localSecurityOptionsClientDigitallySignCommunicationsAlways":  false,
    "localSecurityOptionsClientSendUnencryptedPasswordToThirdPartySMBServers":  false,
    "localSecurityOptionsDisableServerDigitallySignCommunicationsAlways":  false,
    "localSecurityOptionsDisableServerDigitallySignCommunicationsIfClientAgrees":  false,
    "localSecurityOptionsRestrictAnonymousAccessToNamedPipesAndShares":  false,
    "localSecurityOptionsDoNotAllowAnonymousEnumerationOfSAMAccounts":  false,
    "localSecurityOptionsAllowAnonymousEnumerationOfSAMAccountsAndShares":  false,
    "localSecurityOptionsDoNotStoreLANManagerHashValueOnNextPasswordChange":  false,
    "localSecurityOptionsSmartCardRemovalBehavior":  "noAction",
    "defenderSecurityCenterDisableAppBrowserUI":  false,
    "defenderSecurityCenterDisableFamilyUI":  false,
    "defenderSecurityCenterDisableHealthUI":  false,
    "defenderSecurityCenterDisableNetworkUI":  false,
    "defenderSecurityCenterDisableVirusUI":  false,
    "defenderSecurityCenterDisableAccountUI":  false,
    "defenderSecurityCenterDisableClearTpmUI":  false,
    "defenderSecurityCenterDisableHardwareUI":  false,
    "defenderSecurityCenterDisableNotificationAreaUI":  false,
    "defenderSecurityCenterDisableRansomwareUI":  false,
    "defenderSecurityCenterDisableSecureBootUI":  false,
    "defenderSecurityCenterDisableTroubleshootingUI":  false,
    "defenderSecurityCenterDisableVulnerableTpmFirmwareUpdateUI":  false,
    "defenderSecurityCenterOrganizationDisplayName":  null,
    "defenderSecurityCenterHelpEmail":  null,
    "defenderSecurityCenterHelpPhone":  null,
    "defenderSecurityCenterHelpURL":  null,
    "defenderSecurityCenterNotificationsFromApp":  "notConfigured",
    "defenderSecurityCenterITContactDisplay":  "notConfigured",
    "windowsDefenderTamperProtection":  "notConfigured",
    "firewallBlockStatefulFTP":  false,
    "firewallIdleTimeoutForSecurityAssociationInSeconds":  null,
    "firewallPreSharedKeyEncodingMethod":  "deviceDefault",
    "firewallIPSecExemptionsAllowNeighborDiscovery":  false,
    "firewallIPSecExemptionsAllowICMP":  false,
    "firewallIPSecExemptionsAllowRouterDiscovery":  false,
    "firewallIPSecExemptionsAllowDHCP":  false,
    "firewallCertificateRevocationListCheckMethod":  "deviceDefault",
    "firewallMergeKeyingModuleSettings":  false,
    "firewallPacketQueueingMethod":  "deviceDefault",
    "firewallProfileDomain":  null,
    "firewallProfilePublic":  null,
    "firewallProfilePrivate":  null,
    "defenderAdobeReaderLaunchChildProcess":  "userDefined",
    "defenderAttackSurfaceReductionExcludedPaths":  [

                                                    ],
    "defenderOfficeAppsOtherProcessInjectionType":  "userDefined",
    "defenderOfficeAppsOtherProcessInjection":  "userDefined",
    "defenderOfficeCommunicationAppsLaunchChildProcess":  "userDefined",
    "defenderOfficeAppsExecutableContentCreationOrLaunchType":  "userDefined",
    "defenderOfficeAppsExecutableContentCreationOrLaunch":  "userDefined",
    "defenderOfficeAppsLaunchChildProcessType":  "userDefined",
    "defenderOfficeAppsLaunchChildProcess":  "userDefined",
    "defenderOfficeMacroCodeAllowWin32ImportsType":  "userDefined",
    "defenderOfficeMacroCodeAllowWin32Imports":  "userDefined",
    "defenderScriptObfuscatedMacroCodeType":  "userDefined",
    "defenderScriptObfuscatedMacroCode":  "userDefined",
    "defenderScriptDownloadedPayloadExecutionType":  "userDefined",
    "defenderScriptDownloadedPayloadExecution":  "userDefined",
    "defenderPreventCredentialStealingType":  "userDefined",
    "defenderProcessCreationType":  "userDefined",
    "defenderProcessCreation":  "userDefined",
    "defenderUntrustedUSBProcessType":  "userDefined",
    "defenderUntrustedUSBProcess":  "userDefined",
    "defenderUntrustedExecutableType":  "userDefined",
    "defenderUntrustedExecutable":  "userDefined",
    "defenderEmailContentExecutionType":  "userDefined",
    "defenderEmailContentExecution":  "userDefined",
    "defenderAdvancedRansomewareProtectionType":  "userDefined",
    "defenderGuardMyFoldersType":  "userDefined",
    "defenderGuardedFoldersAllowedAppPaths":  [

                                              ],
    "defenderAdditionalGuardedFolders":  [

                                         ],
    "defenderNetworkProtectionType":  "userDefined",
    "defenderExploitProtectionXml":  null,
    "defenderExploitProtectionXmlFileName":  null,
    "defenderSecurityCenterBlockExploitProtectionOverride":  false,
    "appLockerApplicationControl":  "notConfigured",
    "deviceGuardLocalSystemAuthorityCredentialGuardSettings":  "notConfigured",
    "deviceGuardEnableVirtualizationBasedSecurity":  false,
    "deviceGuardEnableSecureBootWithDMA":  false,
    "deviceGuardSecureBootWithDMA":  "notConfigured",
    "deviceGuardLaunchSystemGuard":  "notConfigured",
    "smartScreenEnableInShell":  false,
    "smartScreenBlockOverrideForFiles":  false,
    "applicationGuardEnabled":  false,
    "applicationGuardEnabledOptions":  "notConfigured",
    "applicationGuardBlockFileTransfer":  "notConfigured",
    "applicationGuardBlockNonEnterpriseContent":  false,
    "applicationGuardAllowPersistence":  false,
    "applicationGuardForceAuditing":  false,
    "applicationGuardBlockClipboardSharing":  "notConfigured",
    "applicationGuardAllowPrintToPDF":  false,
    "applicationGuardAllowPrintToXPS":  false,
    "applicationGuardAllowPrintToLocalPrinters":  false,
    "applicationGuardAllowPrintToNetworkPrinters":  false,
    "applicationGuardAllowVirtualGPU":  false,
    "applicationGuardAllowFileSaveOnHost":  false,
    "bitLockerAllowStandardUserEncryption":  false,
    "bitLockerDisableWarningForOtherDiskEncryption":  false,
    "bitLockerEnableStorageCardEncryptionOnMobile":  false,
    "bitLockerEncryptDevice":  false,
    "bitLockerRecoveryPasswordRotation":  "notConfigured",
    "defenderDisableScanArchiveFiles":  null,
    "defenderAllowScanArchiveFiles":  null,
    "defenderDisableBehaviorMonitoring":  null,
    "defenderAllowBehaviorMonitoring":  null,
    "defenderDisableCloudProtection":  null,
    "defenderAllowCloudProtection":  null,
    "defenderEnableScanIncomingMail":  null,
    "defenderEnableScanMappedNetworkDrivesDuringFullScan":  null,
    "defenderDisableScanRemovableDrivesDuringFullScan":  null,
    "defenderAllowScanRemovableDrivesDuringFullScan":  null,
    "defenderDisableScanDownloads":  null,
    "defenderAllowScanDownloads":  null,
    "defenderDisableIntrusionPreventionSystem":  null,
    "defenderAllowIntrusionPreventionSystem":  null,
    "defenderDisableOnAccessProtection":  null,
    "defenderAllowOnAccessProtection":  null,
    "defenderDisableRealTimeMonitoring":  null,
    "defenderAllowRealTimeMonitoring":  null,
    "defenderDisableScanNetworkFiles":  null,
    "defenderAllowScanNetworkFiles":  null,
    "defenderDisableScanScriptsLoadedInInternetExplorer":  null,
    "defenderAllowScanScriptsLoadedInInternetExplorer":  null,
    "defenderBlockEndUserAccess":  null,
    "defenderAllowEndUserAccess":  null,
    "defenderScanMaxCpuPercentage":  null,
    "defenderCheckForSignaturesBeforeRunningScan":  null,
    "defenderCloudBlockLevel":  null,
    "defenderCloudExtendedTimeoutInSeconds":  null,
    "defenderDaysBeforeDeletingQuarantinedMalware":  null,
    "defenderDisableCatchupFullScan":  null,
    "defenderDisableCatchupQuickScan":  null,
    "defenderEnableLowCpuPriority":  null,
    "defenderFileExtensionsToExclude":  [

                                        ],
    "defenderFilesAndFoldersToExclude":  [

                                         ],
    "defenderProcessesToExclude":  [

                                   ],
    "defenderPotentiallyUnwantedAppAction":  null,
    "defenderScanDirection":  null,
    "defenderScanType":  null,
    "defenderScheduledQuickScanTime":  null,
    "defenderScheduledScanDay":  null,
    "defenderScheduledScanTime":  null,
    "defenderSignatureUpdateIntervalInHours":  null,
    "defenderSubmitSamplesConsentType":  null,
    "defenderDetectedMalwareActions":  null,
    "firewallRules":  [

                      ],
    "userRightsAccessCredentialManagerAsTrustedCaller":  {
                                                             "state":  "notConfigured",
                                                             "localUsersOrGroups":  [

                                                                                    ]
                                                         },
    "userRightsAllowAccessFromNetwork":  {
                                             "state":  "notConfigured",
                                             "localUsersOrGroups":  [

                                                                    ]
                                         },
    "userRightsBlockAccessFromNetwork":  {
                                             "state":  "notConfigured",
                                             "localUsersOrGroups":  [

                                                                    ]
                                         },
    "userRightsActAsPartOfTheOperatingSystem":  {
                                                    "state":  "notConfigured",
                                                    "localUsersOrGroups":  [

                                                                           ]
                                                },
    "userRightsLocalLogOn":  {
                                 "state":  "notConfigured",
                                 "localUsersOrGroups":  [

                                                        ]
                             },
    "userRightsDenyLocalLogOn":  {
                                     "state":  "notConfigured",
                                     "localUsersOrGroups":  [

                                                            ]
                                 },
    "userRightsBackupData":  {
                                 "state":  "notConfigured",
                                 "localUsersOrGroups":  [

                                                        ]
                             },
    "userRightsChangeSystemTime":  {
                                       "state":  "notConfigured",
                                       "localUsersOrGroups":  [

                                                              ]
                                   },
    "userRightsCreateGlobalObjects":  {
                                          "state":  "notConfigured",
                                          "localUsersOrGroups":  [

                                                                 ]
                                      },
    "userRightsCreatePageFile":  {
                                     "state":  "notConfigured",
                                     "localUsersOrGroups":  [

                                                            ]
                                 },
    "userRightsCreatePermanentSharedObjects":  {
                                                   "state":  "notConfigured",
                                                   "localUsersOrGroups":  [

                                                                          ]
                                               },
    "userRightsCreateSymbolicLinks":  {
                                          "state":  "notConfigured",
                                          "localUsersOrGroups":  [

                                                                 ]
                                      },
    "userRightsCreateToken":  {
                                  "state":  "notConfigured",
                                  "localUsersOrGroups":  [

                                                         ]
                              },
    "userRightsDebugPrograms":  {
                                    "state":  "notConfigured",
                                    "localUsersOrGroups":  [

                                                           ]
                                },
    "userRightsRemoteDesktopServicesLogOn":  {
                                                 "state":  "notConfigured",
                                                 "localUsersOrGroups":  [

                                                                        ]
                                             },
    "userRightsDelegation":  {
                                 "state":  "notConfigured",
                                 "localUsersOrGroups":  [

                                                        ]
                             },
    "userRightsGenerateSecurityAudits":  {
                                             "state":  "notConfigured",
                                             "localUsersOrGroups":  [

                                                                    ]
                                         },
    "userRightsImpersonateClient":  {
                                        "state":  "notConfigured",
                                        "localUsersOrGroups":  [

                                                               ]
                                    },
    "userRightsIncreaseSchedulingPriority":  {
                                                 "state":  "notConfigured",
                                                 "localUsersOrGroups":  [

                                                                        ]
                                             },
    "userRightsLoadUnloadDrivers":  {
                                        "state":  "notConfigured",
                                        "localUsersOrGroups":  [

                                                               ]
                                    },
    "userRightsLockMemory":  {
                                 "state":  "notConfigured",
                                 "localUsersOrGroups":  [

                                                        ]
                             },
    "userRightsManageAuditingAndSecurityLogs":  {
                                                    "state":  "notConfigured",
                                                    "localUsersOrGroups":  [

                                                                           ]
                                                },
    "userRightsManageVolumes":  {
                                    "state":  "notConfigured",
                                    "localUsersOrGroups":  [

                                                           ]
                                },
    "userRightsModifyFirmwareEnvironment":  {
                                                "state":  "notConfigured",
                                                "localUsersOrGroups":  [

                                                                       ]
                                            },
    "userRightsModifyObjectLabels":  {
                                         "state":  "notConfigured",
                                         "localUsersOrGroups":  [

                                                                ]
                                     },
    "userRightsProfileSingleProcess":  {
                                           "state":  "notConfigured",
                                           "localUsersOrGroups":  [

                                                                  ]
                                       },
    "userRightsRemoteShutdown":  {
                                     "state":  "notConfigured",
                                     "localUsersOrGroups":  [

                                                            ]
                                 },
    "userRightsRestoreData":  {
                                  "state":  "notConfigured",
                                  "localUsersOrGroups":  [

                                                         ]
                              },
    "userRightsTakeOwnership":  {
                                    "state":  "notConfigured",
                                    "localUsersOrGroups":  [

                                                           ]
                                },
    "bitLockerSystemDrivePolicy":  {
                                       "encryptionMethod":  null,
                                       "startupAuthenticationRequired":  false,
                                       "startupAuthenticationBlockWithoutTpmChip":  false,
                                       "startupAuthenticationTpmUsage":  "blocked",
                                       "startupAuthenticationTpmPinUsage":  "blocked",
                                       "startupAuthenticationTpmKeyUsage":  "blocked",
                                       "startupAuthenticationTpmPinAndKeyUsage":  "blocked",
                                       "minimumPinLength":  null,
                                       "recoveryOptions":  null,
                                       "prebootRecoveryEnableMessageAndUrl":  false,
                                       "prebootRecoveryMessage":  null,
                                       "prebootRecoveryUrl":  null
                                   },
    "bitLockerFixedDrivePolicy":  {
                                      "encryptionMethod":  null,
                                      "requireEncryptionForWriteAccess":  false,
                                      "recoveryOptions":  null
                                  },
    "bitLockerRemovableDrivePolicy":  {
                                          "encryptionMethod":  null,
                                          "requireEncryptionForWriteAccess":  false,
                                          "blockCrossOrganizationWriteAccess":  false
                                      }
}

"@

####################################################


Add-DeviceConfigurationPolicy -Json $EndpointProtection