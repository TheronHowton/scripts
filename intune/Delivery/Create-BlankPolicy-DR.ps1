
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

$name = Read-Host "Enter Name of new Device Restriction Policy"
$desc = Read-Host "Enter a description for '$name'"
####################################################
$DeviceRestriction = @"

{
    "@odata.type":  "#microsoft.graph.windows10GeneralConfiguration",
    "description":  "$desc",
    "displayName":  "$name",
    "taskManagerBlockEndTask":  false,
    "energySaverOnBatteryThresholdPercentage":  null,
    "energySaverPluggedInThresholdPercentage":  null,
    "powerLidCloseActionOnBattery":  "notConfigured",
    "powerLidCloseActionPluggedIn":  "notConfigured",
    "powerButtonActionOnBattery":  "notConfigured",
    "powerButtonActionPluggedIn":  "notConfigured",
    "powerSleepButtonActionOnBattery":  "notConfigured",
    "powerSleepButtonActionPluggedIn":  "notConfigured",
    "powerHybridSleepOnBattery":  "notConfigured",
    "powerHybridSleepPluggedIn":  "notConfigured",
    "windows10AppsForceUpdateSchedule":  null,
    "enableAutomaticRedeployment":  false,
    "microsoftAccountSignInAssistantSettings":  "notConfigured",
    "authenticationAllowSecondaryDevice":  false,
    "authenticationWebSignIn":  "notConfigured",
    "authenticationPreferredAzureADTenantDomainName":  null,
    "cryptographyAllowFipsAlgorithmPolicy":  false,
    "displayAppListWithGdiDPIScalingTurnedOn":  [

                                                ],
    "displayAppListWithGdiDPIScalingTurnedOff":  [

                                                 ],
    "enterpriseCloudPrintDiscoveryEndPoint":  null,
    "enterpriseCloudPrintOAuthAuthority":  null,
    "enterpriseCloudPrintOAuthClientIdentifier":  null,
    "enterpriseCloudPrintResourceIdentifier":  null,
    "enterpriseCloudPrintDiscoveryMaxLimit":  null,
    "enterpriseCloudPrintMopriaDiscoveryResourceIdentifier":  null,
    "experienceDoNotSyncBrowserSettings":  "notConfigured",
    "messagingBlockSync":  false,
    "messagingBlockMMS":  false,
    "messagingBlockRichCommunicationServices":  false,
    "printerNames":  [

                     ],
    "printerDefaultName":  null,
    "printerBlockAddition":  false,
    "searchBlockDiacritics":  false,
    "searchDisableAutoLanguageDetection":  false,
    "searchDisableIndexingEncryptedItems":  false,
    "searchEnableRemoteQueries":  false,
    "searchDisableUseLocation":  false,
    "searchDisableLocation":  false,
    "searchDisableIndexerBackoff":  false,
    "searchDisableIndexingRemovableDrive":  false,
    "searchEnableAutomaticIndexSizeManangement":  false,
    "searchBlockWebResults":  false,
    "findMyFiles":  "notConfigured",
    "securityBlockAzureADJoinedDevicesAutoEncryption":  false,
    "diagnosticsDataSubmissionMode":  "userDefined",
    "oneDriveDisableFileSync":  false,
    "systemTelemetryProxyServer":  null,
    "edgeTelemetryForMicrosoft365Analytics":  "notConfigured",
    "inkWorkspaceAccess":  "notConfigured",
    "inkWorkspaceAccessState":  "notConfigured",
    "inkWorkspaceBlockSuggestedApps":  false,
    "smartScreenEnableAppInstallControl":  false,
    "smartScreenAppInstallControl":  "notConfigured",
    "personalizationDesktopImageUrl":  null,
    "personalizationLockScreenImageUrl":  null,
    "bluetoothAllowedServices":  [

                                 ],
    "bluetoothBlockAdvertising":  false,
    "bluetoothBlockPromptedProximalConnections":  false,
    "bluetoothBlockDiscoverableMode":  false,
    "bluetoothBlockPrePairing":  false,
    "edgeBlockAutofill":  false,
    "edgeBlocked":  false,
    "edgeCookiePolicy":  "userDefined",
    "edgeBlockDeveloperTools":  false,
    "edgeBlockSendingDoNotTrackHeader":  false,
    "edgeBlockExtensions":  false,
    "edgeBlockInPrivateBrowsing":  false,
    "edgeBlockJavaScript":  false,
    "edgeBlockPasswordManager":  false,
    "edgeBlockAddressBarDropdown":  false,
    "edgeBlockCompatibilityList":  false,
    "edgeClearBrowsingDataOnExit":  false,
    "edgeAllowStartPagesModification":  false,
    "edgeDisableFirstRunPage":  false,
    "edgeBlockLiveTileDataCollection":  false,
    "edgeSyncFavoritesWithInternetExplorer":  false,
    "edgeFavoritesListLocation":  null,
    "edgeBlockEditFavorites":  false,
    "edgeNewTabPageURL":  null,
    "edgeHomeButtonConfiguration":  null,
    "edgeHomeButtonConfigurationEnabled":  false,
    "edgeOpensWith":  "specificPages",
    "edgeBlockSideloadingExtensions":  false,
    "edgeRequiredExtensionPackageFamilyNames":  [

                                                ],
    "edgeBlockPrinting":  false,
    "edgeFavoritesBarVisibility":  "notConfigured",
    "edgeBlockSavingHistory":  false,
    "edgeBlockFullScreenMode":  false,
    "edgeBlockWebContentOnNewTabPage":  false,
    "edgeBlockTabPreloading":  false,
    "edgeBlockPrelaunch":  false,
    "edgeShowMessageWhenOpeningInternetExplorerSites":  "notConfigured",
    "edgePreventCertificateErrorOverride":  false,
    "edgeKioskModeRestriction":  "notConfigured",
    "edgeKioskResetAfterIdleTimeInMinutes":  null,
    "cellularBlockDataWhenRoaming":  false,
    "cellularBlockVpn":  false,
    "cellularBlockVpnWhenRoaming":  false,
    "cellularData":  "allowed",
    "defenderBlockEndUserAccess":  false,
    "defenderDaysBeforeDeletingQuarantinedMalware":  null,
    "defenderDetectedMalwareActions":  null,
    "defenderSystemScanSchedule":  "userDefined",
    "defenderFilesAndFoldersToExclude":  [

                                         ],
    "defenderFileExtensionsToExclude":  [

                                        ],
    "defenderScanMaxCpu":  null,
    "defenderMonitorFileActivity":  "userDefined",
    "defenderPotentiallyUnwantedAppAction":  "deviceDefault",
    "defenderPotentiallyUnwantedAppActionSetting":  "userDefined",
    "defenderProcessesToExclude":  [

                                   ],
    "defenderPromptForSampleSubmission":  "userDefined",
    "defenderRequireBehaviorMonitoring":  false,
    "defenderRequireCloudProtection":  false,
    "defenderRequireNetworkInspectionSystem":  false,
    "defenderRequireRealTimeMonitoring":  false,
    "defenderScanArchiveFiles":  false,
    "defenderScanDownloads":  false,
    "defenderScheduleScanEnableLowCpuPriority":  false,
    "defenderDisableCatchupQuickScan":  true,
    "defenderDisableCatchupFullScan":  true,
    "defenderScanNetworkFiles":  false,
    "defenderScanIncomingMail":  false,
    "defenderScanMappedNetworkDrivesDuringFullScan":  false,
    "defenderScanRemovableDrivesDuringFullScan":  false,
    "defenderScanScriptsLoadedInInternetExplorer":  false,
    "defenderSignatureUpdateIntervalInHours":  null,
    "defenderScanType":  "userDefined",
    "defenderScheduledScanTime":  null,
    "defenderScheduledQuickScanTime":  null,
    "defenderCloudBlockLevel":  "notConfigured",
    "defenderCloudExtendedTimeout":  null,
    "defenderCloudExtendedTimeoutInSeconds":  null,
    "defenderBlockOnAccessProtection":  false,
    "defenderSubmitSamplesConsentType":  "sendSafeSamplesAutomatically",
    "lockScreenAllowTimeoutConfiguration":  false,
    "lockScreenBlockActionCenterNotifications":  false,
    "lockScreenBlockCortana":  false,
    "lockScreenBlockToastNotifications":  false,
    "lockScreenTimeoutInSeconds":  null,
    "lockScreenActivateAppsWithVoice":  "notConfigured",
    "passwordBlockSimple":  false,
    "passwordExpirationDays":  null,
    "passwordMinimumLength":  null,
    "passwordMinutesOfInactivityBeforeScreenTimeout":  null,
    "passwordMinimumCharacterSetCount":  null,
    "passwordPreviousPasswordBlockCount":  null,
    "passwordRequired":  false,
    "passwordRequireWhenResumeFromIdleState":  false,
    "passwordRequiredType":  "deviceDefault",
    "passwordSignInFailureCountBeforeFactoryReset":  null,
    "passwordMinimumAgeInDays":  null,
    "privacyAdvertisingId":  "notConfigured",
    "privacyAutoAcceptPairingAndConsentPrompts":  false,
    "privacyDisableLaunchExperience":  false,
    "privacyBlockInputPersonalization":  false,
    "privacyBlockPublishUserActivities":  false,
    "privacyBlockActivityFeed":  false,
    "activateAppsWithVoice":  "notConfigured",
    "startBlockUnpinningAppsFromTaskbar":  false,
    "startMenuAppListVisibility":  "userDefined",
    "startMenuHideChangeAccountSettings":  false,
    "startMenuHideFrequentlyUsedApps":  false,
    "startMenuHideHibernate":  false,
    "startMenuHideLock":  false,
    "startMenuHidePowerButton":  false,
    "startMenuHideRecentJumpLists":  false,
    "startMenuHideRecentlyAddedApps":  false,
    "startMenuHideRestartOptions":  false,
    "startMenuHideShutDown":  false,
    "startMenuHideSignOut":  false,
    "startMenuHideSleep":  false,
    "startMenuHideSwitchAccount":  false,
    "startMenuHideUserTile":  false,
    "startMenuLayoutEdgeAssetsXml":  null,
    "startMenuLayoutXml":  null,
    "startMenuMode":  "userDefined",
    "startMenuPinnedFolderDocuments":  "notConfigured",
    "startMenuPinnedFolderDownloads":  "notConfigured",
    "startMenuPinnedFolderFileExplorer":  "notConfigured",
    "startMenuPinnedFolderHomeGroup":  "notConfigured",
    "startMenuPinnedFolderMusic":  "notConfigured",
    "startMenuPinnedFolderNetwork":  "notConfigured",
    "startMenuPinnedFolderPersonalFolder":  "notConfigured",
    "startMenuPinnedFolderPictures":  "notConfigured",
    "startMenuPinnedFolderSettings":  "notConfigured",
    "startMenuPinnedFolderVideos":  "notConfigured",
    "settingsBlockSettingsApp":  false,
    "settingsBlockSystemPage":  false,
    "settingsBlockDevicesPage":  false,
    "settingsBlockNetworkInternetPage":  false,
    "settingsBlockPersonalizationPage":  false,
    "settingsBlockAccountsPage":  false,
    "settingsBlockTimeLanguagePage":  false,
    "settingsBlockEaseOfAccessPage":  false,
    "settingsBlockPrivacyPage":  false,
    "settingsBlockUpdateSecurityPage":  false,
    "settingsBlockAppsPage":  false,
    "settingsBlockGamingPage":  false,
    "windowsSpotlightBlockConsumerSpecificFeatures":  false,
    "windowsSpotlightBlocked":  false,
    "windowsSpotlightBlockOnActionCenter":  false,
    "windowsSpotlightBlockTailoredExperiences":  false,
    "windowsSpotlightBlockThirdPartyNotifications":  false,
    "windowsSpotlightBlockWelcomeExperience":  false,
    "windowsSpotlightBlockWindowsTips":  false,
    "windowsSpotlightConfigureOnLockScreen":  "notConfigured",
    "networkProxyApplySettingsDeviceWide":  false,
    "networkProxyDisableAutoDetect":  false,
    "networkProxyAutomaticConfigurationUrl":  null,
    "networkProxyServer":  null,
    "accountsBlockAddingNonMicrosoftAccountEmail":  false,
    "antiTheftModeBlocked":  false,
    "bluetoothBlocked":  false,
    "cameraBlocked":  false,
    "connectedDevicesServiceBlocked":  false,
    "certificatesBlockManualRootCertificateInstallation":  false,
    "copyPasteBlocked":  false,
    "cortanaBlocked":  false,
    "deviceManagementBlockFactoryResetOnMobile":  false,
    "deviceManagementBlockManualUnenroll":  false,
    "safeSearchFilter":  "userDefined",
    "edgeBlockPopups":  false,
    "edgeBlockSearchSuggestions":  false,
    "edgeBlockSearchEngineCustomization":  false,
    "edgeBlockSendingIntranetTrafficToInternetExplorer":  false,
    "edgeSendIntranetTrafficToInternetExplorer":  false,
    "edgeRequireSmartScreen":  false,
    "edgeEnterpriseModeSiteListLocation":  null,
    "edgeFirstRunUrl":  null,
    "edgeHomepageUrls":  [

                         ],
    "edgeBlockAccessToAboutFlags":  false,
    "smartScreenBlockPromptOverride":  false,
    "smartScreenBlockPromptOverrideForFiles":  false,
    "webRtcBlockLocalhostIpAddress":  false,
    "internetSharingBlocked":  false,
    "settingsBlockAddProvisioningPackage":  false,
    "settingsBlockRemoveProvisioningPackage":  false,
    "settingsBlockChangeSystemTime":  false,
    "settingsBlockEditDeviceName":  false,
    "settingsBlockChangeRegion":  false,
    "settingsBlockChangeLanguage":  false,
    "settingsBlockChangePowerSleep":  false,
    "locationServicesBlocked":  false,
    "microsoftAccountBlocked":  false,
    "microsoftAccountBlockSettingsSync":  false,
    "nfcBlocked":  false,
    "resetProtectionModeBlocked":  false,
    "screenCaptureBlocked":  false,
    "storageBlockRemovableStorage":  false,
    "storageRequireMobileDeviceEncryption":  false,
    "usbBlocked":  false,
    "voiceRecordingBlocked":  false,
    "wiFiBlockAutomaticConnectHotspots":  false,
    "wiFiBlocked":  false,
    "wiFiBlockManualConfiguration":  false,
    "wiFiScanInterval":  null,
    "wirelessDisplayBlockProjectionToThisDevice":  false,
    "wirelessDisplayBlockUserInputFromReceiver":  false,
    "wirelessDisplayRequirePinForPairing":  false,
    "windowsStoreBlocked":  false,
    "appsAllowTrustedAppsSideloading":  "notConfigured",
    "windowsStoreBlockAutoUpdate":  false,
    "developerUnlockSetting":  "notConfigured",
    "sharedUserAppDataAllowed":  false,
    "appsBlockWindowsStoreOriginatedApps":  false,
    "windowsStoreEnablePrivateStoreOnly":  false,
    "storageRestrictAppDataToSystemVolume":  false,
    "storageRestrictAppInstallToSystemVolume":  false,
    "gameDvrBlocked":  false,
    "experienceBlockDeviceDiscovery":  false,
    "experienceBlockErrorDialogWhenNoSIM":  false,
    "experienceBlockTaskSwitcher":  false,
    "logonBlockFastUserSwitching":  false,
    "tenantLockdownRequireNetworkDuringOutOfBoxExperience":  false,
    "appManagementMSIAllowUserControlOverInstall":  false,
    "appManagementMSIAlwaysInstallWithElevatedPrivileges":  false,
    "dataProtectionBlockDirectMemoryAccess":  true,
    "appManagementPackageFamilyNamesToLaunchAfterLogOn":  [

                                                          ],
    "uninstallBuiltInApps":  false,
    "configureTimeZone":  null,
    "edgeSearchEngine":  {
                             "@odata.type":  "#microsoft.graph.edgeSearchEngine",
                             "edgeSearchEngineType":  "default"
                         }
}
"@

####################################################

Add-DeviceConfigurationPolicy -Json $DeviceRestriction