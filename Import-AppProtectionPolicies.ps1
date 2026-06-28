<#
    .SYNOPSIS
    Imports 24 Intune policies (App Protection, Compliance, Device Configuration)
    and assigns the EUD scope tag. No external JSON files or specific path required.

    .PARAMETER ScopeTagName
    Display name of the Intune scope tag to assign to every policy. Defaults to "EUD".

    .NOTES
    Required Graph scopes:
        DeviceManagementApps.ReadWrite.All
        DeviceManagementConfiguration.ReadWrite.All
        DeviceManagementRBAC.Read.All

    Required modules (installed automatically if missing):
        Microsoft.Graph.Authentication

    .EXAMPLE
    .\Import-AppProtectionPolicies.ps1
    .\Import-AppProtectionPolicies.ps1 -ScopeTagName "EUD"
#>
[CmdletBinding()]
param(
    [string] $ScopeTagName = 'EUD'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Disclaimer
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '===============================================================' -ForegroundColor Yellow
Write-Host '  DISCLAIMER' -ForegroundColor Yellow
Write-Host '===============================================================' -ForegroundColor Yellow
Write-Host '  This script creates Intune policies in your Microsoft tenant' -ForegroundColor Yellow
Write-Host '  via the Microsoft Graph API.' -ForegroundColor Yellow
Write-Host ''
Write-Host '  - Run this script only in a tenant you are authorised to'    -ForegroundColor Yellow
Write-Host '    manage and only with an account that holds the necessary'   -ForegroundColor Yellow
Write-Host '    Intune Administrator or equivalent permissions.'            -ForegroundColor Yellow
Write-Host '  - Review all embedded policy definitions before running.'     -ForegroundColor Yellow
Write-Host '  - Existing policies with matching display names are skipped.' -ForegroundColor Yellow
Write-Host '  - The author accepts no liability for unintended changes.'    -ForegroundColor Yellow
Write-Host '===============================================================' -ForegroundColor Yellow
Write-Host ''

# ---------------------------------------------------------------------------
# Prerequisites - NuGet provider
# ---------------------------------------------------------------------------
Write-Host 'Checking prerequisites...' -ForegroundColor White

if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue |
          Where-Object { $_.Version -ge '2.8.5.208' })) {
    Write-Host '  Installing NuGet provider...' -ForegroundColor Yellow
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208 -Force -Scope CurrentUser | Out-Null
    Write-Host '  NuGet provider installed.' -ForegroundColor Green
}
else {
    Write-Host '  NuGet provider OK.' -ForegroundColor Green
}

# Prerequisites - PowerShell modules
foreach ($module in @('Microsoft.Graph.Authentication')) {
    if (-not (Get-Module -Name $module -ListAvailable)) {
        Write-Host "  Installing module '$module'..." -ForegroundColor Yellow
        Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
        Write-Host "  Module '$module' installed." -ForegroundColor Green
    }
    else {
        Write-Host "  Module '$module' OK." -ForegroundColor Green
    }
    Import-Module -Name $module -ErrorAction Stop
}

Write-Host '  Prerequisites OK.' -ForegroundColor Green
Write-Host ''

# ---------------------------------------------------------------------------
# Interactive Graph authentication
# ---------------------------------------------------------------------------
Write-Host 'Connecting to Microsoft Graph...' -ForegroundColor White
Write-Host '  A browser window will open for interactive sign-in.' -ForegroundColor DarkGray

Connect-MgGraph -Scopes 'DeviceManagementApps.ReadWrite.All',
                         'DeviceManagementConfiguration.ReadWrite.All',
                         'DeviceManagementRBAC.Read.All' `
    -NoWelcome -ErrorAction Stop

$ctx = Get-MgContext
Write-Host ''
Write-Host '  Signed in as : ' -NoNewline -ForegroundColor Green
Write-Host $ctx.Account
Write-Host '  Tenant ID    : ' -NoNewline -ForegroundColor Green
Write-Host $ctx.TenantId
Write-Host ''

# ---------------------------------------------------------------------------
# Resolve scope tag
# ---------------------------------------------------------------------------
$escapedTag  = $ScopeTagName -replace "'", "''"
$tagResponse = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags?`$filter=displayName eq '$escapedTag'"
$scopeTag = $tagResponse.value | Select-Object -First 1
if (-not $scopeTag) { throw "Scope tag '$ScopeTagName' not found in Intune." }
Write-Host "Scope tag '$ScopeTagName' -> $($scopeTag.id)" -ForegroundColor DarkGray
Write-Host ''

# ---------------------------------------------------------------------------
# Endpoint routing helper
# ---------------------------------------------------------------------------
function Get-PolicyEndpoint {
    param([string] $ODataType)
    if ($ODataType -match 'ManagedAppProtection') {
        return 'https://graph.microsoft.com/beta/deviceAppManagement/managedAppPolicies'
    }
    elseif ($ODataType -match 'CompliancePolicy') {
        return 'https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies'
    }
    else {
        return 'https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations'
    }
}

# ---------------------------------------------------------------------------
# Pre-fetch all existing policy names from all 3 endpoints
# ---------------------------------------------------------------------------
Write-Host 'Fetching existing policies...' -ForegroundColor White
$existingNames = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)

foreach ($ep in @(
    'https://graph.microsoft.com/beta/deviceAppManagement/managedAppPolicies',
    'https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies',
    'https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations'
)) {
    $resp = Invoke-MgGraphRequest -Method GET -Uri $ep
    foreach ($item in $resp.value) {
        $null = $existingNames.Add($item.displayName)
    }
}
Write-Host "  Found $($existingNames.Count) existing policies." -ForegroundColor DarkGray
Write-Host ''

# ---------------------------------------------------------------------------
# Policy definitions (24 policies embedded - no external files needed)
# ---------------------------------------------------------------------------
$policyJsons = @(

# === 1. Android Enterprise Basic Data Protection v1.7 ===
@'
{
    "displayName":  "Android Enterprise Basic Data Protection v1.7",
    "description":  "This app protection policy ensures that apps with work or school account data are protected with a PIN, encrypted, validates Android device attestation, and enables selective wipe operations.",
    "periodOfflineBeforeAccessCheck":  "PT12H",
    "periodOnlineBeforeAccessCheck":  "PT30M",
    "allowedInboundDataTransferSources":  "allApps",
    "allowedOutboundDataTransferDestinations":  "allApps",
    "organizationalCredentialsRequired":  false,
    "allowedOutboundClipboardSharingLevel":  "allApps",
    "dataBackupBlocked":  false,
    "deviceComplianceRequired":  true,
    "managedBrowserToOpenLinksRequired":  false,
    "saveAsBlocked":  false,
    "periodOfflineBeforeWipeIsEnforced":  "P90D",
    "pinRequired":  true,
    "maximumPinRetries":  5,
    "simplePinBlocked":  false,
    "minimumPinLength":  4,
    "pinCharacterSet":  "numeric",
    "periodBeforePinReset":  "PT0S",
    "allowedDataStorageLocations":  [],
    "contactSyncBlocked":  false,
    "printBlocked":  false,
    "fingerprintBlocked":  false,
    "disableAppPinIfDevicePinIsSet":  false,
    "maximumRequiredOsVersion":  null,
    "maximumWarningOsVersion":  null,
    "maximumWipeOsVersion":  null,
    "minimumRequiredOsVersion":  null,
    "minimumWarningOsVersion":  null,
    "minimumRequiredAppVersion":  null,
    "minimumWarningAppVersion":  null,
    "minimumWipeOsVersion":  null,
    "minimumWipeAppVersion":  null,
    "appActionIfDeviceComplianceRequired":  "block",
    "appActionIfMaximumPinRetriesExceeded":  "block",
    "pinRequiredInsteadOfBiometricTimeout":  "PT12H",
    "allowedOutboundClipboardSharingExceptionLength":  0,
    "notificationRestriction":  "allow",
    "previousPinBlockCount":  0,
    "managedBrowser":  "notConfigured",
    "maximumAllowedDeviceThreatLevel":  "notConfigured",
    "mobileThreatDefenseRemediationAction":  "block",
    "blockDataIngestionIntoOrganizationDocuments":  false,
    "allowedDataIngestionLocations":  [ "oneDriveForBusiness", "sharePoint", "camera" ],
    "appActionIfUnableToAuthenticateUser":  null,
    "dialerRestrictionLevel":  "allApps",
    "targetedAppManagementLevels":  "unspecified",
    "appGroupType":  "allCoreMicrosoftApps",
    "screenCaptureBlocked":  false,
    "disableAppEncryptionIfDeviceEncryptionIsEnabled":  false,
    "encryptAppData":  true,
    "minimumRequiredPatchVersion":  "0000-00-00",
    "minimumWarningPatchVersion":  "0000-00-00",
    "minimumWipePatchVersion":  "0000-00-00",
    "allowedAndroidDeviceManufacturers":  null,
    "appActionIfAndroidDeviceManufacturerNotAllowed":  "block",
    "requiredAndroidSafetyNetDeviceAttestationType":  "basicIntegrityAndDeviceCertification",
    "appActionIfAndroidSafetyNetDeviceAttestationFailed":  "block",
    "requiredAndroidSafetyNetAppsVerificationType":  "enabled",
    "appActionIfAndroidSafetyNetAppsVerificationFailed":  "block",
    "customBrowserPackageId":  "",
    "customBrowserDisplayName":  "",
    "minimumRequiredCompanyPortalVersion":  null,
    "minimumWarningCompanyPortalVersion":  null,
    "minimumWipeCompanyPortalVersion":  null,
    "keyboardsRestricted":  false,
    "allowedAndroidDeviceModels":  [],
    "appActionIfAndroidDeviceModelNotAllowed":  "block",
    "customDialerAppPackageId":  null,
    "customDialerAppDisplayName":  null,
    "biometricAuthenticationBlocked":  false,
    "requiredAndroidSafetyNetEvaluationType":  "basic",
    "blockAfterCompanyPortalUpdateDeferralInDays":  0,
    "warnAfterCompanyPortalUpdateDeferralInDays":  0,
    "wipeAfterCompanyPortalUpdateDeferralInDays":  0,
    "deviceLockRequired":  true,
    "appActionIfDeviceLockNotSet":  "block",
    "connectToVpnOnLaunch":  false,
    "exemptedAppPackages":  [],
    "approvedKeyboards":  [],
    "@odata.type":  "#microsoft.graph.androidManagedAppProtection"
}
'@

# === 2. iOS/iPadOS Enterprise Basic Data Protection v1.2 ===
@'
{
    "displayName":  "iOS/iPadOS Enterprise Basic Data Protection v1.2",
    "description":  "This app protection policy ensures that apps with work or school account data are protected with a PIN, encrypted, and enables selective wipe operations.",
    "periodOfflineBeforeAccessCheck":  "PT12H",
    "periodOnlineBeforeAccessCheck":  "PT30M",
    "allowedInboundDataTransferSources":  "allApps",
    "allowedOutboundDataTransferDestinations":  "allApps",
    "organizationalCredentialsRequired":  false,
    "allowedOutboundClipboardSharingLevel":  "allApps",
    "dataBackupBlocked":  false,
    "deviceComplianceRequired":  true,
    "managedBrowserToOpenLinksRequired":  false,
    "saveAsBlocked":  false,
    "periodOfflineBeforeWipeIsEnforced":  "P90D",
    "pinRequired":  true,
    "maximumPinRetries":  5,
    "simplePinBlocked":  false,
    "minimumPinLength":  4,
    "pinCharacterSet":  "numeric",
    "periodBeforePinReset":  "PT0S",
    "allowedDataStorageLocations":  [],
    "contactSyncBlocked":  false,
    "printBlocked":  false,
    "fingerprintBlocked":  false,
    "disableAppPinIfDevicePinIsSet":  false,
    "maximumRequiredOsVersion":  null,
    "maximumWarningOsVersion":  null,
    "maximumWipeOsVersion":  null,
    "minimumRequiredOsVersion":  null,
    "minimumWarningOsVersion":  null,
    "minimumRequiredAppVersion":  null,
    "minimumWarningAppVersion":  null,
    "minimumWipeOsVersion":  null,
    "minimumWipeAppVersion":  null,
    "appActionIfDeviceComplianceRequired":  "block",
    "appActionIfMaximumPinRetriesExceeded":  "block",
    "pinRequiredInsteadOfBiometricTimeout":  "PT12H",
    "allowedOutboundClipboardSharingExceptionLength":  0,
    "notificationRestriction":  "allow",
    "previousPinBlockCount":  0,
    "managedBrowser":  "notConfigured",
    "maximumAllowedDeviceThreatLevel":  "notConfigured",
    "mobileThreatDefenseRemediationAction":  "block",
    "blockDataIngestionIntoOrganizationDocuments":  false,
    "allowedDataIngestionLocations":  [ "oneDriveForBusiness", "sharePoint", "camera" ],
    "appActionIfUnableToAuthenticateUser":  null,
    "dialerRestrictionLevel":  "allApps",
    "targetedAppManagementLevels":  "unspecified",
    "appGroupType":  "allCoreMicrosoftApps",
    "appDataEncryptionType":  "whenDeviceLocked",
    "minimumRequiredSdkVersion":  null,
    "faceIdBlocked":  false,
    "minimumWipeSdkVersion":  null,
    "allowedIosDeviceModels":  null,
    "appActionIfIosDeviceModelNotAllowed":  "block",
    "thirdPartyKeyboardsBlocked":  false,
    "filterOpenInToOnlyManagedApps":  false,
    "disableProtectionOfManagedOutboundOpenInData":  false,
    "protectInboundDataFromUnknownSources":  false,
    "customBrowserProtocol":  "",
    "customDialerAppProtocol":  null,
    "exemptedAppProtocols":  [
        { "name": "Default", "value": "skype;app-settings;calshow;itms;itmss;itms-apps;itms-appss;itms-services;" }
    ],
    "@odata.type":  "#microsoft.graph.iosManagedAppProtection"
}
'@

# === 3. Android Enterprise Enhanced Data Protection v1.9 ===
@'
{
    "displayName":  "Android Enterprise Enhanced Data Protection v1.9",
    "description":  "This app protection policy introduces data leakage prevention mechanisms and minimum OS requirements. This is the configuration that is applicable to most mobile users accessing work or school data.",
    "periodOfflineBeforeAccessCheck":  "PT12H",
    "periodOnlineBeforeAccessCheck":  "PT30M",
    "allowedInboundDataTransferSources":  "allApps",
    "allowedOutboundDataTransferDestinations":  "managedApps",
    "organizationalCredentialsRequired":  false,
    "allowedOutboundClipboardSharingLevel":  "managedAppsWithPasteIn",
    "dataBackupBlocked":  true,
    "deviceComplianceRequired":  true,
    "managedBrowserToOpenLinksRequired":  true,
    "saveAsBlocked":  true,
    "periodOfflineBeforeWipeIsEnforced":  "P90D",
    "pinRequired":  true,
    "maximumPinRetries":  5,
    "simplePinBlocked":  false,
    "minimumPinLength":  4,
    "pinCharacterSet":  "numeric",
    "periodBeforePinReset":  "PT0S",
    "allowedDataStorageLocations":  [ "oneDriveForBusiness", "sharePoint" ],
    "contactSyncBlocked":  false,
    "printBlocked":  false,
    "fingerprintBlocked":  false,
    "disableAppPinIfDevicePinIsSet":  false,
    "maximumRequiredOsVersion":  null,
    "maximumWarningOsVersion":  null,
    "maximumWipeOsVersion":  null,
    "minimumRequiredOsVersion":  "9.0",
    "minimumWarningOsVersion":  null,
    "minimumRequiredAppVersion":  null,
    "minimumWarningAppVersion":  null,
    "minimumWipeOsVersion":  null,
    "minimumWipeAppVersion":  null,
    "appActionIfDeviceComplianceRequired":  "block",
    "appActionIfMaximumPinRetriesExceeded":  "block",
    "pinRequiredInsteadOfBiometricTimeout":  "PT12H",
    "allowedOutboundClipboardSharingExceptionLength":  0,
    "notificationRestriction":  "blockOrganizationalData",
    "previousPinBlockCount":  0,
    "managedBrowser":  "microsoftEdge",
    "maximumAllowedDeviceThreatLevel":  "notConfigured",
    "mobileThreatDefenseRemediationAction":  "block",
    "blockDataIngestionIntoOrganizationDocuments":  false,
    "allowedDataIngestionLocations":  [ "oneDriveForBusiness", "sharePoint", "camera" ],
    "appActionIfUnableToAuthenticateUser":  "block",
    "dialerRestrictionLevel":  "allApps",
    "targetedAppManagementLevels":  "unspecified",
    "appGroupType":  "allCoreMicrosoftApps",
    "screenCaptureBlocked":  true,
    "disableAppEncryptionIfDeviceEncryptionIsEnabled":  false,
    "encryptAppData":  true,
    "minimumRequiredPatchVersion":  null,
    "minimumWarningPatchVersion":  null,
    "minimumWipePatchVersion":  null,
    "allowedAndroidDeviceManufacturers":  null,
    "appActionIfAndroidDeviceManufacturerNotAllowed":  "block",
    "requiredAndroidSafetyNetDeviceAttestationType":  "basicIntegrityAndDeviceCertification",
    "appActionIfAndroidSafetyNetDeviceAttestationFailed":  "block",
    "requiredAndroidSafetyNetAppsVerificationType":  "enabled",
    "appActionIfAndroidSafetyNetAppsVerificationFailed":  "block",
    "customBrowserPackageId":  "",
    "customBrowserDisplayName":  "",
    "minimumRequiredCompanyPortalVersion":  null,
    "minimumWarningCompanyPortalVersion":  null,
    "minimumWipeCompanyPortalVersion":  null,
    "keyboardsRestricted":  false,
    "allowedAndroidDeviceModels":  [],
    "appActionIfAndroidDeviceModelNotAllowed":  "block",
    "customDialerAppPackageId":  null,
    "customDialerAppDisplayName":  null,
    "biometricAuthenticationBlocked":  true,
    "requiredAndroidSafetyNetEvaluationType":  "hardwareBacked",
    "blockAfterCompanyPortalUpdateDeferralInDays":  0,
    "warnAfterCompanyPortalUpdateDeferralInDays":  0,
    "wipeAfterCompanyPortalUpdateDeferralInDays":  0,
    "deviceLockRequired":  true,
    "appActionIfDeviceLockNotSet":  "block",
    "connectToVpnOnLaunch":  false,
    "exemptedAppPackages":  [],
    "approvedKeyboards":  [],
    "@odata.type":  "#microsoft.graph.androidManagedAppProtection"
}
'@

# === 4. iOS/iPadOS Enterprise Enhanced Data Protection v1.5 ===
@'
{
    "displayName":  "iOS/iPadOS Enterprise Enhanced Data Protection v1.5",
    "description":  "This app protection policy introduces data leakage prevention mechanisms and minimum OS requirements. This is the configuration that is applicable to most mobile users accessing work or school data.",
    "periodOfflineBeforeAccessCheck":  "PT12H",
    "periodOnlineBeforeAccessCheck":  "PT30M",
    "allowedInboundDataTransferSources":  "allApps",
    "allowedOutboundDataTransferDestinations":  "managedApps",
    "organizationalCredentialsRequired":  false,
    "allowedOutboundClipboardSharingLevel":  "managedAppsWithPasteIn",
    "dataBackupBlocked":  true,
    "deviceComplianceRequired":  true,
    "managedBrowserToOpenLinksRequired":  true,
    "saveAsBlocked":  true,
    "periodOfflineBeforeWipeIsEnforced":  "P90D",
    "pinRequired":  true,
    "maximumPinRetries":  5,
    "simplePinBlocked":  false,
    "minimumPinLength":  4,
    "pinCharacterSet":  "numeric",
    "periodBeforePinReset":  "PT0S",
    "allowedDataStorageLocations":  [ "oneDriveForBusiness", "sharePoint" ],
    "contactSyncBlocked":  false,
    "printBlocked":  false,
    "fingerprintBlocked":  false,
    "disableAppPinIfDevicePinIsSet":  false,
    "maximumRequiredOsVersion":  null,
    "maximumWarningOsVersion":  null,
    "maximumWipeOsVersion":  null,
    "minimumRequiredOsVersion":  "14.8",
    "minimumWarningOsVersion":  null,
    "minimumRequiredAppVersion":  null,
    "minimumWarningAppVersion":  null,
    "minimumWipeOsVersion":  null,
    "minimumWipeAppVersion":  null,
    "appActionIfDeviceComplianceRequired":  "block",
    "appActionIfMaximumPinRetriesExceeded":  "block",
    "pinRequiredInsteadOfBiometricTimeout":  "PT12H",
    "allowedOutboundClipboardSharingExceptionLength":  0,
    "notificationRestriction":  "blockOrganizationalData",
    "previousPinBlockCount":  0,
    "managedBrowser":  "microsoftEdge",
    "maximumAllowedDeviceThreatLevel":  "notConfigured",
    "mobileThreatDefenseRemediationAction":  "block",
    "blockDataIngestionIntoOrganizationDocuments":  false,
    "allowedDataIngestionLocations":  [ "oneDriveForBusiness", "sharePoint", "camera" ],
    "appActionIfUnableToAuthenticateUser":  "block",
    "dialerRestrictionLevel":  "allApps",
    "targetedAppManagementLevels":  "unspecified",
    "appGroupType":  "allCoreMicrosoftApps",
    "appDataEncryptionType":  "whenDeviceLocked",
    "minimumRequiredSdkVersion":  null,
    "faceIdBlocked":  false,
    "minimumWipeSdkVersion":  null,
    "allowedIosDeviceModels":  null,
    "appActionIfIosDeviceModelNotAllowed":  "block",
    "thirdPartyKeyboardsBlocked":  false,
    "filterOpenInToOnlyManagedApps":  false,
    "disableProtectionOfManagedOutboundOpenInData":  false,
    "protectInboundDataFromUnknownSources":  false,
    "customBrowserProtocol":  "",
    "customDialerAppProtocol":  null,
    "exemptedAppProtocols":  [
        { "name": "Default", "value": "skype;app-settings;calshow;itms;itmss;itms-apps;itms-appss;itms-services;" }
    ],
    "@odata.type":  "#microsoft.graph.iosManagedAppProtection"
}
'@

# === 5. Android Enterprise High Data Protection v1.9 ===
@'
{
    "displayName":  "Android Enterprise High Data Protection v1.9",
    "description":  "This app protection policy is for devices used by specific users or groups who are uniquely high risk (for example, users who handle highly sensitive data where unauthorized disclosure causes considerable material loss to the organization).",
    "periodOfflineBeforeAccessCheck":  "PT12H",
    "periodOnlineBeforeAccessCheck":  "PT30M",
    "allowedInboundDataTransferSources":  "managedApps",
    "allowedOutboundDataTransferDestinations":  "managedApps",
    "organizationalCredentialsRequired":  false,
    "allowedOutboundClipboardSharingLevel":  "managedAppsWithPasteIn",
    "dataBackupBlocked":  true,
    "deviceComplianceRequired":  true,
    "managedBrowserToOpenLinksRequired":  true,
    "saveAsBlocked":  true,
    "periodOfflineBeforeWipeIsEnforced":  "P90D",
    "pinRequired":  true,
    "maximumPinRetries":  5,
    "simplePinBlocked":  true,
    "minimumPinLength":  6,
    "pinCharacterSet":  "numeric",
    "periodBeforePinReset":  "P365D",
    "allowedDataStorageLocations":  [ "oneDriveForBusiness", "sharePoint" ],
    "contactSyncBlocked":  false,
    "printBlocked":  true,
    "fingerprintBlocked":  false,
    "disableAppPinIfDevicePinIsSet":  false,
    "maximumRequiredOsVersion":  "11.0",
    "maximumWarningOsVersion":  null,
    "maximumWipeOsVersion":  null,
    "minimumRequiredOsVersion":  "9.0",
    "minimumWarningOsVersion":  null,
    "minimumRequiredAppVersion":  null,
    "minimumWarningAppVersion":  null,
    "minimumWipeOsVersion":  null,
    "minimumWipeAppVersion":  null,
    "appActionIfDeviceComplianceRequired":  "wipe",
    "appActionIfMaximumPinRetriesExceeded":  "block",
    "pinRequiredInsteadOfBiometricTimeout":  "PT12H",
    "allowedOutboundClipboardSharingExceptionLength":  0,
    "notificationRestriction":  "blockOrganizationalData",
    "previousPinBlockCount":  0,
    "managedBrowser":  "microsoftEdge",
    "maximumAllowedDeviceThreatLevel":  "secured",
    "mobileThreatDefenseRemediationAction":  "block",
    "blockDataIngestionIntoOrganizationDocuments":  true,
    "allowedDataIngestionLocations":  [ "oneDriveForBusiness", "sharePoint" ],
    "appActionIfUnableToAuthenticateUser":  "block",
    "dialerRestrictionLevel":  "managedApps",
    "targetedAppManagementLevels":  "unspecified",
    "appGroupType":  "allCoreMicrosoftApps",
    "screenCaptureBlocked":  true,
    "disableAppEncryptionIfDeviceEncryptionIsEnabled":  false,
    "encryptAppData":  true,
    "minimumRequiredPatchVersion":  "0000-00-00",
    "minimumWarningPatchVersion":  "0000-00-00",
    "minimumWipePatchVersion":  "0000-00-00",
    "allowedAndroidDeviceManufacturers":  null,
    "appActionIfAndroidDeviceManufacturerNotAllowed":  "block",
    "requiredAndroidSafetyNetDeviceAttestationType":  "basicIntegrityAndDeviceCertification",
    "appActionIfAndroidSafetyNetDeviceAttestationFailed":  "block",
    "requiredAndroidSafetyNetAppsVerificationType":  "enabled",
    "appActionIfAndroidSafetyNetAppsVerificationFailed":  "block",
    "customBrowserPackageId":  "",
    "customBrowserDisplayName":  "",
    "minimumRequiredCompanyPortalVersion":  null,
    "minimumWarningCompanyPortalVersion":  null,
    "minimumWipeCompanyPortalVersion":  null,
    "keyboardsRestricted":  true,
    "allowedAndroidDeviceModels":  [],
    "appActionIfAndroidDeviceModelNotAllowed":  "block",
    "customDialerAppPackageId":  "",
    "customDialerAppDisplayName":  "",
    "biometricAuthenticationBlocked":  false,
    "requiredAndroidSafetyNetEvaluationType":  "hardwareBacked",
    "blockAfterCompanyPortalUpdateDeferralInDays":  0,
    "warnAfterCompanyPortalUpdateDeferralInDays":  0,
    "wipeAfterCompanyPortalUpdateDeferralInDays":  0,
    "deviceLockRequired":  true,
    "appActionIfDeviceLockNotSet":  "block",
    "connectToVpnOnLaunch":  false,
    "exemptedAppPackages":  [],
    "approvedKeyboards":  [
        { "name": "com.google.android.inputmethod.latin",      "value": "Gboard - the Google Keyboard" },
        { "name": "com.touchtype.swiftkey",                    "value": "SwiftKey Keyboard" },
        { "name": "com.sec.android.inputmethod",               "value": "Samsung Keyboard" },
        { "name": "com.google.android.apps.inputmethod.hindi", "value": "Google Indic Keyboard" },
        { "name": "com.google.android.inputmethod.pinyin",     "value": "Google Pinyin Input" },
        { "name": "com.google.android.inputmethod.japanese",   "value": "Google Japanese Input" },
        { "name": "com.google.android.inputmethod.korean",     "value": "Google Korean Input" },
        { "name": "com.google.android.apps.handwriting.ime",   "value": "Google Handwriting Input" },
        { "name": "com.google.android.googlequicksearchbox",   "value": "Google voice typing" },
        { "name": "com.samsung.android.svoiceime",             "value": "Samsung voice input" },
        { "name": "com.samsung.android.honeyboard",            "value": "Samsung Keyboard" }
    ],
    "@odata.type":  "#microsoft.graph.androidManagedAppProtection"
}
'@

# === 6. iOS/iPadOS Enterprise High Data Protection v1.5 ===
@'
{
    "displayName":  "iOS/iPadOS Enterprise High Data Protection v1.5",
    "description":  "This app protection policy is for devices used by specific users or groups who are uniquely high risk (for example, users who handle highly sensitive data where unauthorized disclosure causes considerable material loss to the organization).",
    "periodOfflineBeforeAccessCheck":  "PT12H",
    "periodOnlineBeforeAccessCheck":  "PT30M",
    "allowedInboundDataTransferSources":  "managedApps",
    "allowedOutboundDataTransferDestinations":  "managedApps",
    "organizationalCredentialsRequired":  false,
    "allowedOutboundClipboardSharingLevel":  "managedAppsWithPasteIn",
    "dataBackupBlocked":  true,
    "deviceComplianceRequired":  true,
    "managedBrowserToOpenLinksRequired":  true,
    "saveAsBlocked":  true,
    "periodOfflineBeforeWipeIsEnforced":  "P90D",
    "pinRequired":  true,
    "maximumPinRetries":  5,
    "simplePinBlocked":  true,
    "minimumPinLength":  6,
    "pinCharacterSet":  "numeric",
    "periodBeforePinReset":  "P365D",
    "allowedDataStorageLocations":  [ "oneDriveForBusiness", "sharePoint" ],
    "contactSyncBlocked":  false,
    "printBlocked":  true,
    "fingerprintBlocked":  false,
    "disableAppPinIfDevicePinIsSet":  false,
    "maximumRequiredOsVersion":  "15.0",
    "maximumWarningOsVersion":  null,
    "maximumWipeOsVersion":  null,
    "minimumRequiredOsVersion":  "14.8",
    "minimumWarningOsVersion":  null,
    "minimumRequiredAppVersion":  null,
    "minimumWarningAppVersion":  null,
    "minimumWipeOsVersion":  null,
    "minimumWipeAppVersion":  null,
    "appActionIfDeviceComplianceRequired":  "wipe",
    "appActionIfMaximumPinRetriesExceeded":  "block",
    "pinRequiredInsteadOfBiometricTimeout":  "PT12H",
    "allowedOutboundClipboardSharingExceptionLength":  0,
    "notificationRestriction":  "blockOrganizationalData",
    "previousPinBlockCount":  0,
    "managedBrowser":  "microsoftEdge",
    "maximumAllowedDeviceThreatLevel":  "secured",
    "mobileThreatDefenseRemediationAction":  "block",
    "blockDataIngestionIntoOrganizationDocuments":  true,
    "allowedDataIngestionLocations":  [ "oneDriveForBusiness", "sharePoint" ],
    "appActionIfUnableToAuthenticateUser":  "block",
    "dialerRestrictionLevel":  "customApp",
    "targetedAppManagementLevels":  "unspecified",
    "appGroupType":  "allCoreMicrosoftApps",
    "appDataEncryptionType":  "whenDeviceLocked",
    "minimumRequiredSdkVersion":  null,
    "faceIdBlocked":  false,
    "minimumWipeSdkVersion":  null,
    "allowedIosDeviceModels":  null,
    "appActionIfIosDeviceModelNotAllowed":  "block",
    "thirdPartyKeyboardsBlocked":  true,
    "filterOpenInToOnlyManagedApps":  false,
    "disableProtectionOfManagedOutboundOpenInData":  false,
    "protectInboundDataFromUnknownSources":  false,
    "customBrowserProtocol":  "",
    "customDialerAppProtocol":  "replace_with_dialer_app_url_scheme",
    "exemptedAppProtocols":  [
        { "name": "Default", "value": "tel;telprompt;skype;app-settings;calshow;itms;itmss;itms-apps;itms-appss;itms-services;" }
    ],
    "@odata.type":  "#microsoft.graph.iosManagedAppProtection"
}
'@

# === 7. Fully managed basic security compliance (Level 1) v1.2 ===
@'
{
    "@odata.type":  "#microsoft.graph.androidDeviceOwnerCompliancePolicy",
    "description":  "Level 1 is the minimum security configuration for an enterprise mobile device owned by the organization.",
    "displayName":  "Fully managed basic security compliance (Level 1) v1.2",
    "scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":""}]}],
    "deviceThreatProtectionEnabled":  false,
    "deviceThreatProtectionRequiredSecurityLevel":  "unavailable",
    "advancedThreatProtectionRequiredSecurityLevel":  "unavailable",
    "securityRequireSafetyNetAttestationBasicIntegrity":  true,
    "securityRequireSafetyNetAttestationCertifiedDevice":  true,
    "osMinimumVersion":  "9.0",
    "osMaximumVersion":  null,
    "minAndroidSecurityPatchLevel":  null,
    "passwordRequired":  true,
    "passwordMinimumLength":  6,
    "passwordMinimumLetterCharacters":  null,
    "passwordMinimumLowerCaseCharacters":  null,
    "passwordMinimumNonLetterCharacters":  null,
    "passwordMinimumNumericCharacters":  null,
    "passwordMinimumSymbolCharacters":  null,
    "passwordMinimumUpperCaseCharacters":  null,
    "passwordRequiredType":  "numericComplex",
    "passwordMinutesOfInactivityBeforeLock":  5,
    "passwordExpirationDays":  null,
    "passwordPreviousPasswordCountToBlock":  null,
    "storageRequireEncryption":  true,
    "securityRequireIntuneAppIntegrity":  true
}
'@

# === 8. Fully managed enhanced security compliance (Level 2) v1.2 ===
@'
{
    "@odata.type":  "#microsoft.graph.androidDeviceOwnerCompliancePolicy",
    "description":  "This compliance policy is the security configuration recommended as a standard for organization owned devices where users access more sensitive information.",
    "displayName":  "Fully managed enhanced security compliance (Level 2) v1.2",
    "scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":""}]}],
    "deviceThreatProtectionEnabled":  false,
    "deviceThreatProtectionRequiredSecurityLevel":  "unavailable",
    "advancedThreatProtectionRequiredSecurityLevel":  "unavailable",
    "securityRequireSafetyNetAttestationBasicIntegrity":  true,
    "securityRequireSafetyNetAttestationCertifiedDevice":  true,
    "osMinimumVersion":  "9.0",
    "osMaximumVersion":  null,
    "minAndroidSecurityPatchLevel":  null,
    "passwordRequired":  true,
    "passwordMinimumLength":  6,
    "passwordMinimumLetterCharacters":  null,
    "passwordMinimumLowerCaseCharacters":  null,
    "passwordMinimumNonLetterCharacters":  null,
    "passwordMinimumNumericCharacters":  null,
    "passwordMinimumSymbolCharacters":  null,
    "passwordMinimumUpperCaseCharacters":  null,
    "passwordRequiredType":  "numericComplex",
    "passwordMinutesOfInactivityBeforeLock":  5,
    "passwordExpirationDays":  365,
    "passwordPreviousPasswordCountToBlock":  5,
    "storageRequireEncryption":  true,
    "securityRequireIntuneAppIntegrity":  true
}
'@

# === 9. Fully managed high security compliance (Level 3) v1.1 ===
@'
{
    "@odata.type":  "#microsoft.graph.androidDeviceOwnerCompliancePolicy",
    "description":  "This compliance policy is for devices used by specific users or groups who are uniquely high risk (for example, users who handle highly sensitive data where unauthorized disclosure causes considerable material loss to the organization).",
    "displayName":  "Fully managed high security compliance (Level 3) v1.1",
    "scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":""}]}],
    "deviceThreatProtectionEnabled":  true,
    "deviceThreatProtectionRequiredSecurityLevel":  "secured",
    "advancedThreatProtectionRequiredSecurityLevel":  "secured",
    "securityRequireSafetyNetAttestationBasicIntegrity":  true,
    "securityRequireSafetyNetAttestationCertifiedDevice":  true,
    "osMinimumVersion":  "11.0",
    "osMaximumVersion":  null,
    "minAndroidSecurityPatchLevel":  null,
    "passwordRequired":  true,
    "passwordMinimumLength":  6,
    "passwordMinimumLetterCharacters":  null,
    "passwordMinimumLowerCaseCharacters":  null,
    "passwordMinimumNonLetterCharacters":  null,
    "passwordMinimumNumericCharacters":  null,
    "passwordMinimumSymbolCharacters":  null,
    "passwordMinimumUpperCaseCharacters":  null,
    "passwordRequiredType":  "numericComplex",
    "passwordMinutesOfInactivityBeforeLock":  5,
    "passwordExpirationDays":  365,
    "passwordPreviousPasswordCountToBlock":  5,
    "storageRequireEncryption":  true,
    "securityRequireIntuneAppIntegrity":  true
}
'@

# === 10. Work profile enhanced security compliance (Level 2) v1.4 ===
@'
{
    "@odata.type":  "#microsoft.graph.androidWorkProfileCompliancePolicy",
    "description":  "This compliance policy is the minimum security configuration for personal devices where users access work or school data. This configuration is applicable to most mobile users.",
    "displayName":  "Work profile enhanced security compliance (Level 2) v1.4",
    "scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":""}]}],
    "passwordRequired":  true,
    "passwordMinimumLength":  6,
    "passwordRequiredType":  "numericComplex",
    "passwordMinutesOfInactivityBeforeLock":  5,
    "passwordExpirationDays":  null,
    "passwordPreviousPasswordBlockCount":  null,
    "passwordSignInFailureCountBeforeFactoryReset":  null,
    "securityPreventInstallAppsFromUnknownSources":  true,
    "securityDisableUsbDebugging":  true,
    "securityRequireVerifyApps":  false,
    "deviceThreatProtectionEnabled":  false,
    "deviceThreatProtectionRequiredSecurityLevel":  "unavailable",
    "advancedThreatProtectionRequiredSecurityLevel":  "unavailable",
    "securityBlockJailbrokenDevices":  true,
    "osMinimumVersion":  "9.0",
    "osMaximumVersion":  null,
    "minAndroidSecurityPatchLevel":  null,
    "storageRequireEncryption":  true,
    "securityRequireSafetyNetAttestationBasicIntegrity":  true,
    "securityRequireSafetyNetAttestationCertifiedDevice":  true,
    "securityRequireGooglePlayServices":  true,
    "securityRequireUpToDateSecurityProviders":  true,
    "securityRequireCompanyPortalAppIntegrity":  true,
    "securityRequiredAndroidSafetyNetEvaluationType":  "hardwareBacked"
}
'@

# === 11. Work profile high security compliance (Level 3) v1.2 ===
@'
{
    "@odata.type":  "#microsoft.graph.androidWorkProfileCompliancePolicy",
    "description":  "This compliance policy is for devices used by specific users or groups who are uniquely high risk (for example, users who handle highly sensitive data where unauthorized disclosure causes considerable material loss to the organization).",
    "displayName":  "Work profile high security compliance (Level 3) v1.2",
    "scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":""}]}],
    "passwordRequired":  true,
    "passwordMinimumLength":  6,
    "passwordRequiredType":  "numericComplex",
    "passwordMinutesOfInactivityBeforeLock":  5,
    "passwordExpirationDays":  365,
    "passwordPreviousPasswordBlockCount":  5,
    "passwordSignInFailureCountBeforeFactoryReset":  null,
    "securityPreventInstallAppsFromUnknownSources":  true,
    "securityDisableUsbDebugging":  true,
    "securityRequireVerifyApps":  false,
    "deviceThreatProtectionEnabled":  true,
    "deviceThreatProtectionRequiredSecurityLevel":  "secured",
    "advancedThreatProtectionRequiredSecurityLevel":  "secured",
    "securityBlockJailbrokenDevices":  true,
    "osMinimumVersion":  "11.0",
    "osMaximumVersion":  null,
    "minAndroidSecurityPatchLevel":  null,
    "storageRequireEncryption":  true,
    "securityRequireSafetyNetAttestationBasicIntegrity":  true,
    "securityRequireSafetyNetAttestationCertifiedDevice":  true,
    "securityRequireGooglePlayServices":  true,
    "securityRequireUpToDateSecurityProviders":  true,
    "securityRequireCompanyPortalAppIntegrity":  true,
    "securityRequiredAndroidSafetyNetEvaluationType":  "basic"
}
'@

# === 12. iOS/iPadOS enhanced security compliance (Level 2) v1.2 ===
@'
{
    "@odata.type":  "#microsoft.graph.iosCompliancePolicy",
    "description":  "This compliance policy is the minimum security configuration for personal and supervised devices where users access work or school data. This configuration is applicable to most mobile users.",
    "displayName":  "iOS/iPadOS enhanced security compliance (Level 2) v1.2",
    "scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":""}]}],
    "passcodeBlockSimple":  true,
    "passcodeExpirationDays":  null,
    "passcodeMinimumLength":  6,
    "passcodeMinutesOfInactivityBeforeLock":  5,
    "passcodeMinutesOfInactivityBeforeScreenTimeout":  5,
    "passcodePreviousPasscodeBlockCount":  null,
    "passcodeMinimumCharacterSetCount":  null,
    "passcodeRequiredType":  "numeric",
    "passcodeRequired":  true,
    "osMinimumVersion":  "14.8",
    "osMaximumVersion":  null,
    "osMinimumBuildVersion":  null,
    "osMaximumBuildVersion":  null,
    "securityBlockJailbrokenDevices":  true,
    "deviceThreatProtectionEnabled":  false,
    "deviceThreatProtectionRequiredSecurityLevel":  "unavailable",
    "advancedThreatProtectionRequiredSecurityLevel":  "unavailable",
    "managedEmailProfileRequired":  false,
    "restrictedApps":  []
}
'@

# === 13. iOS/iPadOS high security compliance (Level 3) v1.3 ===
@'
{
    "@odata.type":  "#microsoft.graph.iosCompliancePolicy",
    "description":  "This compliance policy is for devices used by specific users or groups who are uniquely high risk (for example, users who handle highly sensitive data where unauthorized disclosure causes considerable material loss to the organization).",
    "displayName":  "iOS/iPadOS high security compliance (Level 3) v1.3",
    "scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":""}]}],
    "passcodeBlockSimple":  true,
    "passcodeExpirationDays":  365,
    "passcodeMinimumLength":  6,
    "passcodeMinutesOfInactivityBeforeLock":  5,
    "passcodeMinutesOfInactivityBeforeScreenTimeout":  5,
    "passcodePreviousPasscodeBlockCount":  null,
    "passcodeMinimumCharacterSetCount":  null,
    "passcodeRequiredType":  "numeric",
    "passcodeRequired":  true,
    "osMinimumVersion":  "15.0",
    "osMaximumVersion":  null,
    "osMinimumBuildVersion":  null,
    "osMaximumBuildVersion":  null,
    "securityBlockJailbrokenDevices":  true,
    "deviceThreatProtectionEnabled":  true,
    "deviceThreatProtectionRequiredSecurityLevel":  "secured",
    "advancedThreatProtectionRequiredSecurityLevel":  "secured",
    "managedEmailProfileRequired":  false,
    "restrictedApps":  []
}
'@

# === 14. Fully managed basic security configuration (Level 1) v1.2 ===
@'
{
    "@odata.type":  "#microsoft.graph.androidDeviceOwnerGeneralDeviceConfiguration",
    "description":  "Level 1 is the minimum security configuration for an enterprise mobile device owned by the organization.",
    "displayName":  "Fully managed basic security configuration (Level 1) v1.2",
    "appsAutoUpdatePolicy":  "wiFiOnly",
    "certificateCredentialConfigurationDisabled":  true,
    "enrollmentProfile":  "notConfigured",
    "factoryResetDeviceAdministratorEmails":  [],
    "factoryResetBlocked":  true,
    "kioskCustomizationStatusBar":  "notConfigured",
    "kioskCustomizationSystemNavigation":  "notConfigured",
    "kioskModeWifiAllowedSsids":  [],
    "passwordBlockKeyguardFeatures":  [],
    "passwordMinimumLength":  6,
    "passwordMinutesOfInactivityBeforeScreenTimeout":  5,
    "passwordRequiredType":  "numericComplex",
    "passwordSignInFailureCountBeforeFactoryReset":  10,
    "securityRequireVerifyApps":  true,
    "stayOnModes":  [],
    "storageBlockExternalMedia":  true,
    "storageBlockUsbFileTransfer":  true,
    "systemUpdateInstallType":  "automatic",
    "vpnAlwaysOnLockdownMode":  false,
    "vpnAlwaysOnPackageIdentifier":  "",
    "workProfilePasswordMinimumLength":  6,
    "workProfilePasswordSignInFailureCountBeforeFactoryReset":  10,
    "workProfilePasswordRequiredType":  "numericComplex",
    "azureAdSharedDeviceDataClearApps":  [],
    "kioskModeApps":  [],
    "kioskModeManagedFolders":  [],
    "kioskModeAppPositions":  [],
    "systemUpdateFreezePeriods":  [],
    "personalProfilePersonalApplications":  []
}
'@

# === 15. Fully managed enhanced security configuration (Level 2) v1.2 ===
@'
{
    "@odata.type":  "#microsoft.graph.androidDeviceOwnerGeneralDeviceConfiguration",
    "description":  "This configuration policy is the security configuration recommended as a standard for organization owned devices where users access more sensitive information.",
    "displayName":  "Fully managed enhanced security configuration (Level 2) v1.2",
    "appsAutoUpdatePolicy":  "wiFiOnly",
    "certificateCredentialConfigurationDisabled":  true,
    "enrollmentProfile":  "notConfigured",
    "factoryResetDeviceAdministratorEmails":  [ "example@gmail.com" ],
    "factoryResetBlocked":  true,
    "googleAccountsBlocked":  true,
    "kioskCustomizationStatusBar":  "notConfigured",
    "kioskCustomizationSystemNavigation":  "notConfigured",
    "kioskModeWifiAllowedSsids":  [],
    "passwordBlockKeyguardFeatures":  [],
    "passwordExpirationDays":  365,
    "passwordMinimumLength":  6,
    "passwordMinutesOfInactivityBeforeScreenTimeout":  5,
    "passwordPreviousPasswordCountToBlock":  5,
    "passwordRequiredType":  "numericComplex",
    "passwordSignInFailureCountBeforeFactoryReset":  5,
    "securityRequireVerifyApps":  true,
    "stayOnModes":  [],
    "storageBlockExternalMedia":  true,
    "storageBlockUsbFileTransfer":  true,
    "systemUpdateInstallType":  "automatic",
    "usersBlockAdd":  true,
    "usersBlockRemove":  true,
    "vpnAlwaysOnLockdownMode":  false,
    "vpnAlwaysOnPackageIdentifier":  "",
    "workProfilePasswordExpirationDays":  365,
    "workProfilePasswordMinimumLength":  6,
    "workProfilePasswordPreviousPasswordCountToBlock":  5,
    "workProfilePasswordSignInFailureCountBeforeFactoryReset":  10,
    "workProfilePasswordRequiredType":  "numericComplex",
    "azureAdSharedDeviceDataClearApps":  [],
    "kioskModeApps":  [],
    "kioskModeManagedFolders":  [],
    "kioskModeAppPositions":  [],
    "systemUpdateFreezePeriods":  [],
    "personalProfilePersonalApplications":  []
}
'@

# === 16. Fully managed high security configuration (Level 3) v1.2 ===
@'
{
    "@odata.type":  "#microsoft.graph.androidDeviceOwnerGeneralDeviceConfiguration",
    "description":  "This compliance policy is for devices used by specific users or groups who are uniquely high risk (for example, users who handle highly sensitive data where unauthorized disclosure causes considerable material loss to the organization).",
    "displayName":  "Fully managed high security configuration (Level 3) v1.2",
    "appsAutoUpdatePolicy":  "always",
    "bluetoothBlockContactSharing":  false,
    "cellularBlockWiFiTethering":  true,
    "certificateCredentialConfigurationDisabled":  true,
    "dateTimeConfigurationBlocked":  true,
    "enrollmentProfile":  "notConfigured",
    "factoryResetDeviceAdministratorEmails":  [ "example@gmail.com" ],
    "factoryResetBlocked":  true,
    "googleAccountsBlocked":  true,
    "kioskCustomizationStatusBar":  "notConfigured",
    "kioskCustomizationSystemNavigation":  "notConfigured",
    "kioskModeWifiAllowedSsids":  [],
    "nfcBlockOutgoingBeam":  true,
    "passwordBlockKeyguardFeatures":  [ "trustAgents", "unredactedNotifications" ],
    "passwordExpirationDays":  365,
    "passwordMinimumLength":  6,
    "passwordMinutesOfInactivityBeforeScreenTimeout":  5,
    "passwordPreviousPasswordCountToBlock":  5,
    "passwordRequiredType":  "numericComplex",
    "passwordSignInFailureCountBeforeFactoryReset":  5,
    "securityRequireVerifyApps":  true,
    "stayOnModes":  [],
    "storageBlockExternalMedia":  true,
    "storageBlockUsbFileTransfer":  true,
    "systemUpdateInstallType":  "automatic",
    "usersBlockAdd":  true,
    "usersBlockRemove":  true,
    "vpnAlwaysOnLockdownMode":  false,
    "vpnAlwaysOnPackageIdentifier":  "",
    "personalProfilePlayStoreMode":  "notConfigured",
    "workProfilePasswordExpirationDays":  365,
    "workProfilePasswordMinimumLength":  6,
    "workProfilePasswordPreviousPasswordCountToBlock":  5,
    "workProfilePasswordSignInFailureCountBeforeFactoryReset":  5,
    "workProfilePasswordRequiredType":  "numericComplex",
    "azureAdSharedDeviceDataClearApps":  [],
    "kioskModeApps":  [],
    "kioskModeManagedFolders":  [],
    "kioskModeAppPositions":  [],
    "systemUpdateFreezePeriods":  [],
    "personalProfilePersonalApplications":  []
}
'@

# === 17. Work profile enhanced security configuration (Level 2) v1.3 ===
@'
{
    "@odata.type":  "#microsoft.graph.androidWorkProfileGeneralDeviceConfiguration",
    "description":  "This device restriction configuration policy is the minimum security configuration for personally owned devices where users access work or school data. This configuration is applicable to most mobile users.",
    "displayName":  "Work profile enhanced security configuration (Level 2) v1.3",
    "passwordBlockFaceUnlock":  false,
    "passwordBlockFingerprintUnlock":  false,
    "passwordBlockIrisUnlock":  false,
    "passwordBlockTrustAgents":  false,
    "passwordExpirationDays":  null,
    "passwordMinimumLength":  6,
    "passwordMinutesOfInactivityBeforeScreenTimeout":  5,
    "passwordPreviousPasswordBlockCount":  null,
    "passwordSignInFailureCountBeforeFactoryReset":  10,
    "passwordRequiredType":  "numericComplex",
    "workProfileAllowAppInstallsFromUnknownSources":  false,
    "workProfileDataSharingType":  "allowPersonalToWork",
    "workProfileBlockNotificationsWhileDeviceLocked":  false,
    "workProfileBlockAddingAccounts":  true,
    "workProfileBluetoothEnableContactSharing":  true,
    "workProfileBlockScreenCapture":  true,
    "workProfileBlockCrossProfileCallerId":  false,
    "workProfileBlockCamera":  false,
    "workProfileBlockCrossProfileContactsSearch":  false,
    "workProfileBlockCrossProfileCopyPaste":  true,
    "workProfileDefaultAppPermissionPolicy":  "deviceDefault",
    "workProfilePasswordBlockFaceUnlock":  false,
    "workProfilePasswordBlockFingerprintUnlock":  false,
    "workProfilePasswordBlockIrisUnlock":  false,
    "workProfilePasswordBlockTrustAgents":  false,
    "workProfilePasswordExpirationDays":  null,
    "workProfilePasswordMinimumLength":  6,
    "workProfilePasswordMinutesOfInactivityBeforeScreenTimeout":  5,
    "workProfilePasswordPreviousPasswordBlockCount":  null,
    "workProfilePasswordSignInFailureCountBeforeFactoryReset":  10,
    "workProfilePasswordRequiredType":  "numericComplex",
    "workProfileRequirePassword":  true,
    "securityRequireVerifyApps":  true,
    "vpnAlwaysOnPackageIdentifier":  null,
    "vpnEnableAlwaysOnLockdownMode":  false,
    "workProfileAllowWidgets":  true,
    "workProfileBlockPersonalAppInstallsFromUnknownSources":  false
}
'@

# === 18. Work profile high security configuration (Level 3) v1.2 ===
@'
{
    "@odata.type":  "#microsoft.graph.androidWorkProfileGeneralDeviceConfiguration",
    "description":  "This device restriction configuration policy is for devices used by specific users or groups who are uniquely high risk (for example, users who handle highly sensitive data where unauthorized disclosure causes considerable material loss to the organization).",
    "displayName":  "Work profile high security configuration (Level 3) v1.2",
    "passwordBlockFaceUnlock":  false,
    "passwordBlockFingerprintUnlock":  false,
    "passwordBlockIrisUnlock":  false,
    "passwordBlockTrustAgents":  false,
    "passwordExpirationDays":  365,
    "passwordMinimumLength":  6,
    "passwordMinutesOfInactivityBeforeScreenTimeout":  5,
    "passwordPreviousPasswordBlockCount":  5,
    "passwordSignInFailureCountBeforeFactoryReset":  5,
    "passwordRequiredType":  "numericComplex",
    "workProfileAllowAppInstallsFromUnknownSources":  false,
    "workProfileDataSharingType":  "allowPersonalToWork",
    "workProfileBlockNotificationsWhileDeviceLocked":  true,
    "workProfileBlockAddingAccounts":  true,
    "workProfileBluetoothEnableContactSharing":  false,
    "workProfileBlockScreenCapture":  true,
    "workProfileBlockCrossProfileCallerId":  false,
    "workProfileBlockCamera":  false,
    "workProfileBlockCrossProfileContactsSearch":  true,
    "workProfileBlockCrossProfileCopyPaste":  true,
    "workProfileDefaultAppPermissionPolicy":  "deviceDefault",
    "workProfilePasswordBlockFaceUnlock":  false,
    "workProfilePasswordBlockFingerprintUnlock":  false,
    "workProfilePasswordBlockIrisUnlock":  false,
    "workProfilePasswordBlockTrustAgents":  true,
    "workProfilePasswordExpirationDays":  365,
    "workProfilePasswordMinimumLength":  6,
    "workProfilePasswordMinutesOfInactivityBeforeScreenTimeout":  5,
    "workProfilePasswordPreviousPasswordBlockCount":  5,
    "workProfilePasswordSignInFailureCountBeforeFactoryReset":  5,
    "workProfilePasswordRequiredType":  "numericComplex",
    "workProfileRequirePassword":  true,
    "securityRequireVerifyApps":  true,
    "vpnAlwaysOnPackageIdentifier":  null,
    "vpnEnableAlwaysOnLockdownMode":  false,
    "workProfileAllowWidgets":  false,
    "workProfileBlockPersonalAppInstallsFromUnknownSources":  true
}
'@

# === 19. iOS/iPadOS Personal basic security configuration (Level 1) v1.1 ===
@'
{
    "@odata.type":  "#microsoft.graph.iosGeneralDeviceConfiguration",
    "description":  "This device restriction configuration policy is the minimum security configuration for personally owned devices where users access work or school data.",
    "displayName":  "iOS/iPadOS Personal basic security configuration (Level 1) v1.1",
    "airDropForceUnmanagedDropTarget":  true,
    "appleWatchForceWristDetection":  true,
    "certificatesBlockUntrustedTlsCertificates":  true,
    "enterpriseAppBlockTrust":  true,
    "iCloudBlockManagedAppsSync":  true,
    "iCloudRequireEncryptedBackup":  true,
    "lockScreenBlockNotificationView":  true,
    "lockScreenBlockTodayView":  true,
    "passcodeBlockSimple":  true,
    "passcodeMinimumLength":  6,
    "passcodeMinutesOfInactivityBeforeLock":  5,
    "passcodeMinutesOfInactivityBeforeScreenTimeout":  5,
    "passcodeSignInFailureCountBeforeWipe":  10,
    "passcodeRequiredType":  "numeric",
    "passcodeRequired":  true,
    "safariRequireFraudWarning":  true,
    "siriBlockedWhenLocked":  true,
    "voiceDialingBlocked":  true,
    "kioskModeAppType":  "notConfigured",
    "appsSingleAppModeList":  [],
    "appsVisibilityList":  [],
    "compliantAppsList":  [],
    "networkUsageRules":  [
        { "cellularDataBlockWhenRoaming": false, "cellularDataBlocked": false, "managedApps": [] },
        { "cellularDataBlockWhenRoaming": false, "cellularDataBlocked": false, "managedApps": [] }
    ]
}
'@

# === 20. iOS/iPadOS Supervised basic security configuration (Level 1) v1.1 ===
@'
{
    "@odata.type":  "#microsoft.graph.iosGeneralDeviceConfiguration",
    "description":  "This device restriction configuration policy is the minimum security configuration for corporate owned supervised devices where users access work or school data.",
    "displayName":  "iOS/iPadOS Supervised basic security configuration (Level 1) v1.1",
    "activationLockAllowWhenSupervised":  true,
    "airDropForceUnmanagedDropTarget":  true,
    "appleWatchForceWristDetection":  true,
    "autoFillForceAuthentication":  true,
    "certificatesBlockUntrustedTlsCertificates":  true,
    "enterpriseAppBlockTrust":  true,
    "iCloudBlockManagedAppsSync":  true,
    "iCloudRequireEncryptedBackup":  true,
    "lockScreenBlockNotificationView":  true,
    "lockScreenBlockTodayView":  true,
    "passcodeBlockSimple":  true,
    "passcodeMinimumLength":  6,
    "passcodeMinutesOfInactivityBeforeLock":  5,
    "passcodeMinutesOfInactivityBeforeScreenTimeout":  5,
    "passcodeSignInFailureCountBeforeWipe":  10,
    "passcodeRequiredType":  "numeric",
    "passcodeRequired":  true,
    "proximityBlockSetupToNewDevice":  true,
    "safariRequireFraudWarning":  true,
    "siriBlockedWhenLocked":  true,
    "voiceDialingBlocked":  true,
    "keychainBlockCloudSync":  true,
    "airPrintBlockCredentialsStorage":  true,
    "airPrintForceTrustedTLS":  true,
    "airPrintBlockiBeaconDiscovery":  true,
    "passwordBlockProximityRequests":  true,
    "passwordBlockAirDropSharing":  true,
    "kioskModeAppType":  "notConfigured",
    "appsSingleAppModeList":  [],
    "appsVisibilityList":  [],
    "compliantAppsList":  [],
    "networkUsageRules":  [
        { "cellularDataBlockWhenRoaming": false, "cellularDataBlocked": false, "managedApps": [] },
        { "cellularDataBlockWhenRoaming": false, "cellularDataBlocked": false, "managedApps": [] }
    ]
}
'@

# === 21. iOS/iPadOS Personal enhanced security configuration (Level 2) v1.2 ===
@'
{
    "@odata.type":  "#microsoft.graph.iosGeneralDeviceConfiguration",
    "description":  "This device restriction configuration policy introduces data transfer controls for managed apps. This is the configuration that is applicable to most mobile users accessing work or school data using personally owned devices.",
    "displayName":  "iOS/iPadOS Personal enhanced security configuration (Level 2) v1.2",
    "airDropForceUnmanagedDropTarget":  true,
    "appleWatchForceWristDetection":  true,
    "certificatesBlockUntrustedTlsCertificates":  true,
    "diagnosticDataBlockSubmission":  true,
    "documentsBlockManagedDocumentsInUnmanagedApps":  true,
    "enterpriseAppBlockTrust":  true,
    "iCloudBlockManagedAppsSync":  true,
    "iCloudRequireEncryptedBackup":  true,
    "lockScreenBlockNotificationView":  true,
    "lockScreenBlockTodayView":  true,
    "passcodeBlockSimple":  true,
    "passcodeMinimumLength":  6,
    "passcodeMinutesOfInactivityBeforeLock":  5,
    "passcodeMinutesOfInactivityBeforeScreenTimeout":  5,
    "passcodeSignInFailureCountBeforeWipe":  10,
    "passcodeRequiredType":  "numeric",
    "passcodeRequired":  true,
    "safariRequireFraudWarning":  true,
    "siriBlockedWhenLocked":  true,
    "voiceDialingBlocked":  true,
    "enterpriseBookBlockBackup":  true,
    "enterpriseBookBlockMetadataSync":  true,
    "contactsAllowManagedToUnmanagedWrite":  true,
    "onDeviceOnlyDictationForced":  true,
    "onDeviceOnlyTranslationForced":  true,
    "kioskModeAppType":  "notConfigured",
    "appsSingleAppModeList":  [],
    "appsVisibilityList":  [],
    "compliantAppsList":  [],
    "networkUsageRules":  [
        { "cellularDataBlockWhenRoaming": false, "cellularDataBlocked": false, "managedApps": [] },
        { "cellularDataBlockWhenRoaming": false, "cellularDataBlocked": false, "managedApps": [] }
    ]
}
'@

# === 22. iOS/iPadOS Supervised enhanced security configuration (Level 2) v1.2 ===
@'
{
    "@odata.type":  "#microsoft.graph.iosGeneralDeviceConfiguration",
    "description":  "This device restriction configuration policy introduces data transfer controls for managed apps. This is the configuration that is applicable to most mobile users accessing work or school data using supervised devices.",
    "displayName":  "iOS/iPadOS Supervised enhanced security configuration (Level 2) v1.2",
    "activationLockAllowWhenSupervised":  true,
    "airDropForceUnmanagedDropTarget":  true,
    "appleWatchForceWristDetection":  true,
    "autoFillForceAuthentication":  true,
    "certificatesBlockUntrustedTlsCertificates":  true,
    "diagnosticDataBlockSubmission":  true,
    "documentsBlockManagedDocumentsInUnmanagedApps":  true,
    "enterpriseAppBlockTrust":  true,
    "iCloudBlockDocumentSync":  true,
    "iCloudBlockManagedAppsSync":  true,
    "iCloudRequireEncryptedBackup":  true,
    "lockScreenBlockNotificationView":  true,
    "lockScreenBlockTodayView":  true,
    "passcodeBlockSimple":  true,
    "passcodeMinimumLength":  6,
    "passcodeMinutesOfInactivityBeforeLock":  5,
    "passcodeMinutesOfInactivityBeforeScreenTimeout":  5,
    "passcodeSignInFailureCountBeforeWipe":  10,
    "passcodeRequiredType":  "numeric",
    "passcodeRequired":  true,
    "proximityBlockSetupToNewDevice":  true,
    "safariRequireFraudWarning":  true,
    "siriBlockedWhenLocked":  true,
    "voiceDialingBlocked":  true,
    "keychainBlockCloudSync":  true,
    "enterpriseBookBlockBackup":  true,
    "enterpriseBookBlockMetadataSync":  true,
    "airPrintBlockCredentialsStorage":  true,
    "airPrintForceTrustedTLS":  true,
    "airPrintBlockiBeaconDiscovery":  true,
    "filesUsbDriveAccessBlocked":  true,
    "passwordBlockProximityRequests":  true,
    "passwordBlockAirDropSharing":  true,
    "contactsAllowManagedToUnmanagedWrite":  true,
    "onDeviceOnlyDictationForced":  true,
    "onDeviceOnlyTranslationForced":  true,
    "managedPasteboardRequired":  true,
    "kioskModeAppType":  "notConfigured",
    "appsSingleAppModeList":  [],
    "appsVisibilityList":  [],
    "compliantAppsList":  [],
    "networkUsageRules":  [
        { "cellularDataBlockWhenRoaming": false, "cellularDataBlocked": false, "managedApps": [] },
        { "cellularDataBlockWhenRoaming": false, "cellularDataBlocked": false, "managedApps": [] }
    ]
}
'@

# === 23. iOS/iPadOS Personal high security configuration (Level 3) v1.2 ===
@'
{
    "@odata.type":  "#microsoft.graph.iosGeneralDeviceConfiguration",
    "description":  "This device restriction configuration policy is for devices used by specific users or groups who are uniquely high risk (for example, users who handle highly sensitive data where unauthorized disclosure causes considerable material loss to the organization).",
    "displayName":  "iOS/iPadOS Personal high security configuration (Level 3) v1.2",
    "airDropForceUnmanagedDropTarget":  true,
    "airPlayForcePairingPasswordForOutgoingRequests":  true,
    "appleWatchForceWristDetection":  true,
    "certificatesBlockUntrustedTlsCertificates":  true,
    "diagnosticDataBlockSubmission":  true,
    "documentsBlockManagedDocumentsInUnmanagedApps":  true,
    "enterpriseAppBlockTrust":  true,
    "iCloudBlockActivityContinuation":  true,
    "iCloudBlockManagedAppsSync":  true,
    "iCloudRequireEncryptedBackup":  true,
    "lockScreenBlockNotificationView":  true,
    "lockScreenBlockTodayView":  true,
    "passcodeBlockSimple":  true,
    "passcodeExpirationDays":  365,
    "passcodeMinimumLength":  6,
    "passcodeMinutesOfInactivityBeforeLock":  5,
    "passcodeMinutesOfInactivityBeforeScreenTimeout":  5,
    "passcodePreviousPasscodeBlockCount":  5,
    "passcodeSignInFailureCountBeforeWipe":  5,
    "passcodeRequiredType":  "numeric",
    "passcodeRequired":  true,
    "safariRequireFraudWarning":  true,
    "screenCaptureBlocked":  true,
    "siriBlockedWhenLocked":  true,
    "voiceDialingBlocked":  true,
    "enterpriseBookBlockBackup":  true,
    "enterpriseBookBlockMetadataSync":  true,
    "autoUnlockBlocked":  true,
    "contactsAllowManagedToUnmanagedWrite":  true,
    "onDeviceOnlyDictationForced":  true,
    "onDeviceOnlyTranslationForced":  true,
    "kioskModeAppType":  "notConfigured",
    "appsSingleAppModeList":  [],
    "appsVisibilityList":  [],
    "compliantAppsList":  [],
    "networkUsageRules":  [
        { "cellularDataBlockWhenRoaming": false, "cellularDataBlocked": false, "managedApps": [] },
        { "cellularDataBlockWhenRoaming": false, "cellularDataBlocked": false, "managedApps": [] }
    ]
}
'@

# === 24. iOS/iPadOS Supervised high security configuration (Level 3) v1.2 ===
@'
{
    "@odata.type":  "#microsoft.graph.iosGeneralDeviceConfiguration",
    "description":  "This device restriction configuration policy is for supervised devices used by specific users or groups who are uniquely high risk (for example, users who handle highly sensitive data where unauthorized disclosure causes considerable material loss to the organization).",
    "displayName":  "iOS/iPadOS Supervised high security configuration (Level 3) v1.2",
    "accountBlockModification":  true,
    "activationLockAllowWhenSupervised":  true,
    "airDropBlocked":  true,
    "airDropForceUnmanagedDropTarget":  true,
    "airPlayForcePairingPasswordForOutgoingRequests":  true,
    "appleWatchForceWristDetection":  true,
    "appStoreBlocked":  true,
    "autoFillForceAuthentication":  true,
    "certificatesBlockUntrustedTlsCertificates":  true,
    "configurationProfileBlockChanges":  true,
    "deviceBlockEraseContentAndSettings":  true,
    "diagnosticDataBlockSubmission":  true,
    "documentsBlockManagedDocumentsInUnmanagedApps":  true,
    "enterpriseAppBlockTrust":  true,
    "esimBlockModification":  true,
    "findMyFriendsBlocked":  true,
    "gamingBlockGameCenterFriends":  true,
    "gamingBlockMultiplayer":  true,
    "gameCenterBlocked":  true,
    "hostPairingBlocked":  true,
    "iCloudBlockActivityContinuation":  true,
    "iCloudBlockBackup":  true,
    "iCloudBlockDocumentSync":  true,
    "iCloudBlockManagedAppsSync":  true,
    "iCloudRequireEncryptedBackup":  true,
    "iTunesBlockExplicitContent":  true,
    "lockScreenBlockNotificationView":  true,
    "lockScreenBlockTodayView":  true,
    "passcodeBlockSimple":  true,
    "passcodeExpirationDays":  365,
    "passcodeMinimumLength":  6,
    "passcodeMinutesOfInactivityBeforeLock":  5,
    "passcodeMinutesOfInactivityBeforeScreenTimeout":  5,
    "passcodePreviousPasscodeBlockCount":  5,
    "passcodeSignInFailureCountBeforeWipe":  5,
    "passcodeRequiredType":  "numeric",
    "passcodeRequired":  true,
    "proximityBlockSetupToNewDevice":  true,
    "safariBlockAutofill":  true,
    "safariRequireFraudWarning":  true,
    "screenCaptureBlocked":  true,
    "siriBlocked":  true,
    "siriBlockedWhenLocked":  true,
    "voiceDialingBlocked":  true,
    "keychainBlockCloudSync":  true,
    "enterpriseBookBlockBackup":  true,
    "enterpriseBookBlockMetadataSync":  true,
    "airPrintBlocked":  true,
    "airPrintBlockCredentialsStorage":  true,
    "airPrintForceTrustedTLS":  true,
    "airPrintBlockiBeaconDiscovery":  true,
    "filesNetworkDriveAccessBlocked":  true,
    "filesUsbDriveAccessBlocked":  true,
    "vpnBlockCreation":  true,
    "appRemovalBlocked":  true,
    "passwordBlockAutoFill":  true,
    "passwordBlockProximityRequests":  true,
    "passwordBlockAirDropSharing":  true,
    "dateAndTimeForceSetAutomatically":  true,
    "contactsAllowManagedToUnmanagedWrite":  true,
    "findMyFriendsInFindMyAppBlocked":  true,
    "iTunesBlocked":  true,
    "autoUnlockBlocked":  true,
    "onDeviceOnlyDictationForced":  true,
    "onDeviceOnlyTranslationForced":  true,
    "managedPasteboardRequired":  true,
    "kioskModeAppType":  "notConfigured",
    "appsSingleAppModeList":  [],
    "appsVisibilityList":  [],
    "compliantAppsList":  [],
    "networkUsageRules":  [
        { "cellularDataBlockWhenRoaming": false, "cellularDataBlocked": false, "managedApps": [] },
        { "cellularDataBlockWhenRoaming": false, "cellularDataBlocked": false, "managedApps": [] }
    ]
}
'@

)

# ---------------------------------------------------------------------------
# Import loop
# ---------------------------------------------------------------------------
Write-Host "Policies to import : $($policyJsons.Count)" -ForegroundColor Cyan
Write-Host ''

$created = 0
$skipped = 0

foreach ($json in $policyJsons) {

    $policy   = $json | ConvertFrom-Json
    $name     = $policy.displayName
    $odataType = $policy.'@odata.type'

    Write-Host "--- $name ---" -ForegroundColor Cyan

    if ($existingNames.Contains($name)) {
        Write-Host '  Already exists - skipping.' -ForegroundColor Yellow
        $skipped++
        continue
    }

    # Inject scope tag
    $policy | Add-Member -NotePropertyName 'roleScopeTagIds' `
                         -NotePropertyValue @($scopeTag.id) -Force

    $endpoint = Get-PolicyEndpoint -ODataType $odataType
    $body     = $policy | ConvertTo-Json -Depth 20

    $result = Invoke-MgGraphRequest -Method POST -ContentType 'application/json' `
                  -Uri $endpoint -Body $body
    Write-Host "  Created (ID: $($result.id))" -ForegroundColor Green
    $created++
}

Write-Host ''
Write-Host "Done. Created: $created  Skipped: $skipped" -ForegroundColor Cyan
