<#
.SYNOPSIS
    Import Intune Device Configuration Policy from JSON using Microsoft Graph PowerShell Module

.DESCRIPTION
    This script imports a device configuration policy from a JSON file and creates it in Intune
    using the Microsoft Graph PowerShell SDK. It automatically checks for existing policies
    with the same displayName and skips import if found.

.PARAMETER FileName
    Path to the JSON file containing the device configuration policy

.NOTES
    Requires: Microsoft.Graph PowerShell Module
    Install with: Install-Module Microsoft.Graph -Scope CurrentUser
    
    Required Permissions:
    - DeviceManagementConfiguration.ReadWrite.All

.EXAMPLE
    .\Import-DeviceConfigurationPolicy.ps1 -FileName "C:\Policies\iOSDeviceConfig.json"

.COPYRIGHT
    Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
    Modified to use Microsoft Graph PowerShell Module with automatic duplicate detection
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [String]$FileName
)

####################################################

Function Write-LogMessage {
<#
.SYNOPSIS
    Writes formatted log messages with timestamps
.DESCRIPTION
    Provides consistent logging throughout the script
.EXAMPLE
    Write-LogMessage -Message "Policy created" -Level "Success"
#>
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    switch ($Level) {
        "Info"    { Write-Host "[$timestamp] [INFO] $Message" -ForegroundColor Cyan }
        "Success" { Write-Host "[$timestamp] [SUCCESS] $Message" -ForegroundColor Green }
        "Warning" { Write-Host "[$timestamp] [WARNING] $Message" -ForegroundColor Yellow }
        "Error"   { Write-Host "[$timestamp] [ERROR] $Message" -ForegroundColor Red }
    }
}

####################################################

Function Test-JSON {
<#
.SYNOPSIS
    Validates if the provided string is valid JSON format
.DESCRIPTION
    Tests if the JSON passed to the REST Post is valid
.EXAMPLE
    Test-JSON -JSON $JSON
    Returns $true if valid, $false if invalid
.NOTES
    NAME: Test-JSON
#>

    param (
        [Parameter(Mandatory=$true)]
        $JSON
    )

    try {
        $TestJSON = ConvertFrom-Json $JSON -ErrorAction Stop
        return $true
    }
    catch {
        Write-LogMessage -Message "JSON validation failed: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

####################################################

Function Get-DeviceConfigurationPolicyType {
<#
.SYNOPSIS
    Determines the type of device configuration policy
.DESCRIPTION
    Analyzes the @odata.type to determine the policy category
.EXAMPLE
    Get-DeviceConfigurationPolicyType -ODataType "#microsoft.graph.iosGeneralDeviceConfiguration"
    Returns "iOS General Configuration"
.NOTES
    NAME: Get-DeviceConfigurationPolicyType
#>

    param (
        [Parameter(Mandatory=$true)]
        [string]$ODataType
    )

    $typeMapping = @{
        "iosGeneralDeviceConfiguration" = "iOS General Configuration"
        "androidGeneralDeviceConfiguration" = "Android General Configuration"
        "androidWorkProfileGeneralDeviceConfiguration" = "Android Work Profile Configuration"
        "windows10GeneralConfiguration" = "Windows 10 General Configuration"
        "macOSGeneralDeviceConfiguration" = "macOS General Configuration"
        "iosDeviceFeaturesConfiguration" = "iOS Device Features"
        "androidDeviceOwnerGeneralDeviceConfiguration" = "Android Device Owner"
        "windows10EndpointProtectionConfiguration" = "Windows 10 Endpoint Protection"
        "iosUpdateConfiguration" = "iOS Update Configuration"
        "windowsUpdateForBusinessConfiguration" = "Windows Update for Business"
        "iosCustomConfiguration" = "iOS Custom Configuration"
        "androidCustomConfiguration" = "Android Custom Configuration"
        "windows10CustomConfiguration" = "Windows 10 Custom Configuration"
        "macOSCustomConfiguration" = "macOS Custom Configuration"
        "editionUpgradeConfiguration" = "Windows 10 Edition Upgrade"
        "windowsDefenderAdvancedThreatProtectionConfiguration" = "Windows Defender ATP"
        "sharedPCConfiguration" = "Shared PC Configuration"
        "windows10SecureAssessmentConfiguration" = "Windows 10 Secure Assessment"
        "windowsKioskConfiguration" = "Windows Kiosk Configuration"
    }

    foreach ($key in $typeMapping.Keys) {
        if ($ODataType -match $key) {
            return $typeMapping[$key]
        }
    }

    return "Generic Device Configuration"
}

####################################################

Function Get-ExistingDeviceConfigurationPolicy {
<#
.SYNOPSIS
    Retrieves existing device configuration policies from Intune
.DESCRIPTION
    Queries Microsoft Graph to get all device configuration policies
.EXAMPLE
    Get-ExistingDeviceConfigurationPolicy -DisplayName "iOS Corporate Configuration"
    Returns the policy object if found, otherwise $null
.NOTES
    NAME: Get-ExistingDeviceConfigurationPolicy
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$DisplayName
    )

    $graphApiVersion = "beta"
    $Resource = "deviceManagement/deviceConfigurations"
    
    try {
        Write-LogMessage -Message "Checking for existing device configuration policy: '$DisplayName'" -Level "Info"
        
        # Get all device configuration policies
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri
        
        # Check if any policy matches the display name
        $existingPolicy = $response.value | Where-Object { $_.displayName -eq $DisplayName }
        
        if ($existingPolicy) {
            Write-LogMessage -Message "Found existing policy with ID: $($existingPolicy.id)" -Level "Warning"
            return $existingPolicy
        }
        else {
            Write-LogMessage -Message "No existing policy found with this name" -Level "Info"
            return $null
        }
    }
    catch {
        Write-LogMessage -Message "Error checking for existing policies: $($_.Exception.Message)" -Level "Error"
        throw
    }
}

####################################################

Function Add-DeviceConfigurationPolicy {
<#
.SYNOPSIS
    Creates a device configuration policy using Microsoft Graph API
.DESCRIPTION
    Uses Invoke-MgGraphRequest to add a device configuration policy to Intune
.EXAMPLE
    Add-DeviceConfigurationPolicy -JSON $JSON
    Creates the policy and returns the response object
.NOTES
    NAME: Add-DeviceConfigurationPolicy
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        $JSON
    )

    $graphApiVersion = "beta"
    $Resource = "deviceManagement/deviceConfigurations"
    
    try {
        if ([string]::IsNullOrWhiteSpace($JSON)) {
            Write-LogMessage -Message "No JSON specified for the Device Configuration Policy" -Level "Error"
            throw "JSON cannot be null or empty"
        }

        # Validate JSON structure
        if (!(Test-JSON -JSON $JSON)) {
            throw "Invalid JSON format"
        }

        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        
        Write-LogMessage -Message "Sending POST request to create device configuration policy" -Level "Info"
        
        # Using Invoke-MgGraphRequest to create the policy
        $response = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $JSON -ContentType "application/json"
        
        Write-LogMessage -Message "Successfully created device configuration policy with ID: $($response.id)" -Level "Success"
        return $response
    }
    catch {
        $ex = $_.Exception
        Write-LogMessage -Message "Error creating device configuration policy: $($ex.Message)" -Level "Error"
        
        # Try to extract detailed error information from Graph API response
        if ($_.ErrorDetails.Message) {
            try {
                $errorDetail = $_.ErrorDetails.Message | ConvertFrom-Json
                Write-LogMessage -Message "Graph API Error: $($errorDetail.error.message)" -Level "Error"
            }
            catch {
                Write-LogMessage -Message "Error details: $($_.ErrorDetails.Message)" -Level "Error"
            }
        }
        
        throw
    }
}

####################################################

#region Authentication

Write-Host
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Intune Device Configuration Import" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host

Write-LogMessage -Message "Checking for Microsoft Graph PowerShell module..." -Level "Info"

# Check if Microsoft.Graph module is installed
$GraphModule = Get-Module -Name "Microsoft.Graph.Authentication" -ListAvailable

if ($null -eq $GraphModule) {
    Write-LogMessage -Message "Microsoft Graph PowerShell module not installed" -Level "Error"
    Write-Host
    Write-Host "Install by running: Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Yellow
    Write-Host
    exit 1
}

Write-LogMessage -Message "Microsoft Graph module found - Version: $($GraphModule.Version | Select-Object -First 1)" -Level "Success"

# Check if already connected to Microsoft Graph
$context = Get-MgContext

if ($null -eq $context) {
    Write-Host
    Write-LogMessage -Message "Connecting to Microsoft Graph..." -Level "Info"
    Write-LogMessage -Message "Please sign in with an account that has Intune Administrator permissions" -Level "Info"
    Write-Host
    
    # Connect to Microsoft Graph with required scopes
    try {
        Connect-MgGraph -Scopes "DeviceManagementConfiguration.ReadWrite.All" -NoWelcome -ErrorAction Stop
        Write-LogMessage -Message "Successfully connected to Microsoft Graph" -Level "Success"
    }
    catch {
        Write-LogMessage -Message "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level "Error"
        exit 1
    }
}
else {
    Write-LogMessage -Message "Already connected to Microsoft Graph as: $($context.Account)" -Level "Info"
    
    # Verify we have the required scopes
    $requiredScope = "DeviceManagementConfiguration.ReadWrite.All"
    if ($context.Scopes -notcontains $requiredScope) {
        Write-Host
        Write-LogMessage -Message "Current connection missing required scope: $requiredScope" -Level "Warning"
        Write-LogMessage -Message "Reconnecting with required permissions..." -Level "Info"
        
        Disconnect-MgGraph | Out-Null
        Connect-MgGraph -Scopes $requiredScope -NoWelcome -ErrorAction Stop
    }
}

# Display current context
$context = Get-MgContext
Write-Host
Write-Host "Current Microsoft Graph Context:" -ForegroundColor Cyan
Write-Host "  Account: $($context.Account)" -ForegroundColor White
Write-Host "  Tenant: $($context.TenantId)" -ForegroundColor White
Write-Host "  Environment: $($context.Environment)" -ForegroundColor White
Write-Host

#endregion

####################################################

#region File Import and Validation

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " File Import and Validation" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host

# Get JSON file path
if ($FileName -and (Test-Path -Path $FileName -Type Leaf)) {
    $ImportPath = $FileName
    Write-LogMessage -Message "Using provided file path: $FileName" -Level "Info"
}
else {
    if ($FileName) {
        Write-LogMessage -Message "Provided file path does not exist: $FileName" -Level "Warning"
    }
    $ImportPath = Read-Host -Prompt "Please specify a path to a JSON file (e.g., C:\Policies\DeviceConfig.json)"
}

# Remove quotes if present
$ImportPath = $ImportPath.Replace('"','').Replace("'","")

# Validate file exists
if (!(Test-Path "$ImportPath")) {
    Write-LogMessage -Message "Import path does not exist: $ImportPath" -Level "Error"
    Write-LogMessage -Message "Script cannot continue" -Level "Error"
    exit 1
}

# Validate it's a JSON file
if ([System.IO.Path]::GetExtension($ImportPath) -ne ".json") {
    Write-LogMessage -Message "File is not a JSON file: $ImportPath" -Level "Warning"
    $continue = Read-Host "Continue anyway? (Y/N)"
    if ($continue -ne 'Y') {
        Write-LogMessage -Message "Import cancelled by user" -Level "Warning"
        exit 0
    }
}

Write-LogMessage -Message "Reading JSON file from: $ImportPath" -Level "Info"

# Read JSON file
try {
    $JSON_Data = Get-Content "$ImportPath" -Raw -ErrorAction Stop
}
catch {
    Write-LogMessage -Message "Failed to read file: $($_.Exception.Message)" -Level "Error"
    exit 1
}

# Validate JSON structure
if (!(Test-JSON -JSON $JSON_Data)) {
    Write-LogMessage -Message "File does not contain valid JSON" -Level "Error"
    exit 1
}

Write-LogMessage -Message "JSON file successfully loaded and validated" -Level "Success"

#endregion

####################################################

#region Policy Processing

Write-Host
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Policy Processing" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host

# Convert from JSON and exclude properties that shouldn't be in the create request
Write-LogMessage -Message "Processing JSON data..." -Level "Info"

# Excluding entries that are not required
# id, createdDateTime, lastModifiedDateTime, version - auto-generated
# supportsScopeTags - may cause issues on some tenants
# @odata.context - only used in GET responses
$JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * `
    -ExcludeProperty id,createdDateTime,lastModifiedDateTime,version,supportsScopeTags,'@odata.context','@odata.type@odata.context'

# Validate that displayName exists
if ([string]::IsNullOrWhiteSpace($JSON_Convert.displayName)) {
    Write-LogMessage -Message "JSON does not contain a 'displayName' property" -Level "Error"
    exit 1
}

$DisplayName = $JSON_Convert.displayName
Write-LogMessage -Message "Policy Display Name: '$DisplayName'" -Level "Info"

# Check for @odata.type to determine policy type
if ($JSON_Convert.'@odata.type') {
    $policyType = $JSON_Convert.'@odata.type'
    $policyCategory = Get-DeviceConfigurationPolicyType -ODataType $policyType
    Write-LogMessage -Message "Policy Type: $policyType" -Level "Info"
    Write-LogMessage -Message "Policy Category: $policyCategory" -Level "Info"
}
else {
    Write-LogMessage -Message "Warning: No @odata.type found in JSON" -Level "Warning"
    $policyCategory = "Unknown"
}

# Check for description
if ($JSON_Convert.description) {
    Write-LogMessage -Message "Policy Description: $($JSON_Convert.description)" -Level "Info"
}

# Convert back to JSON with increased depth for complex configurations
$JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 20

# Final JSON validation
if (!(Test-JSON -JSON $JSON_Output)) {
    Write-LogMessage -Message "Processed JSON is invalid" -Level "Error"
    exit 1
}

Write-Host
Write-LogMessage -Message "Processed JSON content:" -Level "Info"
Write-Host $JSON_Output -ForegroundColor Gray
Write-Host

#endregion

####################################################

#region Duplicate Check and Import

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Duplicate Check and Import" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host

# Check if policy with same name already exists
try {
    $existingPolicy = Get-ExistingDeviceConfigurationPolicy -DisplayName $DisplayName
    
    if ($existingPolicy) {
        Write-Host
        Write-LogMessage -Message "SKIPPED: A device configuration policy with the name '$DisplayName' already exists" -Level "Warning"
        Write-LogMessage -Message "Existing Policy ID: $($existingPolicy.id)" -Level "Info"
        
        if ($existingPolicy.'@odata.type') {
            $existingCategory = Get-DeviceConfigurationPolicyType -ODataType $existingPolicy.'@odata.type'
            Write-LogMessage -Message "Existing Policy Type: $($existingPolicy.'@odata.type')" -Level "Info"
            Write-LogMessage -Message "Existing Policy Category: $existingCategory" -Level "Info"
        }
        
        if ($existingPolicy.createdDateTime) {
            Write-LogMessage -Message "Created Date: $($existingPolicy.createdDateTime)" -Level "Info"
        }
        
        if ($existingPolicy.lastModifiedDateTime) {
            Write-LogMessage -Message "Last Modified: $($existingPolicy.lastModifiedDateTime)" -Level "Info"
        }
        
        Write-Host
        Write-LogMessage -Message "To import this policy, either delete the existing one or rename the policy in the JSON file" -Level "Info"
        Write-Host
        
        # Exit with success code since this is expected behavior
        exit 0
    }
}
catch {
    Write-LogMessage -Message "Error during duplicate check: $($_.Exception.Message)" -Level "Error"
    exit 1
}

# No duplicate found, proceed with import
Write-Host
Write-LogMessage -Message "No existing policy found - proceeding with import" -Level "Success"
Write-LogMessage -Message "Creating device configuration policy: '$DisplayName'" -Level "Info"

if ($policyCategory -ne "Unknown") {
    Write-LogMessage -Message "Category: $policyCategory" -Level "Info"
}

Write-Host

try {
    $createdPolicy = Add-DeviceConfigurationPolicy -JSON $JSON_Output
    
    Write-Host
    Write-Host "========================================" -ForegroundColor Green
    Write-Host " Import Successful" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host
    Write-LogMessage -Message "Policy Name: $($createdPolicy.displayName)" -Level "Success"
    Write-LogMessage -Message "Policy ID: $($createdPolicy.id)" -Level "Success"
    
    if ($createdPolicy.'@odata.type') {
        $createdCategory = Get-DeviceConfigurationPolicyType -ODataType $createdPolicy.'@odata.type'
        Write-LogMessage -Message "Policy Type: $($createdPolicy.'@odata.type')" -Level "Success"
        Write-LogMessage -Message "Policy Category: $createdCategory" -Level "Success"
    }
    
    if ($createdPolicy.version) {
        Write-LogMessage -Message "Version: $($createdPolicy.version)" -Level "Success"
    }
    
    Write-Host
    Write-LogMessage -Message "Next steps:" -Level "Info"
    Write-LogMessage -Message "  1. Assign the policy to groups in the Intune portal" -Level "Info"
    Write-LogMessage -Message "  2. Monitor deployment status in Intune" -Level "Info"
    Write-LogMessage -Message "  3. Review device compliance after policy is applied" -Level "Info"
    Write-Host
    
    exit 0
}
catch {
    Write-Host
    Write-Host "========================================" -ForegroundColor Red
    Write-Host " Import Failed" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host
    Write-LogMessage -Message "Failed to create device configuration policy" -Level "Error"
    Write-Host
    
    exit 1
}

#endregion

####################################################

# Optional: Disconnect from Microsoft Graph
# Uncomment if you want to disconnect after script execution
# Write-LogMessage -Message "Disconnecting from Microsoft Graph" -Level "Info"
# Disconnect-MgGraph