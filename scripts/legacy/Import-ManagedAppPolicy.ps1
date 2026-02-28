<#
.SYNOPSIS
    Import Intune Managed App Protection Policy from JSON using Microsoft Graph PowerShell Module

.DESCRIPTION
    This script imports a managed app protection policy from a JSON file and creates it in Intune
    using the Microsoft Graph PowerShell SDK. It automatically checks for existing policies
    with the same displayName and skips import if found.

.PARAMETER FileName
    Path to the JSON file containing the app protection policy configuration

.NOTES
    Requires: Microsoft.Graph PowerShell Module
    Install with: Install-Module Microsoft.Graph -Scope CurrentUser
    
    Required Permissions:
    - DeviceManagementApps.ReadWrite.All

.EXAMPLE
    .\Import-AppProtectionPolicy.ps1 -FileName "C:\Policies\iOSAppProtection.json"

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

Function Get-ManagedAppPolicyType {
<#
.SYNOPSIS
    Determines the type of managed app protection policy
.DESCRIPTION
    Analyzes the @odata.type to determine iOS, Android, Windows, or other policy types
.EXAMPLE
    Get-ManagedAppPolicyType -ODataType "#microsoft.graph.iosManagedAppProtection"
    Returns "iOS"
.NOTES
    NAME: Get-ManagedAppPolicyType
#>

    param (
        [Parameter(Mandatory=$true)]
        [string]$ODataType
    )

    switch -Regex ($ODataType) {
        "ios" { return "iOS" }
        "android" { return "Android" }
        "windows" { return "Windows" }
        "mdm" { return "MDM" }
        default { return "Generic" }
    }
}

####################################################

Function Get-ExistingManagedAppPolicy {
<#
.SYNOPSIS
    Retrieves existing managed app protection policies from Intune
.DESCRIPTION
    Queries Microsoft Graph to get all managed app policies
.EXAMPLE
    Get-ExistingManagedAppPolicy -DisplayName "iOS App Protection"
    Returns the policy object if found, otherwise $null
.NOTES
    NAME: Get-ExistingManagedAppPolicy
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$DisplayName
    )

    $graphApiVersion = "beta"
    
    try {
        Write-LogMessage -Message "Checking for existing app protection policy: '$DisplayName'" -Level "Info"
        
        # Check multiple endpoints as app protection policies can be in different locations
        $endpoints = @(
            "deviceAppManagement/managedAppPolicies",
            "deviceAppManagement/iosManagedAppProtections",
            "deviceAppManagement/androidManagedAppProtections",
            "deviceAppManagement/windowsManagedAppProtections"
        )
        
        foreach ($endpoint in $endpoints) {
            try {
                $uri = "https://graph.microsoft.com/$graphApiVersion/$endpoint"
                $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction SilentlyContinue
                
                if ($response.value) {
                    $existingPolicy = $response.value | Where-Object { $_.displayName -eq $DisplayName }
                    
                    if ($existingPolicy) {
                        Write-LogMessage -Message "Found existing policy in endpoint: $endpoint" -Level "Warning"
                        Write-LogMessage -Message "Policy ID: $($existingPolicy.id)" -Level "Info"
                        return $existingPolicy
                    }
                }
            }
            catch {
                # Silently continue if endpoint doesn't exist or access denied
                continue
            }
        }
        
        Write-LogMessage -Message "No existing policy found with this name" -Level "Info"
        return $null
    }
    catch {
        Write-LogMessage -Message "Error checking for existing policies: $($_.Exception.Message)" -Level "Error"
        throw
    }
}

####################################################

Function Add-ManagedAppPolicy {
<#
.SYNOPSIS
    Creates a managed app protection policy using Microsoft Graph API
.DESCRIPTION
    Uses Invoke-MgGraphRequest to add a managed app protection policy to Intune
.EXAMPLE
    Add-ManagedAppPolicy -JSON $JSON
    Creates the policy and returns the response object
.NOTES
    NAME: Add-ManagedAppPolicy
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        $JSON
    )

    $graphApiVersion = "beta"
    $Resource = "deviceAppManagement/managedAppPolicies"
    
    try {
        if ([string]::IsNullOrWhiteSpace($JSON)) {
            Write-LogMessage -Message "No JSON specified for the Managed App Policy" -Level "Error"
            throw "JSON cannot be null or empty"
        }

        # Validate JSON structure
        if (!(Test-JSON -JSON $JSON)) {
            throw "Invalid JSON format"
        }

        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        
        Write-LogMessage -Message "Sending POST request to create managed app policy" -Level "Info"
        
        # Using Invoke-MgGraphRequest to create the policy
        $response = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $JSON -ContentType "application/json"
        
        Write-LogMessage -Message "Successfully created managed app policy with ID: $($response.id)" -Level "Success"
        return $response
    }
    catch {
        $ex = $_.Exception
        Write-LogMessage -Message "Error creating managed app policy: $($ex.Message)" -Level "Error"
        
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
Write-Host " Intune App Protection Policy Import" -ForegroundColor Cyan
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
    # DeviceManagementApps.ReadWrite.All is required for app protection policies
    try {
        Connect-MgGraph -Scopes "DeviceManagementApps.ReadWrite.All" -NoWelcome -ErrorAction Stop
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
    $requiredScope = "DeviceManagementApps.ReadWrite.All"
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
    $ImportPath = Read-Host -Prompt "Please specify a path to a JSON file (e.g., C:\Policies\AppProtectionPolicy.json)"
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

# Excluding entries that are not required - id, createdDateTime, lastModifiedDateTime, version, @odata.context, deployedAppCount
$JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * `
    -ExcludeProperty id,createdDateTime,lastModifiedDateTime,version,'@odata.context','apps@odata.context',deployedAppCount

# Process apps array if it exists
if ($JSON_Convert.apps) {
    Write-LogMessage -Message "Processing apps array (found $($JSON_Convert.apps.Count) apps)" -Level "Info"
    
    # Clean up app entries - remove id and version from each app
    $JSON_Apps = $JSON_Convert.apps | Select-Object * -ExcludeProperty id,version
    
    # Update the apps property with cleaned data
    $JSON_Convert | Add-Member -MemberType NoteProperty -Name 'apps' -Value @($JSON_Apps) -Force
    
    Write-LogMessage -Message "Cleaned app entries in policy" -Level "Info"
}
else {
    Write-LogMessage -Message "No apps array found in policy (this may be expected for some policy types)" -Level "Info"
}

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
    $policyPlatform = Get-ManagedAppPolicyType -ODataType $policyType
    Write-LogMessage -Message "Policy Type: $policyType" -Level "Info"
    Write-LogMessage -Message "Policy Platform: $policyPlatform" -Level "Info"
}
else {
    Write-LogMessage -Message "Warning: No @odata.type found in JSON" -Level "Warning"
    $policyPlatform = "Unknown"
}

# Convert back to JSON with increased depth (app protection policies can be complex)
$JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 10

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
    $existingPolicy = Get-ExistingManagedAppPolicy -DisplayName $DisplayName
    
    if ($existingPolicy) {
        Write-Host
        Write-LogMessage -Message "SKIPPED: An app protection policy with the name '$DisplayName' already exists" -Level "Warning"
        Write-LogMessage -Message "Existing Policy ID: $($existingPolicy.id)" -Level "Info"
        
        if ($existingPolicy.'@odata.type') {
            Write-LogMessage -Message "Existing Policy Type: $($existingPolicy.'@odata.type')" -Level "Info"
        }
        
        if ($existingPolicy.createdDateTime) {
            Write-LogMessage -Message "Created Date: $($existingPolicy.createdDateTime)" -Level "Info"
        }
        
        if ($existingPolicy.apps) {
            Write-LogMessage -Message "Targeted Apps: $($existingPolicy.apps.Count)" -Level "Info"
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
Write-LogMessage -Message "Creating app protection policy: '$DisplayName'" -Level "Info"

if ($policyPlatform -ne "Unknown") {
    Write-LogMessage -Message "Platform: $policyPlatform" -Level "Info"
}

Write-Host

try {
    $createdPolicy = Add-ManagedAppPolicy -JSON $JSON_Output
    
    Write-Host
    Write-Host "========================================" -ForegroundColor Green
    Write-Host " Import Successful" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host
    Write-LogMessage -Message "Policy Name: $($createdPolicy.displayName)" -Level "Success"
    Write-LogMessage -Message "Policy ID: $($createdPolicy.id)" -Level "Success"
    
    if ($createdPolicy.'@odata.type') {
        Write-LogMessage -Message "Policy Type: $($createdPolicy.'@odata.type')" -Level "Success"
    }
    
    if ($createdPolicy.apps) {
        Write-LogMessage -Message "Targeted Apps: $($createdPolicy.apps.Count)" -Level "Success"
    }
    
    Write-Host
    
    exit 0
}
catch {
    Write-Host
    Write-Host "========================================" -ForegroundColor Red
    Write-Host " Import Failed" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host
    Write-LogMessage -Message "Failed to create app protection policy" -Level "Error"
    Write-Host
    
    exit 1
}

#endregion

####################################################

# Optional: Disconnect from Microsoft Graph
# Uncomment if you want to disconnect after script execution
# Write-LogMessage -Message "Disconnecting from Microsoft Graph" -Level "Info"
# Disconnect-MgGraph