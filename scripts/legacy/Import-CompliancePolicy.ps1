<#
.SYNOPSIS
    Import Intune Device Compliance Policy from JSON using Microsoft Graph PowerShell Module

.DESCRIPTION
    This script imports a device compliance policy from a JSON file and creates it in Intune
    using the Microsoft Graph PowerShell SDK. It automatically checks for existing policies
    with the same displayName and skips import if found.

.PARAMETER FileName
    Path to the JSON file containing the compliance policy configuration

.NOTES
    Requires: Microsoft.Graph PowerShell Module
    Install with: Install-Module Microsoft.Graph -Scope CurrentUser
    
    Required Permissions:
    - DeviceManagementConfiguration.ReadWrite.All

.EXAMPLE
    .\Import-CompliancePolicy.ps1 -FileName "C:\Policies\iOSCompliance.json"

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

Function Get-ExistingCompliancePolicy {
<#
.SYNOPSIS
    Retrieves existing compliance policies from Intune
.DESCRIPTION
    Queries Microsoft Graph to get all device compliance policies
.EXAMPLE
    Get-ExistingCompliancePolicy -DisplayName "iOS Compliance Policy"
    Returns the policy object if found, otherwise $null
.NOTES
    NAME: Get-ExistingCompliancePolicy
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$DisplayName
    )

    $graphApiVersion = "beta"
    $Resource = "deviceManagement/deviceCompliancePolicies"
    
    try {
        Write-LogMessage -Message "Checking for existing policy with name: '$DisplayName'" -Level "Info"
        
        # Get all compliance policies
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

Function Add-DeviceCompliancePolicy {
<#
.SYNOPSIS
    Creates a device compliance policy using Microsoft Graph API
.DESCRIPTION
    Uses Invoke-MgGraphRequest to add a device compliance policy to Intune
.EXAMPLE
    Add-DeviceCompliancePolicy -JSON $JSON
    Creates the policy and returns the response object
.NOTES
    NAME: Add-DeviceCompliancePolicy
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        $JSON
    )

    $graphApiVersion = "beta"
    $Resource = "deviceManagement/deviceCompliancePolicies"
    
    try {
        if ([string]::IsNullOrWhiteSpace($JSON)) {
            Write-LogMessage -Message "No JSON specified for the Compliance Policy" -Level "Error"
            throw "JSON cannot be null or empty"
        }

        # Validate JSON structure
        if (!(Test-JSON -JSON $JSON)) {
            throw "Invalid JSON format"
        }

        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        
        Write-LogMessage -Message "Sending POST request to create compliance policy" -Level "Info"
        
        # Using Invoke-MgGraphRequest to create the policy
        $response = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $JSON -ContentType "application/json"
        
        Write-LogMessage -Message "Successfully created compliance policy with ID: $($response.id)" -Level "Success"
        return $response
    }
    catch {
        $ex = $_.Exception
        Write-LogMessage -Message "Error creating compliance policy: $($ex.Message)" -Level "Error"
        
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
Write-Host " Intune Compliance Policy Import Script" -ForegroundColor Cyan
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
    $ImportPath = Read-Host -Prompt "Please specify a path to a JSON file (e.g., C:\Policies\policy.json)"
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

$JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id,createdDateTime,lastModifiedDateTime,version,'@odata.context'

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
    Write-LogMessage -Message "Policy Type: $policyType" -Level "Info"
}
else {
    Write-LogMessage -Message "Warning: No @odata.type found in JSON" -Level "Warning"
}

# Convert back to JSON with increased depth
$JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 10

# Add scheduled actions rule if not already present
# This defines the action to take when device is non-compliant
if ($JSON_Output -notlike "*scheduledActionsForRule*") {
    Write-LogMessage -Message "Adding scheduledActionsForRule to policy definition" -Level "Info"
    
    $scheduledActionsForRule = '"scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":"","notificationMessageCCList":[]}]}]'
    
    # Remove closing brace and add scheduled actions
    $JSON_Output = $JSON_Output.TrimEnd("}")
    $JSON_Output = $JSON_Output.TrimEnd() + "," + "`r`n"
    $JSON_Output = $JSON_Output + $scheduledActionsForRule + "`r`n" + "}"
}
else {
    Write-LogMessage -Message "scheduledActionsForRule already exists in policy" -Level "Info"
}

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
    $existingPolicy = Get-ExistingCompliancePolicy -DisplayName $DisplayName
    
    if ($existingPolicy) {
        Write-Host
        Write-LogMessage -Message "SKIPPED: A compliance policy with the name '$DisplayName' already exists" -Level "Warning"
        Write-LogMessage -Message "Existing Policy ID: $($existingPolicy.id)" -Level "Info"
        Write-LogMessage -Message "Existing Policy Type: $($existingPolicy.'@odata.type')" -Level "Info"
        Write-LogMessage -Message "Created Date: $($existingPolicy.createdDateTime)" -Level "Info"
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
Write-LogMessage -Message "Creating compliance policy: '$DisplayName'" -Level "Info"
Write-Host

try {
    $createdPolicy = Add-DeviceCompliancePolicy -JSON $JSON_Output
    
    Write-Host
    Write-Host "========================================" -ForegroundColor Green
    Write-Host " Import Successful" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host
    Write-LogMessage -Message "Policy Name: $($createdPolicy.displayName)" -Level "Success"
    Write-LogMessage -Message "Policy ID: $($createdPolicy.id)" -Level "Success"
    Write-LogMessage -Message "Policy Type: $($createdPolicy.'@odata.type')" -Level "Success"
    Write-Host
    
    exit 0
}
catch {
    Write-Host
    Write-Host "========================================" -ForegroundColor Red
    Write-Host " Import Failed" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host
    Write-LogMessage -Message "Failed to create compliance policy" -Level "Error"
    Write-Host
    
    exit 1
}

#endregion

####################################################

# Optional: Disconnect from Microsoft Graph
# Uncomment if you want to disconnect after script execution
# Write-LogMessage -Message "Disconnecting from Microsoft Graph" -Level "Info"
# Disconnect-MgGraph