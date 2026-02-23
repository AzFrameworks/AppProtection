<#
.SYNOPSIS
    Batch Import Intune Policies with Duplicate Detection

.DESCRIPTION
    This script imports multiple Intune policies (Compliance, Device Configuration, and App Protection)
    from JSON files. Before each import, it checks if a policy with the same displayName already exists
    in the tenant and skips the import if found.

.NOTES
    Requires: Microsoft.Graph PowerShell Module
    Install with: Install-Module Microsoft.Graph -Scope CurrentUser
    
    Required Permissions:
    - DeviceManagementConfiguration.ReadWrite.All (for Compliance and Device Configuration)
    - DeviceManagementApps.ReadWrite.All (for App Protection Policies)

.EXAMPLE
    .\Batch-Import-IntunePolicies.ps1

.COPYRIGHT
    Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
    Enhanced with integrated duplicate detection
#>

[CmdletBinding()]
param()

####################################################
# Configuration
####################################################

$RepoPath = "C:\SATIG-Repo"
$JSONPath = "$RepoPath\AppProtection\JSON"

# Import script paths (relative to repo)
$ImportComplianceScript = "$RepoPath\Import-CompliancePolicy.ps1"
$ImportDeviceConfigScript = "$RepoPath\Import-DeviceConfiguration.ps1"
$ImportAppProtectionScript = "$RepoPath\Import-ManagedAppPolicy.ps1"

####################################################
# Helper Functions
####################################################

Function Write-LogMessage {
<#
.SYNOPSIS
    Writes formatted log messages with timestamps
#>
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("Info", "Success", "Warning", "Error", "Skipped")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    switch ($Level) {
        "Info"    { Write-Host "[$timestamp] [INFO] $Message" -ForegroundColor Cyan }
        "Success" { Write-Host "[$timestamp] [SUCCESS] $Message" -ForegroundColor Green }
        "Warning" { Write-Host "[$timestamp] [WARNING] $Message" -ForegroundColor Yellow }
        "Error"   { Write-Host "[$timestamp] [ERROR] $Message" -ForegroundColor Red }
        "Skipped" { Write-Host "[$timestamp] [SKIPPED] $Message" -ForegroundColor DarkYellow }
    }
}

####################################################

Function Get-PolicyDisplayNameFromJSON {
<#
.SYNOPSIS
    Extracts the displayName from a JSON file without importing it
#>
    param (
        [Parameter(Mandatory=$true)]
        [string]$JSONFilePath
    )
    
    try {
        if (!(Test-Path $JSONFilePath)) {
            Write-LogMessage -Message "JSON file not found: $JSONFilePath" -Level "Error"
            return $null
        }
        
        $jsonContent = Get-Content $JSONFilePath -Raw | ConvertFrom-Json
        
        if ([string]::IsNullOrWhiteSpace($jsonContent.displayName)) {
            Write-LogMessage -Message "No displayName found in JSON: $JSONFilePath" -Level "Warning"
            return $null
        }
        
        return $jsonContent.displayName
    }
    catch {
        Write-LogMessage -Message "Error reading JSON file: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

####################################################

Function Test-CompliancePolicyExists {
<#
.SYNOPSIS
    Checks if a compliance policy with the given displayName exists
#>
    param (
        [Parameter(Mandatory=$true)]
        [string]$DisplayName
    )
    
    try {
        $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies"
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        
        $existingPolicy = $response.value | Where-Object { $_.displayName -eq $DisplayName }
        
        return ($null -ne $existingPolicy)
    }
    catch {
        Write-LogMessage -Message "Error checking compliance policy: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

####################################################

Function Test-DeviceConfigurationPolicyExists {
<#
.SYNOPSIS
    Checks if a device configuration policy with the given displayName exists
#>
    param (
        [Parameter(Mandatory=$true)]
        [string]$DisplayName
    )
    
    try {
        $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        
        $existingPolicy = $response.value | Where-Object { $_.displayName -eq $DisplayName }
        
        return ($null -ne $existingPolicy)
    }
    catch {
        Write-LogMessage -Message "Error checking device configuration policy: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

####################################################

Function Test-ManagedAppPolicyExists {
<#
.SYNOPSIS
    Checks if a managed app protection policy with the given displayName exists
#>
    param (
        [Parameter(Mandatory=$true)]
        [string]$DisplayName
    )
    
    try {
        # Check multiple endpoints as app protection policies can be in different locations
        $endpoints = @(
            "deviceAppManagement/managedAppPolicies",
            "deviceAppManagement/iosManagedAppProtections",
            "deviceAppManagement/androidManagedAppProtections"
        )
        
        foreach ($endpoint in $endpoints) {
            try {
                $uri = "https://graph.microsoft.com/beta/$endpoint"
                $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction SilentlyContinue
                
                if ($response.value) {
                    $existingPolicy = $response.value | Where-Object { $_.displayName -eq $DisplayName }
                    
                    if ($existingPolicy) {
                        return $true
                    }
                }
            }
            catch {
                # Silently continue if endpoint doesn't exist
                continue
            }
        }
        
        return $false
    }
    catch {
        Write-LogMessage -Message "Error checking app protection policy: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

####################################################

Function Invoke-PolicyImportWithCheck {
<#
.SYNOPSIS
    Checks if policy exists and imports only if it doesn't
#>
    param (
        [Parameter(Mandatory=$true)]
        [string]$ScriptPath,
        
        [Parameter(Mandatory=$true)]
        [string]$JSONFilePath,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("Compliance", "DeviceConfiguration", "AppProtection")]
        [string]$PolicyType
    )
    
    # Extract file name for logging
    $fileName = Split-Path $JSONFilePath -Leaf
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-LogMessage -Message "Processing: $fileName" -Level "Info"
    Write-Host "========================================" -ForegroundColor Cyan
    
    # Validate JSON file exists
    if (!(Test-Path $JSONFilePath)) {
        Write-LogMessage -Message "JSON file not found: $JSONFilePath" -Level "Error"
        return [PSCustomObject]@{
            FileName = $fileName
            PolicyType = $PolicyType
            Status = "Error - File Not Found"
            Action = "Skipped"
        }
    }
    
    # Extract displayName from JSON
    $displayName = Get-PolicyDisplayNameFromJSON -JSONFilePath $JSONFilePath
    
    if ([string]::IsNullOrWhiteSpace($displayName)) {
        Write-LogMessage -Message "Could not extract displayName from JSON" -Level "Error"
        return [PSCustomObject]@{
            FileName = $fileName
            PolicyType = $PolicyType
            Status = "Error - No DisplayName"
            Action = "Skipped"
        }
    }
    
    Write-LogMessage -Message "Policy Name: '$displayName'" -Level "Info"
    Write-LogMessage -Message "Policy Type: $PolicyType" -Level "Info"
    
    # Check if policy already exists
    $policyExists = $false
    
    switch ($PolicyType) {
        "Compliance" {
            $policyExists = Test-CompliancePolicyExists -DisplayName $displayName
        }
        "DeviceConfiguration" {
            $policyExists = Test-DeviceConfigurationPolicyExists -DisplayName $displayName
        }
        "AppProtection" {
            $policyExists = Test-ManagedAppPolicyExists -DisplayName $displayName
        }
    }
    
    if ($policyExists) {
        Write-LogMessage -Message "Policy already exists in tenant - SKIPPING import" -Level "Skipped"
        return [PSCustomObject]@{
            FileName = $fileName
            PolicyName = $displayName
            PolicyType = $PolicyType
            Status = "Already Exists"
            Action = "Skipped"
        }
    }
    
    # Policy doesn't exist, proceed with import
    Write-LogMessage -Message "Policy does not exist - proceeding with import" -Level "Info"
    
    try {
        # Validate import script exists
        if (!(Test-Path $ScriptPath)) {
            Write-LogMessage -Message "Import script not found: $ScriptPath" -Level "Error"
            return [PSCustomObject]@{
                FileName = $fileName
                PolicyName = $displayName
                PolicyType = $PolicyType
                Status = "Error - Script Not Found"
                Action = "Failed"
            }
        }
        
        # Execute import script
        & $ScriptPath -FileName $JSONFilePath
        
        if ($LASTEXITCODE -eq 0) {
            Write-LogMessage -Message "Successfully imported policy" -Level "Success"
            return [PSCustomObject]@{
                FileName = $fileName
                PolicyName = $displayName
                PolicyType = $PolicyType
                Status = "Success"
                Action = "Imported"
            }
        }
        else {
            Write-LogMessage -Message "Import script returned error code: $LASTEXITCODE" -Level "Error"
            return [PSCustomObject]@{
                FileName = $fileName
                PolicyName = $displayName
                PolicyType = $PolicyType
                Status = "Error - Import Failed"
                Action = "Failed"
            }
        }
    }
    catch {
        Write-LogMessage -Message "Error executing import script: $($_.Exception.Message)" -Level "Error"
        return [PSCustomObject]@{
            FileName = $fileName
            PolicyName = $displayName
            PolicyType = $PolicyType
            Status = "Error - Exception"
            Action = "Failed"
        }
    }
}

####################################################
# Main Script
####################################################

Write-Host ""
Write-Host "========================================" -ForegroundColor Magenta
Write-Host " Intune Policy Batch Import with" -ForegroundColor Magenta
Write-Host " Duplicate Detection" -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta
Write-Host ""

$startTime = Get-Date

# Change to repository directory
Set-Location $RepoPath
Write-LogMessage -Message "Working directory: $RepoPath" -Level "Info"

####################################################
# Authentication
####################################################

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Authentication" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-LogMessage -Message "Checking Microsoft Graph connection..." -Level "Info"

$context = Get-MgContext

if ($null -eq $context) {
    Write-LogMessage -Message "Not connected to Microsoft Graph - connecting now..." -Level "Info"
    
    try {
        # Connect with all required scopes
        Connect-MgGraph -Scopes @(
            "DeviceManagementConfiguration.ReadWrite.All",
            "DeviceManagementApps.ReadWrite.All"
        ) -NoWelcome -ErrorAction Stop
        
        Write-LogMessage -Message "Successfully connected to Microsoft Graph" -Level "Success"
    }
    catch {
        Write-LogMessage -Message "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level "Error"
        exit 1
    }
}
else {
    Write-LogMessage -Message "Already connected as: $($context.Account)" -Level "Success"
    
    # Verify required scopes
    $requiredScopes = @(
        "DeviceManagementConfiguration.ReadWrite.All",
        "DeviceManagementApps.ReadWrite.All"
    )
    
    $missingScopes = $requiredScopes | Where-Object { $context.Scopes -notcontains $_ }
    
    if ($missingScopes.Count -gt 0) {
        Write-LogMessage -Message "Missing required scopes - reconnecting..." -Level "Warning"
        Disconnect-MgGraph | Out-Null
        Connect-MgGraph -Scopes $requiredScopes -NoWelcome -ErrorAction Stop
    }
}

$context = Get-MgContext
Write-LogMessage -Message "Tenant ID: $($context.TenantId)" -Level "Info"
Write-Host ""

####################################################
# Import Results Tracking
####################################################

$importResults = @()

####################################################
# Import Compliance Policies
####################################################

Write-Host ""
Write-Host "###############################################" -ForegroundColor Magenta
Write-Host "# COMPLIANCE POLICIES" -ForegroundColor Magenta
Write-Host "###############################################" -ForegroundColor Magenta

$importResults += Invoke-PolicyImportWithCheck -ScriptPath $ImportComplianceScript -JSONFilePath "$JSONPath\level-1-fm-basic-security-compliance.json" -PolicyType "Compliance"
$importResults += Invoke-PolicyImportWithCheck -ScriptPath $ImportComplianceScript -JSONFilePath "$JSONPath\level-2-fm-enhanced-security-compliance.json" -PolicyType "Compliance"
$importResults += Invoke-PolicyImportWithCheck -ScriptPath $ImportComplianceScript -JSONFilePath "$JSONPath\level-3-fm-high-security-compliance.json" -PolicyType "Compliance"
$importResults += Invoke-PolicyImportWithCheck -ScriptPath $ImportComplianceScript -JSONFilePath "$JSONPath\level-2-wp-enhanced-security-compliance.json" -PolicyType "Compliance"
$importResults += Invoke-PolicyImportWithCheck -ScriptPath $ImportComplianceScript -JSONFilePath "$JSONPath\level-3-wp-high-security-compliance.json" -PolicyType "Compliance"
$importResults += Invoke-PolicyImportWithCheck -ScriptPath $ImportComplianceScript -JSONFilePath "$JSONPath\level-2-iOS_iPadOS-enhanced-security-compliance.json" -PolicyType "Compliance"
$importResults += Invoke-PolicyImportWithCheck -ScriptPath $ImportComplianceScript -JSONFilePath "$JSONPath\level-3-iOS_iPadOS-high-security-compliance.json" -PolicyType "Compliance"

####################################################
# Import Device Configuration Policies
####################################################

Write-Host ""
Write-Host "###############################################" -ForegroundColor Magenta
Write-Host "# DEVICE CONFIGURATION POLICIES" -ForegroundColor Magenta
Write-Host "###############################################" -ForegroundColor Magenta

$importResults += Invoke-PolicyImportWithCheck -ScriptPath $ImportDeviceConfigScript -JSONFilePath "$JSONPath\level-1-fm-basic-security-configuration.json" -PolicyType "DeviceConfiguration"
$importResults += Invoke-PolicyImportWithCheck -ScriptPath $ImportDeviceConfigScript -JSONFilePath "$JSONPath\level-2-fm-enhanced-security-configuration.json" -PolicyType "DeviceConfiguration"
$importResults += Invoke-PolicyImportWithCheck -ScriptPath $ImportDeviceConfigScript -JSONFilePath "$JSONPath\level-3-fm-high-security-configuration.json" -PolicyType "DeviceConfiguration"
$importResults += Invoke-PolicyImportWithCheck -ScriptPath $ImportDeviceConfigScript -JSONFilePath "$JSONPath\level-2-wp-enhanced-security-configuration.json" -PolicyType "DeviceConfiguration"
$importResults += Invoke-PolicyImportWithCheck -ScriptPath $ImportDeviceConfigScript -JSONFilePath "$JSONPath\level-3-wp-high-security-configuration.json" -PolicyType "DeviceConfiguration"
$importResults += Invoke-PolicyImportWithCheck -ScriptPath $ImportDeviceConfigScript -JSONFilePath "$JSONPath\level-1-iOS_iPadOS-personal-basic-security-configuration.json" -PolicyType "DeviceConfiguration"
$importResults += Invoke-PolicyImportWithCheck -ScriptPath $ImportDeviceConfigScript -JSONFilePath "$JSONPath\level-2-iOS_iPadOS-personal-enhanced-security-configuration.json" -PolicyType "DeviceConfiguration"
$importResults += Invoke-PolicyImportWithCheck -ScriptPath $ImportDeviceConfigScript -JSONFilePath "$JSONPath\level-3-iOS_iPadOS-personal-high-security-configuration.json" -PolicyType "DeviceConfiguration"
$importResults += Invoke-PolicyImportWithCheck -ScriptPath $ImportDeviceConfigScript -JSONFilePath "$JSONPath\level-1-iOS_iPadOS-supervised-basic-security-configuration.json" -PolicyType "DeviceConfiguration"
$importResults += Invoke-PolicyImportWithCheck -ScriptPath $ImportDeviceConfigScript -JSONFilePath "$JSONPath\level-2-iOS_iPadOS-supervised-enhanced-security-configuration.json" -PolicyType "DeviceConfiguration"
$importResults += Invoke-PolicyImportWithCheck -ScriptPath $ImportDeviceConfigScript -JSONFilePath "$JSONPath\level-3-iOS_iPadOS-supervised-high-security-configuration.json" -PolicyType "DeviceConfiguration"

####################################################
# Import App Protection Policies
####################################################

Write-Host ""
Write-Host "###############################################" -ForegroundColor Magenta
Write-Host "# APP PROTECTION POLICIES" -ForegroundColor Magenta
Write-Host "###############################################" -ForegroundColor Magenta

$importResults += Invoke-PolicyImportWithCheck -ScriptPath $ImportAppProtectionScript -JSONFilePath "$JSONPath\level-1-enterprise-basic-data-protection-Android.json" -PolicyType "AppProtection"
$importResults += Invoke-PolicyImportWithCheck -ScriptPath $ImportAppProtectionScript -JSONFilePath "$JSONPath\level-1-enterprise-basic-data-protection-iOS.json" -PolicyType "AppProtection"
$importResults += Invoke-PolicyImportWithCheck -ScriptPath $ImportAppProtectionScript -JSONFilePath "$JSONPath\level-2-enterprise-enhanced-data-protection-Android.json" -PolicyType "AppProtection"
$importResults += Invoke-PolicyImportWithCheck -ScriptPath $ImportAppProtectionScript -JSONFilePath "$JSONPath\level-2-enterprise-enhanced-data-protection-iOS.json" -PolicyType "AppProtection"
$importResults += Invoke-PolicyImportWithCheck -ScriptPath $ImportAppProtectionScript -JSONFilePath "$JSONPath\level-3-enterprise-high-data-protection-Android.json" -PolicyType "AppProtection"
$importResults += Invoke-PolicyImportWithCheck -ScriptPath $ImportAppProtectionScript -JSONFilePath "$JSONPath\level-3-enterprise-high-data-protection-iOS.json" -PolicyType "AppProtection"

####################################################
# Summary Report
####################################################

$endTime = Get-Date
$duration = $endTime - $startTime

Write-Host ""
Write-Host "========================================" -ForegroundColor Magenta
Write-Host " Import Summary Report" -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta
Write-Host ""

# Display detailed results table
$importResults | Format-Table -Property FileName, PolicyType, Action, Status -AutoSize

# Calculate statistics
$totalPolicies = $importResults.Count
$imported = ($importResults | Where-Object { $_.Action -eq "Imported" }).Count
$skipped = ($importResults | Where-Object { $_.Action -eq "Skipped" }).Count
$failed = ($importResults | Where-Object { $_.Action -eq "Failed" }).Count

Write-Host ""
Write-Host "Statistics:" -ForegroundColor Cyan
Write-Host "  Total Policies Processed: $totalPolicies" -ForegroundColor White
Write-Host "  Successfully Imported: $imported" -ForegroundColor Green
Write-Host "  Skipped (Already Exist): $skipped" -ForegroundColor Yellow
Write-Host "  Failed: $failed" -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "Green" })
Write-Host ""

# Breakdown by policy type
Write-Host "Breakdown by Policy Type:" -ForegroundColor Cyan

$compliancePolicies = $importResults | Where-Object { $_.PolicyType -eq "Compliance" }
$deviceConfigPolicies = $importResults | Where-Object { $_.PolicyType -eq "DeviceConfiguration" }
$appProtectionPolicies = $importResults | Where-Object { $_.PolicyType -eq "AppProtection" }

Write-Host "  Compliance Policies:" -ForegroundColor White
Write-Host "    Total: $($compliancePolicies.Count)" -ForegroundColor White
Write-Host "    Imported: $(($compliancePolicies | Where-Object { $_.Action -eq 'Imported' }).Count)" -ForegroundColor Green
Write-Host "    Skipped: $(($compliancePolicies | Where-Object { $_.Action -eq 'Skipped' }).Count)" -ForegroundColor Yellow
Write-Host ""

Write-Host "  Device Configuration Policies:" -ForegroundColor White
Write-Host "    Total: $($deviceConfigPolicies.Count)" -ForegroundColor White
Write-Host "    Imported: $(($deviceConfigPolicies | Where-Object { $_.Action -eq 'Imported' }).Count)" -ForegroundColor Green
Write-Host "    Skipped: $(($deviceConfigPolicies | Where-Object { $_.Action -eq 'Skipped' }).Count)" -ForegroundColor Yellow
Write-Host ""

Write-Host "  App Protection Policies:" -ForegroundColor White
Write-Host "    Total: $($appProtectionPolicies.Count)" -ForegroundColor White
Write-Host "    Imported: $(($appProtectionPolicies | Where-Object { $_.Action -eq 'Imported' }).Count)" -ForegroundColor Green
Write-Host "    Skipped: $(($appProtectionPolicies | Where-Object { $_.Action -eq 'Skipped' }).Count)" -ForegroundColor Yellow
Write-Host ""

Write-Host "Total Execution Time: $($duration.ToString('mm\:ss'))" -ForegroundColor Cyan
Write-Host ""

# Export results to CSV for record keeping
$reportPath = "$RepoPath\Import-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
$importResults | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

Write-LogMessage -Message "Detailed report saved to: $reportPath" -Level "Info"
Write-Host ""

# Exit code based on failures
if ($failed -gt 0) {
    Write-LogMessage -Message "Batch import completed with $failed failure(s)" -Level "Warning"
    exit 1
}
else {
    Write-LogMessage -Message "Batch import completed successfully" -Level "Success"
    exit 0
}