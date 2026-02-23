<#
.SYNOPSIS
    Assigns "EUD" scope tag to Intune policies and removes "Default" scope tag

.DESCRIPTION
    This script iterates through Compliance Policies, Device Configuration Policies, 
    and App Protection Policies in Microsoft Intune. For policies that:
    - Do NOT start with "PAW-"
    - Have ONLY the "Default" scope tag assigned
    
    The script will:
    - Remove the "Default" scope tag
    - Assign the "EUD" scope tag

.NOTES
    Requires: Microsoft.Graph PowerShell Module
    Required Permissions:
    - DeviceManagementConfiguration.ReadWrite.All
    - DeviceManagementApps.ReadWrite.All
    - DeviceManagementRBAC.ReadWrite.All

.EXAMPLE
    .\Set-IntuneScopeTags.ps1

.EXAMPLE
    .\Set-IntuneScopeTags.ps1 -WhatIf

.AUTHOR
    IT Operations Team

.VERSION
    1.2 - Fixed app protection policy handling
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

#region Helper Functions

Function Write-Log {
    <#
    .SYNOPSIS
        Writes formatted log messages
    #>
    param(
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
    
    # Also write to log file
    $logFile = "ScopeTag-Assignment-$(Get-Date -Format 'yyyyMMdd').log"
    "$timestamp [$Level] $Message" | Out-File -FilePath $logFile -Append -Encoding UTF8
}

#endregion

#region Main Script

Write-Host ""
Write-Host "========================================" -ForegroundColor Magenta
Write-Host " Intune Scope Tag Assignment Script" -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta
Write-Host ""

if ($WhatIf) {
    Write-Log -Message "Running in WhatIf mode - no changes will be made" -Level "Warning"
}

$startTime = Get-Date

#region Authentication

Write-Log -Message "Checking Microsoft Graph PowerShell module..." -Level "Info"

# Check if Microsoft.Graph module is installed
$graphModule = Get-Module -Name "Microsoft.Graph.Authentication" -ListAvailable

if ($null -eq $graphModule) {
    Write-Log -Message "Microsoft.Graph PowerShell module not found" -Level "Error"
    Write-Host ""
    Write-Host "Install the module with: Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

Write-Log -Message "Microsoft Graph module found - Version: $($graphModule.Version | Select-Object -First 1)" -Level "Success"

# Check connection
$context = Get-MgContext

if ($null -eq $context) {
    Write-Log -Message "Connecting to Microsoft Graph..." -Level "Info"
    
    try {
        Connect-MgGraph -Scopes @(
            "DeviceManagementConfiguration.ReadWrite.All",
            "DeviceManagementApps.ReadWrite.All",
            "DeviceManagementRBAC.ReadWrite.All"
        ) -NoWelcome -ErrorAction Stop
        
        Write-Log -Message "Successfully connected to Microsoft Graph" -Level "Success"
    }
    catch {
        Write-Log -Message "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level "Error"
        exit 1
    }
}
else {
    Write-Log -Message "Already connected as: $($context.Account)" -Level "Info"
    
    # Verify required scopes
    $requiredScopes = @(
        "DeviceManagementConfiguration.ReadWrite.All",
        "DeviceManagementApps.ReadWrite.All",
        "DeviceManagementRBAC.ReadWrite.All"
    )
    
    $missingScopes = $requiredScopes | Where-Object { $context.Scopes -notcontains $_ }
    
    if ($missingScopes.Count -gt 0) {
        Write-Log -Message "Missing required scopes - reconnecting..." -Level "Warning"
        Disconnect-MgGraph | Out-Null
        Connect-MgGraph -Scopes $requiredScopes -NoWelcome -ErrorAction Stop
    }
}

$context = Get-MgContext
Write-Log -Message "Tenant ID: $($context.TenantId)" -Level "Info"
Write-Host ""

#endregion

#region Get Scope Tags

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Retrieving Scope Tags" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Log -Message "Retrieving scope tags from Intune..." -Level "Info"

try {
    # Get all scope tags
    $uri = "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags"
    $scopeTagsResponse = Invoke-MgGraphRequest -Method GET -Uri $uri
    $scopeTags = $scopeTagsResponse.value
    
    Write-Log -Message "Found $($scopeTags.Count) scope tags" -Level "Success"
    
    # Find Default scope tag (ID = 0)
    $defaultScopeTag = $scopeTags | Where-Object { $_.id -eq "0" }
    
    if ($defaultScopeTag) {
        Write-Log -Message "Default scope tag: ID=$($defaultScopeTag.id), Name=$($defaultScopeTag.displayName)" -Level "Info"
    }
    else {
        Write-Log -Message "Note: Default scope tag (ID=0) is implicit and may not appear in the list" -Level "Info"
    }
    
    # Find EUD scope tag
    $eudScopeTag = $scopeTags | Where-Object { $_.displayName -eq "EUD" }
    
    if ($null -eq $eudScopeTag) {
        Write-Log -Message "ERROR: 'EUD' scope tag not found in tenant" -Level "Error"
        Write-Log -Message "Please create the 'EUD' scope tag first: Tenant administration > Roles > Scope tags" -Level "Error"
        Write-Host ""
        Write-Host "Available scope tags:" -ForegroundColor Yellow
        $scopeTags | Select-Object id, displayName, description | Format-Table -AutoSize
        exit 1
    }
    
    Write-Log -Message "EUD scope tag: ID=$($eudScopeTag.id), Name=$($eudScopeTag.displayName)" -Level "Success"
    
    $eudScopeTagId = $eudScopeTag.id
    
}
catch {
    Write-Log -Message "Failed to retrieve scope tags: $($_.Exception.Message)" -Level "Error"
    exit 1
}

Write-Host ""

#endregion

#region Process Policies

$processedPolicies = @()
$updatedCount = 0
$skippedCount = 0
$errorCount = 0

#region Compliance Policies

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Processing Compliance Policies" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Log -Message "Retrieving device compliance policies..." -Level "Info"

try {
    # Request with $select to ensure we get roleScopeTagIds
    $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies?`$select=id,displayName,roleScopeTagIds"
    $compliancePoliciesResponse = Invoke-MgGraphRequest -Method GET -Uri $uri
    $compliancePolicies = $compliancePoliciesResponse.value
    
    Write-Log -Message "Found $($compliancePolicies.Count) compliance policies" -Level "Info"
    
    foreach ($policy in $compliancePolicies) {
        Write-Host ""
        Write-Log -Message "Processing: $($policy.displayName)" -Level "Info"
        Write-Log -Message "  Type: Compliance Policy" -Level "Info"
        Write-Log -Message "  ID: $($policy.id)" -Level "Info"
        
        # Check if policy name starts with "PAW-"
        if ($policy.displayName -like "PAW-*") {
            Write-Log -Message "  SKIPPED: Policy name starts with 'PAW-'" -Level "Warning"
            $skippedCount++
            
            $processedPolicies += [PSCustomObject]@{
                PolicyName = $policy.displayName
                PolicyType = "Compliance"
                Action = "Skipped - PAW prefix"
                OldScopeTags = "N/A"
                NewScopeTags = "N/A"
            }
            continue
        }
        
        # Get current role scope tag IDs
        # If roleScopeTagIds is null or empty, it means Default (0) is assigned
        if ($null -eq $policy.roleScopeTagIds -or $policy.roleScopeTagIds.Count -eq 0) {
            $currentScopeTagIds = @("0")
            Write-Log -Message "  Policy has no explicit scope tags - treating as Default (0)" -Level "Info"
        }
        else {
            $currentScopeTagIds = $policy.roleScopeTagIds
            Write-Log -Message "  Current scope tags: $($currentScopeTagIds -join ', ')" -Level "Info"
        }
        
        # Check if only Default scope tag (ID = 0) is assigned
        if ($currentScopeTagIds.Count -eq 1 -and $currentScopeTagIds[0] -eq "0") {
            Write-Log -Message "  Policy has only Default scope tag - will update" -Level "Info"
            
            if (!$WhatIf) {
                try {
                    # Update policy with EUD scope tag
                    $updateUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$($policy.id)"
                    $body = @{
                        roleScopeTagIds = @($eudScopeTagId)
                    } | ConvertTo-Json -Depth 10
                    
                    Invoke-MgGraphRequest -Method PATCH -Uri $updateUri -Body $body -ContentType "application/json"
                    
                    Write-Log -Message "  SUCCESS: Updated scope tag to EUD (ID: $eudScopeTagId)" -Level "Success"
                    $updatedCount++
                    
                    $processedPolicies += [PSCustomObject]@{
                        PolicyName = $policy.displayName
                        PolicyType = "Compliance"
                        Action = "Updated"
                        OldScopeTags = "0 (Default)"
                        NewScopeTags = "$eudScopeTagId (EUD)"
                    }
                }
                catch {
                    Write-Log -Message "  ERROR: Failed to update policy: $($_.Exception.Message)" -Level "Error"
                    
                    # Try to get more detailed error
                    if ($_.ErrorDetails.Message) {
                        try {
                            $errorDetail = $_.ErrorDetails.Message | ConvertFrom-Json
                            Write-Log -Message "  Error detail: $($errorDetail.error.message)" -Level "Error"
                        }
                        catch {
                            Write-Log -Message "  Error detail: $($_.ErrorDetails.Message)" -Level "Error"
                        }
                    }
                    
                    $errorCount++
                    
                    $processedPolicies += [PSCustomObject]@{
                        PolicyName = $policy.displayName
                        PolicyType = "Compliance"
                        Action = "Error"
                        OldScopeTags = "0 (Default)"
                        NewScopeTags = "Failed"
                    }
                }
            }
            else {
                Write-Log -Message "  WHATIF: Would update scope tag to EUD (ID: $eudScopeTagId)" -Level "Warning"
                $updatedCount++
                
                $processedPolicies += [PSCustomObject]@{
                    PolicyName = $policy.displayName
                    PolicyType = "Compliance"
                    Action = "WhatIf - Would Update"
                    OldScopeTags = "0 (Default)"
                    NewScopeTags = "$eudScopeTagId (EUD)"
                }
            }
        }
        else {
            if ($currentScopeTagIds.Count -eq 0) {
                Write-Log -Message "  SKIPPED: Policy has no scope tags assigned (unexpected state)" -Level "Warning"
            }
            elseif ($currentScopeTagIds.Count -gt 1) {
                Write-Log -Message "  SKIPPED: Policy has multiple scope tags ($($currentScopeTagIds -join ', '))" -Level "Warning"
            }
            elseif ($currentScopeTagIds[0] -ne "0") {
                Write-Log -Message "  SKIPPED: Policy has custom scope tag ($($currentScopeTagIds[0])), not Default" -Level "Warning"
            }
            
            $skippedCount++
            
            $processedPolicies += [PSCustomObject]@{
                PolicyName = $policy.displayName
                PolicyType = "Compliance"
                Action = "Skipped - Multiple or non-Default tags"
                OldScopeTags = ($currentScopeTagIds -join ", ")
                NewScopeTags = ($currentScopeTagIds -join ", ")
            }
        }
    }
}
catch {
    Write-Log -Message "Failed to retrieve or process compliance policies: $($_.Exception.Message)" -Level "Error"
}

Write-Host ""

#endregion

#region Device Configuration Policies

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Processing Device Configuration Policies" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Log -Message "Retrieving device configuration policies..." -Level "Info"

try {
    # Request with $select to ensure we get roleScopeTagIds
    $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$select=id,displayName,roleScopeTagIds"
    $configPoliciesResponse = Invoke-MgGraphRequest -Method GET -Uri $uri
    $configPolicies = $configPoliciesResponse.value
    
    Write-Log -Message "Found $($configPolicies.Count) device configuration policies" -Level "Info"
    
    foreach ($policy in $configPolicies) {
        Write-Host ""
        Write-Log -Message "Processing: $($policy.displayName)" -Level "Info"
        Write-Log -Message "  Type: Device Configuration" -Level "Info"
        Write-Log -Message "  ID: $($policy.id)" -Level "Info"
        
        # Check if policy name starts with "PAW-"
        if ($policy.displayName -like "PAW-*") {
            Write-Log -Message "  SKIPPED: Policy name starts with 'PAW-'" -Level "Warning"
            $skippedCount++
            
            $processedPolicies += [PSCustomObject]@{
                PolicyName = $policy.displayName
                PolicyType = "Device Configuration"
                Action = "Skipped - PAW prefix"
                OldScopeTags = "N/A"
                NewScopeTags = "N/A"
            }
            continue
        }
        
        # Get current role scope tag IDs
        # If roleScopeTagIds is null or empty, it means Default (0) is assigned
        if ($null -eq $policy.roleScopeTagIds -or $policy.roleScopeTagIds.Count -eq 0) {
            $currentScopeTagIds = @("0")
            Write-Log -Message "  Policy has no explicit scope tags - treating as Default (0)" -Level "Info"
        }
        else {
            $currentScopeTagIds = $policy.roleScopeTagIds
            Write-Log -Message "  Current scope tags: $($currentScopeTagIds -join ', ')" -Level "Info"
        }
        
        # Check if only Default scope tag (ID = 0) is assigned
        if ($currentScopeTagIds.Count -eq 1 -and $currentScopeTagIds[0] -eq "0") {
            Write-Log -Message "  Policy has only Default scope tag - will update" -Level "Info"
            
            if (!$WhatIf) {
                try {
                    # Update policy with EUD scope tag
                    $updateUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$($policy.id)"
                    $body = @{
                        roleScopeTagIds = @($eudScopeTagId)
                    } | ConvertTo-Json -Depth 10
                    
                    Invoke-MgGraphRequest -Method PATCH -Uri $updateUri -Body $body -ContentType "application/json"
                    
                    Write-Log -Message "  SUCCESS: Updated scope tag to EUD (ID: $eudScopeTagId)" -Level "Success"
                    $updatedCount++
                    
                    $processedPolicies += [PSCustomObject]@{
                        PolicyName = $policy.displayName
                        PolicyType = "Device Configuration"
                        Action = "Updated"
                        OldScopeTags = "0 (Default)"
                        NewScopeTags = "$eudScopeTagId (EUD)"
                    }
                }
                catch {
                    Write-Log -Message "  ERROR: Failed to update policy: $($_.Exception.Message)" -Level "Error"
                    
                    # Try to get more detailed error
                    if ($_.ErrorDetails.Message) {
                        try {
                            $errorDetail = $_.ErrorDetails.Message | ConvertFrom-Json
                            Write-Log -Message "  Error detail: $($errorDetail.error.message)" -Level "Error"
                        }
                        catch {
                            Write-Log -Message "  Error detail: $($_.ErrorDetails.Message)" -Level "Error"
                        }
                    }
                    
                    $errorCount++
                    
                    $processedPolicies += [PSCustomObject]@{
                        PolicyName = $policy.displayName
                        PolicyType = "Device Configuration"
                        Action = "Error"
                        OldScopeTags = "0 (Default)"
                        NewScopeTags = "Failed"
                    }
                }
            }
            else {
                Write-Log -Message "  WHATIF: Would update scope tag to EUD (ID: $eudScopeTagId)" -Level "Warning"
                $updatedCount++
                
                $processedPolicies += [PSCustomObject]@{
                    PolicyName = $policy.displayName
                    PolicyType = "Device Configuration"
                    Action = "WhatIf - Would Update"
                    OldScopeTags = "0 (Default)"
                    NewScopeTags = "$eudScopeTagId (EUD)"
                }
            }
        }
        else {
            if ($currentScopeTagIds.Count -eq 0) {
                Write-Log -Message "  SKIPPED: Policy has no scope tags assigned (unexpected state)" -Level "Warning"
            }
            elseif ($currentScopeTagIds.Count -gt 1) {
                Write-Log -Message "  SKIPPED: Policy has multiple scope tags ($($currentScopeTagIds -join ', '))" -Level "Warning"
            }
            elseif ($currentScopeTagIds[0] -ne "0") {
                Write-Log -Message "  SKIPPED: Policy has custom scope tag ($($currentScopeTagIds[0])), not Default" -Level "Warning"
            }
            
            $skippedCount++
            
            $processedPolicies += [PSCustomObject]@{
                PolicyName = $policy.displayName
                PolicyType = "Device Configuration"
                Action = "Skipped - Multiple or non-Default tags"
                OldScopeTags = ($currentScopeTagIds -join ", ")
                NewScopeTags = ($currentScopeTagIds -join ", ")
            }
        }
    }
}
catch {
    Write-Log -Message "Failed to retrieve or process device configuration policies: $($_.Exception.Message)" -Level "Error"
}

Write-Host ""

#endregion

#region App Protection Policies

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Processing App Protection Policies" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Log -Message "Retrieving app protection policies..." -Level "Info"

try {
    # App protection policies have multiple endpoints for different platforms
    $appProtectionEndpoints = @(
        @{Name = "iOS"; Uri = "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections"},
        @{Name = "Android"; Uri = "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections"},
        @{Name = "Windows"; Uri = "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections"}
    )
    
    foreach ($endpoint in $appProtectionEndpoints) {
        Write-Log -Message "Checking $($endpoint.Name) app protection policies..." -Level "Info"
        
        try {
            # CRITICAL FIX: Add $select parameter to get roleScopeTagIds
            $listUri = "$($endpoint.Uri)?`$select=id,displayName,roleScopeTagIds"
            $response = Invoke-MgGraphRequest -Method GET -Uri $listUri -ErrorAction SilentlyContinue
            $policies = $response.value
            
            if ($policies.Count -gt 0) {
                Write-Log -Message "Found $($policies.Count) $($endpoint.Name) app protection policies" -Level "Info"
                
                foreach ($policy in $policies) {
                    Write-Host ""
                    Write-Log -Message "Processing: $($policy.displayName)" -Level "Info"
                    Write-Log -Message "  Type: $($endpoint.Name) App Protection" -Level "Info"
                    Write-Log -Message "  ID: $($policy.id)" -Level "Info"
                    
                    # Check if policy name starts with "PAW-"
                    if ($policy.displayName -like "PAW-*") {
                        Write-Log -Message "  SKIPPED: Policy name starts with 'PAW-'" -Level "Warning"
                        $skippedCount++
                        
                        $processedPolicies += [PSCustomObject]@{
                            PolicyName = $policy.displayName
                            PolicyType = "$($endpoint.Name) App Protection"
                            Action = "Skipped - PAW prefix"
                            OldScopeTags = "N/A"
                            NewScopeTags = "N/A"
                        }
                        continue
                    }
                    
                    # CRITICAL FIX: For app protection policies, sometimes we need to retrieve full policy details
                    # to get roleScopeTagIds if it's not in the list response
                    if ($null -eq $policy.roleScopeTagIds) {
                        Write-Log -Message "  Retrieving full policy details to get scope tags..." -Level "Info"
                        try {
                            $detailUri = "$($endpoint.Uri)/$($policy.id)?`$select=id,displayName,roleScopeTagIds"
                            $policyDetail = Invoke-MgGraphRequest -Method GET -Uri $detailUri -ErrorAction Stop
                            
                            if ($null -ne $policyDetail.roleScopeTagIds -and $policyDetail.roleScopeTagIds.Count -gt 0) {
                                $policy.roleScopeTagIds = $policyDetail.roleScopeTagIds
                            }
                        }
                        catch {
                            Write-Log -Message "  Warning: Could not retrieve full policy details: $($_.Exception.Message)" -Level "Warning"
                        }
                    }
                    
                    # Get current role scope tag IDs
                    if ($null -eq $policy.roleScopeTagIds -or $policy.roleScopeTagIds.Count -eq 0) {
                        $currentScopeTagIds = @("0")
                        Write-Log -Message "  Policy has no explicit scope tags - treating as Default (0)" -Level "Info"
                    }
                    else {
                        $currentScopeTagIds = $policy.roleScopeTagIds
                        Write-Log -Message "  Current scope tags: $($currentScopeTagIds -join ', ')" -Level "Info"
                    }
                    
                    # Check if only Default scope tag (ID = 0) is assigned
                    if ($currentScopeTagIds.Count -eq 1 -and $currentScopeTagIds[0] -eq "0") {
                        Write-Log -Message "  Policy has only Default scope tag - will update" -Level "Info"
                        
                        if (!$WhatIf) {
                            try {
                                # Update URI for app protection policy
                                $updateUri = "$($endpoint.Uri)/$($policy.id)"
                                
                                $body = @{
                                    roleScopeTagIds = @($eudScopeTagId)
                                } | ConvertTo-Json -Depth 10
                                
                                Invoke-MgGraphRequest -Method PATCH -Uri $updateUri -Body $body -ContentType "application/json"
                                
                                Write-Log -Message "  SUCCESS: Updated scope tag to EUD (ID: $eudScopeTagId)" -Level "Success"
                                $updatedCount++
                                
                                $processedPolicies += [PSCustomObject]@{
                                    PolicyName = $policy.displayName
                                    PolicyType = "$($endpoint.Name) App Protection"
                                    Action = "Updated"
                                    OldScopeTags = "0 (Default)"
                                    NewScopeTags = "$eudScopeTagId (EUD)"
                                }
                            }
                            catch {
                                Write-Log -Message "  ERROR: Failed to update policy: $($_.Exception.Message)" -Level "Error"
                                
                                if ($_.ErrorDetails.Message) {
                                    try {
                                        $errorDetail = $_.ErrorDetails.Message | ConvertFrom-Json
                                        Write-Log -Message "  Error detail: $($errorDetail.error.message)" -Level "Error"
                                    }
                                    catch {
                                        Write-Log -Message "  Error detail: $($_.ErrorDetails.Message)" -Level "Error"
                                    }
                                }
                                
                                $errorCount++
                                
                                $processedPolicies += [PSCustomObject]@{
                                    PolicyName = $policy.displayName
                                    PolicyType = "$($endpoint.Name) App Protection"
                                    Action = "Error"
                                    OldScopeTags = "0 (Default)"
                                    NewScopeTags = "Failed"
                                }
                            }
                        }
                        else {
                            Write-Log -Message "  WHATIF: Would update scope tag to EUD (ID: $eudScopeTagId)" -Level "Warning"
                            $updatedCount++
                            
                            $processedPolicies += [PSCustomObject]@{
                                PolicyName = $policy.displayName
                                PolicyType = "$($endpoint.Name) App Protection"
                                Action = "WhatIf - Would Update"
                                OldScopeTags = "0 (Default)"
                                NewScopeTags = "$eudScopeTagId (EUD)"
                            }
                        }
                    }
                    else {
                        if ($currentScopeTagIds.Count -gt 1) {
                            Write-Log -Message "  SKIPPED: Policy has multiple scope tags ($($currentScopeTagIds -join ', '))" -Level "Warning"
                        }
                        elseif ($currentScopeTagIds[0] -ne "0") {
                            Write-Log -Message "  SKIPPED: Policy has custom scope tag ($($currentScopeTagIds[0])), not Default" -Level "Warning"
                        }
                        
                        $skippedCount++
                        
                        $processedPolicies += [PSCustomObject]@{
                            PolicyName = $policy.displayName
                            PolicyType = "$($endpoint.Name) App Protection"
                            Action = "Skipped - Multiple or non-Default tags"
                            OldScopeTags = ($currentScopeTagIds -join ", ")
                            NewScopeTags = ($currentScopeTagIds -join ", ")
                        }
                    }
                }
            }
            else {
                Write-Log -Message "No $($endpoint.Name) app protection policies found" -Level "Info"
            }
        }
        catch {
            Write-Log -Message "Failed to retrieve $($endpoint.Name) app protection policies: $($_.Exception.Message)" -Level "Warning"
        }
    }
}
catch {
    Write-Log -Message "Failed to process app protection policies: $($_.Exception.Message)" -Level "Error"
}

Write-Host ""

#endregion

#endregion

#region Summary Report

$endTime = Get-Date
$duration = $endTime - $startTime

Write-Host ""
Write-Host "========================================" -ForegroundColor Magenta
Write-Host " Summary Report" -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta
Write-Host ""

# Display summary table
Write-Host "Processed Policies:" -ForegroundColor Cyan
$processedPolicies | Format-Table -Property PolicyName, PolicyType, Action, OldScopeTags, NewScopeTags -AutoSize

Write-Host ""
Write-Host "Statistics:" -ForegroundColor Cyan
Write-Host "  Total Policies Processed: $($processedPolicies.Count)" -ForegroundColor White

if ($WhatIf) {
    Write-Host "  Policies That Would Be Updated: $updatedCount" -ForegroundColor Yellow
}
else {
    Write-Host "  Policies Updated: $updatedCount" -ForegroundColor Green
}

Write-Host "  Policies Skipped: $skippedCount" -ForegroundColor Yellow
Write-Host "  Errors: $errorCount" -ForegroundColor $(if ($errorCount -gt 0) { "Red" } else { "Green" })
Write-Host ""

Write-Host "Execution Time: $($duration.ToString('mm\:ss'))" -ForegroundColor Cyan
Write-Host ""

# Export results to CSV
$reportPath = "ScopeTag-Assignment-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
$processedPolicies | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

Write-Log -Message "Detailed report saved to: $reportPath" -Level "Info"
Write-Host ""

if ($WhatIf) {
    Write-Host "WhatIf mode completed - no changes were made" -ForegroundColor Yellow
    Write-Host "Run the script without -WhatIf parameter to apply changes" -ForegroundColor Yellow
}
elseif ($errorCount -gt 0) {
    Write-Log -Message "Script completed with $errorCount error(s)" -Level "Warning"
    exit 1
}
else {
    Write-Log -Message "Script completed successfully" -Level "Success"
    exit 0
}

#endregion

#endregion