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
    1.3 - Added pagination, retry logic, and removed code duplication
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

Function Invoke-MgGraphRequestWithRetry {
    <#
    .SYNOPSIS
        Invokes a Graph API request with exponential backoff and jitter for rate limits.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Method,
        [Parameter(Mandatory=$true)]
        [string]$Uri,
        [Parameter(Mandatory=$false)]
        [string]$Body,
        [Parameter(Mandatory=$false)]
        [string]$ContentType = "application/json",
        [Parameter(Mandatory=$false)]
        [int]$MaxRetries = 5
    )
    $retryCount = 0
    $baseDelayMs = 1000
    
    while ($true) {
        try {
            if ($Body) {
                return Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body $Body -ContentType $ContentType -ErrorAction Stop
            } else {
                return Invoke-MgGraphRequest -Method $Method -Uri $Uri -ErrorAction Stop
            }
        }
        catch {
            $errorRecord = $_
            $exception = $errorRecord.Exception
            $statusCode = 0
            
            if ($exception.Response) {
                $statusCode = [int]$exception.Response.StatusCode
            } elseif ($errorRecord.ErrorDetails -and $errorRecord.ErrorDetails.Message) {
                if ($errorRecord.ErrorDetails.Message -match 'TooManyRequests|429') {
                    $statusCode = 429
                }
            }
            
            # Retry on 429 (Too Many Requests) or 5xx errors
            if ($statusCode -eq 429 -or ($statusCode -ge 500 -and $statusCode -lt 600)) {
                if ($retryCount -ge $MaxRetries) {
                    Write-Log -Message "Max retries ($MaxRetries) reached for $Uri" -Level "Error"
                    throw $errorRecord
                }
                $retryCount++
                # Respect Retry-After header when present, otherwise exponential backoff with jitter
                $retryAfterMs = 0
                if ($exception.Response -and $exception.Response.Headers) {
                    $retryAfterHeader = $exception.Response.Headers['Retry-After']
                    if ($retryAfterHeader) {
                        $retryAfterSec = 0
                        if ([int]::TryParse($retryAfterHeader, [ref]$retryAfterSec)) {
                            $retryAfterMs = $retryAfterSec * 1000
                        }
                    }
                }
                if ($retryAfterMs -gt 0) {
                    $delayMs = $retryAfterMs
                } else {
                    $jitter = Get-Random -Minimum 0 -Maximum 500
                    $delayMs = ($baseDelayMs * [math]::Pow(2, $retryCount - 1)) + $jitter
                }
                Write-Log -Message "Graph API rate limited or server error ($statusCode). Retrying in $($delayMs)ms (Attempt $retryCount of $MaxRetries)..." -Level "Warning"
                Start-Sleep -Milliseconds $delayMs
            }
            else {
                throw $errorRecord
            }
        }
    }
}

Function Process-PolicyScopeTags {
    <#
    .SYNOPSIS
        Processes a specific type of Intune policy, handling pagination and updating scope tags.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$EndpointUri,
        [Parameter(Mandatory=$true)]
        [string]$PolicyType,
        [Parameter(Mandatory=$true)]
        [string]$EudScopeTagId,
        [Parameter(Mandatory=$false)]
        [switch]$IsAppProtection,
        [Parameter(Mandatory=$false)]
        [switch]$WhatIfMode
    )
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host " Processing $PolicyType" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Log -Message "Retrieving $PolicyType..." -Level "Info"
    
    $localProcessed = @()
    $localUpdated = 0
    $localSkipped = 0
    $localError = 0
    
    $MaxPages = 100
    
    try {
        $currentUri = "$EndpointUri?`$select=id,displayName,roleScopeTagIds"
        $pageCount = 1
        
        while ($currentUri -and $pageCount -le $MaxPages) {
            Write-Log -Message "Fetching page $pageCount of $PolicyType..." -Level "Info"
            $response = Invoke-MgGraphRequestWithRetry -Method GET -Uri $currentUri
            $policies = $response.value
            
            if ($policies) {
                Write-Log -Message "Processing $($policies.Count) policies from page $pageCount..." -Level "Info"
                
                foreach ($policy in $policies) {
                    Write-Host ""
                    Write-Log -Message "Processing: $($policy.displayName)" -Level "Info"
                    Write-Log -Message "  Type: $PolicyType" -Level "Info"
                    Write-Log -Message "  ID: $($policy.id)" -Level "Info"
                    
                    # Check if policy name starts with "PAW-"
                    if ($policy.displayName -like "PAW-*") {
                        Write-Log -Message "  SKIPPED: Policy name starts with 'PAW-'" -Level "Warning"
                        $localSkipped++
                        
                        $localProcessed += [PSCustomObject]@{
                            PolicyName = $policy.displayName
                            PolicyType = $PolicyType
                            Action = "Skipped - PAW prefix"
                            OldScopeTags = "N/A"
                            NewScopeTags = "N/A"
                        }
                        continue
                    }
                    
                    # For app protection policies, sometimes we need to retrieve full policy details
                    if ($IsAppProtection -and $null -eq $policy.roleScopeTagIds) {
                        Write-Log -Message "  Retrieving full policy details to get scope tags..." -Level "Info"
                        try {
                            $detailUri = "$EndpointUri/$($policy.id)?`$select=id,displayName,roleScopeTagIds"
                            $policyDetail = Invoke-MgGraphRequestWithRetry -Method GET -Uri $detailUri
                            
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
                        
                        if (!$WhatIfMode) {
                            try {
                                $updateUri = "$EndpointUri/$($policy.id)"
                                $body = @{
                                    roleScopeTagIds = @($EudScopeTagId)
                                } | ConvertTo-Json -Depth 10
                                
                                Invoke-MgGraphRequestWithRetry -Method PATCH -Uri $updateUri -Body $body -ContentType "application/json"
                                
                                Write-Log -Message "  SUCCESS: Updated scope tag to EUD (ID: $EudScopeTagId)" -Level "Success"
                                $localUpdated++
                                
                                $localProcessed += [PSCustomObject]@{
                                    PolicyName = $policy.displayName
                                    PolicyType = $PolicyType
                                    Action = "Updated"
                                    OldScopeTags = "0 (Default)"
                                    NewScopeTags = "$EudScopeTagId (EUD)"
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
                                
                                $localError++
                                
                                $localProcessed += [PSCustomObject]@{
                                    PolicyName = $policy.displayName
                                    PolicyType = $PolicyType
                                    Action = "Error"
                                    OldScopeTags = "0 (Default)"
                                    NewScopeTags = "Failed"
                                }
                            }
                        }
                        else {
                            Write-Log -Message "  WHATIF: Would update scope tag to EUD (ID: $EudScopeTagId)" -Level "Warning"
                            $localUpdated++
                            
                            $localProcessed += [PSCustomObject]@{
                                PolicyName = $policy.displayName
                                PolicyType = $PolicyType
                                Action = "WhatIf - Would Update"
                                OldScopeTags = "0 (Default)"
                                NewScopeTags = "$EudScopeTagId (EUD)"
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
                        
                        $localSkipped++
                        
                        $localProcessed += [PSCustomObject]@{
                            PolicyName = $policy.displayName
                            PolicyType = $PolicyType
                            Action = "Skipped - Multiple or non-Default tags"
                            OldScopeTags = ($currentScopeTagIds -join ", ")
                            NewScopeTags = ($currentScopeTagIds -join ", ")
                        }
                    }
                }
            }
            else {
                Write-Log -Message "No $PolicyType found on page $pageCount" -Level "Info"
            }
            
            if ($response.'@odata.nextLink') {
                $currentUri = $response.'@odata.nextLink'
                $pageCount++
            } else {
                $currentUri = $null
            }
        }
        
        if ($pageCount -gt $MaxPages) {
            Write-Log -Message "Safety limit of $MaxPages pages reached for $PolicyType. Results may be incomplete." -Level "Error"
        }
    }
    catch {
        Write-Log -Message "Failed to retrieve or process $PolicyType : $($_.Exception.Message)" -Level "Error"
    }
    
    return @{
        Processed = $localProcessed
        Updated = $localUpdated
        Skipped = $localSkipped
        Error = $localError
    }
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
    $scopeTagsResponse = Invoke-MgGraphRequestWithRetry -Method GET -Uri $uri
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

# Compliance Policies
$result = Process-PolicyScopeTags -EndpointUri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies" -PolicyType "Compliance Policy" -EudScopeTagId $eudScopeTagId -WhatIfMode:$WhatIf
$processedPolicies += $result.Processed
$updatedCount += $result.Updated
$skippedCount += $result.Skipped
$errorCount += $result.Error

# Device Configuration Policies
$result = Process-PolicyScopeTags -EndpointUri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations" -PolicyType "Device Configuration" -EudScopeTagId $eudScopeTagId -WhatIfMode:$WhatIf
$processedPolicies += $result.Processed
$updatedCount += $result.Updated
$skippedCount += $result.Skipped
$errorCount += $result.Error

# App Protection Policies
$appProtectionEndpoints = @(
    @{Name = "iOS App Protection"; Uri = "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections"},
    @{Name = "Android App Protection"; Uri = "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections"},
    @{Name = "Windows App Protection"; Uri = "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections"}
)

foreach ($endpoint in $appProtectionEndpoints) {
    $result = Process-PolicyScopeTags -EndpointUri $endpoint.Uri -PolicyType $endpoint.Name -EudScopeTagId $eudScopeTagId -IsAppProtection -WhatIfMode:$WhatIf
    $processedPolicies += $result.Processed
    $updatedCount += $result.Updated
    $skippedCount += $result.Skipped
    $errorCount += $result.Error
}

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
