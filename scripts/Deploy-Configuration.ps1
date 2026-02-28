<#
.SYNOPSIS
    Deploys Intune protection policies using Microsoft365DSC for idempotent state management.

.DESCRIPTION
    Reads JSON policy templates from policies/, maps them to Microsoft365DSC DSC
    resources, and applies them idempotently to the Intune tenant. Each policy is tested first;
    only policies that have drifted from desired state are remediated.

    Supports two modes:
      - Test:  Reports drift without making changes.
      - Apply: Remediates drift to converge on desired state.

    Authentication supports interactive credential or service principal (certificate-based).

.PARAMETER Mode
    'Test' to detect drift only. 'Apply' to remediate drift.

.PARAMETER Credential
    PSCredential for interactive/delegated authentication.

.PARAMETER ApplicationId
    Azure AD application (client) ID for service principal authentication.

.PARAMETER TenantId
    Azure AD tenant ID for service principal authentication.

.PARAMETER CertificateThumbprint
    Certificate thumbprint for service principal authentication.

.PARAMETER FactoryResetAdminEmail
    Email address for Android factory-reset recovery (replaces placeholder in templates).
    Mandatory — blocks deployment if not provided.

.PARAMETER CustomDialerAppProtocol
    iOS custom dialer URL scheme for Level 3 app protection (replaces placeholder in templates).
    Mandatory — blocks deployment if not provided.

.EXAMPLE
    .\Deploy-Configuration.ps1 -Mode Test -Credential (Get-Credential) `
        -FactoryResetAdminEmail admin@contoso.com -CustomDialerAppProtocol tel

.EXAMPLE
    .\Deploy-Configuration.ps1 -Mode Apply `
        -ApplicationId "00000000-0000-0000-0000-000000000000" `
        -TenantId "00000000-0000-0000-0000-000000000000" `
        -CertificateThumbprint "AABBCCDDEE..." `
        -FactoryResetAdminEmail admin@contoso.com `
        -CustomDialerAppProtocol tel
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Apply', 'Test')]
    [string]$Mode,

    [Parameter(ParameterSetName = 'Interactive')]
    [PSCredential]$Credential,

    [Parameter(ParameterSetName = 'AppBased', Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ApplicationId,

    [Parameter(ParameterSetName = 'AppBased', Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter(ParameterSetName = 'AppBased', Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')]
    [string]$FactoryResetAdminEmail,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$CustomDialerAppProtocol
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$MinimumM365DSCVersion = '1.24.1218.1'
$JsonBasePath = Join-Path (Split-Path $PSScriptRoot) 'policies'

$ResourceTypeMap = @{
    '#microsoft.graph.androidManagedAppProtection'                  = 'IntuneAppProtectionPolicyAndroid'
    '#microsoft.graph.iosManagedAppProtection'                      = 'IntuneAppProtectionPolicyiOS'
    '#microsoft.graph.androidDeviceOwnerCompliancePolicy'           = 'IntuneDeviceCompliancePolicyAndroidDeviceOwner'
    '#microsoft.graph.androidWorkProfileCompliancePolicy'           = 'IntuneDeviceCompliancePolicyAndroidWorkProfile'
    '#microsoft.graph.iosCompliancePolicy'                          = 'IntuneDeviceCompliancePolicyiOs'
    '#microsoft.graph.androidDeviceOwnerGeneralDeviceConfiguration' = 'IntuneDeviceConfigurationPolicyAndroidDeviceOwner'
    '#microsoft.graph.androidWorkProfileGeneralDeviceConfiguration' = 'IntuneDeviceConfigurationPolicyAndroidWorkProfile'
    '#microsoft.graph.iosGeneralDeviceConfiguration'                = 'IntuneDeviceConfigurationPolicyiOs'
}

$ExcludedProperties = @(
    '@odata.type',
    '@odata.context',
    'apps@odata.context',
    'id',
    'createdDateTime',
    'lastModifiedDateTime',
    'version',
    'isAssigned',
    'deployedAppCount',
    'supportsScopeTags',
    'roleScopeTagIds',
    'targetedAppManagementLevels',
    'deviceManagementApplicabilityRuleOsEdition',
    'deviceManagementApplicabilityRuleOsVersion',
    'deviceManagementApplicabilityRuleDeviceMode'
)

$PlaceholderPatterns = @(
    'example@',
    'replace_with_',
    'TODO',
    'FIXME',
    'placeholder'
)

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('Info','Success','Warning','Error','Drift','InSync')][string]$Level = 'Info'
    )
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    switch ($Level) {
        'Info'    { Write-Host "[$ts] [INFO]    $Message" -ForegroundColor Cyan }
        'Success' { Write-Host "[$ts] [SUCCESS] $Message" -ForegroundColor Green }
        'Warning' { Write-Host "[$ts] [WARNING] $Message" -ForegroundColor Yellow }
        'Error'   { Write-Host "[$ts] [ERROR]   $Message" -ForegroundColor Red }
        'Drift'   { Write-Host "[$ts] [DRIFT]   $Message" -ForegroundColor Magenta }
        'InSync'  { Write-Host "[$ts] [OK]      $Message" -ForegroundColor DarkGreen }
    }
}

function Install-M365DSCPrerequisites {
    Write-Log 'Checking Microsoft365DSC module...'
    $installed = Get-Module -Name Microsoft365DSC -ListAvailable |
        Sort-Object Version -Descending |
        Select-Object -First 1

    if (-not $installed -or $installed.Version -lt [version]$MinimumM365DSCVersion) {
        Write-Log "Installing Microsoft365DSC (minimum version: $MinimumM365DSCVersion)..." -Level Warning
        Install-Module -Name Microsoft365DSC -MinimumVersion $MinimumM365DSCVersion `
            -Force -AllowClobber -Scope CurrentUser
        $installed = Get-Module -Name Microsoft365DSC -ListAvailable |
            Sort-Object Version -Descending |
            Select-Object -First 1
    }

    if (-not $installed) {
        Write-Log 'Failed to install Microsoft365DSC module.' -Level Error
        throw 'Microsoft365DSC installation failed.'
    }

    Write-Log "Microsoft365DSC version: $($installed.Version)" -Level Success
    Import-Module Microsoft365DSC -Force

    Write-Log 'Updating Microsoft365DSC dependencies...'
    Update-M365DSCDependencies
    Write-Log 'Dependencies updated.' -Level Success
}

function ConvertTo-InitialCap {
    param([string]$Name)
    if ([string]::IsNullOrEmpty($Name)) { return $Name }
    return $Name.Substring(0,1).ToUpper() + $Name.Substring(1)
}

function Test-PlaceholderValues {
    param([hashtable]$Properties, [string]$FileName)
    foreach ($pattern in $PlaceholderPatterns) {
        foreach ($key in $Properties.Keys) {
            $val = $Properties[$key]
            if ($val -is [string] -and $val -match [regex]::Escape($pattern)) {
                Write-Log "BLOCKED: '$FileName' property '$key' contains placeholder pattern '$pattern' (value: '$val')" -Level Error
                return $false
            }
            if ($val -is [string[]]) {
                foreach ($element in $val) {
                    if ($element -match [regex]::Escape($pattern)) {
                        Write-Log "BLOCKED: '$FileName' property '$key' contains placeholder pattern '$pattern' (value: '$element')" -Level Error
                        return $false
                    }
                }
            }
        }
    }
    return $true
}

function ConvertTo-CimInstance {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Object,
        [Parameter(Mandatory = $true)]
        [string]$ClassName
    )
    $cimProperties = @{}
    foreach ($prop in $Object.PSObject.Properties) {
        $dscName = ConvertTo-InitialCap -Name $prop.Name
        $val = $prop.Value

        if ($null -eq $val) { continue }

        if ($val -is [PSCustomObject]) {
            $cimProperties[$dscName] = ConvertTo-CimInstance -Object $val -ClassName "$($ClassName)_$dscName"
            continue
        }

        if ($val -is [object[]]) {
            if ($val.Count -eq 0) { continue }
            if ($val[0] -is [PSCustomObject]) {
                $nested = @()
                foreach ($item in $val) {
                    $nested += ConvertTo-CimInstance -Object $item -ClassName "$($ClassName)_$dscName"
                }
                $cimProperties[$dscName] = [CimInstance[]]$nested
            }
            else {
                $cimProperties[$dscName] = [string[]]$val
            }
            continue
        }

        if ($val -is [bool])   { $cimProperties[$dscName] = $val; continue }
        if ($val -is [int] -or $val -is [long] -or $val -is [double]) { $cimProperties[$dscName] = [int]$val; continue }
        $cimProperties[$dscName] = [string]$val
    }

    return (New-CimInstance -ClassName $ClassName -Property $cimProperties -ClientOnly)
}

function Convert-JsonToDscProperties {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$JsonObject,
        [hashtable]$AuthParams,
        [string]$FactoryResetEmail,
        [string]$DialerProtocol
    )

    $properties = @{}

    foreach ($prop in $JsonObject.PSObject.Properties) {
        if ($prop.Name -in $ExcludedProperties) { continue }
        if ($null -eq $prop.Value) { continue }

        $dscName = ConvertTo-InitialCap -Name $prop.Name
        $value = $prop.Value

        if ($value -is [PSCustomObject]) {
            Write-Log "  Skipping nested object property '$($prop.Name)' — single-object CIM mapping not implemented." -Level Warning
            continue
        }

        if ($value -is [object[]]) {
            if ($value.Count -eq 0) { continue }

            if ($value[0] -is [PSCustomObject]) {
                $cimClassName = "MSFT_$dscName"
                $cimInstances = @()
                foreach ($item in $value) {
                    $cimInstances += ConvertTo-CimInstance -Object $item -ClassName $cimClassName
                }
                $properties[$dscName] = [CimInstance[]]$cimInstances
                continue
            }

            if ($value[0] -is [bool])   { $properties[$dscName] = [bool[]]$value; continue }
            if ($value[0] -is [int] -or $value[0] -is [long] -or $value[0] -is [double]) {
                $properties[$dscName] = [int[]]$value; continue
            }
            $properties[$dscName] = [string[]]$value
            continue
        }

        if ($value -is [bool]) {
            $properties[$dscName] = $value
            continue
        }

        if ($value -is [int] -or $value -is [long] -or $value -is [double]) {
            $properties[$dscName] = [int]$value
            continue
        }

        if ($value -is [string]) {
            if ($value -eq 'example@gmail.com' -and $FactoryResetEmail) {
                $properties[$dscName] = $FactoryResetEmail
            }
            elseif ($value -eq 'replace_with_dialer_app_url_scheme' -and $DialerProtocol) {
                $properties[$dscName] = $DialerProtocol
            }
            else {
                $properties[$dscName] = $value
            }
            continue
        }
    }

    if ($JsonObject.PSObject.Properties['factoryResetDeviceAdministratorEmails']) {
        $emails = $JsonObject.factoryResetDeviceAdministratorEmails
        if ($emails -and $emails.Count -gt 0) {
            $replaced = @()
            foreach ($email in $emails) {
                if ($email -eq 'example@gmail.com') {
                    $replaced += $FactoryResetEmail
                }
                else {
                    $replaced += $email
                }
            }
            $properties['FactoryResetDeviceAdministratorEmails'] = [string[]]$replaced
        }
    }

    $properties['Ensure'] = 'Present'

    foreach ($key in $AuthParams.Keys) {
        $properties[$key] = $AuthParams[$key]
    }

    return $properties
}

function Get-DscResourceName {
    param([string]$ODataType)
    if ($ResourceTypeMap.ContainsKey($ODataType)) {
        return $ResourceTypeMap[$ODataType]
    }
    Write-Log "Unknown @odata.type: $ODataType" -Level Error
    return $null
}

function Invoke-PolicyDsc {
    param(
        [string]$ResourceName,
        [hashtable]$Properties,
        [string]$PolicyDisplayName,
        [string]$Mode
    )

    Write-Log "Processing: $PolicyDisplayName [$ResourceName]"

    try {
        $testResult = Invoke-DscResource -Name $ResourceName `
            -ModuleName 'Microsoft365DSC' `
            -Method Test `
            -Property $Properties `
            -ErrorAction Stop

        if ($testResult.InDesiredState) {
            Write-Log "$PolicyDisplayName — in desired state." -Level InSync
            return [PSCustomObject]@{
                PolicyName  = $PolicyDisplayName
                Resource    = $ResourceName
                Status      = 'InSync'
                Action      = 'None'
            }
        }

        Write-Log "$PolicyDisplayName — DRIFT detected." -Level Drift

        if ($Mode -eq 'Test') {
            return [PSCustomObject]@{
                PolicyName  = $PolicyDisplayName
                Resource    = $ResourceName
                Status      = 'Drift'
                Action      = 'TestOnly'
            }
        }

        if ($Mode -eq 'Apply') {
            Write-Log "Remediating: $PolicyDisplayName" -Level Warning
            Invoke-DscResource -Name $ResourceName `
                -ModuleName 'Microsoft365DSC' `
                -Method Set `
                -Property $Properties `
                -ErrorAction Stop

            $verifyResult = Invoke-DscResource -Name $ResourceName `
                -ModuleName 'Microsoft365DSC' `
                -Method Test `
                -Property $Properties `
                -ErrorAction Stop

            if ($verifyResult.InDesiredState) {
                Write-Log "$PolicyDisplayName — remediated successfully." -Level Success
                return [PSCustomObject]@{
                    PolicyName  = $PolicyDisplayName
                    Resource    = $ResourceName
                    Status      = 'Remediated'
                    Action      = 'Applied'
                }
            }
            else {
                Write-Log "$PolicyDisplayName — remediation incomplete. Manual review required." -Level Error
                return [PSCustomObject]@{
                    PolicyName  = $PolicyDisplayName
                    Resource    = $ResourceName
                    Status      = 'RemediationFailed'
                    Action      = 'ManualReviewRequired'
                }
            }
        }
    }
    catch {
        Write-Log "$PolicyDisplayName — ERROR: $($_.Exception.Message)" -Level Error
        return [PSCustomObject]@{
            PolicyName  = $PolicyDisplayName
            Resource    = $ResourceName
            Status      = 'Error'
            Action      = $_.Exception.Message
        }
    }
}

Write-Host ''
Write-Host '================================================' -ForegroundColor Magenta
Write-Host '  Intune Protection — Microsoft365DSC Deployment' -ForegroundColor Magenta
Write-Host '================================================' -ForegroundColor Magenta
Write-Host ''

$startTime = Get-Date

Install-M365DSCPrerequisites

if ($PSCmdlet.ParameterSetName -eq 'Interactive' -and -not $Credential) {
    $Credential = Get-Credential -Message 'Enter Microsoft 365 tenant admin credentials'
    if (-not $Credential) {
        Write-Log 'No credentials provided. Aborting.' -Level Error
        exit 1
    }
}

$authParams = @{}
if ($PSCmdlet.ParameterSetName -eq 'Interactive') {
    $authParams['Credential'] = $Credential
}
else {
    $authParams['ApplicationId']        = $ApplicationId
    $authParams['TenantId']             = $TenantId
    $authParams['CertificateThumbprint'] = $CertificateThumbprint
}

if (-not (Test-Path $JsonBasePath)) {
    Write-Log "JSON template directory not found: $JsonBasePath" -Level Error
    exit 1
}

$jsonFiles = Get-ChildItem -Path $JsonBasePath -Filter '*.json' | Sort-Object Name
if ($jsonFiles.Count -eq 0) {
    Write-Log "No JSON templates found in: $JsonBasePath" -Level Error
    exit 1
}

Write-Log "Found $($jsonFiles.Count) JSON templates in: $JsonBasePath"
Write-Log "Mode: $Mode"
Write-Host ''

$results = @()

foreach ($jsonFile in $jsonFiles) {
    $rawJson = Get-Content -Path $jsonFile.FullName -Raw -ErrorAction Stop

    $jsonObj = $rawJson | ConvertFrom-Json -ErrorAction Stop

    if (-not $jsonObj.'@odata.type' -and -not $jsonObj.displayName) {
        Write-Log "Skipping $($jsonFile.Name) — no @odata.type or displayName found." -Level Warning
        continue
    }

    $odataType = $jsonObj.'@odata.type'

    if (-not $odataType) {
        if ($jsonObj.PSObject.Properties['encryptAppData']) {
            $odataType = '#microsoft.graph.androidManagedAppProtection'
        }
        elseif ($jsonObj.PSObject.Properties['appDataEncryptionType']) {
            $odataType = '#microsoft.graph.iosManagedAppProtection'
        }
        else {
            Write-Log "Skipping $($jsonFile.Name) — cannot determine policy type." -Level Warning
            continue
        }
    }

    $resourceName = Get-DscResourceName -ODataType $odataType
    if (-not $resourceName) {
        Write-Log "Skipping $($jsonFile.Name) — unmapped @odata.type: $odataType" -Level Warning
        continue
    }

    $dscProperties = Convert-JsonToDscProperties `
        -JsonObject $jsonObj `
        -AuthParams $authParams `
        -FactoryResetEmail $FactoryResetAdminEmail `
        -DialerProtocol $CustomDialerAppProtocol

    if (-not (Test-PlaceholderValues -Properties $dscProperties -FileName $jsonFile.Name)) {
        $results += [PSCustomObject]@{
            PolicyName = $jsonObj.displayName
            Resource   = $resourceName
            Status     = 'Blocked'
            Action     = 'PlaceholderDetected'
        }
        continue
    }

    $result = Invoke-PolicyDsc `
        -ResourceName $resourceName `
        -Properties $dscProperties `
        -PolicyDisplayName $jsonObj.displayName `
        -Mode $Mode

    $results += $result
}

$endTime = Get-Date
$duration = $endTime - $startTime

Write-Host ''
Write-Host '================================================' -ForegroundColor Magenta
Write-Host '  Deployment Summary' -ForegroundColor Magenta
Write-Host '================================================' -ForegroundColor Magenta
Write-Host ''

$results | Format-Table -Property PolicyName, Resource, Status, Action -AutoSize

$inSync     = ($results | Where-Object { $_.Status -eq 'InSync' }).Count
$driftCount = ($results | Where-Object { $_.Status -eq 'Drift' }).Count
$remediated = ($results | Where-Object { $_.Status -eq 'Remediated' }).Count
$failed     = ($results | Where-Object { $_.Status -in @('Error','RemediationFailed','Blocked') }).Count

Write-Host ''
Write-Host "Policies processed:  $($results.Count)" -ForegroundColor White
Write-Host "In desired state:    $inSync" -ForegroundColor Green
Write-Host "Drift detected:      $driftCount" -ForegroundColor Yellow
Write-Host "Remediated:          $remediated" -ForegroundColor Cyan
Write-Host "Errors/Blocked:      $failed" -ForegroundColor $(if ($failed -gt 0) { 'Red' } else { 'Green' })
Write-Host "Duration:            $($duration.ToString('mm\:ss'))" -ForegroundColor White
Write-Host ''

$reportDir = Join-Path $PSScriptRoot 'Reports'
if (-not (Test-Path $reportDir)) {
    New-Item -Path $reportDir -ItemType Directory -Force | Out-Null
}
$reportPath = Join-Path $reportDir "DeployReport-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
$results | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8
Write-Log "Report saved to: $reportPath" -Level Info

if ($failed -gt 0) {
    Write-Log "Deployment completed with $failed failure(s)." -Level Error
    exit 1
}
else {
    Write-Log 'Deployment completed successfully.' -Level Success
    exit 0
}
