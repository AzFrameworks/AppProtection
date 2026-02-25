<#
.SYNOPSIS
    Exports the current Intune tenant configuration using Microsoft365DSC.

.DESCRIPTION
    Captures the current state of Intune policies (compliance, device configuration,
    app protection) as a Microsoft365DSC configuration file. Use this to:
      - Establish a baseline before applying changes.
      - Detect manual drift between deployments.
      - Generate a DSC configuration from an existing tenant.

.PARAMETER OutputPath
    Directory where the exported configuration will be saved.
    Defaults to ./Exports/ relative to this script.

.PARAMETER Credential
    PSCredential for interactive authentication.

.PARAMETER ApplicationId
    Azure AD application (client) ID for service principal authentication.

.PARAMETER TenantId
    Azure AD tenant ID for service principal authentication.

.PARAMETER CertificateThumbprint
    Certificate thumbprint for service principal authentication.

.EXAMPLE
    .\Export-CurrentConfig.ps1 -Credential (Get-Credential)

.EXAMPLE
    .\Export-CurrentConfig.ps1 -ApplicationId "..." -TenantId "..." -CertificateThumbprint "..."
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath,

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
    [string]$CertificateThumbprint
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $OutputPath) {
    $OutputPath = Join-Path $PSScriptRoot 'Exports'
}

if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

$module = Get-Module -Name Microsoft365DSC -ListAvailable |
    Sort-Object Version -Descending |
    Select-Object -First 1

if (-not $module) {
    Write-Error 'Microsoft365DSC module not installed. Run Deploy-Configuration.ps1 first to install prerequisites.'
    exit 1
}

Import-Module Microsoft365DSC -Force

$intuneComponents = @(
    'IntuneAppProtectionPolicyAndroid',
    'IntuneAppProtectionPolicyiOS',
    'IntuneDeviceCompliancePolicyAndroidDeviceOwner',
    'IntuneDeviceCompliancePolicyAndroidWorkProfile',
    'IntuneDeviceCompliancePolicyiOs',
    'IntuneDeviceConfigurationPolicyAndroidDeviceOwner',
    'IntuneDeviceConfigurationPolicyAndroidWorkProfile',
    'IntuneDeviceConfigurationPolicyiOs'
)

$exportParams = @{
    Components = $intuneComponents
    Path       = $OutputPath
    FileName   = "IntuneExport-$(Get-Date -Format 'yyyyMMdd-HHmmss').ps1"
}

if ($PSCmdlet.ParameterSetName -eq 'Interactive') {
    if (-not $Credential) {
        $Credential = Get-Credential -Message 'Enter Microsoft 365 tenant admin credentials'
    }
    $exportParams['Credential'] = $Credential
}
else {
    $exportParams['ApplicationId']        = $ApplicationId
    $exportParams['TenantId']             = $TenantId
    $exportParams['CertificateThumbprint'] = $CertificateThumbprint
}

Write-Host ''
Write-Host '================================================' -ForegroundColor Cyan
Write-Host '  Microsoft365DSC — Intune Configuration Export' -ForegroundColor Cyan
Write-Host '================================================' -ForegroundColor Cyan
Write-Host ''

Write-Host "Exporting Intune configuration to: $OutputPath" -ForegroundColor Cyan
Write-Host "Components: $($intuneComponents -join ', ')" -ForegroundColor Gray
Write-Host ''

$startTime = Get-Date

Export-M365DSCConfiguration @exportParams

$duration = (Get-Date) - $startTime
$exportFile = Join-Path $OutputPath $exportParams.FileName

Write-Host ''
if (Test-Path $exportFile) {
    $fileSize = (Get-Item $exportFile).Length
    Write-Host "Export completed successfully." -ForegroundColor Green
    Write-Host "  File: $exportFile" -ForegroundColor White
    Write-Host "  Size: $([math]::Round($fileSize / 1KB, 1)) KB" -ForegroundColor White
    Write-Host "  Duration: $($duration.ToString('mm\:ss'))" -ForegroundColor White
}
else {
    Write-Host "Export completed but file not found at expected path." -ForegroundColor Yellow
    Write-Host "Check $OutputPath for exported files." -ForegroundColor Yellow
}

Write-Host ''
