# Intune Security Baseline

Declarative, idempotent management of Intune compliance, device configuration, and app protection policies using **Microsoft365DSC**. Implements Microsoft's three-tier data protection framework (Level 1 Basic, Level 2 Enhanced, Level 3 High) as code.

## Architecture

```
policies/                        ← JSON templates + CSV (source of truth)
scripts/
  Deploy-Configuration.ps1       ← Test / Apply desired state
  Export-CurrentConfig.ps1       ← Export tenant baseline for drift comparison
  AssignEUDScopeTag.ps1          ← Optional scope-tag post-step
  legacy/                        ← Deprecated imperative import scripts
docs/
```

The JSON templates in `policies/` define the desired state for 24 Intune policies across three tiers (Level 1 Basic, Level 2 Enhanced, Level 3 High) covering:

| Category | Platforms | Count |
|---|---|---|
| App protection (MAM) | Android, iOS | 6 |
| Device compliance | Android DO, Android WP, iOS | 7 |
| Device configuration | Android DO, Android WP, iOS personal, iOS supervised | 11 |

`Deploy-Configuration.ps1` reads each JSON template, maps it to the corresponding Microsoft365DSC DSC resource, and invokes DSC **Test** (detect drift) and **Set** (remediate) operations. This provides true idempotency: running the script N times produces the same tenant state as running it once, regardless of transient API errors, concurrent administrators, or existing policies.

## Quick start

### Prerequisites

- PowerShell 5.1 or later (Windows PowerShell recommended for DSC compatibility).
- An account or service principal with these Graph permissions:
  - `DeviceManagementConfiguration.ReadWrite.All`
  - `DeviceManagementApps.ReadWrite.All`
- The `Microsoft365DSC` module is installed automatically by the deploy script if missing.

### 1. Test for drift (read-only)

```powershell
cd scripts
.\Deploy-Configuration.ps1 -Mode Test -Credential (Get-Credential) `
    -FactoryResetAdminEmail admin@yourorg.com `
    -CustomDialerAppProtocol tel
```

### 2. Apply desired state

```powershell
.\Deploy-Configuration.ps1 -Mode Apply -Credential (Get-Credential) `
    -FactoryResetAdminEmail admin@yourorg.com `
    -CustomDialerAppProtocol tel
```

### 3. Service principal authentication (CI/CD)

```powershell
.\Deploy-Configuration.ps1 -Mode Apply `
    -ApplicationId "00000000-0000-0000-0000-000000000000" `
    -TenantId "00000000-0000-0000-0000-000000000000" `
    -CertificateThumbprint "AABBCCDDEE..." `
    -FactoryResetAdminEmail admin@yourorg.com `
    -CustomDialerAppProtocol tel
```

### 4. Export current tenant state

```powershell
.\Export-CurrentConfig.ps1 -Credential (Get-Credential)
```

Exports the current Intune configuration as a Microsoft365DSC configuration file for baseline comparison.

## Mandatory parameters

| Parameter | Purpose | Why mandatory |
|---|---|---|
| `FactoryResetAdminEmail` | Android factory-reset recovery email (replaces `example@gmail.com` placeholder in Level 2/3 templates) | Deploying the placeholder would send recovery prompts to an uncontrolled address |
| `CustomDialerAppProtocol` | iOS dialer URL scheme for Level 3 app protection (replaces `replace_with_dialer_app_url_scheme` placeholder) | The literal placeholder string would break dialer restriction enforcement |

## How idempotency works

The previous imperative scripts used a **check-then-create** pattern via Graph API that was vulnerable to:
- **Fail-open errors**: API errors during the existence check caused duplicate creation.
- **TOCTOU races**: Concurrent runs could both observe "not found" and both create.
- **No drift remediation**: Existing policies with drifted settings were silently skipped.
- **Missing pagination**: Tenants with >100 policies missed duplicates beyond page 1.

Microsoft365DSC resolves all of these by design:
- Each DSC resource implements **Get** (read current state), **Test** (compare to desired), and **Set** (remediate differences) as atomic operations.
- The DSC engine handles conflict resolution, retries, and partial failures internally.
- Drift detection is built-in: `Test` mode reports exactly which policies differ from desired state.

## Optional: scope tags

After applying policies, the scope tag assignment script can be run separately:

```powershell
.\AssignEUDScopeTag.ps1
```

Requires an `EUD` scope tag to exist in the tenant. Policies prefixed with `PAW-` are excluded to support Privileged Access Workstation separation.

## Repository structure

```
policies/
│   ├── level-{1,2,3}-enterprise-*-Android.json   # App protection (MAM)
│   ├── level-{1,2,3}-enterprise-*-iOS.json
│   ├── level-{1,2,3}-fm-*-compliance.json        # Device compliance
│   ├── level-{1,2,3}-fm-*-configuration.json     # Device configuration
│   ├── level-{2,3}-wp-*-compliance.json
│   ├── level-{2,3}-wp-*-configuration.json
│   ├── level-{1,2,3}-iOS_iPadOS-*-configuration.json
│   └── Apple-App-BundleIDs.csv
scripts/
│   ├── Deploy-Configuration.ps1                 # Main entry point
│   ├── Export-CurrentConfig.ps1                  # Tenant export utility
│   ├── AssignEUDScopeTag.ps1                    # Optional scope-tag post-step
│   └── legacy/                                  # Deprecated imperative scripts
docs/
```

## Legacy scripts (deprecated)

The original imperative import scripts are preserved in `scripts/legacy/` for reference but are superseded by the M365DSC approach.

## Microsoft documentation references

- **Data protection framework using app protection policies** — taxonomy and guidance for the three-tier model
- **Microsoft365DSC** — declarative configuration-as-code for Microsoft 365
- **Intune Graph API reference** — underlying API used by Microsoft365DSC resources
- **AzureAD PowerShell retirement** — migration guidance that motivated this refactoring

## Support statement

Always validate resulting policies and assignments in the Intune admin center before broad rollout. Microsoft365DSC Test mode provides a non-destructive way to verify desired state before applying changes.
