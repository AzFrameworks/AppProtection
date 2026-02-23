# Scope Tag Assignment (Optional)

This document describes the optional script `AssignEUDScopeTag.ps1`, which can be executed after importing the policies.

## Purpose

The script assigns an Intune scope tag to policies that currently have only the default scope tag state. This helps organizations apply Intune RBAC boundaries by scope tag.

## When to run

Run this script **after** you have imported policies and you want to apply a consistent scope tag to the imported artifacts.

## Requirements

- Microsoft Graph PowerShell SDK installed.
- Permissions that allow reading and updating Intune policies and scope tags.
- A scope tag named **`EUD`** must already exist in Intune.

If the `EUD` scope tag is not present, the script stops and lists available scope tags.

## What the script changes

The script iterates through:

- Device compliance policies
- Device configuration profiles
- App protection policies (platform-specific endpoints)

For each policy, it applies the following rules:

1. Policies with names starting with `PAW-` are **excluded**.
2. Policies that have **only** the default scope tag state are updated to use the `EUD` scope tag.
3. Policies that already have non-default or multiple scope tags are left unchanged.

## Why `PAW-` is excluded

Many environments operate separate management boundaries for **Privileged Access Workstations (PAW/PAW-CSM)** and standard **Enterprise User Devices (EUD)**. Excluding `PAW-` avoids accidentally retagging PAW-related artifacts and supports a clear separation of administrative scope.

## Customizing the target scope tag

If your organization uses a different scope tag name than `EUD`, update the script section that searches for the scope tag by `displayName`. The script is intentionally written to fail fast if the required tag is not found, to avoid applying unintended changes.

## Safe execution options

To simulate changes without applying them, use:

