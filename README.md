# Intune App Protection Framework (Automation)

## Overview

This repository provides a PowerShell-based automation framework to deploy a complete Microsoft Intune App Protection baseline using a single, self-contained script.

The script enables organizations to deploy a standardized set of App Protection configurations in a consistent and repeatable manner without relying on external configuration files. All required policy definitions are embedded directly within the script, simplifying execution and reducing operational complexity.

The solution aligns with Microsoft guidance for mobile application management and supports rapid implementation of a production-ready protection baseline across iOS and Android environments.

## Key Capabilities

The script automates the end-to-end deployment of core Intune security components required for mobile application protection.

It provisions device compliance policies to evaluate device posture and enforce security requirements. It deploys device configuration profiles to harden relevant device settings. It also creates and configures managed app protection policies to ensure that corporate data is secured within supported applications.

The deployed app protection policies implement controls such as access requirements, encryption enforcement, and restrictions to prevent data leakage between managed and unmanaged applications.

## What Has Changed

The previous implementation relied on multiple scripts and external JSON templates that had to be downloaded, maintained, and imported into the environment. This approach introduced operational complexity and required additional lifecycle management of configuration artifacts.

The current implementation replaces this model with a single, fully self-contained script. All configuration elements are defined within the script itself, removing dependencies on external files and simplifying deployment. This results in improved portability, easier maintenance, and a more deterministic execution model.

## Background: App Protection Framework

Microsoft Intune provides an App Protection Data Protection Framework that defines structured guidance for securing organizational data within mobile applications.

The framework introduces a set of recommended configurations organized into three distinct levels. Each level builds upon the previous one and reflects increasing levels of protection aligned to organizational risk profiles.

The first level focuses on baseline protection by ensuring that applications enforce access controls such as PIN requirements and encryption while supporting selective wipe capabilities.

The second level introduces enhanced data protection by applying additional restrictions to reduce the risk of data leakage. This includes controls governing data transfer between applications and minimum platform requirements.

The third level provides advanced protection for high-risk scenarios and typically includes stronger authentication requirements and integration with additional threat protection capabilities.

This structured approach allows organizations to align mobile application protection with their security requirements while balancing usability and operational impact.

## Purpose of This Framework

This repository translates Microsoft’s recommended App Protection configurations into an automated deployment model.

The purpose of the framework is to simplify adoption, ensure consistent implementation across environments, and reduce the effort required to deploy and maintain secure configurations. It enables organizations to accelerate the rollout of App Protection Policies and minimize configuration drift over time.

The framework is particularly relevant for supporting secure bring-your-own-device scenarios and modern mobile-first access patterns.

## Technical Design

The implementation follows a modern and simplified design approach.

The script uses the Microsoft Graph PowerShell SDK to configure Intune resources. It is designed to be safely re-executable and avoids creating duplicate configurations by checking for existing objects during execution. All policy definitions are embedded directly in the script to ensure consistent and predictable outcomes.

This design eliminates reliance on legacy tooling and reduces external dependencies, making the solution easier to operate and maintain.

## Execution

The script requires an Intune-enabled environment and appropriate administrative permissions to create and manage policies.

Execution is performed by running the PowerShell script, which connects to Microsoft Graph and deploys the required configurations end-to-end without requiring additional input files.

## Deployment Model Recommendation

It is recommended to follow a staged rollout approach when deploying App Protection configurations.

Organizations should begin with a test environment, followed by a pilot group of users, and finally expand to full production deployment. This approach reduces risk and allows validation of policies before broad enforcement.

## Optional Post-Deployment Steps

After deployment, organizations may choose to extend the configuration by assigning policies to specific user groups, integrating with Conditional Access policies, and aligning configurations with identity governance models.
