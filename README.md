# Microsoft Cyber Range — Defender XDR, Sentinel & Identity Protection

## Overview

This project documents my build and investigation of an isolated Microsoft cloud cyber range using Azure, Microsoft Defender XDR, Microsoft Sentinel, Microsoft Entra ID, Intune and the wider Microsoft security stack.

The goal was not simply to deploy the services, but to understand **how telemetry moves between workloads and security products**, how identity and endpoint detections appear during an attack, and how a phishing-resistant authentication control changes the outcome.

The lab progressed through four main stages:

1. Build an isolated Azure environment and connect the Microsoft security stack.
2. Onboard Windows and Linux workloads into Microsoft Defender for Endpoint.
3. Generate controlled phishing and adversary-in-the-middle (AiTM) activity and investigate the resulting telemetry.
4. Introduce a phishing-resistant passkey policy and repeat the authentication flow to validate the defence.

---

## Architecture

![Cyber Range Architecture](images/cyber-range-architecture.png)

The environment was built in a dedicated Azure resource group and separated into client and server subnets.

---

## Technologies

- Microsoft Azure
- Azure Virtual Network, subnets and Network Security Groups
- Azure Bastion
- Azure NAT Gateway
- Windows Server 2025
- Windows 11 Enterprise
- Ubuntu Server 22.04
- OWASP Juice Shop
- Microsoft Defender XDR
- Microsoft Defender for Endpoint
- Microsoft Defender for Cloud
- Microsoft Defender for Cloud Apps
- Microsoft Defender for Office 365
- Microsoft Sentinel
- Azure Log Analytics
- Microsoft Entra ID
- Entra ID Protection
- Conditional Access
- Passkeys / FIDO2
- Microsoft Intune
- Kusto Query Language (KQL)
- Evilginx in an isolated lab environment

---

## 1. Building the Azure Range

I first created the Azure landing zone for the range, including the resource group, virtual network, server and client subnets, Log Analytics workspace and Azure Bastion.

The server and client workloads did not expose public RDP or SSH management ports. Instead, Azure Bastion was used as the management path into the range.

![Azure Resource Group](images/azure-resource-group.png)

![VNet Subnets](images/vnet-subnets.png)

### Workloads

The range contained six main workloads:

| Workload | Purpose |
| --- | --- |
| `vm-cli01` `vm-cli02` <br> `vm-cli03` `vm-cli04`| Windows 11 client devices for user, identity and endpoint telemetry |
| `vm-fs01` | Windows file server for Windows Server and audited file activity |
| `vm-web01` | Ubuntu server running OWASP Juice Shop for Linux and web-application activity |

The Windows file server `vm-fs01` gave the range a server workload capable of producing file-access and Windows infrastructure telemetry. I enabled file-system auditing on a file share so that access activity could be observed by the security tooling.

``` sh
# Install the Windows File Server role/feature onto the server
Install-WindowsFeature FS-FileServer 

# Create a new local directory
New-Item C:\Shares\Finance -ItemType Directory

# Create a network SMB share pointing to that new directory and grant full read/write access to all users
New-SmbShare -Name Finance -Path C:\Shares\Finance -FullAccess Everyone

# Record successful access to audited file-system objects
auditpol /set /subcategory:"File System" /success:enable
```
>NOTE: All roles having full access would not typically be the case in a production environment. This is just to remove permissions complexity from the lab. In a real environment, this directory and file would be subject to least privilege, e.g.: <br>
>- Finance Users → Modify <br>
>- Finance Admins → Full Control<br>
>- Everyone → no access

The Ubuntu server `vm-web01` provided a second operating system and a deliberately vulnerable web application. A NAT Gateway was used to give the private client and server subnets outbound internet connectivity without assigning a public IP directly to the VMs. Once internet access was configured, OWASP Juice Shop was run within a Docker container on the Ubuntu server.

![Juice Shop running on Docker](images/juice-shop.png)

### Why include both servers?

Their purpose was to make the range a broader security environment rather than a collection of client machines.

They also demonstrated an important architectural difference: **clients were onboarded to Defender for Endpoint through Intune, while the servers were onboarded through Defender for Cloud / Defender for Servers Plan 2.**

---
