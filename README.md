# Microsoft Cyber Range — Defender XDR, Sentinel & Identity Protection

## Overview

This project documents my build and investigation of an isolated Microsoft cloud cyber range using Azure, Microsoft Defender XDR, Microsoft Sentinel, Microsoft Entra ID, Intune and the wider Microsoft security stack.

The goal was not simply to deploy the services, but to understand **how telemetry moves between workloads and security products**, how identity and endpoint detections appear during an attack, and how a phishing-resistant authentication control changes the outcome.

The lab progressed through four main stages:

1. Build an isolated Azure environment and connect the Microsoft security stack.
2. Onboard Windows and Linux workloads into Microsoft Defender for Endpoint.
3. Generate controlled phishing and adversary-in-the-middle (AiTM) activity and investigate the resulting telemetry.
4. Introduce a phishing-resistant passkey policy and repeat the authentication flow to validate the defence.
