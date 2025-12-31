# WMI Log Clearing Detection

## Project Overview
This project implements a persistent detection mechanism for Windows Log Clearing events (Event ID 104) using WMI Event Subscriptions. It allows security teams to detect when an adversary attempts to cover their tracks by wiping the System event log.

## Features
- **Agentless**: Uses native WMI; no external agents required.
- **Persistent**: Survives reboots.
- **Real-time**: Polls every 5 seconds.
- **Extensible**: Supports local logging and optional Splunk HEC forwarding.

## Prerequisites
- PowerShell 5.1 or later.
- Administrator privileges.

## Installation
1. Open PowerShell as **Administrator**.
2. Navigate to this directory.
3. Run the registration script:
   ```powershell
   PowerShell.exe -ExecutionPolicy Bypass -File .\Register-Detection.ps1
   ```
4. You should see a "Success!" message.

## Usage / Verification
To verify the detection without deleting your actual logs, run this simulation command:

```powershell
eventcreate /L SYSTEM /T INFORMATION /ID 104 /SO "Attack-Simulator" /D "The System log file was cleared (SIMULATION)."
```

Check the output file: `DetectedEvents.log`

## Uninstallation
To remove the WMI subscription and clean up:
```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\Uninstall-Detection.ps1
```
