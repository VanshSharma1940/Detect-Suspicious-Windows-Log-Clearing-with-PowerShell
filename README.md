# Detect-Suspicious-Windows-Log-Clearing-with-PowerShell
This project detects suspicious Windows Event Log clearing by creating a persistent WMI event subscription for Event ID 104. When logs are cleared, a PowerShell handler records details to a local file or forwards them via HTTP POST to a SIEM (e.g., Splunk), enabling timely incident detection and response.
