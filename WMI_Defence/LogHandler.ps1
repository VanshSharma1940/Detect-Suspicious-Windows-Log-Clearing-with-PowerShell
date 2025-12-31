<#
   .SYNOPSIS
    Handler script for WMI Event ID 104 Detection.
    
   .DESCRIPTION
    This script is invoked by the WMI CommandLineEventConsumer.
    It receives event details, logs them to a local file, and 
    optionally forwards them to a SIEM (Splunk) via HTTP.
    
   .PARAMETER EventMessage
    The content of the log event message.
    
   .PARAMETER TimeGenerated
    The timestamp when the event was created (WMI format).
    
   .PARAMETER ComputerName
    The name of the host.
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$EventMessage,

    [Parameter(Mandatory=$true)]
    [string]$TimeGenerated,

    [string]$ComputerName = $env:COMPUTERNAME
)

# --- CONFIGURATION SECTION ---
# Path for local fallback logging
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogFilePath = Join-Path $ScriptDir "DetectedEvents.log"
$ErrorLogPath = Join-Path $ScriptDir "ScriptErrors.log"

# Splunk HEC Configuration (Set $SplunkEnabled to $true to use)
$SplunkEnabled = $false
$SplunkUrl = "https://splunk-server:8088/services/collector/event"
$SplunkToken = "00000000-0000-0000-0000-000000000000"
# -----------------------------

try {
    # 1. Timestamp Formatting
    # WMI Time is often in DMTF format (e.g., 20251231141300.000000-000) or sometimes simplified. We treat it as a string for logging.
    $FormattedTime = $TimeGenerated
    
    # 2. Construct the Log Entry for Local Storage
    $LogEntry = @"
--------------------------------------------------
 System Log Cleared Detected
Timestamp : $FormattedTime
Computer  : $ComputerName
Message   : $EventMessage
--------------------------------------------------
"@

    # 3. Write to Local File (Append mode)
    # Uses a mutex or simple append to avoid locking issues if multiple events fire
    Add-Content -Path $LogFilePath -Value $LogEntry -ErrorAction Stop

    # 4. Forward to Splunk (If Enabled)
    if ($SplunkEnabled) {
        # Bypass SSL check for self-signed certs (Common in dev/test environments)
        # WARNING: In production, install valid certs and remove this callback.
        if (::ServerCertificateValidationCallback -eq $null) {
           [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        }

        # Header with Authentication Token
        $Headers = @{
            "Authorization" = "Splunk $SplunkToken"
        }

        # Construct JSON Payload compliant with Splunk HEC
        $Payload = @{
            host = $ComputerName
            sourcetype = "wmi:logclear:alert"
            source = "WMI_Defense_Script"what was the role of AWS,
            and what all screenshots of AWS were to be taken
            
            event = @{
                message = $EventMessage
                timestamp = $FormattedTime
                alert_type = "DefenseEvasion"
                severity = "High"
                technique_id = "T1070.001"
            }
        }

        # Convert to JSON (Depth 2 ensures nested objects are preserved)
        $JsonPayload = $Payload | ConvertTo-Json -Depth 2
        
        # Send the POST request
        $Response = Invoke-RestMethod -Uri $SplunkUrl -Method Post -Headers $Headers -Body $JsonPayload -ContentType 'application/json'
        
        # Log Splunk response code for debugging (Optional)
        Add-Content -Path $LogFilePath -Value ": $($Response.text)"
    }

} catch {
    # Last resort error logging
    # If the script fails (e.g., network down, file permission), we record it.
    $ErrorMsg = " Script Failure: $_"
    Add-Content -Path $ErrorLogPath -Value $ErrorMsg
}
