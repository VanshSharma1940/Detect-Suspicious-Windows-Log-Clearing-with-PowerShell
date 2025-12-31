<#
   .SYNOPSIS
    Registers a Permanent WMI Event Subscription to detect Event ID 104.
    
   .DESCRIPTION
    Creates __EventFilter, CommandLineEventConsumer, and __FilterToConsumerBinding.
    Requires Administrator privileges.
    
   .NOTES
    Steps:
    1. Clean up old instances (Idempotency).
    2. Define the Query (Filter).
    3. Define the Action (Consumer).
    4. Bind them together.
#>

# Ensure the script is running as Administrator
$CurrentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "You must run this script as Administrator!"
    break
}

$ErrorActionPreference = "Stop"

# --- CONSTANTS ---
$Namespace = "root\subscription"
$FilterName = "LogClearFilter"
$ConsumerName = "LogClearConsumer"
# Dynamically get the path to LogHandler.ps1 in the same directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ScriptPath = Join-Path $ScriptDir "LogHandler.ps1"

if (-not (Test-Path $ScriptPath)) {
    Write-Error "LogHandler.ps1 not found at $ScriptPath"
    exit
}

# --- 1. CLEANUP OLD INSTANCES ---
# Ideally, we remove old versions before creating new ones to avoid conflicts.
Write-Host "Cleaning up existing WMI subscriptions..." -ForegroundColor Cyan

# Remove Binding first (best practice)
Get-CimInstance -Namespace $Namespace -ClassName __FilterToConsumerBinding | 
    Where-Object { $_.Filter.Name -eq $FilterName -or $_.Consumer.Name -eq $ConsumerName } | 
    Remove-CimInstance -ErrorAction SilentlyContinue

# Remove Consumer
Get-CimInstance -Namespace $Namespace -ClassName CommandLineEventConsumer | 
    Where-Object Name -eq $ConsumerName | 
    Remove-CimInstance -ErrorAction SilentlyContinue

# Remove Filter
Get-CimInstance -Namespace $Namespace -ClassName __EventFilter | 
    Where-Object Name -eq $FilterName | 
    Remove-CimInstance -ErrorAction SilentlyContinue


# --- 2. CREATE EVENT FILTER ---
Write-Host "Creating WMI Event Filter..." -ForegroundColor Green

# Query Breakdown:
# __InstanceCreationEvent: Detects new objects.
# WITHIN 5: Checks every 5 seconds.
# TargetInstance ISA 'Win32_NTLogEvent': Checks Event Logs.
# EventCode = 104: System Log Cleared.
# LogFile = 'System': Targeted log.
$Query = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.EventCode = 104 AND TargetInstance.LogFile = 'System'"

$FilterParams = @{
    Name = $FilterName
    EventNamespace = "root\cimv2"  # Where the Event Log events live
    QueryLanguage = "WQL"
    Query = $Query
}

# Create the Filter Instance in root\subscription
$FilterInstance = New-CimInstance -Namespace $Namespace -ClassName __EventFilter -Property $FilterParams


# --- 3. CREATE EVENT CONSUMER ---
Write-Host "Creating WMI Event Consumer..." -ForegroundColor Green

# Constructing the Command Line
# -ExecutionPolicy Bypass: Required to run the script unattended.
# -WindowStyle Hidden: Prevents a popup window (though running as SYSTEM makes it invisible regardless).
# -File: Path to the handler.
# Arguments: We quote the WMI variables "%TargetInstance.Property%" to handle spaces.
$CommandLine = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File ""$ScriptPath"" -EventMessage ""%TargetInstance.Message%"" -TimeGenerated ""%TargetInstance.TimeGenerated%"""

$ConsumerParams = @{
    Name = $ConsumerName
    CommandLineTemplate = $CommandLine
    # ExecutablePath is optional if CommandLineTemplate is used, but good for specificity
    ExecutablePath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
}

$ConsumerInstance = New-CimInstance -Namespace $Namespace -ClassName CommandLineEventConsumer -Property $ConsumerParams


# --- 4. BIND FILTER AND CONSUMER ---
Write-Host "Binding Filter and Consumer..." -ForegroundColor Green

# Use the Relative Path (RELPATH) to ensure the Binding class accepts the reference correctly.
# New-CimInstance returns the object, and we extract natural key paths.

$BindingParams = @{
    Filter = $FilterInstance
    Consumer = $ConsumerInstance
}

# If the standard object passing fails (Type Mismatch), we try using the WMI path explicitly.
# If the standard object passing fails (Type Mismatch), let's use the legacy (but reliable) Set-WmiInstance for the binding.
# This handles the object-to-path conversion internally for WMI.

# Re-fetch objects using Get-WmiObject to ensure compatibility with Set-WmiInstance
$FilterWmi = Get-WmiObject -Namespace $Namespace -Class __EventFilter | Where-Object Name -eq $FilterName
$ConsumerWmi = Get-WmiObject -Namespace $Namespace -Class CommandLineEventConsumer | Where-Object Name -eq $ConsumerName

if ($FilterWmi -and $ConsumerWmi) {
    Set-WmiInstance -Namespace $Namespace -Class __FilterToConsumerBinding -Arguments @{Filter=$FilterWmi; Consumer=$ConsumerWmi}
} else {
    Write-Error "Could not retrieve WMI objects for binding."
    exit
}


Write-Host "-------------------------------------------------------------" -ForegroundColor Yellow
Write-Host "Success! WMI Detection Registered."
Write-Host "Monitor: Event ID 104 (System Log Cleared)"
Write-Host "Action : Execute $ScriptPath"
Write-Host "Output : $ScriptDir\DetectedEvents.log"
Write-Host "-------------------------------------------------------------"
