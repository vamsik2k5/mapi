<#
.SYNOPSIS
    PoC Host Intrusion Detection System (HIDS) Telemetry Monitor
.DESCRIPTION
    This script monitors Windows Event Logs (Sysmon) for behaviors
    identified in the Threat Model (Quasar RAT, Go TaskRunner, NSIS Dropper).
    It uses a basic heuristic scoring module to flag processes that trigger
    multiple behavioral indicators and outputs JSON alerts.
#>

param(
    [int]$PollingInterval = 5
)

Write-Host "[*] Starting PoC HIDS Telemetry Monitor..." -ForegroundColor Green
Write-Host "[*] Press Ctrl+C to exit." -ForegroundColor Green

# Heuristic Tracking Table (PID -> Score)
$global:ProcessScores = @{}

function Write-Alert {
    param([int]$PID, [string]$RuleTriggered, [string]$Severity, [string]$Details)
    
    $alert = @{
        Timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
        ProcessID = $PID
        Rule = $RuleTriggered
        Severity = $Severity
        Details = $Details
    }
    $jsonAlert = $alert | ConvertTo-Json -Compress
    Write-Host "[ALERT] $jsonAlert" -ForegroundColor Red
}

function Evaluate-Heuristics {
    param([int]$PID, [int]$ScoreAdd, [string]$Context)
    
    if (-not $global:ProcessScores.ContainsKey($PID)) {
        $global:ProcessScores[$PID] = 0
    }
    
    $global:ProcessScores[$PID] += $ScoreAdd
    
    if ($global:ProcessScores[$PID] -ge 10) {
        Write-Alert -PID $PID -RuleTriggered "Heuristic_Threshold_Exceeded" -Severity "CRITICAL" -Details "Process $PID triggered multiple behavioral indicators. Last trigger: $Context"
        # Reset score to avoid spamming alerts
        $global:ProcessScores[$PID] = 0
    }
}

# Monitor loop (Simulated reading of Sysmon logs via Windows Event Log)
try {
    $lastEventId = 0
    
    # Try to get the latest event to avoid processing historical data
    try {
        $latest = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 -ErrorAction Stop
        if ($latest) { $lastEventId = $latest.RecordId }
    } catch {
        Write-Host "[!] Sysmon log not found. Running in fallback mode for demonstration." -ForegroundColor Yellow
    }

    while ($true) {
        try {
            if ($lastEventId -gt 0) {
                # Fetch new events
                $events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -ErrorAction Stop | Where-Object { $_.RecordId -gt $lastEventId }
                
                # Reverse events to process oldest to newest
                [array]::Reverse($events)
                
                foreach ($event in $events) {
                    $lastEventId = [Math]::Max($lastEventId, $event.RecordId)
                    
                    # Parse Event Data
                    $xml = [xml]$event.ToXml()
                    $eventData = $xml.Event.EventData.Data
                    
                    $procId = 0
                    $targetObj = ""
                    $targetFile = ""
                    
                    foreach ($data in $eventData) {
                        if ($data.Name -eq "ProcessId") { $procId = $data.'#text' }
                        if ($data.Name -eq "TargetObject") { $targetObj = $data.'#text' }
                        if ($data.Name -eq "TargetFilename") { $targetFile = $data.'#text' }
                    }
                    
                    # Rule 1: Quasar Persistence
                    if ($event.Id -eq 13 -and $targetObj -match "SOFTWARE\\(WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run") {
                        Write-Alert -PID $procId -RuleTriggered "Registry_RunKey_Modification" -Severity "HIGH" -Details "Target: $targetObj"
                        Evaluate-Heuristics -PID $procId -ScoreAdd 5 -Context "RunKey Mod"
                    }
                    
                    # Rule 2: Browser Data Theft
                    if ($event.Id -eq 11 -and ($targetFile -match "Login Data" -or $targetFile -match "IntelliForms\\Storage2")) {
                        Write-Alert -PID $procId -RuleTriggered "Browser_Data_Access" -Severity "HIGH" -Details "Target: $targetFile"
                        Evaluate-Heuristics -PID $procId -ScoreAdd 5 -Context "Browser Data"
                    }
                    
                    # Rule 3: Evasion/Geolocation (Simulated via Network Connection)
                    if ($event.Id -eq 3) {
                        # A full implementation would check DestinationIp against known services
                        # For PoC, we add a minor heuristic score for network connections
                        Evaluate-Heuristics -PID $procId -ScoreAdd 2 -Context "Network Connection"
                    }
                }
            }
        } catch {
            # Ignore errors if no new events are found in this cycle
        }
        
        Start-Sleep -Seconds $PollingInterval
    }
} finally {
    Write-Host "[*] Monitor stopped."
}
