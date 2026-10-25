#Requires -Version 5.1
<#
.SYNOPSIS
    Follow a running oracle client: its discovery, connection and hub lines, and
    the cache's /stats.

.DESCRIPTION
    Prints the lines of Shareaza's debug log that matter for a GWebCache test as
    they appear, and every few minutes saves the cache's /stats to
    <WorkDir>\stats\. Stop it with Ctrl+C; nothing it does changes Shareaza.

    Lines to look for:
    - "Querying discovery service" / "[DiscoveryServices] Request:": a cache query.
    - "Discovery service ... failed, fail count N": a failure. Two in a row
      remove the cache from the client's list.
    - "Is Gnutella2 hub capable?" and the YES/NO/OK lines after it.
    - "Accepting incoming", "Listening for UDP": the listener.

.EXAMPLE
    .\Watch-Oracle.ps1 -Hours 4
#>
[CmdletBinding()]
param(
    [string] $CacheUrl = 'http://gwc-edge.net/',
    [double] $Hours = 1,
    [int] $StatsEveryMinutes = 5,
    [string] $WorkDir = (Join-Path $env:USERPROFILE 'ShareazaOracle')
)
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$log = Join-Path $env:APPDATA 'Shareaza\Data\Shareaza.log'
$statsDir = Join-Path $WorkDir 'stats'
New-Item -ItemType Directory -Force -Path $statsDir | Out-Null
$pattern = 'Discovery|discovery|hub capable|YES:|NO:|OK:|Accepting incoming|Listening for|Connecting to|Disconnected|Shutting down|VersionChecker|Firewall|firewalled|update'

# Shareaza keeps the log open, so read it with sharing allowed. It is UTF-16 LE.
function Read-Log {
    if (-not (Test-Path $log)) { return @() }
    $fs = [IO.File]::Open($log, 'Open', 'Read', 'ReadWrite')
    try { $sr = New-Object IO.StreamReader($fs, [Text.Encoding]::Unicode); $text = $sr.ReadToEnd() } finally { $fs.Dispose() }
    return $text -split "`r?`n"
}

$statsUrl = ($CacheUrl.TrimEnd('/')) + '/stats'
$end = (Get-Date).AddHours($Hours)
$seen = 0
$nextStats = Get-Date
Write-Host "Watching $log until $($end.ToString('HH:mm')); /stats from $statsUrl every $StatsEveryMinutes min."
while ((Get-Date) -lt $end) {
    $lines = @(Read-Log)
    # The last element is either empty or a line Shareaza is still writing: never count it.
    $complete = [Math]::Max(0, $lines.Count - 1)
    if ($complete -lt $seen) { $seen = 0 }   # the log was rotated
    for ($i = $seen; $i -lt $complete; $i++) {
        if ($lines[$i] -match $pattern) { Write-Host $lines[$i] }
    }
    $seen = $complete

    if ((Get-Date) -ge $nextStats) {
        try {
            $raw = (Invoke-WebRequest -UseBasicParsing -Uri $statsUrl -TimeoutSec 20).Content
            $file = Join-Path $statsDir ('stats-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json')
            Set-Content -Path $file -Value $raw -Encoding UTF8
            $s = $raw | ConvertFrom-Json
            $clients = ($s.requests.by_client | ForEach-Object { "$($_.client) $($_.version)=$($_.n)" }) -join ', '
            Write-Host ("[stats {0}] hubs served={1} verified={2}; requests total={3} hostfile={4} urlfile={5} update={6} limited={7}; clients: {8}" -f `
                (Get-Date -Format 'HH:mm'), $s.hubs.served, $s.hubs.verified, $s.requests.total,
                $s.requests.by_kind.hostfile, $s.requests.by_kind.urlfile, $s.requests.by_kind.update,
                $s.requests.by_kind.limited, $clients) -ForegroundColor Cyan
        } catch {
            Write-Host "[stats] $statsUrl failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        $nextStats = (Get-Date).AddMinutes($StatsEveryMinutes)
    }
    Start-Sleep -Seconds 10
}
