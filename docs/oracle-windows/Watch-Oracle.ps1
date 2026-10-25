#Requires -Version 5.1
<#
.SYNOPSIS
    Follow a running oracle client: its discovery, connection and hub lines, and
    the cache's /stats.

.DESCRIPTION
    Prints the lines of Shareaza's debug log that matter for a GWebCache test as
    they appear, and keeps them in <WorkDir>\run\watch.log. Every few minutes it
    saves the cache's /stats to <WorkDir>\run\stats\. Stop it with Ctrl+C; it
    changes nothing in Shareaza. It does not need an elevated PowerShell.

    Lines to look for:
    - "Querying discovery service" / "[DiscoveryServices] Request:": a cache query.
    - "Discovery service ... failed, fail count N": a failed query.
    - "Accepting incoming TCP connections on ... port N": the listening port.
    - "Is Gnutella2 hub capable?" and the YES/NO/OK lines after it, at connect.

.EXAMPLE
    .\Watch-Oracle.ps1 -Hours 4
#>
[CmdletBinding()]
param(
    [string] $CacheUrl = 'http://gwc-edge.net/',
    [double] $Hours = 1,
    [int] $StatsEveryMinutes = 5,
    [int] $Port = 0,
    [string] $WorkDir = (Join-Path $env:USERPROFILE 'ShareazaOracle')
)
. (Join-Path $PSScriptRoot 'OracleCommon.ps1')
$WorkDir = Resolve-WorkDir $WorkDir

$log = Join-Path $script:UserData 'Data\Shareaza.log'
$run = Join-Path $WorkDir 'run'
$statsDir = Join-Path $run 'stats'
$watchLog = Join-Path $run 'watch.log'
New-Item -ItemType Directory -Force -Path $statsDir | Out-Null
if (-not $Port) {
    $prepared = Join-Path $run 'prepared.txt'
    if ((Test-Path $prepared) -and ((Get-Content -Raw $prepared) -match 'port=(\d+)')) { $Port = [int]$Matches[1] }
}
$pattern = 'Discovery|discovery|hub capable|YES:|NO:|OK:|Accepting incoming|Listening for|Disconnected|Shutting down|VersionChecker|firewalled|Firewall'

function Out-Line([string] $Text, [string] $Color = '') {
    if ($Color) { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text }
    Add-Content -Path $watchLog -Value $Text -Encoding UTF8
}

# Shareaza opens its log exclusively for each message (Shareaza.cpp), so a read can
# collide with a write: then skip this round. Read only what was appended since the
# last round, to hold the file as briefly as possible. The log is UTF-16 LE.
$script:offset = 0L
function Read-NewText {
    if (-not (Test-Path $log)) { return '' }
    try {
        $fs = [IO.File]::Open($log, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete')
    } catch [IO.IOException] { return '' }
    try {
        if ($fs.Length -lt $script:offset) { $script:offset = 0L }           # rotated: start again
        if ($script:offset -eq 0 -and $fs.Length -ge 2) { $script:offset = 2L }   # skip the BOM
        $count = [int][Math]::Min($fs.Length - $script:offset, 64MB)
        $count -= $count % 2
        if ($count -le 0) { return '' }
        $buffer = New-Object byte[] $count
        [void]$fs.Seek($script:offset, [IO.SeekOrigin]::Begin)
        $read = $fs.Read($buffer, 0, $count)
        $read -= $read % 2
        $script:offset += $read
        return [Text.Encoding]::Unicode.GetString($buffer, 0, $read)
    } finally { $fs.Dispose() }
}

$statsUrl = ($CacheUrl.TrimEnd('/')) + '/stats'
$end = (Get-Date).AddHours($Hours)
$nextStats = Get-Date
$pending = ''
Out-Line "Watching $log until $($end.ToString('HH:mm')); /stats from $statsUrl every $StatsEveryMinutes min."
while ((Get-Date) -lt $end) {
    $parts = @(($pending + (Read-NewText)) -split "`r?`n")
    $pending = $parts[-1]   # a line Shareaza is still writing, or ''
    if ($parts.Count -ge 2) {
        foreach ($line in $parts[0..($parts.Count - 2)]) {
            if ($line -match $pattern) { Out-Line $line }
            if ($Port -and $line -match 'Accepting incoming TCP connections on \S+ port (\d+)' -and [int]$Matches[1] -ne $Port) {
                Out-Line "WARNING: Shareaza listens on port $($Matches[1]), not the prepared $Port; the forwarded port will not reach it." 'Yellow'
            }
        }
    }

    if ((Get-Date) -ge $nextStats) {
        try {
            $raw = (Invoke-WebRequest -UseBasicParsing -Uri $statsUrl -TimeoutSec 20).Content
            $s = $raw | ConvertFrom-Json
            Set-Content -Path (Join-Path $statsDir ('stats-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json')) -Value $raw -Encoding UTF8
            $clients = ($s.requests.by_client | ForEach-Object { "$($_.client) $($_.version)=$($_.n)" }) -join ', '
            Out-Line ("[stats {0}] hubs served={1} verified={2}; requests total={3} hostfile={4} urlfile={5} update={6} limited={7}; clients: {8}" -f `
                (Get-Date -Format 'HH:mm'), $s.hubs.served, $s.hubs.verified, $s.requests.total,
                $s.requests.by_kind.hostfile, $s.requests.by_kind.urlfile, $s.requests.by_kind.update,
                $s.requests.by_kind.limited, $clients) 'Cyan'
        } catch {
            Out-Line "[stats] $statsUrl failed: $($_.Exception.Message)" 'Yellow'
        }
        $nextStats = (Get-Date).AddMinutes($StatsEveryMinutes)
    }
    Start-Sleep -Seconds 10
}
