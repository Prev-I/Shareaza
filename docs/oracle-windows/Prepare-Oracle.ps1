#Requires -Version 5.1
<#
.SYNOPSIS
    Prepare an installed Shareaza to test one GWebCache, as a leaf or as a hub.

.DESCRIPTION
    Run it after every install, with Shareaza closed, from an elevated PowerShell
    opened from your own account. It:

    1. Backs up, once, your existing Shareaza settings (HKCU\Software\Shareaza),
       its data folder (%APPDATA%\Shareaza) and DefaultServices.dat into
       <WorkDir>\backup, and moves the data folder aside, so the client starts
       with an empty library, host cache and discovery list.
       Restore-Oracle.ps1 puts everything back.
    2. Makes the cache under test the only discovery service: DefaultServices.dat
       becomes "2 <CacheUrl>" (a G2 GWebCache). Shareaza reloads that file
       whenever its list is short, so deleting services in the GUI is not enough.
    3. Points the download folder at an empty <WorkDir>\Downloads. On its first
       run Shareaza SHARES its download folder, and the default is your whole
       Downloads folder.
    4. Turns off what goes online by itself (update check, BitTorrent, DHT, UPnP,
       Gnutella1, eD2k, DC), skips the QuickStart wizard and the dialogs after
       it while still connecting at start, turns on the debug log, and sets the
       G2 mode and listening port.
    5. Opens the port in Windows Firewall (inbound TCP and UDP), and optionally
       makes Windows prefer IPv4: gwc-edge.net has IPv6 addresses, and a hub
       that reaches the cache over IPv6 while reporting its IPv4 address is
       rejected as ip:source_mismatch.

.EXAMPLE
    .\Prepare-Oracle.ps1 -Mode Leaf
.EXAMPLE
    .\Prepare-Oracle.ps1 -Mode Hub -Port 6346 -PreferIPv4
#>
[CmdletBinding()]
param(
    [string] $CacheUrl = 'http://gwc-edge.net/',
    [ValidateSet('Leaf', 'Hub')]
    [string] $Mode = 'Leaf',
    [ValidateRange(1024, 65535)]
    [int] $Port = 6346,
    [switch] $PreferIPv4,
    [string] $WorkDir = (Join-Path $env:USERPROFILE 'ShareazaOracle')
)
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell (Run as administrator).'
}
if (Get-Process -Name Shareaza -ErrorAction SilentlyContinue) {
    throw 'Shareaza is running. Close it first, or its exit save overwrites these settings.'
}

# The client's own URL check (DiscoveryServices.cpp, CheckWebCacheValid): http://,
# at least 12 characters, a dot after the scheme and a slash after that dot.
if ($CacheUrl -notmatch '^http://[^/]*\.[^/]*/' -or $CacheUrl.Length -lt 12) {
    throw "$CacheUrl is not a URL Shareaza accepts: use http://host.domain/... with a trailing path."
}

$key = 'HKCU:\Software\Shareaza\Shareaza'
$app = (Get-ItemProperty -Path $key -Name Path -ErrorAction SilentlyContinue).Path
if (-not $app) { $app = Join-Path $env:ProgramFiles 'Shareaza' }
if (-not (Test-Path (Join-Path $app 'Shareaza.exe'))) { throw "Shareaza is not installed in $app. Run Install-Shareaza.ps1." }
$userData = Join-Path $env:APPDATA 'Shareaza'
$defaults = Join-Path $app 'Data\DefaultServices.dat'

# 1. One-time backup. A second run (after a reinstall) keeps the first backup.
$backup = Join-Path $WorkDir 'backup'
if (-not (Test-Path $backup)) {
    New-Item -ItemType Directory -Force -Path $backup | Out-Null
    if (Test-Path 'HKCU:\Software\Shareaza') {
        & reg.exe export 'HKCU\Software\Shareaza' (Join-Path $backup 'shareaza.reg') /y | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'reg export failed.' }
    }
    if (Test-Path $userData) {
        Move-Item -Path $userData -Destination (Join-Path $backup 'AppData-Shareaza')
        Write-Host "Moved your Shareaza data folder to $backup\AppData-Shareaza"
    }
    Write-Host "Backed up your Shareaza settings to $backup"
} elseif (Test-Path $userData) {
    # Leftovers of an earlier oracle run, not your own data: that was moved on the first run.
    $old = Join-Path $WorkDir ('runs\AppData-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    New-Item -ItemType Directory -Force -Path (Split-Path $old) | Out-Null
    Move-Item -Path $userData -Destination $old
    Write-Host "Moved the previous oracle run's data to $old"
}
# Saved on every run: the installer restores the stock file each time.
Copy-Item -Path $defaults -Destination (Join-Path $backup 'DefaultServices.dat') -Force

# 2. Discovery: only the cache under test.
[IO.File]::WriteAllText($defaults, "2 $CacheUrl`r`n", [Text.Encoding]::ASCII)

# 3. An empty, dedicated download folder, because the download folder is shared.
$complete = Join-Path $WorkDir 'Downloads'
$incomplete = Join-Path $WorkDir 'Incomplete'
foreach ($d in $complete, $incomplete) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
    if (Get-ChildItem -Force -Path $d) { throw "$d is not empty; it would be shared. Empty it first." }
}

function Set-Setting([string] $Section, [string] $Name, $Value) {
    $path = if ($Section) { "$key\$Section" } else { $key }
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    $type = if ($Value -is [string]) { 'String' } else { 'DWord' }
    New-ItemProperty -Path $path -Name $Name -Value $Value -PropertyType $type -Force | Out-Null
}

# 4. Settings, all in HKCU\Software\Shareaza\Shareaza (Settings.cpp).
Set-Setting 'Downloads'    'CompletePath'   $complete
Set-Setting 'Downloads'    'IncompletePath' $incomplete
Set-Setting 'VersionCheck' 'UpdateCheck'    0
Set-Setting 'BitTorrent'   'EnableAlways'   0
Set-Setting 'BitTorrent'   'EnableDHT'      0
Set-Setting 'Connection'   'EnableUPnP'     0
Set-Setting 'Gnutella1'    'EnableAlways'   0
Set-Setting 'eDonkey'      'EnableAlways'   0
Set-Setting 'DC'           'EnableAlways'   0
Set-Setting 'Gnutella2'    'EnableAlways'   1
Set-Setting 'Gnutella2'    'ClientMode'     $(if ($Mode -eq 'Hub') { 2 } else { 1 })   # 1 leaf, 2 forced hub
Set-Setting 'Connection'   'InPort'         $Port
Set-Setting 'Connection'   'AutoConnect'    1
# On a first run Shareaza connects only from inside the wizard (WndMain.cpp), and
# Windows\RunWizard decides whether the wizard opens: both are needed.
Set-Setting 'Settings'     'FirstRun'       0
Set-Setting 'Windows'      'RunWizard'      1
Set-Setting 'Windows'      'RunWarnings'    1
Set-Setting 'Windows'      'RunPromote'     1
Set-Setting 'Settings'     'CloseMode'      1   # exit when the window is closed
Set-Setting ''             'DebugLog'       1   # %APPDATA%\Shareaza\Data\Shareaza.log
Set-Setting ''             'LogLevel'       4

# 5. Windows Firewall, and optionally IPv4 first.
foreach ($proto in 'TCP', 'UDP') {
    $rule = "Shareaza oracle $proto $Port"
    if (-not (Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $rule -Direction Inbound -Action Allow -Protocol $proto `
            -LocalPort $Port -Profile Any | Out-Null
    }
}
if ($PreferIPv4) {
    $state = Join-Path $WorkDir 'prefixpolicy-before.txt'
    if (-not (Test-Path $state)) { & netsh interface ipv6 show prefixpolicies | Out-File -Encoding ASCII $state }
    # Raise IPv4-mapped addresses above ::/0 (40); the default is 35. Restore-Oracle.ps1 puts 35 back.
    & netsh interface ipv6 set prefixpolicy '::ffff:0:0/96' 100 4 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'netsh prefixpolicy failed.' }
    Write-Host 'Windows now prefers IPv4 over IPv6.'
}

New-Item -ItemType File -Force -Path (Join-Path $WorkDir 'prepared.txt') -Value `
    "cache=$CacheUrl mode=$Mode port=$Port preferipv4=$PreferIPv4 at=$(Get-Date -Format o)" | Out-Null
Write-Host ''
Write-Host "Prepared: $Mode on port $Port, talking only to $CacheUrl."
Write-Host "Shared folder: $complete (empty)."
if ($Mode -eq 'Hub') { Write-Host "Forward TCP and UDP $Port on your router to this PC before starting." }
Write-Host "Start Shareaza from the Start menu or: & '$app\Shareaza.exe'"
Write-Host 'Then, in another PowerShell: .\Watch-Oracle.ps1'
