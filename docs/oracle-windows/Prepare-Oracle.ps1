#Requires -Version 5.1
<#
.SYNOPSIS
    Prepare an installed Shareaza to test one GWebCache, as a leaf or as a hub.

.DESCRIPTION
    Run it after Install-Shareaza.ps1, and again whenever you switch mode or
    reinstall, with Shareaza closed, from PowerShell opened as administrator from
    your own account. It:

    1. Saves your own Shareaza setup, if Install-Shareaza.ps1 has not already
       (only once per test session), and moves any earlier oracle run aside.
    2. Replaces HKCU\Software\Shareaza\Shareaza with a clean key holding only
       the kit's settings, so nothing from your own setup (shared folders, random
       port, bandwidth limits) changes the test.
    3. Makes the cache under test the only discovery service: DefaultServices.dat
       becomes "2 <CacheUrl>", a G2 GWebCache. Shareaza reloads that file
       whenever its list is short, so deleting services in the GUI is not enough.
    4. Shares nothing: the four folders Shareaza shares on its first run
       (downloads, incomplete, collections, torrents) are new, empty folders under
       <WorkDir>\shared, and the installer copy Shareaza would otherwise put in
       its download folder is turned off. The 2.7.10.2 default download folder is
       your whole Downloads folder.
    5. Turns off what goes online by itself (update check, BitTorrent, DHT, UPnP,
       Gnutella1, eD2k, DC), skips the QuickStart wizard and the dialogs after it
       while still connecting at start, turns on the debug log, and sets the G2
       mode and listening port.
    6. Opens the port in Windows Firewall for Shareaza.exe, and optionally makes
       Windows prefer IPv4: gwc-edge.net has IPv6 addresses, and a hub that
       reaches the cache over IPv6 while reporting its IPv4 address is rejected
       as ip:source_mismatch.

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
. (Join-Path $PSScriptRoot 'OracleCommon.ps1')

# Every check first, before anything changes.
Assert-Admin
Assert-NotRunning
Assert-SameVolume $WorkDir
# The client's own URL check (DiscoveryServices.cpp, CheckWebCacheValid): at least
# 12 characters, a dot after the scheme and a slash after that dot. http:// only:
# HTTPS in these builds checks no certificate.
if ($CacheUrl -notmatch '^http://[^/]*\.[^/]*/' -or $CacheUrl.Length -lt 12) {
    throw "$CacheUrl is not a URL Shareaza accepts: use http://host.domain/ with a trailing slash or path."
}
$app = Get-ShareazaApp
$exe = Join-Path $app 'Shareaza.exe'
if (-not (Test-Path $exe)) { throw "Shareaza is not installed in $app. Run Install-Shareaza.ps1." }
$defaults = Join-Path $app 'Data\DefaultServices.dat'

# 1. Your own setup, saved once; then this run's starting point.
Backup-UserSetup $WorkDir
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runs = Join-Path $WorkDir "runs\$stamp"
$shared = Join-Path $WorkDir 'shared'
$run = Join-Path $WorkDir 'run'
if (Test-Path $script:UserData) { Move-Folder $script:UserData (Join-Path $runs 'AppData-Shareaza') }
if (Test-Path $shared) { Move-Folder $shared (Join-Path $runs 'shared') }
if (Test-Path $run) { Move-Folder $run (Join-Path $runs 'run') }
$folders = [ordered]@{
    CompletePath   = Join-Path $shared 'Downloads'
    IncompletePath = Join-Path $shared 'Incomplete'
    CollectionPath = Join-Path $shared 'Collections'
    TorrentPath    = Join-Path $shared 'Torrents'
}
foreach ($d in @($folders.Values) + $run) { New-Item -ItemType Directory -Force -Path $d | Out-Null }

# 2. A clean settings key. Only Shareaza's own section is replaced; the backup has
#    the whole HKCU\Software\Shareaza.
if (Test-Path $script:ShareazaKey) { Remove-Item -Recurse -Force $script:ShareazaKey }
New-Item -Path $script:ShareazaKey -Force | Out-Null

function Set-Setting([string] $Section, [string] $Name, $Value) {
    $path = if ($Section) { "$script:ShareazaKey\$Section" } else { $script:ShareazaKey }
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    $type = if ($Value -is [string]) { 'String' } else { 'DWord' }
    New-ItemProperty -Path $path -Name $Name -Value $Value -PropertyType $type -Force | Out-Null
}

# 3. Discovery: only the cache under test.
[IO.File]::WriteAllText($defaults, "2 $CacheUrl`r`n", [Text.Encoding]::ASCII)

# 4 and 5. Settings, all in HKCU\Software\Shareaza\Shareaza (Settings.cpp).
Set-Setting ''             'Path'           $app
Set-Setting ''             'UserPath'       $script:UserData
foreach ($f in $folders.GetEnumerator()) { Set-Setting 'Downloads' $f.Key $f.Value }
Set-Setting 'Settings'     'Upgrade'        0   # else it copies its installer into the shared folder
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
Set-Setting 'Connection'   'RandomPort'     0
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
Set-Setting ''             'MaxDebugLogSize' 104857600   # bytes; 100 MB, the maximum, so hours fit in one log

# 6. Windows Firewall, and optionally IPv4 first.
Get-NetFirewallRule -DisplayName 'Shareaza oracle *' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
foreach ($proto in 'TCP', 'UDP') {
    New-NetFirewallRule -DisplayName "Shareaza oracle $proto $Port" -Direction Inbound -Action Allow `
        -Protocol $proto -LocalPort $Port -Program $exe -Profile Any | Out-Null
}
$policyFile = Join-Path $WorkDir 'session\prefixpolicy.txt'
if ($PreferIPv4) {
    if (-not (Test-Path $policyFile)) {
        $row = (& netsh interface ipv6 show prefixpolicies) -match '::ffff:0:0/96'
        if (-not $row) { throw 'netsh shows no ::ffff:0:0/96 prefix policy; set the IPv4 preference by hand.' }
        $fields = (@($row)[0].Trim() -split '\s+')
        Set-Content -Encoding ASCII $policyFile "$($fields[0]) $($fields[1])"   # precedence label
    }
    # Raise IPv4-mapped addresses above ::/0 (40). Restore-Oracle.ps1 puts the saved values back.
    if ((Invoke-Native 'netsh.exe' @('interface', 'ipv6', 'set', 'prefixpolicy', '::ffff:0:0/96', '100', '4')) -ne 0) {
        throw 'netsh prefixpolicy failed.'
    }
    Write-Host 'Windows now prefers IPv4 over IPv6.'
}

Set-Content -Encoding UTF8 (Join-Path $run 'prepared.txt') `
    "cache=$CacheUrl mode=$Mode port=$Port preferipv4=$PreferIPv4 client=$(Get-InstalledVersion) at=$(Get-Date -Format o)"
Write-Host ''
Write-Host "Prepared: $Mode on port $Port, discovering only through $CacheUrl."
Write-Host "Shared: only the empty folders under $shared."
if ($Mode -eq 'Hub') { Write-Host "Forward TCP and UDP $Port on your router to this PC before starting." }
Write-Host 'Start Shareaza from the Start menu, NOT from this elevated window, or run:'
Write-Host "  explorer.exe `"$exe`""
Write-Host 'Then: .\Watch-Oracle.ps1'
