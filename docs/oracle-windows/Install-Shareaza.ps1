#Requires -Version 5.1
<#
.SYNOPSIS
    Save your own Shareaza setup, then download, verify and silently install a
    Shareaza client for oracle testing.

.DESCRIPTION
    Official: Shareaza 2.7.10.2 x64 from SourceForge, checked against the SHA-256
    SourceForge publishes. Fork: this fork's x64 build from a published GitHub
    release, checked against the release's SHA256SUMS.txt.

    Before installing, it saves your existing Shareaza settings, data folder,
    DefaultServices.dat and installed version (once per test session), because
    the installer itself changes some of them. Restore-Oracle.ps1 puts them back.

    The silent install keeps the installer's Windows Firewall exception and turns
    off its UPnP, desktop and quick-launch tasks. It never launches Shareaza.

    Run it from PowerShell opened as administrator from your own account.

.EXAMPLE
    .\Install-Shareaza.ps1 -Client Official
.EXAMPLE
    .\Install-Shareaza.ps1 -Client Fork -ReleaseTag v2.7.10.6-previ.1
#>
[CmdletBinding()]
param(
    [ValidateSet('Official', 'Fork')]
    [string] $Client = 'Official',
    [string] $ReleaseTag = 'v2.7.10.6-previ.1',
    [string] $Repository = 'Prev-I/Shareaza',
    [string] $WorkDir = (Join-Path $env:USERPROFILE 'ShareazaOracle')
)
. (Join-Path $PSScriptRoot 'OracleCommon.ps1')
Assert-Admin
Assert-NotRunning
Assert-SameVolume $WorkDir

$downloads = Join-Path $WorkDir 'installers'
New-Item -ItemType Directory -Force -Path $downloads | Out-Null
# SourceForge serves an HTML page, not the file, to Windows PowerShell's browser-like
# default user agent; the hash check below would catch it, but this avoids it.
$agent = 'Wget/1.21.4'

if ($Client -eq 'Official') {
    $name = 'Shareaza_2.7.10.2_x64.exe'
    $url = 'https://downloads.sourceforge.net/project/shareaza/Shareaza/Shareaza-2.7.10.2/Shareaza_2.7.10.2_x64.exe'
    $expected = 'D6FF141D69A3AF53F8F7547B40E308A4E2AA4818EEB28DA827D7545165EF3051'   # published by SourceForge
    $exe = Join-Path $downloads $name
    Write-Host "Downloading $name from SourceForge"
    Invoke-WebRequest -UseBasicParsing -UserAgent $agent -Uri $url -OutFile $exe
} else {
    # The release's own SHA256SUMS.txt names its installers, so no GitHub API call
    # is needed: the API's anonymous limit is easily reached on a shared address.
    $base = "https://github.com/$Repository/releases/download/$ReleaseTag"
    $sums = Join-Path $downloads 'SHA256SUMS.txt'
    Write-Host "Downloading SHA256SUMS.txt from $ReleaseTag"
    Invoke-WebRequest -UseBasicParsing -UserAgent $agent -Uri "$base/SHA256SUMS.txt" -OutFile $sums
    # Lines are "<hash> <name>" or "<hash> *<name>".
    $lines = @(Get-Content $sums | Where-Object { $_ -match '^[0-9a-fA-F]{64} [ *]\S+_x64_Release_\S+\.exe$' })
    if ($lines.Count -ne 1) { throw "Expected one x64 installer in $ReleaseTag's SHA256SUMS.txt, found $($lines.Count)." }
    $expected = ($lines[0] -split ' ')[0].ToUpperInvariant()
    $name = ($lines[0] -replace '^[0-9a-fA-F]{64} [ *]', '')
    $exe = Join-Path $downloads $name
    Write-Host "Downloading $name from $ReleaseTag"
    Invoke-WebRequest -UseBasicParsing -UserAgent $agent -Uri "$base/$name" -OutFile $exe
}

$actual = (Get-FileHash -Algorithm SHA256 -Path $exe).Hash
if ($actual -ne $expected) { throw "$name has SHA-256 $actual, expected $expected. Not installing." }
Write-Host "SHA-256 OK: $actual"

Backup-UserSetup $WorkDir

$log = Join-Path $WorkDir "install-$Client.log"
$arguments = @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-',
               '/MERGETASKS="firewall,!upnp,!desktopicon,!quicklaunch"', "/LOG=`"$log`"")
Write-Host "Installing $name silently"
$p = Start-Process -FilePath $exe -ArgumentList $arguments -Wait -PassThru
if ($p.ExitCode -ne 0) { throw "The installer exited with $($p.ExitCode); see $log" }
if (-not (Select-String -Path $log -SimpleMatch 'Installation process succeeded.' -Quiet)) {
    throw "The installer did not report success; see $log"
}

$app = Get-ShareazaApp
if (-not (Test-Path (Join-Path $app 'Shareaza.exe'))) { throw "Shareaza.exe not found in $app" }
# With no Shareaza before the test, keep the stock discovery list for Restore-Oracle.ps1.
$stock = Join-Path $WorkDir 'session\DefaultServices.dat'
if (-not (Test-Path $stock)) { Copy-Item (Join-Path $app 'Data\DefaultServices.dat') $stock }
Write-Host "Installed $Client $(Get-InstalledVersion) in $app"
Write-Host 'Next: .\Prepare-Oracle.ps1'
