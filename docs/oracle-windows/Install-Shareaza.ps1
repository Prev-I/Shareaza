#Requires -Version 5.1
<#
.SYNOPSIS
    Download, verify and silently install a Shareaza client for oracle testing.

.DESCRIPTION
    Official: Shareaza 2.7.10.2 x64 from SourceForge, checked against the SHA-256
    SourceForge publishes. Fork: this fork's x64 build from a published GitHub
    release, checked against the release's SHA256SUMS.txt.

    The silent install keeps the installer's Windows Firewall exception and turns
    off its UPnP, desktop and quick-launch tasks. It never launches Shareaza.

    Run it from an elevated PowerShell opened from YOUR OWN account (right-click,
    Run as administrator), so the per-user settings land in your profile.

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
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest is very slow with its progress bar
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell (Run as administrator).'
}
if (Get-Process -Name Shareaza -ErrorAction SilentlyContinue) {
    throw 'Shareaza is running. Close it first.'
}

$downloads = Join-Path $WorkDir 'installers'
New-Item -ItemType Directory -Force -Path $downloads | Out-Null

if ($Client -eq 'Official') {
    $name = 'Shareaza_2.7.10.2_x64.exe'
    $url = 'https://downloads.sourceforge.net/project/shareaza/Shareaza/Shareaza-2.7.10.2/Shareaza_2.7.10.2_x64.exe'
    $expected = 'D6FF141D69A3AF53F8F7547B40E308A4E2AA4818EEB28DA827D7545165EF3051'   # published by SourceForge
    $exe = Join-Path $downloads $name
    Write-Host "Downloading $name from SourceForge"
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $exe
} else {
    $api = "https://api.github.com/repos/$Repository/releases/tags/$ReleaseTag"
    $release = Invoke-RestMethod -UseBasicParsing -Uri $api -Headers @{ 'User-Agent' = 'shareaza-oracle' }
    $assets = @($release.assets | Where-Object { $_.name -match '_x64_Release_.*\.exe$' })
    if ($assets.Count -ne 1) { throw "Expected one x64 installer in $ReleaseTag, found $($assets.Count)." }
    $name = $assets[0].name
    $base = "https://github.com/$Repository/releases/download/$ReleaseTag"
    $exe = Join-Path $downloads $name
    $sums = Join-Path $downloads 'SHA256SUMS.txt'
    Write-Host "Downloading $name and SHA256SUMS.txt from $ReleaseTag"
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$name" -OutFile $exe
    Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS.txt" -OutFile $sums
    # Lines are "<hash> <name>" or "<hash> *<name>".
    $line = Get-Content $sums | Where-Object { $_ -match "^([0-9a-fA-F]{64}) [ *]$([regex]::Escape($name))$" } | Select-Object -First 1
    if (-not $line) { throw "$name is not listed in SHA256SUMS.txt." }
    $expected = ($line -split ' ')[0].ToUpperInvariant()
}

$actual = (Get-FileHash -Algorithm SHA256 -Path $exe).Hash
if ($actual -ne $expected) { throw "$name has SHA-256 $actual, expected $expected. Not installing." }
Write-Host "SHA-256 OK: $actual"

$log = Join-Path $WorkDir "install-$Client.log"
$arguments = @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-',
               '/MERGETASKS="firewall,!upnp,!desktopicon,!quicklaunch"', "/LOG=`"$log`"")
Write-Host "Installing $name silently"
$p = Start-Process -FilePath $exe -ArgumentList $arguments -Wait -PassThru
if ($p.ExitCode -ne 0) { throw "The installer exited with $($p.ExitCode); see $log" }
if (-not (Select-String -Path $log -SimpleMatch 'Installation process succeeded.' -Quiet)) {
    throw "The installer did not report success; see $log"
}

$path = (Get-ItemProperty -Path 'HKCU:\Software\Shareaza\Shareaza' -Name Path -ErrorAction SilentlyContinue).Path
if (-not $path) { $path = Join-Path $env:ProgramFiles 'Shareaza' }
if (-not (Test-Path (Join-Path $path 'Shareaza.exe'))) { throw "Shareaza.exe not found in $path" }
Write-Host "Installed $Client in $path"
Write-Host 'Next: .\Prepare-Oracle.ps1 (the installer has just reset part of the settings).'
