#Requires -Version 5.1
<#
.SYNOPSIS
    Collect the evidence of an oracle run, then put your own Shareaza setup back.

.DESCRIPTION
    With Shareaza closed, from an elevated PowerShell opened from your own account:

    1. Collects into <WorkDir>\evidence-<time>.zip: Shareaza.log, Discovery.dat,
       HostCache.dat, an export of HKCU\Software\Shareaza, the saved /stats, the
       install logs and prepared.txt. The log and the host cache contain the
       public IP addresses of the hubs the client met, and Shareaza.log may show
       your own public address: look before sharing the zip.
    2. Removes the "Shareaza oracle" firewall rules, and the IPv4 preference if
       Prepare-Oracle.ps1 -PreferIPv4 set it.
    3. Puts back the DefaultServices.dat, the settings and the data folder that
       Prepare-Oracle.ps1 backed up. The oracle run's data folder is kept under
       <WorkDir>\runs\.

    Use -CollectOnly to make the zip and change nothing.
#>
[CmdletBinding()]
param(
    [switch] $CollectOnly,
    [string] $WorkDir = (Join-Path $env:USERPROFILE 'ShareazaOracle')
)
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

if (Get-Process -Name Shareaza -ErrorAction SilentlyContinue) {
    throw 'Shareaza is running. Close it first (File > Exit), so it saves its data.'
}
if (-not $CollectOnly) {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this from an elevated PowerShell (Run as administrator), or use -CollectOnly.'
    }
}

$key = 'HKCU:\Software\Shareaza\Shareaza'
$userData = Join-Path $env:APPDATA 'Shareaza'
$backup = Join-Path $WorkDir 'backup'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

# 1. Evidence.
$staging = Join-Path $WorkDir "evidence-$stamp"
New-Item -ItemType Directory -Force -Path $staging | Out-Null
foreach ($f in 'Shareaza.log', 'Shareaza.old.log', 'Discovery.dat', 'HostCache.dat') {
    $p = Join-Path $userData "Data\$f"
    if (Test-Path $p) { Copy-Item $p $staging }
}
if (Test-Path 'HKCU:\Software\Shareaza') {
    & reg.exe export 'HKCU\Software\Shareaza' (Join-Path $staging 'shareaza.reg') /y | Out-Null
}
foreach ($p in (Join-Path $WorkDir 'stats'), (Join-Path $WorkDir 'prepared.txt')) {
    if (Test-Path $p) { Copy-Item -Recurse $p $staging }
}
Get-ChildItem -Path $WorkDir -Filter 'install-*.log' -ErrorAction SilentlyContinue | Copy-Item -Destination $staging
$zip = "$staging.zip"
Compress-Archive -Path (Join-Path $staging '*') -DestinationPath $zip -Force
Remove-Item -Recurse -Force $staging
Write-Host "Evidence: $zip"
if ($CollectOnly) { return }

# 2. Firewall rules and the IPv4 preference.
Get-NetFirewallRule -DisplayName 'Shareaza oracle *' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
$state = Join-Path $WorkDir 'prefixpolicy-before.txt'
if (Test-Path $state) {
    & netsh interface ipv6 set prefixpolicy '::ffff:0:0/96' 35 4 | Out-Null   # the Windows default
    Remove-Item $state
    Write-Host 'Windows IPv6/IPv4 preference set back to the default.'
}

# 3. Your own setup.
$app = (Get-ItemProperty -Path $key -Name Path -ErrorAction SilentlyContinue).Path
if (-not $app) { $app = Join-Path $env:ProgramFiles 'Shareaza' }
$savedDefaults = Join-Path $backup 'DefaultServices.dat'
if (Test-Path $savedDefaults) { Copy-Item $savedDefaults (Join-Path $app 'Data\DefaultServices.dat') -Force }

if (Test-Path $userData) {
    $run = Join-Path $WorkDir "runs\AppData-$stamp"
    New-Item -ItemType Directory -Force -Path (Split-Path $run) | Out-Null
    Move-Item -Path $userData -Destination $run
    Write-Host "This run's data folder is kept in $run"
}
$savedData = Join-Path $backup 'AppData-Shareaza'
if (Test-Path $savedData) { Move-Item -Path $savedData -Destination $userData }

if (Test-Path 'HKCU:\Software\Shareaza') { Remove-Item -Recurse -Force 'HKCU:\Software\Shareaza' }
$savedReg = Join-Path $backup 'shareaza.reg'
if (Test-Path $savedReg) {
    & reg.exe import $savedReg 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "reg import of $savedReg failed; import it by hand." }
    Write-Host 'Your Shareaza settings are back.'
} else {
    Write-Host 'There were no Shareaza settings before the test; the oracle ones are removed.'
}
# The backup has been used; a new Prepare-Oracle.ps1 run takes a fresh one.
Remove-Item -Recurse -Force $backup
Write-Host 'Restored. To remove Shareaza entirely, uninstall it from Settings > Apps.'
