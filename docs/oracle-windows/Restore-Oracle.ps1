#Requires -Version 5.1
<#
.SYNOPSIS
    Collect the evidence of an oracle run, then put your own Shareaza setup back.

.DESCRIPTION
    With Shareaza closed, from PowerShell opened as administrator from your own
    account:

    1. Collects into <WorkDir>\evidence-<time>.zip: Shareaza.log, Discovery.dat,
       HostCache.dat, an export of HKCU\Software\Shareaza, and this run's notes,
       /stats snapshots and watcher log. The log and the host cache contain the
       public IP addresses of the hubs the client met, and probably yours: look
       before sharing the zip.
    2. Removes the kit's firewall rules, and puts back the IPv6/IPv4 preference
       if Prepare-Oracle.ps1 -PreferIPv4 changed it.
    3. Puts back the settings, data folder and DefaultServices.dat saved before
       the test, keeping the test run's data under <WorkDir>\runs\, and deletes
       the saved copy only once everything is back.

    It refuses to run when there is no saved setup to put back. Use -CollectOnly
    to make the zip and change nothing.
#>
[CmdletBinding()]
param(
    [switch] $CollectOnly,
    [string] $WorkDir = (Join-Path $env:USERPROFILE 'ShareazaOracle')
)
. (Join-Path $PSScriptRoot 'OracleCommon.ps1')
$WorkDir = Resolve-WorkDir $WorkDir
Assert-NotRunning
$session = Join-Path $WorkDir 'session'
$manifest = Get-Session $WorkDir
$marker = Join-Path $session 'restoring'
# An earlier restore stopped partway: %APPDATA%\Shareaza may already hold your own
# data again, so collect nothing from it and only finish the restore.
$resuming = Test-Path $marker
if (-not $CollectOnly) {
    Assert-Admin
    Assert-SameVolume $WorkDir
    if (-not $manifest) {
        throw "No saved setup in $session (no manifest.json): nothing to restore. Restore-Oracle.ps1 has either run already, or Install-Shareaza.ps1 / Prepare-Oracle.ps1 never did."
    }
}
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

# 1. Evidence.
if ($resuming) {
    Write-Host 'Finishing an interrupted restore; no evidence is collected this time.'
} else {
$staging = Join-Path $WorkDir "evidence-$stamp"
New-Item -ItemType Directory -Force -Path $staging | Out-Null
foreach ($f in 'Shareaza.log', 'Shareaza.old.log', 'Discovery.dat', 'HostCache.dat') {
    $p = Join-Path $script:UserData "Data\$f"
    if (Test-Path $p) { Copy-Item $p $staging }
}
if (Test-Path 'HKCU:\Software\Shareaza') {
    [void](Invoke-Native 'reg.exe' @('export', 'HKCU\Software\Shareaza', "`"$staging\shareaza.reg`"", '/y'))
}
$run = Join-Path $WorkDir 'run'
if (Test-Path $run) { Copy-Item -Recurse $run (Join-Path $staging 'run') }
Get-ChildItem -Path $WorkDir -Filter 'install-*.log' -ErrorAction SilentlyContinue | Copy-Item -Destination $staging
Set-Content -Encoding ASCII (Join-Path $staging 'collected.txt') "at=$(Get-Date -Format o)"
$zip = "$staging.zip"
Compress-Archive -Path (Join-Path $staging '*') -DestinationPath $zip -Force
Remove-Item -Recurse -Force $staging
Write-Host "Evidence: $zip"
}
if ($CollectOnly) { return }
# From here on, nothing else may run until this restore has finished.
Set-Content -Encoding ASCII $marker "at=$(Get-Date -Format o)"

# 2. Firewall rules and the IPv6/IPv4 preference.
Get-NetFirewallRule -DisplayName 'Shareaza oracle *' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
$policyFile = Join-Path $session 'prefixpolicy.txt'
if (Test-Path $policyFile) {
    $saved = (Get-Content $policyFile -TotalCount 1).Trim() -split '\s+'
    if ((Invoke-Native 'netsh.exe' @('interface', 'ipv6', 'set', 'prefixpolicy', '::ffff:0:0/96', $saved[0], $saved[1])) -ne 0) {
        throw "netsh could not restore the prefix policy to precedence $($saved[0]), label $($saved[1]); set it by hand."
    }
    Remove-Item $policyFile
    Write-Host "Windows IPv6/IPv4 preference put back (precedence $($saved[0]))."
}

# 3. Your own setup. Every step can be repeated if an earlier run stopped partway.
$target = $null
if ($manifest.PSObject.Properties['defaultsPath']) { $target = $manifest.defaultsPath }
if (-not $target) { $target = Join-Path (Get-ShareazaApp) 'Data\DefaultServices.dat' }
$savedDefaults = Join-Path $session 'DefaultServices.dat'
if ((Test-Path $savedDefaults) -and (Test-Path (Split-Path $target))) { Copy-Item $savedDefaults $target -Force }

$runs = Join-Path $WorkDir "runs\$stamp"
foreach ($d in 'shared', 'run') {
    $p = Join-Path $WorkDir $d
    if (Test-Path $p) { Move-Folder $p (Join-Path $runs $d) }
}
$savedData = Join-Path $session 'AppData-Shareaza'
if ($manifest.hadAppData -and -not (Test-Path $savedData)) {
    # An interrupted restore already moved your data back: leave it where it is.
    Write-Host "Your data folder is already back in $script:UserData."
} else {
    # Whatever is there now belongs to the oracle runs.
    if (Test-Path $script:UserData) { Move-Folder $script:UserData (Join-Path $runs 'AppData-Shareaza') }
    if ($manifest.hadAppData) { Move-Folder $savedData $script:UserData }
}

if (Test-Path 'HKCU:\Software\Shareaza') { Remove-Item -Recurse -Force 'HKCU:\Software\Shareaza' }
if ($manifest.hadRegistry) {
    $savedReg = Join-Path $session 'shareaza.reg'
    if ((Invoke-Native 'reg.exe' @('import', "`"$savedReg`"")) -ne 0) {
        throw "reg import of $savedReg failed. Your settings are still in that file: import it by hand (double-click it), then delete $session."
    }
    Write-Host 'Your Shareaza settings are back.'
} else {
    Write-Host 'There were no Shareaza settings before the test; the oracle ones are removed.'
}

$now = Get-InstalledVersion
if ($manifest.previousVersion -and $manifest.previousVersion -ne $now) {
    Write-Host "Note: you had Shareaza $($manifest.previousVersion) before the test; $now is installed now. Reinstall your own version before using it." -ForegroundColor Yellow
} elseif ($manifest.hadRegistry -or $manifest.hadAppData) {
    # Uninstalling deletes %APPDATA%\Shareaza\Data and HKCU\Software\Shareaza: the data just restored.
    if (-not $manifest.previousVersion) {
        Write-Host 'Note: your Shareaza version before the test could not be read; reinstall your own version if it differs.' -ForegroundColor Yellow
    }
    Write-Host 'Do not uninstall Shareaza to clean up: the uninstaller deletes the settings and data that were just put back.' -ForegroundColor Yellow
} else {
    Write-Host 'Shareaza was not on this PC before the test. Uninstall it from Settings > Apps if you no longer want it.'
}
# Everything is back; only now is the saved copy deleted.
Remove-Item -Recurse -Force $session
Write-Host 'Restored.'
