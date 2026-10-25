# Shared by the kit's scripts; dot-source it, don't run it.
#
# Layout under <WorkDir> (default %USERPROFILE%\ShareazaOracle):
#   session\          your own Shareaza setup, saved before the kit changed anything:
#                     manifest.json (written last), shareaza.reg, AppData-Shareaza\,
#                     DefaultServices.dat. Restore-Oracle.ps1 puts it back and deletes it.
#   session.partial\  a backup still being made; if it is left behind, a run died midway.
#   shared\           the only folders Shareaza is allowed to share; empty at start.
#   run\              this run's notes, /stats snapshots and watcher log.
#   runs\<time>\      earlier runs' data, kept for reference.
#   installers\       the downloaded installers.

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$script:ShareazaKey = 'HKCU:\Software\Shareaza\Shareaza'
$script:UserData = Join-Path $env:APPDATA 'Shareaza'

function Assert-Admin {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this from PowerShell opened as administrator, from your own account.'
    }
}

function Assert-NotRunning {
    if (Get-Process -Name Shareaza -ErrorAction SilentlyContinue) {
        throw 'Shareaza is running. Close it first (File > Exit), so it saves its data.'
    }
}

function Assert-SameVolume([string] $WorkDir) {
    # Folders are moved, not copied, between the work folder and %APPDATA%.
    if ([IO.Path]::GetPathRoot([IO.Path]::GetFullPath($WorkDir)) -ne [IO.Path]::GetPathRoot($env:APPDATA)) {
        throw "-WorkDir must be on the same drive as $env:APPDATA."
    }
}

# A registry value, or $null when the key or the value is missing.
function Get-RegValue([string] $Path, [string] $Name) {
    if (-not (Test-Path $Path)) { return $null }
    $item = Get-ItemProperty -Path $Path
    $prop = $item.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $null
}

function Get-ShareazaApp {
    $app = Get-RegValue $script:ShareazaKey 'Path'
    if (-not $app) { $app = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Shareaza.exe' 'Path' }
    if (-not $app) { $app = Join-Path $env:ProgramFiles 'Shareaza' }
    return $app
}

function Get-InstalledVersion {
    Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Shareaza_is1' 'DisplayVersion'
}

# Run a native program and judge it by its exit code alone: reg.exe and netsh print
# success messages on stderr, which Windows PowerShell would turn into errors.
function Invoke-Native([string] $File, [string[]] $Arguments) {
    $p = Start-Process -FilePath $File -ArgumentList $Arguments -Wait -PassThru -NoNewWindow
    return $p.ExitCode
}

# Move a folder, retrying while Windows or an antivirus still holds a file in it.
function Move-Folder([string] $From, [string] $To) {
    New-Item -ItemType Directory -Force -Path (Split-Path $To) | Out-Null
    for ($i = 1; ; $i++) {
        try { Move-Item -Path $From -Destination $To; return }
        catch { if ($i -ge 20) { throw "Could not move $From to $To after 60 s: $($_.Exception.Message)" }; Start-Sleep 3 }
    }
}

function Get-Session([string] $WorkDir) {
    $manifest = Join-Path $WorkDir 'session\manifest.json'
    if (Test-Path $manifest) { return (Get-Content -Raw $manifest | ConvertFrom-Json) }
    return $null
}

# Save the user's own Shareaza setup once, before the kit changes anything.
function Backup-UserSetup([string] $WorkDir) {
    $session = Join-Path $WorkDir 'session'
    $partial = Join-Path $WorkDir 'session.partial'
    if (Test-Path (Join-Path $session 'manifest.json')) { return }
    if (Test-Path $partial) {
        throw "$partial exists: an earlier backup did not finish. Your own data may be in it. Move anything from $partial\AppData-Shareaza back to $script:UserData if that folder is missing, delete $partial, and run again."
    }
    if (Test-Path $session) { throw "$session exists but has no manifest.json. Check it by hand, then delete it." }
    New-Item -ItemType Directory -Force -Path $partial | Out-Null

    $hadRegistry = Test-Path 'HKCU:\Software\Shareaza'
    if ($hadRegistry) {
        if ((Invoke-Native 'reg.exe' @('export', 'HKCU\Software\Shareaza', "`"$partial\shareaza.reg`"", '/y')) -ne 0) { throw 'reg export failed.' }
    }
    $app = Get-ShareazaApp
    $defaults = Join-Path $app 'Data\DefaultServices.dat'
    $hadDefaults = Test-Path $defaults
    if ($hadDefaults) { Copy-Item $defaults (Join-Path $partial 'DefaultServices.dat') }
    $hadAppData = Test-Path $script:UserData
    if ($hadAppData) { Move-Folder $script:UserData (Join-Path $partial 'AppData-Shareaza') }

    $manifest = [ordered]@{
        created         = (Get-Date -Format o)
        hadRegistry     = $hadRegistry
        hadAppData      = $hadAppData
        hadDefaults     = $hadDefaults
        previousVersion = (Get-InstalledVersion)
    }
    $manifest | ConvertTo-Json | Set-Content -Encoding UTF8 (Join-Path $partial 'manifest.json')
    Rename-Item -Path $partial -NewName 'session'
    Write-Host "Saved your own Shareaza setup in $session (restored by Restore-Oracle.ps1)."
}
