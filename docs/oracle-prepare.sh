#!/usr/bin/env bash
# Prepare a Wine prefix holding an installed Shareaza to run as an isolated,
# unattended protocol oracle. See docs/ORACLE.md for what each step does and
# what it does not isolate.
#
# usage: docs/oracle-prepare.sh <wine prefix> <cache url>
#   e.g. docs/oracle-prepare.sh ~/.wine-shareaza-sf http://127.0.0.1:8787/
#
# Run it after every install or upgrade, with the client closed.
set -euo pipefail

[ $# -eq 2 ] || { echo "usage: $0 <wine prefix> <cache url>" >&2; exit 2; }
export WINEPREFIX=$1
cache=$2
app="$WINEPREFIX/drive_c/Program Files/Shareaza"
k='HKCU\Software\Shareaza\Shareaza'

[ -f "$app/Shareaza.exe" ] || { echo "$WINEPREFIX: Shareaza is not installed" >&2; exit 1; }
if pgrep -f 'Shareaza.exe' >/dev/null; then
    echo "a Shareaza client is running; close it first, or its exit save overwrites these settings" >&2
    exit 1
fi

reg() { wine reg add "$k$1" "${@:2}" /f >/dev/null; }

# 0. Under Wine, Shareaza saves a setting only into a section key that already
#    exists. Create every section in Settings.cpp so its own saves persist.
for sec in Bandwidth BitTorrent Community Connection DC Discovery Downloads Experimental Fonts \
           Gnutella Gnutella1 Gnutella2 IRC Interface Library MediaPlayer Remote Search Settings \
           Toolbars Uploads VersionCheck WINE Web Windows eDonkey; do
    reg "\\$sec"
done

# 1. Discovery: the cache under test is the only service the client knows.
#    Format "<type> <url>", 2 = G2 GWebCache, CRLF line ending.
printf '2 %s\r\n' "$cache" > "$app/Data/DefaultServices.dat"

# 2. Nothing else that goes online by itself.
reg '\VersionCheck' /v UpdateCheck  /t REG_DWORD /d 0
reg '\BitTorrent'   /v EnableAlways /t REG_DWORD /d 0
reg '\BitTorrent'   /v EnableDHT    /t REG_DWORD /d 0
reg '\Connection'   /v EnableUPnP   /t REG_DWORD /d 0

# 3. Start without the wizard and connect; exit on close instead of asking.
reg '\Settings' /v FirstRun    /t REG_DWORD /d 0
reg '\Windows'  /v RunWizard   /t REG_DWORD /d 1
reg '\Windows'  /v RunWarnings /t REG_DWORD /d 1
reg '\Windows'  /v RunPromote  /t REG_DWORD /d 1
reg '\Settings' /v CloseMode   /t REG_DWORD /d 1

# 4. A debug log of everything, in Data/Shareaza.log under %APPDATA%\Shareaza.
reg '' /v DebugLog /t REG_DWORD /d 1
reg '' /v LogLevel /t REG_DWORD /d 4

wineserver --wait
echo "$WINEPREFIX: prepared for $cache"
