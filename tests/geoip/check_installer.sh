#!/usr/bin/env bash
# Checks that the installer ships the GeoIP database together with its licence texts.
# Usage: tests/geoip/check_installer.sh   (from the repository root)
set -euo pipefail

iss=setup/scripts/main.iss
fail() { echo "FAIL $*"; exit 1; }

expect_source() {   # source path (as main.iss writes it), installed name
	grep -q -F "Source: \"$1\"; DestDir: \"{app}\"; DestName: \"$2\";" "$iss" \
		|| fail "$iss does not install $1 as {app}\\$2"
	[ -f "${1//\\//}" ] || fail "$1 does not exist"
}

grep -q -F 'Source: "GeoIP\GeoIP.dat"; DestDir: "{app}";' "$iss" || fail "$iss does not install GeoIP.dat"
expect_source 'setup\misc\LICENSE-GeoIP.txt' 'LICENSE-GeoIP.txt'
expect_source 'GeoIP\License.txt' 'LICENSE-GeoIP-LGPL-2.1.txt'

licence=setup/misc/LICENSE-GeoIP.txt
for text in 'https://creativecommons.org/licenses/by/4.0/' 'Eris Networks S.A.S' \
	'LICENSE-GeoIP-LGPL-2.1.txt' 'Internet Systems Consortium'; do
	grep -q -F "$text" "$licence" || fail "$licence does not mention '$text'"
done
echo "PASS the installer ships GeoIP.dat with its licence texts"
