#!/usr/bin/env bash
# Checks that GeoIP/GeoIP.dat is the file GeoIP/SOURCE.txt describes.
# Usage: tests/geoip/check_source.sh [repository root]   (default: current directory)
set -euo pipefail

root="${1:-.}"
source_txt="$root/GeoIP/SOURCE.txt"
dat="$root/GeoIP/GeoIP.dat"
keys=(package version suite deb-sha256 file file-sha256 build inrelease-signer verified)

fail() { echo "FAIL $*"; exit 1; }

[ -f "$source_txt" ] || fail "missing $source_txt"
[ -f "$dat" ] || fail "missing $dat"

mapfile -t found < <(sed -n 's/^\([a-z0-9-]*\): .*/\1/p' "$source_txt")
[ "${found[*]}" = "${keys[*]}" ] || fail "SOURCE.txt keys are '${found[*]}', expected '${keys[*]}'"

value() { sed -n "s/^$1: //p" "$source_txt"; }

[ "$(value package)" = "geoip-database" ] || fail "package is not geoip-database"
[ "$(value file)" = "GeoIP.dat" ] || fail "file is not GeoIP.dat"
[[ "$(value deb-sha256)" =~ ^[0-9a-f]{64}$ ]] || fail "deb-sha256 is not a SHA-256"
[[ "$(value inrelease-signer)" =~ ^[0-9A-F]{40}$ ]] || fail "inrelease-signer is not a fingerprint"
actual="$(sha256sum "$dat" | cut -d' ' -f1)"
[ "$(value file-sha256)" = "$actual" ] || fail "GeoIP.dat SHA-256 is $actual, SOURCE.txt says $(value file-sha256)"
grep -a -q -F "$(value build)" "$dat" || fail "GeoIP.dat does not contain the build string '$(value build)'"

echo "PASS SOURCE.txt describes GeoIP.dat ($(value version))"
