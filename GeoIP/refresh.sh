#!/usr/bin/env bash
# Refreshes GeoIP/GeoIP.dat from Debian's geoip-database package (DB-IP's country data in the
# legacy GeoIP format) and records where it came from in GeoIP/SOURCE.txt.
#
# Usage: bash GeoIP/refresh.sh            (from the repository root)
# Environment:
#   KEYRING  Debian archive keyring (default /usr/share/keyrings/debian-archive-keyring.gpg,
#            from the debian-archive-keyring package)
#   MIRROR   Debian mirror (default https://deb.debian.org/debian)
#
# Trust chain: InRelease signed by a Debian archive key -> SHA-256 of Packages.xz listed in the
# signed text -> SHA-256 of the .deb listed in Packages -> lookup test on the extracted file.
# Nothing in GeoIP/ is written until every step has passed.
#
# Prints "updated <version>" or "current <version>" and exits 0; any failure exits non-zero.
set -euo pipefail

KEYRING="${KEYRING:-/usr/share/keyrings/debian-archive-keyring.gpg}"
MIRROR="${MIRROR:-https://deb.debian.org/debian}"
SUITE=sid
PACKAGES_PATH=main/binary-all/Packages.xz

die() { echo "refresh: $*" >&2; exit 1; }

[ -f GeoIP/GeoIP.c ] && [ -f tests/geoip/test_geoip.c ] || die "run from the repository root"
[ -f "$KEYRING" ] || die "keyring not found: $KEYRING"

work="$(mktemp -d)"
trap 'rm -rf "${work:?}"' EXIT
mkdir "$work/release" "$work/packages" "$work/deb" "$work/extract" "$work/build"

fetch() { curl -sfL --retry 3 "$1" -o "$2" || die "download failed: $1"; }

# 1. InRelease, accepted as apt would: one clearsigned message and nothing else; at least one
#    good signature by a key in the keyring; every other signature only by a key the keyring
#    does not hold (sid carries a second signature Ubuntu's keyring may lack, which makes gpgv's
#    exit status non-zero, so the status lines are read instead); and not past its Valid-Until.
fetch "$MIRROR/dists/$SUITE/InRelease" "$work/release/InRelease"
release="$work/release/InRelease"
if [ "$(head -n1 "$release")" != "-----BEGIN PGP SIGNED MESSAGE-----" ] \
	|| [ "$(grep -c -- '-----BEGIN PGP SIGNED MESSAGE-----' "$release")" -ne 1 ] \
	|| [ "$(grep -c -- '-----BEGIN PGP SIGNATURE-----' "$release")" -ne 1 ] \
	|| [ "$(grep -c -- '-----END PGP SIGNATURE-----' "$release")" -ne 1 ] \
	|| [ "$(tail -n1 "$release")" != "-----END PGP SIGNATURE-----" ]; then
	die "InRelease is not a single clearsigned message"
fi
gpgv --keyring "$KEYRING" --status-fd 3 --output "$work/release/signed.txt" \
	"$release" 3>"$work/release/status" >/dev/null 2>&1 || true
status="$work/release/status"
count() { grep -c "^\[GNUPG:\] $1\b" "$status" || true; }
if grep -q -E '^\[GNUPG:\] (BADSIG|EXPSIG|EXPKEYSIG|REVKEYSIG|ERROR|FAILURE|NODATA)\b' "$status" \
	|| awk '$2 == "ERRSIG" && $8 != 9 { found = 1 } END { exit !found }' "$status" \
	|| [ "$(count VALIDSIG)" -lt 1 ] \
	|| [ "$(count NEWSIG)" -ne $(( $(count VALIDSIG) + $(count NO_PUBKEY) )) ]; then
	die "InRelease signature not valid"
fi
signer="$(awk '$2 == "VALIDSIG" { print $3; exit }' "$status")"
valid_until="$(sed -n 's/^Valid-Until: //p' "$work/release/signed.txt")"
[ -n "$valid_until" ] || die "InRelease has no Valid-Until"
until_epoch="$(date -u -d "$valid_until" +%s 2>/dev/null)" || die "InRelease Valid-Until unreadable: $valid_until"
[ "$(date -u +%s)" -le "$until_epoch" ] || die "InRelease expired at $valid_until"

# 2. Packages.xz, checked against the SHA256 section of the signed text.
expected="$(awk -v path="$PACKAGES_PATH" '
	/^SHA256:/ { in_sha = 1; next }
	/^[^ ]/    { in_sha = 0 }
	in_sha && $3 == path { print $1; exit }' "$work/release/signed.txt")"
[ -n "$expected" ] || die "InRelease lists no SHA-256 for $PACKAGES_PATH"
fetch "$MIRROR/dists/$SUITE/$PACKAGES_PATH" "$work/packages/Packages.xz"
[ "$(sha256sum "$work/packages/Packages.xz" | cut -d' ' -f1)" = "$expected" ] \
	|| die "Packages.xz SHA-256 does not match InRelease"

stanza="$(xz -dc "$work/packages/Packages.xz" \
	| awk '/^Package: geoip-database$/ { p = 1 } p && /^$/ { p = 0; done = 1 } p && !done')"
version="$(sed -n 's/^Version: //p' <<<"$stanza")"
filename="$(sed -n 's/^Filename: //p' <<<"$stanza")"
deb_sha256="$(sed -n 's/^SHA256: //p' <<<"$stanza")"
[ -n "$version" ] && [ -n "$filename" ] && [[ "$deb_sha256" =~ ^[0-9a-f]{64}$ ]] \
	|| die "Packages has no complete geoip-database entry"

recorded="$(sed -n 's/^version: //p' GeoIP/SOURCE.txt 2>/dev/null || true)"
if [ -n "$recorded" ]; then
	if dpkg --compare-versions "$version" eq "$recorded"; then
		echo "current $version"
		exit 0
	fi
	dpkg --compare-versions "$version" gt "$recorded" \
		|| die "mirror offers geoip-database $version, older than the recorded $recorded"
fi

# 3. The .deb, checked against Packages, then extracted into an empty directory.
fetch "$MIRROR/$filename" "$work/deb/package.deb"
[ "$(sha256sum "$work/deb/package.deb" | cut -d' ' -f1)" = "$deb_sha256" ] \
	|| die ".deb SHA-256 does not match Packages"
dpkg-deb -x "$work/deb/package.deb" "$work/extract"
dat="$work/extract/usr/share/GeoIP/GeoIP.dat"
[ -f "$dat" ] || die "the package holds no usr/share/GeoIP/GeoIP.dat"

# 4. The lookup test, built from the bundled library.
gcc -std=gnu99 -Wall -DPACKAGE_VERSION='"1.6.12"' -DGEOIPDATADIR='"/tmp"' -I GeoIP \
	-o "$work/build/test_geoip" tests/geoip/test_geoip.c GeoIP/GeoIP.c GeoIP/GeoIPCity.c \
	GeoIP/GeoIP_deprecated.c GeoIP/regionName.c GeoIP/timeZone.c 2>"$work/build/gcc.log" \
	|| { cat "$work/build/gcc.log" >&2; die "lookup test did not build"; }
"$work/build/test_geoip" "$dat" >&2 || die "lookup test failed on $version"

build="$(strings -n 8 "$dat" | grep -m1 '^GEO-' || true)"
[ -n "$build" ] || die "no build string in GeoIP.dat"

# 5. Every check passed: write the file and its record.
cp "$dat" GeoIP/GeoIP.dat
cat >GeoIP/SOURCE.txt <<EOF_SOURCE
package: geoip-database
version: $version
suite: $SUITE
deb-sha256: $deb_sha256
file: GeoIP.dat
file-sha256: $(sha256sum GeoIP/GeoIP.dat | cut -d' ' -f1)
build: $build
inrelease-signer: $signer
verified: $(date -u +%F)
EOF_SOURCE
echo "updated $version"
