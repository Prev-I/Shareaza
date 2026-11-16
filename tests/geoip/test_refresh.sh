#!/usr/bin/env bash
# Tests GeoIP/refresh.sh against a local copy of the Debian archive.
#
# Usage: tests/geoip/test_refresh.sh            (from the repository root)
# Environment: KEYRING (as for refresh.sh), MIRROR_SOURCE (default https://deb.debian.org/debian).
#
# The real InRelease, Packages.xz and geoip-database .deb are fetched once, then served from a
# local directory, tampered with one at a time. Each case runs refresh.sh in a scratch copy of
# GeoIP/ and tests/geoip/, never in the caller's tree.
set -euo pipefail

root="$(pwd)"
source_mirror="${MIRROR_SOURCE:-https://deb.debian.org/debian}"
work="$(mktemp -d)"
server_pid=""
cleanup() { [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null; rm -rf "${work:?}"; }
trap cleanup EXIT

failures=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; failures=$((failures + 1)); }

# --- fetch the real files once ---------------------------------------------------------------
pristine="$work/pristine"
mkdir -p "$pristine/dists/sid/main/binary-all"
curl -sfL "$source_mirror/dists/sid/InRelease" -o "$pristine/dists/sid/InRelease"
curl -sfL "$source_mirror/dists/sid/main/binary-all/Packages.xz" -o "$pristine/dists/sid/main/binary-all/Packages.xz"
stanza="$(xz -dc "$pristine/dists/sid/main/binary-all/Packages.xz" | awk '/^Package: geoip-database$/{p=1} p&&/^$/{p=0; done=1} p&&!done')"
filename="$(sed -n 's/^Filename: //p' <<<"$stanza")"
version="$(sed -n 's/^Version: //p' <<<"$stanza")"
mkdir -p "$pristine/$(dirname "$filename")"
curl -sfL "$source_mirror/$filename" -o "$pristine/$filename"

# --- serve a mirror directory ------------------------------------------------------------------
mirror="$work/mirror"
port="$(python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
mkdir -p "$mirror"
python3 -I -m http.server "$port" --bind 127.0.0.1 --directory "$mirror" >/dev/null 2>&1 &
server_pid=$!
for _ in $(seq 50); do curl -sf "http://127.0.0.1:$port/" >/dev/null && break; sleep 0.1; done

reset_mirror() { rm -rf "${mirror:?}"/*; cp -a "$pristine"/. "$mirror"/; }

# --- a scratch copy of the files refresh.sh reads and writes -----------------------------------
scratch="$work/repo"
new_scratch() {
	rm -rf "${scratch:?}"; mkdir -p "$scratch/tests"
	cp -a "$root/GeoIP" "$scratch/GeoIP"
	cp -a "$root/tests/geoip" "$scratch/tests/geoip"
	# Without a record every case reaches the .deb; the repository's own record may already
	# name the newest version, which would stop refresh.sh before the step under test.
	rm -f "$scratch/GeoIP/SOURCE.txt"
}
digest() { (cd "$scratch" && find GeoIP -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum); }

run_refresh() {   # prints refresh.sh's output to $work/out, returns its exit status
	(cd "$scratch" && MIRROR="http://127.0.0.1:$port" KEYRING="${CASE_KEYRING:-${KEYRING:-/usr/share/keyrings/debian-archive-keyring.gpg}}" \
		bash GeoIP/refresh.sh) >"$work/out" 2>&1
}

# --- a throwaway signing key, to build InRelease files Debian never signed ------------------------
export GNUPGHOME="$work/gnupg"
mkdir -m 700 "$GNUPGHOME"
gpg_test() { gpg --batch --quiet --pinentry-mode loopback --passphrase '' "$@" 2>/dev/null; }
gpg_test --quick-gen-key 'GeoIP refresh test <test@invalid>' ed25519 sign 1d
gpg_test --faked-system-time '20200101T000000!' --quick-gen-key 'GeoIP refresh expired <expired@invalid>' ed25519 sign 1d
gpg_test --export 'test@invalid' >"$work/test-keyring.gpg"
gpg_test --export 'expired@invalid' >"$work/expired-keyring.gpg"
# The real InRelease's signed text, with sed expression $2 applied, clearsigned by key $1.
resign() {   # key uid, sed expression, [extra gpg options]
	# Only the text is wanted here; gpgv exits 2 on sid's second, unknown-key signature.
	{ gpgv --keyring "${KEYRING:-/usr/share/keyrings/debian-archive-keyring.gpg}" --output - \
		"$pristine/dists/sid/InRelease" 2>/dev/null || true; } | sed -e "$2" >"$work/signed.txt"
	gpg_test "${@:3}" --local-user "$1" --clearsign --output - "$work/signed.txt" \
		>"$mirror/dists/sid/InRelease"
}

expect_refused() {   # case name, pattern the refusal message must match
	local before; before="$(digest)"
	if run_refresh; then fail "$1: refresh.sh succeeded"; return; fi
	if ! grep -q -E "$2" "$work/out"; then fail "$1: refused for another reason: $(tr '\n' ' ' <"$work/out")"; return; fi
	[ "$(digest)" = "$before" ] && pass "$1: refused, GeoIP/ unchanged" || fail "$1: GeoIP/ changed"
}

# Case 1: InRelease whose signed text was altered.
reset_mirror; new_scratch
sed -i '0,/^Suite: /s/^Suite: .*/Suite: tampered/' "$mirror/dists/sid/InRelease"
expect_refused "tampered InRelease" "^refresh: InRelease signature"

# Case 2: Packages.xz that does not match InRelease.
reset_mirror; new_scratch
printf 'Package: geoip-database\nVersion: 99\n\n' | xz -c >"$mirror/dists/sid/main/binary-all/Packages.xz"
expect_refused "Packages.xz hash mismatch" "^refresh: Packages.xz SHA-256"

# Case 3: .deb that does not match Packages.
reset_mirror; new_scratch
printf 'x' >>"$mirror/$filename"
expect_refused ".deb hash mismatch" "^refresh: .deb SHA-256"

# Case 3a: InRelease signed only by a key the keyring does not hold.
reset_mirror; new_scratch
CASE_KEYRING="$work/test-keyring.gpg" expect_refused "InRelease from an unknown key" "^refresh: InRelease signature"

# Case 3b: InRelease signed by a key that has expired.
reset_mirror; new_scratch
resign 'expired@invalid' 's/^Suite: /Suite: /' --faked-system-time '20200101T120000!'
CASE_KEYRING="$work/expired-keyring.gpg" expect_refused "InRelease from an expired key" "^refresh: InRelease signature"

# Case 3c: InRelease whose Valid-Until has passed.
reset_mirror; new_scratch
resign 'test@invalid' 's/^Valid-Until: .*/Valid-Until: Sat, 01 Jan 2022 00:00:00 UTC/'
CASE_KEYRING="$work/test-keyring.gpg" expect_refused "expired InRelease" "^refresh: InRelease expired"

# Case 3d: text outside the clearsigned message.
reset_mirror; new_scratch
resign 'test@invalid' 's/^Suite: /Suite: /'
printf 'Suite: unsigned\n' >>"$mirror/dists/sid/InRelease"
CASE_KEYRING="$work/test-keyring.gpg" expect_refused "text outside the signature" "^refresh: InRelease is not a single clearsigned message"

# Case 3e: the mirror offers an older version than the one recorded.
reset_mirror; new_scratch
printf 'package: geoip-database\nversion: 99999999-1\n' >"$scratch/GeoIP/SOURCE.txt"
expect_refused "older version offered" "^refresh: mirror offers geoip-database .* older than the recorded 99999999-1"

# Case 4: the recorded version is already the newest.
reset_mirror; new_scratch
printf 'package: geoip-database\nversion: %s\n' "$version" >"$scratch/GeoIP/SOURCE.txt"
before="$(digest)"
if run_refresh && grep -q "^current $version\$" "$work/out" && [ "$(digest)" = "$before" ]; then
	pass "current version: nothing changed"
else
	fail "current version: $(tr '\n' ' ' <"$work/out")"
fi

# Case 5: a newer version is fetched, checked and recorded.
reset_mirror; new_scratch
if run_refresh && grep -q "^updated $version\$" "$work/out" && bash "$root/tests/geoip/check_source.sh" "$scratch" >/dev/null; then
	pass "update: GeoIP.dat and SOURCE.txt written and consistent"
else
	fail "update: $(tr '\n' ' ' <"$work/out")"
fi

if [ "$failures" -ne 0 ]; then echo "$failures case(s) failed"; exit 1; fi
echo "PASS all refresh cases"
