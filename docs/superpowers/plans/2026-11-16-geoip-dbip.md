# Current country data (DB-IP via Debian, libGeoIP 1.6.12) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the 2017 `GeoIP/GeoIP.dat` with Debian's current DB-IP build, read by libGeoIP 1.6.12, with a verified refresh and a lookup test.

**Architecture:** The bundled C library in `GeoIP/` becomes upstream 1.6.12, unmodified; `geoip.dll`'s exports and the client stay as they are. A shell script fetches Debian's signed `geoip-database` package, verifies it, extracts `GeoIP.dat`, runs a C lookup test and records provenance in `GeoIP/SOURCE.txt`; a manual workflow runs it and pushes a branch.

**Tech Stack:** C (MSVC v143 for the DLL, gcc for the test), Bash, gpgv, dpkg-deb, GitHub Actions, Inno Setup (unchanged).

**Spec:** `docs/superpowers/specs/2026-11-15-geoip-dbip-design.md`

## Global Constraints

- IPv4 only. `GeoIPv6.dat` is not shipped; no client code changes (`shareaza/` untouched except the About line in `Shareaza.rc`).
- Library sources are byte-identical to `maxmind/geoip-api-c` tag `v1.6.12`, commit `4b526e7331ca1d692b74a0509ddcc725622ed31a`, directory `libGeoIP/`. Windows needs go in the vcxproj.
- Data: Debian `sid`, package `geoip-database`, verified via `InRelease` signature (`gpgv`, Debian archive keyring) → `Packages.xz` SHA-256 → `.deb` SHA-256.
- The client never contacts a geolocation service.
- About line, exact text (ASCII): `IP geolocation by DB-IP (db-ip.com), CC BY 4.0, converted to GeoIP format by Debian.`
- `Shareaza.rc` stays CP-1252. Windows runners stay `windows-2022`.
- Fork rules: PR into `main` with `gh pr create --repo Prev-I/Shareaza`; once a PR is handed over, push nothing more to it. Conventional commits.
- Downloaded archives are untrusted: extract each into its own new empty directory; scripts live elsewhere.

## Review Focus

1. **A GeoIP id outside the 1.6.12 table** (a future Debian build with a new code): the lookup test must fail the refresh, not ship it. Covered by Task 2's walk (`id <= 0 || id > 254` among countries fails, except 0 for unassigned).
2. **A tampered or mismatched download** (bad signature, wrong `Packages.xz` hash, wrong `.deb` hash): `refresh.sh` must exit non-zero and leave `GeoIP/` untouched. Task 3, Step 1 tests each with a corrupted input.
3. **The DLL loses its exports** (1.6.12's `GEOIP_API` is empty unless `GEOIP_EXPORTS` is defined): the client would load the DLL and silently get no countries. Task 1 checks the export table of the built DLL.
4. **Reserved and private addresses** (127.0.0.1, 10.x, 192.168.x, 0.0.0.1, 255.255.255.255) must return no country (NULL), as today. Task 2 asserts them.
5. **Re-running the refresh with nothing new** must change nothing and exit 0. Task 3, Step 1 asserts it.

---

### Task 1: Library 1.6.12 in `GeoIP/`

**Files:**
- Replace: `GeoIP/GeoIP.c`, `GeoIP/GeoIP.h`
- Create: `GeoIP/GeoIP_internal.h`, `GeoIP/GeoIPCity.c`, `GeoIP/GeoIPCity.h`, `GeoIP/GeoIP_deprecated.c`, `GeoIP/regionName.c`, `GeoIP/timeZone.c`, `GeoIP/pread.c`, `GeoIP/pread.h`, `GeoIP/README.md`
- Replace: `GeoIP/License.txt` (upstream `COPYING`, verbatim)
- Modify: `GeoIP/GeoIP_143.vcxproj`, `GeoIP/GeoIP_143.vcxproj.filters`, `GeoIP/GeoIP.rc`

**Interfaces:**
- Produces: `geoip.dll` exporting at least `GeoIP_new`, `GeoIP_cleanup`, `GeoIP_delete`, `GeoIP_country_code_by_ipnum`, `GeoIP_country_name_by_ipnum`, `GeoIP_country_code_by_ipnum_v6`, `GeoIP_country_name_by_ipnum_v6` (the names `Shareaza.cpp:1616-1622` resolves). Task 2 compiles the same `.c` files with gcc.

- [ ] **Step 1: Fetch the sources at the pinned commit**

Run (outside the repo, in a new empty directory):
`git clone --depth 1 --branch v1.6.12 https://github.com/maxmind/geoip-api-c /tmp/geoip-1.6.12 && git -C /tmp/geoip-1.6.12 rev-parse HEAD`
Expected: `4b526e7331ca1d692b74a0509ddcc725622ed31a`. Copy the ten `libGeoIP/` files listed above into `GeoIP/`, and `COPYING` over `GeoIP/License.txt`. `diff` each copied file against the clone: no output.

- [ ] **Step 2: Update the project**

`GeoIP_143.vcxproj`, all four configurations: add `GEOIP_EXPORTS` and `PACKAGE_VERSION="1.6.12"` to `PreprocessorDefinitions` (keep `ws2_32.lib`; keep the post-build `xcopy` of `GeoIP.dat`). `ClCompile`: the six `.c` files; `ClInclude`: the four headers plus `resource.h`; the same in `.filters`. `GEOIPDATADIR` is not needed on `_WIN32`. Fix MSVC warnings by project settings (e.g. disable a specific warning for this project), never by editing sources.

- [ ] **Step 3: Version resource**

`GeoIP.rc`: `FILEVERSION 1,6,12,0`, `"FileVersion", "1.6.12.0"`, `"LegalCopyright", "Copyright (C) 2002-2018 MaxMind LLC"`. Leave `PRODUCTVERSION`/`ProductName` as they are. Keep the file's existing code page and encoding.

- [ ] **Step 4: `GeoIP/README.md`**

States: upstream repository and tag, the commit hash above, that the sources are unmodified, licence LGPL 2.1 (`License.txt`), and that `GeoIP.dat` and `SOURCE.txt` are refreshed by `refresh.sh` (Task 3). Delete `GeoIP/HowToUpdate.txt`.

- [ ] **Step 5: Linux smoke build**

Run: `gcc -w -DGEOIP_EXPORTS -DPACKAGE_VERSION='"1.6.12"' -DGEOIPDATADIR='"/tmp"' -I GeoIP -c GeoIP/GeoIP.c GeoIP/GeoIPCity.c GeoIP/GeoIP_deprecated.c GeoIP/regionName.c GeoIP/timeZone.c -o /dev/null` per file (or into `/tmp`).
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add GeoIP
git commit -m "feat: update the bundled GeoIP library to 1.6.12"
```

- [ ] **Step 7: Windows build and export check**

Push the branch and run `gh workflow run msbuild.yml --repo Prev-I/Shareaza --ref prev-i/geoip-dbip`. Expected: all four legs green. Then dispatch `release.yml` the same way, download its x64 artifact, and list `geoip.dll`'s exports (`objdump -p` or `llvm-objdump --private-headers` on Linux). Expected: the seven names above are present. If a leg fails, fix in the project settings and repeat.

---

### Task 2: Lookup test

**Files:**
- Create: `tests/geoip/test_geoip.c`
- Create: `.github/workflows/geoip-test.yml`

**Interfaces:**
- Consumes: Task 1's sources in `GeoIP/`.
- Produces: the build-and-run command `gcc -std=c99 -Wall -DPACKAGE_VERSION='"1.6.12"' -DGEOIPDATADIR='"/tmp"' -I GeoIP -o /tmp/test_geoip tests/geoip/test_geoip.c GeoIP/GeoIP.c GeoIP/GeoIPCity.c GeoIP/GeoIP_deprecated.c GeoIP/regionName.c GeoIP/timeZone.c && /tmp/test_geoip <path-to-GeoIP.dat>`; exit 0 = pass, non-zero with one line per failure. Task 3 runs exactly this.

- [ ] **Step 1: Write the test**

`int main(int argc, char **argv)`: opens `argv[1]` with `GeoIP_open(path, GEOIP_MEMORY_CACHE)`, then:
- `GeoIP_database_edition(gi) == GEOIP_COUNTRY_EDITION` (1).
- **Walk:** for `ip` from 0 to 0xFFFFFFFF, `GeoIP_id_by_ipnum_gl(gi, ip, &gl)`; step by `1 << (32 - gl.netmask)`, and by `1 << 24` when `gl.netmask` is 0 (Debian's file returns netmask 0 at 0.0.0.0). Fail if any id is `< 0` or `> 254`; record whether id 254 occurs. Fail if no range returns 254, and check `GeoIP_code_by_id(254)` is `"SS"`.
- **Fixed addresses** (each with a comment giving the reason):

```c
{ "193.0.6.139",   "NL" }, /* RIPE NCC's own network, Amsterdam */
{ "202.12.29.205", "AU" }, /* APNIC's own network, Brisbane */
{ "199.212.0.46",  "US" }, /* ARIN's own network */
{ "151.1.1.1",     "IT" }, /* Wind Tre, Italian ISP */
```

- **No country:** `127.0.0.1`, `10.1.2.3`, `192.168.178.88`, `0.0.0.1`, `255.255.255.255` each return NULL from `GeoIP_country_code_by_addr`.
- Print `PASS <n> checks` on success.

- [ ] **Step 2: Run it against the current (2017) data to see it fail**

Run: the Task 2 command with `GeoIP/GeoIP.dat`.
Expected: FAIL, at least "no range returns SS (254)" (the 2017 file predates the code in its table). Note the other results in the commit message body.

- [ ] **Step 3: Workflow `geoip-test.yml`**

Copy the shape of `release-notes-test.yml` (same pinned `actions/checkout`, `persist-credentials: false`, `permissions: contents: read`, `ubuntu-latest`). Paths: `GeoIP/**`, `tests/geoip/**`, `.github/workflows/geoip-test.yml`, on `pull_request` and on `push` to `main`. One step: the Task 2 command on `GeoIP/GeoIP.dat`.

- [ ] **Step 4: Commit** (the test is red until Task 3 lands; say so in the body)

```bash
git add tests/geoip .github/workflows/geoip-test.yml
git commit -m "test: check the bundled GeoIP database with a lookup test"
```

---

### Task 3: Refresh script, workflow and the new data

**Files:**
- Create: `GeoIP/refresh.sh`, `GeoIP/SOURCE.txt`, `.github/workflows/geoip-refresh.yml`, `tests/geoip/test_refresh.sh`
- Replace: `GeoIP/GeoIP.dat`

**Interfaces:**
- Consumes: Task 2's command.
- Produces: `GeoIP/refresh.sh` (run from the repo root, no arguments). Environment: `KEYRING` (default `/usr/share/keyrings/debian-archive-keyring.gpg`), `MIRROR` (default `https://deb.debian.org/debian`). Exit 0 and prints `updated <version>` or `current <version>`; any verification failure exits non-zero and leaves `GeoIP/` unchanged. `SOURCE.txt` format, one `key: value` per line, in this order:

```
package: geoip-database
version: 20261101-1
suite: sid
deb-sha256: <64 hex>
file: GeoIP.dat
file-sha256: <64 hex>
build: GEO-106FREE 20261110 Build
inrelease-signer: <40-hex fingerprint from gpgv VALIDSIG>
verified: <YYYY-MM-DD UTC>
```

- [ ] **Step 1: Write `tests/geoip/test_refresh.sh`**

Runs `refresh.sh` against a local `MIRROR` (a directory served by `python3 -m http.server`, built from the real files) to assert:
- a corrupted `InRelease` signature → non-zero, `git diff --quiet GeoIP` true;
- a `Packages.xz` whose hash differs from `InRelease` → non-zero, `GeoIP` unchanged;
- a `.deb` whose hash differs from `Packages` → non-zero, `GeoIP` unchanged;
- a run whose version equals `SOURCE.txt`'s → exit 0, prints `current`, `GeoIP` unchanged.

Runs in a temporary copy of the repo (`git worktree add` to `/tmp`), never in the caller's tree.

- [ ] **Step 2: Run it to see it fail**

Run: `bash tests/geoip/test_refresh.sh`. Expected: FAIL, `GeoIP/refresh.sh` not found.

- [ ] **Step 3: Write `GeoIP/refresh.sh`**

`set -euo pipefail`; work in `mktemp -d`, removed on exit; each download into its own empty subdirectory. Steps, in order: fetch `$MIRROR/dists/sid/InRelease`; `gpgv --keyring "$KEYRING" --status-fd 1 --output InRelease.txt InRelease` and take the fingerprint from `[GNUPG:] VALIDSIG`; take the SHA-256 of `main/binary-all/Packages.xz` from the `SHA256:` section of `InRelease.txt`, fetch and check it; from the `Package: geoip-database` stanza take `Version`, `Filename`, `SHA256`; if `Version` equals `SOURCE.txt`'s `version`, print `current <version>` and exit 0; fetch `$MIRROR/<Filename>`, check its SHA-256; `dpkg-deb -x` into an empty directory; run Task 2's command on `usr/share/GeoIP/GeoIP.dat`; read the build string with the test binary or `strings`; only then copy the file to `GeoIP/GeoIP.dat`, write `SOURCE.txt`, print `updated <version>`.

- [ ] **Step 4: Run the script tests**

Run: `bash tests/geoip/test_refresh.sh`. Expected: PASS. Locally, without the Ubuntu keyring package installed: `apt download debian-archive-keyring` into a new empty directory, `dpkg-deb -x` it, and point `KEYRING` at the extracted `.gpg`.

- [ ] **Step 5: Refresh the data for real**

Run: `bash GeoIP/refresh.sh` from the repo root. Expected: `updated <version>` (20261101-1 or newer). Then the Task 2 command on `GeoIP/GeoIP.dat`: `PASS`. `GeoIP/SOURCE.txt` is complete.

- [ ] **Step 6: Workflow `geoip-refresh.yml`**

`workflow_dispatch` only; `ubuntu-latest`; top-level `permissions: contents: read`, the job `contents: write`. Steps: pinned `actions/checkout` (as in Task 2); `sudo apt-get install -y debian-archive-keyring`; `bash GeoIP/refresh.sh`; if it printed `updated <v>`: create branch `prev-i/geoip-<v>`, commit `GeoIP/GeoIP.dat` and `GeoIP/SOURCE.txt` as `github-actions[bot]` with message `chore: refresh GeoIP country data to Debian geoip-database <v>`, push, and write to the job summary that the owner should open the pull request from that branch. If it printed `current <v>`, write that to the summary and stop. Also run `bash tests/geoip/test_refresh.sh` in `geoip-test.yml` (add `GeoIP/refresh.sh` to its paths).

- [ ] **Step 7: Commit**

```bash
git add GeoIP/refresh.sh GeoIP/SOURCE.txt GeoIP/GeoIP.dat tests/geoip/test_refresh.sh .github/workflows/geoip-refresh.yml .github/workflows/geoip-test.yml
git commit -m "feat: ship current country data from Debian's DB-IP build, with a verified refresh"
```

---

### Task 4: Attribution and documentation

**Files:**
- Modify: `shareaza/Shareaza.rc` (`IDD_ABOUT`, the MaxMind `LTEXT`)
- Replace: `setup/misc/LICENSE-GeoIP.txt`
- Modify: `README.md` (§ History and credits), `docs/RELEASING.md` (§ Releasing)

**Interfaces:**
- Consumes: `GeoIP/SOURCE.txt` (Task 3) for the attribution details.

- [ ] **Step 1: Check PR #47**

Run: `gh pr view 47 --repo Prev-I/Shareaza --json state`. If `MERGED`: `git fetch origin && git rebase origin/main` first. If still open: edit only the line's text where it stands today; the rebase after #47 merges resolves the position.

- [ ] **Step 2: About line**

Replace the `LTEXT` string `"This product includes GeoLite data created by MaxMind, available from http://maxmind.com/"` with the exact text from Global Constraints; keep its control id and rectangle. Check: `python3 -c "open('shareaza/Shareaza.rc','rb').read().decode('cp1252')"` succeeds and `git diff shareaza/Shareaza.rc` shows only that line changed (byte-level; no re-encoding).

- [ ] **Step 3: `setup/misc/LICENSE-GeoIP.txt`**

Two parts: (1) the GeoIP C library, MaxMind, LGPL 2.1, see `GeoIP/License.txt`; (2) the country data: "IP geolocation by DB-IP (https://db-ip.com), Copyright 2014-2026 Eris Networks S.A.S / DB-IP, licensed under CC BY 4.0, https://creativecommons.org/licenses/by/4.0/. Converted to the GeoIP legacy format by Debian's geoip-database package; not modified since. Source and version: GeoIP/SOURCE.txt." Drop the MaxMind GeoLite and APNIC/ARIN/RIPE text.

- [ ] **Step 4: README and RELEASING**

`README.md` § History and credits: one bullet for DB-IP (country data, CC BY 4.0) and Debian's `geoip-database` (conversion). `docs/RELEASING.md` § Releasing: a new step 0 before tagging: run `geoip-refresh.yml`; if it pushed a branch, open the PR from it and merge it before tagging; if it says current, nothing to do. The release notes mention new country data only when the release carries a refresh.

- [ ] **Step 5: Commit**

```bash
git add shareaza/Shareaza.rc setup/misc/LICENSE-GeoIP.txt README.md docs/RELEASING.md
git commit -m "docs: credit DB-IP and Debian for the country data"
```

---

### Task 5: Evidence and pull request

- [ ] **Step 1: Rebase if #47 has merged** (as Task 4, Step 1), then re-run the Task 2 command and `bash tests/geoip/test_refresh.sh`: PASS.
- [ ] **Step 2: CI on the branch.** Push; dispatch `msbuild.yml` and `release.yml` on the branch; then `oracle-windows.yml` with `build_run=<release run id>`. Expected: all green. The oracle shows no country the script can read, so state in the PR that the lookup test and the build are the evidence for the data.
- [ ] **Step 3: Review.** Write `git diff origin/main...HEAD -- . ':!GeoIP/GeoIP.dat' > /tmp/geoip-review.diff` and dispatch `reviewer` with that path, the spec and this plan. Fix findings before the PR.
- [ ] **Step 4: Open the PR** with `gh pr create --repo Prev-I/Shareaza --base main`, body following earlier fork PRs: summary, evidence (run ids), what is not covered by CI, and the owner's manual check: Help > About shows the DB-IP line; a few connected hosts show sensible flags. Hand it over; push nothing more to it.
- [ ] **Step 5: After the merge.** Dispatch `geoip-refresh.yml` on `main`. Expected: `current <version>` in the summary, no branch pushed.
