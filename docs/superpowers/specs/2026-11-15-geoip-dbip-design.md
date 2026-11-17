# Current country data: DB-IP via Debian, libGeoIP 1.6.12: design

Date: 2026-11-15. Status: approved by the owner on 2026-11-16, for previ.10. The data source (DB-IP, taken from
Debian's `geoip-database` package), the library update to 1.6.12 and the IPv4-only scope were
decided by the owner; items marked *(designer's call)* were settled while writing.

## Intent

The owner saw the client show the wrong country for some addresses. The client ships
`GeoIP/GeoIP.dat` with the build string `GEO-106FREE 20170905 Build 1`: MaxMind's free legacy
country database of 5 September 2017, last updated in 3130ad34c (2017-09-16). IPv4 blocks have
been sold and moved between countries since then, so stale entries show the wrong flag and name,
and `IsIgnoredCountry` (`Security.h:112`, `HostCache.cpp:478`) blocks or admits hosts by that
stale country.

MaxMind stopped publishing the legacy format on 2019-01-02, so `GeoIP/HowToUpdate.txt` cannot
produce a newer file. Debian's `geoip-database` package has been rebuilt from DB-IP's free
country database every month since July 2026, in the same legacy format.

## Goals

- Ship current IPv4 country data, taken from Debian's `geoip-database`.
- Replace the bundled libGeoIP 1.4.8 with 1.6.12, the version Debian builds its files with, so
  the file and the reader share one country table.
- Make the refresh repeatable, verified and reviewed: one workflow run before each release.
- Credit the data as CC BY 4.0 requires.

## Non-goals

- IPv6 country data (owner, 2026-11-15). Debian's `GeoIPv6.dat` is not shipped, and the
  client's IPv6 lookups keep returning an empty string, as they do today. A later change may add
  it together with flags for IPv6 peers.
- Any change to client code. The client's `LoadCountry`, lookups and their callers stay as they
  are.
- MMDB or libmaxminddb; city, region or ASN data.
- Correcting DB-IP's own data. Its answers are what the client will show.
- Kosovo (`XK`): neither library version has the code; Kosovo's ranges show whatever Debian's
  converter maps them to.

## Anti-goals

- Anything that makes the client contact a geolocation service. The owner's rule stands: the
  client sends nothing the user did not choose. The data stays a file in the installer.
- A database in the repository whose origin cannot be checked.
- A refresh that reaches a release without a pull request the owner merged.

## Facts established on 2026-11-15

- **Country tables.** 1.6.12's country table extends 1.4.8's (`GeoIP/GeoIP.c:86`): the entries
  1.4.8 has are identical, and 1.6.12 adds two at the end. Debian builds its files against
  1.6.12's table.
- **Debian's file.** `geoip-database` 20261101-1 (sid, built 2026-11-10, `.deb` SHA-256
  `878590767d49e314dee26a99d265e15c63d1468744d8546cd1189ee84bddba30`) holds
  `/usr/share/GeoIP/GeoIP.dat` (3,580,419 bytes, about 1.9 MB compressed, edition 1, country),
  reporting `GEO-106FREE 20261110 Build`. Its `copyright` file names DB-IP, Eris Networks
  S.A.S, as the copyright holder, under CC-BY-4.0.
- **The data uses 1.6.12's table.** Walking every IPv4 range of that file with 1.6.12 finds 245
  distinct ids, all inside the table.
- **1.4.8 is not fit for it.** Its country-code lookup, `GeoIP_country_code_by_ipnum`, has an
  out-of-bounds read (a table index used without a range check). 1.6.12 range-checks it.
- **1.6.12 reads it.** Built locally with gcc, 1.6.12 opens the file and answers sample lookups
  (8.8.8.8 US, 193.0.6.139 NL).
- **Windows path.** 1.6.12's `_GeoIP_full_path_to` still uses the directory of the host EXE on
  `_WIN32` (`GetModuleFileNameA`), as 1.4.8 does, and it already maps `fileno` to `_fileno`
  for MSVC. Every function the client resolves with `GetProcAddress` (`Shareaza.cpp:1616-1622`)
  exists in 1.6.12 with the same signature.
- **Repository.** No branch protection on any branch; one ruleset, `release-tags`, on tags only.
  The default workflow token is read-only and Actions may not open pull requests. A push made
  with `GITHUB_TOKEN` starts no workflows. The repository is about 150 MB.
- **`setup/misc/LICENSE-GeoIP.txt` is not packaged** by the installer; the About dialog's line
  (`Shareaza.rc`, `IDD_ABOUT`) is the only attribution users see.
- **Open PR #47** (`prev-i/about-history`) moves the About dialog's GeoLite line and adds a
  CP-1252 encoding check for `Shareaza.rc`.

## Approaches

- **A. Own converter.** A script in the fork converts DB-IP's CSV into a legacy `.dat` using the
  bundled library's table. Full control, but a few hundred lines to write and keep.
- **B. Debian's file plus libGeoIP 1.6.12 (chosen by the owner).** Take the file from Debian's
  signed archive and update the library so its table matches the one Debian builds with. Little
  new code; the conversion is done and maintained by Debian.
- **B without the library update (rejected).** 1.4.8's table does not match the data, and its
  country-code lookup has the out-of-bounds read above.

Data sources set aside: IP2Location LITE allows redistribution only in its own BIN format;
MaxMind GeoLite2 requires deleting old copies within 30 days and limits disclosure; IPinfo Lite
is CC BY-SA, a share-alike term on a bundled file.

## Design

### 1. Library: libGeoIP 1.6.12

- Replace the C sources in `GeoIP/` with `libGeoIP/` from MaxMind's `geoip-api-c` tag
  `v1.6.12`: `GeoIP.c`, `GeoIP.h`, `GeoIP_internal.h`, `GeoIPCity.c`, `GeoIPCity.h`,
  `GeoIP_deprecated.c`, `regionName.c`, `timeZone.c`, `pread.c`, `pread.h`, unmodified, plus
  upstream's `COPYING` (LGPL 2.1). `GeoIP/README.md` records the tag's commit hash
  *(designer's call: a commit hash is stable, a GitHub archive's bytes are not)*.
- `GeoIP_143.vcxproj` and its filters compile the new file list, for all four configurations.
  Defines that 1.6.12 needs on Windows (such as `PACKAGE_VERSION`) go in the project, not in
  the sources, so the sources stay byte-identical to upstream.
- `GeoIP.rc`: FileVersion and ProductVersion become 1.6.12, so the installer's
  `replacesameversion` replaces the old DLL.
- The DLL keeps its name, `geoip.dll`; the post-build `xcopy` of `GeoIP.dat` stays.

### 2. Data file and its refresh

- `GeoIP/GeoIP.dat` is replaced and stays committed as an ordinary file *(designer's call: about
  1.9 MB of history per refresh in a 150 MB repository; builds stay offline and reproducible from
  the repository)*. Next to it, `GeoIP/SOURCE.txt` records the Debian package name and version,
  the suite, the `.deb` SHA-256, the file's SHA-256, its build string, and the fingerprint of the
  key that signed the `InRelease` it was verified against.
- The refresh logic lives in one script, `GeoIP/refresh.sh`, which runs the same on a runner and
  on a Linux machine *(designer's call)*. It:
  1. downloads `InRelease` for Debian `sid` and accepts it as apt would, against the keyring of
     Ubuntu's `debian-archive-keyring` package *(designer's call: the runner image is already
     trusted to build the whole client; the signer's fingerprint goes into `SOURCE.txt` so review
     sees it)*: one clearsigned message and nothing outside it; at least one good signature;
     any other signature only by a key the keyring lacks (no bad, expired or revoked one); and
     not past its `Valid-Until` *(tightened after the final review, 2026-11-16)*;
  2. takes the `geoip-database` entry from the `Packages` index listed in that `InRelease`, and
     checks the index's and the `.deb`'s SHA-256;
  3. refuses a version older than the recorded one (`dpkg --compare-versions`), then extracts
     `GeoIP.dat` with `dpkg-deb`;
  4. runs the lookup test (§ 3) on it;
  5. writes `GeoIP/GeoIP.dat` and `GeoIP/SOURCE.txt` if the package version differs from the
     one recorded; otherwise it says the data is current and changes nothing.
- A new workflow, `geoip-refresh.yml`, runs by hand (`workflow_dispatch`) before each release
  *(designer's call: users get the data only with a release, so a schedule adds pull requests and
  no value)*. It runs the script and, if the files changed, commits them to a branch
  `prev-i/geoip-<debian-version>` and pushes it, with `contents: write` for that job only.
  The owner, or a session at the owner's request, opens the pull request; opening it is a
  `pull_request` event, so the normal checks run *(designer's call: no repository setting
  changes)*.
- **First data.** The pull request that brings the library and the workflow also brings the
  first data, produced by running `refresh.sh` locally. A workflow cannot be dispatched before
  it is on `main`, so after the merge the first dispatch run must report that the data is
  current, which tests that path *(designer's call)*.
- `GeoIP/HowToUpdate.txt` is replaced by a section in `docs/RELEASING.md`: run the workflow,
  open the pull request, merge it before tagging.

### 3. Tests

- **Lookup test.** A small C program in `tests/geoip/`, built with gcc from the bundled 1.6.12
  sources, checks that:
  - the file opens with edition 1 (country);
  - every id met while walking all IPv4 ranges is inside the table (1 to 255), and no range
    returns 255 (`O1`);
  - the last id of 1.6.12's table occurs in the walk and reads as its code *(designer's call:
    asserted from the walk, not from a fixed address, so a refresh that moves a range does not
    break it)*;
  - a short list of addresses whose country is stable returns that country. Each address carries
    its reason in the test (a registry's own network, for example); anycast addresses are not
    used.
- **Where it runs.** In `refresh.sh`, and in a new workflow `geoip-test.yml` on pushes and pull
  requests touching `GeoIP/` or `tests/geoip/` *(designer's call: a workflow of its own, not a
  required check, since `main` has no branch protection)*.
- **Windows build.** The existing MSBuild workflow builds `geoip.dll` and the client for x64
  and Win32.
- **Client check.** The Windows oracle already installs and runs the client. The builder adds a
  check there only if the client shows a country it can read; otherwise the lookup test and the
  build are the evidence, said so in the pull request.

### 4. Installer

- `setup/scripts/main.iss` already installs `GeoIP.dll` and `GeoIP\GeoIP.dat`; it now also
  installs the licence texts next to them, `LICENSE-GeoIP.txt` (from `setup/misc/`) and
  `LICENSE-GeoIP-LGPL-2.1.txt` (from `GeoIP/License.txt`) *(owner, 2026-11-16, after the final
  review found that users saw no licence link or copyright holder)*. The installer grows by
  about 1.2 MB compressed.

### 5. Attribution and licences

- The About dialog's MaxMind line becomes: `IP geolocation by DB-IP (db-ip.com), CC BY 4.0,
  converted to GeoIP format by Debian.` ASCII only, so it passes PR #47's CP-1252 check, at the
  position PR #47 gives the line.
- `setup/misc/LICENSE-GeoIP.txt` is rewritten: the library under LGPL 2.1 (MaxMind), the data
  under CC BY 4.0 (DB-IP, Eris Networks S.A.S), the licence link, and the change notice
  (converted to the legacy GeoIP format by Debian's `geoip-database`, unmodified since), and the
  ISC notice of `pread.c`/`pread.h`. `GeoIP/License.txt` follows.
- `README.md`'s credits gain DB-IP and Debian's `geoip-database`.
- The release notes say the country data is new and where it comes from, under the owner's
  release-notes checklist.

## Constraints

- Work goes through pull requests into `main`; the owner merges after their own tests.
- This branch starts from `main`. Because it edits the About dialog line that PR #47 moves, it
  is rebased onto `main` after #47 merges, before its own pull request opens.
- The runner image stays `windows-2022` with the v143 toolset.
- `Shareaza.rc` stays CP-1252.

## Left to the builder

- The exact Windows defines and warning settings 1.6.12 needs under v143.
- Whether `GeoIP.h` from 1.6.12 needs an include-order change in `shareaza/StdAfx.h`.
- The stable addresses for the lookup test, each with its reason.
- Whether Ubuntu's `debian-archive-keyring` on the runner holds a key that signs sid's current
  `InRelease`; if not, the narrowest fix, said in the pull request.
