# previ.11: the update download bypasses IP filtering, deferred fixes, and version 2.7.11.6: design

Date: 2026-11-19. Status: approved by the owner on 2026-11-20. The scope and the decisions marked
*(owner)* were settled with the owner on 2026-11-18/19; items marked *(designer's call)* were
settled while writing.

## Intent

previ.11 is the release meant to be announced *(owner)*. previ.10 has one problem that matters
more once new users arrive: the eMule-Security IP list, which a user may subscribe to, covers
`185.199.108.0/22`, the network GitHub serves release files from. With that list on, the
client's update download never connects. The update check uses WinINet and is unaffected, so the
user is told an update exists and then nothing happens: the source fails, is retried with a
growing delay, is dropped after `Download.MaxAllowedFailures` failures, and the download dies
after three hours without data, with no message that names the cause. A user stuck that way
cannot receive the later fixes through the updater.

The same release carries every small item left over from previ.9 and previ.10 *(owner)*.

## Goals

1. **The update download is exempt from all IP filtering** *(owner)*: subscribed IP lists, the
   user's own rules in My rules, and the deny-by-default policy. Every other download, including
   URLs the user pastes or clicks and every source found on the network, stays subject to the IP
   lists and the security rules exactly as today *(owner)*.
2. The deferred fixes listed under *Deferred fixes*.
3. Version 2.7.11.6, released as `v2.7.11.6-previ.11`.
4. The third-party libraries updated, as listed under *Dependency updates* *(owner, 2026-11-22)*.

## Non-goals

- Exempting user-chosen web downloads *(owner)*: no marker for sources the user adds from a URL; the only per-source marker is the update's own (*Which sources*).
- Changing what IP lists or security rules do to P2P traffic.
- Helping previ.10 installs: the exemption ships in previ.11, so a previ.10 client with the
  eMule-Security list still cannot download previ.11 through the updater. The known-issue note on
  the previ.10 release (untick the list, or add an Accept rule) stays the remedy for them, and the
  previ.11 release notes repeat it *(designer's call)*.
- Upstream: treated as closed; nothing is reported.

## Approaches considered for the exemption

- **A. A per-connection flag on `CConnection`** (chosen). A protected member, off by default, tells
  `CConnection::ConnectTo` (IPv4 and IPv6) to skip `Security.IsDenied`. Only
  `CDownloadTransferHTTPS` sets it, and only for a download with `m_bRequireValidCert`. Smallest
  change; touches neither the rule order nor the miss cache.
- **B. Exempt the update from IP lists only, keep My rules.** Needs a parameter through
  `CSecurity::IsDenied` that skips the list step, and care with `m_Cache`: an address that passed
  without the list check must not be cached as a miss, or later P2P connections to it would skip
  the lists too. More work and more risk, and a user's Deny rule could still recreate today's
  silent stall. The owner chose full exemption, which also matches the update check: WinINet has
  never gone through `CSecurity`.
- **C. A temporary Accept rule for GitHub's addresses.** Rejected: it would be saved in the user's
  rules, interact with the cache, and the CDN's addresses change.
- **D. A new parameter on `ConnectTo`.** Rejected: it is virtual with many overrides and callers,
  for the same result as A.

## The exemption (approach A)

- **Which sources.** `CDownload::m_bRequireValidCert`, set only by `CUpgradeDlg::OnOK`
  (`DlgUpgrade.cpp`) and saved with the download, marks the update download, but it only
  restricts (HTTPS only, strict certificate) and never grants the exemption on its own: it is
  saved state, and a saved download can come from elsewhere. The exemption belongs to sources:
  `CDownloadSource::m_bUpdateExempt`, runtime-only, never saved, written in one place,
  `CDownloadWithSources::AddSourceURL`, on the source it has just built from a URL in this
  process. It is passed down for three URLs only: the update check's own URL from
  `CUpgradeDlg::OnOK`; a redirect target, when the source that redirected was exempt, the
  download has `m_bRequireValidCert` and the TLS was validated; and the URLs
  `CDownloads::ReseedUpdate` gives back at load (below). A source read from a saved download,
  found on the network or added by the user is never exempt. An update source is always HTTPS
  (`CDownloadSource::IsAllowedForDownload` refuses others), so `CDownloadTransferHTTP` and
  `CDownloadTransferFTP` are not touched. *(Revised 2026-11-20 after the final review and an
  expert consultation; the owner chose this binding. An earlier draft used
  `m_bRequireValidCert` itself as the marker.)*
- **Redirects.** GitHub redirects the asset URL to another host. The redirect target becomes a new
  source of the same download and inherits the mark from the redirecting source; the existing
  limits (five redirects, HTTPS only, certificate valid for the URL's host) still apply.
- **After a restart.** The redirecting source is removed once it redirects, and neither the
  redirect count nor failed sources are saved, so a saved update download holds only the
  redirect target, whose signed URL expires and which is no longer exempt. At load,
  `CDownloads::ReseedUpdate` replaces its sources with the update check's URL when it is still
  the update the check found: the file name equals `Settings.VersionCheck.UpgradeFile` exactly,
  `CVersionChecker::IsVersionNewer` holds, and the sizes match when both are known. Otherwise it
  is left filtered like any download. The GitHub response carries no size, so in practice the
  file name, which carries the version, is what keeps two releases' bytes apart: every release
  must change the version. The update download is not renamed by `Content-Disposition`, so the
  name keeps matching.
- **Where.** `CDownloadTransferHTTPS::Initiate` sets the `CConnection` flag `m_bSkipSecurity` to
  `m_bRequireValidCert && m_pSource->m_bUpdateExempt`, both ways, every time. Both
  `CConnection::ConnectTo` overloads connect even when `Security.IsDenied` refuses the address
  when the flag is set (it is still evaluated, for the log line under *Visibility*).
  Every other check in `ConnectTo` (null or zero address, port 0) stays. A connection opened
  with the flag is never handed to another download (`GiveConnectionToNext`).
- **What protects the update instead.** HTTPS with a certificate valid for the URL's host, on
  every hop of the redirect. There is no hash check: since previ.5 the update download carries no
  hash (the GitHub release response has none), and the client never offers to run the file; the
  user runs the installer. *(Corrected 2026-11-20 after the final review: an earlier draft claimed
  a SHA-1 and size check through `CVersionChecker::CheckUpgradeHash`, which never fires in this
  configuration.)* IP filtering is not an integrity check, so skipping it does not weaken what
  the user later runs.
- **Visibility.** When the flag is set and `Security.IsDenied` *would* have denied the address,
  the client logs one line naming the address and that the update download is exempt from IP
  filtering *(designer's call)*, so a user reading the log sees why the connection went through.
  New string in English and Italian; other languages fall back to English. Evaluating
  `IsDenied` only for this log line is acceptable: it is one connect per update source.
- **Inbound and P2P** are unchanged: the flag is set nowhere else.

## Deferred fixes

Each is described by class and function. None concerns a withheld trigger, but the disclosure
check below still applies.

1. **`CSecurity::GetCount`** returns the rule list plus the single-address IPv4 map, but
   `CSecurity::Serialize` then also writes the single-address IPv6 map. On load the count is
   short, so IPv6 single-address rules are lost. Count all three; check that loading a file
   written by previ.10 still works (it holds no IPv6 single-address rules beyond the count, or the
   loader stops at the count) and that a file written by previ.11 loads in previ.10 without harm,
   or record that it does not.
2. **`CSecurity::FromXML` and the old import path** leak the rule object when an incoming rule
   replaces an existing rule at the same address. Free it (or reuse it), in both paths.
3. **`CDatagrams::OnReceiveSGP` (IPv6 overload)** sends its acknowledgement on the IPv4 socket.
   Send it on the IPv6 socket. IPv6 is off by default.
4. **`FindAssetURI`** (`VersionChecker.cpp`) picks the first asset whose URL contains the platform
   and build type. Also require the URL to end in `.exe`, so a symbols zip or any future asset
   can never be chosen as the update.
5. **`CNetwork::Disconnect`**: after `CloseThread()` a thread that was terminated by force never
   runs the line that clears `m_nRunningThreadId`, so the watchdog keeps a stale thread id. Clear
   it after `CloseThread()` returns.
6. **`CMutexTracked`** (`StdAfx.h`): MFC's `CMutex::Lock` returns TRUE on `WAIT_ABANDONED` too.
   The dead owner's counters and thread id are left as they were, so `m_nThreadId` is not updated
   to the new owner. On abandonment, reset the tracking state before recording the new owner. How
   abandonment is detected (calling the wait directly instead of `CMutex::Lock`) is the builder's
   call.
7. **`docs/DIAGNOSTICS.md`**: replace the Inno Setup placeholder `{app}\Data` with words a user
   understands (the installation folder's `Data`), and re-read the section for other wording nits.

## Dependency updates

Added on 2026-11-22 *(owner)*: every bundled third-party library with a newer release that fixes
a defect the client can reach, or that is useful to take, is updated on this branch. Each comes
from its official release, checked by signature or by the release's published digest, and each
is its own commit.

| Library | From | To | Why |
|---|---|---|---|
| bzip2 (`bzlib/`) | 1.0.6 | 1.0.8 | Out-of-bounds write in `BZ2_decompress` (CVE-2019-12900); the client decompresses bzip2 data with it. |
| miniupnpc (`MiniUPnPc/`) | 2.3.3 + 3 patches | 2.3.5 | Ships the three `minixml.c` fixes applied by hand; bounded header parsing in `miniwget.c`. |
| zlib (`zlibwapi/zlib`) | 1.2.12 | 1.4 | Memory-safety fixes in inflate, deflate, the gz functions and minizip, which `zlibwapi.dll` exports and DocumentReader, SkinScanSKS, ZIPBuilder and the IP-list import use. |
| 7-Zip Extra (`7zxa*.dll`) | 17.01 beta | 26.06 | Nine years of parser fixes; the DLLs become verifiable against the release. |
| UnRAR.dll | 6.11 | 7.23 | Four years of RARLab updates to the library. Its RAR5 recovery-volume fix (CVE-2026-14191) is not reachable through the plugin, which only lists archives. |
| Inno Setup (CI) | 6.7.3 | 6.7.4 | Last 6.x; fixes RedirectionGuard inheritance by processes Setup starts. 7.x stays a change of its own. |
| GitTools actions (CI) | v4.7.0 / v1 | v4.7.2 | Maintenance and an `overrideConfig` fix; `msbuild.yml` moves off v1 and GitVersion 5. |
| Other CI actions | `@v2`/`@v4` tags | `release.yml`'s pins | `msbuild.yml` and `tls-test.yml` take the commit-pinned checkout, setup-msbuild and upload-artifact versions `release.yml` uses. |

Sources for the reasons: each project's release notes or changelog (zlib `ChangeLog`, miniupnpc
`Changelog.txt`, UnRAR `whatsnew.txt`, Inno Setup `whatsnew.htm`, the GitTools v4.7.0...v4.7.2
compare), and the Debian security tracker for CVE-2026-14191.

`unrar.h` 7.23 puts its new pointer fields in reserved space sized for 64-bit pointers: on x64
the structures keep their sizes, on x86 `RARHeaderDataEx` and `RAROpenArchiveDataEx` shrink by 8
and 4 bytes. The x86 DLL is built from the same header, so caller and DLL agree; an older x86
`unrar.dll` would not.

Behaviour kept *(designer's call)*: UnRAR 7.2x opens archives unshared by default, so the RAR
plugin asks for the shared mode every earlier version used; zlib's export list moves out of the
tree zlib no longer ships it in.

Not updated: SQLite 3.20.1 (fixed SQL on a local file; no reachable fix), Boost 1.84 (the NuGet
feed stops at 1.87; no fix in the parts used), the GFL SDK 3.40 (no newer release exists), and
GitVersion 7 (breaking). The unused copy of zlib 1.2.12 in the root `zlib/` folder is left as it
is.

## Release

- One pull request for the exemption and one for the deferred fixes, or a single one: the
  builder's call, by size *(designer's call)*.
- Version bump to 2.7.11.6 in its own pull request, as before.
- Run `geoip-refresh.yml` before the release, as for previ.10.
- Release notes: the update download is no longer subject to IP lists or security rules; the
  fixes by class/function; the previ.10 known issue repeated for previ.10 users.
- Afterwards: the test-kits pull request pointing at previ.11, and the "mark designs as shipped"
  docs change.
- Disclosure: commit messages, pull request titles and bodies, and release notes name classes and
  functions only. The reviewer checks for trigger disclosure as a named item before anything is
  pushed.

## Verification

- MSBuild, all four legs, and the existing tests under `tests/`.
- The oracle runs (Wine and Windows) on the release build.
- **The exemption, end to end** *(designer's call; the method is the builder's)*: a test build
  whose version is below 2.7.11.5 is offered previ.10 by the update check. With the
  eMule-Security list subscribed, its update download must complete, the log must show the
  exemption line, and an ordinary download from a `185.199.108.0/22` URL in the same session
  must still be refused.
- `GetCount`: save and load a rule set holding IPv6 single-address rules; they survive.
- Owner checks before release: the end-to-end exemption above on a real Windows machine, and the
  log line's Italian text.

## Left to the builder

- Names: the `CConnection` flag, the string ID, branch names.
- The split into pull requests.
- How `CMutexTracked` detects abandonment, and how `GetCount`'s compatibility is checked.
- How the end-to-end exemption test is built (a low-version CI build, or another way).
