# Shareaza post-SVN security audit — 2026-10-24

Static security review of what was added to Shareaza after the original SourceForge project ended.
It was done for this fork of `github.com/ansani/Shareaza` before its builds were used as protocol
oracles for `gwc-edge` (see [ORACLE.md](ORACLE.md)).

**Status, 2026-10-26.** Findings 3, 4 and 5 are fixed on `main` by
[PR #8](https://github.com/Prev-I/Shareaza/pull/8) (merge `d2f09dd42`). The only part not fixed
is finding 4's missing opt-out. The first release built with the fixes is `v2.7.10.6-previ.2`.
Findings 1 and 2 are still open. All five were reported privately to ansani/Shareaza on
2026-10-26. The text below is the audit as written, apart from the dated bullets under
**Disclosure**, the **Fixed** lines under findings 3 to 5, and the notes under "Consequences for
the oracle". What changed since is in the
[addendum](#addendum-2026-10-26-fixes-for-findings-3-4-and-5).

**Disclosure.**
- **Not reported upstream.** As of 2026-10-25 the findings have not been reported to ansani/Shareaza.
- **Reported upstream on 2026-10-26.**
  - Findings 1 to 5 were reported privately to ansani/Shareaza, with links to the fixes for
    findings 3 to 5.
  - No reply yet.
- **Finding 3 omits its trigger.** It names the faulty code but not the packet that reaches it.
  Since the source is public, that only slows a reader down.
- **The fix gives the trigger away.** The message of fix commit `91330b820` describes how finding 3
  is reached closely enough to count as public, and so does its diff. Treat the trigger as public
  from 2026-10-26.
- **Scope of "affected".** Where a finding says the official 2.7.10.2 is not affected, that is
  inferred from the source: the SVN baseline, which is no older than the 2.7.10.2 release, lacks the
  code. The 2.7.10.2 binary itself was not examined.

**Verdict: no backdoor or malicious code found.** There are real security weaknesses, the worst of
them in the TLS support and the IPv6 code, plus supply-chain risk from third-party prebuilt
dependencies. None of it looks deliberate.

The audit is static only: nothing was compiled or run. It was done with AI agents.
- **✔ findings** were re-read in the source by a second pass after the first reported them.
- **The rest** are first-pass findings with file and line evidence, not independently confirmed.
- **"Inference"** marks claims nobody verified.

## Scope

| | |
|---|---|
| Baseline | `511345b0a`, 2017-09-23, raspopov — the last commit carrying the SVN repository id |
| Target | `f24b0ce37`, 2024-06-21 — `ansani/Shareaza` `master` at the time of the audit |
| Range | 348 commits: 141 Salvatore Ansani (2022–2024), 206 ivan / ivan386 (a 2013 fork merged in on 2017-11-10 by `f98b7b64d`), 1 `restyled-io[bot]` |

It ran as three independent passes:

1. **Core client**, `shareaza/`: about 20.8k diff lines, read in full.
2. **Plugins, installer, build, CI and `Data/`**: about 8.7k diff lines.
3. **Provenance of what can't be read as source**: prebuilt binaries, vendored third-party trees,
   NuGet packages and commit signatures.

To regenerate the diffs from a clone of the fork:

```bash
B=511345b0a; T=f24b0ce37
V=(':!BugTrap' ':!BugSplat' ':!MiniUPnPc' ':!zlib' ':!zlibwapi/zlib' ':!*.png' ':!*.ico' ':!*.bmp'
   ':!*.gif' ':!*.jpg' ':!plugins/RARBuilder/unrar*' ':!plugins/RARBuilder/UnRAR*' ':!plugins/7ZipBuilder/7z*'
   ':!*.vsidx' ':!*.VC.db' ':!Languages' ':!Skins' ':!Schemas' ':!*.h.REMOTE.h' ':!*.h.LOCAL.h' ':!*.h.BASE.h')
O=(-M -w --ignore-cr-at-eol --ignore-blank-lines --diff-filter=d)
git diff "${O[@]}" $B $T -- shareaza "${V[@]}" > core.diff
git diff "${O[@]}" $B $T -- plugins "${V[@]}" > plugins.diff
git diff "${O[@]}" $B $T -- . ':!shareaza' ':!plugins' "${V[@]}" > rest.diff
```

Deleted files and images, language and skin files are excluded from the diffs. The vendored trees
went to the provenance pass instead.

## Serious

### 1. ✔ HTTPS never verifies the server certificate

- **Where:** `shareaza/Connection.cpp:470-484`, from commit `4f4563788` (Ansani, 2023-09-23, "Added
  support for SSL connections").
- **What's missing:** there is no `SSL_CTX_set_verify`, no CA store, no SNI and no hostname check
  anywhere in the tree, so any certificate is accepted.
- **Who is exposed:** every `https://` download. That includes the update installer, which comes
  from the GitHub release asset `browser_download_url` (`VersionChecker.cpp:315-325`,
  `DlgUpgrade.cpp:83-88`), carries no hash, and is not run automatically.
- **What is safe:** the update *check* goes through WinINet, which validates certificates.
- **Also in this code:** the `SSL_CTX` leaks on every connection, and `sslConnection` is never
  initialised or freed.

### 2. ✔ Third-party OpenSSL 1.1.1b linked into the client

- **Where:** `shareaza/packages.config:49` pulls the NuGet package `openssl-vc140-static-32_64`
  1.1.1.1.
- **Who publishes it:** nuget.org lists the owners as `apriorit_dev` and `Holiday`. The nuspec's
  claim to come from the "OpenSSL Software Foundation" is false; OpenSSL publishes no NuGet packages.
- **What it contains:** prebuilt static libraries of OpenSSL **1.1.1b** (2019-02-26), built with
  Conan on a developer machine (`C:\Users\kleymenov.nikita\.conan\...`).
- **Why it matters:** 1.1.1 has been end-of-life since 2023-09. This build misses later CVE fixes
  including CVE-2022-0778, a remotely triggerable infinite loop. The libraries cannot be checked
  against an official build, because OpenSSL publishes source only.

### 3. ✔ Probable remote crash from one UDP packet

- **Where:** `shareaza/SearchManager.cpp:215,245`, from ivan386's `b18e0a23c` (2018-03-12, "partial
  ipv6 support 10"). The 2017 SVN baseline has none of this code.
- **The bug:** for an IPv4 sender, a pointer derived from a NULL IPv6 address is passed on as if it
  were valid. `CNetwork::IsValidAddressFor` (`Network.cpp:790`) then dereferences it.
- **Reach:** a single packet, either over UDP from any IPv4 peer or over TCP from a connected IPv4
  neighbour. Which packet is deliberately left out here.
- **Affects:** ansani's releases from 2.7.10.3 on (inference: they all postdate the commit) and this
  fork's builds. The SVN baseline lacks the code, so 2.7.10.2 should not be affected (inference from
  source).
- **Not verified:** the path was traced in the code but not run.
- **Fixed** in `91330b820`, with `ad4d685df` for IPv6 hubs. See the addendum.

### 4. IPv6 traffic bypasses the ban list and address filters

- **Accept-time ban check:** `Handshakes.cpp:455-468` treats the IPv6 caller as `SOCKADDR_IN`, so
  `Security.IsDenied` reads `sin6_flowinfo`.
- **UDP:** `Datagrams.cpp:929` and `Send(SOCKADDR_IN6*)` skip the `IsFirewalledAddress` and
  `IsDenied` checks the IPv4 paths make.
- **DHT:** `BTPacket.cpp:67-73` blacklists no IPv6 address.
- **Deny-by-default:** `Security.cpp:695-697` returns `FALSE` when no rule matches, so this policy
  is not applied to IPv6.
- **No opt-out:** the IPv6 listeners always bind to `in6addr_any`.
- **Fixed**, apart from the opt-out, by `e6ad1a848`, `85be3a518`, `178100427` and `2c632d30c`.
  Three more defects found on the way are in the addendum.

### 5. ✔ The installer deletes every top-level `*.exe` and `*.dll` in the install folder

- **Where:** `setup/scripts/main.iss:543-544`, inside `[InstallDelete]`, from commit `0628872c4`
  (Ansani, 2024-04-30, "Remove unused DLLs and Exes.").
- **Effect:** `[InstallDelete]` runs at install time, not uninstall. With `DirExistsWarning=no`,
  installing into an existing folder silently removes these files. Intent looks benign: the rules
  belong in `[UninstallDelete]`.
- **Fixed** in `14578ddb0`, but not by moving the rules. They cleaned up after the switch from
  BugTrap to BugSplat, so they now name the retired files instead of matching every `*.exe` and
  `*.dll`.

## Medium

- **✔ MiniUPnPc reports 2.2.4 but compiles 2017 code.** Commit `f85ce7ca2` added the 2.2.4 tree, but
  `MiniUPnPc_143.vcxproj` still compiles the root-level 2.0.20170509 sources: the root
  `miniupnpc.h` still defines `MINIUPNPC_VERSION "2.0.20170509"`. Those sources miss upstream's
  2017-12 fixes for a buffer overrun in `minixml.c` and an uninitialised variable in
  `upnpreplyparse.c`.
- **Weaker G2 hit anti-spoofing.** `G2Packet.cpp:1030-1040` now accepts hits whose node address
  differs from the UDP sender, provided the sender is in the host cache.
- **Global IPv6 address advertised.** It goes out in G2 search replies (`LocalSearch.cpp:959-963`),
  BitTorrent tracker announces (`BTTrackerRequest.cpp:356-359`), the BitTorrent extension handshake,
  and push requests. Inference: it can leak when only IPv4 is routed through a VPN.
- **Other third-party prebuilt packages.**
  - `zlib128-vc140-static-32_64` 1.2.8, also from apriorit. Probably vestigial, since zlibwapi
    compiles the vendored 1.2.12 itself.
  - Boost 1.84.0: 45 packages from a single community publisher.
  - `7-Zip.StandaloneConsole.x64` 23.1.0, a community repack used only at build time.

## Low, or just worth knowing

- **BugSplat replaced BugTrap** as the crash reporter (commit `c87dc59ae`, 2024-04-30).
  - Crash and hang minidumps go to BugSplat's service under the database `shareaza`
    (`Shareaza.cpp:316-339`). The installer does not disclose this.
  - Its 16 binaries carry valid Authenticode signatures by BugSplat LLC, with a DigiCert EV chain
    verified to the root, and are consistent with SDK 5.2.0. No vendor hash comparison was possible:
    the SDK download requires a login.
  - The resource DLL path is relative to the current directory (inference: a DLL-planting risk at
    crash time).
- **UnRAR 6.11.0 DLLs** are authentic (win.rar GmbH signature, chain verified to the GlobalSign
  intermediate) but old.
- **The 7-Zip extraction DLLs** (`7zxa*.dll`) are unchanged since the baseline and unverified.
- **Sentry 4.4.0** is the official .NET SDK but nothing in the source uses it. Its `Sentry.targets`
  is still imported at build time and does nothing unless upload properties are set.
- **Country block by default:** `Settings.cpp:308` sets `IgnoredCountry=|TW|HK|CN|`, so hosts in
  those countries are kept out of the host cache (ivan, 2013). It is visible in Advanced settings.
- **Connection test:** `Shareaza.h:458` points to `https://connectiontest.kirurusec.com/`, opened in
  the browser only from Help. Who owns the domain is unknown.
- **Update check:** it queries `api.github.com/repos/ansani/Shareaza/releases/latest` and is now off
  by default. A malformed JSON response is not caught and crashes the client.
- **The fork renames itself:** ivan386's `64541b5d5`, "Soft name change", 2017-10-03.
  - Vendor code `RAZI` (`Shareaza.h:444`), so a GWebCache sees `client=RAZI2.7.10.6` on G2
    (`DiscoveryServices.cpp:1423-1424`), not `RAZA`.
  - User agent `iShareaza 2.7.10.6` (`Shareaza.cpp:1109-1111`).
  - BitTorrent peer-ID prefix `iS`.
- **IDE caches** committed in `640fd8caf` under `zlibwapi/zlib/contrib/vstudio/vc14/.vs/` include
  the developer's Windows user name (`C:\Users\salva`) and their PATH. Privacy and hygiene only.
- **Commit signatures:** all 62 signed commits verify (61 GitHub web-flow, 1 Ansani's key), and the
  rest are unsigned. No author or committer metadata looks spoofed. The author/commit date gaps on
  ivan386 commits are SVN-sync replays.

## Checked and clean

- **`Data/`** is identical to the SVN baseline, including `DefaultServices.dat`,
  `DefaultSecurity.dat` and the ban lists, and so are `Schemas/`, `Skins/` and `Templates/`.
- **Plugins:** no logic changed. VirusTotal only opens a hash lookup in the browser, uploading no
  file and using no API key. ShortURL sends a magnet link only when the user asks.
- **No hidden behaviour:**
  - no new `ShellExecute`, `CreateProcess` or `WinExec` driven by network input;
  - no `LoadLibrary` from network input;
  - no Run keys, services, scheduled tasks or firewall changes;
  - no hardcoded credentials;
  - no base64 or XOR blobs, and no host names assembled from pieces.
- **Vendored zlib** matches the official 1.2.12 tarball, apart from two harmless patches taken from
  1.2.13 (`crc32.c` `ZEXPORT`, and the `zlib.h` 64-bit combine declarations).
- **`plugins/RARBuilder/unrar.h`** matches RARLab's `dll.hpp`.
- **MiniUPnPc's** `src/` and `include/` trees match official 2.2.4, though they aren't what is
  compiled (see Medium).
- **`gvmat32.asm` and `gvmat32c.c`** match zlib 1.2.3's `contrib/masmx86` and are not built.
- **The installer** downloads only `VC_redist` from go.microsoft.com, which predates the fork, and
  writes nothing outside `{app}` and `{userappdata}\Shareaza` beyond what it already did.

## Consequences for the oracle

- **Not unattended on the live G2 network.** Findings 1, 3 and 4 mean any peer may be able to crash
  the client or slip past its ban list.
  - From `v2.7.10.6-previ.2`, findings 3 and 4 are fixed, apart from finding 4's opt-out.
  - Finding 1 is still open, and the fixes were verified by review and a clean build, not by running
    an attack.
  - So the rule stands.
- **A fresh Wine prefix per installer**, because of finding 5.
  - Releases from `previ.2` delete only the retired BugTrap files. A program that keeps its own
    `dbghelp.dll` in the same folder would still lose it.
  - A fresh prefix is still needed for a clean comparison between clients.
- **Revision string:** the fork's builds show ` Release 64-bit (commit <sha> of <date>)` in the About
  box.
- **Identifying the client:** they identify to caches as `RAZI2.7.10.6`, as ansani's own builds do.
  The official SourceForge 2.7.10.2 sends `RAZA2.7.10.2`.

## Addendum 2026-10-26: fixes for findings 3, 4 and 5

[PR #8](https://github.com/Prev-I/Shareaza/pull/8), merged as `d2f09dd`, landed these commits.

| Commit | Finding | Change |
|---|---|---|
| `91330b820` | 3 | Fixes the NULL-derived pointer dereference. |
| `ad4d685df` | 3 | Follow-up for hubs connected over IPv6, so the fix does not drop their entries. |
| `e6ad1a848` | 4 | `CSecurity::IsDenied` for an IPv6 address no rule matches returns the default policy, as the IPv4 overload does. |
| `85be3a518` | 4 | `CHandshakes::AcceptCheck` checks an IPv6 caller's own address. |
| `178100427` | 4 | `TryReadIPv6` and `Send(SOCKADDR_IN6*)` apply the same filters as their IPv4 twins. |
| `2c632d30c` | 4 | `dht_blacklisted` applies the ban list, self and site-local filtering, and the port-0 check to IPv6 nodes. |
| `809d1c840` | 4, new | Outgoing IPv6 connections are refused for banned hosts and the unspecified address. The audit missed this path; the download sources reach it. |
| `d613cffb2` | 4, new | Each security miss cache is emptied once it reaches 65536 entries. Before, a sender could grow them by one entry per source address it used, which costs nothing from a single IPv6 /64. The IPv6 receive filter above made that a per-datagram cost, so the limit came with it. |
| `570dbdd05` | new (IPv6 rule map) | `CSecurity::Remove` erases a single-address (/128) IPv6 rule from its address map before freeing it. |
| `14578ddb0` | 5 | `[InstallDelete]` names the retired BugTrap files instead of `*.exe` and `*.dll`. |

**The use-after-free fixed by `570dbdd05`.** The audit missed it; the second review of the fixes
found it.
- **What it was:** removing certain single-address IPv6 rules from the Security window freed the
  rule but left it in the IPv6 address map.
- **What followed:** saving and listing the rules, both of which happen right after a removal, read
  the freed rule at once. Later checks of that address, inbound or outbound, read and wrote it.
- **Who could trigger it:** it took the local user's own actions in the Security window. It could
  not be reached from the network alone.

**How the fixes were verified.**
- Root causes traced in the source.
- Two independent read-only reviews.
- A clean Win32 and x64, Release and Debug build, with no compiler warning in any changed line.

The crash in finding 3 was not reproduced. No exploit was written to prove the fix, and this
document still does not spell out the trigger. The fix commit is a different matter: see
**Disclosure** at the top.

**Still open.**
- Findings 1 (no TLS certificate check) and 2 (third-party OpenSSL 1.1.1b).
- The "no opt-out" point of finding 4: the IPv6 listeners always bind to `in6addr_any`.
- **Single-address IPv6 rules can't be edited or removed** from the Security window, because
  `CSecurity::GetGUID` does not search the map that holds them.
  - This is a functional defect.
  - Never fix `GetGUID` in a tree that lacks `570dbdd05`: there, a single Remove click would reach
    the use-after-free.
- **Editing a rule into a single address leaves the original active.** This applies to an IPv6
  /128 rule and an IPv4 /32 one alike.
  - The edited copy goes into the address map, but the original stays in place with the same GUID.
  - So the old rule still applies after the user believes they changed it.

## Evidence (`security-audit/evidence/`, `security-audit/tools/`)

The large inputs — downloaded vendor tarballs, nupkgs, extracted trees, 341 MB in all — were not
kept. Every one can be fetched again from the URLs whose hashes are in `dl-sha256.txt`.

| File | Contents |
|---|---|
| `security-audit/evidence/sha256.txt` | SHA-256 of every prebuilt binary in the range. `e3b0c442…` is the hash of an empty file: the binary was absent from the tree hashed. |
| `security-audit/evidence/pe-report.txt` | PE header, version resource, Authenticode digest, signer chain and timestamp checks per binary |
| `security-audit/evidence/dl-sha256.txt` | SHA-256 of every vendor archive downloaded for comparison |
| `security-audit/evidence/nuget-registry.jsonl` | nuget.org registration and search data for all 49 referenced packages |
| `security-audit/evidence/post-svn-commits.txt` | the commit range |
| `security-audit/evidence/added-urls.txt`, `added-ips.txt` | every URL and IPv4 literal on an added line, with counts |
| `security-audit/evidence/binary-files.txt` | binary files changed in the range |
| `security-audit/tools/analyze.py`, `chain.py` | PE and Authenticode parsing, and certificate chain verification (Python, run with `-I`) |
| `security-audit/tools/nuget.py` | the nuget.org queries |
| `security-audit/tools/cmpextra.sh` | vendored-file versus upstream-tree comparison, ignoring line endings and whitespace |

The scripts hard-code the scratch paths of the original run (`/tmp/shareaza-audit/provenance/...`).
