# Shareaza post-SVN security audit — 2026-10-24

Static security review of what was added to Shareaza after the original SourceForge project ended.
It was done for this fork of `github.com/ansani/Shareaza` before its builds were used as protocol
oracles for `rs-gwc-edge` (see [ORACLE.md](ORACLE.md)).

**Disclosure.**
- **Not reported upstream.** As of 2026-10-25 the findings have not been reported to ansani/Shareaza.
- **Finding 3 omits its trigger.** It names the faulty code but not the packet that reaches it.
  Since the source is public, that only slows a reader down.
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

### 4. IPv6 traffic bypasses the ban list and address filters

- **Accept-time ban check:** `Handshakes.cpp:455-468` treats the IPv6 caller as `SOCKADDR_IN`, so
  `Security.IsDenied` reads `sin6_flowinfo`.
- **UDP:** `Datagrams.cpp:929` and `Send(SOCKADDR_IN6*)` skip the `IsFirewalledAddress` and
  `IsDenied` checks the IPv4 paths make.
- **DHT:** `BTPacket.cpp:67-73` blacklists no IPv6 address.
- **Deny-by-default:** `Security.cpp:695-697` returns `FALSE` when no rule matches, so this policy
  is not applied to IPv6.
- **No opt-out:** the IPv6 listeners always bind to `in6addr_any`.

### 5. ✔ The installer deletes every top-level `*.exe` and `*.dll` in the install folder

- **Where:** `setup/scripts/main.iss:543-544`, inside `[InstallDelete]`, from commit `0628872c4`
  (Ansani, 2024-04-30, "Remove unused DLLs and Exes.").
- **Effect:** `[InstallDelete]` runs at install time, not uninstall. With `DirExistsWarning=no`,
  installing into an existing folder silently removes these files. Intent looks benign: the rules
  belong in `[UninstallDelete]`.

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
- **A fresh Wine prefix per installer**, because of finding 5.
- **Revision string:** the fork's builds show ` Release 64-bit (commit <sha> of <date>)` in the About
  box.
- **Identifying the client:** they identify to caches as `RAZI2.7.10.6`, as ansani's own builds do.
  The official SourceForge 2.7.10.2 sends `RAZA2.7.10.2`.

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
