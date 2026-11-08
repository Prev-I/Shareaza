# previ.5 privacy changes and version 2.7.11.0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship previ.5: BugSplat removed, an IPv6 switch off by default, partial sharing no longer forced on, profile serving off covering every profile path, then version 2.7.11.0 with the update check on this fork.

**Architecture:** Two pull requests into `main`. A (`prev-i/privacy`) carries the four privacy changes, their documentation and the oracle changes that test an unreleased build. B (`prev-i/version-2.7.11`), opened after A merges, carries the version, the update and website URLs and a settings migration. IPv6 is cut at its sources (sockets, the outbound connect choke point, address learning), not at each writer.

**Tech Stack:** C++/MFC (Visual Studio v143), Inno Setup 6.7.3, GitHub Actions on `windows-2022` and `ubuntu-24.04`, Windows PowerShell 5.1, bash.

**Spec:** `docs/superpowers/specs/2026-11-08-previ5-privacy-design.md`

## Global Constraints

- **No local build or test run.** The workstation is Linux; the client builds only in CI (`msbuild.yml` on every pull request touching code, `release.yml` by dispatch or tag). The client has no unit-test harness. Each task's "test" is a grep assertion that must hold before the commit, plus the CI build and the oracle checks of Task 6.
- New setting: `Connection.EnableIPv6`, `bool`, default `false`, member `Settings.Connection.EnableIPv6`.
- Version: `2.7.11.0`. Tag: `v2.7.11.0-previ.5`. Every later release raises the fourth number.
- `SMART_VERSION` stays 61 in pull request A and becomes 62 in pull request B.
- Update URL: `https://api.github.com/repos/Prev-I/Shareaza/releases/latest`. Website: `https://github.com/Prev-I/Shareaza/releases`.
- Never push to `ansani/Shareaza`, never push upstream tags, never commit to `master`. Commit inside `checkouts/Shareaza` only.
- Commit messages, pull request bodies and release notes describe each change by class and function, never by the input that reaches a defect. The reviewer checks for trigger disclosure as a named item.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`; pull request bodies end with `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.
- Every coding change gets a `reviewer` pass before its pull request is opened.

## Review Focus

1. **The setting turned off while connected.** A user unticks `EnableIPv6` and reconnects: the IPv6 sockets opened earlier must still close on disconnect. `Disconnect` closes them whatever the setting says. Owned by Task 3, step 3.
2. **An IPv6 address typed by hand, or pushed by a peer, with the setting off.** The connect is refused, the caller cleans up, nothing hangs or crashes. Every caller of `CConnection::ConnectTo(const IN6_ADDR*, WORD)` must handle `FALSE`. Owned by Task 3, step 4.
3. **Upgrading over previ.4.** The new `[InstallDelete]` patterns remove exactly the BugSplat files and nothing else in `{app}`. Owned by Task 1, step 4.
4. **Profile serving on, or an empty nickname.** Behaviour must be byte-for-byte previ.4's. Owned by Task 4, step 2.
5. **An install that stored upstream's update URL.** After pull request B it asks the fork. One with a custom URL also ends up on the fork, which is intended. Owned by Task 8, step 3.

---

## Pull request A: `prev-i/privacy`

The branch exists with the design committed (`1d872108b`). Work from `checkouts/Shareaza`.

### Task 1: Remove BugSplat

**Files:**
- Modify: `shareaza/Shareaza.cpp:314-343` (delete `RegisterBugReporting`) and `:361` (its call)
- Modify: `shareaza/Shareaza.h:240,245` (`mpSender`, `RegisterBugReporting`)
- Modify: `shareaza/StdAfx.h:231` (the `BugSplat.h` include)
- Modify: `shareaza/Shareaza_143.vcxproj:144,147,192,197,249,257,306,314` (`BugSplat.lib`/`BugSplat64.lib`, `..\BugSplat\...` library directories)
- Delete: `BugSplat/` (whole directory)
- Modify: `setup/scripts/main.iss:203-214` (`[Files]` block) and the `[InstallDelete]` section beside `:543-545`

**Interfaces:** none.

- [ ] **Step 1: Assert the starting state.** `git grep -n -i bugsplat -- shareaza setup vc143` lists the lines above and nothing else in code. If it lists more, add them to this task.
- [ ] **Step 2: Remove the source, project and binary references** listed under Files. Keep the BugTrap-era `[InstallDelete]` entries.
- [ ] **Step 3: Add the retirement entries** to `[InstallDelete]`, right after the BugTrap ones, with a one-line comment naming previ.4 as the last release that installed them:

```
Type: files; Name: "{app}\BugSplat*.dll"
Type: files; Name: "{app}\BsSndRpt*.exe"
Type: files; Name: "{app}\BugSplatHD*.exe"
Type: files; Name: "{app}\BugSplatRc*.dll"
```

- [ ] **Step 4: Check the patterns (Review Focus 3).** Against the file list of a previ.4 install (the `[Files]` section as it was at `3e7ef72ff`: `git show 3e7ef72ff:setup/scripts/main.iss`), each pattern matches only the BugSplat files that block installed. Note the result in the commit message body.
- [ ] **Step 5: Verify.** `git grep -n -i 'bugsplat\|BsSndRpt\|mpSender' -- shareaza setup vc143` prints only the four `[InstallDelete]` lines and their comment.
- [ ] **Step 6: Commit** `build: remove the BugSplat crash reporter`, body saying dumps went to upstream's BugSplat account, crashes now fall to Windows' own error reporting, and upgrades delete the previ.4 files.

### Task 2: Stop forcing partial sharing on upgrade

**Files:**
- Modify: `shareaza/Settings.cpp:862` (the `Uploads.SharePartials = true;` line at the top of `CSettings::SmartUpgrade`)

**Interfaces:** none. Task 8 relies on this line being gone before it raises `SMART_VERSION`.

- [ ] **Step 1: Delete the line.** Leave a two-line comment saying an upgrade no longer touches the user's partial-sharing choice. Do not change `SMART_VERSION`.
- [ ] **Step 2: Verify.** `grep -n 'SharePartials' shareaza/Settings.cpp` shows the `Add(...)` registration only, and `grep -n 'define SMART_VERSION' shareaza/Settings.cpp` still shows 61.
- [ ] **Step 3: Commit** `fix(settings): stop a settings upgrade from turning partial sharing back on`.

### Task 3: The IPv6 switch

**Files:**
- Modify: `shareaza/Settings.h:283-291` region (declare the member), `shareaza/Settings.cpp:276-311` region (register it)
- Modify: `shareaza/Handshakes.cpp:138` (`Listen` calls `ListenIPv6`), `:144-176` (`ListenIPv6` bind failure), `:182-185` (`Disconnect`)
- Modify: `shareaza/Datagrams.cpp:267` (`Listen` calls `ListenIPv6`), `:319-345` (`ListenIPv6` bind failure), `:350-379` (`Disconnect`)
- Modify: `shareaza/Connection.cpp:370-435` (`CConnection::ConnectTo(const IN6_ADDR*, WORD)`)
- Modify: `shareaza/Network.cpp:600-629` (`CNetwork::AcquireLocalAddress(const IN6_ADDR&, WORD, const IN6_ADDR*)`)
- Modify: `shareaza/NeighboursWithConnect.cpp:1231-1298` (auto-connect loop, around `:1244` and `:1277`)
- Modify: `shareaza/G2Neighbour.cpp:275-297` (`CG2Neighbour::SendStartups`)

**Interfaces:**
- Produces: `bool CSettings::sConnection::EnableIPv6`, registered as `Add( _T("Connection"), _T("EnableIPv6"), &Connection.EnableIPv6, false );`. Task 6's oracle sets `HKCU\Software\Shareaza\Shareaza\Connection\EnableIPv6` as a `DWORD`, so the setting must be a plain `bool` item like `EnableUPnP`.

- [ ] **Step 1: Declare and register the setting**, with a comment: off means no IPv6 socket, connection or own address; takes effect at the next connect.
- [ ] **Step 2: Gate the listeners.** `CHandshakes::Listen` and `CDatagrams::Listen` call `ListenIPv6()` only when `Settings.Connection.EnableIPv6`.
- [ ] **Step 3: Fix the bind failure and keep Disconnect unconditional (Review Focus 1).** In both `ListenIPv6` functions, a failed `bind` closes the socket through `CNetwork::CloseSocket` and leaves `m_hSocketIPv6 == INVALID_SOCKET` before returning `FALSE`. In both `Disconnect` functions, confirm the IPv6 socket is closed whatever the setting says. `CDatagrams::Disconnect` returns early when the IPv4 socket is invalid (`:352`): make sure an open IPv6 socket is still closed on that path.
- [ ] **Step 4: Refuse outbound IPv6 TCP (Review Focus 2).** `CConnection::ConnectTo(const IN6_ADDR*, WORD)` returns `FALSE` before creating a socket when `! Settings.Connection.EnableIPv6`, with a `MSG_DEBUG` line. Then read each caller and confirm it handles `FALSE` without leaking or retrying in a loop: `CNeighboursWithConnect::ConnectTo(IN6)` (`NeighboursWithConnect.cpp:222`), `CShakeNeighbour::ConnectTo(IN6)` (`ShakeNeighbour.cpp:117`), `CTransfer::ConnectToIPv6` (`Transfer.cpp:74`), `CTransfer::TLSConnectTo(IN6)` (`Transfer.cpp:100`), `CHandshake::Push(IN6)` (`Handshake.cpp:147`), and the typed-address path (`Network.cpp:467-476`). Record the result per caller in the commit body.
- [ ] **Step 5: Stop learning our IPv6 address.** `CNetwork::AcquireLocalAddress(const IN6_ADDR&, ...)` returns `FALSE` at the top when the setting is off, so `m_pHostIPv6` keeps the unspecified address and port 0.
- [ ] **Step 6: Skip IPv6-only hosts when picking connections.** In the auto-connect loop, a host for which `IsIPv6Host()` is true and which has no IPv4 address is skipped when the setting is off. Hosts are still stored and passed on.
- [ ] **Step 7: Fix `CG2Neighbour::SendStartups`.** The IPv6 branch writes `&Network.m_pHostIPv6.sin6_addr`, 16 bytes, instead of the 4-byte IPv4 field.
- [ ] **Step 8: Check the remaining socket uses.** `grep -n 'm_hSocketIPv6' shareaza/*.cpp`: every use outside `ListenIPv6` and `Disconnect` is guarded by an `INVALID_SOCKET` or `IsValid(true)` check. List any unguarded one in the commit body and guard it.
- [ ] **Step 9: Verify by grep.** `grep -n 'EnableIPv6' shareaza/*.cpp shareaza/*.h` shows the declaration, the registration, the two listener gates, the `ConnectTo` gate, the `AcquireLocalAddress` gate and the host-loop gate. `grep -n 'm_pHost.sin_addr, 16' shareaza/G2Neighbour.cpp` prints nothing.
- [ ] **Step 10: Commit** `feat(network): add Connection.EnableIPv6, off by default`, body listing the gates, the two fixes on the IPv6 path by class and function, and the caller check of step 4.

### Task 4: Profile serving off covers every profile path

**Files:**
- Modify: `shareaza/LocalSearch.cpp:1015-1024` (`CLocalSearch::CreatePacketG2`, the `UPRO/NICK` block)
- Modify: `shareaza/G2Packet.cpp:1328-1345` (`CG2Packet::OnCrawlRequest`, nick and GPS)
- Modify: `shareaza/G2Neighbour.cpp:1752-1765` (`CG2Neighbour::OnProfileChallenge`)
- Modify: `shareaza/ChatSession.cpp:1017-1025` (`CChatSession::OnProfileChallenge`)
- Modify: `shareaza/UploadTransferHTTP.cpp:1015-1024` (`X-Nick` on responses)
- Modify: `shareaza/DownloadTransferHTTP.cpp:421-431` (`X-Nick` on requests)

**Interfaces:** consumes the existing `Settings.Community.ServeProfile` (`bool`, default `true`).

- [ ] **Step 1: Gate each writer on `Settings.Community.ServeProfile`.** Hits omit the whole `UPRO` child; crawl answers leave the nick and GPS empty but still answer; both `OnProfileChallenge` handlers return `TRUE` without sending; both `X-Nick` headers are omitted. The chat `X-Nickname` header (`ChatSession.cpp:485-489`) stays as it is.
- [ ] **Step 2: Check the unchanged cases (Review Focus 4).** With `ServeProfile` on, each edited function sends exactly what it did before. Each gate wraps the existing code without reordering writes. With an empty nick, the hit still omits `UPRO` as today.
- [ ] **Step 3: Search for other writers.** `grep -n 'MyProfile.GetNick\|MyProfile.GetXML\|MyProfile.GetPackedGPS\|GetNick()' shareaza/*.cpp`. Gate any other G2 or HTTP writer the same way. Leave ED2K, DC, IRC and the chat nickname alone, and list what was left and why in the commit body.
- [ ] **Step 4: Verify.** For every file under Files, `grep -n 'ServeProfile'` shows the new gate.
- [ ] **Step 5: Commit** `fix(profile): keep the nickname, location and profile private when profile serving is off`.

### Task 5: Documentation

**Files:**
- Modify: `docs/SECURITY-AUDIT.md`: status paragraph (`:13-22`), "as written, apart from" sentence (`:24-30`), finding 4 (`:131-143`), MiniUPnPc `Fixed` (`:163`), prebuilt packages `Fixed` (`:176`), Sentry `Fixed` (`:202`), update check `Fixed` (`:209`), the BugSplat Low item (`:189-196`), the second addendum's table (`:312-316`)
- Modify: `docs/ORACLE.md:228` (BugSplat) and the "HTTPS in the fork" area (add the IPv6 setting)

**Interfaces:** cites the commits of Tasks 1-4 by hash.

- [ ] **Step 1: Audit.** Add a **Fixed** line for finding 4's opt-out (Task 3's commit) and for the BugSplat item (Task 1's commit). Add a "Status, 2026-11-08" sentence saying all five findings are now fixed in the fork. Change the four "Fixed on 2026-10-27" dates of the items fixed by PR #19 and #20 to 2026-11-07, and add PR #16 to the second addendum's table. Extend the "as written, apart from" sentence to name the new **Fixed** lines and correct its date.
- [ ] **Step 2: ORACLE.md.** Drop BugSplat from line 228's text. Add one bullet saying `Connection.EnableIPv6` is off by default from previ.5 on, and that the oracle runs IPv4 only either way.
- [ ] **Step 3: Verify.** `grep -n '2026-10-27' docs/SECURITY-AUDIT.md` shows no **Fixed** line for #19 or #20 work. `grep -n -i bugsplat docs/ORACLE.md` prints nothing. The text names no packet, field or input for finding 3.
- [ ] **Step 4: Commit** `docs: record the previ.5 privacy changes in the audit and the oracle guide`.

### Task 6: Oracles can test an unreleased build, and check IPv6 and BugSplat

**Files:**
- Modify: `docs/oracle-windows/Install-Shareaza.ps1` (new `-InstallerDir` parameter)
- Modify: `docs/oracle-windows/README.md` (document it)
- Modify: `.github/workflows/oracle-windows.yml`
- Modify: `.github/workflows/oracle-wine.yml:36-39,85` and its check step (`:245-251`)

**Interfaces:**
- Produces: `Install-Shareaza.ps1 -Client Fork -InstallerDir <folder>`, where the folder holds one `*_x64_Release_*.exe` and a `SHA256SUMS.txt` naming it. It is mutually exclusive with `-ReleaseTag`. The pinned-hash table applies only to `-ReleaseTag`.
- Produces: workflow input `build_run` on `oracle-windows.yml`, the ID of a `release.yml` run.
- Consumes: `Connection\EnableIPv6` (`DWORD`) from Task 3.

- [ ] **Step 1: `Install-Shareaza.ps1 -InstallerDir`.** Reuse the existing `SHA256SUMS.txt` parsing: exactly one x64 Release line, plain file name, hash verified with `Get-FileHash`, else throw. Document it in the README.
- [ ] **Step 2: Workflow input and download.** Add the `build_run` input and `actions: read` to the job's permissions. A step before installing runs only when `build_run` is set and the client is `Fork`: `gh run download <build_run> -R $GITHUB_REPOSITORY -n "Shareaza Windows x64 Release" -D build`, with `GH_TOKEN: ${{ github.token }}`. The install step passes `-InstallerDir build` in that case, else `-ReleaseTag` as today.
- [ ] **Step 3: Expected strings from the installed version.** Matrix rows hold templates: the Fork row has `expect: client=RAZI{version}&` and `agent: iShareaza {version}`, and the Official row keeps literals. The install step records `Get-InstalledVersion` (from `OracleCommon.ps1`) into `$env:GITHUB_ENV` as `CLIENT_VERSION`. The check step replaces `{version}` before matching.
- [ ] **Step 4: Capability detection.** After installing, set `HAS_IPV6_SETTING=1` in `$env:GITHUB_ENV` when `Shareaza.exe` contains the UTF-16LE bytes of `EnableIPv6` (`[Text.Encoding]::Unicode.GetBytes('EnableIPv6')`, searched in `[IO.File]::ReadAllBytes`). Otherwise set it to 0 and print a notice that the IPv6 checks are skipped for this build. This is the case for the official client and previ.4.
- [ ] **Step 5: BugSplat check.** In the install step, when `HAS_IPV6_SETTING` is 1, fail if `Get-ChildItem "$app\BugSplat*","$app\BsSndRpt*"` finds anything.
- [ ] **Step 6: Socket check in `run-client.ps1`.** Add a `[switch] $ExpectIPv6` parameter. While the client runs, after `Watch-Oracle.ps1`, when `HAS_IPV6_SETTING` is 1:
  - take the client's PID from `Get-Process -Name Shareaza`;
  - collect `Get-NetTCPConnection -State Listen -OwningProcess $pid` and `Get-NetUDPEndpoint -OwningProcess $pid`;
  - print both lists;
  - without `-ExpectIPv6`, fail if any `LocalAddress` contains `:`;
  - with it, fail unless both a TCP listener and a UDP endpoint have `LocalAddress` `::`.
- [ ] **Step 7: A third run with IPv6 on.** After "Run 2, as a hub", add a step that runs only when `HAS_IPV6_SETTING` is 1. It sets `HKCU:\Software\Shareaza\Shareaza\Connection` `EnableIPv6` = 1 as a `DWORD`, then runs `.\run-client.ps1 -Name ipv6 -ExpectIPv6` with a 10-minute timeout. The existing restore removes the value with the rest of the oracle settings. Check that the check step's "two runs" count still holds: it requires at least two queries, so a third is fine.
- [ ] **Step 8: Wine workflow.** The previ row gets `expect: client=RAZI{version}&` and `agent: iShareaza {version}`. The version comes from the downloaded installer's name (`iShareaza_<version>_x64_Release_<date>.exe`, the `exe` variable at `:85`) and is written to `$GITHUB_ENV`. The check step substitutes it. The sf row keeps literals.
- [ ] **Step 9: Verify syntax locally.** Run `python3 -c "import yaml,sys;[yaml.safe_load(open(f)) for f in sys.argv[1:]]" .github/workflows/oracle-windows.yml .github/workflows/oracle-wine.yml`; it exits 0. `actionlint` too if it is installed.
- [ ] **Step 10: Commit** `ci(oracle): test unreleased builds, read the expected version, check IPv6 listeners and BugSplat files`.

### Task 7: Review, open pull request A, gather evidence

- [ ] **Step 1: Review package.** `git diff main..prev-i/privacy > /tmp/previ5/review-a.diff`. Dispatch `reviewer` with the path, the spec and this plan. Name four review items: trigger disclosure; every `ConnectTo(IN6)` caller handling `FALSE`; `[InstallDelete]` pattern precision; profile behaviour unchanged with `ServeProfile` on. Fix what it finds, then re-review if the fixes are not trivial.
- [ ] **Step 2: Push and open the pull request** against `main`, with a body summarising the four changes, the owner's manual checks (BugSplat files gone after upgrading over previ.4; partial sharing stays off across an upgrade; a second client sees no nickname with profile serving off) and the evidence runs.
- [ ] **Step 3: Build an unreleased installer.** `gh workflow run release.yml -R Prev-I/Shareaza --ref prev-i/privacy`, then wait for it. It must succeed and must not publish anything.
- [ ] **Step 4: Run the Windows oracle on it.** `gh workflow run oracle-windows.yml -R Prev-I/Shareaza --ref prev-i/privacy -f build_run=<run id>`. Expected: both legs pass. The Fork log shows no IPv6 listener in the leaf and hub runs, both IPv6 listeners in the ipv6 run, and no BugSplat file.
- [ ] **Step 5: Confirm the pull request's own checks pass.** These are MSBuild, both oracles against previ.4 with the IPv6 checks skipped, and TLS tests if triggered. Add the run links to the pull request body.
- [ ] **Step 6: Hand over to the owner** for their Windows checks and the merge.

---

## Pull request B: `prev-i/version-2.7.11`

Start only after A is merged: `git checkout -b prev-i/version-2.7.11 origin/main`.

### Task 8: Version 2.7.11.0 and the update check on the fork

**Files:**
- Modify: `shareaza/Shareaza.rc:272-273,291,296`
- Modify: `shareaza/Shareaza.h:456,458` (`WEB_SITE`, `URI_UPDATE`)
- Modify: `setup/scripts/main.iss:172` (`AppUpdatesURL`)
- Modify: `shareaza/Settings.cpp:35` (`SMART_VERSION`) and `CSettings::SmartUpgrade`, before `:1221`

**Interfaces:** consumes Task 2: the forced `SharePartials` line must already be gone from `SmartUpgrade`.

- [ ] **Step 1: Precondition.** `grep -n 'Uploads.SharePartials = true' shareaza/Settings.cpp` prints nothing. If it prints a line, stop: A has not merged.
- [ ] **Step 2: Version and URLs.** `FILEVERSION 2,7,11,0`, `PRODUCTVERSION 2,7,11,0`, `"FileVersion", "2.7.11.0"`, `"ProductVersion", "2.7.11.0"`. Set `URI_UPDATE` and `WEB_SITE` to the values in Global Constraints, and `AppUpdatesURL` to the website value.
- [ ] **Step 3: Migration (Review Focus 5).** `SMART_VERSION` becomes 62, and `SmartUpgrade` gains `if ( General.SmartVersion < 62 ) SetDefault( &VersionCheck.UpdateCheckURL );`, following the `eDonkey.ServerListURL` line at `:1161-1164`, with a comment that the update check moved to the fork in 2.7.11.0.
- [ ] **Step 4: Verify.** `grep -rn '2,7,10,6\|"2.7.10.6"' shareaza/Shareaza.rc` prints nothing. `grep -n 'ansani' shareaza/Shareaza.h setup/scripts/main.iss` prints no update or website URL.
- [ ] **Step 5: Commit** `feat: version 2.7.11.0, with the update check on this fork`.
- [ ] **Step 6: Review and open.** Write the diff to `/tmp/previ5/review-b.diff`, dispatch `reviewer` with it, apply the findings, then push and open the pull request. Its MSBuild must pass. The oracles still install previ.4 and read its version, so they pass unchanged.

---

## Release and after (once B is merged, and with the owner's go-ahead to tag)

### Task 9: Release v2.7.11.0-previ.5 and point the kits at it

- [ ] **Step 1: Tag** `git tag -a v2.7.11.0-previ.5 -m 'Shareaza 2.7.11.0, Prev-I fork build 5' <main head>` and push the tag. Wait for `release.yml`. The draft's x64 asset must be named `iShareaza_2.7.11.0_x64_Release_<date>.exe`.
- [ ] **Step 2: Release notes** above the generated ones. Cover:
  - BugSplat removed;
  - IPv6 off by default, what that costs a user with working IPv6, and where to turn it on;
  - partial sharing no longer forced on, and users who had turned it off should check it once;
  - profile serving off now covers search results, crawls, profile requests and headers;
  - the update check now asks this fork.

  Review the notes for trigger disclosure, then publish as latest.
- [ ] **Step 3: Oracles against the release.** Dispatch both oracle workflows with `release_tag=v2.7.11.0-previ.5`. Both must pass. The Windows Fork leg now runs the IPv6 and BugSplat checks from the release itself.
- [ ] **Step 4: Kits pull request** on `prev-i/kits-previ5`, as PR #22 did:
  - set the default tag in `oracle-windows.yml` and `Install-Shareaza.ps1`;
  - pin the x64 SHA-256 from the release's `SHA256SUMS.txt`;
  - update the current release and the download lines in `ORACLE.md`.

  Have the reviewer check it, then open it.
- [ ] **Step 5: Records.** In the workspace's `docs/shareaza-audit/README.md`, add a dated status line for previ.5. Update the memory note for the fork.
