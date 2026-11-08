# previ.6 follow-ups and version 2.7.11.1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship previ.6 (2.7.11.1): working Help-menu links, correct version bytes on the wire, two IPv6 refinements, clearer oracle checks, an accurate README with credits, then the version bump the owner uses to test the update check.

**Architecture:** Two pull requests into `main`, as for previ.5. A (`prev-i/followups`, which already holds the design) carries Tasks 1-6; B (`prev-i/version-2.7.11.1`) carries Task 8 after A merges.

**Tech Stack:** C++/MFC (v143), skin XML, GitHub Actions (Windows PowerShell 5.1), Markdown.

**Spec:** `docs/superpowers/specs/2026-11-08-previ6-followups-design.md`

## Global Constraints

- No local build and no unit-test harness. Each task's test is a check script in the plan workspace, run before the change (it must fail) and after it (it must pass). CI's MSBuild and the oracles are the real gate (Task 7).
- Original-site base: `https://shareaza.sourceforge.net/`. Wiki base: `https://shareaza.sourceforge.net/mediawiki/`. Fork home: `https://github.com/Prev-I/Shareaza`. `WEB_SITE` stays `https://github.com/Prev-I/Shareaza/releases`.
- Version 2.7.11.1, tag `v2.7.11.1-previ.6`. `SMART_VERSION` stays 62.
- Commit messages, pull request bodies and release notes describe changes by class and function; the reviewer checks trigger disclosure as a named item. Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Every coding change gets a `reviewer` pass before its pull request.

## Review Focus

1. **A skin that still lists the removed items** (Skin+): its menu must not show dead or disabled entries. Owned by Task 1.
2. **Version numbers above 35** in the peer ID: no BEP 20 character exists; the encoder must not emit punctuation. Owned by Task 2.
3. **A user-typed IPv6 address with IPv6 off:** the log names the address and the reason at a visible level. Owned by Task 3.
4. **An HTTP download source given by host name** (no address yet): it must not be skipped as IPv6-only. Owned by Task 3.
5. **The oracle's outgoing-connection check on a runner:** loopback and IPv4 connections must not count as IPv6. Owned by Task 4.

---

### Task 1: Help menu

**Files:**
- Modify: `shareaza/Shareaza.h:454-495` (constants and the URL table comment)
- Modify: `shareaza/WndMain.cpp:180-184` (message map), `:2858-2990` (handlers); `shareaza/WndMain.h:208-212`
- Modify: `shareaza/Res/Default.xml:547-548, 654-655, 753-754`; `Skins/Skin+/Skin+.xml:270-271`
- Modify: `shareaza/PageSettingsSkins.cpp:465`, `shareaza/PageSettingsPlugins.cpp:203` (add-ons page)

**Interfaces:** Produces `ORIGINAL_SITE_T` (`_T("https://shareaza.sourceforge.net/")`), `ORIGINAL_WIKI_T` (`ORIGINAL_SITE_T _T("mediawiki/")`) and `FORK_HOME_T` (`_T("https://github.com/Prev-I/Shareaza")`) in `Shareaza.h`.

- [ ] **Step 1: Check script** `check-task1.sh` asserts:
  - no `help/` path is appended to `WEB_SITE` in `WndMain.cpp`;
  - `ID_HELP_WEB_1` and `ID_HELP_WEB_2` appear in no `<item` of `Res/Default.xml` or `Skins/Skin+/Skin+.xml`;
  - `OnHelpWeb1` to `OnHelpWeb5` are gone from `WndMain.cpp` and `WndMain.h`;
  - each wiki page name from the spec appears in `WndMain.cpp`;
  - `kirurusec` appears nowhere in `shareaza/`.

  Run it: FAIL.
- [ ] **Step 2: Constants.** Add the three constants. `CONNECTION_SITE_T` becomes `ORIGINAL_SITE_T _T("help/test/")`. Rewrite the URL table comment to the new targets.
- [ ] **Step 3: Handlers.**
  - FAQ, Guide, Router, Security, Codec and Torrent open `ORIGINAL_WIKI_T` plus `FAQ`, `QuickGuide`, `FAQ.FirewallsRouters`, `FAQ.Security`, `Troubleshoot.VideoCodec` and `BitTorrent`.
  - Forums opens `ORIGINAL_SITE_T _T("phpbb/")`.
  - Web6 opens `https://www.deviantart.com/search?q=shareaza%20skin`.
  - Homepage opens `FORK_HOME_T`; Update ("Latest news") opens `WEB_SITE_T`.
  - Connection test keeps its query string on the new base.
  - Delete `OnHelpWeb1` to `OnHelpWeb5`, with their message-map lines and declarations.
- [ ] **Step 4: Add-ons page.** Both settings pages open `ORIGINAL_SITE_T _T("?id=addon&Version=")` plus the version.
- [ ] **Step 5: Menus.** Remove the `ID_HELP_WEB_1` and `ID_HELP_WEB_2` items from the three Help menus in `Res/Default.xml` and from `Skin+.xml` (Review Focus 1). Leave the `<image id1=...>` icon aliases.
- [ ] **Step 6: Run the check:** PASS.
- [ ] **Step 7: Commit** `fix(help): point the Help menu at pages that exist`.

### Task 2: Version bytes on the wire

**Files:** `shareaza/DownloadWithTorrent.cpp:595-598`, `shareaza/EDClient.cpp:878-880`, `shareaza/EDNeighbour.cpp:690-692`

**Interfaces:** Produces `static BYTE VersionDigit(WORD n)` in `DownloadWithTorrent.cpp`, returning `'0'+n` for 0-9, `'A'+n-10` for 10-35, and `'Z'` above 35 (Review Focus 2).

- [ ] **Step 1: Check script** `check-task2.sh` asserts:
  - the peer ID is built with `VersionDigit` for all four parts;
  - no `'0' + theApp.m_nVersion` remains;
  - both eD2k encoders use `min(...,7)` or an equivalent cap, not `& 0x07`.

  Also check the encoder's arithmetic: compile a copy of `VersionDigit` with `g++` in the workspace and assert 9→'9', 10→'A', 11→'B', 35→'Z', 36→'Z'. Run: FAIL.
- [ ] **Step 2: Implement** `VersionDigit` and use it for bytes 3-6.
- [ ] **Step 3: eD2k.** Cap the third number at 7 in both encoders, with a comment that the field has three bits.
- [ ] **Step 4: Run the check:** PASS.
- [ ] **Step 5: Commit** `fix(bt,ed2k): encode version numbers above 9 the way decoders read them`.

### Task 3: IPv6 refinements

**Files:**
- Modify: `shareaza/Connection.cpp:376-380` (the refusal in `CConnection::ConnectTo(const IN6_ADDR*, WORD)`)
- Modify: `shareaza/DownloadSource.cpp:566` (`CDownloadSource::CanInitiate`)

**Interfaces:** consumes `Settings.Connection.EnableIPv6` and `CDownloadSource::IsIPv6Source()`.

- [ ] **Step 1: Check script** `check-task3.sh` asserts:
  - `CanInitiate` returns `FALSE` for `IsIPv6Source()` when the setting is off;
  - the refusal in `ConnectTo(IN6)` logs at `MSG_INFO` or above, with the address and the setting name.

  Run: FAIL.
- [ ] **Step 2: Refusal log.** Log at `MSG_NOTICE` with the address and "IPv6 is off (Connection.EnableIPv6)". A refused automatic connect costs one line, and that is the price of the user seeing a typed address refused. Changing the callers' failure messages is out of scope.
- [ ] **Step 3: Skip IPv6-only sources.** At the top of `CanInitiate`, after the network check: `if ( ! Settings.Connection.EnableIPv6 && IsIPv6Source() ) return FALSE;`.
  - `IsIPv6Source()` is true only with no IPv4 address and a non-zero IPv6 one, or with an IPv6 transfer. A source known only by host name has neither, so it is not skipped (Review Focus 4).
  - `IsIPv6Source` asserts the transfers lock on its transfer branch. Confirm `CanInitiate`'s callers hold it, and record the caller list in the commit body.
- [ ] **Step 4: Run the check:** PASS.
- [ ] **Step 5: Commit** `fix(network): skip IPv6-only download sources and log refused IPv6 connects with IPv6 off`.

### Task 4: Oracle checks

**Files:** `.github/workflows/oracle-windows.yml:186-200` (run-client socket check), `:273, :289, :293` (messages)

- [ ] **Step 1: Check script** `check-task4.sh`:
  - lint and parse, as in the previ.5 Task 6 check;
  - assert no "two runs" or "the hub run" message remains;
  - assert the off branch reads `Get-NetTCPConnection -OwningProcess` without `-State Listen`.

  Run: FAIL.
- [ ] **Step 2: Messages.** "expected a query from each run", "the last run did not listen…", "the last run did not finish…".
- [ ] **Step 3: Outgoing connections.** In the off branch, add every TCP connection of the process, in any state, to the set checked for `:`. IPv4 and loopback addresses contain no colon (Review Focus 5). Print the count checked.
- [ ] **Step 4: Run the check:** PASS.
- [ ] **Step 5: Commit** `ci(oracle): clearer check messages, and check outgoing connections with IPv6 off`.

### Task 5: Oracle guide warning box

**Files:** `docs/ORACLE.md:19-26`

- [ ] **Step 1: Check script** `check-task5.sh` asserts the crash line says "fixed from `previ.2` on". The ban-list line must say "fixed from `previ.2` on, and IPv6 is opt-in from `previ.5`". The added text names no packet or input. Run: FAIL.
- [ ] **Step 2: Edit** those two bullets only. Keep the existing wording otherwise.
- [ ] **Step 3: Run:** PASS. **Commit** `docs: mark the fixed findings in the oracle guide's warning`.

### Task 6: README

**Files:** `README.md` (whole file)

- [ ] **Step 1: Check script** `check-task6.sh` asserts:
  - no `gzip.exe`, `DirectX` or `QuickStart` remains;
  - `Inno Setup 6`, `v143`, `ATL`, `MFC` and `release.yml` appear;
  - all three credit links appear: `sourceforge.net/p/shareaza/code`, `github.com/ivan386/Shareaza`, `github.com/ansani/Shareaza`.

  Run: FAIL.
- [ ] **Step 2: Rewrite.**
  - A one-paragraph intro: this fork, its purpose, and a link to the releases.
  - **History and credits:** the original SourceForge project and its Subversion repository, ivan386's 2013 import of SVN build 9329, and ansani's continuation, which this fork is a fork of.
  - **Building:**
    - Visual Studio 2022 with the C++ desktop workload and the v143 ATL and MFC libraries; not the VS 2026 images;
    - Inno Setup 6, 6.3 or later, in its default folder;
    - NuGet restore, then open `vc143\Shareaza.sln`;
    - the installer lands in `setup\builds`;
    - `.github/workflows/release.yml` is the reference setup.
  - **What is no longer needed:** gzip.exe, since `7z.cmd` uses Windows PowerShell; the DirectX SDK; the QuickStart Pack.

  Keep the existing note about building x64 on 32-bit Windows.
- [ ] **Step 3: Run:** PASS. **Commit** `docs: bring the README's build steps up to date and credit the earlier work`.

### Task 7: Review, pull request A, evidence

- [ ] **Step 1:** Write the diff and the commit messages to the workspace. Dispatch `reviewer` with the spec, this plan, the Review Focus and the named item. Fix Critical and Important findings with a check that fails first, and ledger the minors.
- [ ] **Step 2:** Push and open pull request A.
- [ ] **Step 3:** Dispatch `release.yml` on the branch, then `oracle-windows.yml -f build_run=<id>`. Both legs must pass, and the off runs must print the outgoing-connection count.
- [ ] **Step 4:** All pull request checks pass. Hand over to the owner.

### Task 8: Version 2.7.11.1 (pull request B, after A merges)

**Files:** `shareaza/Shareaza.rc:272-273, 291, 296`

- [ ] **Step 1: Check script:** the four version places read 2.7.11.1, and `SMART_VERSION` is still 62. Run: FAIL. Edit. Run: PASS.
- [ ] **Step 2: Commit** `feat: version 2.7.11.1`. Have the reviewer check it, push, open the pull request, and get MSBuild green.

### Task 9: Release (after B merges)

- [ ] Tag `v2.7.11.1-previ.6`, then wait for the draft.
- [ ] Run the Windows oracle on the draft's artifact.
- [ ] Write the release notes and have the reviewer check them for trigger disclosure and accuracy, then publish as latest.
- [ ] Run both oracles against the release.
- [ ] Open the kits pull request: default tag, pinned hash, `ORACLE.md` lines and client-string row.
- [ ] Update the workspace disclosure record and memory.
