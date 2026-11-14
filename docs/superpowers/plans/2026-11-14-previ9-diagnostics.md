# previ.9 local diagnostics and bounded datagram pass: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the next hub hang or crash leave a local dump and log lines that name the stuck thread, publish matching PDBs with every release, and bound the datagram receive pass.

**Architecture:** Three pull requests into `main`. A (`prev-i/previ9-symbols`, which also carries the design and this plan) changes only the release workflows and docs, so it can be dry-run with `workflow_dispatch` before anything is published. B (`prev-i/previ9-diagnostics`) adds a pure, header-only hang detector tested with g++, a Win32 diagnostics module tested by a Windows console program on CI, and the wiring into the client. C (`prev-i/previ9-datagram-bound`) bounds `CDatagrams::OnRun`. The previ.9 release itself, and the other previ.9 backlog items, are outside this plan.

**Tech Stack:** C++/MFC (v143, `_WIN32_WINNT 0x0601`), Win32 `dbghelp` (`MiniDumpWriteDump`), GitHub Actions, g++ for the header-only unit tests.

**Spec:** `docs/superpowers/specs/2026-11-14-local-hang-diagnostics-design.md`

## Global Constraints

- **Local only.** No network call, no upload, no third-party crash service. Nothing in the client opens a connection for diagnostics.
- **Off by default.** `General.Diagnostics` defaults to `false`; with it off the client installs no exception filter, starts no watchdog thread, loads no `dbghelp`, and creates no folder.
- **Values from the spec:** stall threshold 30 s (setting, range 10–600 s); reminder every 5 minutes; one dump per episode; keep the 5 most recent dumps, crash and hang together; folder `<UserPath>\Data\Diagnostics\`; lock-timeout lines at `MSG_DEBUG`, at most one per site per minute with the suppressed count.
- **`dbghelp.dll`** is loaded only by full path from `GetSystemDirectoryW()` (the installer deletes the app-folder copy; no search-path loading).
- **Owner tracking** in release builds for `Network.m_pSection` only. Every other section keeps its type.
- **Watchdog never takes** `Network.m_pSection`, `theApp.m_csMessage` (except by `TryEnterCriticalSection`), or any other section a stalled thread may hold; it never suspends threads or walks stacks.
- **Testing.** No Windows build here. Header-only logic gets g++ unit tests run here and on CI; Win32 code gets `DiagTest`, a console program built and run by a CI workflow on `windows-2022`; anything else gets a check script in `.superpowers/sdd/2026-11-14-previ9/` (git-ignored), run before the change (FAIL) and after (PASS). CI MSBuild and the oracles are the real gate.
- **Commits** are conventional, English, atomic, and end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- **Disclosure.** Commit messages, PR texts, release notes and docs describe the datagram change as a missing bound in `CDatagrams::OnRun`, never which input reaches it or how to cause it. The reviewer checks trigger disclosure as a named item on every PR.
- **Outward steps** (push, opening PRs, dispatching workflows, tagging) wait for the owner's go. After a PR is handed over, push nothing more to it.

## Review Focus

1. **Clock and sampling irregularities:** the watchdog thread itself delayed (machine asleep, debugger break) so two samples are minutes apart. Expect no false stall from a single late sample: a stall needs the condition observed across samples covering the threshold, measured with `GetTickCount64`. Owned by Task 2 (test `late sample after sleep is not a stall`).
2. **Network thread restarting** (disconnect then reconnect) during or between episodes: a new thread ID and a heartbeat that restarts must not read as a stall, and an episode whose thread died ends. Owned by Task 2 (tests `thread gone ends heartbeat stall`, `thread restart is not a stall`).
3. **Diagnostics folder unwritable or full:** dump creation fails. Expect one log line saying so per episode, no retry loop, no crash. Owned by Task 4 (DiagTest case `unwritable folder`).
4. **Crash on a thread with an exhausted stack:** the dump must still be written. Owned by Task 4 (DiagTest case `--crash-stack-overflow`).
5. **Non-dump files in the folder** (a user's notes, a renamed dump): retention deletes only files matching the dump name pattern. Owned by Task 2 (test `retention ignores foreign files`).

---

## Pull request A: `prev-i/previ9-symbols`

Create the branch from `main`; commit the design and this plan first (`docs: design and plan for previ.9 local diagnostics`).

### Task 1: PDBs built, archived, hashed, attested and documented

**Files:** Modify `.github/workflows/release.yml`, `.github/workflows/verify-release.yml`, `docs/RELEASING.md`; Modify `shareaza/Shareaza_143.vcxproj` and the shipped plugin/library projects only if they do not already emit full PDBs in Release; Create `docs/DIAGNOSTICS.md`.

**Interfaces:** Produces, per platform, a release asset `<installer basename>_symbols.zip` (e.g. `iShareaza_2.7.11.4_x64_Release_2026-11-20_symbols.zip`) holding the PDBs of every binary the solution builds and the installer ships, flat, plus `SHA256SUMS.txt` lines for it.

- [ ] **Check script** `check-task1.sh` asserts:
  - each Release configuration of `Shareaza_143.vcxproj` and of every project whose output `setup/scripts/main.iss` installs has `GenerateDebugInformation` true (explicitly or by the toolset default; the script states which) and `/Zi`-style debug info;
  - the build job collects the PDBs next to the installer into the zip named above, before *Compute SHA-256 manifest*, and that step hashes `*.exe *.zip`;
  - the upload step's `path` includes the zip;
  - *Verify and merge SHA-256 manifests* copies and counts `*.zip` like `*.exe` and hashes both;
  - the attest step's `subject-path` covers `dist/*.exe` and `dist/*.zip`; the release step uploads both;
  - `verify-release.yml` runs `gh release verify-asset` and `gh attestation verify` for every asset in `SHA256SUMS.txt`, not only installers;
  - `docs/RELEASING.md`'s asset contract names the symbols archive;
  - `docs/DIAGNOSTICS.md` has sections *Turning diagnostics on* (the two settings, under Tools → Settings → Advanced, effective at next start), *Where files go* (`<UserPath>\Data\Diagnostics\`, the 5-dump limit, `Diagnostics.log`, that dumps may contain peer addresses and search terms, that uninstall treats them like other user data), *Taking a dump by hand* (Task Manager → Create dump file; ProcDump `-ma`), *Opening a dump* (WinDbg/Visual Studio, symbol path `<extracted zip>;srv*<cache>*https://msdl.microsoft.com/download/symbols`, `~*k` to list all stacks);
  - `actionlint` passes.

  Run: FAIL.
- [ ] **Edit** to satisfy it. The zip is built in the build job, from the same build that fed ISCC.
- [ ] **Run:** PASS. **Commit:** `ci: publish symbols with each release` and `docs: how to turn on, find and read local diagnostics`.

### Task A-end: Review, dry run, pull request A

- [ ] Whole-diff `reviewer` pass on `main..prev-i/previ9-symbols` (diff written to a scratch file), trigger disclosure named. Fix, re-run the check.
- [ ] After the owner's go: push; `gh workflow run release.yml --ref prev-i/previ9-symbols`. Expected: both artifacts contain the installer, the symbols zip and a `SHA256SUMS.txt` with both lines; `sha256sum -c` passes on each downloaded artifact; in the zip, `Shareaza.pdb` exists and `Shareaza.exe`'s debug directory GUID/age (from the installer's extracted exe, `dumpbin /headers` on a Windows runner or `llvm-readobj --coff-debug-directory` here) equals the PDB's. Record the result in the PR.
- [ ] After the owner's go: open PR A, hand it over.

## Pull request B: `prev-i/previ9-diagnostics` (from `main` after A merges)

### Task 2: Header-only hang detector, retention and rate limiter

**Files:** Create `shareaza/HangDetector.h`, `tests/diagnostics/test_hang_detector.cpp`, `.github/workflows/diagnostics-test.yml`

**Interfaces:** Produces, in `namespace Diag`, no MFC or Win32 dependency, C++14:

- `enum HangKind : unsigned { HangNone = 0, HangHeartbeat = 1, HangSection = 2 };`
- `struct HangSample { uint64_t nowMs; uint32_t heartbeat; uint32_t networkThreadId; uint32_t sectionOwner; uint32_t sectionAcquisitions; };` — `networkThreadId` 0 means no network thread; `sectionOwner` 0 means free.
- `struct HangEvent { enum Type { Nothing, Started, KindAdded, Reminder, Ended } type; unsigned kinds; uint64_t durationMs; uint32_t ownerThreadId; };`
- `class HangDetector { public: HangDetector(uint64_t thresholdMs, uint64_t reminderMs); HangEvent Sample(const HangSample& s); };` — a kind is stalled when its signal (heartbeat value for a given `networkThreadId`; owner plus acquisitions for the section) has not changed between samples spanning at least `thresholdMs`, and no gap between consecutive samples exceeds `thresholdMs / 2`; a larger gap restarts the observation. `Started` once per episode; `KindAdded` when a second kind joins; `Reminder` every `reminderMs` after `Started`; `Ended` when no kind is stalled, with the episode's duration.
- `std::wstring DumpFileName(const std::wstring& stampYmdHms, const wchar_t* kind, const std::wstring& version);` → `<YYYYMMDD-HHMMSS>-<kind>-<version>.dmp`; `kind` is `L"crash"` or `L"hang"`.
- `std::vector<std::wstring> DumpsToDelete(std::vector<std::wstring> names, size_t keep);` — only names matching `^\d{8}-\d{6}-(crash|hang)-[^\\/]+\.dmp$`, oldest first, beyond `keep`.
- `class RateLimiter { public: bool Allow(uint64_t nowMs, uint32_t& suppressed); };` — lock-free (`std::atomic`); true at most once per 60 000 ms, then `suppressed` is the count refused since the last true.

- [ ] **Write the failing tests** (`Expect`/`ExpectTrue` as in `tests/release-notes`), samples every 1000 ms unless stated, threshold 30 000, reminder 300 000:
  - `healthy`: heartbeat +1 each sample, section free, 120 samples → all `Nothing`.
  - `heartbeat flat 29 s` → `Nothing`; `heartbeat flat 30 s` → `Started`, `kinds == HangHeartbeat`.
  - `no network thread`: `networkThreadId == 0`, heartbeat flat 60 s → `Nothing`.
  - `section held 30 s`: owner 7, acquisitions 41 constant → `Started`, `kinds == HangSection`, `ownerThreadId == 7`.
  - `section re-taken`: owner 7, acquisitions +1 each sample, 60 s → `Nothing`.
  - `owner changes`: owner alternates 7/9, acquisitions constant → `Nothing`.
  - `both kinds one episode`: both stalled from t=0 → exactly one `Started` with `kinds == 3`; heartbeat stalled at t=0 and section at t=10 s → `Started` then `KindAdded`, never a second `Started`.
  - `reminders`: stall held 11 min → `Reminder` at 5 min and 10 min after `Started`, nothing in between.
  - `ended`: stall from t=0, cleared at t=95 s → `Ended`, `durationMs == 95000`; a new stall after that → `Started` again.
  - `thread gone ends heartbeat stall`: heartbeat stall started, then `networkThreadId` 0 → `Ended`.
  - `thread restart is not a stall`: thread id 100 → 200 with heartbeat restarting at 0 → `Nothing`.
  - `late sample after sleep is not a stall`: one gap of 120 s with unchanged heartbeat, then normal samples → `Nothing`.
  - `file name`: `DumpFileName(L"20261114-153000", L"hang", L"2.7.11.4")` == `L"20261114-153000-hang-2.7.11.4.dmp"`.
  - `retention`: 7 matching names (mixed crash/hang) → the 2 oldest; `retention ignores foreign files`: plus `notes.txt`, `old.dmp`, `20261114-153000-hang-x.dmp.bak` → those never returned.
  - `rate limiter`: true at 0, false ×3 within 60 s, true at 60 000 with `suppressed == 3`.
- [ ] **Run** `g++ -std=c++14 -Wall -Wextra -Werror -I shareaza -o /tmp/hd tests/diagnostics/test_hang_detector.cpp && /tmp/hd`: FAIL (no header).
- [ ] **Implement** `HangDetector.h`.
- [ ] **Run:** PASS. Add `diagnostics-test.yml` mirroring `release-notes-test.yml` (same pins, `contents: read`, paths `shareaza/HangDetector.h`, `shareaza/ReceiveBudget.h`, `tests/diagnostics/**`, the workflow), running every `tests/diagnostics/test_*.cpp`; actionlint passes.
- [ ] **Commit:** `feat: hang detector, dump retention and rate limiter (header-only)`.

### Task 3: Owner tracking for `Network.m_pSection` and the network heartbeat

**Files:** Modify `shareaza/StdAfx.h`, `shareaza/Network.h`, `shareaza/Network.cpp`

**Interfaces:** Produces:
- `class CMutexTracked : public CMutex` in all builds, with `BOOL Lock(DWORD)`, `BOOL Unlock()`, `volatile LONG m_nThreadId`, `volatile LONG m_nEnterCount`, `volatile LONG m_nAcquisitions` (incremented when `m_nEnterCount` goes 0 → 1). In `_DEBUG` builds `CMutexEx` stays as today; `ASSUME_LOCK(Network.m_pSection)` keeps compiling and checking in debug.
- `CNetwork::m_pSection` becomes `CMutexTracked`.
- `CNetwork::m_nHeartbeat` (`volatile LONG`), `InterlockedIncrement`ed in `OnRun` immediately after `Doze( 100 )`, before the `m_bLive` check.
- `DWORD CNetwork::GetRunningThreadId() const` — the network thread's ID while it runs, else 0.

- [ ] **Check script** `check-task3.sh` asserts: `CMutexTracked` is outside any `#ifdef _DEBUG`; `Network.h` declares `CMutexTracked m_pSection`; no other `m_pSection` changed type (`git diff` touches only `Network.h` among headers declaring sections); the increment is the first statement after `Doze( 100 );` in `CNetwork::OnRun`; `m_nAcquisitions` increments only on the 0 → 1 transition. Run: FAIL.
- [ ] **Implement.** CI's MSBuild (Debug and Release, Win32 and x64) must compile; any `CSingleLock`/`ASSUME_LOCK` use of `Network.m_pSection` that fails to compile is fixed at the call site, not by changing other sections.
- [ ] **Run:** PASS. **Commit:** `feat: track the owner of the network section in all builds; network loop heartbeat`.

### Task 4: Diagnostics module and `DiagTest`

**Files:** Create `shareaza/Diagnostics.h`, `shareaza/Diagnostics.cpp`, `DiagTest/DiagTest.cpp`, `DiagTest/DiagTest_143.vcxproj`, `.github/workflows/diag-test.yml`; Modify `shareaza/Shareaza_143.vcxproj` (+ `.filters`) to compile `Diagnostics.cpp`.

**Interfaces:** Consumes `HangDetector.h` (Task 2), `CMutexTracked` (Task 3). Produces, in `namespace Diagnostics` (no dependency on `theApp`, `CNetwork` or `Settings`, so `DiagTest` links it alone):
- `typedef void (*LogFn)(bool bError, LPCWSTR pszLine);` — called from the watchdog; must not block (the client passes a function using `TryEnterCriticalSection`, Task 5).
- `typedef DWORD (*ThreadIdFn)();`
- `bool Start(LPCWSTR pszFolder, LPCWSTR pszVersion, LogFn pfnLog);` — creates the folder, loads `<GetSystemDirectoryW()>\dbghelp.dll` by full path, installs the unhandled-exception filter. Returns false (and logs once) if `dbghelp` or `MiniDumpWriteDump` is missing; the client then runs without diagnostics.
- `bool Watch(const volatile LONG* pHeartbeat, const CMutexTracked* pSection, ThreadIdFn pfnNetworkThread, DWORD nThresholdMs);` — starts the watchdog thread (1000 ms samples, reminder 300 000 ms).
- `void Stop();` — stops the watchdog, removes the filter, frees `dbghelp`.
- Files: dumps via `Diag::DumpFileName`, retention via `Diag::DumpsToDelete(…, 5)` after each new dump; every watchdog line also appended to `<folder>\Diagnostics.log` (UTF-8, its own file handle, rotated to `Diagnostics.old.log` at 1 MB) *(designer's call: the watchdog's record must not depend on `m_csMessage`)*.
- Dump type: `MiniDumpWithDataSegs | MiniDumpWithHandleData | MiniDumpWithThreadInfo | MiniDumpWithUnloadedModules | MiniDumpWithProcessThreadData`.
- Crash path: the filter writes the dump from a fresh thread it creates and waits for (so a stack overflow still dumps), then returns `EXCEPTION_CONTINUE_SEARCH`.
- Log lines (English, fixed form): `Diagnostics: <kinds> stall started, network section held by thread <id>[ (<name>)] for <n> s; dump <file>` / `… still stalled after <n> s` / `… stall ended after <n> s` / `Diagnostics: could not write dump <file>: error <code>`. `<name>` from `CRazaThread`'s thread map only if `DiagTest` can be built without it; otherwise the ID alone *(implementer reports which)*.

- [ ] **Write `DiagTest`** (console, like `TlsTest`; exit 0 = pass), each case in a fresh temp folder, threshold 2000 ms:
  - `hang`: a thread holds a `CMutexTracked` 5 s while the heartbeat stays flat → exactly one `*-hang-*.dmp`; `Diagnostics.log` has one `stall started`, one `stall ended`; the dump's `ThreadListStream` (`MiniDumpReadDumpStream`) contains the holder's thread ID.
  - `re-taken`: a thread takes and releases the mutex every 100 ms for 6 s with heartbeat moving → no dump.
  - `retention`: folder pre-seeded with 5 dump-named files and `notes.txt`; one hang → 5 dump files remain, the oldest seeded one gone, `notes.txt` kept.
  - `unwritable folder`: folder ACL denies file creation → one `could not write dump` line, no second attempt in the episode, process healthy.
  - `--crash` (child process, `CreateProcess` on itself): `Start` then a null write → parent sees exit code `0xC0000005` and one `*-crash-*.dmp`.
  - `--crash-stack-overflow`: unbounded recursion → exit code `0xC00000FD` and one crash dump.
  - `not started`: no `Start` → no folder created, `GetModuleHandleW(L"dbghelp.dll")` is NULL (the test does not load it itself).
- [ ] **Add `diag-test.yml`** mirroring `tls-test.yml` (matrix x64 Release, Win32 Debug; paths `shareaza/Diagnostics.*`, `shareaza/HangDetector.h`, `DiagTest/**`, the workflow; `contents: read`).
- [ ] **Run** after the owner's go to push: `diag-test.yml` FAIL (no module).
- [ ] **Implement** `Diagnostics.cpp`.
- [ ] **Run:** `diag-test.yml` PASS on both matrix entries; MSBuild PASS. **Commit:** `feat: local crash dumps and a network stall watchdog, off by default`.

### Task 5: Settings and client wiring

**Files:** Modify `shareaza/Settings.h`, `shareaza/Settings.cpp`, `shareaza/Shareaza.h`, `shareaza/Shareaza.cpp`, `shareaza/Network.cpp`

**Interfaces:** Consumes Task 3 and Task 4. Produces:
- `Settings.General.Diagnostics` (`bool`, `Add( _T(""), _T("Diagnostics"), …, false )`) and `Settings.General.DiagnosticsHangSeconds` (`DWORD`, default 30, unit 1, min 10, max 600, suffix `_T(" s")`), next to `DebugLog`.
- `bool CShareazaApp::TryMessage(WORD nType, LPCTSTR pszLine)` — appends like `Message` but only if `TryEnterCriticalSection( &m_csMessage.m_sect )` succeeds; the `LogFn` given to `Diagnostics::Start` calls it with `MSG_ERROR` or `MSG_INFO`.
- In `InitInstance`, immediately after `Settings.Load()`: if `Settings.General.Diagnostics`, `Diagnostics::Start( UserPath + L"\\Data\\Diagnostics", <version string>, … )` then `Diagnostics::Watch( &Network.m_nHeartbeat, &Network.m_pSection, <fn returning Network.GetRunningThreadId()>, DiagnosticsHangSeconds * 1000 )`. In `ExitInstance`, `Diagnostics::Stop()` before networking and settings are torn down.

- [ ] **Check script** `check-task5.sh` asserts: the two `Add` lines with those values; `Start` is reached only under `Settings.General.Diagnostics`; `Start` comes after `Settings.Load()` and before `InitFonts()`; `Stop` is in `ExitInstance` before `Network` is cleared; `TryMessage` uses `TryEnterCriticalSection`; no other call to `Diagnostics::` exists; and, after reading `setup/scripts/main.iss`'s uninstall handling of the user's `Data` folder, that `Data\Diagnostics` gets the same treatment (deleted if user data is deleted, kept if it is kept), with the script printing which. Run: FAIL.
- [ ] **Implement.** **Run:** PASS; CI MSBuild PASS; both oracles PASS (diagnostics off, so their behaviour is unchanged).
- [ ] **Commit:** `feat: General.Diagnostics turns on local diagnostics at next start`.

### Task 6: Rate-limited lock-timeout lines

**Files:** Modify `shareaza/Network.h`, `shareaza/Network.cpp`, `shareaza/DiscoveryServices.cpp`

**Interfaces:** Consumes `Diag::RateLimiter` (Task 2). Produces `static void CNetwork::LogLockTimeout(Diag::RateLimiter& oLimiter, LPCTSTR pszSite)` (in `Network.cpp`, not in the `Diagnostics` module, which must not depend on `theApp`) — returns at once if `theApp.IsLogDisabled( MSG_DEBUG )`; else, if `Allow` passes, `theApp.Message( MSG_DEBUG, _T("Lock timeout: network section at %s (%u more suppressed)"), pszSite, suppressed )`. One `static Diag::RateLimiter` per site.

- [ ] **Check script** `check-task6.sh` lists every timed lock on `Network.m_pSection` in the two files (`oLock.Lock( <n> )`, `pLock.Lock( <n> )`, `Network.m_pSection.Lock( <n> )` and the `CSingleLock … TRUE`-less forms) and asserts each failing branch calls `LogLockTimeout` with a distinct site string `"<function>"`; asserts no such call in `Wnd*.cpp`. Run: FAIL.
- [ ] **Implement.** **Run:** PASS; MSBuild PASS.
- [ ] **Commit:** `feat: log network-section lock timeouts at debug level, rate-limited`.

### Task B-end: Review, pull request B, owner checks

- [ ] Whole-diff `reviewer` pass on `main..prev-i/previ9-diagnostics`, trigger disclosure named. Fix, re-run all checks and `diagnostics-test`/`diag-test`.
- [ ] After the owner's go: push, open PR B with the owner's manual checks: with the setting off, no `Data\Diagnostics` after a session; with it on and a restart, the folder exists, `Diagnostics.log` is empty or absent after hours of hub mode (no false stall); Task Manager shows no CPU from the watchdog; a Task Manager dump of that build (installer and symbols from `gh workflow run release.yml --ref prev-i/previ9-diagnostics`) opens in WinDbg per `docs/DIAGNOSTICS.md` and `~*k` shows `CNetwork::OnRun` by name on the network thread. CI green. Hand over.

## Pull request C: `prev-i/previ9-datagram-bound` (from `main`; independent of B)

### Task 7: Bounded datagram receive pass

**Files:** Create `shareaza/ReceiveBudget.h`, `tests/diagnostics/test_receive_budget.cpp`; Modify `shareaza/Datagrams.cpp:688-697`

**Interfaces:** Produces `class Diag::ReceiveBudget { public: ReceiveBudget(uint64_t startMs, uint64_t budgetMs, uint32_t maxCount); bool Next(uint64_t nowMs); };` — `Next` counts one datagram and returns false once `maxCount` datagrams were counted or `nowMs - startMs >= budgetMs`. `CDatagrams::OnRun` makes one budget per call with `budgetMs = 50`, `maxCount = 2048` *(designer's call within the spec's "time budget with a count backstop"; a healthy hub reads far fewer per 100 ms iteration)*, shared by both sockets, and stops reading when it is exhausted; `ManagePartials()` still runs once per loop pass.

- [ ] **Write the failing tests:** `count limit` (`maxCount` 3 → true, true, true, false at constant time); `time limit` (true at 0 and 49, false at 50); `both` (whichever first).
- [ ] **Run** the g++ line for `test_receive_budget.cpp`: FAIL. **Implement.** **Run:** PASS (and `diagnostics-test.yml` picks it up).
- [ ] **Modify** `Datagrams.cpp`; MSBuild PASS; both oracles PASS.
- [ ] **Commit:** `fix: bound the datagram receive pass in CDatagrams::OnRun` — body states the missing bound and the new limits only.
- [ ] Whole-diff `reviewer` pass with trigger disclosure named as the first item. After the owner's go: push, open PR C (text: class and function only), hand over.
