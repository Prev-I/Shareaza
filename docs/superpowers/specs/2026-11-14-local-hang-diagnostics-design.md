# Local hang and crash diagnostics: design

Date: 2026-11-14. Status: approved by the owner on 2026-11-14. Decisions marked *(owner)* were
settled with the owner on 2026-11-14; items marked *(designer's call)* were settled while writing
and are open to correction.

## Intent

The owner's hub (v2.7.11.3-previ.8, G2 hub mode, Windows) stopped working after some uptime:
one core pinned at 100%, the UI responsive, the Discovery window's query/advertise/browse
commands greyed out, new searches returning nothing, and the system log ending in a run of peer
disconnections followed by nothing. Nothing else was recorded.

Since previ.5 removed the BugSplat reporter (`fe0e88439`), the client has **no** way to record a
failure like this:

- there is no unhandled-exception filter and no minidump writer;
- nothing notices a thread that stops making progress;
- a lock that cannot be taken within its timeout (100-250 ms almost everywhere on the network
  side) is abandoned silently, so a stuck lock leaves no log line at all;
- release builds publish only the installers, so even a dump taken by hand cannot be resolved to
  Shareaza function names.

The greyed-out commands point at `Network.m_pSection` being held continuously:
`CDiscoveryWnd::OnUpdateDiscoveryQuery` (`WndDiscovery.cpp:303-318`) enables the command only if
`Network.m_pSection.Lock(100)` succeeds. The network thread (`CNetwork::OnRun`,
`Network.cpp:1252-1357`) holds that section while it runs discovery, datagrams/DHT, searches,
`QueryHashMaster.Build()` and the crawler. That is an inference from the code, not an observation.

The goal is that **the next such episode leaves enough evidence to find the cause**: which
thread held which lock, for how long, and where every thread was at that moment.

Finding the cause of the 2026-11-14 hang itself is a separate, parallel activity *(owner)*; its
results do not change this design.

## Goals, non-goals, anti-goals

**Goals.**

- With diagnostics enabled, a hang of the kind above produces, without the owner watching:
  one minidump in the diagnostics folder and log lines naming the thread that holds
  `Network.m_pSection` and how long it has held it.
- With diagnostics enabled, an unhandled exception (crash) produces one minidump before the
  process dies.
- A lock timeout on the network side leaves a rate-limited log line at debug level.
- Each release from previ.9 on publishes the symbols (PDB) that match its executables, so any dump
  of that release, automatic or taken by hand, resolves to Shareaza source lines.

**Non-goals.**

- Sending anything anywhere. Diagnostics are **local only** *(owner)*: nothing leaves the PC, no
  network endpoint, no upload prompt.
- Recovering from a hang. The watchdog observes and records; it does not restart the network,
  terminate threads or release locks *(designer's call: forcing a thread that holds a lock makes
  the state worse and destroys the evidence)*.
- A user-facing options page or translated UI strings for the setting *(designer's call)*.
- Fixing the hang's cause (separate activity, above).
- Watching every lock in the program. This design watches the network thread and
  `Network.m_pSection`; extending it to other sections is left for later.

**Anti-goals.** Any of these makes the work a failure even if it functions:

- Diagnostics that are on for a user who did not turn them on.
- Any outbound connection or third-party crash service (this undoes previ.5).
- The watchdog itself deadlocking, crashing, or measurably loading the client when nothing is
  wrong.
- Filling the disk: unbounded dumps or log spam during a long hang.

## Constraints

- Release builds run on GitHub-hosted Windows runners (`.github/workflows/release.yml`, matrix
  Win32 and x64, Release). Releases are immutable and carry build provenance attestations
  (previ.8); any new release asset must go through the same manifest and attestation.
- The installer deletes `dbghelp.dll` from the install folder (`setup/scripts/main.iss:547-549`),
  a leftover of the old reporter. `MiniDumpWriteDump` must come from the **system** `dbghelp.dll`,
  loaded from System32 only (no search-path loading) to avoid DLL planting.
- `Network.m_pSection` is declared `CMutexEx` (`Network.h:68`). Only **debug** builds give that
  type owner tracking (`m_nThreadId`, `m_nEnterCount`, `StdAfx.h:533-590`); in release builds
  `CMutexEx` is a plain `typedef CMutex` (`StdAfx.h:590`). The release client therefore has no
  way today to tell who holds a section.
- The network loop sleeps `Doze(100)` per iteration; a healthy loop iterates several times a
  second.
- The fork is public: whatever ships in previ.9 reaches every user who installs it.
- Repository rules: work goes through a pull request into `main`; nothing is pushed upstream.

## Approaches

Three were considered with the owner *(owner chose 3)*:

1. **No code change.** The owner takes a dump by hand (Task Manager, *Create dump file*, or
   ProcDump) when they notice a hang, and releases publish PDBs. Cheapest, but only works if
   the owner is watching, and the hub stays down meanwhile. **Kept as the stopgap until previ.9
   ships** *(owner)*.
2. **External ProcDump monitoring.** No change to Shareaza, but its triggers miss this failure:
   the hung-window trigger does not fire because the UI stays responsive, and a CPU threshold
   cannot tell a hang from a busy hub. It only catches real crashes well.
3. **In-process local diagnostics behind a setting** *(chosen)*: an exception filter that
   writes a minidump, a watchdog thread that notices the network thread or `Network.m_pSection`
   stalling and records a dump plus log lines, rate-limited lock-timeout log lines, and PDBs
   published with each release. It is the only one that records a silent hang without anyone
   watching.

## The design

### Setting *(owner: behind a setting, off by default)*

- One boolean setting, `General.Diagnostics`, default **false**, registered next to `DebugLog`
  in `CSettings::Load` so it appears under *Tools → Settings → Advanced* like every other setting
  *(designer's call: one consent for both the crash dump and the watchdog, because both write
  files that may contain peer IP addresses and search terms)*.
- It governs the exception filter's dump and the watchdog. It does not govern the debug-level
  lock-timeout lines (below), which are already governed by `LogLevel`.
- The setting is read once, at startup, right after `Settings.Load`; changing it takes effect at
  the next start, and the setting's description says so *(designer's call: a run-time toggle
  must start and stop the watchdog and load and release `dbghelp` without leaks, which is not
  worth it for a tool the owner turns on once)*.
- Crashes before `Settings.Load` or after settings are torn down at shutdown are not covered
  *(designer's call)*.

### Crash dump

- With the setting on, an unhandled-exception filter writes one minidump for the crash, then lets
  the process end as it does today (no dialog of our own, no restart).
- It writes from the crashing process with the system `dbghelp.dll`, loaded at startup when the
  setting is on, not at crash time.
- The existing local `__try/__except` blocks (plugins, UPnP, image loading, `CloseThread`) stay as
  they are: an exception they handle is not a crash and is not dumped *(designer's call)*.

### Watchdog

A dedicated thread, running only while the setting is on, that samples every second
*(designer's call)* and never takes any of the locks it watches.

It needs two cheap signals the release build does not have yet:

- **Network heartbeat:** a counter `CNetwork::OnRun` increments once per loop iteration, at the
  top of the loop right after `Doze`, before any early `continue` (not live yet, UPnP search in
  progress) and before taking `m_pSection`. Placed there, every normal state of the loop moves
  it, and a hang anywhere in the iteration (inside or outside the section) stops it.
- **Section owner tracking in release builds, for `Network.m_pSection` only:** a mutex type that
  records, in every build, the owner thread ID, the re-entry count and an **acquisition counter**
  incremented on each outermost acquisition (re-entry count going 0 → 1). `Network.m_pSection`
  switches to that type; every other section keeps today's type, so the rest of the program's
  locking is untouched *(designer's call: smallest blast radius; extending it to other sections
  is a later decision)*. The debug-only `ASSUME_LOCK` checks must keep working on it.
  "Same owner and same acquisition counter across samples" means the section was held
  **continuously**: a release and re-take always moves the counter. The watchdog reads owner and
  counter as two separate loads; a torn read can at worst delay detection by one sample, which is
  acceptable, so no consistent snapshot is needed.

A **stall** is either of:

- the network heartbeat has not moved for **30 s** while the network thread exists (it exits when
  the network disconnects, so a disconnected client never counts as stalled);
- `Network.m_pSection` has been held continuously by the same thread for **30 s**.

Both kinds starting together, or one starting while the other is ongoing, are **one episode**:
one dump, log lines naming each kind *(designer's call)*.

*(designer's call: 30 s. A normal lock wait is 100-250 ms and a healthy loop iterates several
times a second, so 30 s is never normal. The value lives in a setting next to `Diagnostics` so
it can be tuned without a rebuild.)*

When a stall starts, the watchdog:

1. writes an error-level log line naming the stall kind, the owning thread ID (and the thread's
   name, if `CRazaThread`'s thread registry has one for it), and how long the condition has
   held. No in-process stack walking or thread suspension: the dump carries every stack
   *(designer's call: suspending threads from the watchdog risks the very wedge it must avoid)*;
2. writes **one** minidump for the episode;
3. while the stall persists, writes a reminder log line at wide intervals (every 5 minutes,
   *designer's call*), and no further dumps;
4. when the stall ends, writes a log line saying so and how long it lasted.

A new episode may produce a new dump only after the previous one has ended.

The log lines go through `theApp.Message`, so they appear in the system window and, if
`DebugLog` is on, in the log file. The design has to account for `theApp.Message` taking its
own lock (`m_csMessage`): the watchdog must not be able to wedge itself if a stalled thread
holds that lock *(left to the builder how)*.

### Dumps on disk

- Folder: `<UserPath>\Data\Diagnostics\` *(designer's call)*.
- File name carries the kind (`crash` / `hang`), the client version and a timestamp.
- Dump type "medium": all threads' stacks, thread information, handle data and the data
  segments, not the full process memory. A few MB, not hundreds *(designer's call)*. Even so it
  may contain peer addresses, search terms, and the names and paths of files the client has open (downloads, shared files); that is acceptable because it stays local.
- At most the **5** most recent dumps are kept, crash and hang dumps together; older ones are
  deleted when a new one is written *(designer's call)*.
- The folder is user data like the rest of `Data\`: the builder checks what the uninstaller does
  with the user's `Data` folder and gives the diagnostics folder the same treatment, and the
  documentation says where dumps are and that they may contain peer addresses, so a user can
  delete them *(designer's call)*.

### Lock-timeout log lines

- Every timed `Network.m_pSection` lock in `Network.cpp` and `DiscoveryServices.cpp` that gives
  up emits a debug-level (`MSG_DEBUG`) log line naming the site *(designer's call: those two
  files hold the network loop, `RunJobs` and the discovery paths; the UI's 100 ms
  update-handler probes are excluded, they fail by design several times a second during a hang)*.
  Whether that is a helper used at each site or code at each site is the builder's choice.
- Rate-limited per site (at most one line per site per minute, with a count of the suppressed
  failures) *(designer's call)*, so a long hang does not flood the log. The limiter state is
  per site and lock-free.
- The `IsLogDisabled(MSG_DEBUG)` check comes first, before any formatting or limiter work, so
  with debug logging off (the default) a failed lock costs one comparison and never touches
  `theApp.Message`'s lock.
- Not behind `Diagnostics`: they are text only, and `LogLevel` already defaults to info, so they
  are off for anyone who has not raised it.

### Symbols in releases

- Release builds produce full PDBs for every binary the solution builds and the installer ships
  (`Shareaza.exe`, and the plugins and libraries built in the same run); prebuilt third-party
  binaries are out of scope. The builder verifies the project settings actually produce them:
  nothing in `Shareaza_143.vcxproj`'s Release configuration sets it explicitly. The installer is
  packaged in the same job from the same build, so the PDBs match the shipped binaries.
- `release.yml` publishes them as one archive per platform beside the installers, included in
  `SHA256SUMS.txt` (whose globs today cover only `*.exe`) and covered by the same build
  provenance attestation. Because releases are immutable, the change is proven first with a
  `workflow_dispatch` run, which stops at the artifacts without publishing (`release.yml:107`).
- `docs/RELEASING.md` and `docs/ORACLE.md` (or a short new doc) say how to open a dump against
  them: WinDbg or Visual Studio, symbol path pointing at the extracted archive plus Microsoft's
  symbol server.
- PDBs from a public source tree reveal nothing private. The builder confirms they carry no
  local or runner path that matters.

### Also in previ.9: a bounded datagram receive pass *(owner)*

Separate from the diagnostics, decided by the owner on 2026-11-14:

- `CDatagrams::OnRun` (`Datagrams.cpp:690-697`) reads datagrams in a loop with no upper bound on
  time or count, while the network thread holds `Network.m_pSection`. Bound each pass, so that
  one call to `CDatagrams::OnRun` always returns and the network loop always reaches the rest of
  its iteration and releases the section.
- The bound is a time budget per pass, with a count limit as a backstop *(designer's call; the
  values are the builder's)*.
  Datagrams left unread wait in the socket buffer for the next iteration, 100 ms later.
- It ships as its own commit and its own line in the release notes.
- **Disclosure** *(repository rule)*: commit messages, the PR, release notes and docs describe
  this as a missing bound in `CDatagrams::OnRun`, never as which input reaches it or how to
  cause it.

## How it is verified

- With the setting **off**: no watchdog thread, no exception filter, no `dbghelp` loaded, no
  diagnostics folder created.
- On a healthy client with the setting on, a long run (hub mode, hours) produces no dump and no
  stall line: the false-positive check for the anti-goal.
- A debug-only or test-only hook that holds `Network.m_pSection` for longer than the threshold
  produces exactly one dump and the log lines above, and the "ended" line after release. The
  hook must not exist in release builds *(how is left to the builder)*.
- A deliberate crash in a debug or test build produces one crash dump.
- The dump from that test opens in WinDbg against the published PDBs with Shareaza function names
  on the network thread's stack.
- Retention: a sixth dump removes the oldest.
- The previ.9 release's assets include the symbol archives, their hashes are in the manifest,
  and `gh attestation verify` succeeds on them.

## Left to the builder

- Exact names of the new settings, counters, types and files.
- How the watchdog avoids blocking on `m_csMessage` or any other lock a stalled thread may hold.
- How the stall test hook is kept out of release builds.
- The packaging of the symbol archives within the existing release manifest.
- Whether the Wine oracle workflow can exercise any of this cheaply; not required.
