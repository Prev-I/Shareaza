# Testing a GWebCache with Shareaza on Windows

A kit for testing [`gwc-edge`](https://github.com/Prev-I/gwc-edge) at `http://gwc-edge.net/`
with a real Shareaza on Windows 10 or 11: first as a leaf, then as a hub with an open port. It
covers stages 2 and 3 of gwc-edge's `docs/field-test-plan.md`. On Linux, use
[`../ORACLE.md`](../ORACLE.md) instead.

| Script | Does |
|---|---|
| `Install-Shareaza.ps1` | Saves your own Shareaza setup, then downloads the official 2.7.10.2 or this fork's build, checks its SHA-256 and installs it silently |
| `Prepare-Oracle.ps1` | Sets the installed client to share nothing and to talk only to the cache under test, as a leaf or as a hub |
| `Watch-Oracle.ps1` | Follows the client's debug log and saves the cache's `/stats` |
| `Restore-Oracle.ps1` | Zips the evidence, then puts your own Shareaza settings and data back as they were before the test |
| `OracleCommon.ps1` | Shared by the others; not run directly |

`.github/workflows/oracle-windows.yml` runs the kit end to end on a Windows runner, against a
stub cache:
- install, prepare as a leaf, run;
- prepare again as a hub, run;
- restore, then a second restore, which must refuse.

It plants a fake "own setup" first, including a private torrent folder. It checks:
- the folder is never shared, and the setup comes back unchanged;
- the client runs with its security rules;
- Prepare refuses while a restore is unfinished.

It starts Shareaza through `explorer.exe` as you would, unelevated. If the runner gives Explorer
no desktop, it falls back to starting it elevated and says so in a warning.

## Before you start

- **Which client to use.**
  - **The official 2.7.10.2 for everything, and always for the hub test.** The fork's build has
    a probable remote crash reachable from any peer ([`../SECURITY-AUDIT.md`](../SECURITY-AUDIT.md),
    finding 3).
  - **The fork's build only as a short leaf test,** on a port that isn't forwarded. The two
    clients use the same registry key and folders, so run them one after the other, never
    together.
- **Your existing Shareaza, if you have one, is safe.**
  - Before anything changes, `Install-Shareaza.ps1` (or `Prepare-Oracle.ps1`, if you skip it)
    saves your settings, data folder, discovery list and installed version in
    `%USERPROFILE%\ShareazaOracle\session`.
  - `Restore-Oracle.ps1` puts all of it back, and only then deletes the saved copy.
  - The test does replace your installed Shareaza. If it was a different version, reinstall
    yours afterwards; `Restore-Oracle.ps1` tells you when.
  - **Don't uninstall Shareaza to clean up** if you had it before. The uninstaller deletes the
    settings and data that `Restore-Oracle.ps1` has just put back.
  - **If your own Shareaza starts with Windows,** turn that off for the test. A reboot during the
    hub test would otherwise start the oracle client.
- **Nothing is shared.**
  - On its first start Shareaza shares its download, incomplete, collection and torrent folders.
    The kit points all four at new, empty folders under `ShareazaOracle\shared`.
  - The kit also stops Shareaza copying its own installer there.
  - The 2.7.10.2 default would have shared your whole Downloads folder.
- **Shareaza runs as you, not as administrator.** Only the kit's scripts need an elevated
  PowerShell. Start Shareaza itself from the Start menu, or with `explorer.exe`, as shown below.
  Don't start it from the elevated window.
- **For the hub test (test 6),** you also need:
  - a router where you can forward one port (TCP and UDP) to this PC;
  - a public IPv4 address, not behind carrier-grade NAT;
  - about 4 hours.
  A hub accepts connections from anyone on the internet while it runs, so close it when you're
  done.

### Getting the kit

The links below work once this kit is on the fork's `main` branch. Open **PowerShell as
administrator** and run:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$kit = "$env:USERPROFILE\ShareazaOracle\kit"
New-Item -ItemType Directory -Force $kit | Out-Null
$base = 'https://raw.githubusercontent.com/Prev-I/Shareaza/main/docs/oracle-windows'
foreach ($f in 'OracleCommon.ps1','Install-Shareaza.ps1','Prepare-Oracle.ps1','Watch-Oracle.ps1','Restore-Oracle.ps1','README.md') {
    Invoke-WebRequest -UseBasicParsing "$base/$f" -OutFile "$kit\$f"
}
Set-Location $kit
Get-ChildItem *.ps1 | Unblock-File            # downloaded scripts are blocked by default
```

**In every PowerShell window you use for the kit,** elevated or not, first run:

```powershell
Set-Location "$env:USERPROFILE\ShareazaOracle\kit"
Set-ExecutionPolicy -Scope Process Bypass     # this window only
```

## Test 3: bootstrap as a leaf (official client, ~30 minutes)

In the elevated window:

```powershell
.\Install-Shareaza.ps1 -Client Official
.\Prepare-Oracle.ps1 -Mode Leaf
explorer.exe "$env:ProgramFiles\Shareaza\Shareaza.exe"     # starts it as you, not as admin
.\Watch-Oracle.ps1 -Hours 1
```

**What you should see, in order:**
1. **The query.** `Querying discovery service "http://gwc-edge.net/"`, then `[DiscoveryServices]
   Request: http://gwc-edge.net/?get=1&hostfile=1&net=gnutella2&...&client=RAZA2.7.10.2&...`.
2. **The reply.** No `failed, fail count` line follows it.
3. **The connection.** Within a few minutes the status bar says it is connected to G2, and the
   Neighbours window (**Ctrl+F11**) lists one or two hubs.
4. **The cache's side.** The next `[stats]` line lists `RAZA 2.7.10.2` among the clients, and
   gwc-edge's Workers Logs show a `hostfile` line, then a `urlfile` line.

**Passes if:**
- **A hub from the cache.** The first hub the client connected to was in the cache's hostfile
  reply. Compare `Shareaza.log` with what the cache hands out:

  ```powershell
  curl.exe -s -A "Shareaza 2.7.10.2" "http://gwc-edge.net/?get=1&hostfile=1&net=gnutella2&ping=1&client=TEST&version=0"
  ```

- **No failures.** The Discovery window (**F9**) shows `gwc-edge.net` with an access and no
  failures.

## Tests 4 and 5: repeated queries over a long leaf run (same run, a few hours)

```powershell
.\Watch-Oracle.ps1 -Hours 4
```

**A connected leaf doesn't query on a timer.**
- **It only queries when it runs short of hosts.** A G2 query goes out only while the client knows
  25 hosts or fewer (`HostCache`, `EnoughServers`). A leaf that learns hosts from its hubs may
  never query again.
- **There is a floor between queries.** By default it never queries the same cache more often
  than every 30 minutes (`Discovery\AccessPeriod`). A cache can change that for itself with an
  `I|access|period|<seconds>` line in its reply.
- **To force one,** right-click `gwc-edge.net` in the Discovery window and choose **Query Now**.
  Do it after 30 minutes or more.

**Passes if:**
- **Every query succeeds.** Each one, whether automatic or forced, gets a reply with no `failed,
  fail count` line.
- **The cache doesn't throttle it.** No `limited` count appears in the `[stats]` lines.
- **The counts add up.** `/stats` grows by one `hostfile` (and possibly one `urlfile`) per query
  from `RAZA 2.7.10.2`.

Close Shareaza with **File → Exit** before going on.

## Test 6: as a hub (official client, ~4 hours)

1. **Forward a port on your router to this PC, for both TCP and UDP.** The example uses 6346.
   Most routers have this under *Port forwarding* or *Virtual server*. Give the PC a fixed LAN
   address there too.
2. **Prepare for hub mode.** Your saved setup from test 3 is kept; test 3's data is moved to
   `ShareazaOracle\runs\`.

   ```powershell
   .\Prepare-Oracle.ps1 -Mode Hub -Port 6346 -PreferIPv4
   ```

   `-PreferIPv4` makes Windows reach `gwc-edge.net` over IPv4, because `gwc-edge.net` also has
   IPv6 addresses. A hub that contacts the cache over IPv6 while reporting its IPv4 address is
   rejected as `ip:source_mismatch`. `Restore-Oracle.ps1` undoes it.
3. **Start Shareaza and the watcher:**

   ```powershell
   explorer.exe "$env:ProgramFiles\Shareaza\Shareaza.exe"
   .\Watch-Oracle.ps1 -Hours 5
   ```

   The watcher warns if Shareaza listens on a port other than the one prepared.
4. **Check the port is open from outside** while Shareaza runs, with any online port checker on
   TCP 6346. If it's closed, nothing below will happen.

**When to expect what:**
- **Hub mode** is forced (`Gnutella2\ClientMode` = 2), so the client skips the memory, speed
  and 3-hour checks. The Neighbours window starts listing leaves once others connect in.
- **The 2-hour clock starts only at the first incoming connection** (`Handshakes.cpp`,
  `RunStableUpdate`). A closed port means no clock.
- **After 2 hours, and with at least 4 G2 neighbours,** Shareaza sends its first `update` to a
  working cache, then at most one an hour.
- **It picks one of its working caches at random,** and the cache's own URL list may have taught
  it others. So the first update may go elsewhere. A later one, an hour on, may come to
  `gwc-edge.net`.

**Passes if:**
- **The update arrives.** gwc-edge's Workers Logs show an `update` line with `ip:inserted`.
  `/stats` shows `update` above 0.
- **It is verified within 10–20 minutes.** A `cron_hub` line with `now: "verified"` or
  `"alive_full"`.
- **The cache lists you.** The hostfile `curl` above lists your public IP and port.
- **You stay listed** while the hub keeps running.

**If it fails:**
- **`ip:source_mismatch`:** the update came over IPv6 or through a different NAT address. Check
  that `-PreferIPv4` was used.
- **`cron_hub` result `timeout` or `unreachable`:** the port isn't reachable from the internet.
  Check the router forwarding and the port checker.
- **No update after 3 hours:**
  - check that the Neighbours window shows at least 4 G2 hubs or leaves;
  - check that the port checker still says open;
  - check that the watcher showed the prepared port.

## Optional: the fork's build as a leaf

This shows the `RAZI2.7.10.6` client string reaching the cache. Use a port that is **not**
forwarded, and keep the run short:

```powershell
.\Install-Shareaza.ps1 -Client Fork
.\Prepare-Oracle.ps1 -Mode Leaf -Port 6347
explorer.exe "$env:ProgramFiles\Shareaza\Shareaza.exe"
.\Watch-Oracle.ps1 -Hours 0.5
```

**Passes if** the query line carries `client=RAZI2.7.10.6`, and `/stats` lists `RAZI 2.7.10.6`.

## Finishing

Close Shareaza (**File → Exit**), then, in the elevated window:

```powershell
.\Restore-Oracle.ps1
```

It writes `%USERPROFILE%\ShareazaOracle\evidence-<time>.zip`, then:
- removes the kit's firewall rules and the IPv4 preference;
- puts back your own settings, data folder and discovery list;
- keeps the test runs' data under `ShareazaOracle\runs\`.

The installer's own firewall exception for Shareaza stays, as it would after any install.

The zip holds `Shareaza.log`, `Discovery.dat`, `HostCache.dat`, a settings export, and the
watcher's log and `/stats` snapshots. **The log and host cache contain hubs' public IP addresses
and probably yours, so look before sharing it.**

Other ways to run it:
- `Restore-Oracle.ps1 -CollectOnly` makes the zip and changes nothing.
- A second `Restore-Oracle.ps1` refuses, because there is nothing left to restore.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| SmartScreen warns about the installer, or Defender flags it as a potentially unwanted app | Normal for an unsigned P2P installer. The scripts have already checked its SHA-256; allow it, or stop here |
| `session.partial exists` | An earlier run died while saving your setup. The message says how to put your data back; nothing has been lost |
| `An earlier Restore-Oracle.ps1 did not finish` | Run `Restore-Oracle.ps1` again: it finishes the restore. The other scripts refuse until it has |
| No `Querying discovery service` line at all | Shareaza isn't connected to G2 yet (status bar), or it was reinstalled after preparing: close it and run `Prepare-Oracle.ps1` again |
| The QuickStart wizard opens | `Prepare-Oracle.ps1` wasn't run after the last install. Close Shareaza and run it |
| `failed, fail count 1` after a query | The cache's reply didn't satisfy Shareaza: run `scripts/smoke.sh --prod http://gwc-edge.net/` from the gwc-edge repository |
| Connected, but to no hub the cache listed | The first hub it reached handed it others (`X-Try-Hubs`), and it moved on. Check the first connection after the cache query in `Shareaza.log` |
| Windows Firewall asks about Shareaza | Allow it on the network type you're on. `Prepare-Oracle.ps1` already opened the port for Shareaza on all profiles |
