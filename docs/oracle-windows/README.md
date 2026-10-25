# Testing a GWebCache with Shareaza on Windows

A kit for testing [`gwc-edge`](https://github.com/Prev-I/gwc-edge) at
`http://gwc-edge.net/` with a real Shareaza on Windows 10 or 11: first as a leaf, then as a
hub with an open port. It covers stages 2 and 3 of gwc-edge's `docs/field-test-plan.md`.
On Linux, use [`../ORACLE.md`](../ORACLE.md) instead.

| Script | Does |
|---|---|
| `Install-Shareaza.ps1` | Downloads the official 2.7.10.2 or this fork's build, checks its SHA-256, and installs it silently |
| `Prepare-Oracle.ps1` | Backs up your own Shareaza setup, then sets the client to talk only to the cache under test, as a leaf or as a hub |
| `Watch-Oracle.ps1` | Follows the client's debug log and saves the cache's `/stats` |
| `Restore-Oracle.ps1` | Zips the evidence, then puts your own setup back |

`.github/workflows/oracle-windows.yml` runs these four scripts end to end, in this order, on a
Windows runner against a stub cache. Each run checks the cache traffic, the clean shutdown and
the restore.

## Before you start

- **Which client to use.**
  - **The official 2.7.10.2 for everything, and always for the hub test.** The fork's build has
    a probable remote crash reachable from any peer ([`../SECURITY-AUDIT.md`](../SECURITY-AUDIT.md),
    finding 3).
  - **The fork's build only as a short leaf test,** on a port that isn't forwarded. The two
    clients use the same registry key and folders, so run them one after the other, never
    together.
- **An administrator account that is your own.** Run every script from **PowerShell opened as
  administrator from your own Windows account**, so the settings land in your profile.
- **Your existing Shareaza, if any,** is backed up and set aside by `Prepare-Oracle.ps1`, and put
  back by `Restore-Oracle.ps1`.
- **For the hub test (test 6),** you also need:
  - a router where you can forward one port (TCP and UDP) to this PC;
  - a public IPv4 address, not behind carrier-grade NAT;
  - about 4 hours.
- **What's exposed.** Nothing is shared: the download folder is a new, empty
  `%USERPROFILE%\ShareazaOracle\Downloads`. A hub accepts connections from anyone on the internet
  while it runs, so close it when you're done.

### Getting the kit

In an elevated PowerShell:

```powershell
$kit = "$env:USERPROFILE\ShareazaOracle\kit"
New-Item -ItemType Directory -Force $kit | Out-Null
$base = 'https://raw.githubusercontent.com/Prev-I/Shareaza/main/docs/oracle-windows'
foreach ($f in 'Install-Shareaza.ps1','Prepare-Oracle.ps1','Watch-Oracle.ps1','Restore-Oracle.ps1','README.md') {
    Invoke-WebRequest -UseBasicParsing "$base/$f" -OutFile "$kit\$f"
}
Set-Location $kit
Get-ChildItem *.ps1 | Unblock-File            # downloaded scripts are blocked by default
Set-ExecutionPolicy -Scope Process Bypass     # for this window only
```

## Test 3: bootstrap as a leaf (official client, ~30 minutes)

```powershell
.\Install-Shareaza.ps1 -Client Official
.\Prepare-Oracle.ps1 -Mode Leaf
& "$env:ProgramFiles\Shareaza\Shareaza.exe"
.\Watch-Oracle.ps1 -Hours 1                    # in a second elevated PowerShell, in the same folder
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
- **A hub from the cache.** At least one hub in the Neighbours window was in the cache's
  hostfile reply. Compare with what the cache hands out:

  ```powershell
  curl.exe -s -A "Shareaza 2.7.10.2" "http://gwc-edge.net/?get=1&hostfile=1&net=gnutella2&ping=1&client=TEST&version=0"
  ```

- **No failures.** The Discovery window (**F9**) shows `gwc-edge.net` with accesses and no
  failures.

## Test 4: second query (same run, after 30 minutes)

Keep the client running. Shareaza queries the same cache at most every 30 minutes
(`Discovery\AccessPeriod`), so leave it at least 35 minutes.

**Passes if** the Discovery window shows a second access, still with no failures. Two failures
in a row would have removed the cache from the client's list.

## Test 5: a long leaf run (same run, a few hours)

```powershell
.\Watch-Oracle.ps1 -Hours 4
```

**Passes if:**
- the queries keep coming every 30 minutes or more, with no failures;
- no `limited` count appears in the `[stats]` lines;
- the `/stats` counts for `RAZA 2.7.10.2` grow by about one `hostfile` per query.

Close Shareaza with **File → Exit**, or just close the window, before going on.

## Test 6: as a hub (official client, ~4 hours)

1. **Forward a port on your router to this PC, for both TCP and UDP.** The example uses 6346.
   Most routers have this under *Port forwarding* or *Virtual server*. Give the PC a fixed LAN
   address there too.
2. **Prepare for hub mode** (your backup from test 3 is kept):

   ```powershell
   .\Prepare-Oracle.ps1 -Mode Hub -Port 6346 -PreferIPv4
   ```

   `-PreferIPv4` makes Windows reach `gwc-edge.net` over IPv4, because `gwc-edge.net` also has
   IPv6 addresses. A hub that contacts the cache over IPv6 while reporting its IPv4 address is
   rejected as `ip:source_mismatch`. `Restore-Oracle.ps1` undoes it.
3. **Start Shareaza and the watcher:**

   ```powershell
   & "$env:ProgramFiles\Shareaza\Shareaza.exe"
   .\Watch-Oracle.ps1 -Hours 5
   ```

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
- **No update after 3 hours:** look for `Is Gnutella2 hub capable?` and the `NO:` line after it
  in the watcher's output. Check that the Neighbours window shows at least 4 G2 hubs or leaves.

## Optional: the fork's build as a leaf

This shows the `RAZI2.7.10.6` client string reaching the cache. Use a port that is **not**
forwarded, and keep the run short:

```powershell
.\Install-Shareaza.ps1 -Client Fork
.\Prepare-Oracle.ps1 -Mode Leaf -Port 6347
& "$env:ProgramFiles\Shareaza\Shareaza.exe"
.\Watch-Oracle.ps1 -Hours 0.5
```

**Passes if** the query line carries `client=RAZI2.7.10.6`, and `/stats` lists `RAZI 2.7.10.6`.

Close it, then reinstall the official client if you want it back: `.\Install-Shareaza.ps1
-Client Official`.

## Finishing

Close Shareaza, then:

```powershell
.\Restore-Oracle.ps1
```

It writes `%USERPROFILE%\ShareazaOracle\evidence-<time>.zip`, then:
- removes the firewall rules and the IPv4 preference;
- puts back your own settings, data folder and `DefaultServices.dat`;
- keeps the test run's data under `ShareazaOracle\runs\`.

The zip holds `Shareaza.log`, `Discovery.dat`, `HostCache.dat`, a settings export and the saved
`/stats`. **The log and host cache contain hubs' public IP addresses and probably yours, so look
before sharing it.** `Restore-Oracle.ps1 -CollectOnly` makes the zip and changes nothing.

Shareaza itself stays installed. Uninstall it from Settings → Apps if you don't want it.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| SmartScreen warns about the installer, or Defender flags it as a potentially unwanted app | Normal for an unsigned P2P installer. The scripts have already checked its SHA-256; allow it, or stop here |
| No `Querying discovery service` line at all | Shareaza still had a discovery list: run `Prepare-Oracle.ps1` again with Shareaza closed |
| The QuickStart wizard opens | The settings were reset after preparing, for example by a reinstall: close it and run `Prepare-Oracle.ps1` again |
| `failed, fail count 1` after a query | The cache's reply didn't satisfy Shareaza: run `scripts/smoke.sh --prod http://gwc-edge.net/` from the gwc-edge repository |
| Connected, but to no hub the cache listed | The first hub it reached handed it others (`X-Try-Hubs`), and it moved on. Check the first connection after the cache query in `Shareaza.log` |
| Windows Firewall asks about Shareaza | Allow it on the network type you're on. `Prepare-Oracle.ps1` already opened the port for all profiles |
