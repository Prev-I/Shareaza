# Shareaza as a protocol oracle

How to run two Shareaza clients under Wine on Linux or WSL2: the official 2.7.10.2 that most of the
G2 network runs, and this fork's 2.7.10.6 build. With both installed, a GWebCache such as
[`gwc-edge`](https://github.com/Prev-I/gwc-edge) can be exercised against real clients.

`.github/workflows/oracle-wine.yml` checks these steps on `ubuntu-24.04` ([its runs](https://github.com/Prev-I/Shareaza/actions/workflows/oracle-wine.yml)). The results below come from runs on 2026-10-24 and 2026-10-25 with Wine 9.0 (`9.0~repack-4build3`) and winetricks 20240105. [Run 40138506381](https://github.com/Prev-I/Shareaza/actions/runs/40138506381) is the first that ran `docs/oracle-prepare.sh` itself.

| | Status |
|---|---|
| Silent install of both x64 clients, Wine 9.0 with `vcrun2022` | **tested** |
| [Preparing a prefix](#preparing-a-prefix-isolated-and-unattended) with `docs/oracle-prepare.sh`, then starting the client | **tested**, against a stub cache on `127.0.0.1`. Covered: no dialogs at start, the client starts connecting, the stub is the only discovery service it queries, it makes no update check, and it exits by itself on `WM_CLOSE` after saving. Not covered: other traffic (UPnP, DHT, direct connects) is off by configuration only, and nothing watches the network for it. |
| `client=` and user agent per client | **tested** ([table](#which-client-is-which-in-the-caches-logs)) |
| Data file locations | **tested** |
| Downloading the fork's x64 installer from its latest release and checking it against `SHA256SUMS.txt` | **tested** since 2026-10-25, with the same URLs and check as below; earlier runs used the tag build's artifact |
| Interactive installs, the GUI steps (Discovery window, Add Service dialog), `gwc:` links | untested: they come from the source (`Res/Default.xml`, `Shareaza.rc`, `DlgURLAction.cpp`) |
| Win32 builds, WSL2, Wine versions other than 9.0 | untested |

> **Do not leave these clients unattended on the live G2 network.** A [static audit](SECURITY-AUDIT.md)
> of the code added since the original project found three problems. All three are in code that
> came after 2.7.10.2, so they affect this fork's build; going by the source, not the official one:
> - HTTPS that never verifies certificates;
> - a probable remote crash from a single packet, sent over UDP by any IPv4 peer or over TCP by a
>   connected neighbour;
> - IPv6 paths that bypass the ban list.
>
> The 2.7.10.2 code itself, from 2017, was not reviewed.
>
> A client is exposed as soon as it listens on a public interface, before it has discovered
> anything. What [preparing a prefix](#preparing-a-prefix-isolated-and-unattended) does and does
> not isolate is spelled out there.

## The two clients

| Prefix | Installer | Where it comes from | SHA-256 |
|---|---|---|---|
| `~/.wine-shareaza-sf` | `Shareaza_2.7.10.2_x64.exe` | [SourceForge, Shareaza-2.7.10.2](https://sourceforge.net/projects/shareaza/files/Shareaza/Shareaza-2.7.10.2/) | `d6ff141d69a3af53f8f7547b40e308a4e2aa4818eeb28da827d7545165ef3051`, as SourceForge publishes it |
| `~/.wine-shareaza-previ` | `iShareaza_2.7.10.6_x64_Release_<build date>.exe` | this fork's [releases](https://github.com/Prev-I/Shareaza/releases), tag `v2.7.10.6-previ.N`, currently [`v2.7.10.6-previ.1`](https://github.com/Prev-I/Shareaza/releases/tag/v2.7.10.6-previ.1). A new tag first makes a draft, which only the repository owner can download until it is published. | in the release's `SHA256SUMS.txt` |

Each client gets its own prefix, for three reasons:
- **Same registry key.** Both clients keep their settings under `HKCU\Software\Shareaza\Shareaza`,
  so in one prefix they would overwrite each other.
- **Same data folder.** Both use the same `%APPDATA%\Shareaza` folder.
- **The installer deletes files.** In the folder it installs into, it deletes every top-level
  `*.exe`, `*.dll`, `*.dat` and `*.xml` (`setup/scripts/main.iss`, `[InstallDelete]`).

## Installing

Install **silently**:
- **An interactive install starts Shareaza at the end.** The *Launch Shareaza* box is ticked by
  default, so the client starts with the stock list of about twenty public discovery services.
- **The QuickStart wizard then connects.** Its last page is set to connect by default
  (`WizardFinishedPage.cpp`), so the client is on the live network before you have prepared the
  prefix.
- **A silent install never launches it** (`skipifsilent`).

```bash
# Wine with 32-bit support: the Inno Setup installers are 32-bit even for x64 builds.
sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt-get install --no-install-recommends wine wine64 wine32:i386 winetricks cabextract

# Official 2.7.10.2
mkdir -p ~/Downloads
curl -fLo ~/Downloads/Shareaza_2.7.10.2_x64.exe \
  https://downloads.sourceforge.net/project/shareaza/Shareaza/Shareaza-2.7.10.2/Shareaza_2.7.10.2_x64.exe
echo 'd6ff141d69a3af53f8f7547b40e308a4e2aa4818eeb28da827d7545165ef3051  Shareaza_2.7.10.2_x64.exe' \
  | (cd ~/Downloads && sha256sum -c)
export WINEPREFIX=~/.wine-shareaza-sf WINEARCH=win64
wineboot --init && wineserver --wait
winetricks -q isolate_home     # no links to your home folders: see below
winetricks -q vcrun2022
wine ~/Downloads/Shareaza_2.7.10.2_x64.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-
wineserver --wait

# This fork's build, from release v2.7.10.6-previ.1
base=https://github.com/Prev-I/Shareaza/releases/download/v2.7.10.6-previ.1
curl -fLo ~/Downloads/iShareaza_2.7.10.6_x64_Release_2026-10-25.exe "$base/iShareaza_2.7.10.6_x64_Release_2026-10-25.exe"
curl -fLo ~/Downloads/SHA256SUMS.txt "$base/SHA256SUMS.txt"
(cd ~/Downloads && sha256sum -c --ignore-missing SHA256SUMS.txt)   # must print the installer's name and OK
export WINEPREFIX=~/.wine-shareaza-previ WINEARCH=win64
wineboot --init && wineserver --wait
winetricks -q isolate_home     # no links to your home folders: see below
winetricks -q vcrun2022
wine ~/Downloads/iShareaza_2.7.10.6_x64_Release_2026-10-25.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-
wineserver --wait
```

- **Use the exact installer file name** from the release; it carries the build date, so a later
  release changes both download lines and the install line.
- **Run `isolate_home` before the client ever starts.**
  - **The danger:** Wine links the prefix's Downloads, Documents and similar folders to your own.
    On its first start Shareaza **shares its download folder**, and the official 2.7.10.2 uses
    the whole Downloads folder.
  - **Where the link points:** Wine links each of these folders only when the target exists.
    Usually that's `~/Downloads`, so your real downloads would be shared. If
    `~/.config/user-dirs.dirs` sets `XDG_DOWNLOAD_DIR="$HOME/"`, the target is your whole home
    folder. With neither, Wine makes a real folder inside the prefix.
    (`dlls/shell32/shellpath.c`, `dlls/mountmgr.sys/unixlib.c`)
  - **The recipe above makes the link certain.** It creates `~/Downloads` before `wineboot`, so
    the prefix's Downloads would link straight to the folder holding both installers.
  - **What it does:** `winetricks isolate_home` turns the links into `$HOME` into real, empty
    folders inside the prefix.
    - It also turns off Wine's automatic update of the prefix after a Wine upgrade
      (`.update-timestamp`).
    - It leaves alone XDG folders outside `$HOME`, such as `XDG_DOWNLOAD_DIR="/data/Downloads"`.
      `oracle-prepare.sh` reports those too: replace each with an empty folder (`rm <link> &&
      mkdir <link>`).
  - **Why settings can't fix it:** a different download folder can't be set instead, because Wine
    never lets Shareaza read string settings (see [Settings and Wine](#settings-and-wine)).
  - **Checked both ways:**
    - `oracle-prepare.sh` refuses a prefix with any link out of it.
    - CI reproduces the whole-home case, with a canary file in `$HOME`. It then checks that the
      client hashes exactly one file: one planted in its shared folder on purpose.
  - **A prefix whose client already started without `isolate_home`** has indexed your files, and
    may have offered them to peers while online.
    - The best fix is to delete the prefix and follow the steps again.
    - At the very least, with the client closed: run `isolate_home`, then delete
      `drive_c/users/$USER/AppData/Roaming/Shareaza/Data/Library*.dat` and `TigerTree.dat` in
      the prefix. They hold the index of what it saw.
- **Install `vcrun2022` first.** Without it the fork's installer fetches the VC++ runtime itself,
  from go.microsoft.com (`vc143/vcredist/vcredist.iss`). The 2.7.10.2 installer most likely does the
  same: it carries the same download helper (`idp.dll`), but no run has shown it downloading.
- **No DLL override was needed.** With only `vcrun2022` added to a fresh 64-bit prefix, both
  clients installed, started, connected and closed under Wine 9.0 (`9.0~repack-4build3`).
- **One harmless installer error:** Inno Setup's log shows `Internal error: Helper: Response message
  has wrong size.` under Wine. It comes from its 64-bit helper, and the installation completes.
- **WSL2 is untested.** It needs WSLg, or another X server, for the client's window.

## Preparing a prefix: isolated and unattended

[`docs/oracle-prepare.sh`](oracle-prepare.sh) does it, run from a checkout of this repository; CI runs the same script.
- **Run it after every install or upgrade**, before the client's first start, **with the client
  closed**. A running client would overwrite the settings when it exits, and the script refuses to
  run while one is up.
- **It also refuses a prefix with no Shareaza installed**, so it doesn't create an empty one, and
  a prefix whose folders still link out of it, naming the links and the `isolate_home` command.

```bash
CACHE=http://127.0.0.1:8787/          # your gwc-edge; see "Adding a GWebCache" for URL rules
for p in sf previ; do
  docs/oracle-prepare.sh ~/.wine-shareaza-$p "$CACHE"
done
```

**What the script does, step by step:**

0. Creates every settings section key (see [Settings and Wine](#settings-and-wine)).
1. Replaces `DefaultServices.dat` with the single line `2 <cache>`, and sets `Settings\Upgrade` to
   0. After an install Shareaza would otherwise copy its installer into the shared download
   folder. Under Wine that copy can't happen anyway, because it needs a string setting, but the
   setting costs nothing.
2. Sets `VersionCheck\UpdateCheck`, `BitTorrent\EnableAlways`, `BitTorrent\EnableDHT` and
   `Connection\EnableUPnP` to 0.
3. Sets `Settings\FirstRun` to 0 and `Windows\RunWizard`, `RunWarnings` and `RunPromote` to 1, plus
   `Settings\CloseMode` to 1.
4. Turns on `DebugLog` with `LogLevel` 4.

Then start a client with `WINEPREFIX=~/.wine-shareaza-sf wine "C:\\Program Files\\Shareaza\\Shareaza.exe"`,
or the `previ` prefix for the fork. Stop it with `wine taskkill /IM Shareaza.exe`, without `/F`. That
closes it cleanly, so it saves `Discovery.dat` and `HostCache.dat`.

### Why each step

1. **Discovery.** Replacing `DefaultServices.dat` is the only way to keep the client on one cache.
   - **The file is reloaded constantly.** The client reloads it whenever its service list falls below
     a minimum of 1 webcache, 5 G2, 3 G1, 2 server.met and 1 DC hub list
     (`DiscoveryServices.cpp`, `EnoughServices`). That happens at every start, after every removal,
     and after a cache is dropped for failing.
   - **So deleting services in the Discovery window doesn't help.** The stock defaults come back.
   - **The installer restores the stock file** on every install (`main.iss` copies `Data\*.*`).
2. **Nothing else goes online by itself.**
   - Gnutella1, eD2k and DC are off by default in both versions. BitTorrent, its DHT and UPnP are on.
   - **2.7.10.2 checks for updates at startup until a reply sets `VersionCheck\NextCheck`**
     (`VersionChecker.cpp`, `NeedToCheck`). On a fresh prefix that means at the first start. Its
     log showed a request to
     `http://shareaza.sourceforge.net/version/?Version=2.7.10.2&…`
     ([run 40132278270](https://github.com/Prev-I/Shareaza/actions/runs/40132278270)). A reply can
     also add discovery services (`VersionChecker.cpp`).
   - **The fork's update check is off by default.** When enabled, it queries
     `api.github.com/repos/ansani/Shareaza`.
   - **Each install undoes part of this.** It deletes `VersionCheck` and rewrites `EnableUPnP` from
     its *UPnP* task, which is why the script runs after every install.
3. **Unattended start.** Both are needed:
   - **`Windows\RunWizard`, not `FirstRun`, decides whether the QuickStart wizard opens**
     (`WndMain.cpp`).
   - **While `Settings\FirstRun` is set, the client connects only from inside the wizard.**
   - `RunWarnings` and `RunPromote` skip the two dialogs that follow the wizard. `CloseMode=1` exits
     instead of asking when you click the window's X.
4. **Listening can't be restricted from inside the client under Wine.**
   - Both clients listen on `0.0.0.0:6346`, TCP and UDP. The fork also listens on `[::]:6346`.
   - Shareaza's own option for this, `Connection\InBind` plus `InHost`, needs the `InHost` string,
     and string settings are not read under Wine (see below). In
     [run 40137297045](https://github.com/Prev-I/Shareaza/actions/runs/40137297045) it changed
     nothing.
   - **Close the port on the host instead.** This is untested; adjust it for your firewall. It
     drops inbound TCP and UDP to port 6346 from anywhere but loopback. That blocks unsolicited
     packets from strangers. A hub the client connects to itself can still reach the same code over
     that connection.
   - **It also changes how the client behaves.** It drops the UDP replies to the client's own G2
     datagrams, so the client runs as a UDP-firewalled leaf. Outbound TCP to the hosts a cache hands
     out still works. Keep this in mind when reading the client's behaviour.

     ```bash
     for proto in tcp udp; do
       sudo iptables  -I INPUT -p $proto --dport 6346 ! -i lo -j DROP
       sudo ip6tables -I INPUT -p $proto --dport 6346 ! -i lo -j DROP
     done
     ```

   - **WSL2:** with the default NAT networking, the port is not reachable from the LAN unless
     forwarded. With mirrored networking it is exposed on the host's interfaces. Both are inference,
     untested.

**What this does not isolate.**
- **The cache's hosts.** Once the cache under test returns hosts, the client connects to them. A
  live `gwc-edge` returns real G2 hosts, so the client joins the live network. To stay off it,
  the cache must hand out only hosts you control, behind a host firewall.
- **Crash reports.** Both clients ship one: BugSplat in the fork, BugTrap in 2.7.10.2. After a crash
  or hang it can offer to upload a report. Whether it asks first was not checked.

### Settings and Wine

Wine 9.0's registry helpers differ from Windows in two ways that matter for Shareaza. Both were
seen in CI, and both are visible in Wine's `dlls/kernelbase/registry.c`:

- **A setting is saved only if its section key already exists.**
  - `SHRegSetUSValueW` opens the subkey instead of creating it, so Shareaza's writes to a missing
    section fail silently.
  - In [run 40137297045](https://github.com/Prev-I/Shareaza/actions/runs/40137297045), every section
    created beforehand came back full of values. So did the few that MFC's own profile writes create
    at run time (`Interface`, `Search`, `ListStates`, `Delete`). Every other section (`Gnutella2`,
    `Downloads`, `Library`, …) was missing.
  - In [run 40137712433](https://github.com/Prev-I/Shareaza/actions/runs/40137712433), with every
    section created first, they were all saved.
  - **Effect:** a setting changed in the GUI is lost at the next start.
  - **Fix:** step 0 above, which creates every section.
- **Shareaza's string settings are never read.**
  - `SHRegGetUSValueW` returns an error when called without a buffer.
  - `CRegistry::GetString` makes exactly that call to learn the size first. So every
    `Settings.cpp` item read through it falls back to its default: strings (`InHost`, the download
    folders, the nickname, …), and also floats and string sets, which are stored as strings.
  - Values that MFC reads itself (`GetProfileString`, for window and list layouts) are not
    affected.
  - Only number (`REG_DWORD`) settings can be preset or changed. Seen in [run 40137297045](https://github.com/Prev-I/Shareaza/actions/runs/40137297045):
    `InHost`, set to `127.0.0.1` beforehand, was read as empty and saved back as `""`, and the
    listeners stayed on `0.0.0.0`.
  - Strings are still *written*: the export shows `Downloads\CompletePath`, for example. They just
    aren't read back.

## Where Shareaza keeps its data

`<prefix>` is `~/.wine-shareaza-sf` or `~/.wine-shareaza-previ`.

| What | Where |
|---|---|
| Settings | the registry, under `HKCU\Software\Shareaza\Shareaza`, one subkey per section (for example `Connection`, `Settings`, `VersionCheck`, `Windows`), as `REG_DWORD` and `REG_SZ` values. Under Wine, see [Settings and Wine](#settings-and-wine). There is no `Settings.xml`. Inspect with `wine regedit`, or `wine reg export 'HKCU\Software\Shareaza' shareaza.reg`, which writes UTF-16. |
| Discovery services (GWebCaches, UHCs) | `<prefix>/drive_c/users/$USER/AppData/Roaming/Shareaza/Data/Discovery.dat` (binary; not `DiscoveryServices.dat`) |
| Host cache | `HostCache.dat` in the same `Data/` folder. With no hosts learnt it is written only at exit. |
| Debug log | `Shareaza.log` in the same folder, in UTF-16 (`iconv -f UTF-16 -t UTF-8`), once `DebugLog` is on |
| Discovery defaults | `<prefix>/drive_c/Program Files/Shareaza/Data/DefaultServices.dat`, reloaded as described [above](#why-each-step) |

**Measured in CI:** after one start and a clean close, both clients' `Data/` folders held
`Discovery.dat` (156 bytes), `HostCache.dat` (48 bytes) and `Shareaza.log`, at the path above with
`$USER` = `runner`.

## Adding a GWebCache and watching it

For a prepared prefix, the cache is already in place through `DefaultServices.dat`. By hand, in a
client that isn't isolated:

1. Open the Discovery window with F9. It is under **View → Advanced → Discovery** in the default
   tabbed interface, and **View → Discovery** in the windowed one. Right-click in it and choose
   **Add Service…**.
2. Set **Type** to **G2 GWebCache**.
   - The dialog starts on *G1 GWebCache*, which a G2-only cache won't serve.
   - The other choices are Gnutella Bootstrap, G1/G2 GWebCache, Server.met URL, DC++ Hub List URL
     and Blocked.
3. Enter the URL. **Use `http://`.**
   - The client's own check (`CheckWebCacheValid`) also accepts `https://`. But HTTPS in these builds
     verifies no certificate, and HTTPS against a cache has not been tested.
   - The URL must be at least 12 characters, with a `.` after the scheme and a `/` somewhere after
     that dot.
   - **`http://localhost:8787/` is rejected** for having no dot. Use `http://127.0.0.1:8787/` for a
     local `wrangler dev`.
4. **`gwc:` links add a G1/G2 cache, not a G2 one.** Opening
   `wine "C:\\Program Files\\Shareaza\\Shareaza.exe" "gwc:http://cache.example.org/"` shows a
   confirmation dialog. Accepting it adds the cache for both G1 and G2, because the link's protocol
   is dropped (`DlgURLAction.cpp` → `DiscoveryServices.cpp`). Prefer the dialog.
5. **Force a query:** right-click the cache and choose **Query Now**. Or just connect: with an empty
   host cache, the client queries a GWebCache on connect.
6. **Watch it:** the **System** window shows discovery activity, and with `DebugLog` on so does
   `Data/Shareaza.log`.

## Which client is which in the cache's logs

A G2 GWebCache request carries `client=` with the four-letter vendor code followed by the version
(`DiscoveryServices.cpp`, spec 2 requests):

| Client | Vendor code | `client=` | User agent | Seen by the stub cache in CI |
|---|---|---|---|---|
| official 2.7.10.2 (SourceForge) | `RAZA` | `RAZA2.7.10.2` | `Shareaza 2.7.10.2` | yes: `client=RAZA2.7.10.2`, `Shareaza 2.7.10.2` ([run](https://github.com/Prev-I/Shareaza/actions/runs/40137712433)) |
| this fork, 2.7.10.6 | `RAZI` | `RAZI2.7.10.6` | `iShareaza 2.7.10.6` | yes: `client=RAZI2.7.10.6`, `iShareaza 2.7.10.6` ([run](https://github.com/Prev-I/Shareaza/actions/runs/40137712433)) |

**The fork is `RAZI`, not `RAZA`.** ivan386's 2017 "Soft name change", which ansani/Shareaza
inherited, renamed the vendor code, so ansani's own 2.7.10.6 builds send `RAZI` as well. When
correlating with `gwc-edge`'s `/stats`, count `RAZI` as Shareaza too.

A full request from either client looks like this, with only `client=` differing:

```
GET /gwc/?get=1&hostfile=1&net=gnutella2&ping=1&pv=4&client=RAZI2.7.10.6&getleaves=1&getnetworks=1&getclusters=0&getvendors=1&getuptime=1
```

**A reply with no hosts counts as a failure.**
- **Observed:** both clients logged `Discovery service "…" failed, fail count 1` after the stub
  answered with only `I|pong|oracle-stub 0.1|gnutella2`.
- **In a client that isn't isolated:** with the default `Discovery\FailureLimit` of 2, the same in
  both versions, a second such reply removes the cache from its list (`DiscoveryServices.cpp`,
  `OnFailure`). A new cache with no hosts to give out loses these clients quickly.
- **In a prepared prefix:** the cache comes straight back from `DefaultServices.dat`, with its count
  reset.

**Listening differs.** The fork also listens on IPv6 (`[::]:6346`); 2.7.10.2 listens only on IPv4.

**The About box** of a fork build shows the commit it was built from, for example
`Release 64-bit (commit 0dbc19d of 2026-10-25)` for `v2.7.10.6-previ.1`. That string was read
from the built `Shareaza.exe`, not from a screenshot.
