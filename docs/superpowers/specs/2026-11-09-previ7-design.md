# previ.7: real release builds, safer update notices, caches, and version 2.7.11.2: design

Date: 2026-11-09. Status: awaiting the owner's approval. The scope and the decisions marked
*(owner)* were settled with the owner on 2026-11-09; items marked *(designer's call)* were settled
while writing.

## Intent

The owner's update test from previ.5 to previ.6 worked, and showed what to fix next. previ.7
collects those fixes and ships them as 2.7.11.2:

- **Release builds.** Every fork release so far has been an alpha build. It shows a warning at
  each start, and a "test period has ended" message a week after it was compiled.
- **The update notice.**
  - The client logs each line of the release notes as a printf format, so a `%` in them is
    undefined behaviour in every client that sees the release.
  - Characters outside the Windows code page become `?`.
  - Line breaks are lost on the Home page.
  - Markdown shows raw.
  - The upgrade window clips the notes, and its checkbox says more than it does.
- **Updates switch the check off.** The installer deletes the update-check settings on every
  install.
- **Doubled query strings.** Cache addresses containing a query string make the client send a
  doubled query, and spread the bad address.
- **Look and small fixes:**
  - the monitor bar's default place;
  - a confusing IPv6 log line;
  - a stale Skin+ label.
- **A rebuilt default cache list**, from caches the owner tested on 2026-11-09, gwc-edge included.
- **The Windows Firewall rule** *(owner, added 2026-11-09 after a live diagnosis)*.
  - The installer's exception covers only the network profile active at install time.
  - The client tries to change firewall policy, which it has no rights to do, and logs a failure at every start.

## Constraints

- The fork is public. Work goes through pull requests into `main`; tags use `-previ.N`.
- Every release raises the version's fourth number. previ.7 is 2.7.11.2.
- **Release notes must not contain `%`.** previ.6 and earlier clients still log them as a format
  string.
- **Release notes must start with a short plain paragraph.** Older clients show the notes raw,
  and their upgrade window shows only the first lines.
- Installer asset names keep `_Release_<date>`. The update check finds the asset by looking for
  `Release` in its URL, so the installer compiler must not get `RELEASE_BUILD=1`.
- **The upgrade window keeps its five controls.** The 30 translation files identify it by its
  exact control list, a "cookie", and any added control drops every translation.
- Commit messages, pull requests and release notes describe changes by class and function, never
  by the input reaching the audit's withheld finding 3.
- No local build: each change gets a check script, CI builds, oracle runs and a reviewer pass.

## Approaches

**Pull-request layout.** Two pull requests as before *(owner)*: A carries every change below, B
only the version.

**Release notes in the client.** Strip Markdown in the client and show a summary with a link to
the full notes *(owner)*. Rendering Markdown was not considered: the Home page renderer has no
lists or inline styles.

**Placing the monitor bar on the menu row.** Two ways:

- MFC's `DockControlBar` with a rectangle at the row's right end, plus a resize hook;
- making the menu bar's width leave room for the monitor bar.

The menu bar stretches to the full row by default, so the second is needed either way. The
first then places the monitor bar.

*Superseded:* the owner meant the navigation bar's row (item 10). Neither the navigation bar nor
the toolbar stretches, so only the first way is needed there: a docking rectangle at the row's
right end, and a resize step that keeps a right-aligned bar at the end.

## Pull request A: `prev-i/previ7`

### 1. Real release builds

The workflows pass `vc143/ReleaseBuild.props` by a relative path that the Visual C++ targets never
find. `ReleaseBuild.props` also imports `vc143/WindowsXP.props`, which for Win32 sets
`_ATL_XP_TARGETING`, `/Zc:threadSafeInit-` (no thread-safe static initialisation) and a 5.01
subsystem. No fork build has ever compiled with those, and the installers need Windows 10.

So *(designer's call)* release builds are not made by importing that file. Instead:

- `release.yml`, `msbuild.yml`, `codeql-analysis.yml` and `sonarqube.yml` define the release macro
  through the `CL` environment variable they already use for the deprecation define:
  `CL: /D_SILENCE_STDEXT_ARR_ITERS_DEPRECATION_WARNING /DRELEASE_BUILD=1`.
- They drop `/p:ForceImportBeforeCppTargets=...` and the `RELEASEBUILD_FILE_PATH` variable.
- `RELEASE_BUILD` is used only by the C++ source (`StdAfx.h`, `Shareaza.cpp`), not by resources
  or IDL, so the compiler define is enough.
- Nothing passes `RELEASE_BUILD` to ISCC.
- The README's build commands change the same way.

**Evidence:** the oracle's installed `Shareaza.exe` must not contain the UTF-16 text
`ALPHA TEST version` (Task: oracle check).

### 2. The release-notes logging bug

`CVersionChecker::ProcessResponse` logs body lines with `theApp.Message( MSG_NOTICE, _T("%s"),
(LPCTSTR)strLine )`.

### 3. UTF-8 through the JSON parse

- `CVersionChecker::ExecuteRequest` converts the response with `CT2CA( strOutput, CP_UTF8 )`.
- `JsonToCStringIMap` decodes keys and values from UTF-8.

### 4. Release notes as a summary with a link

- **New setting `VersionCheck.UpgradeNotesURL`** (string, persisted), from the release JSON's
  `html_url`. `ClearVersionCheck` clears it.
- **New `CVersionChecker` helpers:**
  - `MarkdownToPlainText`:
    - `**`, `__` and backticks are removed;
    - `[text](url)` becomes `text`;
    - leading `#`s are dropped;
    - `* ` and `- ` items become `• `;
    - HTML tags are dropped.
  - `ReleaseSummary`: the first non-empty paragraph of the body, through `MarkdownToPlainText`,
    cut at a word boundary to at most 400 characters, with `…` if cut.
- **`UpgradePrompt` becomes one paragraph:** "Version 2.7.11.2, released 2026-11-10. " plus the
  summary.
  - The date is the date part of `published_at`.
  - There are no line breaks, so the Home page renders it as written and the upgrade window
    wraps it.
  - The Home page's existing template, which every language file carries, needs no change for
    this.
- **The Home page** gets a "Release notes" link after "Click here to upgrade". It is added at
  run time by `CHomeViewCtrl::Update` into the upgrade group, pointing at `UpgradeNotesURL`, and
  only when that is set. A link click goes through `theApp.InternalURI`, which opens `https://`
  in the browser.
  - The link text is the English "Release notes" in every language *(designer's call: adding a
    string to 30 language files for one link is out of proportion; it can be translated
    later)*.
- **The system log** gets the summary line, not every body line.

### 5. The upgrade window

- **`IDC_MESSAGE` shows `UpgradePrompt`**, now a short paragraph, so it fits the existing
  60-unit box.
- **`IDC_DONT_CHECK` reads "Postpone checks for 31 days"** *(owner)*. The behaviour is unchanged:
  `CUpgradeDlg::ParseCheckAgain` already postpones by 31 days.
  - Change the text in `Shareaza.rc`, in `Languages/default-en.xml`, and in
    `Languages/default-it.xml` ("Rimanda i controlli di 31 giorni").
  - The other 28 language files keep their translation of the old label *(designer's call:
    replacing them with English would lose them; they are listed for translators in the pull
    request)*.
- **The checkbox and buttons are re-laid out in `Shareaza.rc`** so the longer label fits in
  English and Italian. The window grows if needed. The translations' cookie is built from the
  first two letters of each control's window class (`CSkin::Apply`), not from geometry. Keeping
  the control order and types keeps it valid.
- **The window shows no link** *(designer's call: a link is a new control, see Constraints)*.
  The Home page carries it.

### 6. The installer keeps the update check

`setup/scripts/main.iss` stops deleting the whole `VersionCheck` key on install. It deletes only
these values:

- `UpgradePrompt`, `UpgradeFile`, `UpgradeSHA1`, `UpgradeTiger`, `UpgradeSize`,
  `UpgradeSources`, `UpgradeVersion`, `UpgradeNotesURL`: a stale offer;
- `NextCheck`: the next start checks at once, if the check is on.

It keeps `UpdateCheck`, `UpdateCheckURL` and `Quote`, in both HKCU and HKLM. The oracle kit
relies on install-time resets; `Prepare-Oracle.ps1` must set `UpdateCheck=0` itself if it does
not already, and `docs/ORACLE.md`'s note on this is updated.

### 7. Cache addresses with a query or fragment

- **`CDiscoveryServices::CheckWebCacheValid`** rejects an `http`/`https` address containing `?`
  or `#`.
- **Loading `Discovery.dat`** (`CDiscoveryServices::Serialize`) drops stored web-cache records
  whose address contains either, with a debug log line.
- **`CDiscoveryServices::Add(CDiscoveryService*)`**, used by the Discovery window, applies the
  same check.

### 8. The default cache list

`Data/DefaultServices.dat` is rebuilt from the owner's test of 2026-11-09:

Every entry is `http://`, exactly as the owner tested it (including `http://gwc-edge.net/`), and
the server.met entry is `servers.met`, the tested address, replacing `servers.php`.

| Type | Entries |
|---|---|
| 2 (G2) | `bj.ddns.net/beacon/gwc.php`, `bj.ddns.net/cachechu/`, `bj.ddns.net/perlcache/perlgcache.cgi`, `bj.ddns.net/skulls/skulls.php`, `cache.jayl.de/g2/gwc.php`, `dkac.trillinux.org/dkac/dkac.php`, `gwc-edge.net/`, `gweb.4octets.co.uk/skulls.php`, `gweb3.4octets.co.uk/gwc.php`, `midian.jayl.de/g2/bazooka.php`, `midian.jayl.de/g2/gwc.php`, `p2p.findclan.net/skulls.php`, `skulls.gwc.dyslexicfish.net/skulls.php` |
| 1 (G1) | `gweb4.4octets.co.uk/`, `gweb4.4octets.co.uk/gwc.php` |
| D | `peerates.net/servers.met`, `upd.emule-security.org/server.met`, `www.gruk.org/server.met` |
| C | `dchublist.com/hublist.xml.bz2`, `dchublist.ru/hublist.xml.bz2` |

- **No M, U or other entries.** The old active entries not in the test are dropped, not banned.
- **Bans:**
  - `cache.trillinux.org/g2/bazooka.php` stays banned *(owner)*. It still serves mostly
    month-old hosts and lists a dead cache.
  - `p2p.findclan.net/skulls.php`, `gweb.4octets.co.uk/skulls.php` and
    `midian.jayl.de/g2/bazooka.php` leave the ban list *(owner)*.
  - The other X lines stay.
- **The footer** is dated 2026-11-09, and its "latest version" link points to this fork.
- **The file must keep passing the oracle.** It replaces `DefaultServices.dat` with its own stub,
  so nothing there depends on this list.

### 9. New defaults reach existing installs

The client merges `DefaultServices.dat` only when it is short of caches, so on its own an
existing install would never see gwc-edge or the lifted bans.

- **A new setting `Discovery.DefaultsVersion`** (integer, persisted, default 0). When it is
  below 1, after `Discovery.dat` has loaded:
  - `CDiscoveryServices::Load` merges the defaults once: `AddDefaults()`, which adds missing
    entries and applies X lines;
  - stored records for the three addresses unbanned in item 8 that are blocked are turned back
    into web caches;
  - the setting becomes 1, and the list is saved.
- *(designer's call: a dedicated counter, not `SMART_VERSION`. `SmartUpgrade` runs before
  discovery services load, and a counter can be raised again for the next list change.)*
- **Side effects:**
  - The one-time merge re-adds a default the user deleted; accepted.
  - Old defaults no longer in the list stay on existing installs until the client's own failure
    count removes them (`IDS_DISCOVERY_FAIL_REMOVE`). Dead caches go away by themselves.

### 10. The monitor bar beside the navigation bar

When no saved bar layout exists, the monitor bar sits at the far right of the navigation bar's row,
the row with Home … Chat, or of the toolbar's row in windowed mode. This is where `SetGUIMode`
already docks it on a mode switch. It changes the position only: whether the bar is shown follows
`Toolbars.ShowMonitor` and the GUI mode exactly as today.

*(Owner, 2026-11-09, after seeing the first build: the bar meant was the navigation bar, not the
main menu; the right-end alignment is right. A first version put the monitor on the menu row; it
was replaced in a follow-up pull request, and the menu-row sizing code went back to upstream's.)*

- **Detecting no saved layout:** before `LoadBarState`, `CMainWnd::HasSavedBarLayout` reads MFC's
  own summary value, `Toolbars\CoolBar-Summary\Bars`.
- **Placing it:** after the navigation bar or toolbar has been shown, the monitor bar is docked
  into that bar's row with a rectangle at the right end of the dock bar's client area.
- **Height:** unchanged; the monitor bar already snaps to the navigation bar's or toolbar's height.
- **Resizing** *(designer's call, revised at review)*: neither bar stretches, so a docked bar
  keeps its place when the window grows, and a narrow window pushes it next to the navigation bar
  or onto a row of its own. `CMainWnd` remembers whether the monitor bar belongs at the row's
  right end, and after a resize puts it back there once the row has room for both bars.
  - The intent is set when the default placement runs, and otherwise read from where the bar sits:
    it is re-read only when the bar has moved since the last resize, so a bar the user drags
    elsewhere stays where they put it, and one they drag to the end stays at the end.
  - This applies to saved layouts too: loading one is untouched, but a monitor bar it puts at the
    row end is kept there on resize.
  - A hidden monitor bar is not moved; shown again, it goes back to the end at the next resize.
  - Right-to-left layouts are not handled, as in upstream's `SetGUIMode`.
- **Every GUI mode** uses the same default. Mode switches keep working as before.
- **Evidence:** the oracle's screenshots, `screen-*.png`: one from a fresh profile, with the bar
  at the right end of the navigation bar's row, and one from the layout the previous run saved,
  unchanged.

### 11. Small fixes

- `CShakeNeighbour::ConnectTo(const IN6_ADDR*, ...)` logs its failure with the argument's
  address, not the unset `m_pHostIPv6`.
- `Skins/Skin+/Skin+.xml`: the homepage item reads "_Shareaza site", as in `Default.xml`.
- `docs/ORACLE.md`: the update-check note names this fork's repository, not ansani's.

### 12. The Windows Firewall rule

*(owner, 2026-11-09; full findings in the SDD addendum `addendum-12-firewall.md`)*

**The installer owns one inbound allow rule** named `Shareaza`:

- program `{app}\Shareaza.exe`;
- any protocol and any remote address;
- profiles **Private and Domain**, not Public;
- no edge traversal.

**With the `firewall` task:**

- it first deletes every inbound rule named `Shareaza` for that program, from any profile. That
  covers the legacy TCP and UDP pair from `HNetCfg.FwMgr`'s current-profile-only API, and a rule
  made by hand;
- it then adds the rule.

**Without the task, and on uninstall:** the same delete, and nothing is added.

**Mechanism** *(designer's call, as the addendum suggests)*:
`netsh advfirewall firewall delete rule name=Shareaza dir=in program="…"`, then `… add rule …
profile=private,domain`, through `Exec`. The `delete` matches name and program across all
profiles. Exit codes are checked, not localized output. The duplicated silent and interactive
branches of `main.iss` merge into one; a failure in interactive mode still shows
`{cm:dialog_firewall}`. The legacy `HNetCfg.FwMgr` code in `main.iss` goes.

**The client stops changing firewall policy.** It runs as invoker, so an add always failed.

- `CFirewall` loses `AddProgram`, `EnableProgram`, `RemoveProgram`, `EnableService` and
  `SetupService`, with its `Sleep(3000)`.
- `CNetwork::Clear` no longer removes the exception.
- `Connection.DeleteFirewallException` is dropped.
- At startup, when `Connection.EnableFirewallException` is on and the firewall is on for the
  current profile, the client asks `INetFwMgr::IsPortAllowed` whether `Shareaza.exe` may receive
  TCP and UDP on `Connection.InPort`. This needs no admin rights.
- If either is blocked, it logs one `MSG_NOTICE`: "Windows Firewall blocks incoming TCP/UDP for
  Shareaza on this network. If Windows treats this network as Public, set it to Private;
  otherwise run the installer again with the firewall option, or allow Shareaza.exe in Windows
  Firewall." The rule leaves Public networks out, so a Public network is the likeliest cause, and
  reinstalling does not help there (wording revised at review).
- When traffic is allowed, or the firewall is off, it logs nothing.
- A check that could not run gives at most an info line, never an error.

**Evidence:** for builds with this installer, the Windows oracle asserts the rule after installing:
exactly one rule `Shareaza` for the installed exe, Inbound, Allow, Enabled, profiles Domain and
Private, not Public. Before installing, it plants the TCP and UDP pair the old installer made, so
that check also shows the pair is replaced. It also uninstalls at the end and asserts that no such
rule is left.

**Out of scope:** the installer's `upnp` task, which sets the UPnP Device Host service to start
automatically.

## Pull request B: `prev-i/version-2.7.11.2`

`Shareaza.rc` goes to 2.7.11.2. No `SMART_VERSION` change: item 9 has its own counter. It is
opened after A merges.

## Release and after

As for previ.6:

1. Tag `v2.7.11.2-previ.7`.
2. Run the Windows oracle on the draft's build, including the new alpha-text check.
3. Write release notes: plain first paragraph, no `%`. Have the reviewer check them.
4. Publish.
5. Run both oracles against the release.
6. Open the kits pull request.

**The owner's test of the update path:** previ.6 to previ.7 shows the summary and the link,
correct characters, and keeps the update check on after installing.

- The previ.6 installer still switched the check off, so it must be on in previ.6 before the test:
  *Help → Check for new version* does that.
- previ.7 is the first installer that keeps it. Users who lost the setting to an earlier install
  are not switched back on.

## Non-goals

- Translating the new link text and the relabelled checkbox into the other 28 languages.
- WinINet and IPv6, which is still the owner's decision.
- Rendering Markdown.
- Changing the IPv6 success-message ports in the eD2k and DC neighbours, a side note of the
  search: a one-line follow-up if wanted.

## Left to the builder

- Exact helper signatures.
- The summary cut rule beyond "first paragraph, ≤400 characters, word boundary".
- How `OnSize` repositions the monitor bar.
- The registry probe for a saved layout.
- The Italian wording, if a better one fits.
