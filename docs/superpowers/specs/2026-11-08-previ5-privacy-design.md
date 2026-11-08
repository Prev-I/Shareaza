# previ.5: nothing sent that the user did not choose, and version 2.7.11.0: design

Date: 2026-11-08. Status: draft, awaiting the owner's review. The scope, the pull-request layout,
the version number and the HTTPS-only upgrade check were decided by the owner on 2026-11-08.
Items marked *(designer's call)* were settled while writing and are open to the owner's veto.

## Intent

previ.4 closed the audit's serious findings apart from finding 4's opt-out. A search of the client
for everything it contacts or discloses on its own found a few behaviours the user cannot switch
off. The owner's rule for previ.5: **the client sends nothing the user did not choose**, applied to
four items the owner picked:

1. **BugSplat** uploads crash and hang dumps to BugSplat's service, into the `shareaza` database,
   which belongs to upstream, not to this fork. No setting controls it.
2. **IPv6** listeners always bind to every address, and the client puts its global IPv6 address in
   G2 search results, BitTorrent announces and push requests. No setting controls it. This is the
   last open part of audit finding 4.
3. **Partial-file sharing** (`Uploads.SharePartials`) is forced back on by every settings upgrade,
   even after the user turned it off.
4. **Profile serving** (`Community.ServeProfile`) turned off still lets the nickname, location and
   full profile reach other peers by several paths.

At the same time the fork gets a version of its own, **2.7.11.0**, and the update check moves from
upstream's repository to this fork's releases.

## Goals

1. BugSplat is gone: no code, no binaries, no installer entries, and an upgrade over previ.4
   removes the files previ.4 installed.
2. A new setting, `Connection.EnableIPv6`, **off by default**. Off means the client opens no IPv6
   socket, makes no IPv6 connection, learns no IPv6 address of its own and sends none. On means
   previ.4's behaviour, with two IPv6 defects fixed (see *IPv6*).
3. A settings upgrade never changes `Uploads.SharePartials` again.
4. With `Community.ServeProfile` off, no profile data leaves the client except in a chat the user
   takes part in (see *Profile*).
5. The client reports version 2.7.11.0, and its update check asks
   `api.github.com/repos/Prev-I/Shareaza/releases/latest`, also on installs that already stored
   upstream's URL.

## Non-goals

- The other items of the search: web-cache announcements, UPnP, DHT, multicast, search-result
  auto-preview, certificate revocation fetches, version strings in handshakes. Nothing changes
  there. Web-cache announcements in particular are what the gwc-edge oracle exists to observe.
- Defaults other than the new IPv6 setting. `ServeProfile` stays on by default.
- Verifying the upgrade installer by hash. The owner decided HTTPS is enough for now.
- A dialog control for the IPv6 setting *(designer's call: Advanced settings lists every setting,
  so it is reachable without new dialog resources and translations)*.

## Anti-goals

- **Breaking G2 interoperability.** Every change either omits an optional field or reply that the
  protocol already treats as optional, or reproduces bytes an IPv4-only previ.4 already sends.
- **Weakening the oracle.** What the client sends to web caches must not change, apart from the
  version number.
- **Disclosing a withheld trigger.** The audit withholds how finding 3 is reached. Commit messages,
  pull requests and release notes describe each change by class and function only.

## Constraints

- The fork is public. Its `master` is upstream's import; work goes through pull requests into
  `main`. Fork tags use the `-previ.N` suffix; upstream tags are never pushed.
- The update check compares four plain numbers. A release name is parsed from its first digit, so
  `v2.7.11.0-previ.5` reads as 2.7.11.0. **Every later release must raise the fourth number**, or
  the check will not see it.
- `CSettings::Save` writes every setting to the registry, defaults included (`Settings.cpp`,
  `Item::Save`). A changed default does not reach an install that has run once; a migration in
  `CSettings::SmartUpgrade` is needed. `SMART_VERSION` is 61 today.
- `SmartUpgrade` runs its whole body, including the forced `SharePartials = true`, whenever
  `SMART_VERSION` rises. So the partial-sharing fix must merge **before** the version pull request
  raises `SMART_VERSION`.
- The owner cannot test IPv6. Evidence for it comes from review and from an automated socket check
  (see *Evidence*).
- The oracle workflows install **published releases** today, so they cannot check unreleased code.

## Approaches considered

**Pull-request layout.**
1. One pull request per topic, then a release pull request: smallest reviews, each revertible, one
   full build per pull request.
2. **Two pull requests: all changes, then the version bump. Chosen by the owner.** Fewer builds and
   merges; the bump comes last, so 2.7.11.0 is only stamped on once its contents have landed.
3. One pull request for everything: cheapest, hardest to review and revert.

**BugSplat.** Remove it, or keep it behind an opt-in setting. **Removal** *(designer's call,
not contested by the owner)*: the dumps land in upstream's BugSplat account, which this fork cannot
read, so opting in would only send data to a third party with no benefit to the fork. Removal also
drops 16 third-party binaries and a resource DLL loaded by relative path at crash time.

**IPv6 default.** On keeps previ.4's behaviour; **off** follows the owner's rule. Off was proposed
and not contested. The cost: a user with working IPv6 who leaves it off cannot reach peers that are
only reachable over IPv6. The release notes say so.

**Where IPv6 is cut.** At every writer of our address, or at the sources: the sockets, the outbound
connection choke point and the place the client learns its address. **At the sources**
*(designer's call)*: with no IPv6 socket and no learned address, every writer already finds an
unknown address, which is the state an IPv4-only machine runs in today. Fewer edits, and the
resulting wire bytes are ones peers already see.

## Pull request A: `prev-i/privacy`

### BugSplat

- Remove `RegisterBugReporting` and its call in `InitInstance` (`Shareaza.cpp`), `mpSender` and the
  declaration (`Shareaza.h`), and the `BugSplat.h` include (`StdAfx.h`).
- Remove `BugSplat.lib`/`BugSplat64.lib` and the `..\BugSplat\...` library directories from the
  four configurations in `Shareaza_143.vcxproj`.
- Delete the `BugSplat/` directory.
- Installer (`setup/scripts/main.iss`): remove the BugSplat block in `[Files]`; add
  `[InstallDelete]` entries for `{app}\BugSplat*.dll`, `{app}\BsSndRpt*.exe`,
  `{app}\BugSplatHD*.exe` and `{app}\BugSplatRc*.dll`, beside the BugTrap-era entries. Patterns
  must name only these files: the audit's finding 5 was an installer deleting too much.
- After this, a crash is handled by Windows' own error reporting, which follows the system's
  settings, not the client's.

### IPv6

New setting `Connection.EnableIPv6`, boolean, default `false`, registered beside the other
`Connection` settings. A change takes effect at the next network connect, when the listeners are
opened. No `SmartUpgrade` step is needed: previ.4 never stored the key, so every existing install
reads the default and upgrades with IPv6 off. That is intended, and the release notes say so.

With the setting **off**:

- **Listeners.** `CHandshakes::Listen` and `CDatagrams::Listen` do not call their `ListenIPv6`.
- **Outbound TCP.** `CConnection::ConnectTo(const IN6_ADDR*, WORD)` refuses and returns `FALSE`.
  Every IPv6 TCP path goes through it: neighbours, transfers and BitTorrent peers, HTTPS
  (`TLSConnectTo`), and pushes.
- **Outbound UDP.** No change needed: `CDatagrams::Send(const SOCKADDR_IN6*)` already returns when
  the IPv6 socket is not valid, which covers G2, DHT and Kademlia.
- **Our own address.** `CNetwork::AcquireLocalAddress(const IN6_ADDR&)` returns without adopting
  anything, so `m_pHostIPv6` keeps the unspecified address and port 0.
- **Host selection.** The auto-connect loop in `CNeighboursWithConnect` skips IPv6-only hosts
  instead of trying and failing. IPv6 hosts are still stored and passed on as today
  *(designer's call: turning the setting on later finds a populated cache)*.

What then goes on the wire: the IPv6 half of every G2 node address is all zeros, as on an
IPv4-only machine today. The tracker announce and the BitTorrent extension handshake already skip
an unspecified address. No IPv6 neighbour exists, so the IPv6-only `Listen-IP` and LNI branches are
not reached.

With the setting **on**, behaviour is previ.4's, plus two fixes on that path:

- **`CG2Neighbour::SendStartups`** writes 16 bytes from the IPv4 address field into the IPv6 ping,
  reading past it. It must write our IPv6 address.
- **`ListenIPv6`** in both classes leaves the socket open when `bind` fails, so it counts as
  listening. It must close the socket and leave it invalid.

The builder should also check each remaining use of `m_hSocketIPv6` for a missing validity check.

### Partial-file sharing

Remove `Uploads.SharePartials = true;` from the top of `CSettings::SmartUpgrade`. Do not raise
`SMART_VERSION` in this pull request.

An install upgraded to `SMART_VERSION` 61 already had the setting forced on, and the user's earlier
choice is lost. previ.5 leaves the stored value alone; the release notes ask users who had turned
partial sharing off to check it once *(designer's call: forcing it off would be the same mistake
in the other direction)*.

### Profile

With `Community.ServeProfile` **off**:

| Path | Today | Change |
|---|---|---|
| G2 hit, `UPRO/NICK` (`CLocalSearch::CreatePacketG2`) | always sent when a nick exists | omitted |
| G2 crawl answer, nick and location (`CG2Packet::OnCrawlRequest`) | sent on request | omitted; the answer still goes out with its other fields |
| G2 neighbour `PROFILE_CHALLENGE` (`CG2Neighbour::OnProfileChallenge`) | full profile XML, no setting checked | no reply |
| HTTP profile request and avatar (`CUploadTransferHTTP`) | already refused | unchanged |
| `X-Nick` on uploads (`CUploadTransferHTTP`) and downloads (`CDownloadTransferHTTP`) | always sent | omitted |
| Chat profile challenge (`CChatSession::OnProfileChallenge`) | full profile XML | no reply |
| Chat `X-Nickname` (`CChatSession`) | sent | **unchanged**: a chat is a conversation the user takes part in, and it is governed by `Community.ChatEnable` |

**Acceptance rule:** with profile serving off, no nickname, location or profile XML goes to a peer
over G2, HTTP or a chat challenge. The builder greps every use of `MyProfile.GetNick`,
`MyProfile.GetXML` and `MyProfile.GetPackedGPS` and gates any other G2 or HTTP writer it finds the
same way; the table lists the ones known on 2026-11-08.

Compatibility: the hit already omits `UPRO` when the nick is empty, the crawl fields are answered
only when asked for, a challenge without a reply is what a peer sees from any client with no
profile, and `X-Nick` is an optional header. ED2K and DC also send the nick but are off by default
and out of scope.

### Documentation

- `docs/SECURITY-AUDIT.md`: **Fixed** lines for finding 4's opt-out and the BugSplat item; a line
  in the status paragraph; the "audit as written, apart from" sentence extended accordingly.
- *(designer's call)* The two slips found during the previ.4 review: the "Fixed on 2026-10-27"
  dates of the MiniUPnPc and prebuilt-package items, whose pull requests merged on 2026-11-07, and
  the second addendum's table, which omits PR #16.
- `docs/ORACLE.md`: BugSplat removed from the data-locations text; the IPv6 setting and its default.

### Evidence

*(designer's call, added because the owner cannot test IPv6)*

- **Test an unreleased build.** `oracle-windows.yml` gains an optional input naming a
  `release.yml` run, which `workflow_dispatch` already lets build installers without publishing.
  With it, the workflow installs the x64 installer from that run's artifact, checked against the
  artifact's `SHA256SUMS.txt`, instead of a release. `Install-Shareaza.ps1` gains a parameter for a
  local installer path.
- **Socket check.** In the Windows oracle, while the client runs: with the default settings, no
  socket owned by the client listens on an IPv6 address (`Get-NetTCPConnection` and
  `Get-NetUDPEndpoint` by the client's process ID; it is started through Explorer, so look it up by
  name). One extra short run with `EnableIPv6=1` set before start must show both IPv6 listeners.
- **Order of steps.** After pushing `prev-i/privacy`, the builder dispatches `release.yml` on that
  branch, then `oracle-windows.yml` with that run's ID, and records both runs in the pull request.
  The input takes a run ID; the installer comes from the artifact named
  `Shareaza Windows x64 Release`.
- **BugSplat check.** The same run fails if any `BugSplat*` or `BsSndRpt*` file is in the install
  folder after installing.
- **Expected client strings.** In both oracle workflows, Windows and Wine, the fork's expected
  `client=RAZI<version>&` and `iShareaza <version>` are read from the installed `Shareaza.exe`
  version instead of being hard-coded, so they keep working once 2.7.11.0 is the latest release.
- **IPv6-on acceptance.** The listener check plus review of the two fixes. The client has no unit
  test harness, so none is added for `SendStartups`.
- The owner's own Windows test of the rest: BugSplat files gone after upgrading over previ.4, the
  partial-sharing setting stays off across an upgrade once turned off, and with profile serving
  off a search from a second client shows no nickname.

## Pull request B: `prev-i/version-2.7.11`

Opened after A merges.

- `shareaza/Shareaza.rc`: `FILEVERSION` and `PRODUCTVERSION` 2,7,11,0; `FileVersion` and
  `ProductVersion` "2.7.11.0". The installer reads its version and file name from the built exe.
- `shareaza/Shareaza.h`: `URI_UPDATE` becomes
  `https://api.github.com/repos/Prev-I/Shareaza/releases/latest`; `WEB_SITE` becomes
  `https://github.com/Prev-I/Shareaza/releases` *(designer's call)*.
- `setup/scripts/main.iss`: `AppUpdatesURL` points at the fork's releases *(designer's call)*.
- `shareaza/Settings.cpp`: `SMART_VERSION` 62, and in `SmartUpgrade`
  `if ( General.SmartVersion < 62 ) SetDefault( &VersionCheck.UpdateCheckURL );`, following the
  existing `eDonkey.ServerListURL` precedent. This also replaces a custom update URL, which is
  intended.

The response format does not change: previ.4 already parses GitHub's release JSON
(`CVersionChecker::ExecuteRequest` and `ProcessResponse`, asset lookup by platform and build type).
What the update check then does, unchanged from previ.4 apart from the source: it finds the latest
release, offers the asset whose name contains the platform and `Release`, and downloads it over
HTTPS with a valid certificate required. GitHub's answer carries no SHA-1, so the client does not
offer to run the installer; it arrives as a normal download the user runs.

## Release and after

1. Tag `v2.7.11.0-previ.5` on `main` after B merges; the release workflow builds and drafts it.
2. Release notes: BugSplat removed; IPv6 off by default and what that costs a user with working
   IPv6; partial sharing no longer re-enabled; profile serving off now covers hits, crawls,
   challenges and headers; the update check now asks this fork. Reviewed for trigger disclosure.
3. Run both oracles against the published release.
4. A kits pull request, as PR #22 did: default tag, pinned x64 hash and `ORACLE.md` download lines.

## Left to the builder

- Exact code shape of each gate, and whether `EnableIPv6` is read through a helper.
- Commit split inside pull request A, one commit per topic at least.
- Whether a debug log line notes a refused IPv6 connect.
- How the oracle's artifact input is named, and how the extra IPv6-on run is wired into the
  existing leaf and hub runs.
