# previ.10: subscribable IP lists, current bogon checks, deferred fixes, and version 2.7.11.5: design

Date: 2026-11-16. Status: approved by the owner on 2026-11-16; shipped in `v2.7.11.5-previ.10`
(#49, #50, #51). The scope and the decisions marked *(owner)* were settled with the owner on
2026-11-15/16; items marked *(designer's call)* were settled while writing.

## Intent

previ.10 is a larger release *(owner)*. Besides the fixes deferred from previ.9, it gives users
control over IP filtering, which today rests on a list nobody has maintained since 2011.

The client ships `Data/DefaultSecurity.dat`: 60 IPv4 deny rules collected in 2006-2007 (X-Ray,
ale5000, permblock.txt, Media Defender lists), some of them far too broad (212.0.0.0/16 labelled
"RIPE Network Coordination Center", 85.176.0.0/16, 87.122.0.0/16, 64.34.0.0/16, 203.99.0.0/16).
The installer copies it into a new user's `Security.dat` and never touches an existing one, so
every install made since 2011 still carries those rules. Users who want a current blocklist cannot
use one: `CSecurity::Import` reads only Shareaza XML and Gnucleus lines, drops PeerGuardian and
eMule lines without a word, and turns a range into a per-byte mask that blocks too much or too
little. Every non-single-address rule is scanned linearly on each `IsDenied` miss, so a large list
would also be slow.

Anti-monitoring blocklists have a poor record (Chothia et al., 2012: about 31% of monitoring
hosts were on no I-Blocklist entry), and the useful job is blocking spam, hijacked and criminal
networks and unroutable addresses. The owner decided that the client ships **no third-party list
at all** *(owner)*: redistributing lists whose licences are unclear, or that block whole providers,
is not a choice the fork should make for users. Instead the client offers ready-made lists the
user can subscribe to, refreshes them itself, and keeps only a code-level bogon check on by
default.

The same release carries:

- the fixes approved for previ.9 and moved to previ.10 when previ.9 was limited to the hang
  *(owner, 2026-11-15)*;
- PR #47, the About dialog history *(owner)*;
- current country data (DB-IP via Debian, libGeoIP 1.6.12), designed and built in a separate
  session on `prev-i/geoip-data` *(owner)*. This document covers only its ordering with the rest.

## Goals, non-goals, anti-goals

**Goals.**

- Users can subscribe to IP blocklists by URL, from a catalogue of ready-made lists or their own,
  and the client keeps them current while it runs.
- Users can import PeerGuardian `.p2p`, eMule `ipfilter.dat`, CIDR text and Gnucleus files, and
  are told how many lines were taken and how many rejected.
- Large lists (hundreds of thousands of ranges) cost little memory and little time per check.
- The built-in reserved-address check matches the IANA special-purpose registries.
- New installs start with no shipped deny rules; existing installs lose exactly the 60 old shipped
  rules on upgrade *(owner)*.
- The deferred fixes ship.

**Non-goals.**

- Shipping any third-party list in the installer or fetching one at build time *(owner)*.
- Lists that allow addresses (whitelists) or that carry content rules.
- Per-list update intervals *(owner)*: one daily check for all lists.
- Updating lists while Shareaza is closed, or through the Windows Task Scheduler *(owner)*.
- Changing the existing Scheduler window, the deny-by-default policy, or content/regexp rules.
- Judging which list is "correct": a list's entries are applied as published.

**Anti-goals.**

- **The client contacts a list server the user did not choose.** Nothing is subscribed by default;
  no catalogue entry is pre-ticked; the catalogue is a table in the client, not something fetched.
  The owner's rule stands: the client sends nothing the user did not choose.
- **A list overrides the user.** The user's own Accept rules win over every list.
- **A bad download replaces a good list.** A failed, truncated, unparsable or absurd download keeps
  the previous copy.
- **A list cuts the user off their own network.** Lists never deny loopback, private (RFC 1918 /
  `fc00::/7`) or link-local addresses; those stay under `Connection.IgnoreLocalIP` and the user's
  own rules *(designer's call)*.
- **The hot path slows down.** `IsDenied` is called from about 56 sites, several per packet.

## Constraints

- **Disclosure rule.** Commits, PR texts, release notes and docs describe a fixed defect's class and
  function, never which input or condition reaches it. This applies to the `CDatagrams` items in
  Part 4.
- **`Shareaza.rc` and `setup/scripts/main.iss` stay Windows-1252**, edited byte-exactly;
  `tests/encoding/check-cp1252.py` guards them in CI. New dialogs and strings go into
  `Shareaza.rc`.
- **Release notes:** first paragraph plain ASCII, about 330 characters, checked against the owner's
  release-notes checklist (idea-factory `docs/repositories/Shareaza.md`).
- **The 4th version number rises:** previ.10 is 2.7.11.5.
- **Handed-over PRs get no more pushes.** #47 is handed over; changes it needs go in a new PR.
- **`gh pr create` needs `--repo Prev-I/Shareaza`** in this clone.
- **Tests that need no Windows** follow the `tests/receive-budget/` pattern: header-only code
  compiled with `g++ -Wall -Wextra -Werror` in its own workflow.

## Approaches

**Where list rules live and how they are checked** *(owner chose 1)*:

1. **A separate list store (chosen).** Each list keeps its own sorted range table (IPv4 and IPv6);
   the last good copy is cached on disk; `Security.dat` keeps only the user's rules. `IsDenied`
   checks the user's rules first, then each enabled list by binary search. New code beside the
   rules engine; the rule editor, export and saving stay as they are.
2. **List entries as ordinary `CSecureRule`s.** Reuses saving and export, but 200,000 rule objects
   cost tens of MB, `Security.dat` balloons, every entry becomes a row in the rules table, and the
   address-plus-mask rule format still cannot hold an arbitrary range.
3. **One merged range table across all lists.** One lookup instead of one per list, but it must be
   rebuilt on every toggle or update and carry per-range list membership to count hits; with half a
   dozen lists a binary search per list (about 18 steps for 200,000 ranges) is already cheap.

**Where lists appear in the UI** *(owner chose A)*: (A) an "IP lists" table above "My rules" in the
Security window; (B) two tabs in the Security window; (C) a Settings page like Certificates. A keeps
everything that can block an address in one place.

**How a list is added** *(owner chose A)*: (A) one "Add IP list" dialog with the catalogue and a
custom URL; (B) a drop-down on the button. A has room to say what each list blocks and its risk,
and matches how Shareaza's other dialogs behave.

**What refreshes lists** *(owner)*: a timer inside the client, not the existing Scheduler window,
which wraps the Windows Task Scheduler 1.0 API (`ITaskScheduler`, deprecated) and starts
`Shareaza.exe` with a task argument.

**Default list content** *(owner)*: build-time bundling of Spamhaus DROP, Emerging Threats and
eMule-Security was considered and dropped, because only Spamhaus states redistribution terms and the
eMule list blocks whole providers. Everything became a subscription.

## Part 1: IP lists (pull request B)

### 1.1 Model and storage

A **list** has: a GUID; a name; zero or more HTTPS URLs (zero for an imported file; a catalogue
entry may name more than one, e.g. Spamhaus DROP v4 and v6, fetched together into one list)
*(designer's call)*; enabled flag; time of last successful update; time and result of the last
attempt; range counts; hit counters (today, ever) like rules have.

- **Ranges:** IPv4 as sorted, merged, non-overlapping `[start, end]` pairs of host-order 32-bit
  values; IPv6 likewise with 128-bit values. Merging happens at load, so lookup is one binary
  search per family.
- **On disk** *(designer's call)*: list metadata in `Data\IPLists.dat` (CArchive, own version
  number); each list's parsed ranges in `Data\IPLists\<guid>.bin` (compact binary, written to a
  temporary file and renamed, like `Security.dat`). The raw download is not kept. Startup loads the
  binary files; it never reparses or downloads.
- **Not exported** with the user's rules; the Security XML export is unchanged.

### 1.2 Matching

`CSecurity::IsDenied(IN_ADDR*)` and `(IN6_ADDR*)` keep their order: single-address map, miss cache,
user rule scan. Only when none of these decides does the address go to the lists: if it is
loopback, private or link-local it is skipped; otherwise each enabled list is searched, and the
first hit counts that list's hit and returns deny. Then the default policy applies as today.

- **Locking:** lists are read under the existing `m_pSection`. Parsing and file I/O happen outside
  it; the finished range table is swapped in under the lock.
- **Miss cache:** `m_Cache` and `m_CacheIPv6` are cleared whenever a list is added, removed,
  enabled, disabled or updated. Found while mapping: `FromXML` and `Import` also add rules without
  clearing the cache, so a cached miss can hide a new ban; they clear it too *(designer's call)*.

### 1.3 Formats and parsing

One parser, header-only and free of MFC, so it can be unit-tested on Linux. It detects the format
per line and accepts:

- **PeerGuardian `.p2p`:** `description:a.b.c.d-e.f.g.h`, split at the **last** colon.
- **eMule `ipfilter.dat`:** `a.b.c.d - e.f.g.h , level , description`; a range blocks only when its
  level is below 127, as eMule does. Leading zeros (`001.002.003.004`) are decimal.
- **CIDR text:** `a.b.c.d/n`, single `a.b.c.d`, IPv6 `x::y/n` and single IPv6.
- **Gnucleus:** `a.b.c.d[-e.f.g.h][:comment]`, read as a true range (`FromGnucleusString`'s
  per-byte mask is not reused).
- **Spamhaus DROP JSON lines** (`drop_v4.json`, `drop_v6.json`): one JSON object per line; the
  `cidr` field is taken, metadata lines are ignored.
- Comment lines (`#`, `;`, `//`) and blank lines are skipped and not counted as rejected.
- **Containers:** gzip by a streaming inflate (`inflateInit2` with the gzip header), its output
  capped at the 256 MB limit as it is produced — `CBuffer::Ungzip` cannot enforce the cap — and zip
  through minizip's 32-bit in-memory API (`unzOpen2` over the downloaded buffer; minizip is already
  compiled into `zlibwapi` but unused by the client): every member whose content parses is taken
  *(designer's call)*.

The result reports ranges taken and lines rejected, by reason, for the import message and the log.

### 1.4 Limits and sanity checks *(designer's call)*

- Download capped at 64 MB (`CHttpRequest::LimitContentLength`), decompressed content at 256 MB,
  2,000,000 ranges per list.
- A list is refused, keeping the previous copy, when: it yields no range; any IPv4 range spans 2^31
  addresses or more, or the IPv4 ranges together cover more than half the space; any single IPv6
  range contains all of `2000::/3`.
- IPv6 ranges outside `2000::/3` are dropped silently, not counted as rejected: no global unicast
  peer lives there.
- **Measured on 2026-11-16** (the live catalogue files): Team Cymru's IPv6 fullbogons lists
  `8000::/1`, `4000::/2` and others outside `2000::/3`, and inside it unallocated blocks as short as
  `3000::/4` and `2e00::/7` — so no prefix-length limit can apply inside `2000::/3`. IPv4 coverage
  after merging: eMule-Security 22.6% of the space (176,176 ranges, largest 3 × /8),
  CombinedPrivacy 14.2% (57,715, largest /4), fullbogons 13.9% (2,472, largest /4). All pass the
  IPv4 limits above with margin.
- A refused or failed update is logged with its reason and shown in the list's status.

### 1.5 Fetching

- **Transport:** `CHttpRequest` (WinINet, system proxy, default certificate validation). It sends
  the client's usual User-Agent (`Settings.SmartAgent()`), as the web-cache and update-check
  requests already do *(designer's call: a list host learns only what any web cache learns; a
  neutral agent would need a separate `InternetOpen` path)*.
- **HTTPS only:** the dialog refuses a URL that is not `https://`; after the request the final URL
  (`INTERNET_OPTION_URL`) must still be `https://`, otherwise the update fails. Whether WinINet
  follows an https-to-http redirect is unverified; the check makes it irrelevant.
- **Truncated downloads:** a body shorter or longer than its `Content-Length`, or one whose read
  failed, is refused and the previous copy kept: a cut-off last line could be a wider range.
- **Schedule:** checked from `CMainWnd::OnTimer`'s 60-second block. A list is due 24 hours after
  its last successful update; after a failure it is retried 6 hours later. The first check after
  start waits 2 minutes. One download at a time, on a worker thread *(designer's call)*. Fetching
  does not depend on being connected to G2/eD2k; a failed fetch simply follows the retry rule.
- **"Update now"** fetches the selected lists (every enabled list if none is selected) regardless of
  due time.
- No list is ever fetched unless the user added it.

### 1.6 The catalogue *(owner: the five lists; designer's call: wording)*

Built into the client, none pre-ticked. Each entry has a name, what it blocks, its risk, its
licence or terms, and its URL(s). URLs are checked again when the plan is written and before the
release; any that do not serve over HTTPS are dropped from the catalogue rather than downgraded.

| Entry | URL(s) | Format | Shown note |
|---|---|---|---|
| Spamhaus DROP | `https://www.spamhaus.org/drop/drop_v4.json`, `…/drop_v6.json` | JSON lines | Hijacked and criminal networks; few false positives. Data © The Spamhaus Project. |
| Emerging Threats compromised IPs | `https://rules.emergingthreats.net/blockrules/compromised-ips.txt` | addresses | Known compromised hosts. |
| eMule-Security ipfilter | `https://upd.emule-security.org/ipfilter.zip` | zip holding `guarding.p2p`, which is in **eMule** line format despite its name | Anti-P2P companies; very large (about a fifth of all IPv4 addresses); blocks whole providers and CDN ranges (it lists Cloudflare's `1.1.1.0` block). |
| CombinedPrivacy | `https://raw.githubusercontent.com/bongochong/CombinedPrivacyBlockLists/master/combined-final.p2p` | `.p2p` | Aggregate of several privacy and abuse lists. |
| Team Cymru fullbogons | `https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt`, `…-ipv6.txt` | CIDR | Unallocated space; must stay updated or it blocks new networks. |

### 1.7 User interface (Security window, layout A)

- **Two panes:** "IP lists" above, "My rules" below (today's table, unchanged), with a draggable
  split like the Search window's detail panel; its size is saved in a setting.
- **IP lists columns:** check box (enabled), List, Ranges, Updated (time, or "failed: reason"),
  Hits. Imported lists show the file name and "imported".
- **Toolbar** (skin `Res/Default.xml`, `CSecurityWnd`): today's buttons plus "Add list…" and
  "Update now". Each pane has its own context menu; Remove and the Delete key act on the pane that
  has focus.
- **Add IP list dialog:** the catalogue as check boxes with each entry's note, then Name and URL for
  the user's own list, the accepted formats, Add and Cancel. No interval field *(owner)*.
- **Import…:** Shareaza XML still goes into "My rules" (it is the export format). Any other file
  becomes a new list named after the file. The dialog filter widens to `*.xml;*.net;*.p2p;*.dat;
  *.txt;*.gz;*.zip`. The placeholder "Error" boxes on import and export become real messages; a
  successful import reports ranges taken and lines rejected.
- **Strings:** new dialogs and strings in `Shareaza.rc` and `default-en.xml`; Italian by hand;
  the other languages translated by Claude and marked unreviewed, as in previ.8 *(designer's call)*.

## Part 2: reserved addresses (pull request B)

`CNetwork::IsReserved` (`Network.cpp:1127`) is rebuilt from the IANA IPv4 and IPv6 Special-Purpose
Address Registries, as a header-only table tested on Linux.

- **Reserved** = registry entries that are not globally reachable, plus multicast (`224.0.0.0/4`,
  `ff00::/8`), `240.0.0.0/4` and `255.255.255.255`. Examples: `0.0.0.0/8`, `100.64.0.0/10`,
  `127.0.0.0/8`, `192.0.0.0/24`, `192.0.2.0/24`, `198.18.0.0/15`, `198.51.100.0/24`,
  `203.0.113.0/24`; `::/128`, `::1/128`, `::ffff:0:0/96`, `100::/64`, `2001:db8::/32`, `3fff::/20`.
- **How rows are read** *(designer's call, after the builder check)*: a row counts only when its
  "Globally Reachable" is **False**. Rows marked N/A are not reserved, so Teredo `2001::/32` and
  6to4 `2002::/16` peers stay reachable and a client on such an address does not mark itself
  firewalled. A False row that contains rows marked True or N/A (`2001::/23`) is not taken whole;
  only its own False sub-blocks are (for example `2001:2::/48`). The one exception is
  `192.88.99.0/24` (6to4 relay anycast, deprecated by RFC 7526): it stays reserved as today,
  since no peer has that address. The IPv6 additions are checked against every `IsReserved(IN6_ADDR*)`
  caller (host cache, G2 neighbours, query hits, BT DHT, `IsDeniedComplexCheck`, and the IPv6
  firewalled test at `Network.cpp:343`) before the plan is written.
- **Not reserved here:** private-use and link-local ranges (`10/8`, `172.16/12`, `192.168/16`,
  `169.254/16`, `fc00::/7`, `fe80::/10`). They stay with `IsFirewalledAddress` and
  `Connection.IgnoreLocalIP`, so LAN use is unchanged.
- **Dropped:** `6/8`, `7/8`, `55/8` (US military, routed) and `204.152.64.0/23` (allocated).
- **Fixed:** `198.18.0.0/15` covered only `198.18.1-64.x`; the dead `255.255.255.255` branch; the
  header comment that claims private addresses are treated as reserved.
- The table records the registry date it was taken from. No `IsReserved` caller relies on the
  dropped ranges (checked 2026-11-16).

## Part 3: shipped rules (pull request B)

- **New installs:** `Data/DefaultSecurity.dat` becomes a valid archive with no rules
  *(designer's call: keeping the file avoids touching `main.iss`; the oracle's
  `Prepare-Oracle.ps1` copies it and keeps working)*.
- **Existing installs** *(owner)*: after `Security.Load`, if a new setting
  `Security.DefaultsVersion` is below 1, every rule whose GUID is one of the 60 shipped GUIDs is
  removed, the miss caches are cleared, the file is saved, and the setting becomes 1 (the
  `DISCOVERY_DEFAULTS_VERSION` pattern). A user who edited one of those rules keeps its GUID, so it
  is removed too; the owner accepted this.
- **Facts (2026-11-16):** the shipped file is format version 5 with 60 address rules and 60
  distinct GUIDs; the 2011 version (`ec36d5849`) has the same 60 GUIDs; the 2008 version
  (`7fec8d2c5`) has a different shape and is ignored. A test decodes `DefaultSecurity.dat` **as of
  commit `ec36d5849`** (read with `git show`; the workflow fetches that commit, since the default
  checkout is shallow) and checks the client's GUID table against it *(designer's call: no frozen
  copy of the old list is committed under `tests/`)*.

## Part 4: deferred fixes (pull request A, `prev-i/previ10-fixes`)

Approved for previ.9 and moved here *(owner, 2026-11-15)*:

- **Discovery defaults:** raise `DISCOVERY_DEFAULTS_VERSION` to 2 (`DiscoveryServices.cpp:464`) so
  installs that already ran previ.7 merge the defaults again.
- **`release.yml` Verify line:** say `gh` must be signed in (`gh auth login`) and that `Get-FileHash`
  runs in PowerShell.
- **Lithuanian:** the postpone caption starts with two spaces (`Languages/default-lt.xml:4537`).
- **Oracle:** the Windows oracle's client run fails when the client sends no new cache request.
- **"Release notes" link** (`CtrlHomeView.cpp:168`): from a string resource, translated.
- **Italian log strings** (`Languages/default-it.xml`): 16153 reworded as an accepted leaf (and the
  English "falling back to shielded leaf mode" reconsidered); 16202 says query hit, not query;
  16191 translated. Optional: the hardcoded `/LNI/FW` messages (`G2Neighbour.cpp:813,817`) get
  string IDs.
- **`CDatagrams` reviewer items** (class and function only): a guard against a second
  `Remove(CDatagramOut*)` of the same datagram; `CDatagramOut::Create` clears the other address
  family's fields; the IPv6 debug logging formats an IPv6 address correctly.

## Part 5: release

- **Pull requests and order:** #47 (About history) → GeoIP (`prev-i/geoip-data`, rebased after #47)
  → A (fixes) → B (IP lists, bogons, shipped rules; carries this design and its plan) → C (version
  2.7.11.5, `Shareaza.rc` only). A and B are independent and may merge in either order.
- **Before tagging:** run `geoip-refresh.yml` (GeoIP's step 0 in `docs/RELEASING.md`); re-check the
  catalogue URLs; release.yml dry run and both oracles on the release candidate.
- **Release notes:** the old shipped rules are removed on upgrade; IP lists are optional and off;
  bogon check updated; country data current. Plain first paragraph, no withheld input.

## Verification

- **Linux unit tests** (new workflow, receive-budget pattern): parser (each format, malformed
  lines, eMule levels, last-colon split, IPv6), range merging and lookup (boundaries, adjacency,
  overlap), sanity limits, the reserved-address table, the shipped-GUID table against the real file.
- **MSBuild** on all four legs; the encoding check.
- **Windows oracle:** a fresh install starts with an empty rule set; a planted `Security.dat`
  holding the 60 old rules plus one user rule comes out with only the user rule; importing a
  small local `.p2p` file creates a list. No oracle run subscribes to a live list.
- **Owner's manual checks:** the Security window's two panes and dialog in Italian and English;
  subscribing to one catalogue list and seeing it update; "Update now"; a failed URL's status.

## Left to the builder

- Exact class and file names; how the list store hooks into `CSecurity` and `CMainWnd::OnTimer`.
- The binary format of `IPLists.dat` and `<guid>.bin`.
- The registry snapshot date and its exact entries.
- Whether imports of the same file twice replace or duplicate (prefer replace by file name).
