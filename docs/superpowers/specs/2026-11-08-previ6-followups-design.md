# previ.6: reviewer follow-ups, README, and version 2.7.11.1: design

Date: 2026-11-08. Status: awaiting the owner's approval. Every item and the pull-request layout
were decided by the owner on 2026-11-08; items marked *(designer's call)* were settled while writing.

## Intent

Clear the small defects the previ.5 reviews found, bring the README's build instructions up to date
and credit the earlier work, and ship it as 2.7.11.1. That release also lets the owner test the
update check end to end: a previ.5 client with the check on should find previ.6 on this fork.

## Approaches

Two pull requests, as for previ.5 (**chosen by the owner**): A carries every change below, B only the
version. The alternative, one pull request, would stamp the version before the owner has tested
the contents.

## Pull request A: `prev-i/followups`

1. **Help menu** (`WndMain.cpp` handlers, `Res/Default.xml`, `Shareaza.h`). Checked on 2026-11-08
   with plain `curl`, following redirects:
   - **To the original pages, linked directly** rather than through the old site's `help/?…`
     redirect script, which may go: FAQ, Users Guide, Router Help, Security Help, Codec Help and
     torrent-encoding help go to their pages on `https://shareaza.sourceforge.net/mediawiki/`
     (`FAQ`, `QuickGuide`, `FAQ.FirewallsRouters`, `FAQ.Security`, `Troubleshoot.VideoCodec`,
     `BitTorrent`); Forums to `https://shareaza.sourceforge.net/phpbb/` (dormant since 2022, still
     readable); Skin Site to the DeviantArt search it already led to. The Settings add-ons page
     (`?id=addon`) goes to the old site, where it still works.
   - **Connection Test**: back to the original service, `https://shareaza.sourceforge.net/help/test/`
     with the same query, which now leads to `connectiontest.atdot.ch`. The current target,
     `connectiontest.kirurusec.com`, answers 502. *(designer's call: through the redirect, since the
     service has moved once already.)*
   - **To this fork**: Shareaza site (homepage) to `https://github.com/Prev-I/Shareaza`; Latest news
     to the fork's releases. `WEB_SITE` stays the releases page for the dialogs that use it.
   - **Removed**: Zeropaid.com (site down) and P2PForums.com (parked domain): their items in every
     menu of `Res/Default.xml`, and their handlers. Language files keep the unused translations;
     skins only reuse those items' icons.
   - The original-site base gets a constant of its own beside `WEB_SITE`.
2. **BitTorrent peer ID** (`DownloadWithTorrent.cpp`): version numbers 10 and above are encoded as
   `A`-`Z`, so 2.7.11.x gives `-iS27B…`, matching Shareaza's own decoder (`BTClient.cpp`
   `charint`).
3. **eD2k version** (`EDClient.cpp`, `EDNeighbour.cpp`): the field has three bits for the third
   number; cap it at 7 instead of masking, so peers see 2.7.7, not 2.7.3. *(designer's call)*
4. **IPv6, with `Connection.EnableIPv6` off**:
   - a refused IPv6 connection is logged with its address and the reason at a visible level when
     the user asked for it, and at debug level when automatic;
   - IPv6-only download sources are skipped instead of tried and marked failed, so they are not
     blocked for two hours.
5. **Oracle** (`oracle-windows.yml`): the check messages no longer say "two runs" or "the hub run"
   where the third run is meant; with IPv6 off, the socket check also covers outgoing TCP
   connections, not only listening sockets.
6. **`docs/ORACLE.md`**: the warning box at the top marks which listed findings are fixed, and from
   which release.
7. **`README.md`**:
   - a build section that matches what a build needs today: Visual Studio 2022 with the C++ desktop
     workload and the v143 ATL and MFC libraries (not the VS 2026 images, which lack them), and
     Inno Setup 6, at least 6.3, in its default folder; CI's `release.yml` as the reference setup;
   - gzip.exe, the DirectX SDK and the "Unicode Inno Setup QuickStart Pack" sections removed, with
     why;
   - credits: the original project's Subversion repository on SourceForge
     (`https://sourceforge.net/p/shareaza/code/`, trunk at `svn.code.sf.net/p/shareaza/code/trunk`),
     ivan386's import of SVN build 9329 (`https://github.com/ivan386/Shareaza`), and ansani's
     continuation (`https://github.com/ansani/Shareaza`), which this fork is a fork of.

## Pull request B: `prev-i/version-2.7.11.1`

Opened after A merges. `Shareaza.rc` to 2.7.11.1. No settings migration and no `SMART_VERSION`
change. Release `v2.7.11.1-previ.6` afterwards, with release notes, both oracles, and a kits pull
request, as for previ.5.

## Non-goals

- A CI job upgrading over previ.4 to test the BugSplat cleanup: the owner's own upgrade tests it.
- WinINet HTTP and IPv6: still the owner's decision.
- Language files and skins beyond `Res/Default.xml`.

## Left to the builder

Exact log wording, the helper shape for the version-letter encoding, and how the oracle check
finds outgoing connections.
