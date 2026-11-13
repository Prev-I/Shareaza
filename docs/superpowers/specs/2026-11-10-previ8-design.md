# previ.8: verifiable releases, deferred minor fixes, and version 2.7.11.3: design

Date: 2026-11-10. Status: approved by the owner on 2026-11-10. The scope and the decisions marked
*(owner)* were settled with the owner on 2026-11-09/10; items marked *(designer's call)* were
settled while writing.

## Intent

previ.8 is the first release the owner will **announce** to Shareaza users *(owner)*. Whoever
downloads it must be able to check, without trusting the owner's word, that the installer was
built by GitHub Actions from this fork's public source and has not changed since it was
published. The community's recent history makes this the first question anyone will ask: an
earlier GitHub build of Shareaza was reported as a trojan on the original project's tracker, and
the fork's own installers draw heuristic VirusTotal hits.

So previ.8 carries:

- **Verifiable releases** *(owner)*: build provenance attestations, immutable releases, protected
  release tags, written verification instructions, and a written release contract.
- **Groundwork for verifying downloads in the client, without doing it yet** *(owner)*. The client
  keeps downloading the upgrade over HTTPS without checking a hash; everything it would need later
  is put in place and written down.
- **The deferred minor fixes** from the previ.7 reviews *(owner)*: the owner's rule "no release for
  minors alone" no longer applies, because the release has a purpose of its own.
- **Readiness for the announcement**: a place to report problems, and a README that says plainly
  what this fork is.

## Goals, non-goals, anti-goals

**Goals.**

- `gh attestation verify <installer> --repo Prev-I/Shareaza` succeeds for both previ.8 installers.
- `gh release verify v2.7.11.3-previ.8` and `gh release verify-asset` succeed.
- A user without `gh` can check an installer with `Get-FileHash` against a published hash.
- Every backlog item below is fixed or explicitly reasoned out.

**Non-goals.**

- Hash verification inside the client's updater *(owner)*.
- Code signing (needs a paid certificate).
- Bit-reproducible builds.
- SLSA level 3 via an isolated reusable workflow (approach C, rejected below).
- Attesting earlier releases: an attestation can only come from the build that made the file, and
  builds are not reproducible, so previ.1 to previ.7 stay unattested.
- WinINet and IPv6, still the owner's decision.

**Anti-goals.**

- A release that cannot be published because immutability or the tag rule blocks the owner's own
  draft flow.
- Any text, in the release, the README or the announcement, that discloses the audit's withheld
  trigger.

## Constraints

- The fork is public. Work goes through pull requests into `main`; tags use `-previ.N`.
- Every release raises the version's fourth number. previ.8 is **2.7.11.3**.
- **Release notes:** first paragraph plain ASCII, about 330 characters, checked against the owner's
  release-notes checklist. previ.6 and older clients show the notes raw and do not log them safely.
- Installer asset names keep `_Release_<date>`: the update check finds the asset by looking for
  `Release` and the platform in its URL.
- The upgrade window keeps its five controls: translations identify it by its control list.
- **Once a release is published under immutability, its installers can never be replaced.** A
  defect found after publishing means previ.9, and the tag of a deleted immutable release can
  never be reused. The oracle runs on the draft therefore become the last gate, not a formality.
- Commit messages, pull requests, release notes and docs describe changes by class and function,
  never by the input reaching the audit's withheld finding 3.
- No local Windows build: each change gets CI builds, a check script or unit test where possible,
  oracle runs and a reviewer pass.

## Approaches

**Where the attestation is made** *(owner chose A on 2026-11-10)*.

- **A. In the `publish` job (chosen).** One `actions/attest-build-provenance` step on
  `dist/*.exe`, after the hash manifests are verified. Only that small Ubuntu job, which compiles
  nothing, gets `id-token: write` and `attestations: write`. The attestation still names the
  workflow, commit and run, because it is the same run that built the files.
- **B. In each Windows build job.** Closer to the compiler, but it gives attestation-signing rights
  to jobs that run nuget, msbuild and a downloaded installer; a compromised step could sign any
  binary. More exposure for no real gain.
- **C. `slsa-github-generator`.** Provenance made by an isolated reusable workflow (SLSA level 3),
  checked with `slsa-verifier`. Stronger in theory, but a second toolchain for the fork and a second
  tool for every user. Out of proportion for a personal fork.

**Tag protection** *(owner, with A)*: a repository ruleset on `refs/tags/v*`. Immutability locks a
tag only once its release is published; between the tag push and the draft's publication the tag
can still be moved or deleted.

**Pull-request layout** *(designer's call)*: three pull requests, as in earlier cycles.

- **A `prev-i/previ8-release`**: workflows, release docs, README, `SECURITY.md`, Dependabot.
  Independent of the client code, so it can merge first and be exercised by B's CI.
- **B `prev-i/previ8-fixes`**: the client, installer and oracle fixes.
- **C `prev-i/version-2.7.11.3`**: the version only, opened after A and B merge.

## Part 1: verifiable releases (pull request A and repository settings)

### 1.1 Provenance attestation in `release.yml`

- The `publish` job gains `id-token: write` and `attestations: write`, beside `contents: write`.
  The build jobs keep `contents: read` only. `artifact-metadata: write` is not needed: nothing is
  pushed to a registry.
- New step after *Verify and merge SHA-256 manifests*:
  `actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2`, with
  `subject-path: dist/*.exe`. *(designer's call)* `attest-build-provenance` rather than calling
  `actions/attest` directly: since v4 it is a thin wrapper that fills in the SLSA provenance
  predicate, which is exactly what is wanted, and it is the name the owner approved.
- The attestation is made only on a tag push, like the release itself: the `publish` job already
  runs only then. A `workflow_dispatch` run attests nothing.
- `softprops/action-gh-release` moves to v3.0.4
  (`8a0cd651e5b2365bd640854a3fa5dfc70e4875f3`) *(designer's call)*: a maintenance release; v3.0.2
  already reuses existing drafts. The release stays `draft: true`, which is also what the action's
  documentation recommends for immutable releases: assets go on the draft, publication locks them.
- **A draft that is never published leaves its attestation behind.** It attests a file that was
  really built from that commit, so it is harmless, but a discarded draft's installers must not be
  handed out. `docs/RELEASING.md` says so.

### 1.2 Release body: how to verify

The generated `body.md` gains a **Verify** section after the VirusTotal links, plain ASCII, and
passing the owner's release-notes checklist:

- `gh attestation verify <file> --repo Prev-I/Shareaza` (built by this repository's workflow);
- `gh release verify-asset v<tag> <file> --repo Prev-I/Shareaza` (unchanged since publication);
- `Get-FileHash <file> -Algorithm SHA256` compared with `SHA256SUMS.txt` or the hash GitHub shows
  beside each asset;
- the minimum `gh` version: **2.81.0** for `release verify`, and in any case 2.67.0 or later for
  `attestation verify` (older versions could report success with no attestation, CVE-2025-25204).

The owner's curated notes still go on top, so the first paragraph rule is unaffected.

### 1.3 Repository settings

Changed by the builder through the REST API, each at the step named in *Release and after*, and
recorded in `docs/RELEASING.md` so they can be checked later:

| Setting | How | Effect |
|---|---|---|
| Immutable releases | `PUT /repos/Prev-I/Shareaza/immutable-releases` | On publish, assets and tag are locked; GitHub signs a release attestation. Title and notes stay editable. Earlier releases are unaffected. |
| Tag ruleset `release-tags` | `POST /repos/Prev-I/Shareaza/rulesets`, target `tag`, include `refs/tags/v*`, rules `deletion`, `update`, `non_fast_forward` | Release tags cannot be deleted or moved. Creation stays open. |
| Issues | `PATCH /repos/Prev-I/Shareaza` `has_issues: true` | Users of the announced release can report problems. |
| Private vulnerability reporting | `PUT /repos/Prev-I/Shareaza/private-vulnerability-reporting` | Security reports arrive privately, as `SECURITY.md` asks. |

**The ruleset has no bypass actor** *(owner, 2026-11-10)*. The owner can still
create tags. Deleting or moving one needs the ruleset switched off in Settings first: a deliberate
step, which is the point. Today the rulesets list is empty, so the feature is available on this
repository.

**Unverified, and how it is covered:** GitHub's documentation recommends "draft first, attach
assets, then publish" but does not say in so many words that a draft's assets can be replaced. The
previ.8 release is the first exercise. If uploading to the draft fails, the fallback is to switch
immutability off, finish the draft, switch it on again before publishing. Nothing is lost, because
immutability acts at publication.

### 1.4 Verifying the published release automatically

New workflow `verify-release.yml` *(designer's call)*, on `release: published` and
`workflow_dispatch` with a tag input:

- downloads the release's `.exe` assets and `SHA256SUMS.txt`;
- runs `sha256sum -c SHA256SUMS.txt`;
- checks each asset's API `digest` equals its manifest line;
- runs `gh attestation verify` for each installer with `--repo Prev-I/Shareaza`,
  `--signer-workflow Prev-I/Shareaza/.github/workflows/release.yml`,
  `--source-ref refs/tags/<tag>` and `--deny-self-hosted-runners`;
- runs `gh release verify <tag>` and `gh release verify-asset <tag> <file>` for each installer.

It is the release's own proof that the instructions given to users work. It runs on
`ubuntu-latest`, needs only `contents: read`, and uses the runner's `gh`, whose version it logs and
checks against 2.81.0.

- **Retries** *(designer's call)*: the release attestation and asset digests may appear shortly
  after the `release: published` event, so each `gh` check is retried for up to five minutes before
  the job fails.
- **A failure is a signal, not a verdict.** The owner looks at which check failed. If the files
  themselves are wrong, the answer is previ.9 and a note on the release; if the tooling or timing
  is at fault, the workflow is re-run by `workflow_dispatch`. `docs/RELEASING.md` says this.

### 1.5 The release contract: `docs/RELEASING.md`

A new document, the one place a future client change (hash verification in the updater) and the
release process both read from:

- **Asset names:** `iShareaza_<version>_<Win32|x64>_Release_<YYYY-MM-DD>.exe`, one per platform,
  plus `SHA256SUMS.txt` in `sha256sum` format (lowercase hex, two spaces, file name).
- **Where a hash comes from:** each asset's `digest` field in the releases API
  (`sha256:<hex>`, present for every asset uploaded since June 2025; previ.7's are present). That
  is the field a client would read, because the client already parses `releases/latest` and walks
  its `assets`. It is guaranteed to describe the file served only for releases published under
  immutability, so **previ.8 is the first release a hash-checking client could rely on**.
- **What a hash check would and would not protect against:** a corrupted or substituted download;
  not a compromised GitHub account, which could publish a new release with matching digests. The
  attestation is the defence for people; a client cannot check Sigstore bundles at reasonable cost.
- **The release steps** (from *Release and after*), the repository settings table above, the
  release-notes rules, and what to do when a defect is found after publication (next `previ.N`,
  never a replaced asset).
- **Verification instructions for users**, the same as the release body's.

### 1.6 README, `SECURITY.md`, Dependabot

- **README**: a *Download and verify* section near the top. It says this is an unofficial personal
  fork, not the original Shareaza project; points at the Releases page as the only download place;
  and gives the three checks from 1.2, linking `docs/RELEASING.md`.
- **`SECURITY.md`** *(designer's call)*: report vulnerabilities privately through GitHub's private
  reporting, not in Issues; which versions get fixes (the latest `previ.N` only); a pointer to
  `docs/SECURITY-AUDIT.md`. It names no defect and no trigger.
- **`.github/dependabot.yml`** *(designer's call)*: weekly updates for `github-actions` only. Every
  action is pinned by commit, so pins go stale silently; Dependabot proposes the bump as a pull
  request the owner merges after the usual checks.

## Part 2: the deferred minor fixes (pull request B)

### 2.1 Release-notes summary (`shareaza/ReleaseNotes.h`)

Today only `**`/`__`, `*`/`-` bullets, single-line tags and backticks are handled. Additions:

- **Blockquote:** a leading `>` (and one following space) is dropped, repeatedly for nested quotes.
- **Emphasis:** single `*x*` and `_x_` lose their marks. `_` counts as a mark only at a word
  boundary, so `snake_case` and `file_name.exe` keep their underscores.
- **`+ ` bullets** become `•` like `* ` and `- `.
- **Escapes:** a backslash before ASCII punctuation is dropped and the character kept literally
  (so `\*` stays `*` and is not taken as a mark).
- **HTML comments** spanning lines are dropped up to the closing `-->`, which may be on a later line.
- **Fenced code blocks** (```` ``` ```` or `~~~`, with or without a language tag) are dropped
  whole, fence lines included *(designer's call)*: code is not summary material.
- **Thematic breaks** (`***`, `---`, `___`, `* * *`, with optional spaces) end a paragraph and
  produce no text.
- **`HasText`** counts a character as text if it is alphanumeric, or non-ASCII other than `•` and
  `…`, so a paragraph of bullets alone is no longer a summary.

The unit test `tests/release-notes/test_release_notes.cpp` gains a case per addition, and a new CI
workflow `release-notes-test.yml` *(designer's call)* builds and runs it with `g++` on
`ubuntu-latest` for changes to `ReleaseNotes.h` or the test. Today nothing runs it.

### 2.2 Upgrade window

- `IDC_MESSAGE` (`Shareaza.rc:1017`) gains `SS_NOPREFIX`, so `&` in a summary shows as `&`. A style
  change does not alter the control list the translations key on; the builder confirms this.
- **The whole prompt is bounded**, not only the summary. `UpgradePrompt` is
  "Version X, released D." plus the summary, and only the summary is capped at 400. The summary's
  budget becomes 400 minus the prefix length *(designer's call)*, so the prompt never passes 400
  characters and the 60-DLU box does not lose its last line.

### 2.3 Home view link

`CHomeViewCtrl::UpdateReleaseNotesLink` re-checks that `UpgradeNotesURL` starts with `https://`
before showing it. The value lives in the registry and can be edited outside the client; the check
when it is stored (`VersionChecker.cpp:344`) is not enough on its own.

### 2.4 Discovery services

- **Editing a cache to an address with `?` or `#`.** Today the edit is applied in place, then
  `Add` refuses it and deletes the listed cache without a word. The dialog
  (`CDiscoveryServiceDlg::OnChangeAddress`) keeps OK disabled for web-cache types while the address
  has `?` or `#`, like it does for a missing `http://`.
- **Editing to an address already listed** (found while mapping the above): the object path checks
  duplicates by pointer, so an edit can make a second entry for one address. `OnOK` refuses an
  address another entry already has, with a message box, and keeps the dialog open
  *(designer's call)*.
- **Merging new defaults when the list is full.** `MergeNewDefaults` removes a lifted ban and lets
  `AddDefaults` re-add the cache; at `Discovery.CacheCount` (50) the re-add is refused, so the cache
  is lost, and new defaults never arrive although `DefaultsVersion` is marked done. Changes
  *(designer's call)*:
  - a lifted ban is converted in place: the blocked entry becomes a web cache for the protocol the
    defaults file gives, keeping its place in the list;
  - during a merge only, shipped defaults are added even past the cap. The cap limits caches learnt
    from the network; the shipped list is about fifteen per protocol, and the normal ageing of
    failing caches trims the list later;
  - `DefaultsVersion` is then marked only after the merge ran, which is already the case, and now
    means what it says.

### 2.5 Firewall check

- **Random port.** With `Connection.RandomPort`, `InPort` is 0 at `CNetwork::Init`, and the real
  port is chosen later in `PreRun`. The check moves to just after the listeners are up, using the
  port actually bound, and runs once per session *(designer's call)*. It also runs again if the
  listener is re-randomised after a bind failure.
- **The firewall-on test.** `IsFirewallOn` reads the profile captured once at `Init`, so a network
  change is missed. If `INetFwMgr::IsPortAllowed` reports allowed when the firewall is off, as the
  previ.7 review suggested, `IsFirewallOn` goes and the check calls `IsPortAllowed` alone;
  otherwise `IsFirewallOn` re-reads the current profile at each check. The builder settles which
  from the API documentation.
- **TCP blocked, UDP check failed:** today this gives "could not check". It now reports the block
  it did find.
- **Silent install whose `netsh` fails** (`main.iss:983`): today no message and no trace. The
  installer writes `Log()` lines for the delete and add commands and their exit codes, so an
  install run with `/LOG` shows what happened; the client's startup check reports the missing
  rule to the user either way.

### 2.6 Oracle (`oracle-windows.yml`, `docs/oracle-windows/`)

- Records the runner's network profile (`Get-NetConnectionProfile`) in the evidence.
- **Exercises the blocked case.** A new step disables the kit's `Shareaza oracle *` rules and the
  installer's `Shareaza` rule, runs the client briefly, asserts the firewall notice in
  `Shareaza.log`, then restores the rules. Today the kit's rules always allow the port, so the
  notice is never seen.
- The uninstall step gets `timeout-minutes: 10`.
- The post-uninstall check looks for **any** inbound rule whose program is the installed
  `Shareaza.exe`, whatever its name (kit rules excluded by their `Shareaza oracle` prefix), not only
  rules named `Shareaza`.

### 2.7 Monitor bar (`shareaza/WndMain.cpp`)

- **Floating main bar:** no placement when the navigation bar or toolbar is floating.
- **Both navigation bar and toolbar shown:** the monitor stays at the end of whichever row it is
  on; only when it is on neither does it go to the navigation bar's row.
- **Hidden monitor shown again** (`OnWindowMonitor`): it is placed at the row end if it was there
  when hidden.
- **Resize:** today every resize step re-docks the bar when it is not at the row end. It is moved
  within its dock bar instead of re-docked, so dragging the window edge does not flicker. The
  builder chooses the MFC call; the evidence is the oracle's resize screenshots.
- **Right-to-left layouts:** with `WS_EX_LAYOUTRTL` the row's end is on the left, but the placement
  uses screen-right edges, as upstream's `SetGUIMode` does. The placement moves to the dock bar's
  own client coordinates, which Windows mirrors under that style, so one computation should serve
  both directions; the builder confirms it. The oracle gains one run with `General.LanguageRTL`
  set and a screenshot check *(designer's call)*.

### 2.8 Translations of the upgrade window's checkbox

27 languages show the old meaning ("don't check for new versions") and Finnish shows the old
English text, while the box postpones checks by 31 days. The builder translates
"Postpone checks for 31 days" into the 28 languages, in both `Languages/default-*.xml` and the
`.po` files and `default-en.pot` *(owner, 2026-11-10)*. Each file keeps its encoding and format;
the reviewer checks them. The pull request says the translations are
not reviewed by native speakers.

## Pull request C: `prev-i/version-2.7.11.3`

`Shareaza.rc` to 2.7.11.3. No `SMART_VERSION` change: no setting changes meaning.

## Release and after

**Who does what** *(designer's call)*. The session executes every step, but each outward step
(a tag push, a repository-settings change, publishing, opening the kits pull request) waits for
the owner's explicit go at that step, as the owner requires. Publishing the release is
the owner's own act in the GitHub interface, after the oracle runs and the notes review.

**Rehearsal before previ.8** *(owner, 2026-11-10)*.

0. After pull request A merges: switch on immutable releases, but not yet the tag ruleset
   *(designer's call: immutability acts only at publication, so it cannot harm a draft that is
   never published, and the rehearsal must test drafts with it on)*. Push a rehearsal tag
   `v2.7.11.2-rc.1` on `main`. `release.yml` builds, attests and creates a draft that is never
   published. On that draft the session checks: both attestations verify with
   `gh attestation verify`; an asset can be replaced on the draft (`gh release upload --clobber`);
   the draft's asset digests match `SHA256SUMS.txt`. Then the draft and the rehearsal tag are
   deleted. The rehearsal cannot exercise `gh release verify`, which needs a published immutable
   release, so that part is first run on previ.8 itself, by `verify-release.yml`. Drafts are not
   visible to the update check, which asks for the latest published release.
1. Before tagging previ.8: switch on the tag ruleset (1.3).
2. Tag `v2.7.11.3-previ.8` on `main`. `release.yml` builds, attests and creates the draft.
3. Run the Windows and Wine oracles on the draft's build. **This is the last gate**: after
   publication nothing can be replaced.
4. Write release notes: plain ASCII first paragraph, about 330 characters, checked against the
   owner's release-notes checklist. The reviewer checks them, including for trigger disclosure.
5. Publish. `verify-release.yml` runs; it must pass.
6. Run both oracles against the release, then open the kits pull request.
7. Before the announcement: switch on Issues and private vulnerability reporting.
8. Record previ.8 in the owner's disclosure record.

**If the tag's build fails, or the draft is bad, before publication** *(designer's call)*: switch
the ruleset off, delete the draft and the tag, fix through a pull request, tag again, switch the
ruleset on. Nothing is published, so immutability is not involved and the tag name is not burnt.
Once published, a defect means previ.9.

**The owner's update test:** previ.7 to previ.8 is the first update whose notice uses the new
summary and the *Release notes* link (previ.6 rendered previ.7's notes the old way).

## Trigger-disclosure check

The README and `SECURITY.md` link `docs/SECURITY-AUDIT.md`, which is already public and was
written without the withheld trigger, so linking it adds nothing new. The reviewer still checks,
as a named item, pull requests A, B and C, their commit messages, the new docs and the release
notes for trigger disclosure before each goes public.

## Settled with the owner on 2026-11-10

1. **Rehearsal:** yes, with the public tag `v2.7.11.2-rc.1` and a draft never published, both
   deleted afterwards (step 0).
2. **Tag ruleset bypass:** none; the owner switches the ruleset off to move or delete a release tag.
3. **Translations:** the 28 languages are translated (2.8), marked as not reviewed by native speakers.

## Left to the builder

- The exact MFC call that moves the monitor bar within its dock bar.
- Helper signatures in `ReleaseNotes.h` and the order of the new passes.
- How the oracle's blocked-case step stops the client (time or log line).
- Wording of the README section, `SECURITY.md` and `docs/RELEASING.md`, within the content above.
