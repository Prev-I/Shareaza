# HTTPS downloads over Schannel: design

Date: 2026-10-26. Status: draft. The Schannel route and the certificate policy were decided by
the owner on 2026-10-26; the rest awaits their review.

## Intent

Shareaza is being reworked as a multi-protocol download manager. Plain HTTP is part of the
original core: G1 and G2 transfers are HTTP, and a pasted `http://` link becomes a normal
multi-source download. HTTPS sources were added by ansani in 2023
(`CDownloadTransferHTTPS`, a near copy of the HTTP transfer, on top of OpenSSL). The download
logic works; the TLS layer under it does not meet the bar:

- it accepts any certificate (audit finding 1, `docs/SECURITY-AUDIT.md`);
- it links a third-party, end-of-life OpenSSL 1.1.1b from NuGet (finding 2);
- it supports IPv4 only;
- it connects and does the TLS handshake blocking, inside `CDownloadTransferHTTPS::Initiate`,
  while holding `Transfers.m_pSection`, so one slow server stalls every transfer and the UI.

HTTPS stays a first-class source type. This change replaces the TLS layer with Windows'
Schannel (SSPI) so that certificates are verified by Windows, updated by Windows Update, and no
TLS library ships with the fork.

## Goals

1. HTTPS sources keep everything HTTP sources have today: multiple sources per file, ranges,
   queueing, bandwidth throttling, resuming, and handing a kept-alive connection to the next
   download.
2. Certificates are validated by Windows: chain to a trusted root, host name, validity dates.
3. A user setting decides what happens when validation fails (see *Certificate policy*).
4. TLS works over IPv6 as well as IPv4.
5. Nothing in the TLS path blocks the transfers thread or runs while waiting on the network
   under `Transfers.m_pSection`.
6. OpenSSL is gone: the NuGet package, the `.vcxproj` imports, headers, pragmas and every
   `SSL_*` call. Afterwards `git grep -i openssl` hits only `docs/`.
7. Findings 1 and 2, and the blocking-handshake defect, are closed in `docs/SECURITY-AUDIT.md`.

## Non-goals

- Serving files over TLS (uploads, the built-in web interface). Only outgoing HTTPS downloads.
- Client certificates.
- TLS for G1, G2, eDonkey or BitTorrent connections.
- Changing `CHttpRequest`. Its WinINet requests (version check, discovery services) already
  validate certificates through Windows and stay as they are.
- Choosing protocol versions or cipher suites ourselves. Windows policy decides.

## Anti-goals

The change fails, even if downloads work, if any of these is true:

- a certificate failure can be bypassed by anything other than the user's own setting or their
  answer to the prompt;
- the in-app upgrade installer can be fetched without a valid certificate;
- an https source ever sends or receives application data outside TLS;
- the transfers thread can be stalled by a server that is slow to connect or to handshake;
- the G2 oracle (`docs/ORACLE.md`, `oracle-wine.yml`, `oracle-windows.yml`) behaves differently.

## Constraints

- Windows 10 minimum (installer `MinVersion=10.0`), MSVC v143, Win32 and x64, Release and
  Debug, built on GitHub's `windows-2022` runners (`msbuild.yml`).
- No new third-party dependency. Link `secur32.lib` and `crypt32.lib` from the Windows SDK.
- The repository is public. Commit messages, pull requests and docs describe a defect's class and
  the function fixed, never which remote input reaches it. Every change gets a read-only reviewer
  pass, with trigger disclosure as a named item.
- Work lands as pull requests into `main`. Releases are tagged `v2.7.10.6-previ.N`.
- The fixes in pull requests #14 (Security rules) and #15 (TLS session ownership) land first.
  This change replaces the code #15 touches.

## Certificate policy (owner's decisions)

A setting with three levels, in the existing options (Connection or Downloads page, builder's
choice):

1. **Valid certificates only.** The default. A failed validation fails the source.
2. **Ask me.**
   - The download engine never waits on a dialog. On a validation failure the connection closes
     and the source waits in a visible state such as "certificate not trusted".
   - The UI thread shows a prompt with the host, the reason (expired, wrong name, unknown
     issuer, revoked, ...) and the certificate's SHA-256 fingerprint.
   - Several sources failing at once on the same host and certificate produce one prompt.
   - If the user accepts, the source retries. The decision is remembered for that host and that
     exact certificate, across restarts. A different certificate on the same host asks again.
   - If the user rejects, the source fails as in level 1.
   - The options page has a way to clear the remembered decisions.
3. **Don't check.** The connection stays encrypted but the server is not authenticated. The
   options page says so in one line next to the choice: anyone on the path can impersonate the
   server, and only a file with a known hash is still verified after download.

**The upgrade installer always requires a valid certificate**, whatever the setting says. It is
run by the user and arrives with no hash (`VersionChecker.cpp`, `DlgUpgrade.cpp`).
- *(Build's call)* The requirement is a flag on the `CDownload` that `CUpgradeDlg::OnOK`
  creates, saved in its `.sd` file. It applies to every source of that download, including
  sources created by redirects (a GitHub asset URL normally redirects to another host), and
  after a restart. It overrides the setting and any remembered decision.

**Only certificate validation is subject to the setting.** A handshake that fails for any other
reason (no protocol or cipher in common, malformed messages, validation unable to run) fails the
source at every level, without a prompt. *(Build's call.)*

## Design decisions made by Build (the owner may override)

- **Host name and SNI** come from the current source's URL (`CDownloadSource::m_sURL`, parsed
  with `CShareazaURL`), passed to Schannel as the target name. A redirect creates a new source
  with its own host; nothing carries over between sources.
- **Revocation**: checked, soft-fail (offline or missing revocation information does not fail
  the handshake; a certificate known to be revoked does). This is what browsers do.
- **Credentials**: one process-wide Schannel credential handle per policy (validating, and
  manual-validation for level 3 and for evaluating level 2), created lazily under a lock and
  freed at shutdown. Never `SCH_CRED_NO_SERVERNAME_CHECK`.
- **Level 2 evaluation**: the handshake runs with manual validation, then the chain and name are
  validated explicitly (`CertGetCertificateChain` / `CertVerifyCertificateChainPolicy` with
  `CERT_CHAIN_POLICY_SSL`), so the reason and the certificate are available for the prompt and
  the remembered-decision lookup. Level 1 may use the same path, as long as the result is the
  same as Schannel's automatic validation.
- **Security context**: one per `CConnection`, freed in the destructor and when a new one is
  created, moved with the socket in `CConnection::AttachTo` (the ownership rule #15 sets for
  the OpenSSL session).
- **Non-blocking handshake**: the socket is non-blocking from the start, like `ConnectTo`.
  `FD_CONNECT` starts the handshake, `FD_READ`/`FD_WRITE` drive it, and the transfer's
  `OnConnected()` runs only after the handshake succeeds. Handshake time counts against the
  existing connect timeout.
- **Record layer**: every write path (`DoRun`, `QueueRun`, `DelayClose`) goes through
  encryption; incoming ciphertext is buffered separately so partial records and extra data are
  handled; renegotiation re-enters the handshake; an expired context is treated as the peer
  closing; shutdown sends close_notify before the context is deleted.
- **Connection reuse**: a kept-alive TLS connection is handed to another source
  (`CDownloadTransferHTTPS::GiveConnectionToNext`) only if that source has the same host name
  (case-insensitive) and port and its download allows the same validation outcome (an upgrade
  download never takes a connection validated under a weaker level). Today `Equals` compares
  address and port only, which for TLS could hand one site's session to another site on a shared
  address.
- **No incoming TLS**: TLS is client-side only. A pushed connection, or any connection without
  an established client context, attached to an https transfer is closed, as #15 already does.
  https URLs in the source mesh (`X-Alt`/`Alt-Location`) are advertised and accepted as today.
- **Throttling** counts bytes on the wire (ciphertext), like the socket meters do today. The
  difference from plaintext is a few percent and is documented in a code comment.
- **Where the code lives**: a TLS layer class owned by `CConnection` (or a `CConnection`
  subclass used by `CDownloadTransferHTTPS`), so the HTTPS transfer logic above it changes as
  little as possible. The exact shape is left to the builder.
- **Saved downloads**: `.sd` files with https sources load and resume unchanged
  (`PROTOCOL_SSL` keeps its value).
- **Name resolution is out of scope.** https host names are resolved the way http ones are
  (`CDownloadSource::ResolveURL`, `CShareazaURL::ParseHTTPS`, `Network.Resolve`, IPv4 only and
  blocking). So goal 4 covers IPv6 literals and IPv6 source addresses, and goal 5 covers
  connecting and the handshake, not resolution. Async, dual-stack resolution for http and https
  together is a separate follow-up.
- **Remembered certificate decisions** are stored like other user data, without tamper
  protection: a process that can write them already runs as the user.
- **Wine**: the oracles do not use https downloads, so they need no TLS under Wine and no
  runtime capability check. HTTPS is not compiled out for Wine.

## When to stop and remove the feature instead

The owner's rule: if the impact grows too much, remove the in-house HTTPS download path instead
(expert option D: reject `https://` at parse, keep `.sd` files loading, open the release page in
the browser for upgrades). Build's proposal for "too much", to be confirmed when it happens:
stop and report to the owner if the TLS work cannot be contained in `CConnection`, a TLS layer
class, `CDownloadTransferHTTPS`, the settings and the prompt; if it needs changes to how other
protocols' connections run; or if it breaks the G2 oracle.

## Verification

- The four-leg MSBuild stays green, with no new compiler warning on changed lines.
- A new CI job on Windows, required before merge, runs the built client (or a small test
  harness linking the TLS layer) against real endpoints and checks the outcome per policy level:
  - a valid certificate on a large public host (for example a GitHub release asset);
  - expired, wrong host name, self-signed and untrusted-root endpoints (for example
    `badssl.com`'s);
  - an IPv6-reachable HTTPS host, if the runner has IPv6; otherwise this is noted as untested.

  Each check is retried a few times. An endpoint still unreachable after the retries fails the
  job with a message that says so, distinct from a wrong result; the owner decides whether to
  re-run. *(Build's call.)*
- The Wine oracle and the Windows oracle runs stay green.
- Reviewer passes on each pull request, plus an `expert` review of the Schannel state machine.

## Documentation

- `docs/SECURITY-AUDIT.md`: findings 1 and 2 marked fixed, with commits; the blocking-handshake
  defect added by class and function only.
- `docs/ORACLE.md` and release notes: the new setting and its default.
- Release `v2.7.10.6-previ.4` after merge.

## Left to the builder

The class structure of the TLS layer, the settings key names and options-page placement, where
remembered certificate decisions are stored, the prompt's look, the split into pull requests,
and the test harness shape.
