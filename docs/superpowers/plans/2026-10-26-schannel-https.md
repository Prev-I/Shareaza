# HTTPS downloads over Schannel: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the OpenSSL layer under `CDownloadTransferHTTPS` with Schannel: certificate
policy with three levels, non-blocking handshake, IPv6, no OpenSSL left.

**Architecture:** A self-contained TLS core (`TlsClient`, `TlsVerify`) uses only Win32, SSPI,
CryptoAPI and the STL, never MFC or Shareaza globals. It is a pure byte transform: it never
touches a socket. A standalone console test program links the core and runs offline and network
tests in CI. `CConnection` owns one `CTlsClient` per connection and makes its own `OnRead` and
`OnWrite` TLS-aware, so every write path goes through TLS. App-side glue (`TlsPolicy`) applies
the user's setting, the remembered decisions and the prompt.

**Tech Stack:** C++ (MSVC v143), MFC, Winsock, SSPI/Schannel (`secur32.lib`), CryptoAPI
(`crypt32.lib`), GitHub Actions on `windows-2022`.

**Spec:** `docs/superpowers/specs/2026-10-26-schannel-https-design.md`

## Global Constraints

- Prerequisite: pull requests #14 and #15 are merged into `main`. Branch from `main` after that.
- Windows 10 minimum; MSVC v143; Win32 and x64, Release and Debug; `windows-2022` runners.
- No new third-party dependency. Only `secur32.lib` (already linked) and `crypt32.lib` (to add).
- No certificate failure is bypassed except by the user's setting or their answer to the prompt.
  Never `SCH_CRED_NO_SERVERNAME_CHECK`.
- The upgrade installer download always requires a valid certificate.
- Setting `Connection.TlsCertPolicy`: `0` valid only (default), `1` ask, `2` don't check.
- Revocation is checked soft-fail: offline or missing revocation information passes; a revoked
  certificate fails.
- Nothing blocks on the network while holding `Transfers.m_pSection`.
- Public repository: commit messages and pull requests describe the defect class and the function
  fixed, never which remote input reaches it. Each pull request gets a `reviewer` pass with trigger
  disclosure as a named item. Pull requests go into `main`.
- No compiler warning on changed lines (`/W4`).

## Review Focus

1. **Messages after the TLS 1.3 handshake.** Session tickets arrive after the handshake and make
   `DecryptMessage` return `SEC_I_RENEGOTIATE`; the client must feed them back to
   `InitializeSecurityContext` and carry on, not fail the download. Pinned by
   `NetGithubHttpGetTls13` (Task 2).
2. **Servers that close without close_notify.** Many do. Data received so far must be delivered
   and the connection treated as closed, not as an error. Pinned by `LocalAbruptClose` (Task 2).
3. **Records split across reads.** Throttled reads deliver ciphertext in arbitrary pieces,
   including one byte at a time. Pinned by `LocalDribbleOneByte` (Task 2).
4. **URL forms.** `https://[2001:db8::1]:8443/x`, `https://Host.Example:443/`, `https://user@host/`
   all give the bare lowercase host, with no brackets or port, for the name check and SNI. Pinned
   by `OfflineHostFromUrl` (Task 3).
5. **Many sources on one host in "Ask" mode.** Ten sources failing at once give one prompt, and a
   second certificate on the same host gives its own. Pinned by `OfflinePendingPromptsDedupe`
   (Task 3) and step 7 of Task 6.

---

### Task 1: TLS core: credentials and handshake, with a CI-run test program

**Files:**
- Create: `shareaza/TlsClient.h`, `shareaza/TlsClient.cpp`
- Create: `TlsTest/TlsTest.cpp`, `TlsTest/TlsTestMain.cpp`, `TlsTest/TlsTest.h`,
  `TlsTest/TlsTest_143.vcxproj`
- Create: `.github/workflows/tls-test.yml`
- Modify: `vc143/Shareaza.sln` (add `TlsTest_143.vcxproj`, all four configurations)

**Interfaces:**
- Produces, in `TlsClient.h`:
  ```cpp
  enum class TlsCred { Validating, Manual };
  enum class TlsResult { Ok, NeedMore, Done, Closed, Failed };
  class CTlsClient {
  public:
      static bool Startup();   // acquires both credential handles once; thread-safe; idempotent
      static void Cleanup();   // frees them; call after every CTlsClient is gone
      CTlsClient(TlsCred nCred, const std::wstring& sHost);
      ~CTlsClient();
      TlsResult Start(std::vector<BYTE>& oSend);
      TlsResult Handshake(const BYTE* pIn, size_t nIn, std::vector<BYTE>& oSend);
      bool IsEstablished() const;
      TlsCred Credential() const;
      SECURITY_STATUS LastStatus() const;
      PCCERT_CONTEXT PeerCertificate() const;   // owned by the client
      DWORD Protocol() const;                    // SP_PROT_* of the established session
  };
  ```
- Produces, in `TlsTest.h`: the macros `TLS_TEST_OFFLINE(name)`, `TLS_TEST_NETWORK(name)` and
  `CHECK(expr)`, and `bool RunHandshake(CTlsClient&, const char* pszHost, unsigned short nPort)`,
  a blocking-socket driver.

- [ ] **Step 1: Write the test program and the failing handshake tests** in `TlsTest/TlsTest.cpp`.
  `TlsTestMain.cpp` runs the registered tests selected by `--offline` or `--network`, retries
  each network test up to 3 times, and prints `PASS name`, `FAIL name: <expr>` or
  `UNREACHABLE name`. It exits 0 if all pass, 1 on any failure, and 2 if the only problems were
  unreachable endpoints.
  ```cpp
  TLS_TEST_NETWORK(NetValidGithub) {
      CTlsClient c(TlsCred::Validating, L"github.com");
      CHECK(RunHandshake(c, "github.com", 443));
      CHECK(c.IsEstablished());
      CHECK(c.Protocol() & (SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT));
  }
  TLS_TEST_NETWORK(NetValidatingRejectsExpired) {      // expired.badssl.com
      CTlsClient c(TlsCred::Validating, L"expired.badssl.com");
      CHECK(!RunHandshake(c, "expired.badssl.com", 443));
      CHECK(c.LastStatus() == SEC_E_CERT_EXPIRED);
  }
  TLS_TEST_NETWORK(NetValidatingRejectsWrongHost) {    // wrong.host.badssl.com
      /* ... */ CHECK(c.LastStatus() == SEC_E_WRONG_PRINCIPAL);
  }
  TLS_TEST_NETWORK(NetValidatingRejectsSelfSigned) {   // self-signed.badssl.com
      /* ... */ CHECK(c.LastStatus() == SEC_E_UNTRUSTED_ROOT);
  }
  TLS_TEST_NETWORK(NetValidatingRejectsUntrustedRoot) { // untrusted-root.badssl.com
      /* ... */ CHECK(c.LastStatus() == SEC_E_UNTRUSTED_ROOT);
  }
  TLS_TEST_NETWORK(NetManualAcceptsExpired) {
      CTlsClient c(TlsCred::Manual, L"expired.badssl.com");
      CHECK(RunHandshake(c, "expired.badssl.com", 443));
      CHECK(c.PeerCertificate() != NULL);
  }
  ```
  `TlsTest_143.vcxproj` is a console application that compiles `..\shareaza\TlsClient.cpp`
  (and, from Task 3, `..\shareaza\TlsVerify.cpp`) with the same toolset and CRT as Shareaza. It
  links `secur32.lib;crypt32.lib;ws2_32.lib`, sets
  `OutDir=$(SolutionDir)TlsTest\$(Platform)\$(Configuration)\`, and has no MFC. Create
  `TlsClient.h/.cpp` in the same step with the Interfaces signatures and stub bodies that return
  `TlsResult::Failed`, so the program builds.

- [ ] **Step 2: Add `.github/workflows/tls-test.yml`.** It runs on `pull_request` touching
  `shareaza/Tls*`, `TlsTest/**` or itself, on `workflow_dispatch`, and on `push` to
  `prev-i/schannel-*`. On `windows-2022`, matrix `x64 Release` and `Win32 Debug`, it runs
  `msbuild TlsTest/TlsTest_143.vcxproj /p:Configuration=… /p:Platform=…`, then
  `TlsTest.exe --offline`, then `TlsTest.exe --network`. Exit code 2 fails the step with the
  message "endpoint unreachable".

- [ ] **Step 3: Push the branch and confirm the tests fail.** `CTlsClient` is an empty stub at this
  point. Expected: the build passes and `--network` exits 1, with each `NetValidating*` test
  reported as FAIL.

- [ ] **Step 4: Implement `CTlsClient` credentials and handshake.**
  - `Startup` tries `SCH_CREDENTIALS` (version `SCH_CREDENTIALS_VERSION`) first and falls back to
    `SCHANNEL_CRED` if `AcquireCredentialsHandleW` rejects it. It sets no protocol list.
  - The `Validating` handle has flags `SCH_CRED_AUTO_CRED_VALIDATION |
    SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | SCH_CRED_IGNORE_NO_REVOCATION_CHECK |
    SCH_CRED_IGNORE_REVOCATION_OFFLINE | SCH_CRED_NO_DEFAULT_CREDS`.
  - The `Manual` handle has flags `SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS`.
  - The handshake uses `InitializeSecurityContextW` with `ISC_REQ_SEQUENCE_DETECT |
    ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM`.
    `sHost` is the target name. Input is buffered internally across calls, and
    `SECBUFFER_EXTRA` is kept.

- [ ] **Step 5: Push and confirm the tests pass.** Expected: both legs green; `--network` prints
  `PASS` for all six tests.

- [ ] **Step 6: Commit** — `feat(tls): add a Schannel client core and its test program`.

### Task 2: TLS core: record layer

**Files:**
- Modify: `shareaza/TlsClient.h`, `shareaza/TlsClient.cpp`
- Modify: `TlsTest/TlsTest.cpp`, `TlsTest/TlsTest.h`
- Create: `TlsTest/tls_server.py` (local HTTPS test server)
- Modify: `.github/workflows/tls-test.yml` (generate a certificate, start the server)

**Interfaces:**
- Consumes: Task 1's `CTlsClient`.
- Produces:
  ```cpp
  TlsResult CTlsClient::Encrypt(const BYTE* p, size_t n, std::vector<BYTE>& oSend);
  TlsResult CTlsClient::Decrypt(const BYTE* pIn, size_t nIn,
                                std::vector<BYTE>& oPlain, std::vector<BYTE>& oSend);
  void      CTlsClient::Shutdown(std::vector<BYTE>& oSend);   // appends close_notify
  ```
  `Decrypt` returns `Ok` when it appended plaintext, `NeedMore` when it needs more input, `Closed`
  on close_notify or `SEC_I_CONTEXT_EXPIRED`, and `Failed` otherwise. On `SEC_I_RENEGOTIATE` it
  passes the extra buffer to `InitializeSecurityContextW`, appends any tokens to `oSend` and
  continues. `Encrypt` splits data at `cbMaximumMessage` from `SECPKG_ATTR_STREAM_SIZES`.
- Produces in `TlsTest.h`: `bool HttpGet(CTlsClient&, SOCKET, const char* pszHost, const char* pszPath, std::string& sBody, size_t nChunk = 0)`.
  `nChunk > 0` feeds received ciphertext to `Decrypt` that many bytes at a time.
  Also `bool ServerLogContains(const char* psz)`, which reads the log file the workflow passes to
  `tls_server.py`, and `bool BodyMatchesPattern(const std::string&)`, which checks `body[i] == i % 251`.

- [ ] **Step 1: Write the failing tests.**
  ```cpp
  TLS_TEST_NETWORK(NetGithubHttpGetTls13) {   // Review Focus 1
      // GET / on github.com with "Connection: close"
      CHECK(body.compare(0, 9, "HTTP/1.1 ") == 0);
      CHECK(c.LastStatus() != SEC_E_DECRYPT_FAILURE);
  }
  TLS_TEST_NETWORK(LocalLargeBodyIPv6) {      // server on [::1]:8443, Manual credential
      // GET /5mb: the body is 5*1024*1024 bytes of (i % 251)
      CHECK(body.size() == 5u * 1024 * 1024);
      CHECK(BodyMatchesPattern(body));
  }
  TLS_TEST_NETWORK(LocalDribbleOneByte) {     // Review Focus 3: nChunk = 1, GET /64k
      CHECK(body.size() == 65536 && BodyMatchesPattern(body));
  }
  TLS_TEST_NETWORK(LocalAbruptClose) {        // Review Focus 2: GET /abrupt
      // the server sends 100000 bytes then closes the socket without close_notify
      CHECK(body.size() == 100000);
  }
  TLS_TEST_NETWORK(LocalShutdownSendsCloseNotify) {
      // after Shutdown(), the server's log file contains "close_notify received"
      CHECK(ServerLogContains("close_notify received"));
  }
  ```
  `tls_server.py` uses Python's standard `ssl` and `http.server` modules only. It serves
  `/5mb`, `/64k` and `/abrupt` on `[::1]:8443` with a certificate generated in the workflow by
  `openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost` (the runner's Git
  openssl). It prints `close_notify received` when `unwrap()` succeeds.

- [ ] **Step 2: Push and confirm the new tests fail** (`Decrypt` and `Encrypt` are stubs).

- [ ] **Step 3: Implement `Encrypt`, `Decrypt` and `Shutdown`.** `Shutdown` uses
  `ApplyControlToken(SCHANNEL_SHUTDOWN)` and then one `InitializeSecurityContextW`.

- [ ] **Step 4: Push and confirm everything passes** on both legs.

- [ ] **Step 5: Expert review of the state machine.** Write `git diff main.. -- shareaza/TlsClient.*`
  to a file and dispatch `expert` with that path. Ask for a correctness review of handshake,
  renegotiation, `SECBUFFER_EXTRA`/`SEC_E_INCOMPLETE_MESSAGE` handling and buffer ownership.
  Fold its findings in.

- [ ] **Step 6: Commit** — `feat(tls): encrypt, decrypt and close over Schannel`.

### Task 3: TLS core: certificate evaluation, trust store, URL host

**Files:**
- Create: `shareaza/TlsVerify.h`, `shareaza/TlsVerify.cpp`
- Modify: `TlsTest/TlsTest.cpp`, `TlsTest/TlsTest_143.vcxproj`

**Interfaces:**
- Produces:
  ```cpp
  enum class TlsCertProblem { None, Expired, WrongName, Untrusted, Revoked, Other };
  TlsCertProblem VerifyServerCertificate(PCCERT_CONTEXT pCert, const std::wstring& sHost);
  TlsCertProblem ProblemFromStatus(SECURITY_STATUS nStatus);   // None if not a certificate error
  std::wstring   CertFingerprintSha256(PCCERT_CONTEXT pCert);  // 64 uppercase hex digits
  std::wstring   TlsHostFromUrl(const std::wstring& sUrl);     // "" unless the scheme is https
  class CTlsTrustStore {          // thread-safe
  public:
      bool   IsAccepted(const std::wstring& sHost, const std::wstring& sFingerprint) const;
      void   Accept(const std::wstring& sHost, const std::wstring& sFingerprint);
      void   Clear();
      size_t Count() const;
      bool   Load(const std::wstring& sPath);        // missing file = empty store, returns true
      bool   Save(const std::wstring& sPath) const;  // writes <path>.tmp, then renames
  };
  class CTlsPendingPrompts {      // thread-safe
  public:
      bool Add(const std::wstring& sHost, const std::wstring& sFingerprint); // false if pending
      void Remove(const std::wstring& sHost, const std::wstring& sFingerprint);
  };
  ```
  Hosts compare case-insensitively. The file has one UTF-8 line per entry,
  `host<TAB>fingerprint`. Malformed lines are skipped.

- [ ] **Step 1: Write the failing tests.**
  ```cpp
  TLS_TEST_OFFLINE(OfflineHostFromUrl) {               // Review Focus 4
      CHECK(TlsHostFromUrl(L"https://[2001:db8::1]:8443/x") == L"2001:db8::1");
      CHECK(TlsHostFromUrl(L"https://Host.Example:443/") == L"host.example");
      CHECK(TlsHostFromUrl(L"https://user@host/a?b") == L"host");
      CHECK(TlsHostFromUrl(L"http://host/") == L"");
  }
  TLS_TEST_OFFLINE(OfflineTrustStore) {
      // Accept("Host.example", F1); IsAccepted("host.EXAMPLE", F1) is true;
      // IsAccepted("host.example", F2) is false; Save then Load into a new store keeps
      // Count() == 1; a file holding "garbage\n" loads as Count() == 0; Clear() then Count() == 0
  }
  TLS_TEST_OFFLINE(OfflinePendingPromptsDedupe) {      // Review Focus 5
      // Add(h, f1) is true; Add(H, f1) is false (case); Add(h, f2) is true;
      // after Remove(h, f1), Add(h, f1) is true again
  }
  TLS_TEST_OFFLINE(OfflineProblemFromStatus) {
      CHECK(ProblemFromStatus(SEC_E_CERT_EXPIRED) == TlsCertProblem::Expired);
      CHECK(ProblemFromStatus(SEC_E_WRONG_PRINCIPAL) == TlsCertProblem::WrongName);
      CHECK(ProblemFromStatus(SEC_E_UNTRUSTED_ROOT) == TlsCertProblem::Untrusted);
      CHECK(ProblemFromStatus(CRYPT_E_REVOKED) == TlsCertProblem::Revoked);
      CHECK(ProblemFromStatus(SEC_E_ALGORITHM_MISMATCH) == TlsCertProblem::None);
  }
  TLS_TEST_NETWORK(NetVerifyProblems) {   // handshake with Manual, then Verify
      // github.com → None; expired.badssl.com → Expired; wrong.host.badssl.com → WrongName;
      // self-signed.badssl.com and untrusted-root.badssl.com → Untrusted;
      // the fingerprint of github.com's certificate is 64 hex characters
  }
  ```

- [ ] **Step 2: Push and confirm they fail.**

- [ ] **Step 3: Implement.** `VerifyServerCertificate` uses `CertGetCertificateChain` with the
  peer's `hCertStore` for intermediates and `CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT`. It
  then calls `CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL)` with
  `AUTHTYPE_SERVER`, `pwszServerName = sHost` and `CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS`.
  It maps `CERT_E_EXPIRED`, `CERT_E_CN_NO_MATCH`, `CERT_E_UNTRUSTEDROOT`/`CERT_E_CHAINING` and
  `CRYPT_E_REVOKED` to the enum.

- [ ] **Step 4: Push and confirm everything passes.**

- [ ] **Step 5: Commit** — `feat(tls): evaluate server certificates and remember accepted ones`.

- [ ] **Step 6: Reviewer pass on Tasks 1–3, then open PR A** "feat(tls): Schannel client core".
  It contains no app change yet. The reviewer's named items: trigger disclosure; no path that
  accepts a certificate the policy should reject; buffer bounds.

### Task 4: Connections speak TLS through the core; OpenSSL removed

**Files:**
- Modify: `shareaza/Connection.h`, `shareaza/Connection.cpp`, `shareaza/Network.h`,
  `shareaza/Network.cpp`, `shareaza/Transfer.h`, `shareaza/Transfer.cpp`,
  `shareaza/DownloadTransferHTTPS.h`, `shareaza/DownloadTransferHTTPS.cpp`,
  `shareaza/DownloadSource.h`, `shareaza/DownloadSource.cpp`, `shareaza/Shareaza.cpp`
- Modify: `shareaza/resource.h`, `shareaza/Shareaza.rc`, `Languages/default-en.xml`
  (`IDS_TLS_HANDSHAKE_FAILED` and the reason strings, at the next free IDs)
- Modify: `shareaza/Shareaza_143.vcxproj` and `.filters` (add `TlsClient.cpp`,
  `TlsVerify.cpp`, `TlsPolicy.cpp` and their headers; add `crypt32.lib` to all four
  `AdditionalDependencies`; delete the OpenSSL import at 1383 and the guard at 1440),
  `shareaza/packages.config` (delete line 49)
- Create: `shareaza/TlsPolicy.h`, `shareaza/TlsPolicy.cpp`

**Interfaces:**
- Consumes: `CTlsClient`, `TlsHostFromUrl`.
- Produces:
  ```cpp
  // CConnection
  BOOL TLSConnectTo(const IN_ADDR*  pAddress, WORD nPort, const CString& sHost, TlsCred nCred);
  BOOL TLSConnectTo(const IN6_ADDR* pAddress, WORD nPort, const CString& sHost, TlsCred nCred);
  virtual BOOL OnTlsEstablished();   // default TRUE; a FALSE return closes the connection
  bool IsTls() const;                // m_pTls exists and the handshake has completed
  bool IsTlsValidated() const;       // established with TlsCred::Validating
  const CTlsClient* GetTls() const;
  // CDownloadSource
  CString GetTlsHost() const;        // TlsHostFromUrl(m_sURL)
  // TlsPolicy.h
  TlsCred TlsCredFor(bool bRequireValid);   // Validating if bRequireValid or the policy is 0
  ```
  `CConnection` holds `std::unique_ptr<CTlsClient> m_pTls` and `std::vector<BYTE> m_oTlsSend`
  (ciphertext not yet sent). Both move in `AttachTo` and are freed in the destructor. They
  replace `sslConnection`, `DestroySSL`, `HasSSL`, `OnSSLRead`, `OnSSLWrite`,
  `CNetwork::SSLSend`/`SSLRecv`, `CConnection::SSLConnectTo` and
  `CTransfer::SSLConnectTo`/`SSLConnectToIPv6`, which are deleted.

- [ ] **Step 1: Connection.** `TLSConnectTo` makes the same checks as `ConnectTo` (security
  deny, OutHost bind, FIONBIO, `WSAConnect` accepting `WSAEWOULDBLOCK`) and creates `m_pTls`.
  - In `DoRun`, when `FD_CONNECT` succeeds and `m_pTls` exists, call `Start` and queue its
    output. `OnConnected()` is not called yet.
  - `OnRead`: while `m_pTls` is not established, feed received bytes to `Handshake`. On `Done`,
    call `OnTlsEstablished()`, then `OnConnected()`. Once established, feed `Decrypt` and append
    plaintext to the input buffer. `Closed` behaves like `FD_CLOSE`.
  - `OnWrite` sends `m_oTlsSend` first. When that is empty, it encrypts up to 16 KiB of the
    output buffer into it and removes those bytes from the buffer. Bandwidth limits apply to
    bytes on the wire.
  - `Close` appends close_notify (`Shutdown`) and makes one non-blocking send attempt before
    closing the socket.
  - A failed handshake logs `IDS_TLS_HANDSHAKE_FAILED` (`%s` host, `%s` reason) and calls
    `OnDropped()`.

- [ ] **Step 2: HTTPS transfer.**
  - `Initiate` uses `TLSConnectTo` with the IPv4 address if set, otherwise the IPv6 address if
    it is not unspecified. The host is `m_pSource->GetTlsHost()` and the credential is
    `TlsCredFor(m_pDownload->m_bRequireValidCert)`. In this task, `m_bRequireValidCert` is a
    placeholder `false` member on `CDownload`; Task 5 makes it real.
  - Delete the `OnRead`/`OnWrite` SSL calls; the inherited handlers now do TLS.
  - Keep `AttachTo`'s early close for connections that are not established TLS (`!IsTls()`).
  - `Shareaza.cpp`: call `CTlsClient::Startup()` after `Network.Init()`, and
    `CTlsClient::Cleanup()` in `ExitInstance` after `Downloads.CloseTransfers()`.

- [ ] **Step 3: Verify OpenSSL is gone.** Run `git grep -n -i openssl -- ':!docs'` and
  `git grep -n -E 'SSL_(new|free|read|write|connect|set_fd|CTX)' -- shareaza`.
  Expected: no output from either.

- [ ] **Step 4: Build.** Push; expected: the four-leg MSBuild and `tls-test.yml` are green, with
  no new warning on changed lines (check with the same log grep used for #14/#15).

- [ ] **Step 5: Manual smoke on Windows** (the owner, or a Windows VM). Add these downloads in the
  client with the default setting:
  1. a GitHub release asset: it completes;
  2. `https://expired.badssl.com/`: the source fails, and the log shows the certificate reason;
  3. `https://[::1]:8443/5mb` against `TlsTest/tls_server.py`: it fails under setting 0 (self-signed).

  Record the results in the PR.

- [ ] **Step 6: Commit** — `feat(https): run https downloads over Schannel and drop OpenSSL`.

### Task 5: Certificate setting, options page, upgrade flag, reuse rule

**Files:**
- Modify: `shareaza/Settings.h` (in `sConnection`: `DWORD TlsCertPolicy;`, plus the enum
  `TLS_CERT_VALID = 0, TLS_CERT_ASK = 1, TLS_CERT_IGNORE = 2` next to the `CONNECTION_*` enum),
  `shareaza/Settings.cpp`
  (`Add( _T("Connection"), _T("TlsCertPolicy"), &Connection.TlsCertPolicy, TLS_CERT_VALID, 1, TLS_CERT_VALID, TLS_CERT_IGNORE );`)
- Create: `shareaza/PageSettingsTls.h`, `shareaza/PageSettingsTls.cpp` (class `CTlsSettingsPage`,
  `IDD_SETTINGS_TLS`)
- Modify: `shareaza/DlgSettingsManager.cpp` (construct the page and `AddPage` it right after
  `pDownloads`), `shareaza/resource.h`, `shareaza/Shareaza.rc`, `Languages/default-en.xml`,
  `shareaza/Shareaza_143.vcxproj` and `.filters`
- Modify: `shareaza/Download.h` (`DOWNLOAD_SER_VERSION` 44 → 45), `shareaza/Download.cpp`
  (save and load `m_bRequireValidCert` after `m_tAdded`, read when `nVersion >= 45`),
  `shareaza/DlgUpgrade.cpp`, `shareaza/TlsPolicy.cpp`, `shareaza/DownloadTransferHTTPS.cpp`

**Interfaces:**
- Consumes: `TlsCredFor`, `CConnection::IsTlsValidated`, `CDownloadSource::GetTlsHost`.
- Produces: `BOOL CDownload::m_bRequireValidCert` (serialised);
  `extern CTlsTrustStore TlsTrust;` in `TlsPolicy.h`, loaded after `Security.Load()` and saved
  next to `Security.Save()` in `Shareaza.cpp`, at
  `Settings.General.UserPath + L"\\Data\\TlsTrust.dat"`;
  `TlsVerdict EvaluateTlsPeer(const CTlsClient& oTls, const CString& sHost, bool bRequireValid, TlsCertProblem& nProblem, CString& sFingerprint)`,
  where `enum TlsVerdict { tlsAccept, tlsReject, tlsAskUser };`.

- [ ] **Step 1: Options page.**
  - A combo with three entries (`IDS_TLS_POLICY_VALID`, `IDS_TLS_POLICY_ASK`,
    `IDS_TLS_POLICY_IGNORE`).
  - The warning line `IDS_TLS_POLICY_IGNORE_WARNING`, shown when entry 3 is selected, reads:
    "The connection stays encrypted, but anyone on the path can impersonate the server. Only
    files with a known hash are still verified after download."
  - The button "Forget accepted certificates" (`IDS_TLS_FORGET`) calls `TlsTrust.Clear()` and
    `Save`, and shows the count removed.
  - Add the dialog entry with its cookie to `Languages/default-en.xml` only; other languages fall
    back to the `.rc` text.

- [ ] **Step 2: Policy.** `EvaluateTlsPeer` rules:
  - Validating credential: an established session is always `tlsAccept`.
  - `bRequireValid`: anything but `TlsCertProblem::None` is `tlsReject`.
  - Policy 2: `tlsAccept`.
  - Policy 1: `None` or `TlsTrust.IsAccepted` gives `tlsAccept`; otherwise `tlsAskUser`.

  `CDownloadTransferHTTPS::OnTlsEstablished` calls it. `tlsReject` logs `IDS_TLS_CERT_REJECTED`
  (host, reason) and closes with `TRI_FALSE`; `tlsAskUser` is wired in Task 6 (here it behaves
  as `tlsReject`). Every failed handshake also closes with `TRI_FALSE`, at every policy level and
  without a prompt: under policy 0 that includes certificate errors
  (`ProblemFromStatus(...) != None`), which go in the log with their reason.

- [ ] **Step 3: Upgrade flag.** `CUpgradeDlg::OnOK` sets `m_bRequireValidCert = TRUE` on the
  `CDownload*` that `Downloads.Add` returns, under the lock it already holds. Redirect sources
  belong to the same download, so the flag covers them.

- [ ] **Step 4: Reuse rule.** In `GiveConnectionToNext`, the existing conditions gain these:
  `pSource->GetTlsHost().CompareNoCase( m_pSource->GetTlsHost() ) == 0 &&
  pSource->m_nPort == m_pSource->m_nPort &&
  ( ! pDownload->m_bRequireValidCert || IsTlsValidated() )`.

- [ ] **Step 5: Build** — push; expected: all green.

- [ ] **Step 6: Manual check** (Windows).
  - Under each of policies 0 and 2, `https://expired.badssl.com/` fails under 0 and downloads
    under 2.
  - After switching to 2, start an upgrade download from a test build whose `UpgradeSources`
    points at `https://expired.badssl.com/`: it fails.
  - A `.sd` saved by the previous build loads with `m_bRequireValidCert == FALSE`.

- [ ] **Step 7: Commit** — `feat(https): certificate policy setting and validated upgrades`.

### Task 6: "Ask me": waiting sources, prompt, remembered decisions

**Files:**
- Modify: `shareaza/Shareaza.h` (`#define WM_TLSPROMPT (WM_APP+120)`), `shareaza/WndMain.h`,
  `shareaza/WndMain.cpp` (`ON_MESSAGE(WM_TLSPROMPT, OnTlsPrompt)`),
  `shareaza/DownloadSource.h/.cpp` (`bool m_bTlsWaiting`, not serialised; `CanInitiate` returns
  FALSE while set; `GetState` returns `IDS_STATUS_TLS_UNTRUSTED` when there is no transfer and
  it is set), `shareaza/Downloads.h/.cpp`, `shareaza/TlsPolicy.h/.cpp`,
  `shareaza/DownloadTransferHTTPS.cpp`, `shareaza/Shareaza.cpp`, `shareaza/resource.h`,
  `shareaza/Shareaza.rc`, `Languages/default-en.xml`

**Interfaces:**
- Consumes: `EvaluateTlsPeer`, `CTlsTrustStore`, `CTlsPendingPrompts`.
- Produces:
  ```cpp
  struct CTlsPromptRequest { CString sHost, sFingerprint; TlsCertProblem nProblem; };
  void RequestTlsDecision(const CString& sHost, const CString& sFingerprint, TlsCertProblem nProblem);
  void CDownloads::OnTlsDecision(const CString& sHost, const CString& sFingerprint, bool bAccepted);
  ```

- [ ] **Step 1:** On `tlsAskUser`, `OnTlsEstablished` does the following:
  - sets `m_pSource->m_bTlsWaiting = true`;
  - logs `IDS_TLS_CERT_WAITING`;
  - calls `RequestTlsDecision` (which posts `WM_TLSPROMPT` with a heap `CTlsPromptRequest` only
    if `CTlsPendingPrompts::Add` returns true);
  - closes with `TRI_TRUE`;
  - returns FALSE.

- [ ] **Step 2:** `CMainWnd::OnTlsPrompt` takes ownership of the request and shows
  `AfxMessageBox( IDS_TLS_PROMPT formatted with host, reason text, fingerprint, MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 )`.
  - Yes: `TlsTrust.Accept` and `Save`.
  - Both answers: take `Transfers.m_pSection`, call `Downloads.OnTlsDecision`, then
    `CTlsPendingPrompts::Remove`.

- [ ] **Step 3:** `OnTlsDecision` visits every source with `m_bTlsWaiting` whose `GetTlsHost()`
  matches.
  - Accepted: clear the flag and make the source eligible to connect at once.
  - Rejected: remove the source.

  A waiting source on a different certificate reconnects and prompts again; that is correct.

- [ ] **Step 4: Build** — push; expected: all green.

- [ ] **Step 5: Manual check** (Windows, policy 1).
  - `https://expired.badssl.com/` shows the source as "Certificate not trusted" and one prompt.
  - No: the source is removed. Yes on a second try: the download proceeds.
  - After a restart, no prompt.
  - "Forget accepted certificates": the prompt appears again.

- [ ] **Step 6: Manual check, Review Focus 5.** Add ten https sources on `expired.badssl.com` to
  one download (the same URL with `?1` … `?10`): exactly one prompt appears.

- [ ] **Step 7: Commit** — `feat(https): ask before trusting an unverified certificate`.
  Reviewer pass on Tasks 4–6 (named items: trigger disclosure; every path where the policy can be
  bypassed; locking around `OnTlsDecision`), then open **PR B**.

### Task 7: Documentation and release

**Files:**
- Modify: `docs/SECURITY-AUDIT.md`, `docs/ORACLE.md`, `docs/oracle-windows/Prepare-Oracle.ps1`
  (its comment saying HTTPS checks no certificate)

- [ ] **Step 1:** Make the audit changes:
  - Status lines: findings 1 and 2 are fixed, with commits.
  - A new item: the connect and TLS handshake used to run blocking while
    `CDownloadTransferHTTPS::Initiate` held the transfers lock. Fixed by the non-blocking
    handshake; class and function only.
  - An addendum section for this change, mirroring the 2026-10-26 one.

- [ ] **Step 2:** In `ORACLE.md`, note the new setting and its default; in `Prepare-Oracle.ps1`,
  correct the comment.

- [ ] **Step 3:** Run `oracle-wine.yml` and `oracle-windows.yml` by hand on the merged `main`;
  both must pass as before.

- [ ] **Step 4:** Reviewer pass (trigger disclosure named), open **PR C**, and after merge tag
  `v2.7.10.6-previ.4` with release notes. The notes cover the setting, the default, and that
  OpenSSL is gone.

- [ ] **Step 5: Commit** — `docs: record the Schannel change in the audit`.

## Stop rule

If Task 4 or 6 needs changes outside `CConnection`, the TLS files, `CDownloadTransferHTTPS`,
`CDownloadSource`/`CDownloads`, the settings and the prompt, or changes to how other protocols'
connections run, or if the Wine or Windows oracle breaks: stop and report to the owner. The
alternative is the spec's removal option.
