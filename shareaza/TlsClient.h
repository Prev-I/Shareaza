//
// TlsClient.h
//
// Copyright (c) Shareaza Development Team, 2026.
// This file is part of SHAREAZA (shareaza.sourceforge.net)
//
// Shareaza is free software; you can redistribute it
// and/or modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2 of
// the License, or (at your option) any later version.
//
// Shareaza is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Shareaza; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//

// CTlsClient is the client side of one TLS session over Schannel. It owns no
// socket: the caller moves bytes between the network and the session. It uses
// only Win32 and SSPI, so it builds without MFC and without precompiled headers.

#pragma once

#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif

#include <windows.h>
#include <wincrypt.h>
#include <sspi.h>
#include <schannel.h>

#include <string>
#include <vector>

// Which process-wide credential a session uses.
enum class TlsCred
{
	Validating,		// Windows validates the chain, the host name and the dates
	Manual			// no validation: the caller must evaluate PeerCertificate()
};

enum class TlsResult
{
	Ok,				// data was produced
	NeedMore,		// send what was produced, then feed more input
	Done,			// the handshake is complete
	Closed,			// the peer closed the session
	Failed			// the session is unusable; see LastStatus()
};

// One instance is not internally synchronised: its owner serialises every
// call on it. Different instances may be used from different threads.
//
// The owner's loop:
//   1. Start(), then Handshake() with every received byte until Done. Send
//      oSend after every call, whatever the result.
//   2. For TlsCred::Manual, evaluate PeerCertificate() and call Accept().
//   3. Call Decrypt( NULL, 0, ... ) once: the final flight may have carried
//      records past the handshake, and only Decrypt() processes them.
//   4. Encrypt() what to send; Decrypt() every received byte. Send oSend
//      after every Decrypt() call, whatever the result.
//   5. Shutdown() and send its close_notify before closing the socket.
class CTlsClient
{
public:
	// Acquires both credential handles once. Thread-safe and idempotent;
	// Start() calls it too. Returns false if Schannel refuses a credential.
	static bool Startup();
	// Frees the credential handles. Call after every CTlsClient is gone.
	static void Cleanup();

	CTlsClient(TlsCred nCred, const std::wstring& sHost);
	~CTlsClient();

	// Begins the handshake. Appends the ClientHello to oSend.
	TlsResult Start(std::vector<BYTE>& oSend);
	// Feeds received bytes. Appends any reply to oSend, which the caller must
	// send whatever the result. NeedMore: wait for more input. Done: the
	// handshake is complete; bytes past it stay buffered until the owner
	// calls Decrypt( NULL, 0, ... ).
	// Valid only between Start() and Done: once the handshake is complete
	// all received bytes go to Decrypt(), and a call here fails the session.
	// With TlsCred::Manual, a server that sends no certificate fails the
	// handshake.
	// With TlsCred::Validating, Schannel builds and checks the certificate
	// chain inside this call and may fetch revocation data over the network,
	// so the call can block for seconds. Do not call it while holding a lock
	// that other I/O needs.
	TlsResult Handshake(const BYTE* pIn, size_t nIn, std::vector<BYTE>& oSend);

	// Accepts the peer certificate of a TlsCred::Manual session, after the
	// owner has evaluated PeerCertificate(). Until then Encrypt() and
	// Decrypt() refuse to work: they fail the session with
	// SEC_E_CERT_UNKNOWN and produce nothing. A TlsCred::Validating session
	// is accepted when its handshake completes, as Schannel validated it.
	// Does nothing before the handshake is complete.
	void Accept();

	// Encrypts n bytes of application data and appends the TLS records to
	// oSend, split at the largest message Schannel allows. p must not point
	// into oSend. Ok: oSend holds the records. NeedMore: a post-handshake
	// message is being processed; nothing is appended, so call again after
	// the next Decrypt(). Closed: the peer closed the session, or Shutdown()
	// was called; nothing is appended. Failed: the session is unusable, and
	// nothing is appended.
	TlsResult Encrypt(const BYTE* p, size_t n, std::vector<BYTE>& oSend);
	// Feeds received bytes once the handshake is complete; nIn may be 0 to
	// decrypt only what is buffered. Appends application data to oPlain and
	// any reply Schannel produces to oSend, which the caller must send
	// whatever the result. Ok: plaintext was appended. NeedMore: wait for
	// more input. Closed: the peer sent close_notify. Failed: the session is
	// unusable. With Closed and with Failed, oPlain may still have received
	// data decrypted by this call before the close or the failure.
	// TLS 1.3 post-handshake messages (session tickets, key updates) are
	// handled here, and their replies go to oSend. A renegotiation in TLS 1.2
	// or earlier is refused: the session fails with SEC_E_UNSUPPORTED_FUNCTION.
	TlsResult Decrypt(const BYTE* pIn, size_t nIn, std::vector<BYTE>& oPlain, std::vector<BYTE>& oSend);
	// Appends close_notify to oSend, once. Afterwards Encrypt() returns
	// Closed. Does nothing before the handshake is complete. Best effort
	// while a post-handshake message is being processed: Schannel may then
	// produce nothing.
	void Shutdown(std::vector<BYTE>& oSend);

	// True while application data can flow: false before the handshake
	// completes, while a post-handshake message is being processed, and after
	// close_notify or a failure.
	bool			IsEstablished() const;
	// True once the handshake has completed, whatever happened since, unless
	// the session failed.
	bool			IsHandshakeComplete() const;
	bool			IsAccepted() const;
	TlsCred			Credential() const;
	SECURITY_STATUS	LastStatus() const;
	PCCERT_CONTEXT	PeerCertificate() const;	// owned by the client
	DWORD			Protocol() const;			// SP_PROT_* of the established session
	bool			IsTls13() const;
	ULONG			PostHandshakeMessages() const;	// SEC_I_RENEGOTIATE seen; a diagnostic

private:
	enum class State
	{
		Initial,
		Handshaking,
		Established,
		Renegotiating,		// Decrypt() feeds a post-handshake message to Schannel
		Closed,				// the peer sent close_notify
		Failed
	};

	TlsCred					m_nCred;
	std::wstring			m_sHost;
	State					m_nState;
	SECURITY_STATUS			m_nStatus;
	CredHandle				m_hCred;
	CtxtHandle				m_hContext;
	std::vector<BYTE>		m_oIn;			// received bytes not yet consumed by Schannel
	PCCERT_CONTEXT			m_pPeerCert;
	DWORD					m_nProtocol;	// SP_PROT_* from SECPKG_ATTR_CONNECTION_INFO
	DWORD					m_nCipherProtocol;	// wire version from SECPKG_ATTR_CIPHER_INFO, or 0
	SecPkgContext_StreamSizes	m_oSizes;
	bool					m_bAccepted;
	bool					m_bShutdown;
	ULONG					m_nPostHandshake;

	TlsResult	Fail(SECURITY_STATUS nStatus);
	TlsResult	Establish();
	bool		QueryStreamSizes();
	// Runs InitializeSecurityContextW over m_oIn until it needs more input
	// (NeedMore), completes (Done) or fails. bCallOnEmpty calls it once even
	// with nothing buffered.
	TlsResult	Negotiate(std::vector<BYTE>& oSend, bool bCallOnEmpty);
	// Decrypts the records in m_oIn, handling post-handshake messages.
	// NeedMore once only a partial record (or nothing) is left.
	TlsResult	DecryptBuffered(std::vector<BYTE>& oPlain, std::vector<BYTE>& oSend);
	SEC_WCHAR*	TargetName() const;

	CTlsClient(const CTlsClient&) = delete;
	CTlsClient& operator=(const CTlsClient&) = delete;
};
