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
	// session is established; bytes past the handshake stay buffered.
	TlsResult Handshake(const BYTE* pIn, size_t nIn, std::vector<BYTE>& oSend);

	bool			IsEstablished() const;
	TlsCred			Credential() const;
	SECURITY_STATUS	LastStatus() const;
	PCCERT_CONTEXT	PeerCertificate() const;	// owned by the client
	DWORD			Protocol() const;			// SP_PROT_* of the established session

private:
	enum class State { Initial, Handshaking, Established, Failed };

	TlsCred					m_nCred;
	std::wstring			m_sHost;
	State					m_nState;
	SECURITY_STATUS			m_nStatus;
	CredHandle				m_hCred;
	CtxtHandle				m_hContext;
	std::vector<BYTE>		m_oIn;			// received bytes not yet consumed by Schannel
	PCCERT_CONTEXT			m_pPeerCert;
	DWORD					m_nProtocol;

	TlsResult	Fail(SECURITY_STATUS nStatus);
	TlsResult	Establish();
	SEC_WCHAR*	TargetName() const;

	CTlsClient(const CTlsClient&) = delete;
	CTlsClient& operator=(const CTlsClient&) = delete;
};
