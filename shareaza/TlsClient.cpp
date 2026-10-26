//
// TlsClient.cpp
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

// SCH_CREDENTIALS is declared only with SCHANNEL_USE_BLACKLISTS, and needs
// UNICODE_STRING from subauth.h, so both come before TlsClient.h's schannel.h.
#define SCHANNEL_USE_BLACKLISTS
#include <windows.h>
#pragma warning(push)
#pragma warning(disable : 4201)		// nonstandard extension used: nameless struct/union
#include <subauth.h>
#pragma warning(pop)

#include "TlsClient.h"

bool CTlsClient::Startup()
{
	return false;
}

void CTlsClient::Cleanup()
{
}

CTlsClient::CTlsClient(TlsCred nCred, const std::wstring& sHost)
	: m_nCred		( nCred )
	, m_sHost		( sHost )
	, m_nState		( State::Initial )
	, m_nStatus		( SEC_E_OK )
	, m_pPeerCert	( NULL )
	, m_nProtocol	( 0 )
{
	SecInvalidateHandle( &m_hCred );
	SecInvalidateHandle( &m_hContext );
}

CTlsClient::~CTlsClient()
{
}

TlsResult CTlsClient::Start(std::vector<BYTE>& /*oSend*/)
{
	return TlsResult::Failed;
}

TlsResult CTlsClient::Handshake(const BYTE* /*pIn*/, size_t /*nIn*/, std::vector<BYTE>& /*oSend*/)
{
	return TlsResult::Failed;
}

bool CTlsClient::IsEstablished() const
{
	return m_nState == State::Established;
}

TlsCred CTlsClient::Credential() const
{
	return m_nCred;
}

SECURITY_STATUS CTlsClient::LastStatus() const
{
	return m_nStatus;
}

PCCERT_CONTEXT CTlsClient::PeerCertificate() const
{
	return m_pPeerCert;
}

DWORD CTlsClient::Protocol() const
{
	return m_nProtocol;
}

TlsResult CTlsClient::Fail(SECURITY_STATUS nStatus)
{
	m_nStatus = nStatus;
	m_nState = State::Failed;
	return TlsResult::Failed;
}

TlsResult CTlsClient::Establish()
{
	return TlsResult::Failed;
}

SEC_WCHAR* CTlsClient::TargetName() const
{
	return const_cast< SEC_WCHAR* >( m_sHost.c_str() );
}
