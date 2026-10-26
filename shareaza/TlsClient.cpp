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

namespace
{
	// Windows validates the chain, the host name and the dates. Revocation is
	// checked but fails soft: missing or unreachable revocation information
	// does not fail the handshake, a certificate known to be revoked does.
	const DWORD TLS_VALIDATING_FLAGS = SCH_CRED_AUTO_CRED_VALIDATION |
		SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | SCH_CRED_IGNORE_NO_REVOCATION_CHECK |
		SCH_CRED_IGNORE_REVOCATION_OFFLINE | SCH_CRED_NO_DEFAULT_CREDS;

	// No validation by Schannel: the caller evaluates the peer certificate.
	const DWORD TLS_MANUAL_FLAGS = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS;

	const ULONG TLS_CONTEXT_FLAGS = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
		ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

	// Handshake input Schannel has not consumed. A record is at most 16 KiB
	// plus overhead, so a buffer this large means the peer is misbehaving.
	const size_t TLS_MAX_HANDSHAKE_INPUT = 1024 * 1024;

	// The process-wide credentials, indexed by TlsCred. SRWLOCK_INIT is a
	// constant, so the lock is usable before any dynamic initialisation.
	SRWLOCK		g_oCredLock = SRWLOCK_INIT;
	bool		g_bCredReady = false;
	CredHandle	g_hCred[ 2 ];

	size_t CredIndex(TlsCred nCred)
	{
		return nCred == TlsCred::Manual ? 1 : 0;
	}

	// SCH_CREDENTIALS first (Windows 10 1809 and later, needed for TLS 1.3),
	// then SCHANNEL_CRED. No protocol list: Windows policy decides.
	SECURITY_STATUS AcquireCredential(DWORD dwFlags, CredHandle& hCred)
	{
		SCH_CREDENTIALS oCred = {};
		oCred.dwVersion = SCH_CREDENTIALS_VERSION;
		oCred.dwFlags = dwFlags;
		SECURITY_STATUS nStatus = AcquireCredentialsHandleW( NULL, const_cast< SEC_WCHAR* >( UNISP_NAME_W ),
			SECPKG_CRED_OUTBOUND, NULL, &oCred, NULL, NULL, &hCred, NULL );
		if ( nStatus == SEC_E_OK )
			return nStatus;

		SCHANNEL_CRED oLegacy = {};
		oLegacy.dwVersion = SCHANNEL_CRED_VERSION;
		oLegacy.dwFlags = dwFlags;
		return AcquireCredentialsHandleW( NULL, const_cast< SEC_WCHAR* >( UNISP_NAME_W ),
			SECPKG_CRED_OUTBOUND, NULL, &oLegacy, NULL, NULL, &hCred, NULL );
	}

	// Call with g_oCredLock held exclusively.
	bool StartupLocked()
	{
		if ( g_bCredReady )
			return true;

		CredHandle hValidating, hManual;
		if ( AcquireCredential( TLS_VALIDATING_FLAGS, hValidating ) != SEC_E_OK )
			return false;
		if ( AcquireCredential( TLS_MANUAL_FLAGS, hManual ) != SEC_E_OK )
		{
			FreeCredentialsHandle( &hValidating );
			return false;
		}
		g_hCred[ CredIndex( TlsCred::Validating ) ] = hValidating;
		g_hCred[ CredIndex( TlsCred::Manual ) ] = hManual;
		g_bCredReady = true;
		return true;
	}

	// Moves a token Schannel allocated to the end of oSend, and frees it.
	void TakeToken(SecBuffer& oBuffer, std::vector<BYTE>& oSend)
	{
		if ( oBuffer.pvBuffer == NULL )
			return;
		const BYTE* pToken = static_cast< const BYTE* >( oBuffer.pvBuffer );
		oSend.insert( oSend.end(), pToken, pToken + oBuffer.cbBuffer );
		FreeContextBuffer( oBuffer.pvBuffer );
		oBuffer.pvBuffer = NULL;
		oBuffer.cbBuffer = 0;
	}
}

bool CTlsClient::Startup()
{
	AcquireSRWLockExclusive( &g_oCredLock );
	const bool bReady = StartupLocked();
	ReleaseSRWLockExclusive( &g_oCredLock );
	return bReady;
}

void CTlsClient::Cleanup()
{
	AcquireSRWLockExclusive( &g_oCredLock );
	if ( g_bCredReady )
	{
		FreeCredentialsHandle( &g_hCred[ CredIndex( TlsCred::Validating ) ] );
		FreeCredentialsHandle( &g_hCred[ CredIndex( TlsCred::Manual ) ] );
		g_bCredReady = false;
	}
	ReleaseSRWLockExclusive( &g_oCredLock );
}

CTlsClient::CTlsClient(TlsCred nCred, const std::wstring& sHost)
	: m_nCred		( nCred )
	, m_sHost		( sHost )
	, m_nState		( State::Initial )
	, m_nStatus		( SEC_E_OK )
	, m_pPeerCert	( NULL )
	, m_nProtocol	( 0 )
	, m_oSizes		()
	, m_bShutdown	( false )
	, m_nRenegotiations	( 0 )
{
	SecInvalidateHandle( &m_hCred );
	SecInvalidateHandle( &m_hContext );
}

CTlsClient::~CTlsClient()
{
	if ( m_pPeerCert )
		CertFreeCertificateContext( m_pPeerCert );
	if ( SecIsValidHandle( &m_hContext ) )
		DeleteSecurityContext( &m_hContext );
}

TlsResult CTlsClient::Start(std::vector<BYTE>& oSend)
{
	if ( m_nState != State::Initial )
		return Fail( SEC_E_INVALID_HANDLE );
	// The host name is the target Schannel validates the certificate against.
	if ( m_sHost.empty() )
		return Fail( SEC_E_INVALID_PARAMETER );

	AcquireSRWLockExclusive( &g_oCredLock );
	const bool bReady = StartupLocked();
	if ( bReady )
		m_hCred = g_hCred[ CredIndex( m_nCred ) ];
	ReleaseSRWLockExclusive( &g_oCredLock );
	if ( ! bReady )
		return Fail( SEC_E_NO_CREDENTIALS );

	SecBuffer oOut = { 0, SECBUFFER_TOKEN, NULL };
	SecBufferDesc oOutDesc = { SECBUFFER_VERSION, 1, &oOut };
	ULONG nAttributes = 0;
	const SECURITY_STATUS nStatus = InitializeSecurityContextW( &m_hCred, NULL, TargetName(),
		TLS_CONTEXT_FLAGS, 0, 0, NULL, 0, &m_hContext, &oOutDesc, &nAttributes, NULL );
	TakeToken( oOut, oSend );
	if ( nStatus != SEC_I_CONTINUE_NEEDED )
		return Fail( nStatus == SEC_E_OK ? SEC_E_INTERNAL_ERROR : nStatus );

	m_nStatus = nStatus;
	m_nState = State::Handshaking;
	return TlsResult::NeedMore;
}

TlsResult CTlsClient::Handshake(const BYTE* pIn, size_t nIn, std::vector<BYTE>& oSend)
{
	switch ( m_nState )
	{
	case State::Initial:
		return Fail( SEC_E_INVALID_HANDLE );
	case State::Failed:
		return TlsResult::Failed;
	case State::Established:
		m_oIn.insert( m_oIn.end(), pIn, pIn + nIn );
		return TlsResult::Done;
	case State::Handshaking:
		break;
	}

	m_oIn.insert( m_oIn.end(), pIn, pIn + nIn );
	if ( m_oIn.size() > TLS_MAX_HANDSHAKE_INPUT )
		return Fail( SEC_E_ILLEGAL_MESSAGE );

	bool bNoClientCertificate = false;
	while ( ! m_oIn.empty() )
	{
		SecBuffer oIn[ 2 ] =
		{
			{ static_cast< ULONG >( m_oIn.size() ), SECBUFFER_TOKEN, m_oIn.data() },
			{ 0, SECBUFFER_EMPTY, NULL }
		};
		SecBufferDesc oInDesc = { SECBUFFER_VERSION, 2, oIn };
		SecBuffer oOut = { 0, SECBUFFER_TOKEN, NULL };
		SecBufferDesc oOutDesc = { SECBUFFER_VERSION, 1, &oOut };
		ULONG nAttributes = 0;
		const SECURITY_STATUS nStatus = InitializeSecurityContextW( &m_hCred, &m_hContext, TargetName(),
			TLS_CONTEXT_FLAGS, 0, 0, &oInDesc, 0, &m_hContext, &oOutDesc, &nAttributes, NULL );
		TakeToken( oOut, oSend );
		m_nStatus = nStatus;

		if ( nStatus == SEC_E_INCOMPLETE_MESSAGE )
			return TlsResult::NeedMore;			// m_oIn is kept whole

		if ( nStatus == SEC_I_INCOMPLETE_CREDENTIALS )
		{
			// The server asked for a client certificate. There is none: call
			// again with the same input and Schannel continues without one.
			if ( bNoClientCertificate )
				return Fail( nStatus );
			bNoClientCertificate = true;
			continue;
		}

		if ( nStatus != SEC_E_OK && nStatus != SEC_I_CONTINUE_NEEDED )
			return Fail( nStatus );

		// Keep what Schannel did not consume: the next handshake message, or
		// after the last one, the first application data.
		if ( oIn[ 1 ].BufferType == SECBUFFER_EXTRA && oIn[ 1 ].cbBuffer > 0 && oIn[ 1 ].cbBuffer <= m_oIn.size() )
			m_oIn.erase( m_oIn.begin(), m_oIn.end() - static_cast< std::ptrdiff_t >( oIn[ 1 ].cbBuffer ) );
		else
			m_oIn.clear();

		if ( nStatus == SEC_E_OK )
			return Establish();
	}
	return TlsResult::NeedMore;
}

TlsResult CTlsClient::Encrypt(const BYTE* /*p*/, size_t /*n*/, std::vector<BYTE>& /*oSend*/)
{
	return Fail( SEC_E_UNSUPPORTED_FUNCTION );
}

TlsResult CTlsClient::Decrypt(const BYTE* /*pIn*/, size_t /*nIn*/, std::vector<BYTE>& /*oPlain*/, std::vector<BYTE>& /*oSend*/)
{
	return Fail( SEC_E_UNSUPPORTED_FUNCTION );
}

void CTlsClient::Shutdown(std::vector<BYTE>& /*oSend*/)
{
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

ULONG CTlsClient::Renegotiations() const
{
	return m_nRenegotiations;
}

TlsResult CTlsClient::Fail(SECURITY_STATUS nStatus)
{
	m_nStatus = nStatus;
	m_nState = State::Failed;
	return TlsResult::Failed;
}

TlsResult CTlsClient::Establish()
{
	SecPkgContext_ConnectionInfo oInfo = {};
	if ( QueryContextAttributesW( &m_hContext, SECPKG_ATTR_CONNECTION_INFO, &oInfo ) == SEC_E_OK )
		m_nProtocol = oInfo.dwProtocol;

	PCCERT_CONTEXT pCert = NULL;
	if ( QueryContextAttributesW( &m_hContext, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &pCert ) == SEC_E_OK )
		m_pPeerCert = pCert;

	m_nStatus = SEC_E_OK;
	m_nState = State::Established;
	return TlsResult::Done;
}

SEC_WCHAR* CTlsClient::TargetName() const
{
	return const_cast< SEC_WCHAR* >( m_sHost.c_str() );
}
