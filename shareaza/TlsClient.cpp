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

#include <algorithm>
#include <string.h>

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

	// USE_SUPPLIED_CREDS: never pick a client certificate on our own when a
	// server asks for one.
	const ULONG TLS_CONTEXT_FLAGS = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
		ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM |
		ISC_REQ_USE_SUPPLIED_CREDS;

	// The TLS 1.3 wire version, as SECPKG_ATTR_CIPHER_INFO reports it.
	const DWORD TLS_WIRE_VERSION_1_3 = 0x0304;

	// Received bytes Schannel has not consumed, in any state. A record is at
	// most 16 KiB plus overhead, so a buffer this large means the peer is
	// misbehaving.
	const size_t TLS_MAX_INPUT = 1024 * 1024;

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

	// Frees a token Schannel allocated, without sending it.
	void DropToken(SecBuffer& oBuffer)
	{
		if ( oBuffer.pvBuffer == NULL )
			return;
		FreeContextBuffer( oBuffer.pvBuffer );
		oBuffer.pvBuffer = NULL;
		oBuffer.cbBuffer = 0;
	}

	// The SECBUFFER_EXTRA buffer in a buffer list, or NULL.
	const SecBuffer* FindExtra(const SecBuffer* pBuffers, size_t nBuffers)
	{
		for ( size_t i = 0 ; i < nBuffers ; ++i )
		{
			if ( pBuffers[ i ].BufferType == SECBUFFER_EXTRA )
				return &pBuffers[ i ];
		}
		return NULL;
	}

	// The size of the SECBUFFER_EXTRA buffer in a buffer list, or 0.
	ULONG ExtraSize(const SecBuffer* pBuffers, size_t nBuffers)
	{
		const SecBuffer* pExtra = FindExtra( pBuffers, nBuffers );
		return pExtra ? pExtra->cbBuffer : 0;
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
	, m_nCipherProtocol	( 0 )
	, m_oSizes		()
	, m_bAccepted	( false )
	, m_bShutdown	( false )
	, m_nPostHandshake	( 0 )
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
	if ( nStatus != SEC_I_CONTINUE_NEEDED )
	{
		DropToken( oOut );
		return Fail( nStatus == SEC_E_OK ? SEC_E_INTERNAL_ERROR : nStatus );
	}
	TakeToken( oOut, oSend );

	m_nStatus = nStatus;
	m_nState = State::Handshaking;
	return TlsResult::NeedMore;
}

TlsResult CTlsClient::Handshake(const BYTE* pIn, size_t nIn, std::vector<BYTE>& oSend)
{
	switch ( m_nState )
	{
	case State::Failed:
		return TlsResult::Failed;
	case State::Handshaking:
		break;
	default:
		// Before Start(), or once established: received bytes go to Decrypt().
		return Fail( SEC_E_INVALID_HANDLE );
	}

	if ( nIn > TLS_MAX_INPUT - m_oIn.size() )
		return Fail( SEC_E_ILLEGAL_MESSAGE );
	if ( nIn )
		m_oIn.insert( m_oIn.end(), pIn, pIn + nIn );

	const TlsResult nResult = Negotiate( oSend, false );
	return nResult == TlsResult::Done ? Establish() : nResult;
}

TlsResult CTlsClient::Encrypt(const BYTE* p, size_t n, std::vector<BYTE>& oSend)
{
	switch ( m_nState )
	{
	case State::Failed:
		return TlsResult::Failed;
	case State::Closed:
		return TlsResult::Closed;
	case State::Renegotiating:
		return m_bShutdown ? TlsResult::Closed : TlsResult::NeedMore;
	case State::Established:
		break;
	default:
		return Fail( SEC_E_INVALID_HANDLE );
	}
	if ( m_bShutdown )
		return TlsResult::Closed;
	if ( ! m_bAccepted )
		return Fail( SEC_E_CERT_UNKNOWN );

	const size_t nStart = oSend.size();
	const ULONG cbHeader = m_oSizes.cbHeader, cbTrailer = m_oSizes.cbTrailer;
	size_t nDone = 0;
	while ( nDone < n )
	{
		// One record: header, data, trailer, encrypted in place in oSend.
		const ULONG cbData = static_cast< ULONG >( ( std::min )( n - nDone, static_cast< size_t >( m_oSizes.cbMaximumMessage ) ) );
		const size_t nRecord = oSend.size();
		oSend.resize( nRecord + cbHeader + cbData + cbTrailer );
		BYTE* const pRecord = oSend.data() + nRecord;
		memcpy( pRecord + cbHeader, p + nDone, cbData );

		BYTE* const pPart[ 3 ] = { pRecord, pRecord + cbHeader, pRecord + cbHeader + cbData };
		const ULONG nPart[ 3 ] = { cbHeader, cbData, cbTrailer };
		SecBuffer oBuffers[ 4 ] =
		{
			{ cbHeader, SECBUFFER_STREAM_HEADER, pPart[ 0 ] },
			{ cbData, SECBUFFER_DATA, pPart[ 1 ] },
			{ cbTrailer, SECBUFFER_STREAM_TRAILER, pPart[ 2 ] },
			{ 0, SECBUFFER_EMPTY, NULL }
		};
		SecBufferDesc oDesc = { SECBUFFER_VERSION, 4, oBuffers };
		const SECURITY_STATUS nStatus = EncryptMessage( &m_hContext, 0, &oDesc, 0 );
		if ( nStatus != SEC_E_OK )
		{
			oSend.resize( nStart );
			return Fail( nStatus );
		}

		// Schannel may use less than the trailer it asked for: close the gaps.
		size_t nLength = 0;
		for ( size_t i = 0 ; i < 3 ; ++i )
		{
			if ( oBuffers[ i ].pvBuffer != pPart[ i ] || oBuffers[ i ].cbBuffer > nPart[ i ] )
			{
				oSend.resize( nStart );
				return Fail( SEC_E_INTERNAL_ERROR );
			}
			if ( pRecord + nLength != pPart[ i ] )
				memmove( pRecord + nLength, pPart[ i ], oBuffers[ i ].cbBuffer );
			nLength += oBuffers[ i ].cbBuffer;
		}
		oSend.resize( nRecord + nLength );
		nDone += cbData;
	}

	m_nStatus = SEC_E_OK;
	return TlsResult::Ok;
}

TlsResult CTlsClient::Decrypt(const BYTE* pIn, size_t nIn, std::vector<BYTE>& oPlain, std::vector<BYTE>& oSend)
{
	switch ( m_nState )
	{
	case State::Failed:
		return TlsResult::Failed;
	case State::Closed:
		return TlsResult::Closed;
	case State::Established:
	case State::Renegotiating:
		break;
	default:
		return Fail( SEC_E_INVALID_HANDLE );
	}
	if ( ! m_bAccepted )
		return Fail( SEC_E_CERT_UNKNOWN );

	// The input is buffered in slices no larger than the space left, and each
	// slice is decrypted before the next, so a large input does not trip the
	// cap. Only an unconsumed buffer that fills the cap fails the session.
	const size_t nPlain = oPlain.size();
	size_t nDone = 0;
	do
	{
		const size_t nTake = ( std::min )( nIn - nDone, TLS_MAX_INPUT - m_oIn.size() );
		if ( nTake == 0 && nDone < nIn )
			return Fail( SEC_E_ILLEGAL_MESSAGE );
		if ( nTake )
			m_oIn.insert( m_oIn.end(), pIn + nDone, pIn + nDone + nTake );
		nDone += nTake;

		const TlsResult nResult = DecryptBuffered( oPlain, oSend );
		if ( nResult == TlsResult::Closed || nResult == TlsResult::Failed )
			return nResult;
	}
	while ( nDone < nIn );

	return oPlain.size() > nPlain ? TlsResult::Ok : TlsResult::NeedMore;
}

void CTlsClient::Shutdown(std::vector<BYTE>& oSend)
{
	if ( m_bShutdown )
		return;
	if ( m_nState != State::Established && m_nState != State::Renegotiating && m_nState != State::Closed )
		return;
	m_bShutdown = true;

	DWORD nType = SCHANNEL_SHUTDOWN;
	SecBuffer oControl = { static_cast< ULONG >( sizeof( nType ) ), SECBUFFER_TOKEN, &nType };
	SecBufferDesc oControlDesc = { SECBUFFER_VERSION, 1, &oControl };
	SECURITY_STATUS nStatus = ApplyControlToken( &m_hContext, &oControlDesc );
	if ( nStatus != SEC_E_OK )
	{
		m_nStatus = nStatus;
		return;
	}

	// With the shutdown token applied, the next call produces close_notify.
	SecBuffer oOut = { 0, SECBUFFER_TOKEN, NULL };
	SecBufferDesc oOutDesc = { SECBUFFER_VERSION, 1, &oOut };
	ULONG nAttributes = 0;
	nStatus = InitializeSecurityContextW( &m_hCred, &m_hContext, TargetName(),
		TLS_CONTEXT_FLAGS, 0, 0, NULL, 0, &m_hContext, &oOutDesc, &nAttributes, NULL );
	if ( nStatus == SEC_E_OK || nStatus == SEC_I_CONTEXT_EXPIRED )
		TakeToken( oOut, oSend );
	else
		DropToken( oOut );
	m_nStatus = nStatus;
}

void CTlsClient::Accept()
{
	if ( IsHandshakeComplete() )
		m_bAccepted = true;
}

bool CTlsClient::IsEstablished() const
{
	return m_nState == State::Established;
}

bool CTlsClient::IsHandshakeComplete() const
{
	return m_nState == State::Established || m_nState == State::Renegotiating || m_nState == State::Closed;
}

bool CTlsClient::IsAccepted() const
{
	return m_bAccepted;
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

bool CTlsClient::IsTls13() const
{
	return ( m_nProtocol & SP_PROT_TLS1_3_CLIENT ) != 0 || m_nCipherProtocol == TLS_WIRE_VERSION_1_3;
}

ULONG CTlsClient::PostHandshakeMessages() const
{
	return m_nPostHandshake;
}

TlsResult CTlsClient::Fail(SECURITY_STATUS nStatus)
{
	m_nStatus = nStatus;
	m_nState = State::Failed;
	return TlsResult::Failed;
}

TlsResult CTlsClient::Establish()
{
	if ( ! QueryStreamSizes() )
		return TlsResult::Failed;

	SecPkgContext_ConnectionInfo oInfo = {};
	const SECURITY_STATUS nInfo = QueryContextAttributesW( &m_hContext, SECPKG_ATTR_CONNECTION_INFO, &oInfo );
	if ( nInfo != SEC_E_OK )
		return Fail( nInfo );
	m_nProtocol = oInfo.dwProtocol;

	// The wire version too, where Windows reports it: either source may name
	// TLS 1.3, which decides whether post-handshake messages are allowed.
	SecPkgContext_CipherInfo oCipher = {};
	if ( QueryContextAttributesW( &m_hContext, SECPKG_ATTR_CIPHER_INFO, &oCipher ) == SEC_E_OK )
		m_nCipherProtocol = oCipher.dwProtocol;

	PCCERT_CONTEXT pCert = NULL;
	if ( QueryContextAttributesW( &m_hContext, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &pCert ) == SEC_E_OK )
		m_pPeerCert = pCert;
	// A manual session exists so that the owner can judge the certificate:
	// without one there is nothing to judge.
	if ( m_nCred == TlsCred::Manual && m_pPeerCert == NULL )
		return Fail( SEC_E_CERT_UNKNOWN );

	m_bAccepted = m_nCred == TlsCred::Validating;
	m_nStatus = SEC_E_OK;
	m_nState = State::Established;
	return TlsResult::Done;
}

bool CTlsClient::QueryStreamSizes()
{
	SecPkgContext_StreamSizes oSizes = {};
	const SECURITY_STATUS nStatus = QueryContextAttributesW( &m_hContext, SECPKG_ATTR_STREAM_SIZES, &oSizes );
	if ( nStatus != SEC_E_OK )
	{
		Fail( nStatus );
		return false;
	}
	if ( oSizes.cbMaximumMessage == 0 )
	{
		Fail( SEC_E_INTERNAL_ERROR );
		return false;
	}
	m_oSizes = oSizes;
	return true;
}

TlsResult CTlsClient::Negotiate(std::vector<BYTE>& oSend, bool bCallOnEmpty)
{
	bool bNoClientCertificate = false;
	while ( ! m_oIn.empty() || bCallOnEmpty )
	{
		bCallOnEmpty = false;
		// Schannel is given a non-null pointer even for an empty token.
		BYTE nEmpty = 0;
		SecBuffer oIn[ 2 ] =
		{
			{ static_cast< ULONG >( m_oIn.size() ), SECBUFFER_TOKEN, m_oIn.empty() ? &nEmpty : m_oIn.data() },
			{ 0, SECBUFFER_EMPTY, NULL }
		};
		SecBufferDesc oInDesc = { SECBUFFER_VERSION, 2, oIn };
		SecBuffer oOut = { 0, SECBUFFER_TOKEN, NULL };
		SecBufferDesc oOutDesc = { SECBUFFER_VERSION, 1, &oOut };
		ULONG nAttributes = 0;
		const SECURITY_STATUS nStatus = InitializeSecurityContextW( &m_hCred, &m_hContext, TargetName(),
			TLS_CONTEXT_FLAGS, 0, 0, &oInDesc, 0, &m_hContext, &oOutDesc, &nAttributes, NULL );
		m_nStatus = nStatus;

		if ( nStatus == SEC_E_INCOMPLETE_MESSAGE )
		{
			DropToken( oOut );
			return TlsResult::NeedMore;			// m_oIn is kept whole
		}

		if ( nStatus == SEC_I_INCOMPLETE_CREDENTIALS )
		{
			// The server asked for a client certificate. There is none: call
			// again with the same input and Schannel continues without one.
			DropToken( oOut );
			if ( bNoClientCertificate )
				return Fail( nStatus );
			bNoClientCertificate = true;
			bCallOnEmpty = m_oIn.empty();
			continue;
		}

		if ( nStatus != SEC_E_OK && nStatus != SEC_I_CONTINUE_NEEDED )
		{
			DropToken( oOut );
			return Fail( nStatus );
		}
		TakeToken( oOut, oSend );

		// Keep what Schannel did not consume: the next handshake message, or
		// after the last one, the first application data.
		const size_t nBefore = m_oIn.size();
		const ULONG nExtra = ExtraSize( oIn, 2 );
		if ( nExtra > nBefore )
			return Fail( SEC_E_INTERNAL_ERROR );
		m_oIn.erase( m_oIn.begin(), m_oIn.end() - static_cast< std::ptrdiff_t >( nExtra ) );

		if ( nStatus == SEC_E_OK )
			return TlsResult::Done;

		// Nothing consumed: wait for more input rather than spin.
		if ( nBefore && nExtra == nBefore )
			return TlsResult::NeedMore;
	}
	return TlsResult::NeedMore;
}

TlsResult CTlsClient::DecryptBuffered(std::vector<BYTE>& oPlain, std::vector<BYTE>& oSend)
{
	// m_oIn only shrinks within this call, so a second post-handshake message
	// at the same buffer size means neither call consumed anything.
	size_t nRenegotiatedAt = static_cast< size_t >( -1 );
	bool bRenegotiateNow = false;
	for ( ;; )
	{
		if ( m_nState == State::Renegotiating )
		{
			// A post-handshake message: Schannel takes the bytes past it (if
			// any) through InitializeSecurityContextW, called at least once.
			const TlsResult nResult = Negotiate( oSend, bRenegotiateNow );
			bRenegotiateNow = false;
			if ( nResult != TlsResult::Done )
				return nResult;
			if ( ! QueryStreamSizes() )
				return TlsResult::Failed;
			m_nStatus = SEC_E_OK;
			m_nState = State::Established;
		}

		if ( m_oIn.empty() )
			return TlsResult::NeedMore;

		SecBuffer oBuffers[ 4 ] =
		{
			{ static_cast< ULONG >( m_oIn.size() ), SECBUFFER_DATA, m_oIn.data() },
			{ 0, SECBUFFER_EMPTY, NULL },
			{ 0, SECBUFFER_EMPTY, NULL },
			{ 0, SECBUFFER_EMPTY, NULL }
		};
		SecBufferDesc oDesc = { SECBUFFER_VERSION, 4, oBuffers };
		const size_t nBefore = m_oIn.size();
		const SECURITY_STATUS nStatus = DecryptMessage( &m_hContext, &oDesc, 0, NULL );
		m_nStatus = nStatus;

		if ( nStatus == SEC_E_INCOMPLETE_MESSAGE )
			return TlsResult::NeedMore;			// m_oIn is kept whole
		if ( nStatus == SEC_I_CONTEXT_EXPIRED )
		{
			// close_notify. Anything after it is not part of the session.
			m_oIn.clear();
			m_nState = State::Closed;
			return TlsResult::Closed;
		}
		if ( nStatus != SEC_E_OK && nStatus != SEC_I_RENEGOTIATE )
			return Fail( nStatus );

		// The plaintext is decrypted in place, inside m_oIn: copy it out
		// before the buffer changes.
		const BYTE* const pFirst = m_oIn.data();
		const BYTE* const pLast = pFirst + m_oIn.size();
		for ( size_t i = 0 ; i < 4 ; ++i )
		{
			if ( oBuffers[ i ].BufferType != SECBUFFER_DATA || oBuffers[ i ].cbBuffer == 0 )
				continue;
			const BYTE* const pData = static_cast< const BYTE* >( oBuffers[ i ].pvBuffer );
			if ( pData < pFirst || pData > pLast || oBuffers[ i ].cbBuffer > static_cast< size_t >( pLast - pData ) )
				return Fail( SEC_E_INTERNAL_ERROR );
			oPlain.insert( oPlain.end(), pData, pData + oBuffers[ i ].cbBuffer );
		}

		const SecBuffer* const pExtra = FindExtra( oBuffers, 4 );
		const ULONG nExtra = pExtra ? pExtra->cbBuffer : 0;
		if ( nExtra > m_oIn.size() )
			return Fail( SEC_E_INTERNAL_ERROR );
		// The unconsumed bytes must be the tail of m_oIn, as they are kept by size.
		if ( nExtra && pExtra->pvBuffer != pLast - nExtra )
			return Fail( SEC_E_INTERNAL_ERROR );
		if ( nStatus == SEC_E_OK && nExtra == m_oIn.size() )
			return Fail( SEC_E_INTERNAL_ERROR );	// nothing consumed
		m_oIn.erase( m_oIn.begin(), m_oIn.end() - static_cast< std::ptrdiff_t >( nExtra ) );

		if ( nStatus == SEC_I_RENEGOTIATE )
		{
			// TLS 1.3 post-handshake messages continue. A renegotiation in an
			// older protocol could change the peer's identity: refuse it,
			// and refuse too when the protocol is unknown.
			if ( ! IsTls13() )
				return Fail( SEC_E_UNSUPPORTED_FUNCTION );
			if ( nBefore == nRenegotiatedAt )
				return Fail( SEC_E_INTERNAL_ERROR );
			nRenegotiatedAt = nBefore;
			++m_nPostHandshake;
			m_nState = State::Renegotiating;
			bRenegotiateNow = true;
		}
	}
}

SEC_WCHAR* CTlsClient::TargetName() const
{
	return const_cast< SEC_WCHAR* >( m_sHost.c_str() );
}
