//
// TlsTest.cpp
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

// Tests of CTlsClient: credentials, handshake and the record layer.
// The Local tests need tls_server.py listening on [::1]:8443.

#include "TlsTest.h"

#include <stdio.h>

namespace
{
	const char* const		LOCAL_ADDRESS = "::1";
	const unsigned short	LOCAL_PORT = 8443;					// tls_server.py
	const unsigned short	LOCAL_PORT_CLIENT_CERT = 8444;		// tls_server.py, asks for a client certificate
	const unsigned short	LOCAL_PORT_TLS12 = 8445;			// openssl_driver.py, TLS 1.2, renegotiates
	const unsigned short	LOCAL_PORT_TLS13 = 8446;			// openssl_driver.py, TLS 1.3, KeyUpdate

	// Closes a socket when the test returns, a failed CHECK included.
	class CSocketGuard
	{
	public:
		explicit CSocketGuard(SOCKET hSocket) : m_hSocket( hSocket ) {}
		~CSocketGuard() { if ( m_hSocket != INVALID_SOCKET ) closesocket( m_hSocket ); }
		CSocketGuard(const CSocketGuard&) = delete;
		CSocketGuard& operator=(const CSocketGuard&) = delete;
	private:
		SOCKET m_hSocket;
	};

	// The part of a raw HTTP response after the blank line ending its headers.
	std::string ResponseBody(const std::string& sResponse)
	{
		const size_t nEnd = sResponse.find( "\r\n\r\n" );
		return nEnd == std::string::npos ? std::string() : sResponse.substr( nEnd + 4 );
	}

	bool IsStatusOk(const std::string& sResponse)
	{
		return sResponse.size() >= 13 && sResponse.compare( 0, 7, "HTTP/1." ) == 0 &&
			sResponse.compare( 8, 5, " 200 " ) == 0;
	}

	// pszPath with a query that no other request of this run carries, so the
	// server's log lines for it cannot come from an earlier attempt.
	std::string UniquePath(const char* pszPath)
	{
		static unsigned s_nRequest = 0;
		return std::string( pszPath ) + "?n=" + std::to_string( GetTickCount64() ) + "-" + std::to_string( ++s_nRequest );
	}

	// The number of whole TLS records in oData, or 0 if it does not split
	// into whole records.
	size_t CountRecords(const std::vector<BYTE>& oData)
	{
		size_t nRecords = 0, nPos = 0;
		while ( nPos < oData.size() )
		{
			if ( oData.size() - nPos < 5 )
				return 0;
			nPos += 5 + ( static_cast< size_t >( oData[ nPos + 3 ] ) << 8 ) + oData[ nPos + 4 ];
			if ( nPos > oData.size() )
				return 0;
			++nRecords;
		}
		return nRecords;
	}

	// Sends "go" to openssl_driver.py, then decrypts what comes back until
	// "hello" arrives (Ok), the session fails (Failed) or closes (Closed).
	TlsResult SendGoAndRead(CTlsClient& oTls, SOCKET hSocket, std::string& sPlain)
	{
		std::vector<BYTE> oSend, oPlain;
		const BYTE pGo[] = { 'g', 'o', '\n' };
		TlsResult nResult = oTls.Encrypt( pGo, sizeof( pGo ), oSend );
		if ( nResult != TlsResult::Ok )
			return nResult;
		nResult = oTls.Decrypt( NULL, 0, oPlain, oSend );
		for ( ;; )
		{
			sPlain.append( oPlain.begin(), oPlain.end() );
			oPlain.clear();
			if ( ! oSend.empty() )
			{
				if ( ! SendAll( hSocket, oSend ) )
				{
					TlsTestUnreachable( "send failed: error %d", WSAGetLastError() );
					return TlsResult::Failed;
				}
				oSend.clear();
			}
			if ( nResult == TlsResult::Failed || nResult == TlsResult::Closed )
			{
				printf( "  result %d, SECURITY_STATUS 0x%08lX, %lu post-handshake messages\n",
					static_cast< int >( nResult ), static_cast< unsigned long >( oTls.LastStatus() ),
					static_cast< unsigned long >( oTls.PostHandshakeMessages() ) );
				return nResult;
			}
			if ( sPlain.find( "hello" ) != std::string::npos )
			{
				printf( "  hello received, %lu post-handshake messages\n",
					static_cast< unsigned long >( oTls.PostHandshakeMessages() ) );
				return TlsResult::Ok;
			}

			char pBuffer[ 16384 ];
			const int nReceived = recv( hSocket, pBuffer, static_cast< int >( sizeof( pBuffer ) ), 0 );
			if ( nReceived == 0 )
			{
				printf( "  closed by the server\n" );
				return TlsResult::Closed;
			}
			if ( nReceived < 0 )
			{
				TlsTestUnreachable( "receive failed: error %d", WSAGetLastError() );
				return TlsResult::Failed;
			}
			nResult = oTls.Decrypt( reinterpret_cast< const BYTE* >( pBuffer ),
				static_cast< size_t >( nReceived ), oPlain, oSend );
		}
	}

	// Reads until the peer closes the socket. False on a timeout or error.
	bool WaitForClose(SOCKET hSocket)
	{
		char pBuffer[ 4096 ];
		for ( ;; )
		{
			const int nReceived = recv( hSocket, pBuffer, static_cast< int >( sizeof( pBuffer ) ), 0 );
			if ( nReceived == 0 )
				return true;
			if ( nReceived < 0 )
				return false;
		}
	}
}

// Offline: no network, only Schannel.

TLS_TEST_OFFLINE(StartupIsIdempotent)
{
	CHECK( CTlsClient::Startup() );
	CHECK( CTlsClient::Startup() );
	CTlsClient::Cleanup();
	CHECK( CTlsClient::Startup() );
}

TLS_TEST_OFFLINE(NewClientIsNotEstablished)
{
	CTlsClient c( TlsCred::Manual, L"example.com" );
	CHECK( c.Credential() == TlsCred::Manual );
	CHECK( ! c.IsEstablished() );
	CHECK( c.PeerCertificate() == NULL );
	CHECK( c.Protocol() == 0 );
}

TLS_TEST_OFFLINE(StartProducesClientHello)
{
	CTlsClient c( TlsCred::Validating, L"example.com" );
	std::vector<BYTE> oSend;
	CHECK( c.Start( oSend ) == TlsResult::NeedMore );
	CHECK( oSend.size() > 5 );
	CHECK( oSend[ 0 ] == 0x16 );		// handshake record
	CHECK( oSend[ 1 ] == 0x03 );		// TLS record version
	CHECK( oSend[ 5 ] == 0x01 );		// ClientHello
	CHECK( ! c.IsEstablished() );
}

TLS_TEST_OFFLINE(StartTwiceFails)
{
	CTlsClient c( TlsCred::Validating, L"example.com" );
	std::vector<BYTE> oSend;
	CHECK( c.Start( oSend ) == TlsResult::NeedMore );
	CHECK( c.Start( oSend ) == TlsResult::Failed );
}

TLS_TEST_OFFLINE(EmptyHostFails)
{
	CTlsClient c( TlsCred::Validating, L"" );
	std::vector<BYTE> oSend;
	CHECK( c.Start( oSend ) == TlsResult::Failed );
	CHECK( c.LastStatus() != SEC_E_OK );
	CHECK( oSend.empty() );
}

TLS_TEST_OFFLINE(HandshakeBeforeStartFails)
{
	CTlsClient c( TlsCred::Validating, L"example.com" );
	std::vector<BYTE> oSend;
	const BYTE pAlert[] = { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28 };
	CHECK( c.Handshake( pAlert, sizeof( pAlert ), oSend ) == TlsResult::Failed );
	CHECK( c.LastStatus() != SEC_E_OK );
}

TLS_TEST_OFFLINE(HandshakeFailsOnFatalAlert)
{
	CTlsClient c( TlsCred::Validating, L"example.com" );
	std::vector<BYTE> oSend;
	CHECK( c.Start( oSend ) == TlsResult::NeedMore );
	oSend.clear();
	// A fatal handshake_failure alert, as a server sends when it shares no cipher.
	const BYTE pAlert[] = { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28 };
	CHECK( c.Handshake( pAlert, sizeof( pAlert ), oSend ) == TlsResult::Failed );
	CHECK( c.LastStatus() != SEC_E_OK );
	CHECK( ! c.IsEstablished() );
	// The session stays failed.
	CHECK( c.Handshake( pAlert, sizeof( pAlert ), oSend ) == TlsResult::Failed );
}

TLS_TEST_OFFLINE(HandshakeWaitsForPartialRecord)
{
	CTlsClient c( TlsCred::Validating, L"example.com" );
	std::vector<BYTE> oSend;
	CHECK( c.Start( oSend ) == TlsResult::NeedMore );
	oSend.clear();
	// The first three bytes of a handshake record header: Schannel needs more.
	const BYTE pHeader[] = { 0x16, 0x03, 0x03 };
	CHECK( c.Handshake( pHeader, sizeof( pHeader ), oSend ) == TlsResult::NeedMore );
	CHECK( oSend.empty() );
	CHECK( ! c.IsEstablished() );
}

TLS_TEST_OFFLINE(EncryptBeforeHandshakeFails)
{
	CTlsClient c( TlsCred::Validating, L"example.com" );
	std::vector<BYTE> oSend;
	CHECK( c.Start( oSend ) == TlsResult::NeedMore );
	oSend.clear();
	const BYTE pData[] = { 'G', 'E', 'T' };
	CHECK( c.Encrypt( pData, sizeof( pData ), oSend ) == TlsResult::Failed );
	CHECK( c.LastStatus() != SEC_E_OK );
	CHECK( oSend.empty() );
}

TLS_TEST_OFFLINE(DecryptBeforeHandshakeFails)
{
	CTlsClient c( TlsCred::Validating, L"example.com" );
	std::vector<BYTE> oSend, oPlain;
	CHECK( c.Start( oSend ) == TlsResult::NeedMore );
	oSend.clear();
	const BYTE pRecord[] = { 0x17, 0x03, 0x03, 0x00, 0x01, 0x00 };
	CHECK( c.Decrypt( pRecord, sizeof( pRecord ), oPlain, oSend ) == TlsResult::Failed );
	CHECK( oPlain.empty() );
	CHECK( oSend.empty() );
}

TLS_TEST_OFFLINE(ShutdownBeforeHandshakeSendsNothing)
{
	CTlsClient c( TlsCred::Validating, L"example.com" );
	std::vector<BYTE> oSend;
	c.Shutdown( oSend );
	CHECK( oSend.empty() );
	CHECK( c.Start( oSend ) == TlsResult::NeedMore );
	oSend.clear();
	c.Shutdown( oSend );
	CHECK( oSend.empty() );
}

// Network: public endpoints.

TLS_TEST_NETWORK(NetValidGithub)
{
	CTlsClient c( TlsCred::Validating, L"github.com" );
	CHECK( RunHandshake( c, "github.com", 443 ) );
	CHECK( c.IsEstablished() );
	CHECK( c.Protocol() & ( SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT ) );
	CHECK( c.PeerCertificate() != NULL );
}

TLS_TEST_NETWORK(NetValidatingRejectsExpired)
{
	CTlsClient c( TlsCred::Validating, L"expired.badssl.com" );
	CHECK( ! RunHandshake( c, "expired.badssl.com", 443 ) );
	CHECK( c.LastStatus() == SEC_E_CERT_EXPIRED );
}

TLS_TEST_NETWORK(NetValidatingRejectsWrongHost)
{
	CTlsClient c( TlsCred::Validating, L"wrong.host.badssl.com" );
	CHECK( ! RunHandshake( c, "wrong.host.badssl.com", 443 ) );
	CHECK( c.LastStatus() == SEC_E_WRONG_PRINCIPAL );
}

TLS_TEST_NETWORK(NetValidatingRejectsSelfSigned)
{
	CTlsClient c( TlsCred::Validating, L"self-signed.badssl.com" );
	CHECK( ! RunHandshake( c, "self-signed.badssl.com", 443 ) );
	CHECK( c.LastStatus() == SEC_E_UNTRUSTED_ROOT );
}

TLS_TEST_NETWORK(NetValidatingRejectsUntrustedRoot)
{
	CTlsClient c( TlsCred::Validating, L"untrusted-root.badssl.com" );
	CHECK( ! RunHandshake( c, "untrusted-root.badssl.com", 443 ) );
	CHECK( c.LastStatus() == SEC_E_UNTRUSTED_ROOT );
}

TLS_TEST_NETWORK(NetManualAcceptsExpired)
{
	CTlsClient c( TlsCred::Manual, L"expired.badssl.com" );
	CHECK( RunHandshake( c, "expired.badssl.com", 443 ) );
	CHECK( c.PeerCertificate() != NULL );
}

TLS_TEST_NETWORK(NetGithubHttpGetTls13)
{
	CTlsClient c( TlsCred::Validating, L"github.com" );
	const SOCKET hSocket = ConnectAndHandshake( c, "github.com", 443 );
	CSocketGuard oGuard( hSocket );
	CHECK( hSocket != INVALID_SOCKET );
	CHECK( c.Protocol() & SP_PROT_TLS1_3_CLIENT );
	CHECK( c.IsTls13() );
	std::string sResponse;
	CHECK( HttpGet( c, hSocket, "github.com", "/", sResponse ) );
	CHECK( sResponse.compare( 0, 9, "HTTP/1.1 " ) == 0 );
	CHECK( c.LastStatus() != SEC_E_DECRYPT_FAILURE );
}

// Network: tls_server.py on [::1]:8443 (and 8444, which asks for a client
// certificate), and openssl_driver.py on 8445 (TLS 1.2) and 8446 (TLS 1.3).
// Every certificate is self-signed: the sessions are Manual, and
// ConnectAndHandshake accepts them once their certificate is present.

TLS_TEST_NETWORK(LocalLargeBodyIPv6)
{
	CTlsClient c( TlsCred::Manual, L"localhost" );
	const SOCKET hSocket = ConnectAndHandshake( c, LOCAL_ADDRESS, LOCAL_PORT );
	CSocketGuard oGuard( hSocket );
	CHECK( hSocket != INVALID_SOCKET );
	CHECK( c.PeerCertificate() != NULL );
	std::string sResponse;
	CHECK( HttpGet( c, hSocket, "localhost", "/5mb", sResponse ) );
	CHECK( IsStatusOk( sResponse ) );
	const std::string body = ResponseBody( sResponse );
	CHECK( body.size() == 5u * 1024 * 1024 );
	CHECK( BodyMatchesPattern( body ) );
}

TLS_TEST_NETWORK(LocalDribbleOneByte)
{
	CTlsClient c( TlsCred::Manual, L"localhost" );
	const SOCKET hSocket = ConnectAndHandshake( c, LOCAL_ADDRESS, LOCAL_PORT );
	CSocketGuard oGuard( hSocket );
	CHECK( hSocket != INVALID_SOCKET );
	CHECK( c.PeerCertificate() != NULL );
	std::string sResponse;
	CHECK( HttpGet( c, hSocket, "localhost", "/64k", sResponse, 1 ) );
	CHECK( IsStatusOk( sResponse ) );
	const std::string body = ResponseBody( sResponse );
	CHECK( body.size() == 65536 && BodyMatchesPattern( body ) );
}

TLS_TEST_NETWORK(LocalDribbleHandshakeOneByte)
{
	CTlsClient c( TlsCred::Manual, L"localhost" );
	const SOCKET hSocket = ConnectAndHandshake( c, LOCAL_ADDRESS, LOCAL_PORT, 1 );
	CSocketGuard oGuard( hSocket );
	CHECK( hSocket != INVALID_SOCKET );
	CHECK( c.IsHandshakeComplete() );
	CHECK( c.PeerCertificate() != NULL );
	std::string sResponse;
	CHECK( HttpGet( c, hSocket, "localhost", "/64k", sResponse ) );
	CHECK( IsStatusOk( sResponse ) );
	const std::string body = ResponseBody( sResponse );
	CHECK( body.size() == 65536 && BodyMatchesPattern( body ) );
}

TLS_TEST_NETWORK(LocalAbruptClose)
{
	CTlsClient c( TlsCred::Manual, L"localhost" );
	const SOCKET hSocket = ConnectAndHandshake( c, LOCAL_ADDRESS, LOCAL_PORT );
	CSocketGuard oGuard( hSocket );
	CHECK( hSocket != INVALID_SOCKET );
	CHECK( c.PeerCertificate() != NULL );
	const std::string sPath = UniquePath( "/abrupt" );
	std::string sResponse;
	CHECK( HttpGet( c, hSocket, "localhost", sPath.c_str(), sResponse ) );
	CHECK( IsStatusOk( sResponse ) );
	const std::string body = ResponseBody( sResponse );
	CHECK( body.size() == 100000 );
	CHECK( BodyMatchesPattern( body ) );
	CHECK( c.IsEstablished() );		// no close_notify was decrypted
	CHECK( ServerLogContains( ( "closed " + sPath + " without close_notify" ).c_str() ) );
}

TLS_TEST_NETWORK(LocalShutdownSendsCloseNotify)
{
	CTlsClient c( TlsCred::Manual, L"localhost" );
	const SOCKET hSocket = ConnectAndHandshake( c, LOCAL_ADDRESS, LOCAL_PORT );
	CSocketGuard oGuard( hSocket );
	CHECK( hSocket != INVALID_SOCKET );
	CHECK( c.PeerCertificate() != NULL );
	const std::string sPath = UniquePath( "/shutdown" );
	std::string sResponse;
	CHECK( HttpGet( c, hSocket, "localhost", sPath.c_str(), sResponse ) );
	CHECK( IsStatusOk( sResponse ) );
	std::vector<BYTE> oSend;
	c.Shutdown( oSend );
	CHECK( ! oSend.empty() );
	CHECK( SendAll( hSocket, oSend ) );
	// The server logs what unwrap() returned, then closes the connection.
	CHECK( WaitForClose( hSocket ) );
	CHECK( ServerLogContains( ( "close_notify received for " + sPath ).c_str() ) );
	// Nothing more can be sent.
	oSend.clear();
	const BYTE pData[] = { 'x' };
	CHECK( c.Encrypt( pData, sizeof( pData ), oSend ) == TlsResult::Closed );
	CHECK( oSend.empty() );
}

TLS_TEST_NETWORK(LocalPostSplitsRecords)
{
	CTlsClient c( TlsCred::Manual, L"localhost" );
	const SOCKET hSocket = ConnectAndHandshake( c, LOCAL_ADDRESS, LOCAL_PORT );
	CSocketGuard oGuard( hSocket );
	CHECK( hSocket != INVALID_SOCKET );
	CHECK( c.PeerCertificate() != NULL );

	// 40000 pattern bytes: more than two records of at most 16 KiB.
	const std::string sPath = UniquePath( "/echo-len" );
	const size_t nBody = 40000;
	std::string sRequest = "POST " + sPath + " HTTP/1.1\r\nHost: localhost\r\nUser-Agent: TlsTest\r\n"
		"Content-Type: application/octet-stream\r\nContent-Length: " + std::to_string( nBody ) +
		"\r\nConnection: close\r\n\r\n";
	for ( size_t i = 0 ; i < nBody ; ++i )
		sRequest += static_cast< char >( i % 251 );

	std::vector<BYTE> oSend;
	CHECK( c.Encrypt( reinterpret_cast< const BYTE* >( sRequest.data() ), sRequest.size(), oSend ) == TlsResult::Ok );
	const size_t nRecords = CountRecords( oSend );
	printf( "  %zu bytes of plaintext in %zu records\n", sRequest.size(), nRecords );
	CHECK( nRecords >= 3 );
	CHECK( SendAll( hSocket, oSend ) );

	std::string sResponse;
	CHECK( ReadResponse( c, hSocket, "localhost", sPath.c_str(), sResponse ) );
	CHECK( IsStatusOk( sResponse ) );
	CHECK( ResponseBody( sResponse ) == "length 40000 pattern ok\n" );
	CHECK( ServerLogContains( ( "echo-len " + sPath + ": length 40000 pattern ok" ).c_str() ) );
}

TLS_TEST_NETWORK(LocalClientCertificateRequested)
{
	// The server asks for a certificate; the client has none and must carry on.
	CTlsClient c( TlsCred::Manual, L"localhost" );
	const SOCKET hSocket = ConnectAndHandshake( c, LOCAL_ADDRESS, LOCAL_PORT_CLIENT_CERT );
	CSocketGuard oGuard( hSocket );
	CHECK( hSocket != INVALID_SOCKET );
	CHECK( c.PeerCertificate() != NULL );
	const std::string sPath = UniquePath( "/64k" );
	std::string sResponse;
	CHECK( HttpGet( c, hSocket, "localhost", sPath.c_str(), sResponse ) );
	CHECK( IsStatusOk( sResponse ) );
	const std::string body = ResponseBody( sResponse );
	CHECK( body.size() == 65536 && BodyMatchesPattern( body ) );
	CHECK( ServerLogContains( ( "client certificate requested for " + sPath + ": none" ).c_str() ) );
}

TLS_TEST_NETWORK(LocalManualRefusesBeforeAccept)
{
	{
		CTlsClient c( TlsCred::Manual, L"localhost" );
		const SOCKET hSocket = ConnectAndHandshake( c, LOCAL_ADDRESS, LOCAL_PORT, 0, false );
		CSocketGuard oGuard( hSocket );
		CHECK( hSocket != INVALID_SOCKET );
		CHECK( c.PeerCertificate() != NULL );
		CHECK( ! c.IsAccepted() );
		std::vector<BYTE> oSend;
		const BYTE pData[] = { 'G', 'E', 'T' };
		CHECK( c.Encrypt( pData, sizeof( pData ), oSend ) == TlsResult::Failed );
		CHECK( oSend.empty() );
		CHECK( c.LastStatus() == SEC_E_CERT_UNKNOWN );
		// Accepting a failed session changes nothing.
		c.Accept();
		CHECK( c.Encrypt( pData, sizeof( pData ), oSend ) == TlsResult::Failed );
	}
	{
		CTlsClient c( TlsCred::Manual, L"localhost" );
		const SOCKET hSocket = ConnectAndHandshake( c, LOCAL_ADDRESS, LOCAL_PORT, 0, false );
		CSocketGuard oGuard( hSocket );
		CHECK( hSocket != INVALID_SOCKET );
		std::vector<BYTE> oSend, oPlain;
		CHECK( c.Decrypt( NULL, 0, oPlain, oSend ) == TlsResult::Failed );
		CHECK( oPlain.empty() );
		CHECK( c.LastStatus() == SEC_E_CERT_UNKNOWN );
	}
}

TLS_TEST_NETWORK(LocalTls12RenegotiationRefused)
{
	CTlsClient c( TlsCred::Manual, L"localhost" );
	const SOCKET hSocket = ConnectAndHandshake( c, LOCAL_ADDRESS, LOCAL_PORT_TLS12 );
	CSocketGuard oGuard( hSocket );
	CHECK( hSocket != INVALID_SOCKET );
	CHECK( c.Protocol() & SP_PROT_TLS1_2_CLIENT );
	CHECK( ! c.IsTls13() );
	// "go" makes the server start a renegotiation, then send "hello".
	std::string sPlain;
	const TlsResult nResult = SendGoAndRead( c, hSocket, sPlain );
	CHECK( nResult == TlsResult::Failed );
	CHECK( c.LastStatus() == SEC_E_UNSUPPORTED_FUNCTION );
	CHECK( sPlain.find( "hello" ) == std::string::npos );
}

TLS_TEST_NETWORK(LocalTls13KeyUpdate)
{
	CTlsClient c( TlsCred::Manual, L"localhost" );
	const SOCKET hSocket = ConnectAndHandshake( c, LOCAL_ADDRESS, LOCAL_PORT_TLS13 );
	CSocketGuard oGuard( hSocket );
	CHECK( hSocket != INVALID_SOCKET );
	CHECK( c.IsTls13() );
	// "go" makes the server send a KeyUpdate that asks for ours, then "hello"
	// under its new keys.
	std::string sPlain;
	const TlsResult nResult = SendGoAndRead( c, hSocket, sPlain );
	CHECK( nResult == TlsResult::Ok );
	CHECK( sPlain.find( "hello" ) != std::string::npos );
	CHECK( c.PostHandshakeMessages() >= 1 );
	// Our own traffic still flows after the update.
	std::vector<BYTE> oSend;
	const BYTE pData[] = { 'b', 'y', 'e', '\n' };
	CHECK( c.Encrypt( pData, sizeof( pData ), oSend ) == TlsResult::Ok );
	CHECK( SendAll( hSocket, oSend ) );
}
