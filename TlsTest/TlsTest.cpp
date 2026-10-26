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

// Tests of CTlsClient (credentials, handshake and the record layer) and of
// TlsVerify (certificate evaluation, trust store, URL host).
// The Local tests need tls_server.py listening on [::1]:8443.

#include "TlsTest.h"
#include "../shareaza/TlsVerify.h"

#include <atomic>
#include <stdio.h>
#include <thread>

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

	// Two well-formed fingerprints, as text for files and as wide strings.
#define TLSTEST_FP1 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
#define TLSTEST_FP2 "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210"
	const wchar_t* const FP1 = L"" TLSTEST_FP1;
	const wchar_t* const FP2 = L"" TLSTEST_FP2;

	// A path in the temporary directory that no other test or run uses.
	std::wstring TempPath(const wchar_t* pszName)
	{
		wchar_t szDir[ MAX_PATH + 1 ] = {};
		const DWORD nDir = GetTempPathW( MAX_PATH + 1, szDir );
		static unsigned s_nPath = 0;
		return std::wstring( szDir, nDir <= MAX_PATH ? nDir : 0 ) + L"TlsTest-" +
			std::to_wstring( GetCurrentProcessId() ) + L"-" + std::to_wstring( GetTickCount64() ) +
			L"-" + std::to_wstring( ++s_nPath ) + L"-" + pszName;
	}

	// Deletes a file, and the .tmp file Save() writes beside it, when the test returns.
	class CFileGuard
	{
	public:
		explicit CFileGuard(const std::wstring& sPath) : m_sPath( sPath ) {}
		~CFileGuard() { DeleteFileW( m_sPath.c_str() ); DeleteFileW( ( m_sPath + L".tmp" ).c_str() ); }
		CFileGuard(const CFileGuard&) = delete;
		CFileGuard& operator=(const CFileGuard&) = delete;
	private:
		std::wstring m_sPath;
	};

	bool WriteBytes(const std::wstring& sPath, const std::string& sData)
	{
		const HANDLE hFile = CreateFileW( sPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );
		if ( hFile == INVALID_HANDLE_VALUE )
			return false;
		DWORD nWritten = 0;
		const bool bOk = WriteFile( hFile, sData.data(), static_cast< DWORD >( sData.size() ), &nWritten, NULL ) &&
			nWritten == sData.size();
		CloseHandle( hFile );
		return bOk;
	}

	bool ReadBytes(const std::wstring& sPath, std::string& sData)
	{
		const HANDLE hFile = CreateFileW( sPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
		if ( hFile == INVALID_HANDLE_VALUE )
			return false;
		sData.clear();
		char pBuffer[ 4096 ];
		DWORD nRead = 0;
		bool bOk = true;
		for ( ;; )
		{
			if ( ! ReadFile( hFile, pBuffer, static_cast< DWORD >( sizeof( pBuffer ) ), &nRead, NULL ) )
			{
				bOk = false;
				break;
			}
			if ( nRead == 0 )
				break;
			sData.append( pBuffer, nRead );
		}
		CloseHandle( hFile );
		return bOk;
	}

	std::wstring Widen(const char* psz)
	{
		std::wstring s;
		for ( ; *psz ; ++psz )
			s += static_cast< wchar_t >( static_cast< unsigned char >( *psz ) );
		return s;
	}

	const char* ProblemName(TlsCertProblem nProblem)
	{
		switch ( nProblem )
		{
		case TlsCertProblem::None:		return "None";
		case TlsCertProblem::Expired:	return "Expired";
		case TlsCertProblem::WrongName:	return "WrongName";
		case TlsCertProblem::Untrusted:	return "Untrusted";
		case TlsCertProblem::Revoked:	return "Revoked";
		case TlsCertProblem::Other:		return "Other";
		}
		return "?";
	}

	bool IsUpperHex(const std::wstring& s)
	{
		for ( wchar_t c : s )
		{
			if ( ! ( ( c >= L'0' && c <= L'9' ) || ( c >= L'A' && c <= L'F' ) ) )
				return false;
		}
		return true;
	}

	// Runs a Manual handshake with pszHost:nPort, without accepting the
	// session, and evaluates the peer certificate for pszName. False if the
	// handshake failed or left no certificate.
	bool ManualVerdict(const char* pszHost, unsigned short nPort, const char* pszName,
		TlsCertProblem& nProblem, std::wstring* psFingerprint = NULL)
	{
		CTlsClient c( TlsCred::Manual, Widen( pszName ) );
		const SOCKET hSocket = ConnectAndHandshake( c, pszHost, nPort, 0, false );
		CSocketGuard oGuard( hSocket );
		if ( hSocket == INVALID_SOCKET || c.PeerCertificate() == NULL )
			return false;
		nProblem = VerifyServerCertificate( c.PeerCertificate(), Widen( pszName ) );
		if ( psFingerprint )
			*psFingerprint = CertFingerprintSha256( c.PeerCertificate() );
		return true;
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

// Schannel caches sessions by target name and offers a cached session's
// protocol again: a TLS 1.2 session for "localhost" made the next ClientHello
// for "localhost" unacceptable to a TLS 1.3-only server. Each s_server test
// therefore uses a target name of its own.

TLS_TEST_NETWORK(LocalTls12RenegotiationRefused)
{
	CTlsClient c( TlsCred::Manual, L"tls12.localhost" );
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
	CTlsClient c( TlsCred::Manual, L"tls13.localhost" );
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

// TlsVerify, offline.

TLS_TEST_OFFLINE(OfflineHostFromUrl)
{
	CHECK( TlsHostFromUrl( L"https://[2001:db8::1]:8443/x" ) == L"2001:db8::1" );
	CHECK( TlsHostFromUrl( L"https://Host.Example:443/" ) == L"host.example" );
	CHECK( TlsHostFromUrl( L"https://user@host/a?b" ) == L"host" );
	CHECK( TlsHostFromUrl( L"http://host/" ) == L"" );
	CHECK( TlsHostFromUrl( L"HTTPS://HOST.example" ) == L"host.example" );
	CHECK( TlsHostFromUrl( L"https://host?q=1" ) == L"host" );
	CHECK( TlsHostFromUrl( L"https://host#top" ) == L"host" );
	CHECK( TlsHostFromUrl( L"https://user:p@ss@host:1/" ) == L"host" );
	CHECK( TlsHostFromUrl( L"https://[2001:DB8::A]/" ) == L"2001:db8::a" );
	CHECK( TlsHostFromUrl( L"https://b\u00FCcher.example/" ) == L"xn--bcher-kva.example" );
	CHECK( TlsHostFromUrl( L"https://B\u00FCcher.Example:8443/x" ) == L"xn--bcher-kva.example" );
	CHECK( TlsHostFromUrl( L"https://" ) == L"" );
	CHECK( TlsHostFromUrl( L"https:///path" ) == L"" );
	CHECK( TlsHostFromUrl( L"https://:443/" ) == L"" );
	CHECK( TlsHostFromUrl( L"https://user@/" ) == L"" );
	CHECK( TlsHostFromUrl( L"https://[2001:db8::1/" ) == L"" );
	CHECK( TlsHostFromUrl( L"https://[]/" ) == L"" );
	CHECK( TlsHostFromUrl( L"https://ho st/" ) == L"" );
	CHECK( TlsHostFromUrl( L"ftp://host/" ) == L"" );
	CHECK( TlsHostFromUrl( L"https:host" ) == L"" );
	CHECK( TlsHostFromUrl( L"" ) == L"" );
}

TLS_TEST_OFFLINE(OfflineTrustStore)
{
	CTlsTrustStore oStore;
	CHECK( oStore.Count() == 0 );
	oStore.Accept( L"Host.example", FP1 );
	CHECK( oStore.Count() == 1 );
	CHECK( oStore.IsAccepted( L"host.EXAMPLE", FP1 ) );
	CHECK( oStore.IsAccepted( L"host.example", L"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" ) );
	CHECK( ! oStore.IsAccepted( L"host.example", FP2 ) );
	CHECK( ! oStore.IsAccepted( L"other.example", FP1 ) );
	// The same entry again, and entries the file could not hold.
	oStore.Accept( L"HOST.EXAMPLE", FP1 );
	oStore.Accept( L"", FP2 );
	oStore.Accept( L"tab\there", FP2 );
	oStore.Accept( L"short.example", L"0123" );
	oStore.Accept( L"nothex.example", L"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEG" );
	CHECK( oStore.Count() == 1 );

	const std::wstring sPath = TempPath( L"trust.txt" );
	CFileGuard oGuard( sPath );
	CHECK( oStore.Save( sPath ) );
	std::string sText;
	CHECK( ReadBytes( sPath, sText ) );
	CHECK( sText == "host.example\t" TLSTEST_FP1 "\n" );
	CHECK( GetFileAttributesW( ( sPath + L".tmp" ).c_str() ) == INVALID_FILE_ATTRIBUTES );

	CTlsTrustStore oLoaded;
	CHECK( oLoaded.Load( sPath ) );
	CHECK( oLoaded.Count() == 1 );
	CHECK( oLoaded.IsAccepted( L"HOST.EXAMPLE", FP1 ) );

	// Save replaces an existing file.
	oStore.Accept( L"second.example", FP2 );
	CHECK( oStore.Save( sPath ) );
	CHECK( oLoaded.Load( sPath ) );
	CHECK( oLoaded.Count() == 2 );
	CHECK( oLoaded.IsAccepted( L"second.example", FP2 ) );

	// A file that cannot be read, here a directory, leaves the store unchanged.
	wchar_t szDir[ MAX_PATH + 1 ] = {};
	CHECK( GetTempPathW( MAX_PATH + 1, szDir ) > 0 );
	std::wstring sDir( szDir );
	if ( ! sDir.empty() && sDir.back() == L'\\' )
		sDir.pop_back();
	CHECK( ! oLoaded.Load( sDir ) );
	CHECK( oLoaded.Count() == 2 );

	// Malformed lines are skipped; CRLF and a missing final line end are tolerated.
	CHECK( WriteBytes( sPath, "garbage\n" ) );
	CHECK( oLoaded.Load( sPath ) );
	CHECK( oLoaded.Count() == 0 );
	CHECK( WriteBytes( sPath, "a.example\t" TLSTEST_FP1 "\r\nbad line\n\t" TLSTEST_FP2 "\nb.example\t0123\n"
		"x.example\t" TLSTEST_FP1 "\textra\n\nc.example\t" TLSTEST_FP2 ) );
	CHECK( oLoaded.Load( sPath ) );
	CHECK( oLoaded.Count() == 2 );
	CHECK( oLoaded.IsAccepted( L"a.example", FP1 ) );
	CHECK( oLoaded.IsAccepted( L"c.example", FP2 ) );

	// A missing file is an empty store.
	CHECK( oLoaded.Load( TempPath( L"missing.txt" ) ) );
	CHECK( oLoaded.Count() == 0 );

	oStore.Clear();
	CHECK( oStore.Count() == 0 );
	CHECK( ! oStore.IsAccepted( L"host.example", FP1 ) );
}

TLS_TEST_OFFLINE(OfflinePendingPromptsDedupe)
{
	CTlsPendingPrompts oPending;
	CHECK( oPending.Add( L"host.example", FP1 ) );
	CHECK( ! oPending.Add( L"HOST.Example", FP1 ) );
	CHECK( oPending.Add( L"host.example", FP2 ) );
	oPending.Remove( L"Host.Example", FP1 );
	CHECK( oPending.Add( L"host.example", FP1 ) );
	CHECK( ! oPending.Add( L"host.example", FP2 ) );

	// Many threads failing on the same host and certificate: one prompt.
	CTlsPendingPrompts oShared;
	std::atomic< int > nAdded( 0 );
	std::vector< std::thread > oThreads;
	for ( int i = 0 ; i < 8 ; ++i )
	{
		oThreads.emplace_back( [ &oShared, &nAdded ]()
		{
			for ( int j = 0 ; j < 1000 ; ++j )
			{
				if ( oShared.Add( L"race.example", FP1 ) )
					++nAdded;
			}
		} );
	}
	for ( std::thread& oThread : oThreads )
		oThread.join();
	CHECK( nAdded == 1 );
}

TLS_TEST_OFFLINE(OfflineProblemFromStatus)
{
	CHECK( ProblemFromStatus( SEC_E_CERT_EXPIRED ) == TlsCertProblem::Expired );
	CHECK( ProblemFromStatus( SEC_E_WRONG_PRINCIPAL ) == TlsCertProblem::WrongName );
	CHECK( ProblemFromStatus( SEC_E_UNTRUSTED_ROOT ) == TlsCertProblem::Untrusted );
	CHECK( ProblemFromStatus( CRYPT_E_REVOKED ) == TlsCertProblem::Revoked );
	CHECK( ProblemFromStatus( SEC_E_ALGORITHM_MISMATCH ) == TlsCertProblem::None );

	CHECK( ProblemFromStatus( CERT_E_EXPIRED ) == TlsCertProblem::Expired );
	CHECK( ProblemFromStatus( CERT_E_CN_NO_MATCH ) == TlsCertProblem::WrongName );
	CHECK( ProblemFromStatus( CERT_E_INVALID_NAME ) == TlsCertProblem::WrongName );
	CHECK( ProblemFromStatus( CERT_E_UNTRUSTEDROOT ) == TlsCertProblem::Untrusted );
	CHECK( ProblemFromStatus( CERT_E_CHAINING ) == TlsCertProblem::Untrusted );
	CHECK( ProblemFromStatus( SEC_E_ISSUING_CA_UNTRUSTED ) == TlsCertProblem::Untrusted );
	CHECK( ProblemFromStatus( CERT_E_REVOKED ) == TlsCertProblem::Revoked );
	CHECK( ProblemFromStatus( TRUST_E_CERT_SIGNATURE ) == TlsCertProblem::Other );
	CHECK( ProblemFromStatus( CERT_E_WRONG_USAGE ) == TlsCertProblem::Other );
	CHECK( ProblemFromStatus( SEC_E_CERT_WRONG_USAGE ) == TlsCertProblem::Other );
	CHECK( ProblemFromStatus( SEC_E_CERT_UNKNOWN ) == TlsCertProblem::Other );

	CHECK( ProblemFromStatus( SEC_E_OK ) == TlsCertProblem::None );
	CHECK( ProblemFromStatus( SEC_E_UNSUPPORTED_FUNCTION ) == TlsCertProblem::None );
	CHECK( ProblemFromStatus( SEC_E_ILLEGAL_MESSAGE ) == TlsCertProblem::None );
	CHECK( ProblemFromStatus( SEC_E_INTERNAL_ERROR ) == TlsCertProblem::None );
	CHECK( ProblemFromStatus( SEC_E_DECRYPT_FAILURE ) == TlsCertProblem::None );
}

TLS_TEST_OFFLINE(OfflineVerifyWithoutCertificate)
{
	CHECK( VerifyServerCertificate( NULL, L"host.example" ) == TlsCertProblem::Other );
	CHECK( CertFingerprintSha256( NULL ).empty() );
}

// TlsVerify, against public endpoints and tls_server.py.

TLS_TEST_NETWORK(NetVerifyProblems)
{
	const struct { const char* pszHost; TlsCertProblem nExpected; } pCases[] =
	{
		{ "github.com",					TlsCertProblem::None },
		{ "expired.badssl.com",			TlsCertProblem::Expired },
		{ "wrong.host.badssl.com",		TlsCertProblem::WrongName },
		{ "self-signed.badssl.com",		TlsCertProblem::Untrusted },
		{ "untrusted-root.badssl.com",	TlsCertProblem::Untrusted },
	};
	for ( const auto& oCase : pCases )
	{
		TlsCertProblem nProblem = TlsCertProblem::Other;
		std::wstring sFingerprint;
		CHECK( ManualVerdict( oCase.pszHost, 443, oCase.pszHost, nProblem, &sFingerprint ) );
		printf( "  %s: %s, SHA-256 %ls\n", oCase.pszHost, ProblemName( nProblem ), sFingerprint.c_str() );
		CHECK( nProblem == oCase.nExpected );
		CHECK( sFingerprint.size() == 64 );
		CHECK( IsUpperHex( sFingerprint ) );
	}
}

// The verdict of a Manual handshake and VerifyServerCertificate equals
// Schannel's automatic validation, mapped with ProblemFromStatus.
TLS_TEST_NETWORK(NetVerifyMatchesSchannel)
{
	const char* const pHosts[] =
	{
		"github.com", "expired.badssl.com", "wrong.host.badssl.com",
		"self-signed.badssl.com", "untrusted-root.badssl.com"
	};
	bool bAllMatch = true, bAllCertificate = true, bAllManual = true;
	for ( const char* pszHost : pHosts )
	{
		CTlsClient c( TlsCred::Validating, Widen( pszHost ) );
		const bool bValid = RunHandshake( c, pszHost, 443 );
		const SECURITY_STATUS nStatus = bValid ? SEC_E_OK : c.LastStatus();
		const TlsCertProblem nSchannel = bValid ? TlsCertProblem::None : ProblemFromStatus( nStatus );

		TlsCertProblem nManual = TlsCertProblem::Other;
		const bool bManual = ManualVerdict( pszHost, 443, pszHost, nManual );

		printf( "  %-26s Schannel 0x%08lX -> %-9s Manual %s\n", pszHost,
			static_cast< unsigned long >( nStatus ), ProblemName( nSchannel ),
			bManual ? ProblemName( nManual ) : "(handshake failed)" );
		// A Validating failure that is not about the certificate says nothing.
		if ( ! bValid && nSchannel == TlsCertProblem::None )
			bAllCertificate = false;
		if ( ! bManual )
			bAllManual = false;
		else if ( nManual != nSchannel )
			bAllMatch = false;
	}
	CHECK( bAllCertificate );
	CHECK( bAllManual );
	CHECK( bAllMatch );
}

// The fingerprint is the SHA-256 hash Windows records for the certificate.
TLS_TEST_NETWORK(NetFingerprintMatchesCertProperty)
{
	CTlsClient c( TlsCred::Manual, L"github.com" );
	const SOCKET hSocket = ConnectAndHandshake( c, "github.com", 443, 0, false );
	CSocketGuard oGuard( hSocket );
	CHECK( hSocket != INVALID_SOCKET );
	CHECK( c.PeerCertificate() != NULL );
	BYTE pHash[ 32 ];
	DWORD nHash = sizeof( pHash );
	CHECK( CertGetCertificateContextProperty( c.PeerCertificate(), CERT_SHA256_HASH_PROP_ID, pHash, &nHash ) );
	CHECK( nHash == 32 );
	wchar_t szHex[ 65 ] = {};
	for ( DWORD i = 0 ; i < nHash ; ++i )
		swprintf_s( szHex + i * 2, 3, L"%02X", pHash[ i ] );
	CHECK( CertFingerprintSha256( c.PeerCertificate() ) == szHex );
}

TLS_TEST_NETWORK(LocalVerifySelfSigned)
{
	TlsCertProblem nProblem = TlsCertProblem::None;
	std::wstring sFingerprint;
	CHECK( ManualVerdict( LOCAL_ADDRESS, LOCAL_PORT, "localhost", nProblem, &sFingerprint ) );
	printf( "  localhost: %s, SHA-256 %ls\n", ProblemName( nProblem ), sFingerprint.c_str() );
	CHECK( nProblem == TlsCertProblem::Untrusted );
	CHECK( sFingerprint.size() == 64 );
}
