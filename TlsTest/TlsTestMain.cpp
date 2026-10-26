//
// TlsTestMain.cpp
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

// Runs the registered tests and the blocking-socket handshake driver.
//
//   TlsTest --offline		tests that need no network
//   TlsTest --network		tests against public endpoints, each tried up to 3 times
//
// Prints PASS name, FAIL name: <expr> or UNREACHABLE name for each test.
// Exits 0 if all pass, 1 on any failure, 2 if the only problems were
// unreachable endpoints.

#include "TlsTest.h"

#include <algorithm>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

namespace
{
	// Constant-initialised, so registrars in other files can use them during
	// dynamic initialisation.
	TlsTestCase*	g_pFirst = NULL;
	TlsTestCase**	g_ppLast = &g_pFirst;

	const char*		g_pszFailed = NULL;		// first failed CHECK of the running test
	bool			g_bUnreachable = false;	// the running test could not reach its endpoint

	const int		NETWORK_ATTEMPTS = 3;
	const DWORD		SOCKET_TIMEOUT_MS = 15000;

	enum class Outcome { Pass, Fail, Unreachable };

	Outcome RunOnce(const TlsTestCase& oTest)
	{
		g_pszFailed = NULL;
		g_bUnreachable = false;
		oTest.pfnRun();
		if ( g_bUnreachable )
			return Outcome::Unreachable;
		return g_pszFailed ? Outcome::Fail : Outcome::Pass;
	}

	Outcome Run(const TlsTestCase& oTest)
	{
		const int nAttempts = oTest.bNetwork ? NETWORK_ATTEMPTS : 1;
		Outcome nOutcome = Outcome::Fail;
		for ( int nAttempt = 1 ; nAttempt <= nAttempts ; ++nAttempt )
		{
			nOutcome = RunOnce( oTest );
			if ( nOutcome == Outcome::Pass )
				break;
			if ( nAttempt < nAttempts )
				printf( "  %s: attempt %d of %d did not pass, retrying\n", oTest.pszName, nAttempt, nAttempts );
		}

		switch ( nOutcome )
		{
		case Outcome::Pass:
			printf( "PASS %s\n", oTest.pszName );
			break;
		case Outcome::Fail:
			printf( "FAIL %s: %s\n", oTest.pszName, g_pszFailed );
			break;
		case Outcome::Unreachable:
			printf( "UNREACHABLE %s\n", oTest.pszName );
			break;
		}
		return nOutcome;
	}

	SOCKET Connect(const char* pszHost, unsigned short nPort)
	{
		char szPort[ 8 ];
		sprintf_s( szPort, "%u", static_cast< unsigned >( nPort ) );

		addrinfo oHints = {};
		oHints.ai_family = AF_UNSPEC;
		oHints.ai_socktype = SOCK_STREAM;
		oHints.ai_protocol = IPPROTO_TCP;
		addrinfo* pResult = NULL;
		const int nResolve = getaddrinfo( pszHost, szPort, &oHints, &pResult );
		if ( nResolve != 0 )
		{
			TlsTestUnreachable( "cannot resolve %s: error %d", pszHost, nResolve );
			return INVALID_SOCKET;
		}

		SOCKET hSocket = INVALID_SOCKET;
		int nError = 0;
		for ( const addrinfo* pAddr = pResult ; pAddr ; pAddr = pAddr->ai_next )
		{
			hSocket = socket( pAddr->ai_family, pAddr->ai_socktype, pAddr->ai_protocol );
			if ( hSocket == INVALID_SOCKET )
			{
				nError = WSAGetLastError();
				continue;
			}
			const DWORD nTimeout = SOCKET_TIMEOUT_MS;
			setsockopt( hSocket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast< const char* >( &nTimeout ), static_cast< int >( sizeof( nTimeout ) ) );
			setsockopt( hSocket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast< const char* >( &nTimeout ), static_cast< int >( sizeof( nTimeout ) ) );
			if ( connect( hSocket, pAddr->ai_addr, static_cast< int >( pAddr->ai_addrlen ) ) == 0 )
				break;
			nError = WSAGetLastError();
			closesocket( hSocket );
			hSocket = INVALID_SOCKET;
		}
		freeaddrinfo( pResult );

		if ( hSocket == INVALID_SOCKET )
			TlsTestUnreachable( "cannot connect to %s:%u: error %d", pszHost, static_cast< unsigned >( nPort ), nError );
		return hSocket;
	}

	// Feeds nIn received bytes to Handshake(), nChunk at a time if nChunk > 0.
	// Bytes left over after Done go to Decrypt(). False if those held
	// application data or failed the session.
	bool FeedHandshake(CTlsClient& oTls, const BYTE* pIn, size_t nIn, size_t nChunk,
		std::vector<BYTE>& oSend, TlsResult& nResult)
	{
		const size_t nStep = nChunk ? nChunk : nIn;
		size_t nDone = 0;
		do
		{
			const size_t nTake = ( std::min )( nStep, nIn - nDone );
			nResult = oTls.Handshake( pIn + nDone, nTake, oSend );
			nDone += nTake;
		}
		while ( nResult == TlsResult::NeedMore && nDone < nIn );

		if ( nResult != TlsResult::Done || nDone == nIn )
			return true;

		std::vector<BYTE> oPlain;
		const TlsResult nRest = oTls.Decrypt( pIn + nDone, nIn - nDone, oPlain, oSend );
		if ( nRest == TlsResult::Failed || nRest == TlsResult::Closed || ! oPlain.empty() )
		{
			printf( "  %zu bytes after the handshake: result %d, %zu bytes of plaintext\n",
				nIn - nDone, static_cast< int >( nRest ), oPlain.size() );
			return false;
		}
		return true;
	}

	// Reads a whole file that another process may hold open for writing.
	bool ReadSharedFile(const char* pszPath, std::string& sText)
	{
		const HANDLE hFile = CreateFileA( pszPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
		if ( hFile == INVALID_HANDLE_VALUE )
			return false;
		sText.clear();
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
			sText.append( pBuffer, nRead );
		}
		CloseHandle( hFile );
		return bOk;
	}
}

bool SendAll(SOCKET hSocket, const std::vector<BYTE>& oData)
{
	size_t nSent = 0;
	while ( nSent < oData.size() )
	{
		const size_t nChunk = ( std::min )( oData.size() - nSent, static_cast< size_t >( 65536 ) );
		const int nResult = send( hSocket, reinterpret_cast< const char* >( oData.data() + nSent ), static_cast< int >( nChunk ), 0 );
		if ( nResult <= 0 )
			return false;
		nSent += static_cast< size_t >( nResult );
	}
	return true;
}

TlsTestRegistrar::TlsTestRegistrar(TlsTestCase& oTest)
{
	*g_ppLast = &oTest;
	g_ppLast = &oTest.pNext;
}

void TlsTestFail(const char* pszExpr)
{
	if ( ! g_pszFailed )
		g_pszFailed = pszExpr;
}

void TlsTestUnreachable(const char* pszFormat, ...)
{
	g_bUnreachable = true;
	printf( "  unreachable: " );
	va_list pArgs;
	va_start( pArgs, pszFormat );
	vprintf( pszFormat, pArgs );
	va_end( pArgs );
	printf( "\n" );
}

SOCKET ConnectAndHandshake(CTlsClient& oTls, const char* pszHost, unsigned short nPort, size_t nChunk)
{
	SOCKET hSocket = Connect( pszHost, nPort );
	if ( hSocket == INVALID_SOCKET )
		return INVALID_SOCKET;

	std::vector<BYTE> oSend;
	TlsResult nResult = oTls.Start( oSend );
	for ( ;; )
	{
		if ( ! oSend.empty() )
		{
			if ( ! SendAll( hSocket, oSend ) )
			{
				TlsTestUnreachable( "%s:%u: send failed during the handshake: error %d",
					pszHost, static_cast< unsigned >( nPort ), WSAGetLastError() );
				break;
			}
			oSend.clear();
		}

		if ( nResult == TlsResult::Done )
		{
			printf( "  %s:%u: established, protocol 0x%lX\n",
				pszHost, static_cast< unsigned >( nPort ), static_cast< unsigned long >( oTls.Protocol() ) );
			return hSocket;
		}
		if ( nResult != TlsResult::NeedMore )
		{
			printf( "  %s:%u: handshake failed, SECURITY_STATUS 0x%08lX\n",
				pszHost, static_cast< unsigned >( nPort ), static_cast< unsigned long >( oTls.LastStatus() ) );
			break;
		}

		BYTE pBuffer[ 16384 ];
		const int nReceived = recv( hSocket, reinterpret_cast< char* >( pBuffer ), static_cast< int >( sizeof( pBuffer ) ), 0 );
		if ( nReceived <= 0 )
		{
			if ( nReceived == 0 )
				TlsTestUnreachable( "%s:%u: closed by the peer during the handshake",
					pszHost, static_cast< unsigned >( nPort ) );
			else
				TlsTestUnreachable( "%s:%u: receive failed during the handshake: error %d",
					pszHost, static_cast< unsigned >( nPort ), WSAGetLastError() );
			break;
		}
		if ( ! FeedHandshake( oTls, pBuffer, static_cast< size_t >( nReceived ), nChunk, oSend, nResult ) )
			break;
	}

	closesocket( hSocket );
	return INVALID_SOCKET;
}

bool RunHandshake(CTlsClient& oTls, const char* pszHost, unsigned short nPort)
{
	const SOCKET hSocket = ConnectAndHandshake( oTls, pszHost, nPort );
	if ( hSocket == INVALID_SOCKET )
		return false;
	closesocket( hSocket );
	return true;
}

bool HttpGet(CTlsClient& oTls, SOCKET hSocket, const char* pszHost, const char* pszPath,
	std::string& sBody, size_t nChunk)
{
	sBody.clear();
	const std::string sRequest = std::string( "GET " ) + pszPath + " HTTP/1.1\r\nHost: " + pszHost +
		"\r\nUser-Agent: TlsTest\r\nAccept: */*\r\nConnection: close\r\n\r\n";

	std::vector<BYTE> oSend, oPlain;
	if ( oTls.Encrypt( reinterpret_cast< const BYTE* >( sRequest.data() ), sRequest.size(), oSend ) != TlsResult::Ok )
	{
		printf( "  %s: encrypt failed, SECURITY_STATUS 0x%08lX\n",
			pszHost, static_cast< unsigned long >( oTls.LastStatus() ) );
		return false;
	}

	// Bytes that arrived with the end of the handshake are decrypted first.
	TlsResult nResult = oTls.Decrypt( NULL, 0, oPlain, oSend );
	for ( ;; )
	{
		if ( ! oPlain.empty() )
		{
			sBody.append( reinterpret_cast< const char* >( oPlain.data() ), oPlain.size() );
			oPlain.clear();
		}
		if ( ! oSend.empty() )
		{
			if ( ! SendAll( hSocket, oSend ) )
			{
				TlsTestUnreachable( "%s%s: send failed: error %d", pszHost, pszPath, WSAGetLastError() );
				return false;
			}
			oSend.clear();
		}

		if ( nResult == TlsResult::Closed )
		{
			printf( "  %s%s: %zu bytes, then close_notify; %lu post-handshake messages\n",
				pszHost, pszPath, sBody.size(), static_cast< unsigned long >( oTls.Renegotiations() ) );
			return true;
		}
		if ( nResult == TlsResult::Failed )
		{
			printf( "  %s%s: decrypt failed after %zu bytes, SECURITY_STATUS 0x%08lX\n",
				pszHost, pszPath, sBody.size(), static_cast< unsigned long >( oTls.LastStatus() ) );
			return false;
		}

		BYTE pBuffer[ 16384 ];
		const int nReceived = recv( hSocket, reinterpret_cast< char* >( pBuffer ), static_cast< int >( sizeof( pBuffer ) ), 0 );
		if ( nReceived == 0 )
		{
			printf( "  %s%s: %zu bytes, then closed without close_notify; %lu post-handshake messages\n",
				pszHost, pszPath, sBody.size(), static_cast< unsigned long >( oTls.Renegotiations() ) );
			return true;
		}
		if ( nReceived < 0 )
		{
			TlsTestUnreachable( "%s%s: receive failed after %zu bytes: error %d",
				pszHost, pszPath, sBody.size(), WSAGetLastError() );
			return false;
		}

		const size_t nIn = static_cast< size_t >( nReceived );
		const size_t nStep = nChunk ? nChunk : nIn;
		size_t nDone = 0;
		do
		{
			const size_t nTake = ( std::min )( nStep, nIn - nDone );
			nResult = oTls.Decrypt( pBuffer + nDone, nTake, oPlain, oSend );
			nDone += nTake;
		}
		while ( nDone < nIn && ( nResult == TlsResult::Ok || nResult == TlsResult::NeedMore ) );
	}
}

bool ServerLogContains(const char* psz)
{
	char szPath[ MAX_PATH ];
	size_t nLength = 0;
	if ( getenv_s( &nLength, szPath, "TLSTEST_SERVER_LOG" ) != 0 || nLength <= 1 )
	{
		printf( "  TLSTEST_SERVER_LOG is not set\n" );
		return false;
	}

	for ( int nAttempt = 0 ; nAttempt < 50 ; ++nAttempt )
	{
		std::string sLog;
		if ( ReadSharedFile( szPath, sLog ) && sLog.find( psz ) != std::string::npos )
			return true;
		Sleep( 100 );
	}
	return false;
}

bool BodyMatchesPattern(const std::string& sBody)
{
	for ( size_t i = 0 ; i < sBody.size() ; ++i )
	{
		if ( static_cast< unsigned char >( sBody[ i ] ) != i % 251 )
			return false;
	}
	return true;
}

int main(int argc, char* argv[])
{
	setvbuf( stdout, NULL, _IONBF, 0 );

	bool bOffline = false, bNetwork = false, bUsage = argc < 2;
	for ( int nArg = 1 ; nArg < argc ; ++nArg )
	{
		if ( strcmp( argv[ nArg ], "--offline" ) == 0 )
			bOffline = true;
		else if ( strcmp( argv[ nArg ], "--network" ) == 0 )
			bNetwork = true;
		else
			bUsage = true;
	}
	if ( bUsage )
	{
		printf( "usage: TlsTest --offline | --network\n" );
		return 1;
	}

	WSADATA oWSA;
	if ( WSAStartup( MAKEWORD( 2, 2 ), &oWSA ) != 0 )
	{
		printf( "WSAStartup failed\n" );
		return 1;
	}

	int nPassed = 0, nFailed = 0, nUnreachable = 0;
	for ( const TlsTestCase* pTest = g_pFirst ; pTest ; pTest = pTest->pNext )
	{
		if ( pTest->bNetwork ? ! bNetwork : ! bOffline )
			continue;
		switch ( Run( *pTest ) )
		{
		case Outcome::Pass:			++nPassed; break;
		case Outcome::Fail:			++nFailed; break;
		case Outcome::Unreachable:	++nUnreachable; break;
		}
	}

	CTlsClient::Cleanup();
	WSACleanup();

	printf( "%d passed, %d failed, %d unreachable\n", nPassed, nFailed, nUnreachable );
	if ( nFailed )
		return 1;
	return nUnreachable ? 2 : 0;
}
