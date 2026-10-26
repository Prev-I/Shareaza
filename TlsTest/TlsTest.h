//
// TlsTest.h
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

// A small test harness for CTlsClient. Tests register themselves with
// TLS_TEST_OFFLINE or TLS_TEST_NETWORK; TlsTestMain.cpp runs them.

#pragma once

// winsock2.h must come before windows.h, which TlsClient.h includes.
#include <winsock2.h>
#include <ws2tcpip.h>

#include "../shareaza/TlsClient.h"

#include <string>

struct TlsTestCase
{
	const char*		pszName;
	void			(*pfnRun)();
	bool			bNetwork;
	TlsTestCase*	pNext;
};

// Adds a test to the list TlsTestMain.cpp runs, in definition order.
struct TlsTestRegistrar
{
	TlsTestRegistrar(TlsTestCase& oTest);
};

// Records a failed CHECK for the running test.
void TlsTestFail(const char* pszExpr);
// Records that the running test could not reach its endpoint. A network test
// that calls this is reported UNREACHABLE, whatever its checks said.
void TlsTestUnreachable(const char* pszFormat, ...);

#define TLS_TEST_DEFINE(name, network) \
	static void TlsTest_##name(); \
	static TlsTestCase TlsTestCase_##name = { #name, &TlsTest_##name, network, NULL }; \
	static TlsTestRegistrar TlsTestRegistrar_##name( TlsTestCase_##name ); \
	static void TlsTest_##name()

#define TLS_TEST_OFFLINE(name)	TLS_TEST_DEFINE(name, false)
#define TLS_TEST_NETWORK(name)	TLS_TEST_DEFINE(name, true)

// Stops the running test at the first failed check.
#define CHECK(expr) \
	if ( expr ) {} else { TlsTestFail( #expr ); return; }

// Resolves pszHost (any address family), connects and runs the handshake on a
// blocking socket. Returns the connected socket, or INVALID_SOCKET if the
// endpoint is unreachable (reported with TlsTestUnreachable) or the handshake
// fails (its SECURITY_STATUS is printed).
// nChunk > 0 feeds received bytes to Handshake() that many at a time. Bytes
// received after the handshake completes go to Decrypt(); they must not hold
// application data, as no server speaks first in these tests.
// bAccept calls Accept() on a Manual session as soon as the handshake is
// complete; these tests take any certificate the local servers present.
SOCKET ConnectAndHandshake(CTlsClient& oTls, const char* pszHost, unsigned short nPort,
	size_t nChunk = 0, bool bAccept = true);

// ConnectAndHandshake, then closes the socket. True if the session was established.
bool RunHandshake(CTlsClient& oTls, const char* pszHost, unsigned short nPort);

// Sends all of oData. False on a socket error.
bool SendAll(SOCKET hSocket, const std::vector<BYTE>& oData);

// Sends "GET pszPath" with "Connection: close" over an established session
// and reads until the server closes it, with or without close_notify.
// sBody receives everything the server sent: status line, headers and body.
// nChunk > 0 feeds received ciphertext to Decrypt() that many bytes at a time.
// False if the session fails or the socket breaks (the latter reported with
// TlsTestUnreachable).
bool HttpGet(CTlsClient& oTls, SOCKET hSocket, const char* pszHost, const char* pszPath,
	std::string& sBody, size_t nChunk = 0);

// The reading half of HttpGet, for a request the caller already sent.
// pszHost and pszPath only label the output.
bool ReadResponse(CTlsClient& oTls, SOCKET hSocket, const char* pszHost, const char* pszPath,
	std::string& sBody, size_t nChunk = 0);

// True if the log file of tls_server.py, named by the TLSTEST_SERVER_LOG
// environment variable, contains psz. Waits up to five seconds for it.
bool ServerLogContains(const char* psz);

// True if every byte satisfies sBody[ i ] == i % 251, the pattern tls_server.py serves.
bool BodyMatchesPattern(const std::string& sBody);
