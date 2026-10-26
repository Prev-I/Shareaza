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

// Tests of CTlsClient's credentials and handshake.

#include "TlsTest.h"

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
