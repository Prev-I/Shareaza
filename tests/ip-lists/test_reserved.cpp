//
// test_reserved.cpp
//
// Copyright (c) Shareaza Development Team, 2026.
// This file is part of SHAREAZA (shareaza.sourceforge.net)
//
// Shareaza is free software; you can redistribute it
// and/or modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//

#include "ReservedAddresses.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

static int g_nFailed = 0;

static void Check( bool bCondition, const char* pszName )
{
	if ( ! bCondition )
	{
		std::printf( "FAIL: %s\n", pszName );
		++g_nFailed;
	}
}

// Parses a dotted quad into host byte order; the test inputs are always valid.
static uint32_t V4( const char* psz )
{
	unsigned int a = 0, b = 0, c = 0, d = 0;
	std::sscanf( psz, "%u.%u.%u.%u", &a, &b, &c, &d );
	return ( a << 24 ) | ( b << 16 ) | ( c << 8 ) | d;
}

static int HexDigit( char c )
{
	if ( c >= '0' && c <= '9' ) return c - '0';
	if ( c >= 'a' && c <= 'f' ) return c - 'a' + 10;
	if ( c >= 'A' && c <= 'F' ) return c - 'A' + 10;
	return -1;
}

// Parses one side of "::" into 16-bit groups; a trailing dotted quad counts as two groups.
static int Groups( const char* psz, const char* pszEnd, uint16_t* pGroups )
{
	int n = 0;
	while ( psz < pszEnd )
	{
		const char* pszColon = psz;
		while ( pszColon < pszEnd && *pszColon != ':' ) ++pszColon;
		bool bDotted = false;
		for ( const char* p = psz; p < pszColon; ++p )
			if ( *p == '.' ) bDotted = true;
		if ( bDotted )
		{
			char sz[ 16 ] = {};
			std::memcpy( sz, psz, size_t( pszColon - psz ) );
			const uint32_t n4 = V4( sz );
			pGroups[ n++ ] = uint16_t( n4 >> 16 );
			pGroups[ n++ ] = uint16_t( n4 & 0xffff );
		}
		else
		{
			unsigned int nGroup = 0;
			for ( const char* p = psz; p < pszColon; ++p )
				nGroup = ( nGroup << 4 ) | unsigned( HexDigit( *p ) );
			pGroups[ n++ ] = uint16_t( nGroup );
		}
		psz = ( pszColon < pszEnd ) ? pszColon + 1 : pszEnd;
	}
	return n;
}

// Parses an IPv6 address in the textual forms the tests use (with or without "::").
static void V6( const char* psz, uint8_t (&a)[16] )
{
	uint16_t pHead[ 8 ] = {}, pTail[ 8 ] = {}, pAll[ 8 ] = {};
	const char* pszGap = std::strstr( psz, "::" );
	const char* pszEnd = psz + std::strlen( psz );
	const int nHead = Groups( psz, pszGap ? pszGap : pszEnd, pHead );
	const int nTail = pszGap ? Groups( pszGap + 2, pszEnd, pTail ) : 0;
	for ( int i = 0; i < nHead; ++i ) pAll[ i ] = pHead[ i ];
	for ( int i = 0; i < nTail; ++i ) pAll[ 8 - nTail + i ] = pTail[ i ];
	for ( int i = 0; i < 8; ++i )
	{
		a[ i * 2 ] = uint8_t( pAll[ i ] >> 8 );
		a[ i * 2 + 1 ] = uint8_t( pAll[ i ] & 0xff );
	}
}

static bool ReservedV6( const char* psz )
{
	uint8_t a[ 16 ];
	V6( psz, a );
	return Reserved::IsReservedV6( a );
}

static bool LocalV6( const char* psz )
{
	uint8_t a[ 16 ];
	V6( psz, a );
	return Reserved::IsLocalV6( a );
}

int main()
{
	// The parsers themselves.
	{
		Check( V4( "192.168.1.2" ) == 0xC0A80102u, "parser: v4" );
		uint8_t a[ 16 ];
		V6( "2001:db8::1", a );
		Check( a[ 0 ] == 0x20 && a[ 1 ] == 0x01 && a[ 2 ] == 0x0d && a[ 3 ] == 0xb8
			&& a[ 14 ] == 0 && a[ 15 ] == 1, "parser: v6" );
		V6( "::ffff:1.2.3.4", a );
		Check( a[ 10 ] == 0xff && a[ 11 ] == 0xff && a[ 12 ] == 1 && a[ 15 ] == 4,
			"parser: v6 with dotted quad" );
	}

	const char* const pReservedV4[] = {
		"0.0.0.1", "100.64.0.1", "127.0.0.1", "192.0.0.8", "192.0.2.1", "192.88.99.1",
		"198.18.0.1", "198.19.255.255", "198.51.100.1", "203.0.113.1", "224.0.0.1",
		"240.0.0.1", "255.255.255.255",
		// The rest of 192.0.0.0/24 around the two globally reachable addresses.
		"192.0.0.0", "192.0.0.11", "192.0.0.170", "192.0.0.255",
	};
	for ( const char* psz : pReservedV4 )
		Check( Reserved::IsReservedV4( V4( psz ) ), psz );

	const char* const pPublicV4[] = {
		"6.0.0.1", "7.0.0.1", "55.0.0.1", "204.152.64.1", "198.17.255.255", "198.20.0.0",
		"8.8.8.8", "10.0.0.1", "192.168.1.1", "169.254.1.1",
		// Globally reachable rows inside 192.0.0.0/24, and around it.
		"192.0.0.9", "192.0.0.10", "192.0.1.0", "191.255.255.255",
		"223.255.255.255", "100.63.255.255", "100.128.0.0",
	};
	for ( const char* psz : pPublicV4 )
		Check( ! Reserved::IsReservedV4( V4( psz ) ), psz );

	const char* const pReservedV6[] = {
		"::", "::1", "::ffff:1.2.3.4", "100::1", "2001:2::1", "2001:db8::1", "3fff::1",
		"ff02::1",
	};
	for ( const char* psz : pReservedV6 )
		Check( ReservedV6( psz ), psz );

	const char* const pPublicV6[] = {
		"2001::1", "2002::1", "fe80::1", "fc00::1", "2a00:1450::1",
		// Globally reachable rows inside or next to 2001::/23, and NAT64.
		"2001:3::1", "2001:20::1", "2001:5::1", "2001:3::", "64:ff9b::1.2.3.4",
		"::2", "2001:db9::1",
	};
	for ( const char* psz : pPublicV6 )
		Check( ! ReservedV6( psz ), psz );

	const char* const pLocalV4[] = {
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.0.1",
		"169.254.0.1",
	};
	for ( const char* psz : pLocalV4 )
		Check( Reserved::IsLocalV4( V4( psz ) ), psz );
	Check( ! Reserved::IsLocalV4( V4( "172.32.0.1" ) ), "local: 172.32.0.1" );
	Check( ! Reserved::IsLocalV4( V4( "8.8.8.8" ) ), "local: 8.8.8.8" );

	const char* const pLocalV6[] = { "::1", "fc00::1", "fd12::1", "fe80::1" };
	for ( const char* psz : pLocalV6 )
		Check( LocalV6( psz ), psz );
	Check( ! LocalV6( "2001:db8::1" ), "local: 2001:db8::1" );
	Check( ! LocalV6( "fec0::1" ), "local: fec0::1" );

	Check( Reserved::kRegistryDate[ 0 ] != '\0', "registry date recorded" );

	if ( g_nFailed == 0 )
		std::printf( "reserved addresses: all tests passed\n" );
	return g_nFailed ? 1 : 0;
}
