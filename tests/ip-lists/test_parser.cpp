//
// test_parser.cpp
//
// Copyright (c) Shareaza Development Team, 2026.
// This file is part of SHAREAZA (shareaza.sourceforge.net)
//
// Shareaza is free software; you can redistribute it
// and/or modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//

#include "IPListParser.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

static int g_nFailed = 0;

static void Check( bool bCondition, const char* pszName )
{
	if ( ! bCondition )
	{
		std::printf( "FAIL: %s\n", pszName );
		++g_nFailed;
	}
}

static uint32_t V4( uint32_t a, uint32_t b, uint32_t c, uint32_t d )
{
	return ( a << 24 ) | ( b << 16 ) | ( c << 8 ) | d;
}

// Builds an address from its eight 16-bit groups.
static IPList::Addr6 A6( uint16_t g0, uint16_t g1, uint16_t g2, uint16_t g3,
	uint16_t g4, uint16_t g5, uint16_t g6, uint16_t g7 )
{
	const uint16_t g[ 8 ] = { g0, g1, g2, g3, g4, g5, g6, g7 };
	IPList::Addr6 a;
	for ( int i = 0; i < 8; ++i )
	{
		a.b[ i * 2 ] = uint8_t( g[ i ] >> 8 );
		a.b[ i * 2 + 1 ] = uint8_t( g[ i ] & 0xff );
	}
	return a;
}

struct Result
{
	IPList::RangeSet set;
	IPList::ParseStats stats;
};

// Parses text (embedded NULs allowed through n) and finishes the set for lookups.
static void Parse( Result& r, const char* p, size_t n )
{
	IPList::ParseText( p, n, r.set, r.stats );
	r.set.Finish();
}

static void Parse( Result& r, const char* psz )
{
	Parse( r, psz, std::strlen( psz ) );
}

static bool Counts( const Result& r, size_t nTaken, size_t nRejected, size_t nSkipped,
	size_t nAllowed )
{
	return r.stats.taken == nTaken && r.stats.rejected == nRejected &&
		r.stats.skipped == nSkipped && r.stats.allowedByLevel == nAllowed;
}

// The range [first, last] is in the set and its neighbours are not.
static bool HasExactlyV4( const Result& r, uint32_t first, uint32_t last )
{
	return r.set.CountV4() == 1 && r.set.ContainsV4( first ) && r.set.ContainsV4( last ) &&
		( first == 0 || ! r.set.ContainsV4( first - 1 ) ) &&
		( last == 0xffffffffu || ! r.set.ContainsV4( last + 1 ) );
}

static void TestPeerGuardian()
{
	Result r;
	Parse( r, "Some Org: Inc.:1.2.3.0-1.2.3.255\n" );
	Check( Counts( r, 1, 0, 0, 0 ), "peerguardian: counts" );
	Check( HasExactlyV4( r, V4( 1, 2, 3, 0 ), V4( 1, 2, 3, 255 ) ), "peerguardian: range" );
}

static void TestEmule()
{
	Result r;
	Parse( r, "001.002.004.000 - 001.002.004.255 , 000 , China Internet Information Center (CNNIC)\n" );
	Check( Counts( r, 1, 0, 0, 0 ), "emule: counts" );
	Check( HasExactlyV4( r, V4( 1, 2, 4, 0 ), V4( 1, 2, 4, 255 ) ), "emule: range" );

	Result a;
	Parse( a, "001.002.004.000 - 001.002.004.255 , 127 , China Internet Information Center (CNNIC)\n" );
	Check( Counts( a, 0, 0, 0, 1 ), "emule: level 127 allowed" );
	Check( a.set.CountV4() == 0, "emule: level 127 adds nothing" );

	Result b;
	Parse( b, "1.2.4.0 - 1.2.4.255 , 126 , x\n1.2.5.0-1.2.5.255,200,y\n" );
	Check( Counts( b, 1, 0, 0, 1 ), "emule: 126 taken, 200 allowed" );

	// A description holding ':' is still eMule, not PeerGuardian.
	Result c;
	Parse( c, "001.000.000.000 - 001.000.003.255 , 000 , cloudflare:AS13335\n" );
	Check( Counts( c, 1, 0, 0, 0 ), "emule: colon in description" );
	Check( HasExactlyV4( c, V4( 1, 0, 0, 0 ), V4( 1, 0, 3, 255 ) ), "emule: colon range" );

	// eMule shape with no level is rejected.
	Result d;
	Parse( d, "1.2.3.4 - 1.2.3.5 , , x\n1.2.3.4 - 1.2.3.5 , abc\n" );
	Check( Counts( d, 0, 2, 0, 0 ), "emule: bad level rejected" );
}

// eMule-Security's guarding.p2p: eMule lines in a file named .p2p. There is no
// extension input; the format is detected per line, mixed in one buffer.
static void TestEmuleLinesInP2pFile()
{
	Result r;
	Parse( r,
		"001.002.004.000 - 001.002.004.255 , 000 , China Internet Information Center (CNNIC)\n"
		"Some Org: Inc.:1.2.3.0-1.2.3.255\n"
		"009.009.009.000 - 009.009.009.255 , 200 , allowed\n" );
	Check( Counts( r, 2, 0, 0, 1 ), "emule lines in p2p file: counts" );
	Check( r.set.ContainsV4( V4( 1, 2, 4, 128 ) ) && r.set.ContainsV4( V4( 1, 2, 3, 128 ) ),
		"emule lines in p2p file: both ranges" );
	Check( ! r.set.ContainsV4( V4( 9, 9, 9, 1 ) ), "emule lines in p2p file: level honoured" );
}

static void TestGnucleus()
{
	Result r;
	Parse( r, "5.6.7.8-5.6.7.20:bad\n" );
	Check( Counts( r, 1, 0, 0, 0 ), "gnucleus range: counts" );
	Check( HasExactlyV4( r, V4( 5, 6, 7, 8 ), V4( 5, 6, 7, 20 ) ), "gnucleus range: true range" );

	Result s;
	Parse( s, "5.6.7.8\n" );
	Check( Counts( s, 1, 0, 0, 0 ), "gnucleus single: counts" );
	Check( HasExactlyV4( s, V4( 5, 6, 7, 8 ), V4( 5, 6, 7, 8 ) ), "gnucleus single: address" );

	Result c;
	Parse( c, "5.6.7.8:comment\n5.6.7.20-5.6.7.8\n" );
	Check( Counts( c, 2, 0, 0, 0 ), "gnucleus: comment and reversed bounds" );
	Check( HasExactlyV4( c, V4( 5, 6, 7, 8 ), V4( 5, 6, 7, 20 ) ), "gnucleus: reversed range" );
}

static void TestCidr()
{
	Result r;
	Parse( r, "10.0.0.0/8\n" );
	Check( Counts( r, 1, 0, 0, 0 ), "cidr v4: counts" );
	Check( HasExactlyV4( r, V4( 10, 0, 0, 0 ), V4( 10, 255, 255, 255 ) ), "cidr v4: range" );

	// Host bits set: taken as the containing network.
	Result h;
	Parse( h, "10.1.2.3/8\n" );
	Check( Counts( h, 1, 0, 0, 0 ), "cidr v4 host bits: counts" );
	Check( HasExactlyV4( h, V4( 10, 0, 0, 0 ), V4( 10, 255, 255, 255 ) ), "cidr v4 host bits: network" );

	Result e;
	Parse( e, "1.2.3.4/32\n0.0.0.0/0\n" );
	Check( Counts( e, 2, 0, 0, 0 ), "cidr v4: /32 and /0" );
	Check( e.set.ContainsV4( 0 ) && e.set.ContainsV4( 0xffffffffu ), "cidr v4: /0 covers all" );

	Result v;
	Parse( v, "2001:db8::/32\n" );
	Check( Counts( v, 1, 0, 0, 0 ), "cidr v6: counts" );
	Check( v.set.CountV6() == 1 &&
		v.set.ContainsV6( A6( 0x2001, 0x0db8, 0, 0, 0, 0, 0, 0 ) ) &&
		v.set.ContainsV6( A6( 0x2001, 0x0db8, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff ) ) &&
		! v.set.ContainsV6( A6( 0x2001, 0x0db7, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff ) ) &&
		! v.set.ContainsV6( A6( 0x2001, 0x0db9, 0, 0, 0, 0, 0, 0 ) ), "cidr v6: range" );

	Result s;
	Parse( s, "2a00:1450::1\n" );
	Check( Counts( s, 1, 0, 0, 0 ), "single v6: counts" );
	Check( s.set.CountV6() == 1 && s.set.ContainsV6( A6( 0x2a00, 0x1450, 0, 0, 0, 0, 0, 1 ) ) &&
		! s.set.ContainsV6( A6( 0x2a00, 0x1450, 0, 0, 0, 0, 0, 2 ) ) &&
		! s.set.ContainsV6( A6( 0x2a00, 0x1450, 0, 0, 0, 0, 0, 0 ) ), "single v6: address" );

	Result hb;
	Parse( hb, "2001:db8:1:2::5/32\n" );
	Check( Counts( hb, 1, 0, 0, 0 ) &&
		hb.set.ContainsV6( A6( 0x2001, 0x0db8, 0, 0, 0, 0, 0, 0 ) ) &&
		hb.set.ContainsV6( A6( 0x2001, 0x0db8, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff ) ),
		"cidr v6 host bits: network" );

	// Outside 2000::/3: taken by the parser, dropped by the set.
	Result o;
	Parse( o, "8000::/1\n::1\n" );
	Check( Counts( o, 2, 0, 0, 0 ) && o.set.CountV6() == 0, "cidr v6 outside 2000::/3: taken, dropped" );
}

static void TestV6Text()
{
	struct Case { const char* psz; bool bValid; IPList::Addr6 a; };
	const Case cases[] =
	{
		{ "2001:db8:0:0:0:0:0:1", true, A6( 0x2001, 0xdb8, 0, 0, 0, 0, 0, 1 ) },
		{ "2001:DB8::1", true, A6( 0x2001, 0xdb8, 0, 0, 0, 0, 0, 1 ) },
		{ "2001:db8::", true, A6( 0x2001, 0xdb8, 0, 0, 0, 0, 0, 0 ) },
		{ "::2001:db8", true, A6( 0, 0, 0, 0, 0, 0, 0x2001, 0xdb8 ) },
		{ "::", true, A6( 0, 0, 0, 0, 0, 0, 0, 0 ) },
		{ "2001:db8:0:0:0:0:0:0/128", true, A6( 0x2001, 0xdb8, 0, 0, 0, 0, 0, 0 ) },
		{ "2001:db8:1:2:3:4:5::6", false, {} },
		{ ":::", false, {} },
		{ "2001:db8:1:2:3:4:5::", true, A6( 0x2001, 0xdb8, 1, 2, 3, 4, 5, 0 ) },
		{ "2001:db8::1.2.3.4", true, A6( 0x2001, 0xdb8, 0, 0, 0, 0, 0x0102, 0x0304 ) },
		{ "2001:db8:1:2:3:4:1.2.3.4", true, A6( 0x2001, 0xdb8, 1, 2, 3, 4, 0x0102, 0x0304 ) },
		{ "2001:db8:1:2:3:4:5:6:7", false, {} },
		{ "2001:db8:1:2:3:4:5", false, {} },
		{ "2001::db8::1", false, {} },
		{ "2001:db8:::1", false, {} },
		{ "2001:db8::12345", false, {} },
		{ "2001:db8::g", false, {} },
		{ ":2001:db8::1", false, {} },
		{ "2001:db8::1:", false, {} },
		{ "2001:db8::1.2.3", false, {} },
		{ "2001:db8::1.2.3.4:5", false, {} },
		{ "2001:db8:1:2:3:4:5:1.2.3.4", false, {} },
		{ "2001:db8::/129", false, {} },
		{ "2001:db8::/", false, {} },
	};
	for ( const Case& c : cases )
	{
		Result r;
		Parse( r, c.psz );
		char szName[ 96 ];
		std::snprintf( szName, sizeof( szName ), "v6 text: %s", c.psz );
		// Outside 2000::/3 the set drops the range; the line still counts as taken.
		const bool bInside = ( c.a.b[ 0 ] & 0xe0 ) == 0x20;
		if ( c.bValid )
			Check( Counts( r, 1, 0, 0, 0 ) && ( bInside ?
				r.set.ContainsV6( c.a ) && r.set.CountV6() == 1 : r.set.CountV6() == 0 ),
				szName );
		else
			Check( Counts( r, 0, 1, 0, 0 ) && r.set.CountV6() == 0, szName );

		// The address text itself, byte for byte, also outside 2000::/3.
		if ( c.bValid && ! std::strchr( c.psz, '/' ) )
		{
			IPList::Addr6 a = {};
			Check( IPList::Detail::ParseV6( c.psz, c.psz + std::strlen( c.psz ), a ) &&
				a == c.a, szName );
		}
	}
}

static void TestSpamhausJson()
{
	Result r;
	Parse( r, "{\"cidr\":\"1.10.16.0/20\",\"sblid\":\"SBL256894\",\"rir\":\"apnic\"}\n" );
	Check( Counts( r, 1, 0, 0, 0 ), "json cidr: counts" );
	Check( HasExactlyV4( r, V4( 1, 10, 16, 0 ), V4( 1, 10, 31, 255 ) ), "json cidr: range" );

	Result m;
	Parse( m, "{\"type\":\"metadata\",\"timestamp\":1}\n" );
	Check( Counts( m, 0, 0, 1, 0 ), "json metadata: skipped" );

	Result v;
	Parse( v, "{ \"cidr\" : \"2001:db8::/32\" , \"sblid\":\"SBL1\"}\n{\"cidr\":\"1.2.3.0/33\"}\n" );
	Check( Counts( v, 1, 1, 0, 0 ) && v.set.CountV6() == 1, "json: v6 taken, bad cidr rejected" );
}

static void TestCrlfAndBom()
{
	Result clean;
	Parse( clean, "1.2.3.4\n" );

	Result r;
	Parse( r, "\xEF\xBB\xBF" "1.2.3.4\r\n" );
	Check( Counts( r, 1, 0, 0, 0 ), "crlf and bom: counts" );
	Check( HasExactlyV4( r, V4( 1, 2, 3, 4 ), V4( 1, 2, 3, 4 ) ), "crlf and bom: same range" );

	// Trailing spaces, tabs, no final newline.
	Result t;
	Parse( t, "\t Some Org: Inc.:1.2.3.0-1.2.3.255 \t\r\n"
		"  001.002.004.000 - 001.002.004.255 , 000 , CNNIC \t\r\n"
		"\t10.0.0.0/8\t\r\n"
		"5.6.7.8-5.6.7.20:bad\t" );
	Check( Counts( t, 4, 0, 0, 0 ), "crlf and bom: whitespace counts" );
	Check( t.set.ContainsV4( V4( 1, 2, 3, 0 ) ) && t.set.ContainsV4( V4( 1, 2, 4, 255 ) ) &&
		t.set.ContainsV4( V4( 10, 1, 1, 1 ) ) && t.set.ContainsV4( V4( 5, 6, 7, 20 ) ),
		"crlf and bom: whitespace ranges" );
}

static void TestDescriptionWithColonsAndDashes()
{
	Result r;
	Parse( r, "a-b:c-d:1.2.3.4-1.2.3.5\n" );
	Check( Counts( r, 1, 0, 0, 0 ), "description with colons and dashes: counts" );
	Check( HasExactlyV4( r, V4( 1, 2, 3, 4 ), V4( 1, 2, 3, 5 ) ),
		"description with colons and dashes: range" );
}

static void TestRejected()
{
	const char* const lines[] =
	{
		"1.2.3.256", "1.2.3.4/33", "hello", "1.2.3", "1.2.3.4.5", "1.2.3.4/", "1.2.3.4/8x",
		"0001.2.3.4", "1.2.3.4-", "1.2.3.4-1.2.3", "1.2.3.4 junk", "x:1.2.3.4-1.2.3.256",
		"-1.2.3.4", "1..2.3", "\xff\xfe" "1.2.3.4",
	};
	for ( const char* psz : lines )
	{
		Result r;
		Parse( r, psz );
		char szName[ 96 ];
		std::snprintf( szName, sizeof( szName ), "rejected: %s", psz );
		Check( Counts( r, 0, 1, 0, 0 ) && r.set.CountV4() == 0 && r.set.CountV6() == 0, szName );
	}

	Result n;
	Parse( n, "1.2.3.4\0x\n", 10 );
	Check( Counts( n, 0, 1, 0, 0 ), "rejected: embedded NUL" );
}

static void TestComments()
{
	Result r;
	Parse( r, "# x\n; x\n// x\n\n   \n\t\r\n#1.2.3.4\n" );
	Check( Counts( r, 0, 0, 7, 0 ), "comments: skipped" );
	Check( r.set.CountV4() == 0, "comments: nothing added" );

	Result e;
	Parse( e, "", 0 );
	Check( Counts( e, 0, 0, 0, 0 ), "empty input: nothing counted" );
}

static void TestStatsAccumulate()
{
	IPList::RangeSet s;
	IPList::ParseStats st;
	const char* a = "1.2.3.4\nhello\n";
	const char* b = "# c\n5.6.7.8\n";
	IPList::ParseText( a, std::strlen( a ), s, st );
	IPList::ParseText( b, std::strlen( b ), s, st );
	Check( st.taken == 2 && st.rejected == 1 && st.skipped == 1, "stats accumulate across calls" );
	Check( ! s.IsFinished(), "ParseText does not call Finish" );
}

// A pathological long line must be handled in linear time. Quadratic work on
// these 8 MB lines would not finish in any reasonable time.
// Fills a buffer of about n bytes with repeats of psz.
static std::vector< char > Repeat( const char* psz, size_t n )
{
	const size_t nLen = std::strlen( psz );
	std::vector< char > p;
	p.reserve( n + nLen );
	while ( p.size() < n )
		p.insert( p.end(), psz, psz + nLen );
	return p;
}

// A pathological long line must be handled in linear time. Quadratic work on
// these 8 MB lines would not finish in any reasonable time.
static void TestLongLines()
{
	const size_t n = 8u << 20;
	std::vector< char > pJson = Repeat( "\"", n );
	pJson.front() = '{';
	const std::vector< char > lines[] =
	{
		Repeat( ":", n ), Repeat( "1", n ), pJson, Repeat( "1.2.3.4-", n ), Repeat( "1:", n ),
	};

	Result r;
	for ( const std::vector< char >& p : lines )
		Parse( r, p.data(), p.size() );
	Check( Counts( r, 0, 4, 1, 0 ), "long lines: rejected or skipped" );
}

int main()
{
	TestPeerGuardian();
	TestEmule();
	TestEmuleLinesInP2pFile();
	TestGnucleus();
	TestCidr();
	TestV6Text();
	TestSpamhausJson();
	TestCrlfAndBom();
	TestDescriptionWithColonsAndDashes();
	TestRejected();
	TestComments();
	TestStatsAccumulate();
	TestLongLines();

	if ( g_nFailed == 0 )
		std::printf( "parser: all tests passed\n" );
	return g_nFailed ? 1 : 0;
}
