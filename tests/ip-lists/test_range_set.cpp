//
// test_range_set.cpp
//
// Copyright (c) Shareaza Development Team, 2026.
// This file is part of SHAREAZA (shareaza.sourceforge.net)
//
// Shareaza is free software; you can redistribute it
// and/or modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//

#include "IPRangeSet.h"

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

// Fixed-seed xorshift32, so every run tests the same ranges.
static uint32_t g_nRandom = 0x2545F491u;

static uint32_t Random()
{
	g_nRandom ^= g_nRandom << 13;
	g_nRandom ^= g_nRandom >> 17;
	g_nRandom ^= g_nRandom << 5;
	return g_nRandom;
}

// Random ranges over a 16-bit sub-space starting at nBase: short and long ones,
// duplicates, adjacent pairs, reversed bounds. Lookups are compared with a bitmap
// for every address of the sub-space and the address just below it.
static bool BruteForceV4( uint32_t nBase )
{
	std::vector< bool > pMap( 65536, false );
	IPList::RangeSet s;
	const int nRanges = 1 + int( Random() % 120 );
	uint32_t nPrevLast = 0;
	for ( int i = 0; i < nRanges; ++i )
	{
		uint32_t nFirst = Random() & 0xffff;
		uint32_t nLength = ( Random() % 4 == 0 ) ? ( Random() % 4096 ) : ( Random() % 16 );
		switch ( Random() % 8 )
		{
		case 0:		// adjacent to the previous range
			if ( nPrevLast < 0xffff ) nFirst = nPrevLast + 1;
			break;
		case 1:		// touches the top of the sub-space
			nLength = 0xffff - nFirst;
			break;
		}
		uint32_t nLast = nFirst + nLength;
		if ( nLast > 0xffff ) nLast = 0xffff;
		for ( uint32_t a = nFirst; a <= nLast; ++a ) pMap[ a ] = true;
		nPrevLast = nLast;
		if ( Random() % 4 == 0 )
			s.AddV4( nBase + nLast, nBase + nFirst );		// reversed
		else
			s.AddV4( nBase + nFirst, nBase + nLast );
		if ( Random() % 8 == 0 )
			s.AddV4( nBase + nFirst, nBase + nLast );		// duplicate
	}
	s.Finish();

	bool bOK = true;
	for ( uint32_t a = 0; a <= 0xffff; ++a )
		if ( s.ContainsV4( nBase + a ) != pMap[ a ] ) bOK = false;
	if ( nBase > 0 && s.ContainsV4( nBase - 1 ) ) bOK = false;

	// No two stored ranges may overlap or touch: count the edges of the bitmap.
	size_t nRuns = 0;
	for ( uint32_t a = 0; a <= 0xffff; ++a )
		if ( pMap[ a ] && ( a == 0 || ! pMap[ a - 1 ] ) ) ++nRuns;
	if ( s.CountV4() != nRuns ) bOK = false;
	return bOK;
}

// The same over the last 16 bits of an IPv6 /112.
static bool BruteForceV6( uint16_t g0, uint16_t g6 )
{
	std::vector< bool > pMap( 65536, false );
	IPList::RangeSet s;
	const int nRanges = 1 + int( Random() % 120 );
	for ( int i = 0; i < nRanges; ++i )
	{
		const uint32_t nFirst = Random() & 0xffff;
		uint32_t nLast = nFirst + ( ( Random() % 4 == 0 ) ? ( Random() % 4096 ) : ( Random() % 16 ) );
		if ( nLast > 0xffff || Random() % 8 == 0 ) nLast = 0xffff;
		for ( uint32_t a = nFirst; a <= nLast; ++a ) pMap[ a ] = true;
		s.AddV6( A6( g0, 0, 0, 0, 0, 0, g6, uint16_t( nFirst ) ),
			A6( g0, 0, 0, 0, 0, 0, g6, uint16_t( nLast ) ) );
	}
	s.Finish();

	bool bOK = true;
	for ( uint32_t a = 0; a <= 0xffff; ++a )
		if ( s.ContainsV6( A6( g0, 0, 0, 0, 0, 0, g6, uint16_t( a ) ) ) != pMap[ a ] ) bOK = false;
	if ( s.ContainsV6( A6( g0, 0, 0, 0, 0, 0, uint16_t( g6 - 1 ), 0xffff ) ) ) bOK = false;
	if ( s.ContainsV6( A6( g0, 0, 0, 0, 0, 0, uint16_t( g6 + 1 ), 0 ) ) ) bOK = false;

	size_t nRuns = 0;
	for ( uint32_t a = 0; a <= 0xffff; ++a )
		if ( pMap[ a ] && ( a == 0 || ! pMap[ a - 1 ] ) ) ++nRuns;
	if ( s.CountV6() != nRuns ) bOK = false;
	return bOK;
}

static void TestMergeAgreesWithBruteForce()
{
	for ( int i = 0; i < 10; ++i )
	{
		Check( BruteForceV4( 0x00000000u ), "merge agrees with brute force: v4 bottom" );
		Check( BruteForceV4( 0x0A0B0000u ), "merge agrees with brute force: v4 middle" );
		Check( BruteForceV4( 0xFFFF0000u ), "merge agrees with brute force: v4 top" );
		Check( BruteForceV6( 0x2001, 0x1234 ), "merge agrees with brute force: v6" );
	}
}

static void TestAdjacentRangesMerge()
{
	IPList::RangeSet s;
	s.AddV4( 1, 5 );
	s.AddV4( 6, 9 );
	s.Finish();
	Check( s.CountV4() == 1, "adjacent ranges merge: one range" );
	Check( s.Added() == 2, "adjacent ranges merge: two added" );
	Check( ! s.ContainsV4( 0 ) && s.ContainsV4( 1 ) && s.ContainsV4( 5 )
		&& s.ContainsV4( 6 ) && s.ContainsV4( 9 ) && ! s.ContainsV4( 10 ),
		"adjacent ranges merge: lookups" );

	IPList::RangeSet t;
	t.AddV4( 1, 5 );
	t.AddV4( 7, 9 );
	t.Finish();
	Check( t.CountV4() == 2 && ! t.ContainsV4( 6 ), "a gap of one keeps two ranges" );

	IPList::RangeSet u;
	u.AddV6( A6( 0x2001, 0xdb8, 0, 0, 0, 0, 0, 0 ), A6( 0x2001, 0xdb8, 0, 0, 0xffff, 0xffff, 0xffff, 0xffff ) );
	u.AddV6( A6( 0x2001, 0xdb8, 0, 1, 0, 0, 0, 0 ), A6( 0x2001, 0xdb8, 0, 1, 0, 0, 0, 5 ) );
	u.Finish();
	Check( u.CountV6() == 1, "adjacent ranges merge: v6 across a byte carry" );
}

static void TestTopOfAddressSpace()
{
	IPList::RangeSet s;
	s.AddV4( 0xFFFFFF00u, 0xFFFFFFFFu );
	s.AddV4( 0xFFFFFFFEu, 0xFFFFFFFFu );
	s.AddV4( 0xFFFFFFFFu, 0xFFFFFFFFu );
	s.Finish();
	Check( s.CountV4() == 1, "top of address space: merged" );
	Check( s.ContainsV4( 0xFFFFFFFFu ) && s.ContainsV4( 0xFFFFFF00u ) && ! s.ContainsV4( 0xFFFFFEFFu ),
		"top of address space: lookups" );

	IPList::RangeSet t;
	t.AddV4( 0, 0 );
	t.AddV4( 0xFFFFFFFFu, 0xFFFFFFFFu );
	t.Finish();
	Check( t.CountV4() == 2 && t.ContainsV4( 0 ) && t.ContainsV4( 0xFFFFFFFFu ) && ! t.ContainsV4( 1 ),
		"top of address space: both ends, no wrap" );

	const IPList::Addr6 aTop = A6( 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff );
	IPList::RangeSet u;
	u.AddV6( A6( 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xff00 ), aTop );
	u.AddV6( aTop, aTop );
	u.Finish();
	Check( u.Added() == 0 && u.CountV6() == 0 && ! u.ContainsV6( aTop ),
		"top of address space: ffff:...:ffff lies outside 2000::/3" );

	const IPList::Addr6 aTop3 = A6( 0x3fff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff );
	IPList::RangeSet v;
	v.AddV6( A6( 0x3fff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xff00 ), aTop3 );
	v.AddV6( A6( 0x3fff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xfffe ), aTop3 );
	v.Finish();
	Check( v.CountV6() == 1 && v.ContainsV6( aTop3 )
		&& ! v.ContainsV6( A6( 0x3fff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xfeff ) )
		&& ! v.ContainsV6( A6( 0x4000, 0, 0, 0, 0, 0, 0, 0 ) ),
		"top of address space: 3fff:...:ffff, the top of 2000::/3" );
}

static void TestV6OutsideDropped()
{
	IPList::RangeSet s;
	s.AddV6( A6( 0x4000, 0, 0, 0, 0, 0, 0, 0 ), A6( 0x7fff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff ) );
	s.AddV6( A6( 0, 0, 0, 0, 0, 0, 0, 1 ), A6( 0, 0, 0, 0, 0, 0, 0, 1 ) );
	s.AddV6( A6( 0xfe80, 0, 0, 0, 0, 0, 0, 0 ), A6( 0xfe80, 0, 0, 0, 0, 0, 0, 0xffff ) );
	s.Finish();
	Check( s.Added() == 0 && s.CountV6() == 0, "v6 outside 2000::/3 dropped: 4000::/2 and others" );

	IPList::RangeSet t;
	t.AddV6( A6( 0, 0, 0, 0, 0, 0, 0, 0 ), A6( 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff ) );
	t.Finish();
	Check( t.Added() == 1 && t.CountV6() == 1, "v6 outside 2000::/3 dropped: ::/0 keeps one range" );
	Check( t.ContainsV6( A6( 0x2000, 0, 0, 0, 0, 0, 0, 0 ) )
		&& t.ContainsV6( A6( 0x3fff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff ) )
		&& ! t.ContainsV6( A6( 0x1fff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff ) )
		&& ! t.ContainsV6( A6( 0x4000, 0, 0, 0, 0, 0, 0, 0 ) ),
		"v6 outside 2000::/3 dropped: ::/0 clips to exactly 2000::/3" );
	Check( IPList::CheckSanity( t ) == IPList::Refusal::V6CoversGlobalUnicast,
		"v6 outside 2000::/3 dropped: ::/0 refused" );

	// A range straddling only the lower edge, or only the upper edge, is clipped there.
	IPList::RangeSet w;
	w.AddV6( A6( 0x1fff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xfff0 ), A6( 0x2000, 0, 0, 0, 0, 0, 0, 5 ) );
	w.AddV6( A6( 0x3fff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xff00 ), A6( 0x4000, 0, 0, 0, 0, 0, 0, 5 ) );
	w.Finish();
	Check( w.Added() == 2 && w.CountV6() == 2, "v6 clipped at one edge: both kept" );
	Check( w.RangesV6().size() == 2
		&& w.RangesV6()[ 0 ].first == A6( 0x2000, 0, 0, 0, 0, 0, 0, 0 )
		&& w.RangesV6()[ 0 ].last == A6( 0x2000, 0, 0, 0, 0, 0, 0, 5 )
		&& w.RangesV6()[ 1 ].first == A6( 0x3fff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xff00 )
		&& w.RangesV6()[ 1 ].last == A6( 0x3fff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff ),
		"v6 clipped at one edge: exact bounds" );
	Check( ! w.ContainsV6( A6( 0x1fff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff ) )
		&& w.ContainsV6( A6( 0x2000, 0, 0, 0, 0, 0, 0, 0 ) ) && w.ContainsV6( A6( 0x2000, 0, 0, 0, 0, 0, 0, 5 ) )
		&& ! w.ContainsV6( A6( 0x2000, 0, 0, 0, 0, 0, 0, 6 ) )
		&& w.ContainsV6( A6( 0x3fff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff ) )
		&& ! w.ContainsV6( A6( 0x4000, 0, 0, 0, 0, 0, 0, 0 ) ),
		"v6 clipped at one edge: lookups" );

	// Two halves that merge into the whole of 2000::/3 are refused as well.
	IPList::RangeSet u;
	u.AddV6( A6( 0x2000, 0, 0, 0, 0, 0, 0, 0 ), A6( 0x2fff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff ) );
	u.AddV6( A6( 0x3000, 0, 0, 0, 0, 0, 0, 0 ), A6( 0x3fff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff ) );
	u.Finish();
	Check( IPList::CheckSanity( u ) == IPList::Refusal::V6CoversGlobalUnicast,
		"v6 outside 2000::/3 dropped: halves merging into 2000::/3 refused" );

	IPList::RangeSet v;
	v.AddV6( A6( 0x2000, 0, 0, 0, 0, 0, 0, 1 ), A6( 0x3fff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff ) );
	v.Finish();
	Check( IPList::CheckSanity( v ) == IPList::Refusal::None,
		"v6 outside 2000::/3 dropped: all but one address accepted" );
}

static void TestSanity()
{
	using IPList::Refusal;
	{
		IPList::RangeSet s;
		s.Finish();
		Check( IPList::CheckSanity( s ) == Refusal::Empty, "sanity: empty" );
	}
	{
		IPList::RangeSet s;
		s.AddV4( 0x00000000u, 0x7FFFFFFFu );
		s.Finish();
		Check( IPList::CheckSanity( s ) == Refusal::V4RangeTooWide, "sanity: 0.0.0.0-127.255.255.255" );
	}
	{
		IPList::RangeSet s;
		s.AddV4( 0x00000000u, 0x3FFFFFFFu );	// 0.0.0.0/2
		s.AddV4( 0x80000000u, 0xBFFFFFFFu );	// 128.0.0.0/2
		s.AddV4( 0xE0000000u, 0xFFFFFFFFu );	// 224.0.0.0/3
		s.Finish();
		Check( s.CountV4() == 3, "sanity: two /2s and a /3 stay apart" );
		Check( IPList::CheckSanity( s ) == Refusal::V4CoverageTooHigh, "sanity: two /2s plus a /3" );
	}
	{
		IPList::RangeSet s;
		s.AddV4( 0x00000000u, 0x3FFFFFFFu );
		s.AddV4( 0x80000000u, 0xBFFFFFFFu );
		s.Finish();
		Check( IPList::CheckSanity( s ) == Refusal::None, "sanity: two /2s are exactly half, accepted" );
	}
	{
		IPList::RangeSet s;
		s.AddV4( 0x20000000u, 0x3FFFFFFFu );	// 32.0.0.0/3
		s.Finish();
		Check( IPList::CheckSanity( s ) == Refusal::None, "sanity: a /3 alone" );
	}
	{
		IPList::RangeSet s;
		for ( uint32_t i = 0; i < IPList::kMaxRanges + 1; ++i )
			s.AddV4( i * 2, i * 2 );
		Check( s.Added() == IPList::kMaxRanges + 1, "sanity: every add counted" );
		Check( IPList::CheckSanity( s ) == Refusal::TooManyRanges, "sanity: kMaxRanges + 1" );
		s.Finish();
		Check( s.Overflowed(), "overflowed: flagged" );
		Check( IPList::CheckSanity( s ) == Refusal::TooManyRanges, "overflowed: refused once finished" );
		Check( ! s.ContainsV4( 0 ) && ! s.ContainsV4( 2 ), "overflowed: no lookups" );
		Check( IPList::Serialize( s ).empty(), "overflowed: does not serialize" );
	}
	{
		IPList::RangeSet s;
		for ( uint32_t i = 0; i < IPList::kMaxRanges; ++i )
			s.AddV4( i * 2, i * 2 );
		s.Finish();
		Check( IPList::CheckSanity( s ) == Refusal::None, "sanity: kMaxRanges exactly" );
		Check( ! s.Overflowed() && s.ContainsV4( 0 ), "sanity: kMaxRanges exactly is not overflowed" );
	}
	// The order when several apply: Empty, TooManyRanges, V4RangeTooWide,
	// V4CoverageTooHigh, V6CoversGlobalUnicast.
	{
		IPList::RangeSet s;
		s.AddV4( 0x00000000u, 0xFFFFFFFFu );	// too wide and too much coverage
		s.AddV6( A6( 0, 0, 0, 0, 0, 0, 0, 0 ), A6( 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff ) );
		s.Finish();
		Check( IPList::CheckSanity( s ) == Refusal::V4RangeTooWide, "sanity order: too wide first" );
	}
	{
		IPList::RangeSet s;
		s.AddV4( 0x00000000u, 0x3FFFFFFFu );
		s.AddV4( 0x80000000u, 0xBFFFFFFFu );
		s.AddV4( 0xE0000000u, 0xFFFFFFFFu );
		s.AddV6( A6( 0, 0, 0, 0, 0, 0, 0, 0 ), A6( 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff ) );
		s.Finish();
		Check( IPList::CheckSanity( s ) == Refusal::V4CoverageTooHigh, "sanity order: coverage before v6" );
	}
	{
		IPList::RangeSet s;
		s.AddV4( 0x00000000u, 0xFFFFFFFFu );
		for ( uint32_t i = 0; i < IPList::kMaxRanges; ++i )
			s.AddV4( 7, 7 );
		Check( IPList::CheckSanity( s ) == Refusal::TooManyRanges, "sanity order: too many before too wide" );
	}
	{
		IPList::RangeSet s;
		s.AddV6( A6( 0xfe80, 0, 0, 0, 0, 0, 0, 0 ), A6( 0xfe80, 0, 0, 0, 0, 0, 0, 1 ) );
		s.Finish();
		Check( IPList::CheckSanity( s ) == Refusal::Empty, "sanity: only dropped v6 is empty" );
	}
	Check( IPList::kMaxDownload == 64u * 1024 * 1024 && IPList::kMaxInflated == 256u * 1024 * 1024,
		"sanity: size limits" );
}

static IPList::RangeSet SampleSet()
{
	IPList::RangeSet s;
	s.AddV4( 0x01020304u, 0x01020310u );
	s.AddV4( 0x0A000000u, 0x0A0000FFu );
	s.AddV4( 0xFFFFFFF0u, 0xFFFFFFFFu );
	s.AddV6( A6( 0x2001, 0xdb8, 0, 0, 0, 0, 0, 0 ), A6( 0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff ) );
	s.AddV6( A6( 0x3fff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0 ),
		A6( 0x3fff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff ) );
	s.Finish();
	return s;
}

static void TestRoundTrip()
{
	const IPList::RangeSet s = SampleSet();
	const std::vector< uint8_t > pData = IPList::Serialize( s );
	Check( pData.size() == 16u + 3u * 8u + 2u * 32u + 4u, "round trip: size" );
	Check( pData.size() >= 16 && std::memcmp( pData.data(), "SZIL", 4 ) == 0
		&& pData[ 4 ] == 1 && pData[ 5 ] == 0 && pData[ 8 ] == 3 && pData[ 12 ] == 2,
		"round trip: header little-endian" );
	// The first IPv4 range, 1.2.3.4, little-endian.
	Check( pData.size() >= 20 && pData[ 16 ] == 4 && pData[ 17 ] == 3 && pData[ 18 ] == 2 && pData[ 19 ] == 1,
		"round trip: range little-endian" );

	IPList::RangeSet t;
	t.AddV4( 99, 99 );		// replaced by the load
	Check( IPList::Deserialize( pData.data(), pData.size(), t ), "round trip: deserialize" );
	Check( t.CountV4() == 3 && t.CountV6() == 2 && t.Added() == 5, "round trip: counts" );
	const uint32_t pV4[] = { 0x01020303u, 0x01020304u, 0x01020310u, 0x01020311u, 0x0A000080u,
		0x0A000100u, 0xFFFFFFEFu, 0xFFFFFFF0u, 0xFFFFFFFFu, 99 };
	bool bSame = true;
	for ( uint32_t a : pV4 )
		if ( s.ContainsV4( a ) != t.ContainsV4( a ) ) bSame = false;
	const IPList::Addr6 pV6[] = {
		A6( 0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x80 ), A6( 0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x100 ),
		A6( 0x3fff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff ),
		A6( 0x3fff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xfffe, 0xffff ),
	};
	for ( const IPList::Addr6& a : pV6 )
		if ( s.ContainsV6( a ) != t.ContainsV6( a ) ) bSame = false;
	Check( bSame, "round trip: same lookups" );
	Check( IPList::Serialize( t ) == pData, "round trip: serializes identically" );

	IPList::RangeSet g;
	g.AddV4( 1, 2 );
	Check( IPList::Serialize( g ).empty(), "unfinished set does not serialize" );

	IPList::RangeSet e;
	e.Finish();
	const std::vector< uint8_t > pEmpty = IPList::Serialize( e );
	IPList::RangeSet f;
	Check( pEmpty.size() == 20 && IPList::Deserialize( pEmpty.data(), pEmpty.size(), f )
		&& f.Added() == 0, "round trip: empty set" );
}

static void TestDeserializeRejectsTruncation()
{
	const IPList::RangeSet s = SampleSet();
	const std::vector< uint8_t > pData = IPList::Serialize( s );

	bool bAllRejected = true;
	for ( size_t n = 0; n < pData.size(); ++n )
	{
		IPList::RangeSet t;
		if ( IPList::Deserialize( pData.data(), n, t ) ) bAllRejected = false;
	}
	Check( bAllRejected, "deserialize rejects truncation: every prefix" );
	{
		IPList::RangeSet t;
		Check( ! IPList::Deserialize( nullptr, 0, t ), "deserialize rejects truncation: null" );
	}

	bool bFlipRejected = true;
	for ( size_t i = 0; i < pData.size(); ++i )
	{
		std::vector< uint8_t > pBad = pData;
		pBad[ i ] ^= 0x01;
		IPList::RangeSet t;
		if ( IPList::Deserialize( pBad.data(), pBad.size(), t ) ) bFlipRejected = false;
	}
	Check( bFlipRejected, "deserialize rejects truncation: one flipped byte" );

	std::vector< uint8_t > pLong = pData;
	pLong.push_back( 0 );
	IPList::RangeSet t;
	Check( ! IPList::Deserialize( pLong.data(), pLong.size(), t ), "deserialize rejects trailing bytes" );

	// A failed load leaves the target untouched.
	IPList::RangeSet u;
	u.AddV4( 5, 5 );
	u.Finish();
	IPList::Deserialize( pData.data(), pData.size() - 1, u );
	Check( u.ContainsV4( 5 ) && u.CountV4() == 1, "deserialize failure keeps the target" );

	// Counts that would overflow a 32-bit size: header claims 0xFFFFFFFF ranges.
	std::vector< uint8_t > pHuge = pData;
	pHuge[ 8 ] = pHuge[ 9 ] = pHuge[ 10 ] = pHuge[ 11 ] = 0xff;
	Check( ! IPList::Deserialize( pHuge.data(), pHuge.size(), t ), "deserialize rejects huge counts" );

	Check( IPList::Crc32( reinterpret_cast< const uint8_t* >( "123456789" ), 9 ) == 0xCBF43926u,
		"crc-32 check value" );
}

// Overwrites bytes of a serialized buffer and recomputes its trailing CRC, so only
// the structural checks can reject it.
static std::vector< uint8_t > Patch( const std::vector< uint8_t >& pData, size_t nOffset,
	const std::vector< uint8_t >& pBytes )
{
	std::vector< uint8_t > p = pData;
	for ( size_t i = 0; i < pBytes.size(); ++i )
		p[ nOffset + i ] = pBytes[ i ];
	const size_t n = p.size() - 4;
	const uint32_t nCRC = IPList::Crc32( p.data(), n );
	for ( size_t i = 0; i < 4; ++i )
		p[ n + i ] = uint8_t( nCRC >> ( 8 * i ) );
	return p;
}

static std::vector< uint8_t > LE( uint32_t n )
{
	return std::vector< uint8_t >{ uint8_t( n ), uint8_t( n >> 8 ), uint8_t( n >> 16 ), uint8_t( n >> 24 ) };
}

static void CheckRejected( const std::vector< uint8_t >& pBad, const char* pszName )
{
	IPList::RangeSet t;
	t.AddV4( 5, 5 );
	t.Finish();
	const bool bLoaded = IPList::Deserialize( pBad.data(), pBad.size(), t );
	Check( ! bLoaded, pszName );
	Check( t.Added() == 1 && t.CountV4() == 1 && t.CountV6() == 0 && t.ContainsV4( 5 ) && ! t.ContainsV4( 0x01020304u ),
		pszName );
}

static void TestDeserializeRejectsBadRanges()
{
	// SampleSet layout: header 16 bytes; IPv4 ranges at 16, 24, 32 (first, last);
	// IPv6 ranges at 40 and 72 (first 16 bytes, last 16 bytes); CRC at 104.
	const std::vector< uint8_t > pData = IPList::Serialize( SampleSet() );
	Check( pData.size() == 108, "bad ranges: sample layout" );
	if ( pData.size() != 108 ) return;

	{
		IPList::RangeSet t;
		const std::vector< uint8_t > pSame = Patch( pData, 16, LE( 0x01020304u ) );
		Check( IPList::Deserialize( pSame.data(), pSame.size(), t ) && t.ContainsV4( 0x01020304u ),
			"bad ranges: an unchanged patch still loads" );
	}

	std::vector< uint8_t > pReversed = LE( 0x01020310u );
	const std::vector< uint8_t > pLast = LE( 0x01020304u );
	pReversed.insert( pReversed.end(), pLast.begin(), pLast.end() );
	CheckRejected( Patch( pData, 16, pReversed ), "bad ranges: reversed v4" );
	CheckRejected( Patch( pData, 24, LE( 0x01020310u ) ), "bad ranges: overlapping v4" );
	CheckRejected( Patch( pData, 24, LE( 0x01020311u ) ), "bad ranges: adjacent v4" );

	std::vector< uint8_t > pSwapped( pData.begin() + 24, pData.begin() + 32 );
	pSwapped.insert( pSwapped.end(), pData.begin() + 16, pData.begin() + 24 );
	CheckRejected( Patch( pData, 16, pSwapped ), "bad ranges: unsorted v4" );

	CheckRejected( Patch( pData, 40, std::vector< uint8_t >{ 0x1f, 0xff } ), "bad ranges: v6 first below 2000::/3" );
	CheckRejected( Patch( pData, 72 + 16, std::vector< uint8_t >{ 0x40, 0x00 } ), "bad ranges: v6 last above 2000::/3" );
}

static void TestIsDue()
{
	using IPList::IsDue;
	const uint32_t tStart = 1000000;
	// Never attempted: due once the start delay has passed, not before.
	Check( ! IsDue( tStart, tStart, 0, 0, false ), "IsDue: not at start" );
	Check( ! IsDue( tStart + IPList::kStartDelay - 1, tStart, 0, 0, false ), "IsDue: start delay" );
	Check( IsDue( tStart + IPList::kStartDelay, tStart, 0, 0, false ), "IsDue: never attempted after delay" );

	// Success: due 24 h later.
	const uint32_t tOK = tStart - 3600;
	Check( ! IsDue( tOK + IPList::kDaily - 1, tStart, tOK, tOK, false ), "IsDue: before 24 h" );
	Check( IsDue( tOK + IPList::kDaily, tStart, tOK, tOK, false ), "IsDue: 24 h after success" );
	// Even an old success waits for the start delay.
	Check( ! IsDue( tStart + 10, tStart, tOK - IPList::kDaily * 5, tOK - IPList::kDaily * 5, false ),
		"IsDue: overdue list waits for start delay" );

	// Failure: due 6 h after the failed attempt, whatever the last success.
	const uint32_t tFail = tStart + 600;
	Check( ! IsDue( tFail + IPList::kRetry - 1, tStart, tOK, tFail, true ), "IsDue: before 6 h retry" );
	Check( IsDue( tFail + IPList::kRetry, tStart, tOK, tFail, true ), "IsDue: 6 h after failure" );
	Check( ! IsDue( tFail + IPList::kRetry - 1, tStart, 0, tFail, true ), "IsDue: never succeeded, failed" );
	Check( IsDue( tFail + IPList::kRetry, tStart, 0, tFail, true ), "IsDue: never succeeded, retry" );

	Check( IPList::kDaily == 86400 && IPList::kRetry == 21600 && IPList::kStartDelay == 120,
		"IsDue: constants" );
}

int main()
{
	TestMergeAgreesWithBruteForce();
	TestAdjacentRangesMerge();
	TestTopOfAddressSpace();
	TestV6OutsideDropped();
	TestSanity();
	TestRoundTrip();
	TestDeserializeRejectsTruncation();
	TestDeserializeRejectsBadRanges();
	TestIsDue();

	if ( g_nFailed == 0 )
		std::printf( "range set: all tests passed\n" );
	return g_nFailed ? 1 : 0;
}
