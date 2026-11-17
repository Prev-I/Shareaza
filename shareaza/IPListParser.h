//
// IPListParser.h
//
// Copyright (c) Shareaza Development Team, 2026.
// This file is part of SHAREAZA (shareaza.sourceforge.net)
//
// Shareaza is free software; you can redistribute it
// and/or modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// Shareaza is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Shareaza; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
//

// Reads the text of one IP block list into a RangeSet. The format is detected per
// line, never from a file name: eMule-Security's guarding.p2p holds eMule lines.
//
// Each line, after a leading UTF-8 BOM and surrounding whitespace (space, tab,
// CR, VT, FF) are stripped, is tried in this order:
//
//   blank, or starting #, ; or //             skipped
//   {...}            Spamhaus DROP JSON line: the "cidr" string value is taken
//                    (IPv4 or IPv6 CIDR); a line without "cidr" is metadata and
//                    skipped
//   a.b.c.d - e.f.g.h , level [, description]
//                    eMule ipfilter.dat: level < 127 is taken, level >= 127 is
//                    counted in allowedByLevel and adds nothing. Detected before
//                    PeerGuardian, as a description may hold ':'.
//   description:a.b.c.d-e.f.g.h
//                    PeerGuardian .p2p, split at the last ':' (the description
//                    may hold ':' and '-')
//   a.b.c.d[-e.f.g.h][:comment]
//                    Gnucleus, read as a true range
//   a.b.c.d/n, x:y::z/n, x:y::z
//                    CIDR, single IPv4 (also matched by the Gnucleus rule) or
//                    single IPv6. A prefix with host bits set (10.1.2.3/8) is
//                    taken as its containing network (10.0.0.0/8).
//
// Anything else is rejected. Dotted quads take one to three decimal digits per
// octet, leading zeros included (001.002.003.004); an octet above 255, a prefix
// above 32 or 128, or trailing text is rejected. IPv6 follows RFC 4291 text form,
// with '::' and an embedded IPv4 tail; it is passed to RangeSet::AddV6 unclipped,
// which drops what lies outside 2000::/3. Such a line still counts as taken here.
//
// Work is linear in the input: every rule scans a line a bounded number of times.
// Nothing throws on bad input and no locale-dependent function is used.
//
// Header-only and free of MFC, so tests/ip-lists/ can build it with any compiler.

#pragma once

#include "IPRangeSet.h"

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace IPList
{

// Line counts; ParseText adds to them, so one ParseStats can span several calls.
struct ParseStats
{
	size_t taken = 0;			// lines that produced a range
	size_t rejected = 0;		// lines in no known format
	size_t skipped = 0;			// blank, comment and JSON metadata lines
	size_t allowedByLevel = 0;	// eMule lines with level >= 127
};

namespace Detail
{

inline bool IsSpace(char c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f';
}

inline bool IsDigit(char c)
{
	return c >= '0' && c <= '9';
}

// Value of a hex digit, or -1.
inline int HexValue(char c)
{
	if ( c >= '0' && c <= '9' )
		return c - '0';
	if ( c >= 'a' && c <= 'f' )
		return c - 'a' + 10;
	if ( c >= 'A' && c <= 'F' )
		return c - 'A' + 10;
	return -1;
}

inline const char* SkipSpace(const char* p, const char* end)
{
	while ( p < end && IsSpace( *p ) )
		++p;
	return p;
}

// One to nDigits decimal digits, no sign; true if the value is at most nMax.
inline bool ParseNumber(const char*& p, const char* end, int nDigits, uint32_t nMax, uint32_t& n)
{
	const char* q = p;
	uint32_t v = 0;
	while ( q < end && IsDigit( *q ) && q - p < nDigits )
		v = v * 10 + static_cast< uint32_t >( *q++ - '0' );
	if ( q == p || ( q < end && IsDigit( *q ) ) || v > nMax )
		return false;
	n = v;
	p = q;
	return true;
}

// a.b.c.d, host byte order. Advances p past it on success.
inline bool ParseQuad(const char*& p, const char* end, uint32_t& nAddress)
{
	const char* q = p;
	uint32_t v = 0;
	for ( int i = 0; i < 4; ++i )
	{
		if ( i > 0 )
		{
			if ( q >= end || *q != '.' )
				return false;
			++q;
		}
		uint32_t nOctet;
		if ( ! ParseNumber( q, end, 3, 255, nOctet ) )
			return false;
		v = ( v << 8 ) | nOctet;
	}
	nAddress = v;
	p = q;
	return true;
}

// The whole of [p, end) as RFC 4291 IPv6 text: eight groups of one to four hex
// digits, at most one '::' standing for one or more zero groups, and optionally
// a dotted-quad tail standing for the last two groups.
inline bool ParseV6(const char* p, const char* end, Addr6& a)
{
	uint16_t nGroup[ 8 ] = {};
	int nCount = 0;
	int nGap = -1;		// group index where '::' stands

	if ( end - p >= 2 && p[ 0 ] == ':' && p[ 1 ] == ':' )
	{
		nGap = 0;
		p += 2;
	}
	while ( p < end )
	{
		if ( nCount == 8 )
			return false;

		// An embedded IPv4 tail: digits then '.' before any ':'.
		const char* q = p;
		while ( q < end && HexValue( *q ) >= 0 )
			++q;
		if ( q < end && *q == '.' )
		{
			uint32_t nV4 = 0;
			if ( nCount > 6 || ! ParseQuad( p, end, nV4 ) || p != end )
				return false;
			nGroup[ nCount++ ] = static_cast< uint16_t >( nV4 >> 16 );
			nGroup[ nCount++ ] = static_cast< uint16_t >( nV4 & 0xffff );
			break;
		}

		if ( q == p || q - p > 4 )
			return false;
		uint32_t v = 0;
		for ( ; p < q; ++p )
			v = ( v << 4 ) | static_cast< uint32_t >( HexValue( *p ) );
		nGroup[ nCount++ ] = static_cast< uint16_t >( v );

		if ( p == end )
			break;
		if ( *p != ':' )
			return false;
		++p;
		if ( p < end && *p == ':' )
		{
			if ( nGap >= 0 )
				return false;
			nGap = nCount;
			++p;
		}
		else if ( p == end )
		{
			return false;		// a single trailing ':'
		}
	}

	if ( nGap < 0 ? nCount != 8 : nCount > 7 )
		return false;

	uint16_t nFull[ 8 ] = {};
	if ( nGap < 0 )
	{
		for ( int i = 0; i < 8; ++i )
			nFull[ i ] = nGroup[ i ];
	}
	else
	{
		for ( int i = 0; i < nGap; ++i )
			nFull[ i ] = nGroup[ i ];
		const int nTail = nCount - nGap;
		for ( int i = 0; i < nTail; ++i )
			nFull[ 8 - nTail + i ] = nGroup[ nGap + i ];
	}
	for ( int i = 0; i < 8; ++i )
	{
		a.b[ i * 2 ] = static_cast< uint8_t >( nFull[ i ] >> 8 );
		a.b[ i * 2 + 1 ] = static_cast< uint8_t >( nFull[ i ] & 0xff );
	}
	return true;
}

// The whole of [p, end) as a.b.c.d/n, an IPv6 address, or an IPv6 address /n.
// A bare IPv4 address is not accepted here; the Gnucleus rule takes it. Host
// bits below the prefix are cleared: the line stands for its containing network.
inline bool ParseCidr(const char* p, const char* end, RangeSet& out)
{
	const char* pSlash = static_cast< const char* >(
		std::memchr( p, '/', static_cast< size_t >( end - p ) ) );
	const char* pAddrEnd = pSlash ? pSlash : end;

	uint32_t nPrefix = 0;
	uint32_t nV4 = 0;
	const char* q = p;
	if ( ParseQuad( q, end, nV4 ) )
	{
		if ( q != pSlash )
			return false;
		++q;
		if ( ! ParseNumber( q, end, 3, 32, nPrefix ) || q != end )
			return false;
		const uint32_t nMask = nPrefix == 0 ? 0 : ( 0xffffffffu << ( 32 - nPrefix ) );
		out.AddV4( nV4 & nMask, ( nV4 & nMask ) | ~nMask );
		return true;
	}

	Addr6 a;
	if ( ! ParseV6( p, pAddrEnd, a ) )
		return false;
	nPrefix = 128;
	if ( pSlash )
	{
		q = pSlash + 1;
		if ( ! ParseNumber( q, end, 3, 128, nPrefix ) || q != end )
			return false;
	}
	Addr6 aLast = a;
	for ( uint32_t i = 0; i < 16; ++i )
	{
		const uint32_t nBits = nPrefix > i * 8 ? nPrefix - i * 8 : 0;
		const uint8_t nMask = static_cast< uint8_t >( nBits >= 8 ? 0xffu : 0xff00u >> nBits );
		a.b[ i ] = static_cast< uint8_t >( a.b[ i ] & nMask );
		aLast.b[ i ] = static_cast< uint8_t >( a.b[ i ] | static_cast< uint8_t >( ~nMask ) );
	}
	out.AddV6( a, aLast );
	return true;
}

// a.b.c.d WS* - WS* e.f.g.h, advancing p past it.
inline bool ParseDashRange(const char*& p, const char* end, uint32_t& nFirst, uint32_t& nLast)
{
	const char* q = p;
	if ( ! ParseQuad( q, end, nFirst ) )
		return false;
	q = SkipSpace( q, end );
	if ( q >= end || *q != '-' )
		return false;
	q = SkipSpace( q + 1, end );
	if ( ! ParseQuad( q, end, nLast ) )
		return false;
	p = q;
	return true;
}

enum class LineResult { NotThis, Taken, Allowed, Rejected };

// a.b.c.d - e.f.g.h , level [, description]
inline LineResult ParseEmule(const char* p, const char* end, RangeSet& out)
{
	uint32_t nFirst = 0, nLast = 0;
	if ( ! ParseDashRange( p, end, nFirst, nLast ) )
		return LineResult::NotThis;
	p = SkipSpace( p, end );
	if ( p >= end || *p != ',' )
		return LineResult::NotThis;

	// From here the line is eMule; a bad level rejects it. Longer levels are
	// read as 1000, which only has to compare as >= 127.
	p = SkipSpace( p + 1, end );
	uint32_t nLevel = 0;
	const char* q = p;
	while ( q < end && IsDigit( *q ) )
	{
		if ( nLevel < 1000 )
			nLevel = nLevel * 10 + static_cast< uint32_t >( *q - '0' );
		++q;
	}
	if ( q == p )
		return LineResult::Rejected;
	q = SkipSpace( q, end );
	if ( q < end && *q != ',' )
		return LineResult::Rejected;

	if ( nLevel >= 127 )
		return LineResult::Allowed;
	out.AddV4( nFirst, nLast );
	return LineResult::Taken;
}

// description:a.b.c.d-e.f.g.h, split at the last ':'.
inline bool ParsePeerGuardian(const char* p, const char* end, RangeSet& out)
{
	const char* pColon = end;
	while ( pColon > p && pColon[ -1 ] != ':' )
		--pColon;
	if ( pColon == p )
		return false;		// no ':'

	const char* q = SkipSpace( pColon, end );
	uint32_t nFirst = 0, nLast = 0;
	if ( ! ParseDashRange( q, end, nFirst, nLast ) || q != end )
		return false;
	out.AddV4( nFirst, nLast );
	return true;
}

// a.b.c.d[-e.f.g.h][:comment]
inline bool ParseGnucleus(const char* p, const char* end, RangeSet& out)
{
	uint32_t nFirst = 0, nLast = 0;
	const char* q = p;
	if ( ! ParseDashRange( q, end, nFirst, nLast ) )
	{
		q = p;
		if ( ! ParseQuad( q, end, nFirst ) )
			return false;
		nLast = nFirst;
	}
	q = SkipSpace( q, end );
	if ( q < end && *q != ':' )
		return false;
	out.AddV4( nFirst, nLast );
	return true;
}

// The value of "cidr" in a one-line JSON object. NotThis means no "cidr" key.
inline LineResult ParseJson(const char* p, const char* end, RangeSet& out)
{
	static const char szKey[] = "\"cidr\"";
	const size_t nKey = sizeof( szKey ) - 1;
	const char* pKey = nullptr;
	for ( const char* q = p; static_cast< size_t >( end - q ) >= nKey; ++q )
	{
		if ( std::memcmp( q, szKey, nKey ) == 0 )
		{
			pKey = q;
			break;
		}
	}
	if ( ! pKey )
		return LineResult::NotThis;

	const char* q = SkipSpace( pKey + nKey, end );
	if ( q >= end || *q != ':' )
		return LineResult::Rejected;
	q = SkipSpace( q + 1, end );
	if ( q >= end || *q != '"' )
		return LineResult::Rejected;
	++q;
	const char* pClose = static_cast< const char* >(
		std::memchr( q, '"', static_cast< size_t >( end - q ) ) );
	if ( ! pClose )
		return LineResult::Rejected;

	// A bare IPv4 address is a /32 here too.
	uint32_t nV4 = 0;
	const char* r = q;
	if ( ParseQuad( r, pClose, nV4 ) && r == pClose )
	{
		out.AddV4( nV4, nV4 );
		return LineResult::Taken;
	}
	return ParseCidr( q, pClose, out ) ? LineResult::Taken : LineResult::Rejected;
}

inline void ParseLine(const char* p, const char* end, RangeSet& out, ParseStats& stats)
{
	if ( end - p >= 3 && static_cast< unsigned char >( p[ 0 ] ) == 0xEF &&
		static_cast< unsigned char >( p[ 1 ] ) == 0xBB &&
		static_cast< unsigned char >( p[ 2 ] ) == 0xBF )
		p += 3;
	p = SkipSpace( p, end );
	while ( end > p && IsSpace( end[ -1 ] ) )
		--end;

	if ( p == end || *p == '#' || *p == ';' ||
		( end - p >= 2 && p[ 0 ] == '/' && p[ 1 ] == '/' ) )
	{
		++stats.skipped;
		return;
	}

	if ( *p == '{' )
	{
		switch ( ParseJson( p, end, out ) )
		{
		case LineResult::Taken:
			++stats.taken;
			break;
		case LineResult::NotThis:
			++stats.skipped;
			break;
		default:
			++stats.rejected;
			break;
		}
		return;
	}

	switch ( ParseEmule( p, end, out ) )
	{
	case LineResult::Taken:
		++stats.taken;
		return;
	case LineResult::Allowed:
		++stats.allowedByLevel;
		return;
	case LineResult::Rejected:
		++stats.rejected;
		return;
	default:
		break;
	}

	if ( ParsePeerGuardian( p, end, out ) || ParseGnucleus( p, end, out ) ||
		ParseCidr( p, end, out ) )
		++stats.taken;
	else
		++stats.rejected;
}

}	// namespace Detail

// Parses n bytes of list text into out, line by line, adding to stats. Lines end
// at '\n'; an empty piece after a final '\n' is not a line. Does not call Finish.
inline void ParseText(const char* p, size_t n, RangeSet& out, ParseStats& stats)
{
	const char* const end = p + n;
	while ( p < end )
	{
		const char* pEol = static_cast< const char* >(
			std::memchr( p, '\n', static_cast< size_t >( end - p ) ) );
		const char* pLineEnd = pEol ? pEol : end;
		Detail::ParseLine( p, pLineEnd, out, stats );
		p = pEol ? pEol + 1 : end;
	}
}

}	// namespace IPList
