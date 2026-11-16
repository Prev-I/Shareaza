//
// IPRangeSet.h
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

// The address ranges of one downloaded IP block list: a sorted, merged set with
// binary-search lookups, the sanity limits a list must pass before it replaces
// the previous copy, the binary cache format (<guid>.bin) and the update schedule.
//
// Exemption of local and reserved addresses (ReservedAddresses.h) is applied by
// the caller at match time, not here.
//
// Header-only and free of MFC, so tests/ip-lists/ can build it with any compiler.

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

namespace IPList
{

// Limits for one list.
const size_t   kMaxRanges   = 2000000;		// ranges added, before merging
const uint32_t kMaxDownload = 64u << 20;	// bytes downloaded
const uint32_t kMaxInflated = 256u << 20;	// bytes after decompression

// Update schedule, in seconds.
const uint32_t kDaily      = 86400;		// after a successful update
const uint32_t kRetry      = 21600;		// after a failed attempt
const uint32_t kStartDelay = 120;		// nothing is fetched sooner after start

// An IPv6 address in network byte order.
struct Addr6
{
	uint8_t b[ 16 ];
};

inline bool operator<(const Addr6& x, const Addr6& y)
{
	return std::memcmp( x.b, y.b, sizeof( x.b ) ) < 0;
}

inline bool operator==(const Addr6& x, const Addr6& y)
{
	return std::memcmp( x.b, y.b, sizeof( x.b ) ) == 0;
}

// Adds one to a; returns false if it wrapped past ffff:...:ffff.
inline bool Increment(Addr6& a)
{
	for ( int i = 15; i >= 0; --i )
	{
		a.b[ i ] = static_cast< uint8_t >( a.b[ i ] + 1 );
		if ( a.b[ i ] != 0 )
			return true;
	}
	return false;
}

// 2000::/3, the global unicast space: the only IPv6 space a list may cover.
inline Addr6 GlobalUnicastFirst()
{
	Addr6 a = {};
	a.b[ 0 ] = 0x20;
	return a;
}

inline Addr6 GlobalUnicastLast()
{
	Addr6 a;
	std::memset( a.b, 0xff, sizeof( a.b ) );
	a.b[ 0 ] = 0x3f;
	return a;
}

struct RangeV4
{
	uint32_t first;		// host byte order, inclusive
	uint32_t last;
};

struct RangeV6
{
	Addr6 first;		// inclusive
	Addr6 last;
};

class RangeSet;
inline bool Deserialize(const uint8_t* p, size_t n, RangeSet& out);

class RangeSet
{
public:
	RangeSet() : m_nAdded( 0 ), m_bFinished( true ) {}

	// Bounds may come in either order. Once more than kMaxRanges ranges have been
	// added, further ranges are counted but not stored: CheckSanity refuses such a
	// set anyway, and an oversized list cannot grow the set without bound.
	void AddV4(uint32_t first, uint32_t last)
	{
		if ( first > last )
			std::swap( first, last );
		if ( Count() )
		{
			RangeV4 r = { first, last };
			m_pV4.push_back( r );
		}
		m_bFinished = false;
	}

	// Clipped to 2000::/3; a range wholly outside it is dropped and not counted.
	void AddV6(const Addr6& first, const Addr6& last)
	{
		RangeV6 r = { first, last };
		if ( r.last < r.first )
			std::swap( r.first, r.last );
		const Addr6 aLow = GlobalUnicastFirst(), aHigh = GlobalUnicastLast();
		if ( r.last < aLow || aHigh < r.first )
			return;
		if ( r.first < aLow )
			r.first = aLow;
		if ( aHigh < r.last )
			r.last = aHigh;
		if ( Count() )
			m_pV6.push_back( r );
		m_bFinished = false;
	}

	// Sorts and merges overlapping and adjacent ranges. Lookups need it.
	void Finish()
	{
		if ( m_bFinished )
			return;

		std::sort( m_pV4.begin(), m_pV4.end(), [] (const RangeV4& x, const RangeV4& y)
			{ return x.first < y.first || ( x.first == y.first && x.last < y.last ); } );
		size_t nOut = 0;
		for ( size_t i = 0; i < m_pV4.size(); ++i )
		{
			const RangeV4& r = m_pV4[ i ];
			// 64-bit, so a range ending at 255.255.255.255 does not wrap to 0.
			if ( nOut && uint64_t( r.first ) <= uint64_t( m_pV4[ nOut - 1 ].last ) + 1 )
				m_pV4[ nOut - 1 ].last = std::max( m_pV4[ nOut - 1 ].last, r.last );
			else
				m_pV4[ nOut++ ] = r;
		}
		m_pV4.resize( nOut );

		std::sort( m_pV6.begin(), m_pV6.end(), [] (const RangeV6& x, const RangeV6& y)
			{ return x.first < y.first || ( x.first == y.first && x.last < y.last ); } );
		nOut = 0;
		for ( size_t i = 0; i < m_pV6.size(); ++i )
		{
			const RangeV6& r = m_pV6[ i ];
			if ( nOut && Touches( m_pV6[ nOut - 1 ].last, r.first ) )
			{
				if ( m_pV6[ nOut - 1 ].last < r.last )
					m_pV6[ nOut - 1 ].last = r.last;
			}
			else
				m_pV6[ nOut++ ] = r;
		}
		m_pV6.resize( nOut );

		m_bFinished = true;
	}

	// False until Finish has been called after the last Add.
	bool ContainsV4(uint32_t a) const
	{
		if ( ! m_bFinished )
			return false;
		auto it = std::upper_bound( m_pV4.begin(), m_pV4.end(), a,
			[] (uint32_t v, const RangeV4& r) { return v < r.first; } );
		if ( it == m_pV4.begin() )
			return false;
		--it;
		return a <= it->last;
	}

	bool ContainsV6(const Addr6& a) const
	{
		if ( ! m_bFinished )
			return false;
		auto it = std::upper_bound( m_pV6.begin(), m_pV6.end(), a,
			[] (const Addr6& v, const RangeV6& r) { return v < r.first; } );
		if ( it == m_pV6.begin() )
			return false;
		--it;
		return ! ( it->last < a );
	}

	// Ranges stored: after Finish, the merged ranges.
	size_t CountV4() const { return m_pV4.size(); }
	size_t CountV6() const { return m_pV6.size(); }

	// Ranges added since construction, before merging (IPv6 ranges dropped
	// wholly outside 2000::/3 are not counted).
	size_t Added() const { return m_nAdded; }

	bool IsFinished() const { return m_bFinished; }
	const std::vector< RangeV4 >& RangesV4() const { return m_pV4; }
	const std::vector< RangeV6 >& RangesV6() const { return m_pV6; }

private:
	std::vector< RangeV4 > m_pV4;
	std::vector< RangeV6 > m_pV6;
	size_t m_nAdded;
	bool   m_bFinished;

	// Counts one added range; true if it is to be stored.
	bool Count()
	{
		return ++m_nAdded <= kMaxRanges;
	}

	// True if a range starting at next overlaps or adjoins one ending at last,
	// given last's range starts no later than next.
	static bool Touches(const Addr6& last, const Addr6& next)
	{
		if ( ! ( last < next ) )
			return true;
		Addr6 a = last;
		return Increment( a ) && a == next;
	}

	friend bool Deserialize(const uint8_t* p, size_t n, RangeSet& out);
};

enum class Refusal
{
	None,
	Empty,					// no range
	TooManyRanges,			// more than kMaxRanges added
	V4RangeTooWide,			// one IPv4 range spans 2^31 addresses or more
	V4CoverageTooHigh,		// the IPv4 ranges cover more than 2^31 addresses
	V6CoversGlobalUnicast	// one IPv6 range contains all of 2000::/3
};

// Checked in the order of the enum; the first that applies is returned.
// The width and coverage checks look at the merged ranges (the set is finished
// on a copy if need be): pieces that merge into one absurd range, such as two
// halves of 2000::/3, are as absurd as that range given whole.
inline Refusal CheckSanity(const RangeSet& s)
{
	if ( s.Added() == 0 )
		return Refusal::Empty;
	if ( s.Added() > kMaxRanges )
		return Refusal::TooManyRanges;

	if ( ! s.IsFinished() )
	{
		RangeSet t( s );
		t.Finish();
		return CheckSanity( t );
	}

	const uint64_t nHalf = uint64_t( 1 ) << 31;
	uint64_t nCoverage = 0;
	for ( const RangeV4& r : s.RangesV4() )
	{
		const uint64_t nSpan = uint64_t( r.last ) - r.first + 1;
		if ( nSpan >= nHalf )
			return Refusal::V4RangeTooWide;
		nCoverage += nSpan;
	}
	if ( nCoverage > nHalf )
		return Refusal::V4CoverageTooHigh;

	// Ranges are clipped to 2000::/3, so only an exact match contains all of it.
	const Addr6 aLow = GlobalUnicastFirst(), aHigh = GlobalUnicastLast();
	for ( const RangeV6& r : s.RangesV6() )
		if ( r.first == aLow && r.last == aHigh )
			return Refusal::V6CoversGlobalUnicast;

	return Refusal::None;
}

// Standard CRC-32 (reflected polynomial 0xEDB88320), as in zip and PNG.
inline uint32_t Crc32(const uint8_t* p, size_t n)
{
	uint32_t nCRC = 0xFFFFFFFFu;
	for ( size_t i = 0; i < n; ++i )
	{
		nCRC ^= p[ i ];
		for ( int k = 0; k < 8; ++k )
			nCRC = ( nCRC & 1 ) ? ( ( nCRC >> 1 ) ^ 0xEDB88320u ) : ( nCRC >> 1 );
	}
	return nCRC ^ 0xFFFFFFFFu;
}

inline void PutU32(std::vector< uint8_t >& p, uint32_t n)
{
	p.push_back( static_cast< uint8_t >( n ) );
	p.push_back( static_cast< uint8_t >( n >> 8 ) );
	p.push_back( static_cast< uint8_t >( n >> 16 ) );
	p.push_back( static_cast< uint8_t >( n >> 24 ) );
}

inline uint32_t GetU32(const uint8_t* p)
{
	return uint32_t( p[ 0 ] ) | ( uint32_t( p[ 1 ] ) << 8 )
		| ( uint32_t( p[ 2 ] ) << 16 ) | ( uint32_t( p[ 3 ] ) << 24 );
}

// Cache format, every integer little-endian:
//   "SZIL", uint32 version (1), uint32 IPv4 count, uint32 IPv6 count,
//   IPv4 ranges (uint32 first, uint32 last), IPv6 ranges (16 + 16 bytes,
//   network byte order), uint32 CRC-32 of everything before it.
// The merged ranges are written; an unfinished set is finished on a copy.
inline std::vector< uint8_t > Serialize(const RangeSet& s)
{
	if ( ! s.IsFinished() )
	{
		RangeSet t( s );
		t.Finish();
		return Serialize( t );
	}

	std::vector< uint8_t > p;
	p.reserve( 20 + s.CountV4() * 8 + s.CountV6() * 32 );
	p.push_back( 'S' );
	p.push_back( 'Z' );
	p.push_back( 'I' );
	p.push_back( 'L' );
	PutU32( p, 1 );
	PutU32( p, static_cast< uint32_t >( s.CountV4() ) );
	PutU32( p, static_cast< uint32_t >( s.CountV6() ) );
	for ( const RangeV4& r : s.RangesV4() )
	{
		PutU32( p, r.first );
		PutU32( p, r.last );
	}
	for ( const RangeV6& r : s.RangesV6() )
	{
		p.insert( p.end(), r.first.b, r.first.b + 16 );
		p.insert( p.end(), r.last.b, r.last.b + 16 );
	}
	PutU32( p, Crc32( p.data(), p.size() ) );
	return p;
}

// Returns false, leaving out untouched, on any size, magic, version or CRC
// mismatch, and on ranges Serialize could not have written (unsorted, overlapping,
// adjacent, reversed, IPv6 outside 2000::/3, more than kMaxRanges).
inline bool Deserialize(const uint8_t* p, size_t n, RangeSet& out)
{
	if ( p == nullptr || n < 20 )
		return false;
	if ( std::memcmp( p, "SZIL", 4 ) != 0 || GetU32( p + 4 ) != 1 )
		return false;
	const uint32_t nV4 = GetU32( p + 8 ), nV6 = GetU32( p + 12 );
	// 64-bit, so a forged count cannot wrap the expected size on x86.
	const uint64_t nExpected = 20 + uint64_t( nV4 ) * 8 + uint64_t( nV6 ) * 32;
	if ( nExpected != uint64_t( n ) )
		return false;
	if ( Crc32( p, n - 4 ) != GetU32( p + n - 4 ) )
		return false;
	if ( uint64_t( nV4 ) + nV6 > kMaxRanges )
		return false;

	RangeSet s;
	const uint8_t* q = p + 16;
	s.m_pV4.reserve( nV4 );
	for ( uint32_t i = 0; i < nV4; ++i, q += 8 )
	{
		const RangeV4 r = { GetU32( q ), GetU32( q + 4 ) };
		if ( r.first > r.last )
			return false;
		if ( i && uint64_t( r.first ) <= uint64_t( s.m_pV4.back().last ) + 1 )
			return false;
		s.m_pV4.push_back( r );
	}
	const Addr6 aLow = GlobalUnicastFirst(), aHigh = GlobalUnicastLast();
	s.m_pV6.reserve( nV6 );
	for ( uint32_t i = 0; i < nV6; ++i, q += 32 )
	{
		RangeV6 r;
		std::memcpy( r.first.b, q, 16 );
		std::memcpy( r.last.b, q + 16, 16 );
		if ( r.last < r.first || r.first < aLow || aHigh < r.last )
			return false;
		if ( i && RangeSet::Touches( s.m_pV6.back().last, r.first ) )
			return false;
		s.m_pV6.push_back( r );
	}
	s.m_nAdded = size_t( nV4 ) + nV6;
	s.m_bFinished = true;

	std::swap( out, s );
	return true;
}

// True when a list should be fetched now. Times are seconds on one clock.
// Nothing is due within kStartDelay of start; after a failed attempt the list is
// due kRetry after it, otherwise kDaily after its last success (at once if it
// never had one). Differences are unsigned: a clock set back makes a list due
// rather than stalling it.
inline bool IsDue(uint32_t tNow, uint32_t tStarted, uint32_t tLastSuccess,
	uint32_t tLastAttempt, bool bLastFailed)
{
	if ( tNow - tStarted < kStartDelay )
		return false;
	if ( bLastFailed )
		return tNow - tLastAttempt >= kRetry;
	if ( tLastSuccess == 0 )
		return true;
	return tNow - tLastSuccess >= kDaily;
}

} // namespace IPList
