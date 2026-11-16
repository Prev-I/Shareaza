//
// ReservedAddresses.h
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

// Reserved and local addresses, from the IANA IPv4 and IPv6 Special-Purpose
// Address Registries:
//   https://www.iana.org/assignments/iana-ipv4-special-registry/
//   https://www.iana.org/assignments/iana-ipv6-special-registry/
//
// Reserved = rows whose "Globally Reachable" is False, plus multicast,
// 240.0.0.0/4, 255.255.255.255 and the deprecated 192.88.99.0/24.
// A False row that contains globally reachable rows is not taken whole:
// 192.0.0.0/24 is reserved except its two True addresses, and of 2001::/23
// only the False sub-row 2001:2::/48 is. Rows marked N/A (Teredo 2001::/32,
// 6to4 2002::/16) are not reserved. Private-use and link-local rows are not
// reserved here either; IsLocalV4 / IsLocalV6 return them.
//
// Header-only and free of MFC, so tests/ip-lists/ can build it with any compiler.

#pragma once

#include <cstdint>

namespace Reserved
{

// "Last Updated" of both registries when the tables below were taken from them.
const char* const kRegistryDate = "2025-10-09";

struct RangeV4
{
	uint32_t nPrefix;	// host byte order
	uint8_t  nLength;
};

struct RangeV6
{
	uint64_t nHigh;		// first 8 bytes, big-endian
	uint64_t nLow;		// last 8 bytes, big-endian
	uint8_t  nLength;
};

// Top nLength bits set, nLength 0 to 64.
inline uint64_t Mask64(unsigned int nLength)
{
	return nLength == 0 ? 0 : ( ~0ull << ( 64 - nLength ) );
}

inline bool MatchV4(uint32_t nAddress, const RangeV4& r)
{
	const uint32_t nMask = r.nLength == 0 ? 0 : ( ~0u << ( 32 - r.nLength ) );
	return ( nAddress & nMask ) == r.nPrefix;
}

inline bool MatchV6(uint64_t nHigh, uint64_t nLow, const RangeV6& r)
{
	if ( r.nLength <= 64 )
		return ( nHigh & Mask64( r.nLength ) ) == r.nHigh;
	return nHigh == r.nHigh && ( nLow & Mask64( r.nLength - 64u ) ) == r.nLow;
}

template< unsigned int N >
inline bool InV4(uint32_t nAddress, const RangeV4 (&pTable)[N])
{
	for ( unsigned int i = 0; i < N; ++i )
		if ( MatchV4( nAddress, pTable[ i ] ) ) return true;
	return false;
}

template< unsigned int N >
inline bool InV6(const uint8_t (&a)[16], const RangeV6 (&pTable)[N])
{
	uint64_t nHigh = 0, nLow = 0;
	for ( int i = 0; i < 8; ++i )
	{
		nHigh = ( nHigh << 8 ) | a[ i ];
		nLow  = ( nLow  << 8 ) | a[ i + 8 ];
	}
	for ( unsigned int i = 0; i < N; ++i )
		if ( MatchV6( nHigh, nLow, pTable[ i ] ) ) return true;
	return false;
}

// The tables are function-local statics of inline functions, so every translation
// unit that includes this header shares one definition of each.

// nHostOrder: the address in host byte order (ntohl of IN_ADDR::s_addr).
inline bool IsReservedV4(uint32_t nHostOrder)
{
	static const RangeV4 kReservedV4[] =
	{
		{ 0x00000000u,  8 },	// 0.0.0.0/8         "This network", RFC 791
		{ 0x64400000u, 10 },	// 100.64.0.0/10     Shared Address Space, RFC 6598
		{ 0x7F000000u,  8 },	// 127.0.0.0/8       Loopback, RFC 1122
		{ 0xC0000000u, 24 },	// 192.0.0.0/24      IETF Protocol Assignments, RFC 6890 (minus kGlobalV4)
		{ 0xC0000200u, 24 },	// 192.0.2.0/24      Documentation (TEST-NET-1), RFC 5737
		{ 0xC0586300u, 24 },	// 192.88.99.0/24    Deprecated 6to4 Relay Anycast, RFC 7526 (kept: no peer has it)
		{ 0xC6120000u, 15 },	// 198.18.0.0/15     Benchmarking, RFC 2544
		{ 0xC6336400u, 24 },	// 198.51.100.0/24   Documentation (TEST-NET-2), RFC 5737
		{ 0xCB007100u, 24 },	// 203.0.113.0/24    Documentation (TEST-NET-3), RFC 5737
		{ 0xE0000000u,  4 },	// 224.0.0.0/4       Multicast, RFC 5771 (not a registry row)
		{ 0xF0000000u,  4 },	// 240.0.0.0/4       Reserved, RFC 1112
		{ 0xFFFFFFFFu, 32 },	// 255.255.255.255   Limited Broadcast, RFC 8190 (inside 240.0.0.0/4)
	};

	// Globally reachable rows inside a reserved row above.
	static const RangeV4 kGlobalV4[] =
	{
		{ 0xC0000009u, 32 },	// 192.0.0.9/32      Port Control Protocol Anycast, RFC 7723
		{ 0xC000000Au, 32 },	// 192.0.0.10/32     TURN Anycast, RFC 8155
	};

	return InV4( nHostOrder, kReservedV4 ) && ! InV4( nHostOrder, kGlobalV4 );
}

// a: the 16 address bytes in network order.
inline bool IsReservedV6(const uint8_t (&a)[16])
{
	static const RangeV6 kReservedV6[] =
	{
		{ 0x0000000000000000ull, 0x0000000000000000ull, 128 },	// ::/128            Unspecified, RFC 4291
		{ 0x0000000000000000ull, 0x0000000000000001ull, 128 },	// ::1/128           Loopback, RFC 4291
		{ 0x0000000000000000ull, 0x0000FFFF00000000ull,  96 },	// ::ffff:0:0/96     IPv4-mapped, RFC 4291
		{ 0x0064FF9B00010000ull, 0x0000000000000000ull,  48 },	// 64:ff9b:1::/48    IPv4-IPv6 Translation, RFC 8215
		{ 0x0100000000000000ull, 0x0000000000000000ull,  64 },	// 100::/64          Discard-Only, RFC 6666
		{ 0x0100000000000001ull, 0x0000000000000000ull,  64 },	// 100:0:0:1::/64    Dummy IPv6 Prefix, RFC 9780
		{ 0x2001000200000000ull, 0x0000000000000000ull,  48 },	// 2001:2::/48       Benchmarking, RFC 5180 (the only False row in 2001::/23)
		{ 0x20010DB800000000ull, 0x0000000000000000ull,  32 },	// 2001:db8::/32     Documentation, RFC 3849
		{ 0x3FFF000000000000ull, 0x0000000000000000ull,  20 },	// 3fff::/20         Documentation, RFC 9637
		{ 0x5F00000000000000ull, 0x0000000000000000ull,  16 },	// 5f00::/16         Segment Routing (SRv6) SIDs, RFC 9602
		{ 0xFF00000000000000ull, 0x0000000000000000ull,   8 },	// ff00::/8          Multicast, RFC 4291 (not a registry row)
	};

	return InV6( a, kReservedV6 );
}

// Loopback, private-use and link-local.
inline bool IsLocalV4(uint32_t nHostOrder)
{
	static const RangeV4 kLocalV4[] =
	{
		{ 0x0A000000u,  8 },	// 10.0.0.0/8        Private-Use, RFC 1918
		{ 0x7F000000u,  8 },	// 127.0.0.0/8       Loopback, RFC 1122
		{ 0xA9FE0000u, 16 },	// 169.254.0.0/16    Link Local, RFC 3927
		{ 0xAC100000u, 12 },	// 172.16.0.0/12     Private-Use, RFC 1918
		{ 0xC0A80000u, 16 },	// 192.168.0.0/16    Private-Use, RFC 1918
	};

	return InV4( nHostOrder, kLocalV4 );
}

// Loopback, unique-local and link-local.
inline bool IsLocalV6(const uint8_t (&a)[16])
{
	static const RangeV6 kLocalV6[] =
	{
		{ 0x0000000000000000ull, 0x0000000000000001ull, 128 },	// ::1/128           Loopback, RFC 4291
		{ 0xFC00000000000000ull, 0x0000000000000000ull,   7 },	// fc00::/7          Unique-Local, RFC 4193
		{ 0xFE80000000000000ull, 0x0000000000000000ull,  10 },	// fe80::/10         Link-Local Unicast, RFC 4291
	};

	return InV6( a, kLocalV6 );
}

}	// namespace Reserved
