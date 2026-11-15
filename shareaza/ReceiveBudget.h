//
// ReceiveBudget.h
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

// A time and count limit for one receive pass.
// Header-only and free of MFC, so tests/receive-budget/ can build it with any compiler.

#pragma once

#include <cstdint>

namespace Diag
{

class ReceiveBudget
{
public:
	ReceiveBudget(uint64_t startMs, uint64_t budgetMs, uint32_t maxCount)
		: m_startMs( startMs ), m_budgetMs( budgetMs ), m_maxCount( maxCount ), m_count( 0 )
	{
	}

	// Counts one datagram; false once the count limit or the time budget is reached.
	bool Next(uint64_t nowMs)
	{
		if ( m_count >= m_maxCount || nowMs - m_startMs >= m_budgetMs )
			return false;
		++m_count;
		return true;
	}

private:
	uint64_t m_startMs;
	uint64_t m_budgetMs;
	uint32_t m_maxCount;
	uint32_t m_count;
};

}
