//
// test_receive_budget.cpp
//
// Copyright (c) Shareaza Development Team, 2026.
// This file is part of SHAREAZA (shareaza.sourceforge.net)
//
// Shareaza is free software; you can redistribute it
// and/or modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//

#include "ReceiveBudget.h"

#include <cstdio>

static int g_nFailed = 0;

static void Check( bool bCondition, const char* pszName )
{
	if ( ! bCondition )
	{
		std::printf( "FAIL: %s\n", pszName );
		++g_nFailed;
	}
}

int main()
{
	{
		Diag::ReceiveBudget b( 1000, 50, 3 );
		Check( b.Next( 1000 ), "count limit: first" );
		Check( b.Next( 1000 ), "count limit: second" );
		Check( b.Next( 1000 ), "count limit: third" );
		Check( ! b.Next( 1000 ), "count limit: fourth refused" );
		Check( ! b.Next( 1000 ), "count limit: stays refused" );
	}
	{
		Diag::ReceiveBudget b( 0, 50, 100 );
		Check( b.Next( 0 ), "time limit: at 0" );
		Check( b.Next( 49 ), "time limit: at 49" );
		Check( ! b.Next( 50 ), "time limit: refused at 50" );
	}
	{
		Diag::ReceiveBudget b( 10, 50, 2 );
		Check( b.Next( 10 ), "both: first" );
		Check( b.Next( 20 ), "both: second" );
		Check( ! b.Next( 30 ), "both: count first" );

		Diag::ReceiveBudget c( 10, 50, 100 );
		Check( c.Next( 59 ), "both: time not yet" );
		Check( ! c.Next( 60 ), "both: time first" );
	}

	if ( g_nFailed == 0 )
		std::printf( "receive budget: all tests passed\n" );
	return g_nFailed ? 1 : 0;
}
