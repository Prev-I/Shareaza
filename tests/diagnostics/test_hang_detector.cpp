// Unit test for shareaza/HangDetector.h, which has no MFC or Win32 dependency.
// Build and run: g++ -std=c++14 -Wall -Wextra -Werror -I shareaza -o /tmp/hd tests/diagnostics/test_hang_detector.cpp && /tmp/hd
#include "HangDetector.h"
#include <cstdio>
#include <string>
#include <vector>

static int failures = 0;
static void Expect(const std::wstring& got, const std::wstring& want, const char* what)
{
	if ( got != want )
	{
		++failures;
		std::printf( "FAIL %s\n  got:  [%ls]\n  want: [%ls]\n", what, got.c_str(), want.c_str() );
	}
}
static void ExpectTrue(bool ok, const char* what)
{
	if ( ! ok ) { ++failures; std::printf( "FAIL %s\n", what ); }
}

using namespace Diag;
typedef HangEvent::Type T;

static const uint64_t kThreshold = 30000, kReminder = 300000;

// Drives a detector with one sample per second; each lambda-free field is a function of the second.
struct Driver
{
	HangDetector d;
	uint64_t t;
	Driver() : d( kThreshold, kReminder ), t( 0 ) {}
	HangEvent Step(uint32_t hb, uint32_t tid, uint32_t owner, uint32_t acq, uint64_t stepMs = 1000)
	{
		HangSample s = { t, hb, tid, owner, acq };
		t += stepMs;
		return d.Sample( s );
	}
};

// Returns the first non-Nothing event type seen over `seconds` samples with constant signals, counting events.
struct Tally { int started, added, reminder, ended; HangEvent first; };
static Tally RunFlat(Driver& dr, int seconds, uint32_t hb, uint32_t tid, uint32_t owner, uint32_t acq)
{
	Tally n = { 0, 0, 0, 0, { T::Nothing, 0, 0, 0 } };
	for ( int i = 0; i < seconds; ++i )
	{
		HangEvent e = dr.Step( hb, tid, owner, acq );
		if ( e.type == T::Nothing ) continue;
		if ( n.first.type == T::Nothing ) n.first = e;
		if ( e.type == T::Started ) ++n.started;
		else if ( e.type == T::KindAdded ) ++n.added;
		else if ( e.type == T::Reminder ) ++n.reminder;
		else if ( e.type == T::Ended ) ++n.ended;
	}
	return n;
}

int main()
{
	{
		Driver dr;
		bool quiet = true;
		for ( uint32_t i = 0; i < 120; ++i )
			if ( dr.Step( i, 100, 0, 0 ).type != T::Nothing ) quiet = false;
		ExpectTrue( quiet, "healthy" );
	}
	{
		// Samples at t = 0..28 s: heartbeat has been flat for 28 s at the last one.
		Driver dr; Tally n = RunFlat( dr, 30, 5, 100, 0, 0 );
		ExpectTrue( n.started == 0, "heartbeat flat 29 s is quiet" );
	}
	{
		Driver dr; Tally n = RunFlat( dr, 31, 5, 100, 0, 0 );
		ExpectTrue( n.started == 1 && n.first.type == T::Started, "heartbeat flat 30 s starts" );
		ExpectTrue( n.first.kinds == HangHeartbeat, "heartbeat kind" );
		ExpectTrue( n.first.durationMs == 30000, "heartbeat started duration" );
		ExpectTrue( n.first.ownerThreadId == 0, "heartbeat has no owner" );
	}
	{
		Driver dr; Tally n = RunFlat( dr, 90, 5, 0, 0, 0 );
		ExpectTrue( n.started == 0, "no network thread" );
	}
	{
		Driver dr; Tally n = RunFlat( dr, 31, 1, 0, 7, 41 );
		ExpectTrue( n.first.type == T::Started && n.first.kinds == HangSection, "section held 30 s" );
		ExpectTrue( n.first.ownerThreadId == 7, "section owner reported" );
	}
	{
		Driver dr; bool quiet = true;
		for ( uint32_t i = 0; i < 60; ++i )
			if ( dr.Step( i, 100, 7, 41 + i ).type != T::Nothing ) quiet = false;
		ExpectTrue( quiet, "section re-taken" );
	}
	{
		Driver dr; bool quiet = true;
		for ( uint32_t i = 0; i < 90; ++i )
			if ( dr.Step( i, 100, ( i & 1 ) ? 9 : 7, 41 ).type != T::Nothing ) quiet = false;
		ExpectTrue( quiet, "owner changes" );
	}
	{
		Driver dr; Tally n = RunFlat( dr, 60, 5, 100, 7, 41 );
		ExpectTrue( n.started == 1 && n.first.kinds == ( HangHeartbeat | HangSection ), "both kinds one Started" );
		ExpectTrue( n.added == 0, "both kinds no KindAdded" );
		ExpectTrue( n.first.ownerThreadId == 7, "both kinds owner" );
	}
	{
		Driver dr; int started = 0, added = 0; HangEvent addedEv = { T::Nothing, 0, 0, 0 };
		for ( uint32_t i = 0; i < 60; ++i )
		{
			// heartbeat flat from t=0; the section is free for 10 s and then held.
			HangEvent e = ( i < 10 ) ? dr.Step( 5, 100, 0, 0 ) : dr.Step( 5, 100, 7, 41 );
			if ( e.type == T::Started ) ++started;
			if ( e.type == T::KindAdded ) { ++added; addedEv = e; }
		}
		ExpectTrue( started == 1 && added == 1, "staggered kinds: Started then KindAdded" );
		ExpectTrue( addedEv.kinds == ( HangHeartbeat | HangSection ) && addedEv.ownerThreadId == 7, "KindAdded content" );
	}
	{
		// Stall from t=0 for 11 min: Started at 30 s, Reminders at 330 s and 630 s.
		Driver dr; std::vector<uint64_t> at; uint64_t startedAt = 0;
		for ( int i = 0; i < 660; ++i )
		{
			uint64_t now = dr.t;
			HangEvent e = dr.Step( 5, 100, 0, 0 );
			if ( e.type == T::Started ) startedAt = now;
			if ( e.type == T::Reminder ) at.push_back( now );
		}
		ExpectTrue( at.size() == 2 && at[0] == startedAt + 300000 && at[1] == startedAt + 600000, "reminders" );
	}
	{
		Driver dr; Tally n = RunFlat( dr, 95, 5, 100, 0, 0 );
		ExpectTrue( n.started == 1 && n.ended == 0, "ended: stall in progress" );
		HangEvent e = dr.Step( 6, 100, 0, 0 );
		ExpectTrue( e.type == T::Ended && e.durationMs == 95000, "ended duration" );
		ExpectTrue( dr.Step( 7, 100, 0, 0 ).type == T::Nothing, "ended once" );
		Tally m = RunFlat( dr, 40, 7, 100, 0, 0 );
		ExpectTrue( m.started == 1, "new stall after Ended starts again" );
	}
	{
		Driver dr; Tally n = RunFlat( dr, 40, 5, 100, 0, 0 );
		ExpectTrue( n.started == 1, "thread gone: stall started" );
		ExpectTrue( dr.Step( 5, 0, 0, 0 ).type == T::Ended, "thread gone ends heartbeat stall" );
	}
	{
		Driver dr; bool quiet = true;
		for ( uint32_t i = 0; i < 20; ++i ) if ( dr.Step( 1000 + i, 100, 0, 0 ).type != T::Nothing ) quiet = false;
		for ( uint32_t i = 0; i < 60; ++i ) if ( dr.Step( i, 200, 0, 0 ).type != T::Nothing ) quiet = false;
		ExpectTrue( quiet, "thread restart is not a stall" );
	}
	{
		// A thread id change resets observation even if the heartbeat value is the same.
		Driver dr; bool quiet = true;
		for ( int i = 0; i < 20; ++i ) if ( dr.Step( 5, 100, 0, 0 ).type != T::Nothing ) quiet = false;
		for ( int i = 0; i < 20; ++i ) if ( dr.Step( 5, 200, 0, 0 ).type != T::Nothing ) quiet = false;
		ExpectTrue( quiet, "thread id change resets observation" );
	}
	{
		Driver dr; bool quiet = true;
		for ( uint32_t i = 0; i < 10; ++i ) if ( dr.Step( i, 100, 0, 0 ).type != T::Nothing ) quiet = false;
		if ( dr.Step( 9, 100, 0, 0, 120000 ).type != T::Nothing ) quiet = false;   // sample, then a 120 s gap
		if ( dr.Step( 9, 100, 0, 0 ).type != T::Nothing ) quiet = false;           // unchanged after the gap
		for ( uint32_t i = 10; i < 70; ++i ) if ( dr.Step( i, 100, 0, 0 ).type != T::Nothing ) quiet = false;
		ExpectTrue( quiet, "late sample after sleep is not a stall" );
	}

	Expect( DumpFileName( L"20261114-153000", L"hang", L"2.7.11.4" ), L"20261114-153000-hang-2.7.11.4.dmp", "file name" );

	{
		std::vector<std::wstring> names;
		names.push_back( L"20261114-100003-hang-2.7.11.4.dmp" );
		names.push_back( L"20261114-100001-crash-2.7.11.4.dmp" );
		names.push_back( L"20261114-100007-crash-2.7.11.4.dmp" );
		names.push_back( L"20261114-100002-hang-2.7.11.4.dmp" );
		names.push_back( L"20261114-100005-hang-2.7.11.4.dmp" );
		names.push_back( L"20261114-100004-crash-2.7.11.4.dmp" );
		names.push_back( L"20261114-100006-hang-2.7.11.4.dmp" );
		std::vector<std::wstring> del = DumpsToDelete( names, 5 );
		ExpectTrue( del.size() == 2, "retention count" );
		if ( del.size() == 2 )
		{
			Expect( del[0], L"20261114-100001-crash-2.7.11.4.dmp", "retention oldest" );
			Expect( del[1], L"20261114-100002-hang-2.7.11.4.dmp", "retention second oldest" );
		}
		ExpectTrue( DumpsToDelete( names, 7 ).empty() && DumpsToDelete( names, 99 ).empty(), "retention within keep" );

		names.push_back( L"notes.txt" );
		names.push_back( L"old.dmp" );
		names.push_back( L"20261114-153000-hang-x.dmp.bak" );
		names.push_back( L"2026111-153000-hang-x.dmp" );
		names.push_back( L"20261114-153000-other-x.dmp" );
		names.push_back( L"20261114-153000-hang-.dmp" );
		del = DumpsToDelete( names, 5 );
		ExpectTrue( del.size() == 2, "retention ignores foreign files" );
		ExpectTrue( DumpsToDelete( names, 0 ).size() == 7, "retention keep 0 only matching" );
	}

	{
		RateLimiter r; uint32_t sup = 99;
		ExpectTrue( r.Allow( 0, sup ) && sup == 0, "rate limiter first" );
		ExpectTrue( ! r.Allow( 1000, sup ) && ! r.Allow( 2000, sup ) && ! r.Allow( 59999, sup ), "rate limiter refuses" );
		ExpectTrue( r.Allow( 60000, sup ) && sup == 3, "rate limiter reopens with count" );
		ExpectTrue( ! r.Allow( 60001, sup ), "rate limiter closes again" );
	}
	{
		static RateLimiter s;   // static storage duration
		uint32_t sup = 0;
		ExpectTrue( s.Allow( 5000, sup ), "static rate limiter" );
	}

	if ( failures ) { std::printf( "%d failure(s)\n", failures ); return 1; }
	std::printf( "all tests passed\n" );
	return 0;
}
