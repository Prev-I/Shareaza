// Pure logic for the opt-in hang diagnostics: stall detection over once-a-second
// samples, dump-file naming and retention, and a lock-free log rate limiter.
// No MFC or Win32 dependency, so it is unit-tested off Windows (tests/diagnostics).

#pragma once

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace Diag
{

enum HangKind : unsigned { HangNone = 0, HangHeartbeat = 1, HangSection = 2 };

struct HangSample
{
	uint64_t nowMs;
	uint32_t heartbeat;			// network loop heartbeat counter
	uint32_t networkThreadId;	// 0: the network is not running
	uint32_t sectionOwner;		// owner thread of the network mutex, 0: free
	uint32_t sectionAcquisitions;
};

struct HangEvent
{
	enum Type { Nothing, Started, KindAdded, Reminder, Ended } type;
	unsigned kinds;				// HangKind mask of the stalled kinds
	uint64_t durationMs;
	uint32_t ownerThreadId;		// section owner when the section kind is involved, else 0
};

// A kind is stalled when its signal is seen unchanged across consecutive samples
// spanning at least thresholdMs, with no gap between samples above thresholdMs / 2
// (a longer gap, e.g. after sleep, restarts the observation at that sample).
class HangDetector
{
public:
	HangDetector(uint64_t thresholdMs, uint64_t reminderMs)
		: m_threshold( thresholdMs ), m_reminder( reminderMs )
		, m_active( false ), m_kinds( 0 ), m_episodeStart( 0 ), m_nextReminder( 0 ), m_lastNow( 0 ), m_haveLast( false )
	{
	}

	HangEvent Sample(const HangSample& s)
	{
		const bool bigGap = m_haveLast && ( s.nowMs < m_lastNow || s.nowMs - m_lastNow > m_threshold / 2 );
		m_lastNow = s.nowMs;
		m_haveLast = true;

		m_heart.Observe( s.networkThreadId != 0, s.networkThreadId, s.heartbeat, s.nowMs, bigGap );
		m_section.Observe( s.sectionOwner != 0, s.sectionOwner, s.sectionAcquisitions, s.nowMs, bigGap );

		const bool heart = m_heart.Stalled( s.nowMs, m_threshold );
		const bool sect = m_section.Stalled( s.nowMs, m_threshold );
		const unsigned kinds = ( heart ? HangHeartbeat : 0u ) | ( sect ? HangSection : 0u );
		const uint32_t owner = sect ? s.sectionOwner : 0;

		uint64_t earliest = 0;
		if ( heart ) earliest = m_heart.start;
		if ( sect && ( ! heart || m_section.start < earliest ) ) earliest = m_section.start;

		HangEvent e = { HangEvent::Nothing, kinds, 0, owner };

		if ( kinds == 0 )
		{
			if ( m_active )
			{
				m_active = false;
				m_kinds = 0;
				e.type = HangEvent::Ended;
				e.kinds = 0;
				e.durationMs = s.nowMs - m_episodeStart;
				e.ownerThreadId = 0;
			}
			return e;
		}

		if ( ! m_active )
		{
			m_active = true;
			m_kinds = kinds;
			m_episodeStart = earliest;
			m_nextReminder = s.nowMs + m_reminder;
			e.type = HangEvent::Started;
			e.durationMs = s.nowMs - earliest;
			return e;
		}

		if ( earliest < m_episodeStart ) m_episodeStart = earliest;
		const bool added = ( kinds & ~m_kinds ) != 0;
		m_kinds = kinds;

		if ( added )
		{
			e.type = HangEvent::KindAdded;
			e.durationMs = s.nowMs - m_episodeStart;
		}
		else if ( m_reminder != 0 && s.nowMs >= m_nextReminder )
		{
			m_nextReminder += m_reminder;
			if ( m_nextReminder <= s.nowMs ) m_nextReminder = s.nowMs + m_reminder;
			e.type = HangEvent::Reminder;
			e.durationMs = s.nowMs - m_episodeStart;
		}
		return e;
	}

private:
	struct Observation
	{
		bool seen;
		uint32_t key, value;
		uint64_t start;

		Observation() : seen( false ), key( 0 ), value( 0 ), start( 0 ) {}

		void Observe(bool present, uint32_t newKey, uint32_t newValue, uint64_t now, bool bigGap)
		{
			if ( ! present ) { seen = false; return; }
			if ( ! seen || bigGap || key != newKey || value != newValue )
			{
				seen = true;
				key = newKey;
				value = newValue;
				start = now;
			}
		}

		bool Stalled(uint64_t now, uint64_t threshold) const
		{
			return seen && now - start >= threshold;
		}
	};

	uint64_t m_threshold, m_reminder;
	bool m_active;
	unsigned m_kinds;
	uint64_t m_episodeStart, m_nextReminder, m_lastNow;
	bool m_haveLast;
	Observation m_heart;	// key: network thread id, value: heartbeat
	Observation m_section;	// key: owner, value: acquisitions
};

// <YYYYMMDD-HHMMSS>-<kind>-<version>.dmp, kind is L"crash" or L"hang".
inline std::wstring DumpFileName(const std::wstring& stampYmdHms, const wchar_t* kind, const std::wstring& version)
{
	return stampYmdHms + L"-" + kind + L"-" + version + L".dmp";
}

namespace Detail
{
	inline bool IsDigits(const std::wstring& s, size_t pos, size_t count)
	{
		for ( size_t i = pos; i < pos + count; ++i )
			if ( s[i] < L'0' || s[i] > L'9' ) return false;
		return true;
	}

	// ^\d{8}-\d{6}-(crash|hang)-[^\\/]+\.dmp$
	inline bool IsDumpName(const std::wstring& n)
	{
		if ( n.size() < 15 + 1 + 4 + 1 + 1 + 4 ) return false;
		if ( ! IsDigits( n, 0, 8 ) || n[8] != L'-' || ! IsDigits( n, 9, 6 ) || n[15] != L'-' ) return false;
		size_t pos;
		if ( n.compare( 16, 6, L"crash-" ) == 0 ) pos = 22;
		else if ( n.compare( 16, 5, L"hang-" ) == 0 ) pos = 21;
		else return false;
		if ( n.size() < pos + 1 + 4 || n.compare( n.size() - 4, 4, L".dmp" ) != 0 ) return false;
		for ( size_t i = pos; i < n.size() - 4; ++i )
			if ( n[i] == L'\\' || n[i] == L'/' ) return false;
		return true;
	}
}

// Names of dump files to delete: only names that match the pattern, oldest first
// (the leading timestamp orders them), beyond the newest `keep`.
inline std::vector<std::wstring> DumpsToDelete(std::vector<std::wstring> names, size_t keep)
{
	std::vector<std::wstring> dumps;
	for ( size_t i = 0; i < names.size(); ++i )
		if ( Detail::IsDumpName( names[i] ) ) dumps.push_back( names[i] );
	std::sort( dumps.begin(), dumps.end() );	// timestamp first, so name order is age order
	if ( dumps.size() <= keep ) return std::vector<std::wstring>();
	dumps.resize( dumps.size() - keep );
	return dumps;
}

// True at most once per 60 s; `suppressed` is the number of refusals since the last true.
// Lock-free, constexpr-constructible, safe as a function-local or namespace-scope static.
class RateLimiter
{
public:
	constexpr RateLimiter() noexcept : m_last( 0 ), m_suppressed( 0 ) {}

	bool Allow(uint64_t nowMs, uint32_t& suppressed)
	{
		uint64_t prev = m_last.load( std::memory_order_relaxed );	// last allowed time + 1, 0: never
		for (;;)
		{
			if ( prev != 0 && nowMs >= prev - 1 && nowMs - ( prev - 1 ) < 60000 )
			{
				m_suppressed.fetch_add( 1, std::memory_order_relaxed );
				return false;
			}
			if ( m_last.compare_exchange_weak( prev, nowMs + 1, std::memory_order_relaxed ) ) break;
		}
		suppressed = m_suppressed.exchange( 0, std::memory_order_relaxed );
		return true;
	}

private:
	std::atomic<uint64_t> m_last;
	std::atomic<uint32_t> m_suppressed;
};

} // namespace Diag
