//
// IPLists.h
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

// The IP block lists the user subscribed to or imported. They are consulted by
// CSecurity::IsDenied only after the user's own rules decide nothing, and they
// only deny.
//
// Locking: every list's mutable state (the list set itself, ranges pointers,
// enabled flags, times, counters, status) is guarded by Security.m_pSection.
// File I/O, parsing and serialization happen outside that lock; the results are
// swapped in under it. A second lock, m_pFileSection, serializes the writers of
// the files in Data\IPLists; it is always taken before Security.m_pSection,
// never while holding it.
//
// Files: Data\IPLists.dat holds the lists' metadata (CArchive, own version);
// Data\IPLists\<guid>.bin holds each list's ranges (IPList::Serialize format).

#pragma once

#include "IPRangeSet.h"

#include <memory>
#include <vector>

class CIPList
{
public:
	CIPList();
	CIPList(const CIPList& other);				// CStringArray has no copy constructor
	CIPList& operator=(const CIPList& other);

	GUID			m_oGUID;
	CString			m_sName;
	CStringArray	m_pURLs;			// https:// URLs; none for an imported file
	CString			m_sSource;			// file name for imports
	BOOL			m_bEnabled;
	DWORD			m_tLastSuccess;		// time( NULL ) seconds; 0 = never
	DWORD			m_tLastAttempt;
	BOOL			m_bLastFailed;
	CString			m_sStatus;			// result of the last attempt, for the UI
	DWORD			m_nToday;			// hits this session (not saved)
	DWORD			m_nEver;
	std::shared_ptr< const IPList::RangeSet > m_pRanges;	// null = no ranges
};

class CIPLists
{
public:
	CIPLists();
	~CIPLists();

	// Startup and exit. Load never parses or downloads; it reads IPLists.dat
	// and the cached ranges. A cache that is missing (after a success), cannot
	// be read or fails its checks loads empty, with status IDS_IPLIST_CACHE_BAD
	// (IDS_IPLIST_CACHE_BAD_IMPORT for a list without URLs) and no last success,
	// so the list is due again. If IPLists.dat exists but cannot be read, Save
	// refuses to write for the rest of the session.
	BOOL	Load();		// Must not be called with Security.m_pSection held (takes m_pFileSection first).
	BOOL	Save();		// Must not be called with Security.m_pSection held (takes m_pFileSection first).

	// Adds an enabled list with no ranges and returns it. The pointer stays
	// valid until Remove; read its mutable fields only under Security.m_pSection.
	CIPList* Add(const CString& sName, const CStringArray& pURLs, const CString& sSource);
	// Also deletes its <guid>.bin.
	// Must not be called with Security.m_pSection held (takes m_pFileSection first).
	BOOL	Remove(const GUID& oGUID);
	void	SetEnabled(const GUID& oGUID, BOOL bEnabled);

	// pRanges must be Finish()ed and pass IPList::CheckSanity. Writes <guid>.bin,
	// then swaps the ranges in and records a success at tWhen. Returns false and
	// changes nothing when the set is refused, the list is gone or the cache
	// cannot be written; the caller then reports the failure with SetFailed.
	// Must not be called with Security.m_pSection held (takes m_pFileSection first).
	bool	SetRanges(const GUID& oGUID, std::shared_ptr< const IPList::RangeSet > pRanges, DWORD tWhen);
	void	SetFailed(const GUID& oGUID, const CString& sReason, DWORD tWhen);

	// Caller holds Security.m_pSection. Local addresses are never denied; the
	// first enabled list that contains the address counts the hit.
	bool	IsDenied(DWORD nHostOrder);
	bool	IsDenied(const IN6_ADDR& a);

	// Enabled lists with URLs that are due for an update (IPList::IsDue).
	std::vector< GUID > GetDue(DWORD tNow, DWORD tStarted) const;

	// A copy of every list, for the UI.
	void	Snapshot(std::vector< CIPList >& out) const;

private:
	std::vector< CIPList* >	m_pLists;		// guarded by Security.m_pSection
	CCriticalSection		m_pFileSection;	// file writers; taken before Security.m_pSection
	bool					m_bSaveBlocked;	// IPLists.dat exists but was not loaded; guarded by m_pFileSection

	CIPList*	Find(const GUID& oGUID) const;	// caller holds Security.m_pSection

	CIPLists(const CIPLists&);
	CIPLists& operator=(const CIPLists&);
};

extern CIPLists IPLists;
