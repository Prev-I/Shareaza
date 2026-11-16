//
// IPListUpdater.h
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

// Downloads the subscribed IP block lists, one at a time, on a worker thread
// that exits when its queue is empty. OnTimer60 queues the lists that are due;
// UpdateNow queues lists regardless of due time.
//
// A download must be https:// and still be https:// after redirects; it is
// refused above IPList::kMaxDownload bytes, or above IPList::kMaxInflated bytes
// once decompressed. All URLs of a list parse into one set, which must pass
// IPList::CheckSanity before it replaces the list's ranges. Any failure keeps
// the previous ranges and records the reason (CIPLists::SetFailed).

#pragma once

#include "ThreadImpl.h"
#include "HttpRequest.h"
#include "IPListParser.h"

#include <vector>

class CBuffer;
class CIPList;


class CIPListUpdater : public CThreadImpl
{
public:
	CIPListUpdater();
	virtual ~CIPListUpdater();

	// Start records the client's start time (lists are not due sooner than
	// IPList::kStartDelay after it) and allows updates. Stop cancels the
	// download in progress and waits for the thread; once it returns, no
	// update writes anything, so IPLists.Save may follow. Both: main thread.
	void	Start();
	void	Stop();

	// From CMainWnd::OnTimer's 60-second block: queues the lists that are due
	// and starts the thread if it is idle. No I/O. Main thread.
	void	OnTimer60();

	// Queues the given lists regardless of due time; empty = every list with
	// URLs. Main thread.
	void	UpdateNow(const std::vector< GUID >& oLists);

	// Reads one downloaded or imported file into oOut, adding to oStats: gzip
	// (1F 8B) and zip (PK 03 04) are decompressed, every zip member parsed;
	// anything else is parsed as text. Decompressed content is limited to
	// IPList::kMaxInflated bytes in total. Does not Finish oOut. On failure
	// returns FALSE with the reason in sError.
	static BOOL LoadAndParse(const CBuffer& oData, IPList::RangeSet& oOut, IPList::ParseStats& oStats, CString& sError);

protected:
	CCriticalSection	m_pSection;		// guards the members below
	std::vector< GUID >	m_pQueue;		// lists waiting, in order
	GUID				m_oCurrent;		// the list being updated, if m_bBusy
	bool				m_bBusy;
	bool				m_bStarted;		// between Start and Stop
	DWORD				m_tStarted;		// time( NULL ) at Start

	CHttpRequest		m_pRequest;		// worker thread only

	void	Enqueue(const std::vector< GUID >& oLists);
	void	StartThread();
	void	Update(const CIPList& oList);
	bool	Fetch(const CString& sURL, IPList::RangeSet& oRanges, IPList::ParseStats& oStats, CString& sError);

	virtual void OnRun();

private:
	CIPListUpdater(const CIPListUpdater&);
	CIPListUpdater& operator=(const CIPListUpdater&);
};

extern CIPListUpdater IPListUpdater;
