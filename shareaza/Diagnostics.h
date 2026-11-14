//
// Diagnostics.h
//
// Copyright (c) Shareaza Development Team, 2026.
// This file is part of SHAREAZA (shareaza.sourceforge.net)
//
// Shareaza is free software; you can redistribute it
// and/or modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2 of
// the License, or (at your option) any later version.
//
// Shareaza is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Shareaza; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//

// Opt-in local diagnostics: a minidump on an unhandled exception and a watchdog
// thread that writes one minidump per network stall. Win32 and the C++ standard
// library only (no MFC, no theApp), so DiagTest links it alone. Nothing here runs
// unless Start is called.

#pragma once

#include <windows.h>

namespace Diagnostics
{
	// Called from the watchdog thread; must not block (no lock a stalled thread may hold).
	typedef void (*LogFn)(bool bError, LPCWSTR pszLine);

	// Returns the network thread's ID while its loop runs, else 0. Must not block.
	typedef DWORD (*ThreadIdFn)();

	// Creates pszFolder, loads the system dbghelp.dll by full path and installs the
	// unhandled-exception filter. pszVersion is opaque text, sanitised for file names.
	// Returns false (and logs once) if any of that fails; nothing is left installed.
	bool Start(LPCWSTR pszFolder, LPCWSTR pszVersion, LogFn pfnLog);

	// Starts the watchdog thread. It samples the three counters (never a lock) and
	// writes one dump per stall episode. Requires a successful Start.
	bool Watch(const volatile LONG* pHeartbeat, const volatile LONG* pSectionOwner,
		const volatile LONG* pSectionAcquisitions, ThreadIdFn pfnNetworkThread, DWORD nThresholdMs);

	// Stops the watchdog (bounded wait), removes the filter and frees dbghelp.
	void Stop();
}
