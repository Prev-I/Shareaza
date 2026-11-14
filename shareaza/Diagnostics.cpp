//
// Diagnostics.cpp
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

// Built without precompiled headers: Win32 and the C++ standard library only.
//
// Locking: the watchdog takes no lock at all. It reads the counters with plain
// loads, writes its own log file through a handle it opens per line, and reports
// through LogFn, which the caller guarantees does not block. The crash filter
// does no work on the crashing thread beyond starting the thread that writes the
// dump, so a stack overflow still leaves it enough stack.

#include <windows.h>
#pragma warning(push)
#pragma warning(disable : 4091)		// SDK header: 'typedef ': ignored on left of '' when no variable is declared
#include <dbghelp.h>
#pragma warning(pop)

#include "Diagnostics.h"
#include "HangDetector.h"

#include <stdarg.h>
#include <stdio.h>
#include <string>
#include <vector>

namespace Diagnostics
{
namespace
{
	typedef BOOL (WINAPI *MiniDumpWriteDumpFn)(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE,
		PMINIDUMP_EXCEPTION_INFORMATION, PMINIDUMP_USER_STREAM_INFORMATION, PMINIDUMP_CALLBACK_INFORMATION);

	// "Medium" dumps: every thread's stack and information, handles and data segments, not the whole memory.
	const MINIDUMP_TYPE	DUMP_TYPE = (MINIDUMP_TYPE)( MiniDumpWithDataSegs | MiniDumpWithHandleData |
		MiniDumpWithThreadInfo | MiniDumpWithUnloadedModules | MiniDumpWithProcessThreadData );

	const size_t		KEEP_DUMPS			= 5;
	const DWORD			SAMPLE_MS			= 1000;			// watchdog sample interval
	const ULONGLONG		REMINDER_MS			= 300000;		// "still stalled" line interval
	const LONGLONG		LOG_ROTATE_BYTES	= 1024 * 1024;
	const DWORD			STOP_WAIT_MS		= 10000;		// Stop's bounded wait for the watchdog
	const DWORD			CRASH_WAIT_MS		= 120000;		// the crash filter's bounded wait for the dump
	const size_t		PATH_CHARS			= 1024;
	const size_t		LINE_CHARS			= 1024;
	const size_t		VERSION_CHARS		= 64;

	WCHAR					g_szFolder[ PATH_CHARS ]		= {};
	WCHAR					g_szVersion[ VERSION_CHARS + 1 ]	= {};
	LogFn					g_pfnLog			= NULL;
	HMODULE					g_hDbgHelp			= NULL;
	MiniDumpWriteDumpFn		g_pfnWriteDump		= NULL;
	LPTOP_LEVEL_EXCEPTION_FILTER g_pfnPrevFilter = NULL;
	bool					g_bStarted			= false;
	bool					g_bStuck			= false;	// a watchdog outlived Stop's wait: never restart

	volatile LONG			g_nDumpBusy			= 0;		// 1 while a dump is being written
	volatile LONG			g_nCrashing			= 0;		// 1 once the crash filter has run

	// Handed from the crash filter to the dump thread
	EXCEPTION_POINTERS*		g_pCrashPointers	= NULL;
	DWORD					g_nCrashThreadId	= 0;
	HANDLE					g_hCrashDone		= NULL;		// set by the dump thread once the dump is written

	// Watchdog
	HANDLE					g_hWatchdog			= NULL;
	HANDLE					g_hStop				= NULL;
	const volatile LONG*	g_pHeartbeat		= NULL;
	const volatile LONG*	g_pSectionOwner		= NULL;
	const volatile LONG*	g_pSectionAcquisitions = NULL;
	ThreadIdFn				g_pfnNetworkThread	= NULL;
	DWORD					g_nThresholdMs		= 0;

	//////////////////////////////////////////////////////////////////////
	// Log: <folder>\Diagnostics.log, UTF-8, one handle per line, no heap

	void AppendToFile(LPCWSTR pszLine)
	{
		WCHAR szLog[ PATH_CHARS ], szOld[ PATH_CHARS ];
		if ( _snwprintf_s( szLog, _countof( szLog ), _TRUNCATE, L"%ls\\Diagnostics.log", g_szFolder ) < 0 ||
			 _snwprintf_s( szOld, _countof( szOld ), _TRUNCATE, L"%ls\\Diagnostics.old.log", g_szFolder ) < 0 )
			return;

		SYSTEMTIME st;
		GetSystemTime( &st );
		WCHAR szText[ LINE_CHARS ];
		_snwprintf_s( szText, _countof( szText ), _TRUNCATE, L"%04u-%02u-%02u %02u:%02u:%02uZ %ls\r\n",
			st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, pszLine );
		char szUtf8[ LINE_CHARS * 3 ];
		const int nBytes = WideCharToMultiByte( CP_UTF8, 0, szText, -1, szUtf8, (int)sizeof( szUtf8 ), NULL, NULL );
		if ( nBytes <= 1 )
			return;

		const DWORD nShare = FILE_SHARE_READ | FILE_SHARE_WRITE;
		HANDLE hFile = CreateFileW( szLog, FILE_APPEND_DATA, nShare, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );
		if ( hFile == INVALID_HANDLE_VALUE )
			return;
		LARGE_INTEGER nSize;
		if ( GetFileSizeEx( hFile, &nSize ) && nSize.QuadPart >= LOG_ROTATE_BYTES )
		{
			CloseHandle( hFile );
			MoveFileExW( szLog, szOld, MOVEFILE_REPLACE_EXISTING );
			hFile = CreateFileW( szLog, FILE_APPEND_DATA, nShare, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );
			if ( hFile == INVALID_HANDLE_VALUE )
				return;
		}
		DWORD nWritten = 0;
		WriteFile( hFile, szUtf8, (DWORD)( nBytes - 1 ), &nWritten, NULL );
		CloseHandle( hFile );
	}

	void Log(bool bError, LPCWSTR pszFormat, ...)
	{
		WCHAR szLine[ LINE_CHARS ];
		va_list pArgs;
		va_start( pArgs, pszFormat );
		_vsnwprintf_s( szLine, _countof( szLine ), _TRUNCATE, pszFormat, pArgs );
		va_end( pArgs );

		AppendToFile( szLine );
		if ( g_pfnLog )
			g_pfnLog( bError, szLine );
	}

	//////////////////////////////////////////////////////////////////////
	// Dump files

	// UTC, so the name order (retention order) survives DST changes
	void Stamp(WCHAR (&szStamp)[ 32 ])
	{
		SYSTEMTIME st;
		GetSystemTime( &st );
		_snwprintf_s( szStamp, _countof( szStamp ), _TRUNCATE, L"%04u%02u%02u-%02u%02u%02u",
			st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond );
	}

	// Error codes: Win32 errors in decimal, HRESULTs (from MiniDumpWriteDump) in hex.
	void LogDumpError(LPCWSTR pszName, DWORD nError)
	{
		if ( nError > 0xFFFF )
			Log( true, L"Diagnostics: could not write dump %ls: error 0x%08lX", pszName, nError );
		else
			Log( true, L"Diagnostics: could not write dump %ls: error %lu", pszName, nError );
	}

	bool WriteDump(LPCWSTR pszName, EXCEPTION_POINTERS* pExceptionPointers, DWORD nThreadId, DWORD& nError)
	{
		WCHAR szPath[ PATH_CHARS ];
		if ( _snwprintf_s( szPath, _countof( szPath ), _TRUNCATE, L"%ls\\%ls", g_szFolder, pszName ) < 0 )
		{
			nError = ERROR_FILENAME_EXCED_RANGE;
			return false;
		}
		HANDLE hFile = CreateFileW( szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );
		if ( hFile == INVALID_HANDLE_VALUE )
		{
			nError = GetLastError();
			return false;
		}
		MINIDUMP_EXCEPTION_INFORMATION pInfo = { nThreadId, pExceptionPointers, FALSE };
		const BOOL bOK = g_pfnWriteDump( GetCurrentProcess(), GetCurrentProcessId(), hFile, DUMP_TYPE,
			pExceptionPointers ? &pInfo : NULL, NULL, NULL );
		nError = bOK ? 0 : GetLastError();
		CloseHandle( hFile );
		if ( ! bOK )
			DeleteFileW( szPath );
		return bOK != FALSE;
	}

	// Keeps the newest KEEP_DUMPS dump files; any other file is left alone.
	void PruneDumps()
	{
		WCHAR szPattern[ PATH_CHARS ];
		if ( _snwprintf_s( szPattern, _countof( szPattern ), _TRUNCATE, L"%ls\\*.dmp", g_szFolder ) < 0 )
			return;
		std::vector< std::wstring > oNames;
		WIN32_FIND_DATAW pFind;
		HANDLE hFind = FindFirstFileW( szPattern, &pFind );
		if ( hFind == INVALID_HANDLE_VALUE )
			return;
		do
		{
			if ( ! ( pFind.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ) )
				oNames.push_back( pFind.cFileName );
		}
		while ( FindNextFileW( hFind, &pFind ) );
		FindClose( hFind );

		const std::vector< std::wstring > oDelete = Diag::DumpsToDelete( oNames, KEEP_DUMPS );
		for ( size_t i = 0 ; i < oDelete.size() ; ++i )
		{
			const std::wstring sPath = std::wstring( g_szFolder ) + L"\\" + oDelete[ i ];
			DeleteFileW( sPath.c_str() );
		}
	}

	//////////////////////////////////////////////////////////////////////
	// Crash path

	DWORD WINAPI CrashDumpThread(LPVOID)
	{
		// Let a hang dump in progress finish (dbghelp is single-threaded), but not for long
		for ( int i = 0 ; i < 200 && InterlockedCompareExchange( &g_nDumpBusy, 1, 0 ) != 0 ; ++i )
			Sleep( 50 );

		WCHAR szStamp[ 32 ], szName[ 128 ];
		Stamp( szStamp );
		// Same form as Diag::DumpFileName, without the heap: it may be what failed
		_snwprintf_s( szName, _countof( szName ), _TRUNCATE, L"%ls-crash-%ls.dmp", szStamp, g_szVersion );

		const DWORD nCode = g_pCrashPointers && g_pCrashPointers->ExceptionRecord ?
			g_pCrashPointers->ExceptionRecord->ExceptionCode : 0;
		DWORD nError = 0;
		if ( WriteDump( szName, g_pCrashPointers, g_nCrashThreadId, nError ) )
		{
			WCHAR szLine[ 256 ];
			_snwprintf_s( szLine, _countof( szLine ), _TRUNCATE, L"Diagnostics: crash, exception 0x%08lX in thread %lu; dump %ls",
				nCode, g_nCrashThreadId, szName );
			AppendToFile( szLine );
		}
		else
		{
			WCHAR szLine[ 256 ];
			_snwprintf_s( szLine, _countof( szLine ), _TRUNCATE, L"Diagnostics: could not write dump %ls: error %lu", szName, nError );
			AppendToFile( szLine );
		}
		SetEvent( g_hCrashDone );

		// The filter returns once the event is set; retention may not finish before the
		// process ends, in which case the next Start completes it.
		PruneDumps();
		return 0;
	}

	LONG WINAPI CrashFilter(EXCEPTION_POINTERS* pExceptionPointers)
	{
		// One dump per process: a second exception (another thread, or the dump thread) goes straight on
		if ( InterlockedExchange( &g_nCrashing, 1 ) != 0 )
			return EXCEPTION_CONTINUE_SEARCH;

		g_pCrashPointers = pExceptionPointers;
		g_nCrashThreadId = GetCurrentThreadId();

		// A fresh thread with its own stack writes the dump, so a stack overflow still dumps
		HANDLE hThread = CreateThread( NULL, 0, CrashDumpThread, NULL, 0, NULL );
		if ( hThread )
		{
			HANDLE hWait[ 2 ] = { g_hCrashDone, hThread };
			WaitForMultipleObjects( 2, hWait, FALSE, CRASH_WAIT_MS );
			CloseHandle( hThread );
		}
		return EXCEPTION_CONTINUE_SEARCH;
	}

	//////////////////////////////////////////////////////////////////////
	// Watchdog

	LPCWSTR KindsText(unsigned nKinds)
	{
		switch ( nKinds & ( Diag::HangHeartbeat | Diag::HangSection ) )
		{
		case Diag::HangHeartbeat:
			return L"network heartbeat";
		case Diag::HangSection:
			return L"network section";
		case Diag::HangHeartbeat | Diag::HangSection:
			return L"network heartbeat and section";
		default:
			return L"network";
		}
	}

	// ", network section held by thread <id>[ (network thread)]", or empty if the section is not involved
	void OwnerText(DWORD nOwner, WCHAR (&szOwner)[ 96 ])
	{
		szOwner[ 0 ] = 0;
		if ( nOwner == 0 )
			return;
		const DWORD nNetwork = g_pfnNetworkThread ? g_pfnNetworkThread() : 0;
		_snwprintf_s( szOwner, _countof( szOwner ), _TRUNCATE, L", network section held by thread %lu%ls",
			nOwner, nOwner == nNetwork ? L" (network thread)" : L"" );
	}

	void OnStallStarted(const Diag::HangEvent& oEvent)
	{
		WCHAR szStamp[ 32 ];
		Stamp( szStamp );
		const std::wstring sName = Diag::DumpFileName( szStamp, L"hang", g_szVersion );

		DWORD nError = ERROR_BUSY;
		bool bDumped = false;
		if ( InterlockedCompareExchange( &g_nDumpBusy, 1, 0 ) == 0 )
		{
			bDumped = WriteDump( sName.c_str(), NULL, 0, nError );
			if ( bDumped )
				PruneDumps();
			InterlockedExchange( &g_nDumpBusy, 0 );
		}

		WCHAR szOwner[ 96 ];
		OwnerText( oEvent.ownerThreadId, szOwner );
		if ( bDumped )
			Log( true, L"Diagnostics: %ls stall started%ls for %llu s; dump %ls",
				KindsText( oEvent.kinds ), szOwner, (unsigned long long)( oEvent.durationMs / 1000 ), sName.c_str() );
		else
		{
			Log( true, L"Diagnostics: %ls stall started%ls for %llu s; no dump",
				KindsText( oEvent.kinds ), szOwner, (unsigned long long)( oEvent.durationMs / 1000 ) );
			LogDumpError( sName.c_str(), nError );
		}
	}

	DWORD WINAPI WatchdogThread(LPVOID pParam)
	{
		HANDLE hStop = static_cast< HANDLE >( pParam );

		// The detector forgets a signal across a gap above threshold / 2, so short
		// thresholds (tests) sample more often than once a second.
		DWORD nInterval = g_nThresholdMs / 4;
		if ( nInterval > SAMPLE_MS ) nInterval = SAMPLE_MS;
		if ( nInterval == 0 ) nInterval = 1;

		Diag::HangDetector oDetector( g_nThresholdMs, REMINDER_MS );
		unsigned nEpisodeKinds = 0;

		while ( WaitForSingleObject( hStop, nInterval ) == WAIT_TIMEOUT )
		{
			Diag::HangSample oSample;
			oSample.nowMs				= GetTickCount64();
			oSample.networkThreadId		= g_pfnNetworkThread ? (uint32_t)g_pfnNetworkThread() : 0;
			oSample.heartbeat			= (uint32_t)*g_pHeartbeat;
			oSample.sectionOwner		= (uint32_t)*g_pSectionOwner;
			oSample.sectionAcquisitions	= (uint32_t)*g_pSectionAcquisitions;

			const Diag::HangEvent oEvent = oDetector.Sample( oSample );
			WCHAR szOwner[ 96 ];
			switch ( oEvent.type )
			{
			case Diag::HangEvent::Started:
				nEpisodeKinds = oEvent.kinds;
				OnStallStarted( oEvent );
				break;

			case Diag::HangEvent::KindAdded:
			case Diag::HangEvent::Reminder:
				nEpisodeKinds |= oEvent.kinds;
				OwnerText( oEvent.ownerThreadId, szOwner );
				Log( true, L"Diagnostics: %ls still stalled after %llu s%ls",
					KindsText( oEvent.kinds ), (unsigned long long)( oEvent.durationMs / 1000 ), szOwner );
				break;

			case Diag::HangEvent::Ended:
				Log( false, L"Diagnostics: %ls stall ended after %llu s",
					KindsText( nEpisodeKinds ), (unsigned long long)( oEvent.durationMs / 1000 ) );
				nEpisodeKinds = 0;
				break;

			default:
				break;
			}
		}
		return 0;
	}

	//////////////////////////////////////////////////////////////////////
	// Start helpers

	// Creates the folder and any missing parent; true if it exists afterwards.
	bool CreateFolder(LPCWSTR pszFolder)
	{
		WCHAR szPath[ PATH_CHARS ];
		if ( _snwprintf_s( szPath, _countof( szPath ), _TRUNCATE, L"%ls", pszFolder ) < 0 )
			return false;
		for ( WCHAR* p = szPath + 1 ; *p ; ++p )
		{
			if ( ( *p == L'\\' || *p == L'/' ) && p[ -1 ] != L':' && p[ -1 ] != L'\\' && p[ -1 ] != L'/' )
			{
				const WCHAR c = *p;
				*p = 0;
				CreateDirectoryW( szPath, NULL );	// parents: errors are judged by the final check
				*p = c;
			}
		}
		CreateDirectoryW( szPath, NULL );
		const DWORD nAttributes = GetFileAttributesW( szPath );
		return nAttributes != INVALID_FILE_ATTRIBUTES && ( nAttributes & FILE_ATTRIBUTE_DIRECTORY );
	}

	// The version is opaque text: anything a file name cannot hold becomes '_'.
	void SetVersion(LPCWSTR pszVersion)
	{
		size_t n = 0;
		for ( ; pszVersion && pszVersion[ n ] && n < VERSION_CHARS ; ++n )
		{
			const WCHAR c = pszVersion[ n ];
			g_szVersion[ n ] = ( c < 0x20 || wcschr( L"<>:\"/\\|?*", c ) ) ? L'_' : c;
		}
		g_szVersion[ n ] = 0;
		if ( n == 0 )
			wcscpy_s( g_szVersion, L"unknown" );
	}

	void Unload()
	{
		if ( g_hDbgHelp )
			FreeLibrary( g_hDbgHelp );
		g_hDbgHelp = NULL;
		g_pfnWriteDump = NULL;
		if ( g_hCrashDone )
			CloseHandle( g_hCrashDone );
		g_hCrashDone = NULL;
	}
}

//////////////////////////////////////////////////////////////////////
// Public interface

bool Start(LPCWSTR pszFolder, LPCWSTR pszVersion, LogFn pfnLog)
{
	if ( g_bStarted || g_bStuck )
		return false;

	g_pfnLog = pfnLog;
	g_szFolder[ 0 ] = 0;
	if ( ! pszFolder || ! *pszFolder || _snwprintf_s( g_szFolder, _countof( g_szFolder ), _TRUNCATE, L"%ls", pszFolder ) < 0 )
	{
		g_szFolder[ 0 ] = 0;
		if ( pfnLog )
			pfnLog( true, L"Diagnostics: no usable folder; diagnostics are off" );
		return false;
	}
	for ( size_t n = wcslen( g_szFolder ) ; n > 1 && ( g_szFolder[ n - 1 ] == L'\\' || g_szFolder[ n - 1 ] == L'/' ) ; --n )
		g_szFolder[ n - 1 ] = 0;
	SetVersion( pszVersion );

	if ( ! CreateFolder( g_szFolder ) )
	{
		const DWORD nError = GetLastError();
		Log( true, L"Diagnostics: could not create %ls: error %lu; diagnostics are off", g_szFolder, nError );
		return false;
	}

	// The system copy only, by full path: never one found through the search path
	WCHAR szDbgHelp[ MAX_PATH ];
	const UINT nLen = GetSystemDirectoryW( szDbgHelp, MAX_PATH );
	if ( nLen == 0 || nLen >= MAX_PATH - 16 || wcscat_s( szDbgHelp, L"\\dbghelp.dll" ) != 0 )
	{
		Log( true, L"Diagnostics: no system directory; diagnostics are off" );
		return false;
	}
	g_hDbgHelp = LoadLibraryW( szDbgHelp );
	g_pfnWriteDump = g_hDbgHelp ? reinterpret_cast< MiniDumpWriteDumpFn >( GetProcAddress( g_hDbgHelp, "MiniDumpWriteDump" ) ) : NULL;
	if ( ! g_pfnWriteDump )
	{
		Log( true, L"Diagnostics: %ls or its MiniDumpWriteDump is missing; diagnostics are off", szDbgHelp );
		Unload();
		return false;
	}

	g_hCrashDone = CreateEventW( NULL, TRUE, FALSE, NULL );
	if ( ! g_hCrashDone )
	{
		Log( true, L"Diagnostics: could not create an event: error %lu; diagnostics are off", GetLastError() );
		Unload();
		return false;
	}

	PruneDumps();	// finishes retention a crash may have cut short
	g_pfnPrevFilter = SetUnhandledExceptionFilter( CrashFilter );
	g_bStarted = true;
	return true;
}

bool Watch(const volatile LONG* pHeartbeat, const volatile LONG* pSectionOwner,
	const volatile LONG* pSectionAcquisitions, ThreadIdFn pfnNetworkThread, DWORD nThresholdMs)
{
	if ( ! g_bStarted || g_hWatchdog || ! pHeartbeat || ! pSectionOwner || ! pSectionAcquisitions || nThresholdMs == 0 )
		return false;

	g_pHeartbeat			= pHeartbeat;
	g_pSectionOwner			= pSectionOwner;
	g_pSectionAcquisitions	= pSectionAcquisitions;
	g_pfnNetworkThread		= pfnNetworkThread;
	g_nThresholdMs			= nThresholdMs;

	g_hStop = CreateEventW( NULL, TRUE, FALSE, NULL );
	if ( g_hStop )
		g_hWatchdog = CreateThread( NULL, 0, WatchdogThread, g_hStop, 0, NULL );
	if ( ! g_hWatchdog )
	{
		Log( true, L"Diagnostics: could not start the watchdog: error %lu", GetLastError() );
		if ( g_hStop )
			CloseHandle( g_hStop );
		g_hStop = NULL;
		return false;
	}
	return true;
}

void Stop()
{
	bool bWatchdogGone = true;
	if ( g_hWatchdog )
	{
		SetEvent( g_hStop );
		if ( WaitForSingleObject( g_hWatchdog, STOP_WAIT_MS ) != WAIT_OBJECT_0 )
		{
			// Still inside a step (a dump, most likely): leave it everything it uses.
			// It exits on its own at its next wait.
			bWatchdogGone = false;
			g_bStuck = true;
		}
		CloseHandle( g_hWatchdog );
		g_hWatchdog = NULL;
		if ( bWatchdogGone )
			CloseHandle( g_hStop );
		g_hStop = NULL;
	}

	if ( ! g_bStarted )
		return;

	// Put back the previous filter, unless someone has replaced ours since
	LPTOP_LEVEL_EXCEPTION_FILTER pfnCurrent = SetUnhandledExceptionFilter( g_pfnPrevFilter );
	if ( pfnCurrent != CrashFilter )
		SetUnhandledExceptionFilter( pfnCurrent );
	g_pfnPrevFilter = NULL;

	if ( bWatchdogGone && g_nCrashing == 0 )
		Unload();
	g_bStarted = false;
}

} // namespace Diagnostics
