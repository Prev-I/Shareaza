//
// DiagTest.cpp
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

// Console tests for shareaza/Diagnostics.cpp. Every case runs in a child process
// of its own, in a fresh folder under %TEMP%, with a 2000 ms stall threshold. The
// watchdog reads plain counters standing in for the network heartbeat and the
// tracked network section (owner thread, outermost acquisitions).
//
//   DiagTest							run every case, print PASS / FAIL per case
//   DiagTest --case <name>				run one in-process case (used by the above)
//   DiagTest --crash <folder>			Start, then a null write
//   DiagTest --crash-stack-overflow <folder>	Start, then unbounded recursion
//
// Exits 0 if every case passes, 1 otherwise.

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#pragma warning(push)
#pragma warning(disable : 4091 4200)	// SDK header: ignored typedef, zero-sized array
#include <dbghelp.h>
#pragma warning(pop)

#include "..\shareaza\Diagnostics.h"

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>

#pragma optimize( "", off )
#pragma warning(push)
#pragma warning(disable : 4717)		// recursive on all control paths: that is the point
static int Recurse(int n)
{
	volatile char sz[ 512 ];
	sz[ 0 ] = (char)n;
	return Recurse( n + 1 ) + sz[ 0 ];
}
#pragma warning(pop)
#pragma optimize( "", on )

namespace
{
	const DWORD		THRESHOLD_MS	= 2000;
	const DWORD		CASE_TIMEOUT_MS	= 120000;

	int				g_nFailures = 0;

	void Check(bool bOK, const char* pszExpr, int nLine)
	{
		if ( ! bOK )
		{
			printf( "  check failed: %s (line %d)\n", pszExpr, nLine );
			fflush( stdout );
			++g_nFailures;
		}
	}

	#define CHECK(expr) Check( !! ( expr ), #expr, __LINE__ )

	// LogFn: records every line the module reports.

	CRITICAL_SECTION			g_csLog;
	std::vector< std::wstring >	g_oLines;
	DWORD						g_nSlowStartMs = 0;	// test hook: stall-start handler made this much slower

	void RecordLog(bool bError, LPCWSTR pszLine)
	{
		EnterCriticalSection( &g_csLog );
		g_oLines.push_back( pszLine );
		LeaveCriticalSection( &g_csLog );
		printf( "  log%s: %ls\n", bError ? " (error)" : "", pszLine );
		fflush( stdout );
		// The "started" line is logged inside the stall-start handler, just before the
		// dump: sleeping here stands in for a dump that takes seconds.
		if ( g_nSlowStartMs && wcsstr( pszLine, L"stall started" ) )
			Sleep( g_nSlowStartMs );
	}

	size_t CountLines(LPCWSTR pszNeedle)
	{
		size_t nCount = 0;
		EnterCriticalSection( &g_csLog );
		for ( size_t i = 0 ; i < g_oLines.size() ; ++i )
			if ( g_oLines[ i ].find( pszNeedle ) != std::wstring::npos )
				++nCount;
		LeaveCriticalSection( &g_csLog );
		return nCount;
	}

	// <n> from the first "stall ended after <n> s" line, or -1
	long EndedSeconds()
	{
		long nSeconds = -1;
		EnterCriticalSection( &g_csLog );
		for ( size_t i = 0 ; i < g_oLines.size() && nSeconds < 0 ; ++i )
		{
			const size_t nPos = g_oLines[ i ].find( L"stall ended after " );
			if ( nPos != std::wstring::npos )
				nSeconds = wcstol( g_oLines[ i ].c_str() + nPos + 18, NULL, 10 );
		}
		LeaveCriticalSection( &g_csLog );
		return nSeconds;
	}

	// The simulated network thread and section.

	volatile LONG	g_nHeartbeat		= 0;
	volatile LONG	g_nOwner			= 0;
	volatile LONG	g_nAcquisitions		= 0;
	volatile LONG	g_nNetworkThread	= 0;

	DWORD NetworkThreadId()
	{
		return (DWORD)g_nNetworkThread;
	}

	void Take()
	{
		InterlockedIncrement( &g_nAcquisitions );
		InterlockedExchange( &g_nOwner, (LONG)GetCurrentThreadId() );
	}

	void Release()
	{
		InterlockedExchange( &g_nOwner, 0 );
	}

	// Holds the section 5 s with the heartbeat flat, then runs normally for 3 s.
	DWORD WINAPI HangThread(LPVOID)
	{
		InterlockedExchange( &g_nNetworkThread, (LONG)GetCurrentThreadId() );
		Take();
		Sleep( 5000 );
		Release();
		for ( int i = 0 ; i < 30 ; ++i )
		{
			InterlockedIncrement( &g_nHeartbeat );
			Sleep( 100 );
		}
		InterlockedExchange( &g_nNetworkThread, 0 );
		return 0;
	}

	// Holds the section 10 s (5x the threshold) with the heartbeat flat, then runs normally for 3 s.
	DWORD WINAPI LongHangThread(LPVOID)
	{
		InterlockedExchange( &g_nNetworkThread, (LONG)GetCurrentThreadId() );
		Take();
		Sleep( 10000 );
		Release();
		for ( int i = 0 ; i < 30 ; ++i )
		{
			InterlockedIncrement( &g_nHeartbeat );
			Sleep( 100 );
		}
		InterlockedExchange( &g_nNetworkThread, 0 );
		return 0;
	}

	// Takes and releases the section every 100 ms for 6 s, heartbeat moving.
	DWORD WINAPI RetakeThread(LPVOID)
	{
		InterlockedExchange( &g_nNetworkThread, (LONG)GetCurrentThreadId() );
		for ( int i = 0 ; i < 60 ; ++i )
		{
			Take();
			InterlockedIncrement( &g_nHeartbeat );
			Sleep( 50 );
			Release();
			Sleep( 50 );
		}
		InterlockedExchange( &g_nNetworkThread, 0 );
		return 0;
	}

	// Runs pfn on a new thread to completion; returns its thread ID.
	DWORD RunThread(LPTHREAD_START_ROUTINE pfn)
	{
		DWORD nThreadId = 0;
		HANDLE hThread = CreateThread( NULL, 0, pfn, NULL, 0, &nThreadId );
		CHECK( hThread != NULL );
		if ( hThread )
		{
			WaitForSingleObject( hThread, INFINITE );
			CloseHandle( hThread );
		}
		return nThreadId;
	}

	// Files and folders.

	std::wstring NewFolder(LPCWSTR pszCase)
	{
		WCHAR szTemp[ MAX_PATH ] = {};
		GetTempPathW( MAX_PATH, szTemp );
		WCHAR szFolder[ MAX_PATH ] = {};
		swprintf_s( szFolder, L"%lsDiagTest-%lu-%ls", szTemp, GetCurrentProcessId(), pszCase );
		return szFolder;
	}

	bool Exists(const std::wstring& sPath)
	{
		return GetFileAttributesW( sPath.c_str() ) != INVALID_FILE_ATTRIBUTES;
	}

	std::vector< std::wstring > ListFiles(const std::wstring& sFolder)
	{
		std::vector< std::wstring > oNames;
		WIN32_FIND_DATAW fd = {};
		HANDLE hFind = FindFirstFileW( ( sFolder + L"\\*" ).c_str(), &fd );
		if ( hFind == INVALID_HANDLE_VALUE )
			return oNames;
		do
		{
			if ( ! ( fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ) )
				oNames.push_back( fd.cFileName );
		}
		while ( FindNextFileW( hFind, &fd ) );
		FindClose( hFind );
		return oNames;
	}

	bool EndsWith(const std::wstring& s, LPCWSTR pszSuffix)
	{
		const size_t nLen = wcslen( pszSuffix );
		return s.size() >= nLen && s.compare( s.size() - nLen, nLen, pszSuffix ) == 0;
	}

	// Dump files whose name contains pszKind (e.g. L"-hang-"), or every dump if NULL.
	std::vector< std::wstring > Dumps(const std::wstring& sFolder, LPCWSTR pszKind)
	{
		std::vector< std::wstring > oNames = ListFiles( sFolder ), oDumps;
		for ( size_t i = 0 ; i < oNames.size() ; ++i )
			if ( EndsWith( oNames[ i ], L".dmp" ) && ( ! pszKind || oNames[ i ].find( pszKind ) != std::wstring::npos ) )
				oDumps.push_back( oNames[ i ] );
		return oDumps;
	}

	std::string ReadFileBytes(const std::wstring& sPath)
	{
		std::string sData;
		HANDLE hFile = CreateFileW( sPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL );
		if ( hFile == INVALID_HANDLE_VALUE )
			return sData;
		char szBuf[ 4096 ];
		DWORD nRead = 0;
		while ( ReadFile( hFile, szBuf, sizeof( szBuf ), &nRead, NULL ) && nRead )
			sData.append( szBuf, nRead );
		CloseHandle( hFile );
		return sData;
	}

	size_t CountOccurrences(const std::string& sText, const char* pszNeedle)
	{
		size_t nCount = 0;
		for ( size_t nPos = sText.find( pszNeedle ) ; nPos != std::string::npos ; nPos = sText.find( pszNeedle, nPos + 1 ) )
			++nCount;
		return nCount;
	}

	bool WriteSmallFile(const std::wstring& sPath)
	{
		HANDLE hFile = CreateFileW( sPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );
		if ( hFile == INVALID_HANDLE_VALUE )
			return false;
		DWORD nWritten = 0;
		const BOOL bOK = WriteFile( hFile, "seed", 4, &nWritten, NULL );
		CloseHandle( hFile );
		return bOK && nWritten == 4;
	}

	// An explicit deny of FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY to Everyone, ahead of the inherited ACEs.
	bool DenyFileCreation(const std::wstring& sFolder)
	{
		PSECURITY_DESCRIPTOR pSD = NULL;
		if ( ! ConvertStringSecurityDescriptorToSecurityDescriptorW( L"D:(D;;0x6;;;WD)", SDDL_REVISION_1, &pSD, NULL ) )
			return false;
		BOOL bPresent = FALSE, bDefaulted = FALSE;
		PACL pDacl = NULL;
		DWORD nResult = ERROR_INVALID_DATA;
		if ( GetSecurityDescriptorDacl( pSD, &bPresent, &pDacl, &bDefaulted ) && bPresent )
			nResult = SetNamedSecurityInfoW( const_cast< LPWSTR >( sFolder.c_str() ), SE_FILE_OBJECT,
				DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, pDacl, NULL );
		LocalFree( pSD );
		return nResult == ERROR_SUCCESS;
	}

	// True if the dump's ThreadListStream lists nThreadId. Loads the system dbghelp itself.
	bool DumpHasThread(const std::wstring& sPath, DWORD nThreadId)
	{
		typedef BOOL (WINAPI *ReadDumpStreamFn)(PVOID, ULONG, PMINIDUMP_DIRECTORY*, PVOID*, ULONG*);

		WCHAR szDbgHelp[ MAX_PATH ] = {};
		const UINT nLen = GetSystemDirectoryW( szDbgHelp, MAX_PATH );
		if ( nLen == 0 || nLen >= MAX_PATH - 16 )
			return false;
		wcscat_s( szDbgHelp, L"\\dbghelp.dll" );
		HMODULE hDbgHelp = LoadLibraryW( szDbgHelp );
		if ( ! hDbgHelp )
			return false;
		ReadDumpStreamFn pfnRead = reinterpret_cast< ReadDumpStreamFn >( GetProcAddress( hDbgHelp, "MiniDumpReadDumpStream" ) );

		bool bFound = false;
		HANDLE hFile = CreateFileW( sPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL );
		if ( pfnRead && hFile != INVALID_HANDLE_VALUE )
		{
			HANDLE hMap = CreateFileMappingW( hFile, NULL, PAGE_READONLY, 0, 0, NULL );
			if ( hMap )
			{
				PVOID pBase = MapViewOfFile( hMap, FILE_MAP_READ, 0, 0, 0 );
				if ( pBase )
				{
					PMINIDUMP_DIRECTORY pDir = NULL;
					PVOID pStream = NULL;
					ULONG nSize = 0;
					if ( pfnRead( pBase, ThreadListStream, &pDir, &pStream, &nSize ) && pStream && nSize >= sizeof( ULONG32 ) )
					{
						const MINIDUMP_THREAD_LIST* pList = static_cast< const MINIDUMP_THREAD_LIST* >( pStream );
						printf( "  dump lists %lu threads\n", (unsigned long)pList->NumberOfThreads );
						for ( ULONG32 i = 0 ; i < pList->NumberOfThreads ; ++i )
							if ( pList->Threads[ i ].ThreadId == nThreadId )
								bFound = true;
					}
					UnmapViewOfFile( pBase );
				}
				CloseHandle( hMap );
			}
		}
		if ( hFile != INVALID_HANDLE_VALUE )
			CloseHandle( hFile );
		FreeLibrary( hDbgHelp );
		return bFound;
	}

	bool StartAndWatch(const std::wstring& sFolder)
	{
		if ( ! Diagnostics::Start( sFolder.c_str(), L"9.9.9.9 test/build", RecordLog ) )
			return false;
		return Diagnostics::Watch( &g_nHeartbeat, &g_nOwner, &g_nAcquisitions, NetworkThreadId, THRESHOLD_MS );
	}

	// Cases run in their own process.

	void CaseNotStarted()
	{
		const std::wstring sFolder = NewFolder( L"not-started" );
		CHECK( ! Diagnostics::Watch( &g_nHeartbeat, &g_nOwner, &g_nAcquisitions, NetworkThreadId, THRESHOLD_MS ) );
		Diagnostics::Stop();
		CHECK( ! Exists( sFolder ) );
		CHECK( GetModuleHandleW( L"dbghelp.dll" ) == NULL );
	}

	void CaseHang()
	{
		const std::wstring sFolder = NewFolder( L"hang" );
		CHECK( StartAndWatch( sFolder ) );
		const DWORD nHolder = RunThread( HangThread );
		Diagnostics::Stop();

		const std::vector< std::wstring > oDumps = Dumps( sFolder, L"-hang-" );
		CHECK( oDumps.size() == 1 );
		CHECK( Dumps( sFolder, NULL ).size() == 1 );
		const std::string sLog = ReadFileBytes( sFolder + L"\\Diagnostics.log" );
		CHECK( CountOccurrences( sLog, "stall started" ) == 1 );
		CHECK( CountOccurrences( sLog, "stall ended" ) == 1 );
		CHECK( CountLines( L"stall started" ) == 1 );
		CHECK( CountLines( L"stall ended" ) == 1 );
		CHECK( CountLines( L"(network thread)" ) >= 1 );
		CHECK( CountLines( L"could not write dump" ) == 0 );
		if ( oDumps.size() == 1 )
			CHECK( DumpHasThread( sFolder + L"\\" + oDumps[ 0 ], nHolder ) );
	}

	// A slow stall-start (3 s, above threshold / 2) must not end the episode early or dump twice.
	void CaseSlowDump()
	{
		const std::wstring sFolder = NewFolder( L"slow-dump" );
		g_nSlowStartMs = 3000;
		CHECK( StartAndWatch( sFolder ) );
		RunThread( LongHangThread );
		Diagnostics::Stop();

		CHECK( Dumps( sFolder, L"-hang-" ).size() == 1 );
		CHECK( Dumps( sFolder, NULL ).size() == 1 );
		CHECK( CountLines( L"stall started" ) == 1 );
		CHECK( CountLines( L"stall ended" ) == 1 );
		CHECK( EndedSeconds() >= 9 );	// the 3 s spent starting is added back
		const std::string sLog = ReadFileBytes( sFolder + L"\\Diagnostics.log" );
		CHECK( CountOccurrences( sLog, "stall started" ) == 1 );
		CHECK( CountOccurrences( sLog, "stall ended" ) == 1 );
	}

	void CaseRetaken()
	{
		const std::wstring sFolder = NewFolder( L"re-taken" );
		CHECK( StartAndWatch( sFolder ) );
		RunThread( RetakeThread );
		Diagnostics::Stop();

		CHECK( Dumps( sFolder, NULL ).empty() );
		CHECK( CountLines( L"stall started" ) == 0 );
	}

	void CaseRetention()
	{
		const std::wstring sFolder = NewFolder( L"retention" );
		CHECK( CreateDirectoryW( sFolder.c_str(), NULL ) );
		static LPCWSTR const pszSeeds[] =
		{
			L"20200101-000000-hang-seed.dmp",		// the oldest
			L"20200102-000000-crash-seed.dmp",
			L"20200103-000000-hang-seed.dmp",
			L"20200104-000000-crash-seed.dmp",
			L"20200105-000000-hang-seed.dmp",
		};
		for ( size_t i = 0 ; i < sizeof( pszSeeds ) / sizeof( pszSeeds[ 0 ] ) ; ++i )
			CHECK( WriteSmallFile( sFolder + L"\\" + pszSeeds[ i ] ) );
		CHECK( WriteSmallFile( sFolder + L"\\notes.txt" ) );

		CHECK( StartAndWatch( sFolder ) );
		RunThread( HangThread );
		Diagnostics::Stop();

		CHECK( Dumps( sFolder, NULL ).size() == 5 );
		CHECK( ! Exists( sFolder + L"\\" + pszSeeds[ 0 ] ) );
		for ( size_t i = 1 ; i < sizeof( pszSeeds ) / sizeof( pszSeeds[ 0 ] ) ; ++i )
			CHECK( Exists( sFolder + L"\\" + pszSeeds[ i ] ) );
		CHECK( Exists( sFolder + L"\\notes.txt" ) );
		CHECK( CountLines( L"stall started" ) == 1 );
	}

	void CaseUnwritableFolder()
	{
		const std::wstring sFolder = NewFolder( L"unwritable-folder" );
		CHECK( CreateDirectoryW( sFolder.c_str(), NULL ) );
		CHECK( DenyFileCreation( sFolder ) );
		CHECK( ! WriteSmallFile( sFolder + L"\\probe.txt" ) );	// the ACL holds

		CHECK( StartAndWatch( sFolder ) );
		RunThread( HangThread );
		Diagnostics::Stop();

		CHECK( CountLines( L"stall started" ) == 1 );
		CHECK( CountLines( L"could not write dump" ) == 1 );
		CHECK( Dumps( sFolder, NULL ).empty() );

		// Still healthy: the module starts and stops again.
		CHECK( Diagnostics::Start( sFolder.c_str(), L"again", RecordLog ) );
		Diagnostics::Stop();
	}

	// Child processes.

	DWORD Spawn(const std::wstring& sArgs)
	{
		WCHAR szExe[ MAX_PATH ] = {};
		GetModuleFileNameW( NULL, szExe, MAX_PATH );
		std::wstring sCommand = std::wstring( L"\"" ) + szExe + L"\" " + sArgs;
		std::vector< wchar_t > oCommand( sCommand.begin(), sCommand.end() );
		oCommand.push_back( 0 );

		STARTUPINFOW si = {};
		si.cb = sizeof( si );
		si.dwFlags = STARTF_USESTDHANDLES;
		si.hStdInput = GetStdHandle( STD_INPUT_HANDLE );
		si.hStdOutput = GetStdHandle( STD_OUTPUT_HANDLE );
		si.hStdError = GetStdHandle( STD_ERROR_HANDLE );
		PROCESS_INFORMATION pi = {};
		fflush( stdout );
		if ( ! CreateProcessW( NULL, &oCommand[ 0 ], NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi ) )
		{
			printf( "  CreateProcess failed: error %lu\n", GetLastError() );
			return (DWORD)-1;
		}
		DWORD nExitCode = (DWORD)-1;
		if ( WaitForSingleObject( pi.hProcess, CASE_TIMEOUT_MS ) != WAIT_OBJECT_0 )
		{
			printf( "  timed out\n" );
			TerminateProcess( pi.hProcess, (UINT)-1 );
			WaitForSingleObject( pi.hProcess, 10000 );
		}
		else
			GetExitCodeProcess( pi.hProcess, &nExitCode );
		CloseHandle( pi.hThread );
		CloseHandle( pi.hProcess );
		return nExitCode;
	}

	void RunCrashCase(LPCWSTR pszOption, DWORD nExpected)
	{
		const std::wstring sFolder = NewFolder( pszOption + 2 );
		const DWORD nExitCode = Spawn( std::wstring( pszOption ) + L" \"" + sFolder + L"\"" );
		printf( "  exit code 0x%08lX\n", nExitCode );
		CHECK( nExitCode == nExpected );
		CHECK( Dumps( sFolder, L"-crash-" ).size() == 1 );
		CHECK( Dumps( sFolder, NULL ).size() == 1 );
	}

	int CrashChild(LPCWSTR pszFolder, bool bStackOverflow)
	{
		SetErrorMode( SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX );
		if ( ! Diagnostics::Start( pszFolder, L"9.9.9.9", RecordLog ) )
			return 3;
		fflush( stdout );
		if ( bStackOverflow )
			return Recurse( 0 );
		int* volatile pNull = NULL;
		*pNull = 1;
		return 4;
	}

	struct Case
	{
		LPCWSTR	pszName;
		void	(*pfnRun)();
	};

	const Case g_oCases[] =
	{
		{ L"not-started",		CaseNotStarted },
		{ L"hang",				CaseHang },
		{ L"slow-dump",			CaseSlowDump },
		{ L"re-taken",			CaseRetaken },
		{ L"retention",			CaseRetention },
		{ L"unwritable-folder",	CaseUnwritableFolder },
	};

	int RunCase(LPCWSTR pszName)
	{
		for ( size_t i = 0 ; i < sizeof( g_oCases ) / sizeof( g_oCases[ 0 ] ) ; ++i )
		{
			if ( wcscmp( g_oCases[ i ].pszName, pszName ) == 0 )
			{
				g_oCases[ i ].pfnRun();
				fflush( stdout );
				return g_nFailures ? 1 : 0;
			}
		}
		printf( "  unknown case %ls\n", pszName );
		return 1;
	}

	int RunAll()
	{
		int nFailed = 0;
		for ( size_t i = 0 ; i < sizeof( g_oCases ) / sizeof( g_oCases[ 0 ] ) ; ++i )
		{
			printf( "RUN  %ls\n", g_oCases[ i ].pszName );
			const DWORD nExitCode = Spawn( std::wstring( L"--case " ) + g_oCases[ i ].pszName );
			printf( "%s %ls\n", nExitCode == 0 ? "PASS" : "FAIL", g_oCases[ i ].pszName );
			if ( nExitCode != 0 )
				++nFailed;
		}

		static const struct { LPCWSTR pszOption; DWORD nExpected; } oCrashes[] =
		{
			{ L"--crash",					0xC0000005 },	// EXCEPTION_ACCESS_VIOLATION
			{ L"--crash-stack-overflow",	0xC00000FD },	// EXCEPTION_STACK_OVERFLOW
		};
		for ( size_t i = 0 ; i < sizeof( oCrashes ) / sizeof( oCrashes[ 0 ] ) ; ++i )
		{
			printf( "RUN  %ls\n", oCrashes[ i ].pszOption + 2 );
			const int nBefore = g_nFailures;
			RunCrashCase( oCrashes[ i ].pszOption, oCrashes[ i ].nExpected );
			const bool bPass = g_nFailures == nBefore;
			printf( "%s %ls\n", bPass ? "PASS" : "FAIL", oCrashes[ i ].pszOption + 2 );
			if ( ! bPass )
				++nFailed;
		}

		printf( "%d case(s) failed\n", nFailed );
		return nFailed ? 1 : 0;
	}
}

int wmain(int argc, wchar_t* argv[])
{
	InitializeCriticalSection( &g_csLog );
	setvbuf( stdout, NULL, _IONBF, 0 );

	if ( argc == 3 && wcscmp( argv[ 1 ], L"--case" ) == 0 )
		return RunCase( argv[ 2 ] );
	if ( argc == 3 && wcscmp( argv[ 1 ], L"--crash" ) == 0 )
		return CrashChild( argv[ 2 ], false );
	if ( argc == 3 && wcscmp( argv[ 1 ], L"--crash-stack-overflow" ) == 0 )
		return CrashChild( argv[ 2 ], true );
	if ( argc == 1 )
		return RunAll();

	printf( "usage: DiagTest [--case <name> | --crash <folder> | --crash-stack-overflow <folder>]\n" );
	return 1;
}
