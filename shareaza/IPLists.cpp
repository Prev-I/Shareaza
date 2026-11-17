//
// IPLists.cpp
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

#include "StdAfx.h"
#include "Shareaza.h"
#include "Settings.h"
#include "Security.h"
#include "IPLists.h"
#include "ReservedAddresses.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

CIPLists IPLists;

// IPLists.dat format version
// 1 - first version: GUID, name, URLs, source, enabled, last success, last
//     attempt, last failed, status, hits ever
static const int IPLISTS_SER_VERSION = 1;

// The largest <guid>.bin IPList::Deserialize can accept: header, kMaxRanges
// IPv6 ranges, checksum. Anything larger is refused before it is read.
static const ULONGLONG IPLISTS_MAX_CACHE = 20 + ULONGLONG( IPList::kMaxRanges ) * 32;


//////////////////////////////////////////////////////////////////////
// Files

static CString ListsFolder()
{
	return Settings.General.UserPath + _T("\\Data\\IPLists");
}

// The GUID without braces, as in security rule XML.
static CString GuidName(const GUID& oGUID)
{
	wchar_t szGUID[ 39 ];
	if ( StringFromGUID2( oGUID, szGUID, 39 ) != 39 )
		return CString();
	szGUID[ 37 ] = 0;
	return CString( &szGUID[ 1 ] );
}

static CString CachePath(const GUID& oGUID)
{
	return ListsFolder() + _T("\\") + GuidName( oGUID ) + _T(".bin");
}

// Writes a list's ranges to a temporary file and renames it over <guid>.bin.
static bool WriteCache(const GUID& oGUID, const std::vector< uint8_t >& pBytes)
{
	const CString strFolder = ListsFolder();
	const CString strFile = CachePath( oGUID );
	const CString strTemp = strFolder + _T("\\") + GuidName( oGUID ) + _T(".tmp");

	if ( ! CreateDirectory( strFolder ) )
	{
		theApp.Message( MSG_ERROR, _T("Failed to save IP list: %s"), (LPCTSTR)strFolder );
		return false;
	}

	CFile pFile;
	if ( ! pFile.Open( strTemp, CFile::modeWrite | CFile::modeCreate | CFile::shareExclusive | CFile::osSequentialScan ) )
	{
		DeleteFile( strTemp );
		theApp.Message( MSG_ERROR, _T("Failed to save IP list: %s"), (LPCTSTR)strTemp );
		return false;
	}

	try
	{
		pFile.Write( pBytes.data(), static_cast< UINT >( pBytes.size() ) );
		pFile.Close();
	}
	catch ( CException* pException )
	{
		pFile.Abort();
		pException->Delete();
		DeleteFile( strTemp );
		theApp.Message( MSG_ERROR, _T("Failed to save IP list: %s"), (LPCTSTR)strTemp );
		return false;
	}

	if ( ! MoveFileEx( strTemp, strFile, MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING ) )
	{
		DeleteFile( strTemp );
		theApp.Message( MSG_ERROR, _T("Failed to save IP list: %s"), (LPCTSTR)strFile );
		return false;
	}

	return true;
}

enum CacheResult
{
	cacheMissing, cacheBad, cacheGood
};

// Reads <guid>.bin. A set that does not deserialize, or that deserializes but
// would not pass the checks a download must pass, is bad.
static CacheResult ReadCache(const GUID& oGUID, std::shared_ptr< const IPList::RangeSet >& pRanges)
{
	const CString strFile = CachePath( oGUID );

	if ( GetFileAttributes( strFile ) == INVALID_FILE_ATTRIBUTES )
		return cacheMissing;

	CFile pFile;
	if ( ! pFile.Open( strFile, CFile::modeRead | CFile::shareDenyWrite | CFile::osSequentialScan ) )
		return cacheBad;

	try
	{
		const ULONGLONG nLength = pFile.GetLength();
		if ( nLength > IPLISTS_MAX_CACHE )
			return cacheBad;

		std::vector< uint8_t > pBytes( static_cast< size_t >( nLength ) );
		if ( nLength && pFile.Read( pBytes.data(), static_cast< UINT >( nLength ) ) != static_cast< UINT >( nLength ) )
			return cacheBad;
		pFile.Close();

		std::shared_ptr< IPList::RangeSet > pSet( new IPList::RangeSet() );
		if ( ! IPList::Deserialize( pBytes.data(), pBytes.size(), *pSet ) ||
			IPList::CheckSanity( *pSet ) != IPList::Refusal::None )
			return cacheBad;

		pRanges = pSet;
		return cacheGood;
	}
	catch ( CException* pException )
	{
		pFile.Abort();
		pException->Delete();
		return cacheBad;
	}
	catch ( const std::exception& )
	{
		pFile.Abort();
		return cacheBad;
	}
}

static void SerializeList(CArchive& ar, CIPList& oList)
{
	if ( ar.IsStoring() )
	{
		ar.Write( &oList.m_oGUID, sizeof( GUID ) );
		ar << oList.m_sName;
		ar.WriteCount( static_cast< DWORD_PTR >( oList.m_pURLs.GetSize() ) );
		for ( INT_PTR i = 0 ; i < oList.m_pURLs.GetSize() ; ++i )
			ar << oList.m_pURLs.GetAt( i );
		ar << oList.m_sSource;
		ar << oList.m_bEnabled;
		ar << oList.m_tLastSuccess;
		ar << oList.m_tLastAttempt;
		ar << oList.m_bLastFailed;
		ar << oList.m_sStatus;
		ar << oList.m_nEver;
	}
	else
	{
		ReadArchive( ar, &oList.m_oGUID, sizeof( GUID ) );
		ar >> oList.m_sName;
		oList.m_pURLs.RemoveAll();
		for ( DWORD_PTR nCount = ar.ReadCount() ; nCount > 0 ; nCount-- )
		{
			CString sURL;
			ar >> sURL;
			oList.m_pURLs.Add( sURL );
		}
		ar >> oList.m_sSource;
		ar >> oList.m_bEnabled;
		ar >> oList.m_tLastSuccess;
		ar >> oList.m_tLastAttempt;
		ar >> oList.m_bLastFailed;
		ar >> oList.m_sStatus;
		ar >> oList.m_nEver;
	}
}


//////////////////////////////////////////////////////////////////////
// CIPList

CIPList::CIPList()
	: m_oGUID		()
	, m_bEnabled	( TRUE )
	, m_tLastSuccess( 0 )
	, m_tLastAttempt( 0 )
	, m_bLastFailed	( FALSE )
	, m_nToday		( 0 )
	, m_nEver		( 0 )
{
}

CIPList::CIPList(const CIPList& other)
	: m_oGUID		( other.m_oGUID )
	, m_sName		( other.m_sName )
	, m_sSource		( other.m_sSource )
	, m_bEnabled	( other.m_bEnabled )
	, m_tLastSuccess( other.m_tLastSuccess )
	, m_tLastAttempt( other.m_tLastAttempt )
	, m_bLastFailed	( other.m_bLastFailed )
	, m_sStatus		( other.m_sStatus )
	, m_nToday		( other.m_nToday )
	, m_nEver		( other.m_nEver )
	, m_pRanges		( other.m_pRanges )
{
	m_pURLs.Copy( other.m_pURLs );
}

CIPList& CIPList::operator=(const CIPList& other)
{
	if ( this != &other )
	{
		m_oGUID			= other.m_oGUID;
		m_sName			= other.m_sName;
		m_pURLs.Copy( other.m_pURLs );
		m_sSource		= other.m_sSource;
		m_bEnabled		= other.m_bEnabled;
		m_tLastSuccess	= other.m_tLastSuccess;
		m_tLastAttempt	= other.m_tLastAttempt;
		m_bLastFailed	= other.m_bLastFailed;
		m_sStatus		= other.m_sStatus;
		m_nToday		= other.m_nToday;
		m_nEver			= other.m_nEver;
		m_pRanges		= other.m_pRanges;
	}
	return *this;
}


//////////////////////////////////////////////////////////////////////
// CIPLists construction

CIPLists::CIPLists()
	: m_bSaveBlocked( false )
{
}

CIPLists::~CIPLists()
{
	for ( size_t i = 0 ; i < m_pLists.size() ; ++i )
		delete m_pLists[ i ];
}

CIPList* CIPLists::Find(const GUID& oGUID) const
{
	for ( size_t i = 0 ; i < m_pLists.size() ; ++i )
	{
		if ( m_pLists[ i ]->m_oGUID == oGUID )
			return m_pLists[ i ];
	}
	return NULL;
}


//////////////////////////////////////////////////////////////////////
// CIPLists load and save

BOOL CIPLists::Load()
{
	CQuickLock oFileLock( m_pFileSection );

	const CString strFile = Settings.General.UserPath + _T("\\Data\\IPLists.dat");

	std::vector< CIPList* > pLoaded;
	BOOL bResult = TRUE;
	m_bSaveBlocked = false;

	CFile pFile;
	CFileException pError;
	if ( pFile.Open( strFile, CFile::modeRead | CFile::shareDenyWrite | CFile::osSequentialScan, &pError ) )
	{
		bool bFailed = false;
		try
		{
			CArchive ar( &pFile, CArchive::load, 131072 );	// 128 KB buffer
			try
			{
				int nVersion = 0;
				ar >> nVersion;
				if ( nVersion < 1 || nVersion > IPLISTS_SER_VERSION )
					AfxThrowArchiveException( CArchiveException::badSchema );

				for ( DWORD_PTR nCount = ar.ReadCount() ; nCount > 0 ; nCount-- )
				{
					CIPList* pList = new CIPList();
					pLoaded.push_back( pList );
					SerializeList( ar, *pList );
				}

				ar.Close();
			}
			catch ( CException* pException )
			{
				ar.Abort();
				pFile.Abort();
				pException->Delete();
				bFailed = true;
			}
			if ( ! bFailed )
				pFile.Close();
		}
		catch ( CException* pException )
		{
			pFile.Abort();
			pException->Delete();
			bFailed = true;
		}

		if ( bFailed )
		{
			for ( size_t i = 0 ; i < pLoaded.size() ; ++i )
				delete pLoaded[ i ];
			pLoaded.clear();

			// Keep the unreadable file aside under a new name, never over an
			// earlier one, so Save does not overwrite the user's subscriptions
			// with an empty set. If it cannot be moved, Save must not write.
			CString strBad;
			strBad.Format( _T("%s.%lu.bad"), (LPCTSTR)strFile, static_cast< DWORD >( time( NULL ) ) );
			if ( ! MoveFileEx( strFile, strBad, MOVEFILE_COPY_ALLOWED ) )
				m_bSaveBlocked = true;
			theApp.Message( MSG_ERROR, _T("Failed to load IP lists: %s"), (LPCTSTR)strFile );
			bResult = FALSE;
		}
	}
	else if ( pError.m_lOsError != ERROR_FILE_NOT_FOUND && pError.m_lOsError != ERROR_PATH_NOT_FOUND )
	{
		// The file exists but cannot be opened (sharing violation, access
		// denied): never replace it with this session's empty set.
		m_bSaveBlocked = true;
		theApp.Message( MSG_ERROR, _T("Failed to load IP lists: %s"), (LPCTSTR)strFile );
		bResult = FALSE;
	}
	// Otherwise no file: no lists yet.

	// The cached ranges. Never parsed or downloaded here.
	for ( size_t i = 0 ; i < pLoaded.size() ; ++i )
	{
		CIPList* pList = pLoaded[ i ];
		pList->m_pRanges.reset();

		const CacheResult nCache = ReadCache( pList->m_oGUID, pList->m_pRanges );
		if ( nCache == cacheBad || ( nCache == cacheMissing && pList->m_tLastSuccess != 0 ) )
		{
			pList->m_pRanges.reset();
			// An import has no URL to download from; it must be imported again.
			pList->m_sStatus = LoadString( pList->m_pURLs.GetSize() > 0 ?
				IDS_IPLIST_CACHE_BAD : IDS_IPLIST_CACHE_BAD_IMPORT );
			pList->m_tLastSuccess = 0;
			pList->m_bLastFailed = FALSE;	// due as soon as updates may start
			theApp.Message( MSG_ERROR, _T("Failed to load IP list: %s"), (LPCTSTR)CachePath( pList->m_oGUID ) );
		}
	}

	{
		CQuickLock oLock( Security.m_pSection );
		m_pLists.swap( pLoaded );
	}

	// The previous lists (normally none), outside the lock
	for ( size_t i = 0 ; i < pLoaded.size() ; ++i )
		delete pLoaded[ i ];

	Security.ClearMissCache();

	return bResult;
}

BOOL CIPLists::Save()
{
	CQuickLock oFileLock( m_pFileSection );

	const CString strFile = Settings.General.UserPath + _T("\\Data\\IPLists.dat");

	if ( m_bSaveBlocked )
	{
		theApp.Message( MSG_ERROR, _T("Not saving IP lists: %s could not be loaded and is kept as it is"), (LPCTSTR)strFile );
		return FALSE;
	}

	std::vector< CIPList > pLists;
	Snapshot( pLists );

	const CString strTemp = Settings.General.UserPath + _T("\\Data\\IPLists.tmp");

	CFile pFile;
	if ( ! pFile.Open( strTemp, CFile::modeWrite | CFile::modeCreate | CFile::shareExclusive | CFile::osSequentialScan ) )
	{
		DeleteFile( strTemp );
		theApp.Message( MSG_ERROR, _T("Failed to save IP lists: %s"), (LPCTSTR)strTemp );
		return FALSE;
	}

	try
	{
		CArchive ar( &pFile, CArchive::store, 131072 );	// 128 KB buffer
		try
		{
			int nVersion = IPLISTS_SER_VERSION;
			ar << nVersion;

			ar.WriteCount( static_cast< DWORD_PTR >( pLists.size() ) );
			for ( size_t i = 0 ; i < pLists.size() ; ++i )
				SerializeList( ar, pLists[ i ] );

			ar.Close();
		}
		catch ( CException* pException )
		{
			ar.Abort();
			pFile.Abort();
			pException->Delete();
			DeleteFile( strTemp );
			theApp.Message( MSG_ERROR, _T("Failed to save IP lists: %s"), (LPCTSTR)strTemp );
			return FALSE;
		}
		pFile.Close();
	}
	catch ( CException* pException )
	{
		pFile.Abort();
		pException->Delete();
		DeleteFile( strTemp );
		theApp.Message( MSG_ERROR, _T("Failed to save IP lists: %s"), (LPCTSTR)strTemp );
		return FALSE;
	}

	if ( ! MoveFileEx( strTemp, strFile, MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING ) )
	{
		DeleteFile( strTemp );
		theApp.Message( MSG_ERROR, _T("Failed to save IP lists: %s"), (LPCTSTR)strFile );
		return FALSE;
	}

	return TRUE;
}


//////////////////////////////////////////////////////////////////////
// CIPLists changes

CIPList* CIPLists::Add(const CString& sName, const CStringArray& pURLs, const CString& sSource)
{
	CIPList* pList = new CIPList();
	CoCreateGuid( &pList->m_oGUID );
	pList->m_sName = sName;
	pList->m_pURLs.Copy( pURLs );
	pList->m_sSource = sSource;

	{
		CQuickLock oLock( Security.m_pSection );
		m_pLists.push_back( pList );
	}

	Security.ClearMissCache();

	return pList;
}

BOOL CIPLists::Remove(const GUID& oGUID)
{
	CQuickLock oFileLock( m_pFileSection );

	CIPList* pRemoved = NULL;
	{
		CQuickLock oLock( Security.m_pSection );
		for ( std::vector< CIPList* >::iterator i = m_pLists.begin() ; i != m_pLists.end() ; ++i )
		{
			if ( (*i)->m_oGUID == oGUID )
			{
				pRemoved = *i;
				m_pLists.erase( i );
				break;
			}
		}
	}

	if ( ! pRemoved )
		return FALSE;

	DeleteFile( CachePath( oGUID ) );
	delete pRemoved;	// frees its ranges outside the lock (unless a snapshot holds them)

	Security.ClearMissCache();

	return TRUE;
}

void CIPLists::SetEnabled(const GUID& oGUID, BOOL bEnabled)
{
	bool bChanged = false;
	bool bNowEnabled = false;
	{
		CQuickLock oLock( Security.m_pSection );
		if ( CIPList* pList = Find( oGUID ) )
		{
			bChanged = ( ( pList->m_bEnabled != FALSE ) != ( bEnabled != FALSE ) );
			pList->m_bEnabled = bEnabled ? TRUE : FALSE;
			bNowEnabled = ( bEnabled != FALSE );
		}
	}

	if ( bChanged )
	{
		Security.ClearMissCache();

		// Drop connected hosts the list now denies
		if ( bNowEnabled )
			PostMainWndMessage( WM_SANITY_CHECK );
	}
}

bool CIPLists::SetRanges(const GUID& oGUID, std::shared_ptr< const IPList::RangeSet > pRanges, DWORD tWhen)
{
	// Only a finished set that passed the sanity checks may replace a list's
	// ranges; anything else is a caller's bug, and the old copy stays.
	if ( ! pRanges || ! pRanges->IsFinished() ||
		IPList::CheckSanity( *pRanges ) != IPList::Refusal::None )
	{
		ASSERT( FALSE );
		return false;
	}

	const std::vector< uint8_t > pBytes = IPList::Serialize( *pRanges );
	if ( pBytes.empty() )
	{
		ASSERT( FALSE );
		return false;
	}

	// Held to the end, so Remove cannot delete the list, or its file, between
	// the write and the swap.
	CQuickLock oFileLock( m_pFileSection );

	{
		CQuickLock oLock( Security.m_pSection );
		if ( ! Find( oGUID ) )
			return false;
	}

	if ( ! WriteCache( oGUID, pBytes ) )
		return false;

	std::shared_ptr< const IPList::RangeSet > pOld;
	{
		CQuickLock oLock( Security.m_pSection );
		CIPList* pList = Find( oGUID );
		ASSERT( pList );	// only Remove deletes lists, and it waits for m_pFileSection
		if ( ! pList )
			return false;

		pOld = pList->m_pRanges;
		pList->m_pRanges = pRanges;
		pList->m_tLastSuccess = tWhen;
		pList->m_tLastAttempt = tWhen;
		pList->m_bLastFailed = FALSE;
		pList->m_sStatus.Empty();
	}

	pOld.reset();	// frees the previous ranges outside the lock

	Security.ClearMissCache();

	// Drop connected hosts the new ranges deny
	PostMainWndMessage( WM_SANITY_CHECK );

	return true;
}

void CIPLists::SetFailed(const GUID& oGUID, const CString& sReason, DWORD tWhen)
{
	CQuickLock oLock( Security.m_pSection );
	if ( CIPList* pList = Find( oGUID ) )
	{
		pList->m_tLastAttempt = tWhen;
		pList->m_bLastFailed = TRUE;
		pList->m_sStatus = sReason;
	}
}


//////////////////////////////////////////////////////////////////////
// CIPLists matching (caller holds Security.m_pSection)

bool CIPLists::IsDenied(DWORD nHostOrder)
{
	if ( Reserved::IsLocalV4( nHostOrder ) )
		return false;

	for ( size_t i = 0 ; i < m_pLists.size() ; ++i )
	{
		CIPList* pList = m_pLists[ i ];
		if ( pList->m_bEnabled && pList->m_pRanges && pList->m_pRanges->ContainsV4( nHostOrder ) )
		{
			pList->m_nToday ++;
			pList->m_nEver ++;
			return true;
		}
	}
	return false;
}

bool CIPLists::IsDenied(const IN6_ADDR& a)
{
	if ( Reserved::IsLocalV6( a.u.Byte ) )
		return false;

	IPList::Addr6 oAddress;
	memcpy( oAddress.b, a.u.Byte, sizeof( oAddress.b ) );

	for ( size_t i = 0 ; i < m_pLists.size() ; ++i )
	{
		CIPList* pList = m_pLists[ i ];
		if ( pList->m_bEnabled && pList->m_pRanges && pList->m_pRanges->ContainsV6( oAddress ) )
		{
			pList->m_nToday ++;
			pList->m_nEver ++;
			return true;
		}
	}
	return false;
}


//////////////////////////////////////////////////////////////////////
// CIPLists queries

std::vector< GUID > CIPLists::GetDue(DWORD tNow, DWORD tStarted) const
{
	std::vector< GUID > pDue;

	CQuickLock oLock( Security.m_pSection );
	for ( size_t i = 0 ; i < m_pLists.size() ; ++i )
	{
		const CIPList* pList = m_pLists[ i ];
		if ( pList->m_bEnabled && pList->m_pURLs.GetSize() > 0 &&
			IPList::IsDue( tNow, tStarted, pList->m_tLastSuccess, pList->m_tLastAttempt, pList->m_bLastFailed != FALSE ) )
		{
			pDue.push_back( pList->m_oGUID );
		}
	}
	return pDue;
}

void CIPLists::Snapshot(std::vector< CIPList >& out) const
{
	std::vector< CIPList > pCopy;
	{
		CQuickLock oLock( Security.m_pSection );
		pCopy.reserve( m_pLists.size() );
		for ( size_t i = 0 ; i < m_pLists.size() ; ++i )
			pCopy.push_back( *m_pLists[ i ] );
	}
	out.swap( pCopy );	// the caller's previous copies are freed outside the lock
}
