//
// IPListUpdater.cpp
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
#include "Buffer.h"
#include "IPLists.h"
#include "IPListCatalogue.h"
#include "IPListUpdater.h"

// minizip, as built into zlibwapi (zlibwapi.props puts it on the include path)
#include <unzip.h>

#include <string>

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

CIPListUpdater IPListUpdater;

// The Windows oracle (oracle-windows.yml) lists these hosts; update it too.
const CatalogueEntry kCatalogue[ 5 ] =
{
	{ _T("Spamhaus DROP"), IDS_IPLIST_NOTE_SPAMHAUS,
		{ _T("https://www.spamhaus.org/drop/drop_v4.json"),
		  _T("https://www.spamhaus.org/drop/drop_v6.json") } },
	{ _T("Emerging Threats compromised IPs"), IDS_IPLIST_NOTE_EMTHREATS,
		{ _T("https://rules.emergingthreats.net/blockrules/compromised-ips.txt"), NULL } },
	{ _T("eMule-Security ipfilter"), IDS_IPLIST_NOTE_EMULE,
		{ _T("https://upd.emule-security.org/ipfilter.zip"), NULL } },
	{ _T("CombinedPrivacy"), IDS_IPLIST_NOTE_COMBINED,
		{ _T("https://raw.githubusercontent.com/bongochong/CombinedPrivacyBlockLists/master/combined-final.p2p"), NULL } },
	{ _T("Team Cymru fullbogons"), IDS_IPLIST_NOTE_FULLBOGONS,
		{ _T("https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt"),
		  _T("https://www.team-cymru.org/Services/Bogons/fullbogons-ipv6.txt") } },
};


//////////////////////////////////////////////////////////////////////
// Helpers

namespace
{

bool IsHttps(const CString& sURL)
{
	return _tcsnicmp( sURL, _T("https://"), 8 ) == 0;
}

// A copy of the list with that GUID; false if there is none.
bool FindList(const GUID& oGUID, CIPList& oOut)
{
	std::vector< CIPList > pLists;
	IPLists.Snapshot( pLists );
	for ( size_t i = 0 ; i < pLists.size() ; ++i )
	{
		if ( pLists[ i ].m_oGUID == oGUID )
		{
			oOut = pLists[ i ];
			return true;
		}
	}
	return false;
}

enum class Inflated
{
	OK,
	Failed,			// not readable as gzip or zip
	TooLarge,		// more than kMaxInflated bytes
	Cancelled		// the thread was asked to stop
};

const uInt   kChunk   = 65536;	// bytes handed to the sink at a time
const size_t kMaxLine = 65536;	// longest line kept across chunks

// Text goes to IPList::ParseText in whole lines, so a line split between two
// chunks is parsed once, whole. Every byte counts against IPList::kMaxInflated,
// shared by all the sinks of one file through nTotal. A line longer than
// kMaxLine is not kept: it counts as one rejected line and the input is skipped
// to the next '\n'. Each Add first checks that pThread (if any) may continue.
class CTextSink
{
public:
	CTextSink(IPList::RangeSet& oOut, IPList::ParseStats& oStats, uint64_t& nTotal,
		const CThreadImpl* pThread)
		: m_oOut( oOut ), m_oStats( oStats ), m_nTotal( nTotal ), m_pThread( pThread )
		, m_bSkipping( false ), m_nStop( Inflated::OK ) {}

	// False, adding nothing, when the thread is asked to stop or the content
	// would exceed kMaxInflated; Stop() then says which.
	bool Add(const char* p, size_t n)
	{
		if ( m_pThread && ! m_pThread->IsThreadEnabled() )
		{
			m_nStop = Inflated::Cancelled;
			return false;
		}
		if ( n > IPList::kMaxInflated - m_nTotal )	// m_nTotal <= kMaxInflated
		{
			m_nStop = Inflated::TooLarge;
			return false;
		}
		m_nTotal += n;

		const char* const pEnd = p + n;
		if ( m_bSkipping )
		{
			const char* pEol = static_cast< const char* >( memchr( p, '\n', n ) );
			if ( ! pEol )
				return true;
			p = pEol + 1;
			m_bSkipping = false;
		}

		const char* pRest = NULL;				// just past the last '\n'
		for ( const char* q = pEnd ; q > p ; )
		{
			if ( *--q == '\n' )
			{
				pRest = q + 1;
				break;
			}
		}
		if ( ! pRest )
		{
			Carry( p, pEnd );
			return true;
		}

		if ( ! m_sCarry.empty() )
		{
			// Complete the carried line with this chunk's first line
			const char* pEol = static_cast< const char* >(
				memchr( p, '\n', static_cast< size_t >( pEnd - p ) ) );
			const size_t nFirst = static_cast< size_t >( pEol - p );	// without '\n'
			if ( m_sCarry.size() + nFirst > kMaxLine )
			{
				++m_oStats.rejected;
			}
			else
			{
				m_sCarry.append( p, nFirst + 1 );
				IPList::ParseText( m_sCarry.data(), m_sCarry.size(), m_oOut, m_oStats );
			}
			m_sCarry.clear();
			p = pEol + 1;
		}
		if ( pRest > p )
			IPList::ParseText( p, static_cast< size_t >( pRest - p ), m_oOut, m_oStats );
		Carry( pRest, pEnd );
		return true;
	}

	// Parses the last line, if it has no '\n'.
	void Flush()
	{
		if ( ! m_sCarry.empty() )
			IPList::ParseText( m_sCarry.data(), m_sCarry.size(), m_oOut, m_oStats );
		std::string().swap( m_sCarry );
		m_bSkipping = false;
	}

	Inflated Stop() const { return m_nStop; }

private:
	IPList::RangeSet&	m_oOut;
	IPList::ParseStats&	m_oStats;
	uint64_t&			m_nTotal;
	const CThreadImpl*	m_pThread;
	std::string			m_sCarry;
	bool				m_bSkipping;	// dropping the rest of an overlong line
	Inflated			m_nStop;

	// Keeps [p, pEnd), the start of a line, unless the line grows past kMaxLine.
	void Carry(const char* p, const char* pEnd)
	{
		const size_t n = static_cast< size_t >( pEnd - p );
		if ( m_sCarry.size() + n > kMaxLine )
		{
			std::string().swap( m_sCarry );
			++m_oStats.rejected;
			m_bSkipping = true;
		}
		else
		{
			m_sCarry.append( p, n );
		}
	}

	CTextSink(const CTextSink&);
	CTextSink& operator=(const CTextSink&);
};

// A gzip file, possibly of several members one after another.
Inflated Gunzip(const BYTE* pData, DWORD nData, CTextSink& oSink)
{
	z_stream oStream;
	ZeroMemory( &oStream, sizeof( oStream ) );
	if ( inflateInit2( &oStream, 16 + MAX_WBITS ) != Z_OK )	// 16: gzip wrapper
		return Inflated::Failed;

	oStream.next_in  = const_cast< Bytef* >( pData );
	oStream.avail_in = static_cast< uInt >( nData );

	std::vector< char > pOut( kChunk );
	Inflated nResult = Inflated::Failed;
	for ( ;; )
	{
		oStream.next_out  = reinterpret_cast< Bytef* >( &pOut[ 0 ] );
		oStream.avail_out = kChunk;
		const int nError = CBuffer::Inflate( &oStream, Z_NO_FLUSH );

		const size_t nOut = kChunk - oStream.avail_out;
		if ( nOut && ! oSink.Add( &pOut[ 0 ], nOut ) )
		{
			nResult = oSink.Stop();
			break;
		}

		if ( nError == Z_STREAM_END )
		{
			if ( oStream.avail_in >= 2 && oStream.next_in[ 0 ] == 0x1F && oStream.next_in[ 1 ] == 0x8B )
			{
				if ( inflateReset( &oStream ) != Z_OK )
					break;
				continue;
			}
			nResult = Inflated::OK;		// trailing bytes that are not gzip are ignored, as gzip does
			break;
		}
		if ( nError != Z_OK )			// Z_BUF_ERROR here: the file is truncated
			break;
	}
	inflateEnd( &oStream );

	if ( nResult == Inflated::OK )
		oSink.Flush();
	return nResult;
}

// minizip reads the zip from memory through these.
struct CMemoryFile
{
	const BYTE*	pData;
	uLong		nData;
	uLong		nPos;
};

voidpf ZCALLBACK MemOpen(voidpf opaque, const char* /*filename*/, int mode)
{
	if ( mode & ZLIB_FILEFUNC_MODE_WRITE )
		return NULL;
	CMemoryFile* pFile = static_cast< CMemoryFile* >( opaque );
	pFile->nPos = 0;
	return pFile;
}

uLong ZCALLBACK MemRead(voidpf /*opaque*/, voidpf stream, void* buf, uLong size)
{
	CMemoryFile* pFile = static_cast< CMemoryFile* >( stream );
	const uLong nAvailable = pFile->nData - pFile->nPos;
	if ( size > nAvailable )
		size = nAvailable;
	memcpy( buf, pFile->pData + pFile->nPos, size );
	pFile->nPos += size;
	return size;
}

uLong ZCALLBACK MemWrite(voidpf /*opaque*/, voidpf /*stream*/, const void* /*buf*/, uLong /*size*/)
{
	return 0;
}

long ZCALLBACK MemTell(voidpf /*opaque*/, voidpf stream)
{
	return static_cast< long >( static_cast< CMemoryFile* >( stream )->nPos );
}

long ZCALLBACK MemSeek(voidpf /*opaque*/, voidpf stream, uLong offset, int origin)
{
	CMemoryFile* pFile = static_cast< CMemoryFile* >( stream );
	uint64_t nBase;
	switch ( origin )
	{
	case ZLIB_FILEFUNC_SEEK_SET:
		nBase = 0;
		break;
	case ZLIB_FILEFUNC_SEEK_CUR:
		nBase = pFile->nPos;
		break;
	case ZLIB_FILEFUNC_SEEK_END:
		nBase = pFile->nData;
		break;
	default:
		return -1;
	}
	const uint64_t nPos = nBase + offset;
	if ( nPos > pFile->nData )
		return -1;
	pFile->nPos = static_cast< uLong >( nPos );
	return 0;
}

int ZCALLBACK MemClose(voidpf /*opaque*/, voidpf /*stream*/)
{
	return 0;
}

int ZCALLBACK MemError(voidpf /*opaque*/, voidpf /*stream*/)
{
	return 0;
}

// Every member of a zip file, each parsed as text. Only the 32-bit minizip API
// is used: the client may compile against either minizip header in the tree,
// and both declare it alike. A member's declared size is checked against what
// is left of kMaxInflated before it is read, and what is read must match it
// (a zip64 size does not fit the 32-bit field, so it cannot match).
Inflated Unzip(const BYTE* pData, DWORD nData, IPList::RangeSet& oOut,
	IPList::ParseStats& oStats, uint64_t& nTotal, const CThreadImpl* pThread)
{
	CMemoryFile oFile = { pData, nData, 0 };
	zlib_filefunc_def oFuncs =
	{
		MemOpen, MemRead, MemWrite, MemTell, MemSeek, MemClose, MemError, &oFile
	};

	unzFile hZip = unzOpen2( "", &oFuncs );
	if ( ! hZip )
		return Inflated::Failed;

	std::vector< char > pOut( kChunk );
	Inflated nResult = Inflated::Failed;
	int nError = unzGoToFirstFile( hZip );
	for ( ; nError == UNZ_OK ; nError = unzGoToNextFile( hZip ) )
	{
		unz_file_info oInfo;
		if ( unzGetCurrentFileInfo( hZip, &oInfo, NULL, 0, NULL, 0, NULL, 0 ) != UNZ_OK )
			break;
		if ( oInfo.flag & 1 )			// encrypted
			break;
		if ( oInfo.uncompressed_size > IPList::kMaxInflated - nTotal )
		{
			nResult = Inflated::TooLarge;
			break;
		}
		if ( unzOpenCurrentFile( hZip ) != UNZ_OK )
			break;

		CTextSink oSink( oOut, oStats, nTotal, pThread );
		uint64_t nMember = 0;
		bool bStopped = false;
		int nRead = 0;
		while ( ( nRead = unzReadCurrentFile( hZip, &pOut[ 0 ], kChunk ) ) > 0 )
		{
			nMember += static_cast< uint64_t >( nRead );
			if ( nMember > oInfo.uncompressed_size )
			{
				bStopped = true;		// more than declared
				break;
			}
			if ( ! oSink.Add( &pOut[ 0 ], static_cast< size_t >( nRead ) ) )
			{
				nResult = oSink.Stop();
				bStopped = true;
				break;
			}
		}
		// Reports a CRC mismatch once the whole member has been read
		const int nClose = unzCloseCurrentFile( hZip );
		if ( bStopped || nRead < 0 || nClose != UNZ_OK || nMember != oInfo.uncompressed_size )
			break;
		oSink.Flush();
	}
	if ( nError == UNZ_END_OF_LIST_OF_FILE )
		nResult = Inflated::OK;

	unzClose( hZip );
	return nResult;
}

// One file's content, by its first bytes: gzip, zip or text.
Inflated ParseFile(const BYTE* pData, DWORD nData, IPList::RangeSet& oOut,
	IPList::ParseStats& oStats, const CThreadImpl* pThread)
{
	uint64_t nTotal = 0;

	if ( nData >= 2 && pData[ 0 ] == 0x1F && pData[ 1 ] == 0x8B )
	{
		CTextSink oSink( oOut, oStats, nTotal, pThread );
		return Gunzip( pData, nData, oSink );
	}
	if ( nData >= 4 && pData[ 0 ] == 'P' && pData[ 1 ] == 'K' && pData[ 2 ] == 3 && pData[ 3 ] == 4 )
	{
		return Unzip( pData, nData, oOut, oStats, nTotal, pThread );
	}

	// Plain text, in chunks too, so a stop request is seen
	CTextSink oSink( oOut, oStats, nTotal, pThread );
	for ( DWORD nPos = 0 ; nPos < nData ; )
	{
		const DWORD nPart = ( nData - nPos < kChunk ) ? ( nData - nPos ) : kChunk;
		if ( ! oSink.Add( reinterpret_cast< const char* >( pData + nPos ), nPart ) )
			return oSink.Stop();
		nPos += nPart;
	}
	oSink.Flush();
	return Inflated::OK;
}

}	// namespace


//////////////////////////////////////////////////////////////////////
// CIPListUpdater construction

CIPListUpdater::CIPListUpdater()
	: m_oCurrent( GUID_NULL )
	, m_bBusy( false )
	, m_bStarted( false )
	, m_tStarted( 0 )
{
}

CIPListUpdater::~CIPListUpdater()
{
	Stop();
}

//////////////////////////////////////////////////////////////////////
// CIPListUpdater control (main thread)

void CIPListUpdater::Start()
{
	CQuickLock oLock( m_pSection );
	m_tStarted = static_cast< DWORD >( time( NULL ) );
	m_bStarted = true;
}

void CIPListUpdater::Stop()
{
	{
		CQuickLock oLock( m_pSection );
		m_bStarted = false;
		m_pQueue.clear();
	}

	// The thread cancels its own download and parsing when it sees the request
	// (Fetch, LoadAndParse), so m_pRequest is only ever touched by the thread,
	// and it is waited for without a timeout: it must never be terminated
	// while it holds a lock (IPLists' file lock, Security.m_pSection, the heap).
	CloseThread( INFINITE );
}

void CIPListUpdater::OnTimer60()
{
	DWORD tStarted;
	{
		CQuickLock oLock( m_pSection );
		if ( ! m_bStarted )
			return;
		tStarted = m_tStarted;
	}

	Enqueue( IPLists.GetDue( static_cast< DWORD >( time( NULL ) ), tStarted ), false );
}

void CIPListUpdater::UpdateNow(const std::vector< GUID >& oLists)
{
	if ( ! oLists.empty() )
	{
		Enqueue( oLists, true );
		return;
	}

	std::vector< CIPList > pLists;
	IPLists.Snapshot( pLists );

	std::vector< GUID > pAll;
	for ( size_t i = 0 ; i < pLists.size() ; ++i )
	{
		if ( pLists[ i ].m_pURLs.GetSize() > 0 )
			pAll.push_back( pLists[ i ].m_oGUID );
	}
	Enqueue( pAll, true );
}

void CIPListUpdater::Enqueue(const std::vector< GUID >& oLists, bool bForced)
{
	{
		CQuickLock oLock( m_pSection );
		if ( ! m_bStarted )
			return;

		for ( size_t i = 0 ; i < oLists.size() ; ++i )
		{
			const GUID& oGUID = oLists[ i ];
			if ( m_bBusy && m_oCurrent == oGUID )
				continue;
			bool bQueued = false;
			for ( size_t j = 0 ; j < m_pQueue.size() ; ++j )
			{
				if ( m_pQueue[ j ].oGUID == oGUID )
				{
					m_pQueue[ j ].bForced = m_pQueue[ j ].bForced || bForced;
					bQueued = true;
					break;
				}
			}
			if ( ! bQueued )
			{
				const QueueItem oItem = { oGUID, bForced };
				m_pQueue.push_back( oItem );
			}
		}
	}

	StartThread();
}

void CIPListUpdater::StartThread()
{
	{
		CQuickLock oLock( m_pSection );
		if ( ! m_bStarted || m_pQueue.empty() )
			return;
	}

	// Does nothing while the thread is alive. A thread that has just found the
	// queue empty may still be alive for a moment; the next OnTimer60 starts a
	// new one for anything queued meanwhile.
	BeginThread( "IPListUpdater", THREAD_PRIORITY_BELOW_NORMAL );
}

//////////////////////////////////////////////////////////////////////
// CIPListUpdater thread

void CIPListUpdater::OnRun()
{
	while ( IsThreadEnabled() )
	{
		GUID oGUID;
		bool bForced;
		{
			CQuickLock oLock( m_pSection );
			if ( m_pQueue.empty() )
				break;
			oGUID = m_pQueue.front().oGUID;
			bForced = m_pQueue.front().bForced;
			m_pQueue.erase( m_pQueue.begin() );
			m_oCurrent = oGUID;
			m_bBusy = true;
		}

		// Read the list now: it may have changed or gone since it was queued.
		// A list queued because it was due is skipped if it was disabled since.
		CIPList oList;
		if ( FindList( oGUID, oList ) && oList.m_pURLs.GetSize() > 0 &&
			( bForced || oList.m_bEnabled ) )
		{
			Update( oList );
		}

		CQuickLock oLock( m_pSection );
		m_bBusy = false;
	}

	m_pRequest.Clear();		// frees the last response
}

void CIPListUpdater::Update(const CIPList& oList)
{
	IPList::RangeSet oRanges;
	IPList::ParseStats oStats;
	CString sError;

	bool bOK = true;
	for ( INT_PTR i = 0 ; bOK && i < oList.m_pURLs.GetSize() ; ++i )
	{
		bOK = Fetch( oList.m_pURLs.GetAt( i ), oRanges, oStats, sError );
	}
	m_pRequest.Clear();

	// Stopping: record nothing
	if ( ! IsThreadEnabled() )
		return;

	// Removed while it was being fetched: nothing to record
	CIPList oCurrent;
	if ( ! FindList( oList.m_oGUID, oCurrent ) )
		return;

	if ( bOK )
	{
		oRanges.Finish();
		const IPList::Refusal nRefusal = IPList::CheckSanity( oRanges );
		if ( nRefusal != IPList::Refusal::None )
		{
			bOK = false;
			sError = LoadString( RefusalString( nRefusal ) );
		}
	}

	const DWORD tNow = static_cast< DWORD >( time( NULL ) );

	if ( bOK )
	{
		// Checked again: Stop waits for this thread without a timeout
		if ( ! IsThreadEnabled() )
			return;

		std::shared_ptr< const IPList::RangeSet > pRanges =
			std::make_shared< IPList::RangeSet >( std::move( oRanges ) );
		if ( IPLists.SetRanges( oList.m_oGUID, pRanges, tNow ) )
		{
			theApp.Message( MSG_INFO, IDS_IPLIST_LOG_UPDATED, (LPCTSTR)oList.m_sName,
				static_cast< DWORD >( oStats.taken ), static_cast< DWORD >( oStats.rejected ),
				static_cast< DWORD >( pRanges->CountV4() + pRanges->CountV6() ) );
			return;
		}
		if ( ! FindList( oList.m_oGUID, oCurrent ) )
			return;		// removed meanwhile, not a failure
		sError = LoadString( IDS_IPLIST_ERR_SAVE );
	}

	IPLists.SetFailed( oList.m_oGUID, sError, tNow );
	theApp.Message( MSG_NOTICE, IDS_IPLIST_LOG_FAILED, (LPCTSTR)oList.m_sName, (LPCTSTR)sError );
}

bool CIPListUpdater::Fetch(const CString& sURL, IPList::RangeSet& oRanges, IPList::ParseStats& oStats, CString& sError)
{
	if ( ! IsHttps( sURL ) )
	{
		sError = LoadString( IDS_IPLIST_ERR_NOT_HTTPS );
		return false;
	}

	// CHttpRequest::SetURL compares the scheme case-sensitively
	const CString sRequestURL = _T("https://") + sURL.Mid( 8 );

	m_pRequest.Clear();
	if ( ! IsThreadEnabled() || ! m_pRequest.SetURL( sRequestURL ) )
	{
		sError = LoadString( IDS_IPLIST_ERR_NO_RESPONSE );
		return false;
	}
	m_pRequest.LimitContentLength( IPList::kMaxDownload );
	m_pRequest.EnableCookie( false );
	if ( ! m_pRequest.Execute( true ) )
	{
		sError = LoadString( IDS_IPLIST_ERR_NO_RESPONSE );
		return false;
	}
	while ( m_pRequest.IsPending() )
	{
		if ( ! IsThreadEnabled( 100 ) )
		{
			m_pRequest.Cancel();	// closes the connection and waits for the request thread
			return false;
		}
	}

	const CBuffer* pResponse = m_pRequest.GetResponseBuffer();
	const CString sFinalURL = m_pRequest.GetFinalURL();
	const int nStatus = m_pRequest.GetStatusCode();

	// CHttpRequest stops reading once the response passes the limit, without
	// a status code; the length tells.
	if ( pResponse && pResponse->m_nLength > IPList::kMaxDownload )
	{
		sError = LoadString( IDS_IPLIST_ERR_TOO_LARGE );
		return false;
	}
	if ( nStatus == 0 && sFinalURL.IsEmpty() )
	{
		sError = LoadString( IDS_IPLIST_ERR_NO_RESPONSE );
		return false;
	}
	// Redirected away from HTTPS, or the address could not be read
	if ( ! IsHttps( sFinalURL ) )
	{
		sError = LoadString( IDS_IPLIST_ERR_FINAL_NOT_HTTPS );
		return false;
	}
	if ( nStatus == 0 || ! pResponse )
	{
		sError = LoadString( IDS_IPLIST_ERR_NO_RESPONSE );
		return false;
	}
	if ( nStatus < 200 || nStatus > 299 )
	{
		sError.Format( LoadString( IDS_IPLIST_ERR_HTTP_STATUS ), nStatus );
		return false;
	}

	return LoadAndParse( *pResponse, oRanges, oStats, sError, this ) != FALSE;
}

//////////////////////////////////////////////////////////////////////
// CIPListUpdater file contents

UINT CIPListUpdater::RefusalString(IPList::Refusal nRefusal)
{
	switch ( nRefusal )
	{
	case IPList::Refusal::Empty:
		return IDS_IPLIST_ERR_EMPTY;
	case IPList::Refusal::TooManyRanges:
		return IDS_IPLIST_ERR_TOO_MANY;
	case IPList::Refusal::V4RangeTooWide:
		return IDS_IPLIST_ERR_V4_TOO_WIDE;
	case IPList::Refusal::V4CoverageTooHigh:
		return IDS_IPLIST_ERR_V4_COVERAGE;
	case IPList::Refusal::V6CoversGlobalUnicast:
	default:
		return IDS_IPLIST_ERR_V6_GLOBAL;
	}
}

BOOL CIPListUpdater::LoadAndParse(const CBuffer& oData, IPList::RangeSet& oOut, IPList::ParseStats& oStats, CString& sError, const CThreadImpl* pThread)
{
	const Inflated nResult = ParseFile( oData.m_pBuffer, oData.m_nLength, oOut, oStats, pThread );

	switch ( nResult )
	{
	case Inflated::OK:
		return TRUE;
	case Inflated::TooLarge:
		sError = LoadString( IDS_IPLIST_ERR_INFLATED_TOO_LARGE );
		return FALSE;
	case Inflated::Cancelled:
		sError.Empty();
		return FALSE;
	default:
		sError = LoadString( IDS_IPLIST_ERR_DECOMPRESS );
		return FALSE;
	}
}
