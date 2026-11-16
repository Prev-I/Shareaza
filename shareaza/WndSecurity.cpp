//
// WndSecurity.cpp
//
// Copyright (c) Shareaza Development Team, 2002-2012.
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

#include "StdAfx.h"
#include "Shareaza.h"
#include "Buffer.h"
#include "Settings.h"
#include "Security.h"
#include "LiveList.h"
#include "WndSecurity.h"
#include "DlgSecureRule.h"
#include "DlgIPListAdd.h"
#include "CoolInterface.h"
#include "Skin.h"
#include "SchemaCache.h"
#include "XML.h"
#include "IPLists.h"
#include "IPListUpdater.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#define SPLIT_SIZE		6
#define TOOLBAR_HEIGHT	28
#define CAPTION_HEIGHT	20

const static UINT nImageID[] =
{
	IDR_SECURITYFRAME,
	IDI_GRANTED,
	IDI_FIREWALLED,
	NULL
};

namespace
{

// Shareaza's own export format: '<' first, after an optional UTF-8 or UTF-16
// byte order mark and whitespace.
bool IsXMLFile(const BYTE* pData, DWORD nData)
{
	DWORD nPos = 0;
	DWORD nStep = 1;	// bytes per character
	DWORD nLow = 0;		// offset of the byte that holds an ASCII character
	if ( nData >= 3 && pData[ 0 ] == 0xEF && pData[ 1 ] == 0xBB && pData[ 2 ] == 0xBF )
	{
		nPos = 3;
	}
	else if ( nData >= 2 && pData[ 0 ] == 0xFF && pData[ 1 ] == 0xFE )
	{
		nPos = 2;
		nStep = 2;
	}
	else if ( nData >= 2 && pData[ 0 ] == 0xFE && pData[ 1 ] == 0xFF )
	{
		nPos = 2;
		nStep = 2;
		nLow = 1;
	}

	for ( ; nData - nPos >= nStep ; nPos += nStep )
	{
		if ( nStep == 2 && pData[ nPos + 1 - nLow ] != 0 )
			return false;
		const BYTE c = pData[ nPos + nLow ];
		if ( c == ' ' || c == '\t' || c == '\r' || c == '\n' )
			continue;
		return c == '<';
	}
	return false;
}

// Reads the whole file into oData. FALSE if it cannot be read, or if it is
// larger than IPList::kMaxDownload (bTooLarge is then set and nothing read).
BOOL ReadImportFile(LPCTSTR pszFile, CBuffer& oData, bool& bTooLarge)
{
	bTooLarge = false;

	CFile pFile;
	if ( ! pFile.Open( pszFile, CFile::modeRead | CFile::shareDenyWrite ) )
		return FALSE;

	try
	{
		const ULONGLONG nLength = pFile.GetLength();
		if ( nLength > IPList::kMaxDownload )
		{
			bTooLarge = true;
			return FALSE;
		}

		const DWORD nSize = static_cast< DWORD >( nLength );
		if ( nSize )
		{
			if ( ! oData.EnsureBuffer( nSize ) )
				return FALSE;
			if ( pFile.Read( oData.m_pBuffer, nSize ) != nSize )
				return FALSE;
			oData.m_nLength = nSize;
		}
	}
	catch ( CException* pException )
	{
		pException->Delete();
		return FALSE;
	}

	return TRUE;
}

// Parses any file other than Shareaza XML into an IP list named after the
// file. Re-importing a file of the same name replaces that list's ranges.
// Reports the outcome in a message box.
void ImportIPList(const CString& strName, const CBuffer& pBuffer)
{
	IPList::RangeSet oRanges;
	IPList::ParseStats oStats;
	CString strError;

	BOOL bOK = CIPListUpdater::LoadAndParse( pBuffer, oRanges, oStats, strError );
	if ( bOK )
	{
		oRanges.Finish();
		const IPList::Refusal nRefusal = IPList::CheckSanity( oRanges );
		if ( nRefusal != IPList::Refusal::None )
		{
			bOK = FALSE;
			strError = LoadString( CIPListUpdater::RefusalString( nRefusal ) );
		}
	}

	CString strMessage;

	if ( ! bOK )
	{
		strMessage.Format( LoadString( IDS_IPLIST_IMPORT_FAILED ), (LPCTSTR)strName, (LPCTSTR)strError );
		AfxMessageBox( strMessage, MB_ICONEXCLAMATION );
		return;
	}

	// An imported list has no URLs and remembers its file name
	GUID oGUID = {};
	bool bNew = true;
	{
		std::vector< CIPList > pLists;
		IPLists.Snapshot( pLists );
		for ( size_t i = 0 ; i < pLists.size() ; ++i )
		{
			if ( pLists[ i ].m_pURLs.GetSize() == 0 &&
				pLists[ i ].m_sSource.CompareNoCase( strName ) == 0 )
			{
				oGUID = pLists[ i ].m_oGUID;
				bNew = false;
				break;
			}
		}
	}

	if ( bNew )
	{
		const CStringArray pNoURLs;
		oGUID = IPLists.Add( strName, pNoURLs, strName )->m_oGUID;
	}

	const DWORD tNow = static_cast< DWORD >( time( NULL ) );
	const size_t nRanges = oRanges.CountV4() + oRanges.CountV6();	// after merging
	std::shared_ptr< const IPList::RangeSet > pRanges =
		std::make_shared< IPList::RangeSet >( std::move( oRanges ) );

	if ( IPLists.SetRanges( oGUID, pRanges, tNow ) )
	{
		IPLists.Save();
		strMessage.Format( LoadString( IDS_IPLIST_IMPORTED ), (LPCTSTR)strName,
			nRanges, oStats.rejected );
		AfxMessageBox( strMessage, MB_ICONINFORMATION );
		return;
	}

	strError = LoadString( IDS_IPLIST_ERR_SAVE );
	if ( bNew )
	{
		// Leave no empty list behind
		IPLists.Remove( oGUID );
	}
	else
	{
		// The list keeps its previous ranges
		IPLists.SetFailed( oGUID, strError, tNow );
		IPLists.Save();
	}

	strMessage.Format( LoadString( IDS_IPLIST_IMPORT_FAILED ), (LPCTSTR)strName, (LPCTSTR)strError );
	AfxMessageBox( strMessage, MB_ICONEXCLAMATION );
}

// The Updated column: the last failure, a status note, "Imported", the time of
// the last update, or "not downloaded yet".
CString FormatListUpdated(const CIPList& oList)
{
	CString str;
	if ( oList.m_bLastFailed )
	{
		str.Format( LoadString( IDS_IPLIST_STATUS_FAILED ), (LPCTSTR)oList.m_sStatus );
	}
	else if ( oList.m_sStatus.GetLength() )
	{
		str = oList.m_sStatus;
	}
	else if ( oList.m_pURLs.GetSize() == 0 )
	{
		str = LoadString( IDS_IPLIST_STATUS_IMPORTED );
	}
	else if ( oList.m_tLastSuccess )
	{
		CTime pTime( (time_t)oList.m_tLastSuccess );
		str = pTime.Format( _T("%Y-%m-%d %H:%M") );
	}
	else
	{
		str = LoadString( IDS_IPLIST_STATUS_PENDING );
	}
	return str;
}

void SetListText(CListCtrl& wndList, int nItem, int nSubItem, const CString& strText)
{
	if ( wndList.GetItemText( nItem, nSubItem ) != strText )
		wndList.SetItemText( nItem, nSubItem, strText );
}

}	// namespace

IMPLEMENT_SERIAL(CSecurityWnd, CPanelWnd, 0)

BEGIN_MESSAGE_MAP(CSecurityWnd, CPanelWnd)
	ON_WM_CREATE()
	ON_WM_DESTROY()
	ON_WM_SIZE()
	ON_WM_TIMER()
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_RULES, OnCustomDrawList)
	ON_NOTIFY(NM_DBLCLK, IDC_RULES, OnDblClkList)
	ON_NOTIFY(LVN_COLUMNCLICK, IDC_RULES, OnSortList)
	ON_UPDATE_COMMAND_UI(ID_SECURITY_EDIT, OnUpdateSecurityEdit)
	ON_COMMAND(ID_SECURITY_EDIT, OnSecurityEdit)
	ON_UPDATE_COMMAND_UI(ID_SECURITY_RESET, OnUpdateSecurityReset)
	ON_COMMAND(ID_SECURITY_RESET, OnSecurityReset)
	ON_UPDATE_COMMAND_UI(ID_SECURITY_REMOVE, OnUpdateSecurityRemove)
	ON_COMMAND(ID_SECURITY_REMOVE, OnSecurityRemove)
	ON_COMMAND(ID_SECURITY_ADD, OnSecurityAdd)
	ON_UPDATE_COMMAND_UI(ID_SECURITY_POLICY_ACCEPT, OnUpdateSecurityPolicyAccept)
	ON_COMMAND(ID_SECURITY_POLICY_ACCEPT, OnSecurityPolicyAccept)
	ON_UPDATE_COMMAND_UI(ID_SECURITY_POLICY_DENY, OnUpdateSecurityPolicyDeny)
	ON_COMMAND(ID_SECURITY_POLICY_DENY, OnSecurityPolicyDeny)
	ON_WM_CONTEXTMENU()
	ON_UPDATE_COMMAND_UI(ID_SECURITY_MOVE_UP, OnUpdateSecurityMoveUp)
	ON_COMMAND(ID_SECURITY_MOVE_UP, OnSecurityMoveUp)
	ON_UPDATE_COMMAND_UI(ID_SECURITY_MOVE_DOWN, OnUpdateSecurityMoveDown)
	ON_COMMAND(ID_SECURITY_MOVE_DOWN, OnSecurityMoveDown)
	ON_UPDATE_COMMAND_UI(ID_SECURITY_EXPORT, OnUpdateSecurityExport)
	ON_COMMAND(ID_SECURITY_EXPORT, OnSecurityExport)
	ON_COMMAND(ID_SECURITY_IMPORT, OnSecurityImport)
	ON_WM_PAINT()
	ON_WM_SETCURSOR()
	ON_WM_LBUTTONDOWN()
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_IPLISTS, OnItemChangedLists)
	ON_NOTIFY(NM_SETFOCUS, IDC_IPLISTS, OnSetFocusLists)
	ON_NOTIFY(NM_SETFOCUS, IDC_RULES, OnSetFocusRules)
	ON_COMMAND(ID_SECURITY_ADD_LIST, OnSecurityAddList)
	ON_UPDATE_COMMAND_UI(ID_SECURITY_UPDATE_LISTS, OnUpdateSecurityUpdateLists)
	ON_COMMAND(ID_SECURITY_UPDATE_LISTS, OnSecurityUpdateLists)
	ON_UPDATE_COMMAND_UI(ID_SECURITY_LIST_REMOVE, OnUpdateSecurityListRemove)
	ON_COMMAND(ID_SECURITY_LIST_REMOVE, OnSecurityListRemove)
	ON_UPDATE_COMMAND_UI(ID_SECURITY_LIST_ENABLE, OnUpdateSecurityListEnable)
	ON_COMMAND(ID_SECURITY_LIST_ENABLE, OnSecurityListEnable)
END_MESSAGE_MAP()


/////////////////////////////////////////////////////////////////////////////
// CSecurityWnd construction

CSecurityWnd::CSecurityWnd()
	: tLastUpdate		( 0 )
	, m_nListsSize		( static_cast< int >( Settings.Security.ListsPaneSize ) )
	, m_bListsFocus		( FALSE )
	, m_bListsUpdating	( FALSE )
{
	Create( IDR_SECURITYFRAME );
}

CSecurityWnd::~CSecurityWnd()
{
}

/////////////////////////////////////////////////////////////////////////////
// CSecurityWnd message handlers

int CSecurityWnd::OnCreate(LPCREATESTRUCT lpCreateStruct) 
{
	if ( CPanelWnd::OnCreate( lpCreateStruct ) == -1 ) return -1;

	if ( ! m_wndToolBar.Create( this, WS_CHILD|WS_VISIBLE|CBRS_NOALIGN, AFX_IDW_TOOLBAR ) ) return -1;
	m_wndToolBar.SetBarStyle( m_wndToolBar.GetBarStyle() | CBRS_TOOLTIPS | CBRS_BORDER_TOP );

	m_wndList.Create( WS_VISIBLE|LVS_ICON|LVS_AUTOARRANGE|LVS_REPORT|LVS_SHOWSELALWAYS,
		rectDefault, this, IDC_RULES );

	m_pSizer.Attach( &m_wndList );
	
	
	m_wndList.SendMessage( LVM_SETEXTENDEDLISTVIEWSTYLE,
		LVS_EX_DOUBLEBUFFER|LVS_EX_FULLROWSELECT|LVS_EX_HEADERDRAGDROP|LVS_EX_LABELTIP,
		LVS_EX_DOUBLEBUFFER|LVS_EX_FULLROWSELECT|LVS_EX_HEADERDRAGDROP|LVS_EX_LABELTIP );
	

	CoolInterface.LoadIconsTo( m_gdiImageList, nImageID );
	m_wndList.SetImageList( &m_gdiImageList, LVSIL_SMALL );

	m_wndList.InsertColumn( 0, _T("Address / Content"), LVCFMT_LEFT, 200, -1 );
	m_wndList.InsertColumn( 1, _T("Action"), LVCFMT_CENTER, 100, 0 );
	m_wndList.InsertColumn( 2, _T("Expires"), LVCFMT_CENTER, 100, 1 );
	m_wndList.InsertColumn( 3, _T("Precedence"), LVCFMT_CENTER, 00, 2 );
	m_wndList.InsertColumn( 4, _T("Hits"), LVCFMT_CENTER, 60, 3 );
	m_wndList.InsertColumn( 5, _T("Comment"), LVCFMT_LEFT, 100, 4 );

	m_wndList.SetFont( &theApp.m_gdiFont );

	m_wndLists.Create( WS_VISIBLE|LVS_REPORT|LVS_SHOWSELALWAYS,
		rectDefault, this, IDC_IPLISTS );

	m_wndLists.SendMessage( LVM_SETEXTENDEDLISTVIEWSTYLE,
		LVS_EX_DOUBLEBUFFER|LVS_EX_FULLROWSELECT|LVS_EX_HEADERDRAGDROP|LVS_EX_LABELTIP|LVS_EX_CHECKBOXES,
		LVS_EX_DOUBLEBUFFER|LVS_EX_FULLROWSELECT|LVS_EX_HEADERDRAGDROP|LVS_EX_LABELTIP|LVS_EX_CHECKBOXES );

	m_wndLists.InsertColumn( 0, _T("List"), LVCFMT_LEFT, 220, -1 );
	m_wndLists.InsertColumn( 1, _T("Ranges"), LVCFMT_CENTER, 80, 0 );
	m_wndLists.InsertColumn( 2, _T("Updated"), LVCFMT_LEFT, 240, 1 );
	m_wndLists.InsertColumn( 3, _T("Hits"), LVCFMT_CENTER, 80, 2 );

	m_wndLists.SetFont( &theApp.m_gdiFont );
	
	LoadState( _T("CSecurityWnd"), TRUE );
	LayoutPanes();

	Update();
	UpdateLists();

	return 0;
}

void CSecurityWnd::OnDestroy() 
{
	Security.Save();

	Settings.SaveList( _T("CSecurityWnd"), &m_wndList );		
	Settings.SaveList( _T("CSecurityWnd.Lists"), &m_wndLists );
	SaveState( _T("CSecurityWnd") );

	CPanelWnd::OnDestroy();
}

/////////////////////////////////////////////////////////////////////////////
// CSecurityWnd operations

void CSecurityWnd::Update(int nColumn, BOOL bSort)
{
	Security.Expire();

	CAutoPtr< CLiveList > pLiveList( Security.GetList() );

	if ( nColumn >= 0 )
	{
		SetWindowLongPtr( m_wndList.GetSafeHwnd(), GWLP_USERDATA, 0 - nColumn - 1 );
	}

	pLiveList->Apply( &m_wndList, bSort );

	tLastUpdate = GetTickCount();				// Update time after it's done doing its work
}

CSecureRule* CSecurityWnd::GetItem(int nItem)
{
	if ( m_wndList.GetItemState( nItem, LVIS_SELECTED ) )
	{
		CSecureRule* pRule = (CSecureRule*)m_wndList.GetItemData( nItem );
		if ( Security.Check( pRule ) ) return pRule;
	}

	return NULL;
}

/////////////////////////////////////////////////////////////////////////////
// CSecurityWnd message handlers

void CSecurityWnd::OnSize(UINT nType, int cx, int cy) 
{
	CPanelWnd::OnSize( nType, cx, cy );
	LayoutPanes();
}

void CSecurityWnd::OnTimer(UINT_PTR nIDEvent) 
{
	if ( ( nIDEvent == 1 ) && ( IsPartiallyVisible() ) )
	{
		DWORD tTicks = GetTickCount();
		DWORD tDelay = max( ( 2 * (DWORD)Security.GetCount() ), 1000ul ); // Delay based on size of list

		if ( ( tTicks - tLastUpdate ) > tDelay )
		{
			if ( tDelay < 2000 ) Update();			// Sort if list is under 1000
			else Update( -1, FALSE );				// Otherwise just refresh values
		}

		UpdateLists();
	}
}

void CSecurityWnd::OnCustomDrawList(NMHDR* pNMHDR, LRESULT* pResult)
{
	NMLVCUSTOMDRAW* pDraw = (NMLVCUSTOMDRAW*)pNMHDR;

	if ( pDraw->nmcd.dwDrawStage == CDDS_PREPAINT )
	{
		*pResult = CDRF_NOTIFYITEMDRAW;
	}
	else if ( pDraw->nmcd.dwDrawStage == CDDS_ITEMPREPAINT )
	{
		LV_ITEM pItem;
		pItem.mask		= LVIF_IMAGE;
		pItem.iItem		= static_cast< int >( pDraw->nmcd.dwItemSpec );
		pItem.iSubItem	= 0;
		m_wndList.GetItem( &pItem );

		switch ( pItem.iImage )
		{
		case CSecureRule::srAccept:
			pDraw->clrText = CoolInterface.m_crSecurityAllow ;
			break;
		case CSecureRule::srDeny:
			pDraw->clrText = CoolInterface.m_crSecurityDeny ;
			break;
		}

		*pResult = CDRF_DODEFAULT;
	}
}

void CSecurityWnd::OnDblClkList(NMHDR* /*pNMHDR*/, LRESULT* pResult)
{
	OnSecurityEdit();
	*pResult = 0;
}

void CSecurityWnd::OnSortList(NMHDR* pNotifyStruct, LRESULT *pResult)
{
	NM_LISTVIEW* pNMListView = (NM_LISTVIEW*)pNotifyStruct;
	CLiveList::Sort( &m_wndList, pNMListView->iSubItem );
	*pResult = 0;
}

void CSecurityWnd::OnContextMenu(CWnd* pWnd, CPoint point) 
{
	// The IP lists pane, or its header
	const HWND hWnd = pWnd ? pWnd->GetSafeHwnd() : NULL;
	if ( hWnd && ( hWnd == m_wndLists.GetSafeHwnd() || ::GetParent( hWnd ) == m_wndLists.GetSafeHwnd() ) )
	{
		Skin.TrackPopupMenu( _T("CSecurityWnd.Lists"), point );
		return;
	}

	Skin.TrackPopupMenu( _T("CSecurityWnd"), point, ID_SECURITY_EDIT );
}

void CSecurityWnd::OnUpdateSecurityEdit(CCmdUI* pCmdUI) 
{
	pCmdUI->Enable( m_wndList.GetSelectedCount() == 1 && m_wndList.GetItemCount() > 1 );
}

void CSecurityWnd::OnSecurityEdit() 
{
	if ( m_wndList.GetSelectedCount() != 1 || m_wndList.GetItemCount() <= 1 )
		return;

	CSecureRule* pEditableRule;
	{
		CQuickLock oLock( Security.m_pSection );
		
		CSecureRule* pRule = GetItem( m_wndList.GetNextItem( -1, LVIS_SELECTED ) );
		if ( ! pRule ) return;
		pEditableRule = new CSecureRule( *pRule ); 
	}

	CSecureRuleDlg dlg( NULL, pEditableRule );
	if ( dlg.DoModal() == IDOK )
	{
		Security.Save();
		Update();
	}
	else
		delete pEditableRule;
}

void CSecurityWnd::OnUpdateSecurityReset(CCmdUI* pCmdUI) 
{
	pCmdUI->Enable( m_wndList.GetSelectedCount() > 0 );
}

void CSecurityWnd::OnSecurityReset() 
{
	for ( int nItem = -1 ; ( nItem = m_wndList.GetNextItem( nItem, LVIS_SELECTED ) ) >= 0 ; )
	{
		CQuickLock oLock( Security.m_pSection );

		if ( CSecureRule* pRule = GetItem( nItem ) )
		{
			pRule->Reset();
		}
	}

	Security.Save();
	Update();
}

void CSecurityWnd::OnUpdateSecurityRemove(CCmdUI* pCmdUI) 
{
	// Remove acts on the pane that has the focus
	if ( IsListsPaneActive() )
	{
		OnUpdateSecurityListRemove( pCmdUI );
		return;
	}

	pCmdUI->Enable( m_wndList.GetSelectedCount() > 0 && m_wndList.GetItemCount() > 1 );
}

void CSecurityWnd::OnSecurityRemove() 
{
	if ( IsListsPaneActive() )
	{
		OnSecurityListRemove();
		return;
	}

	if ( m_wndList.GetSelectedCount() <= 0 || m_wndList.GetItemCount() <= 1 )
		return;

	CString strMessage;
	LoadString( strMessage, IDS_SECURITY_REMOVE_CONFIRM );
	if ( AfxMessageBox( strMessage, MB_ICONQUESTION|MB_YESNO ) != IDYES ) return;

	for ( int nItem = -1 ; ( nItem = m_wndList.GetNextItem( nItem, LVIS_SELECTED ) ) >= 0 ; )
	{
		CQuickLock oLock( Security.m_pSection );

		if ( CSecureRule* pRule = GetItem( nItem ) )
		{
			Security.Remove( pRule );
		}
	}

	Security.Save();
	Update();
}

void CSecurityWnd::OnUpdateSecurityMoveUp(CCmdUI* pCmdUI) 
{
	pCmdUI->Enable( m_wndList.GetSelectedCount() > 0 );
}

void CSecurityWnd::OnSecurityMoveUp() 
{
	for ( int nItem = -1 ; ( nItem = m_wndList.GetNextItem( nItem, LVIS_SELECTED ) ) >= 0 ; )
	{
		CQuickLock oLock( Security.m_pSection );

		if ( CSecureRule* pRule = GetItem( nItem ) )
		{
			Security.MoveUp( pRule );
		}
	}

	Security.Save();
	Update( 3 );
}

void CSecurityWnd::OnUpdateSecurityMoveDown(CCmdUI* pCmdUI) 
{
	pCmdUI->Enable( m_wndList.GetSelectedCount() > 0 );
}

void CSecurityWnd::OnSecurityMoveDown() 
{
	CQuickLock oLock( Security.m_pSection );

	CList< CSecureRule* > pList;

	for ( int nItem = -1 ; ( nItem = m_wndList.GetNextItem( nItem, LVIS_SELECTED ) ) >= 0 ; )
	{
		pList.AddHead( GetItem( nItem ) );
	}

	while ( pList.GetCount() )
	{
		CSecureRule* pRule = pList.RemoveHead();
		if ( pRule ) Security.MoveDown( pRule );
	}

	Security.Save();
	Update( 3 );
}

void CSecurityWnd::OnSecurityAdd() 
{
	CSecureRuleDlg dlg;

	if ( dlg.DoModal() == IDOK )
	{
		Security.Save();
		Update();
	}
}

void CSecurityWnd::OnUpdateSecurityExport(CCmdUI* pCmdUI) 
{
	pCmdUI->Enable( m_wndList.GetSelectedCount() > 0 );
}

void CSecurityWnd::OnSecurityExport() 
{
	CFileDialog dlg( FALSE, _T("xml"), NULL, OFN_HIDEREADONLY|OFN_OVERWRITEPROMPT,
		_T("XML Security Files|*.xml|NET Security Files|*.net|") +
		SchemaCache.GetFilter( CSchema::uriAllFiles ) +
		_T("|"), this );
	
	if ( dlg.DoModal() != IDOK ) return;
	
	CString strText;
	CFile pFile;
	
	if ( ! pFile.Open( dlg.GetPathName(), CFile::modeWrite|CFile::modeCreate ) )
	{
		CString strMessage;
		strMessage.Format( LoadString( IDS_SECURITY_EXPORT_FAILED ), (LPCTSTR)dlg.GetFileName() );
		AfxMessageBox( strMessage, MB_ICONEXCLAMATION );
		return;
	}

	CWaitCursor pCursor;
	
	if ( dlg.GetFileExt().CompareNoCase( _T("net") ) == 0 )
	{
		for ( int nItem = -1 ; ( nItem = m_wndList.GetNextItem( nItem, LVIS_SELECTED ) ) >= 0 ; )
		{
			CQuickLock oLock( Security.m_pSection );

			if ( CSecureRule* pRule = GetItem( nItem ) )
			{
				strText = pRule->ToGnucleusString();

				if ( strText.GetLength() )
				{
					strText += _T("\r\n");

					int nBytes = WideCharToMultiByte( CP_ACP, 0, strText, strText.GetLength(), NULL, 0, NULL, NULL );
					LPSTR pBytes = new CHAR[nBytes];
					WideCharToMultiByte( CP_ACP, 0, strText, strText.GetLength(), pBytes, nBytes, NULL, NULL );
					pFile.Write( pBytes, nBytes );
					delete [] pBytes;

				}
			}
		}
	}
	else
	{
		auto_ptr< CXMLElement > pXML( new CXMLElement( NULL, _T("security") ) );

		pXML->AddAttribute( _T("xmlns"), CSecurity::xmlns );

		for ( int nItem = -1 ; ( nItem = m_wndList.GetNextItem( nItem, LVIS_SELECTED ) ) >= 0 ; )
		{
			CQuickLock oLock( Security.m_pSection );

			if ( CSecureRule* pRule = GetItem( nItem ) )
			{
				pXML->AddElement( pRule->ToXML() );
			}
		}

		strText = pXML->ToString( TRUE, TRUE );

		int nBytes = WideCharToMultiByte( CP_ACP, 0, strText, strText.GetLength(), NULL, 0, NULL, NULL );
		auto_array< CHAR > pBytes( new CHAR[ nBytes ] );
		WideCharToMultiByte( CP_ACP, 0, strText, strText.GetLength(), pBytes.get(), nBytes, NULL, NULL );
		pFile.Write( pBytes.get(), nBytes );
	}

	pFile.Close();
}

void CSecurityWnd::OnSecurityImport() 
{
	CFileDialog dlg( TRUE, _T("xml"), NULL, OFN_HIDEREADONLY|OFN_FILEMUSTEXIST,
		_T("Security Rules|*.xml;*.net|IP lists|*.p2p;*.dat;*.txt;*.gz;*.zip|") +
		SchemaCache.GetFilter( CSchema::uriAllFiles ) +
		_T("|"), this );
	
	if ( dlg.DoModal() != IDOK ) return;

	const CString strPath = dlg.GetPathName();
	const CString strName = dlg.GetFileName();
	CString strMessage;

	CWaitCursor pCursor;

	CBuffer pBuffer;
	bool bTooLarge = false;
	if ( ! ReadImportFile( strPath, pBuffer, bTooLarge ) )
	{
		if ( bTooLarge )
			strMessage.Format( LoadString( IDS_IPLIST_IMPORT_FAILED ), (LPCTSTR)strName,
				(LPCTSTR)LoadString( IDS_IPLIST_IMPORT_TOO_LARGE ) );
		else
			strMessage.Format( LoadString( IDS_SECURITY_IMPORT_FAILED ), (LPCTSTR)strName );
		AfxMessageBox( strMessage, MB_ICONEXCLAMATION );
		return;
	}

	// Shareaza XML goes into the user's rules; anything else becomes an IP list
	if ( ! IsXMLFile( pBuffer.m_pBuffer, pBuffer.m_nLength ) )
	{
		ImportIPList( strName, pBuffer );
		UpdateLists();
		return;
	}

	if ( Security.Import( strPath ) )
	{
		Security.Save();
	}
	else
	{
		strMessage.Format( LoadString( IDS_SECURITY_IMPORT_FAILED ), (LPCTSTR)strName );
		AfxMessageBox( strMessage, MB_ICONEXCLAMATION );
	}
}

void CSecurityWnd::OnSkinChange()
{
	CPanelWnd::OnSkinChange();

	Settings.LoadList( _T("CSecurityWnd"), &m_wndList, -4 );
	Settings.LoadList( _T("CSecurityWnd.Lists"), &m_wndLists );
	Skin.CreateToolBar( _T("CSecurityWnd"), &m_wndToolBar );

	CoolInterface.LoadIconsTo( m_gdiImageList, nImageID );
	m_wndList.SetImageList( &m_gdiImageList, LVSIL_SMALL );
}

void CSecurityWnd::OnUpdateSecurityPolicyAccept(CCmdUI* pCmdUI) 
{
	pCmdUI->SetCheck( Security.m_bDenyPolicy == FALSE );
}

void CSecurityWnd::OnSecurityPolicyAccept() 
{
	Security.m_bDenyPolicy = FALSE;
	Update();
	m_wndList.RedrawItems( 0, m_wndList.GetItemCount() - 1 );
}

void CSecurityWnd::OnUpdateSecurityPolicyDeny(CCmdUI* pCmdUI) 
{
	pCmdUI->SetCheck( Security.m_bDenyPolicy == TRUE );
}

void CSecurityWnd::OnSecurityPolicyDeny() 
{
	Security.m_bDenyPolicy = TRUE;
	Update();
	m_wndList.RedrawItems( 0, m_wndList.GetItemCount() - 1 );
}


BOOL CSecurityWnd::PreTranslateMessage(MSG* pMsg) 
{
	if ( pMsg->message == WM_KEYDOWN && ::GetFocus() == m_wndLists.GetSafeHwnd() &&
		GetListsHeight( GetPanesRect() ) > 0 )
	{
		// The IP lists pane: its own commands, none of the rules'
		if ( ( GetAsyncKeyState( VK_CONTROL ) & 0x8000 ) == 0 )
		{
			if ( pMsg->wParam == VK_DELETE )
			{
				PostMessage( WM_COMMAND, ID_SECURITY_LIST_REMOVE );
				return TRUE;
			}
			else if ( pMsg->wParam == VK_INSERT )
			{
				PostMessage( WM_COMMAND, ID_SECURITY_ADD_LIST );
				return TRUE;
			}
		}
	}
	else if ( pMsg->message == WM_KEYDOWN )
	{
		if ( GetAsyncKeyState( VK_CONTROL ) & 0x8000 )
		{
			if ( pMsg->wParam == VK_UP )
			{
				PostMessage( WM_COMMAND, ID_SECURITY_MOVE_UP );
				return TRUE;
			}
			else if ( pMsg->wParam == VK_DOWN )
			{
				PostMessage( WM_COMMAND, ID_SECURITY_MOVE_DOWN );
				return TRUE;
			}
		}
		else if ( pMsg->wParam == VK_DELETE )
		{
			PostMessage( WM_COMMAND, ID_SECURITY_REMOVE );
			return TRUE;
		}
		else if ( pMsg->wParam == VK_INSERT )
		{
			PostMessage( WM_COMMAND, ID_SECURITY_ADD );
			return TRUE;
		}
		else if ( pMsg->wParam == VK_RETURN )
		{
			PostMessage( WM_COMMAND, ID_SECURITY_EDIT );
			return TRUE;
		}
	}

	return CPanelWnd::PreTranslateMessage( pMsg );
}

/////////////////////////////////////////////////////////////////////////////
// CSecurityWnd IP lists pane

void CSecurityWnd::UpdateLists()
{
	std::vector< CIPList > pLists;
	IPLists.Snapshot( pLists );

	// Changes made here are not the user's
	m_bListsUpdating = TRUE;

	// Rows follow the snapshot; rebuild them only when the lists changed
	bool bSame = ( pLists.size() == m_pListGUIDs.size() );
	for ( size_t i = 0 ; bSame && i < pLists.size() ; ++i )
	{
		bSame = ( pLists[ i ].m_oGUID == m_pListGUIDs[ i ] );
	}

	if ( ! bSame )
	{
		const std::vector< GUID > pSelected = GetSelectedLists();

		m_wndLists.DeleteAllItems();
		m_pListGUIDs.clear();
		m_pListHasURLs.clear();

		for ( size_t i = 0 ; i < pLists.size() ; ++i )
		{
			const int nItem = m_wndLists.InsertItem( static_cast< int >( i ), pLists[ i ].m_sName );
			if ( nItem != static_cast< int >( i ) )
				break;	// out of memory: show what fits
			m_pListGUIDs.push_back( pLists[ i ].m_oGUID );
			m_pListHasURLs.push_back( pLists[ i ].m_pURLs.GetSize() > 0 );

			for ( size_t j = 0 ; j < pSelected.size() ; ++j )
			{
				if ( pSelected[ j ] == pLists[ i ].m_oGUID )
				{
					m_wndLists.SetItemState( nItem, LVIS_SELECTED, LVIS_SELECTED );
					break;
				}
			}
		}
	}

	CString strText;
	for ( size_t i = 0 ; i < m_pListGUIDs.size() ; ++i )
	{
		const CIPList& oList = pLists[ i ];
		const int nItem = static_cast< int >( i );

		SetListText( m_wndLists, nItem, 0, oList.m_sName );

		const size_t nRanges = oList.m_pRanges ?
			oList.m_pRanges->CountV4() + oList.m_pRanges->CountV6() : 0;
		strText.Format( _T("%Iu"), nRanges );
		SetListText( m_wndLists, nItem, 1, strText );

		SetListText( m_wndLists, nItem, 2, FormatListUpdated( oList ) );

		strText.Format( _T("%lu (%lu)"), oList.m_nToday, oList.m_nEver );
		SetListText( m_wndLists, nItem, 3, strText );

		if ( ( m_wndLists.GetCheck( nItem ) != FALSE ) != ( oList.m_bEnabled != FALSE ) )
			m_wndLists.SetCheck( nItem, oList.m_bEnabled != FALSE );
	}

	m_bListsUpdating = FALSE;
}

std::vector< GUID > CSecurityWnd::GetSelectedLists(bool bDownloadedOnly) const
{
	std::vector< GUID > pSelected;
	for ( int nItem = -1 ; ( nItem = m_wndLists.GetNextItem( nItem, LVNI_SELECTED ) ) >= 0 ; )
	{
		if ( static_cast< size_t >( nItem ) >= m_pListGUIDs.size() )
			continue;
		if ( bDownloadedOnly && ! m_pListHasURLs[ nItem ] )
			continue;
		pSelected.push_back( m_pListGUIDs[ nItem ] );
	}
	return pSelected;
}

BOOL CSecurityWnd::IsListsPaneActive() const
{
	return m_bListsFocus && GetListsHeight( GetPanesRect() ) > 0;
}

CRect CSecurityWnd::GetPanesRect() const
{
	CRect rc;
	GetClientRect( &rc );
	rc.bottom -= TOOLBAR_HEIGHT;
	if ( rc.bottom < rc.top )
		rc.bottom = rc.top;
	return rc;
}

int CSecurityWnd::GetListsHeight(const CRect& rcPanes) const
{
	int nMax = rcPanes.Height() - 2 * CAPTION_HEIGHT - SPLIT_SIZE;
	if ( nMax < 0 )
		nMax = 0;

	int nHeight = m_nListsSize;
	if ( nHeight > nMax )
		nHeight = nMax;
	if ( nHeight < 0 )
		nHeight = 0;
	return nHeight;
}

CRect CSecurityWnd::GetSplitRect() const
{
	const CRect rcPanes = GetPanesRect();
	CRect rc( rcPanes );
	rc.top += CAPTION_HEIGHT + GetListsHeight( rcPanes );
	rc.bottom = rc.top + SPLIT_SIZE;

	// A window too small for it stops at the toolbar
	if ( rc.bottom > rcPanes.bottom )
		rc.bottom = rcPanes.bottom;
	if ( rc.top > rc.bottom )
		rc.top = rc.bottom;
	return rc;
}

CRect CSecurityWnd::GetCaptionRect(BOOL bLists) const
{
	const CRect rcPanes = GetPanesRect();
	CRect rc( rcPanes );
	if ( ! bLists )
		rc.top = GetSplitRect().bottom;
	rc.bottom = rc.top + CAPTION_HEIGHT;

	// A window too small for both stops at the toolbar
	if ( rc.bottom > rcPanes.bottom )
		rc.bottom = rcPanes.bottom;
	if ( rc.top > rc.bottom )
		rc.top = rc.bottom;
	return rc;
}

// Toolbar at the bottom; above it, from the top: the "IP lists" caption and
// table, the split bar, the "My rules" caption and table.
void CSecurityWnd::LayoutPanes()
{
	if ( ! m_wndList.GetSafeHwnd() || ! m_wndLists.GetSafeHwnd() || ! m_wndToolBar.GetSafeHwnd() )
		return;

	CRect rcClient;
	GetClientRect( &rcClient );
	const CRect rcPanes = GetPanesRect();
	const int nLists = GetListsHeight( rcPanes );
	const int nRulesTop = rcPanes.top + CAPTION_HEIGHT + nLists + SPLIT_SIZE + CAPTION_HEIGHT;
	int nRules = rcPanes.bottom - nRulesTop;
	if ( nRules < 0 )
		nRules = 0;

	HDWP hPos = BeginDeferWindowPos( 3 );
	hPos = DeferWindowPos( hPos, m_wndToolBar.GetSafeHwnd(), NULL,
		rcPanes.left, rcPanes.bottom, rcPanes.Width(), rcClient.bottom - rcPanes.bottom,
		SWP_SHOWWINDOW | SWP_NOACTIVATE | SWP_NOZORDER );
	hPos = DeferWindowPos( hPos, m_wndLists.GetSafeHwnd(), NULL,
		rcPanes.left, rcPanes.top + CAPTION_HEIGHT, rcPanes.Width(), nLists,
		SWP_SHOWWINDOW | SWP_NOACTIVATE | SWP_NOZORDER );
	hPos = DeferWindowPos( hPos, m_wndList.GetSafeHwnd(), NULL,
		rcPanes.left, nRulesTop, rcPanes.Width(), nRules,
		SWP_SHOWWINDOW | SWP_NOACTIVATE | SWP_NOZORDER );
	EndDeferWindowPos( hPos );

	Invalidate();
}

// Drags the split bar, as CSearchWnd does its detail panel.
void CSecurityWnd::DoSizeLists()
{
	MSG* pMsg = &AfxGetThreadState()->m_msgCur;
	const CRect rcPanes = GetPanesRect();

	CRect rcClip( rcPanes );
	ClientToScreen( &rcClip );
	ClipCursor( &rcClip );
	SetCapture();

	int nOffset = 0xFFFF;

	while ( GetAsyncKeyState( VK_LBUTTON ) & 0x8000 )
	{
		while ( ::PeekMessage( pMsg, NULL, WM_MOUSEFIRST, WM_MOUSELAST, PM_REMOVE ) );

		if ( ! AfxGetThread()->PumpMessage() )
		{
			AfxPostQuitMessage( 0 );
			break;
		}

		CPoint point;
		GetCursorPos( &point );
		ScreenToClient( &point );

		int nSplit = point.y - rcPanes.top - CAPTION_HEIGHT;

		if ( nOffset == 0xFFFF ) nOffset = GetListsHeight( rcPanes ) - nSplit;
		nSplit += nOffset;

		const int nMax = rcPanes.Height() - 2 * CAPTION_HEIGHT - SPLIT_SIZE;
		if ( nSplit < 8 )
			nSplit = 0;
		if ( nSplit > nMax - 8 )
			nSplit = nMax;
		if ( nSplit < 0 )
			nSplit = 0;

		if ( nSplit != m_nListsSize )
		{
			m_nListsSize = nSplit;
			Settings.Security.ListsPaneSize = static_cast< DWORD >( nSplit );
			LayoutPanes();
		}
	}

	ReleaseCapture();
	ClipCursor( NULL );
}

void CSecurityWnd::OnPaint()
{
	CPaintDC dc( this );

	const CRect rcBar = GetSplitRect();

	dc.FillSolidRect( rcBar.left, rcBar.top, rcBar.Width(), 1, CoolInterface.m_crResizebarEdge );
	dc.FillSolidRect( rcBar.left, rcBar.top + 1, rcBar.Width(), 1, CoolInterface.m_crResizebarHighlight );
	dc.FillSolidRect( rcBar.left, rcBar.bottom - 1, rcBar.Width(), 1, CoolInterface.m_crResizebarShadow );
	dc.FillSolidRect( rcBar.left, rcBar.top + 2, rcBar.Width(), rcBar.Height() - 3, CoolInterface.m_crResizebarFace );

	// Pane captions, in the banner colours CSearchWnd uses for its status strip
	CFont* pOldFont = (CFont*)dc.SelectObject( &CoolInterface.m_fntBold );
	dc.SetBkMode( TRANSPARENT );
	dc.SetTextColor( Skin.m_crBannerText );

	for ( int nPane = 0 ; nPane < 2 ; ++nPane )
	{
		CRect rcCaption = GetCaptionRect( nPane == 0 );
		dc.FillSolidRect( &rcCaption, Skin.m_crBannerBack );

		const CString strCaption = LoadString( nPane == 0 ? IDS_IPLIST_PANE_LISTS : IDS_IPLIST_PANE_RULES );
		rcCaption.DeflateRect( 6, 0 );
		dc.DrawText( strCaption, &rcCaption, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX|DT_END_ELLIPSIS );
	}

	dc.SelectObject( pOldFont );
}

BOOL CSecurityWnd::OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message)
{
	CRect rcBar = GetSplitRect();
	ClientToScreen( &rcBar );

	CPoint point;
	GetCursorPos( &point );

	if ( rcBar.PtInRect( point ) )
	{
		SetCursor( AfxGetApp()->LoadStandardCursor( IDC_SIZENS ) );
		return TRUE;
	}

	return CPanelWnd::OnSetCursor( pWnd, nHitTest, message );
}

void CSecurityWnd::OnLButtonDown(UINT nFlags, CPoint point)
{
	if ( GetSplitRect().PtInRect( point ) )
	{
		DoSizeLists();
		return;
	}

	CPanelWnd::OnLButtonDown( nFlags, point );
}

void CSecurityWnd::OnItemChangedLists(NMHDR* pNMHDR, LRESULT* pResult)
{
	*pResult = 0;

	// Our own refills (SetCheck, InsertItem) are not the user's
	if ( m_bListsUpdating )
		return;

	const NMLISTVIEW* pNMListView = reinterpret_cast< const NMLISTVIEW* >( pNMHDR );
	if ( ( pNMListView->uChanged & LVIF_STATE ) == 0 )
		return;

	// State image 1 = unticked, 2 = ticked; 0 = no check box yet
	const UINT nOld = ( pNMListView->uOldState & LVIS_STATEIMAGEMASK ) >> 12;
	const UINT nNew = ( pNMListView->uNewState & LVIS_STATEIMAGEMASK ) >> 12;
	if ( nOld == 0 || nNew == 0 || nOld == nNew )
		return;

	if ( pNMListView->iItem < 0 || static_cast< size_t >( pNMListView->iItem ) >= m_pListGUIDs.size() )
		return;

	IPLists.SetEnabled( m_pListGUIDs[ pNMListView->iItem ], nNew == 2 );
	IPLists.Save();
}

void CSecurityWnd::OnSetFocusLists(NMHDR* /*pNMHDR*/, LRESULT* pResult)
{
	m_bListsFocus = TRUE;
	*pResult = 0;
}

void CSecurityWnd::OnSetFocusRules(NMHDR* /*pNMHDR*/, LRESULT* pResult)
{
	m_bListsFocus = FALSE;
	*pResult = 0;
}

void CSecurityWnd::OnSecurityAddList()
{
	CIPListAddDlg dlg;
	if ( dlg.DoModal() == IDOK )
		UpdateLists();
}

void CSecurityWnd::OnUpdateSecurityUpdateLists(CCmdUI* pCmdUI)
{
	// Something to download: a selected list with URLs, or with no selection any list
	if ( m_wndLists.GetSelectedCount() > 0 )
		pCmdUI->Enable( ! GetSelectedLists( true ).empty() );
	else
		pCmdUI->Enable( m_wndLists.GetItemCount() > 0 );
}

void CSecurityWnd::OnSecurityUpdateLists()
{
	// The selected lists, or every list when none is selected. Imported lists
	// have nothing to download.
	const std::vector< GUID > pUpdate = GetSelectedLists( true );
	if ( m_wndLists.GetSelectedCount() > 0 && pUpdate.empty() )
		return;

	IPListUpdater.UpdateNow( pUpdate );
}

void CSecurityWnd::OnUpdateSecurityListRemove(CCmdUI* pCmdUI)
{
	pCmdUI->Enable( m_wndLists.GetSelectedCount() > 0 );
}

void CSecurityWnd::OnSecurityListRemove()
{
	const std::vector< GUID > pSelected = GetSelectedLists();
	if ( pSelected.empty() )
		return;

	if ( AfxMessageBox( LoadString( IDS_IPLIST_REMOVE_CONFIRM ), MB_ICONQUESTION|MB_YESNO ) != IDYES )
		return;

	CWaitCursor pCursor;

	for ( size_t i = 0 ; i < pSelected.size() ; ++i )
	{
		IPLists.Remove( pSelected[ i ] );
	}

	IPLists.Save();
	UpdateLists();
}

void CSecurityWnd::OnUpdateSecurityListEnable(CCmdUI* pCmdUI)
{
	BOOL bAllEnabled = TRUE;
	for ( int nItem = -1 ; ( nItem = m_wndLists.GetNextItem( nItem, LVNI_SELECTED ) ) >= 0 ; )
	{
		if ( ! m_wndLists.GetCheck( nItem ) )
		{
			bAllEnabled = FALSE;
			break;
		}
	}

	pCmdUI->Enable( m_wndLists.GetSelectedCount() > 0 );
	pCmdUI->SetCheck( m_wndLists.GetSelectedCount() > 0 && bAllEnabled );
}

void CSecurityWnd::OnSecurityListEnable()
{
	// Turns the selection off when all of it is on, on otherwise
	BOOL bAllEnabled = TRUE;
	for ( int nItem = -1 ; ( nItem = m_wndLists.GetNextItem( nItem, LVNI_SELECTED ) ) >= 0 ; )
	{
		if ( ! m_wndLists.GetCheck( nItem ) )
		{
			bAllEnabled = FALSE;
			break;
		}
	}

	const std::vector< GUID > pSelected = GetSelectedLists();
	if ( pSelected.empty() )
		return;

	for ( size_t i = 0 ; i < pSelected.size() ; ++i )
	{
		IPLists.SetEnabled( pSelected[ i ], ! bAllEnabled );
	}

	IPLists.Save();
	UpdateLists();
}
