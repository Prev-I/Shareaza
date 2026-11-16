//
// DlgIPListAdd.cpp
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
#include "IPLists.h"
#include "IPListCatalogue.h"
#include "IPListUpdater.h"
#include "DlgIPListAdd.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

static const int nCatalogue = static_cast< int >( _countof( kCatalogue ) );

// One check box and one note per catalogue entry, in consecutive IDs
static_assert( IDC_IPLIST_CAT_4 - IDC_IPLIST_CAT_0 + 1 == nCatalogue,
	"one check box per catalogue entry" );
static_assert( IDC_IPLIST_NOTE_4 - IDC_IPLIST_NOTE_0 + 1 == nCatalogue,
	"one note per catalogue entry" );

namespace
{

// https:// and something after it
bool IsHttpsURL(const CString& sURL)
{
	return sURL.GetLength() > 8 && _tcsnicmp( sURL, _T("https://"), 8 ) == 0;
}

// A list already fetched from this (first) URL
bool IsSubscribed(const std::vector< CIPList >& pLists, LPCTSTR pszURL)
{
	for ( size_t i = 0 ; i < pLists.size() ; ++i )
	{
		if ( pLists[ i ].m_pURLs.GetSize() > 0 &&
			pLists[ i ].m_pURLs.GetAt( 0 ).CompareNoCase( pszURL ) == 0 )
			return true;
	}
	return false;
}

}	// namespace

BEGIN_MESSAGE_MAP(CIPListAddDlg, CSkinDialog)
END_MESSAGE_MAP()


/////////////////////////////////////////////////////////////////////////////
// CIPListAddDlg dialog

CIPListAddDlg::CIPListAddDlg(CWnd* pParent)
	: CSkinDialog( CIPListAddDlg::IDD, pParent )
{
}

void CIPListAddDlg::DoDataExchange(CDataExchange* pDX)
{
	CSkinDialog::DoDataExchange( pDX );

	DDX_Text( pDX, IDC_IPLIST_NAME, m_sName );
	DDX_Text( pDX, IDC_IPLIST_URL, m_sURL );
}

/////////////////////////////////////////////////////////////////////////////
// CIPListAddDlg message handlers

BOOL CIPListAddDlg::OnInitDialog()
{
	CSkinDialog::OnInitDialog();

	SkinMe( _T("CIPListAddDlg"), IDR_SECURITYFRAME );

	std::vector< CIPList > pLists;
	IPLists.Snapshot( pLists );

	// Names and notes come from the catalogue, after the skin's captions.
	// Nothing is ticked; a list already added cannot be added again.
	for ( int i = 0 ; i < nCatalogue ; ++i )
	{
		SetDlgItemText( IDC_IPLIST_CAT_0 + i, kCatalogue[ i ].szName );
		SetDlgItemText( IDC_IPLIST_NOTE_0 + i, LoadString( kCatalogue[ i ].nNoteID ) );
		CheckDlgButton( IDC_IPLIST_CAT_0 + i, BST_UNCHECKED );

		if ( IsSubscribed( pLists, kCatalogue[ i ].szURLs[ 0 ] ) )
		{
			if ( CWnd* pBox = GetDlgItem( IDC_IPLIST_CAT_0 + i ) )
				pBox->EnableWindow( FALSE );
		}
	}

	return TRUE;
}

void CIPListAddDlg::OnOK()
{
	if ( ! UpdateData() )
		return;

	m_sName.Trim();
	m_sURL.Trim();

	if ( m_sName.GetLength() && m_sURL.IsEmpty() )
	{
		AfxMessageBox( LoadString( IDS_IPLIST_URL_NEEDED ), MB_ICONEXCLAMATION );
		if ( CWnd* pURL = GetDlgItem( IDC_IPLIST_URL ) )
			pURL->SetFocus();
		return;
	}

	if ( m_sURL.GetLength() && ! IsHttpsURL( m_sURL ) )
	{
		AfxMessageBox( LoadString( IDS_IPLIST_HTTPS_ONLY ), MB_ICONEXCLAMATION );
		if ( CWnd* pURL = GetDlgItem( IDC_IPLIST_URL ) )
			pURL->SetFocus();
		return;
	}

	std::vector< CIPList > pLists;
	IPLists.Snapshot( pLists );

	std::vector< GUID > pAdded;
	const CString strNoSource;
	bool bChosen = ( m_sURL.GetLength() > 0 );

	for ( int i = 0 ; i < nCatalogue ; ++i )
	{
		if ( IsDlgButtonChecked( IDC_IPLIST_CAT_0 + i ) != BST_CHECKED )
			continue;
		bChosen = true;
		if ( IsSubscribed( pLists, kCatalogue[ i ].szURLs[ 0 ] ) )
			continue;

		CStringArray pURLs;
		for ( int j = 0 ; j < static_cast< int >( _countof( kCatalogue[ i ].szURLs ) ) ; ++j )
		{
			if ( kCatalogue[ i ].szURLs[ j ] )
				pURLs.Add( kCatalogue[ i ].szURLs[ j ] );
		}

		pAdded.push_back( IPLists.Add( kCatalogue[ i ].szName, pURLs, strNoSource )->m_oGUID );
	}

	if ( m_sURL.GetLength() && ! IsSubscribed( pLists, m_sURL ) )
	{
		CStringArray pURLs;
		pURLs.Add( m_sURL );

		pAdded.push_back( IPLists.Add( m_sName.GetLength() ? m_sName : m_sURL, pURLs, strNoSource )->m_oGUID );
	}

	// Adding nothing is not a silent success: say why and stay open
	if ( pAdded.empty() )
	{
		AfxMessageBox( LoadString( bChosen ? IDS_IPLIST_ALREADY_ADDED : IDS_IPLIST_NOTHING_CHOSEN ),
			MB_ICONINFORMATION );
		return;
	}

	IPLists.Save();
	IPListUpdater.UpdateNow( pAdded );

	CSkinDialog::OnOK();
}
