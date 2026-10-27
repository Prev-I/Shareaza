//
// PageSettingsTls.cpp
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


#include "StdAfx.h"
#include "Shareaza.h"
#include "Settings.h"
#include "TlsPolicy.h"
#include "PageSettingsTls.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

IMPLEMENT_DYNAMIC(CTlsSettingsPage, CSettingsPage)

BEGIN_MESSAGE_MAP(CTlsSettingsPage, CSettingsPage)
	ON_CBN_SELCHANGE(IDC_TLS_POLICY, &CTlsSettingsPage::OnSelChangePolicy)
	ON_BN_CLICKED(IDC_TLS_FORGET, &CTlsSettingsPage::OnForget)
END_MESSAGE_MAP()


//////////////////////////////////////////////////////////////////////////////
// CTlsSettingsPage construction

CTlsSettingsPage::CTlsSettingsPage() : CSettingsPage( CTlsSettingsPage::IDD )
{
}

CTlsSettingsPage::~CTlsSettingsPage()
{
}

void CTlsSettingsPage::DoDataExchange(CDataExchange* pDX)
{
	CSettingsPage::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_TLS_POLICY, m_wndPolicy);
	DDX_Control(pDX, IDC_TLS_POLICY_WARNING, m_wndWarning);
}

//////////////////////////////////////////////////////////////////////////////
// CTlsSettingsPage message handlers

BOOL CTlsSettingsPage::OnInitDialog()
{
	CSettingsPage::OnInitDialog();

	// The entries are in the order of the TLS_CERT_* values
	m_wndPolicy.AddString( LoadString( IDS_TLS_POLICY_VALID ) );
	m_wndPolicy.AddString( LoadString( IDS_TLS_POLICY_ASK ) );
	m_wndPolicy.AddString( LoadString( IDS_TLS_POLICY_IGNORE ) );

	const DWORD nPolicy = Settings.Connection.TlsCertPolicy;
	m_wndPolicy.SetCurSel( nPolicy <= static_cast< DWORD >( TLS_CERT_IGNORE ) ?
		static_cast< int >( nPolicy ) : static_cast< int >( TLS_CERT_VALID ) );

	m_wndWarning.SetWindowText( LoadString( IDS_TLS_POLICY_IGNORE_WARNING ) );
	UpdateWarning();

	return TRUE;
}

void CTlsSettingsPage::UpdateWarning()
{
	m_wndWarning.ShowWindow( m_wndPolicy.GetCurSel() == TLS_CERT_IGNORE ? SW_SHOW : SW_HIDE );
}

void CTlsSettingsPage::OnSelChangePolicy()
{
	UpdateWarning();
}

void CTlsSettingsPage::OnForget()
{
	const size_t nCount = TlsTrust.Clear();
	if ( ! SaveTlsTrust() )
		theApp.Message( MSG_ERROR, IDS_TLS_TRUST_SAVE_FAILED );

	CString strMessage;
	strMessage.Format( LoadString( IDS_TLS_FORGET ), static_cast< unsigned int >( nCount ) );
	AfxMessageBox( strMessage, MB_ICONINFORMATION | MB_OK );
}

void CTlsSettingsPage::OnOK()
{
	const int nSel = m_wndPolicy.GetCurSel();
	if ( nSel >= TLS_CERT_VALID && nSel <= TLS_CERT_IGNORE )
		Settings.Connection.TlsCertPolicy = static_cast< DWORD >( nSel );

	CSettingsPage::OnOK();
}
