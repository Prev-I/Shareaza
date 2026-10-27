//
// PageSettingsTls.h
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


#pragma once

#include "WndSettingsPage.h"


// The certificate policy for https downloads, and the certificates the user accepted
class CTlsSettingsPage : public CSettingsPage
{
	DECLARE_DYNAMIC(CTlsSettingsPage)

public:
	CTlsSettingsPage();
	virtual ~CTlsSettingsPage();

	enum { IDD = IDD_SETTINGS_TLS };

protected:
	CComboBox	m_wndPolicy;
	CStatic		m_wndWarning;

	void		UpdateWarning();

	virtual void DoDataExchange(CDataExchange* pDX);
	virtual BOOL OnInitDialog();
	virtual void OnOK();

	afx_msg void OnSelChangePolicy();
	afx_msg void OnForget();

	DECLARE_MESSAGE_MAP()
};
