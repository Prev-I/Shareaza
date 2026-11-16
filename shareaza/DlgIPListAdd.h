//
// DlgIPListAdd.h
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

// The Add IP list dialog: the catalogue's lists as check boxes (none ticked),
// each with its note, and a name and https:// address for the user's own
// list. Add subscribes to what was chosen, saves, and starts the downloads.

#pragma once

#include "DlgSkinDialog.h"


class CIPListAddDlg : public CSkinDialog
{
public:
	CIPListAddDlg(CWnd* pParent = NULL);

	enum { IDD = IDD_IPLIST_ADD };

protected:
	CString		m_sName;
	CString		m_sURL;

	virtual void DoDataExchange(CDataExchange* pDX);
	virtual BOOL OnInitDialog();
	virtual void OnOK();

	DECLARE_MESSAGE_MAP()
};
