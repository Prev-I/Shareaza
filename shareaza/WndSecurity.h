//
// WndSecurity.h
//
// Copyright (c) Shareaza Development Team, 2002-2011.
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

#include "WndPanel.h"

#include <vector>

class CSecureRule;


class CSecurityWnd : public CPanelWnd
{
	DECLARE_SERIAL(CSecurityWnd)

public:
	CSecurityWnd();
	virtual ~CSecurityWnd();

protected:
	CCoolBarCtrl	m_wndToolBar;
	CListCtrl		m_wndList;			// My rules, below
	CListCtrl		m_wndLists;			// IP lists, above
	CImageList		m_gdiImageList;
	CLiveListSizer	m_pSizer;
	DWORD			tLastUpdate;
	std::vector< GUID > m_pListGUIDs;	// the list shown in each row of m_wndLists
	std::vector< bool > m_pListHasURLs;	// per row: the list is downloaded (not imported)
	int				m_nListsSize;		// height of the IP lists pane (pixels)
	BOOL			m_bListsFocus;		// the IP lists pane had the focus last
	BOOL			m_bListsUpdating;	// m_wndLists is being refilled: its notifications are ours

	void			Update(int nColumn = -1, BOOL bSort = TRUE);
	CSecureRule*	GetItem(int nItem);
	virtual void	OnSkinChange();

	// IP lists pane
	void			UpdateLists();
	std::vector< GUID > GetSelectedLists(bool bDownloadedOnly = false) const;
	BOOL			IsListsPaneActive() const;		// has the focus and is not collapsed
	CRect			GetPanesRect() const;			// client area above the toolbar
	int				GetListsHeight(const CRect& rcPanes) const;
	CRect			GetSplitRect() const;
	CRect			GetCaptionRect(BOOL bLists) const;	// "IP lists" / "My rules" strip
	void			LayoutPanes();
	void			DoSizeLists();

	virtual BOOL PreTranslateMessage(MSG* pMsg);

	afx_msg int OnCreate(LPCREATESTRUCT lpCreateStruct);
	afx_msg void OnDestroy();
	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	afx_msg void OnCustomDrawList(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnDblClkList(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnSortList(NMHDR* pNotifyStruct, LRESULT *pResult);
	afx_msg void OnUpdateSecurityEdit(CCmdUI* pCmdUI);
	afx_msg void OnSecurityEdit();
	afx_msg void OnUpdateSecurityReset(CCmdUI* pCmdUI);
	afx_msg void OnSecurityReset();
	afx_msg void OnUpdateSecurityRemove(CCmdUI* pCmdUI);
	afx_msg void OnSecurityRemove();
	afx_msg void OnSecurityAdd();
	afx_msg void OnUpdateSecurityPolicyAccept(CCmdUI* pCmdUI);
	afx_msg void OnSecurityPolicyAccept();
	afx_msg void OnUpdateSecurityPolicyDeny(CCmdUI* pCmdUI);
	afx_msg void OnSecurityPolicyDeny();
	afx_msg void OnContextMenu(CWnd* pWnd, CPoint point);
	afx_msg void OnUpdateSecurityMoveUp(CCmdUI* pCmdUI);
	afx_msg void OnSecurityMoveUp();
	afx_msg void OnUpdateSecurityMoveDown(CCmdUI* pCmdUI);
	afx_msg void OnSecurityMoveDown();
	afx_msg void OnUpdateSecurityExport(CCmdUI* pCmdUI);
	afx_msg void OnSecurityExport();
	afx_msg void OnSecurityImport();
	afx_msg void OnPaint();
	afx_msg BOOL OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message);
	afx_msg void OnLButtonDown(UINT nFlags, CPoint point);
	afx_msg void OnItemChangedLists(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnSetFocusLists(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnSetFocusRules(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnSecurityAddList();
	afx_msg void OnUpdateSecurityUpdateLists(CCmdUI* pCmdUI);
	afx_msg void OnSecurityUpdateLists();
	afx_msg void OnUpdateSecurityListRemove(CCmdUI* pCmdUI);
	afx_msg void OnSecurityListRemove();
	afx_msg void OnUpdateSecurityListEnable(CCmdUI* pCmdUI);
	afx_msg void OnSecurityListEnable();

	DECLARE_MESSAGE_MAP()
};

#define IDC_RULES		100
#define IDC_IPLISTS		101
