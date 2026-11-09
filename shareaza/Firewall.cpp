//
// Firewall.cpp
//
// Copyright (c) Shareaza Development Team, 2002-2010.
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

// CFirewall asks Windows Firewall, through its COM interface, whether Shareaza may accept incoming
// connections. It reads only: the installer owns the firewall rule.
// http://shareazasecurity.be/wiki/index.php?title=Developers.Code.CFirewall

#include "StdAfx.h"
#include "Firewall.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

CFirewall::CFirewall()
{
}

CFirewall::~CFirewall()
{
}

BOOL CFirewall::Init()
{
	// Create an instance of the firewall settings manager
	HRESULT hr = FwManager.CoCreateInstance( __uuidof( NetFwMgr ) );
	if ( SUCCEEDED( hr ) && FwManager )
	{
		// Retrieve the local firewall policy, and the profile currently in effect
		hr = FwManager->get_LocalPolicy( &Policy );
		if ( SUCCEEDED( hr ) && Policy )
			hr = Policy->get_CurrentProfile( &Profile );
	}

	return FwManager && Profile;
}

BOOL CFirewall::IsFirewallOn() const
{
	if ( ! Profile )
		return FALSE;

	VARIANT_BOOL vbEnabled = VARIANT_FALSE;
	return SUCCEEDED( Profile->get_FirewallEnabled( &vbEnabled ) ) && vbEnabled != VARIANT_FALSE;
}

// INetFwMgr::IsPortAllowed answers for the program, port and protocol without administrator
// rights, taking every profile rule in effect into account
BOOL CFirewall::IsInboundAllowed(const CString& path, LONG nPort, NET_FW_IP_PROTOCOL nProtocol, BOOL* pbAllowed) const
{
	if ( ! FwManager || ! pbAllowed )
		return FALSE;

	CComBSTR bstrPath( path );
	CComVariant vAllowed, vRestricted;
	HRESULT hr = FwManager->IsPortAllowed( bstrPath, NET_FW_IP_VERSION_ANY, nPort, NULL, nProtocol, &vAllowed, &vRestricted );
	if ( FAILED( hr ) || vAllowed.vt != VT_BOOL )
		return FALSE;

	*pbAllowed = ( vAllowed.boolVal != VARIANT_FALSE );
	return TRUE;
}
