//
// Firewall.h
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

#pragma once


// Reads Windows Firewall state. The client runs without administrator rights, so it never
// changes firewall policy: the installer owns the rule that lets Shareaza receive traffic.
class CFirewall
{
public:
	CFirewall();
	~CFirewall();

	// Windows Firewall COM interfaces
	CComPtr< INetFwMgr >		FwManager;
	CComPtr< INetFwPolicy >		Policy;
	CComPtr< INetFwProfile >	Profile;

	// Initialization: TRUE when the firewall manager and the current profile are available
	BOOL Init();
	// TRUE when the firewall is on for the profile currently in effect
	BOOL IsFirewallOn() const;
	// Whether the program may receive inbound traffic on the port with the protocol
	// (NET_FW_IP_PROTOCOL_TCP or _UDP). Returns FALSE when the check could not run.
	BOOL IsInboundAllowed(const CString& path, LONG nPort, NET_FW_IP_PROTOCOL nProtocol, BOOL* pbAllowed) const;
};
