//
// TlsPolicy.cpp
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

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

// The setting's values are the policies DecideTlsVerdict knows
static_assert( static_cast< DWORD >( TLS_CERT_VALID ) == TLS_POLICY_VALID, "TLS_CERT_VALID" );
static_assert( static_cast< DWORD >( TLS_CERT_ASK ) == TLS_POLICY_ASK, "TLS_CERT_ASK" );
static_assert( static_cast< DWORD >( TLS_CERT_IGNORE ) == TLS_POLICY_IGNORE, "TLS_CERT_IGNORE" );

CTlsTrustStore TlsTrust;

namespace
{
	CString TlsTrustPath()
	{
		return Settings.General.UserPath + L"\\Data\\TlsTrust.dat";
	}
}

void LoadTlsTrust()
{
	if ( ! TlsTrust.Load( std::wstring( (LPCWSTR)TlsTrustPath() ) ) )
		theApp.Message( MSG_ERROR, _T("Unable to read the accepted certificates from %s."), (LPCTSTR)TlsTrustPath() );
}

bool SaveTlsTrust()
{
	return TlsTrust.Save( std::wstring( (LPCWSTR)TlsTrustPath() ) );
}

TlsVerdict EvaluateTlsPeer(TlsCertProblem nProblem, const CString& sHost, const CString& sFingerprint, bool bRequireValid)
{
	// The store is consulted only when the answer can matter
	const DWORD nPolicy = Settings.Connection.TlsCertPolicy;
	const bool bRemembered = nProblem != TlsCertProblem::None && ! bRequireValid && nPolicy == TLS_POLICY_ASK &&
		TlsTrust.IsAccepted( std::wstring( (LPCWSTR)sHost ), std::wstring( (LPCWSTR)sFingerprint ) );
	return DecideTlsVerdict( nProblem, bRequireValid, nPolicy, bRemembered );
}
