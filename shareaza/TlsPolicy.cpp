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
CTlsPendingPrompts TlsPendingPrompts;

namespace
{
	CString TlsTrustPath()
	{
		return Settings.General.UserPath + L"\\Data\\TlsTrust.dat";
	}

	// The file holds what TlsTrust holds: it was read, or TlsTrust was written to it.
	// Only the UI thread loads and saves the store.
	bool g_bTlsTrustInFile = false;
}

void LoadTlsTrust()
{
	g_bTlsTrustInFile = TlsTrust.Load( std::wstring( (LPCWSTR)TlsTrustPath() ) );
	if ( ! g_bTlsTrustInFile )
		theApp.Message( MSG_ERROR, IDS_TLS_TRUST_LOAD_FAILED, (LPCTSTR)TlsTrustPath() );
}

bool SaveTlsTrust()
{
	if ( ! TlsTrust.Save( std::wstring( (LPCWSTR)TlsTrustPath() ) ) )
		return false;
	g_bTlsTrustInFile = true;
	return true;
}

void SaveTlsTrustAtExit()
{
	// A file that could not be read is not replaced by the empty store: the user's
	// answers were saved when they were given.
	if ( g_bTlsTrustInFile && ! SaveTlsTrust() )
		theApp.Message( MSG_ERROR, IDS_TLS_TRUST_SAVE_FAILED );
}

TlsVerdict EvaluateTlsPeer(TlsCertProblem nProblem, const CString& sHost, const CString& sFingerprint, bool bRequireValid)
{
	// The store is consulted only when the answer can matter
	const DWORD nPolicy = Settings.Connection.TlsCertPolicy;
	const bool bRemembered = nProblem != TlsCertProblem::None && ! bRequireValid && nPolicy == TLS_POLICY_ASK &&
		TlsTrust.IsAccepted( std::wstring( (LPCWSTR)sHost ), std::wstring( (LPCWSTR)sFingerprint ) );
	return DecideTlsVerdict( nProblem, bRequireValid, nPolicy, bRemembered );
}

CString TlsProblemText(TlsCertProblem nProblem)
{
	switch ( nProblem )
	{
	case TlsCertProblem::Expired:
		return LoadString( IDS_TLS_REASON_EXPIRED );
	case TlsCertProblem::WrongName:
		return LoadString( IDS_TLS_REASON_WRONGNAME );
	case TlsCertProblem::Untrusted:
		return LoadString( IDS_TLS_REASON_UNTRUSTED );
	case TlsCertProblem::Revoked:
		return LoadString( IDS_TLS_REASON_REVOKED );
	default:
		return LoadString( IDS_TLS_REASON_OTHER );
	}
}

bool RequestTlsDecision(const CString& sHost, const CString& sFingerprint, TlsCertProblem nProblem)
{
	const std::wstring sKeyHost( (LPCWSTR)sHost ), sKeyFingerprint( (LPCWSTR)sFingerprint );

	// The same question is already waiting: its answer covers this source too
	if ( ! TlsPendingPrompts.Add( sKeyHost, sKeyFingerprint ) )
		return true;

	CTlsPromptRequest* pRequest = new CTlsPromptRequest;
	pRequest->sHost			= sHost;
	pRequest->sFingerprint	= sFingerprint;
	pRequest->nProblem		= nProblem;

	if ( PostMainWndMessage( WM_TLSPROMPT, 0, reinterpret_cast< LPARAM >( pRequest ) ) )
		return true;

	delete pRequest;
	TlsPendingPrompts.Remove( sKeyHost, sKeyFingerprint );
	return false;
}
