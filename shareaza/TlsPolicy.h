//
// TlsPolicy.h
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

// The application's side of the TLS certificate policy: the store of the
// certificates the user accepted, and the verdict for a verified session
// under the user's Connection.TlsCertPolicy setting.

#pragma once

#include "TlsVerify.h"

// The certificates the user accepted, by host and fingerprint.
extern CTlsTrustStore TlsTrust;

// Loads TlsTrust from Data\TlsTrust.dat in the user's folder. A missing file is an empty store.
void LoadTlsTrust();
// Saves TlsTrust to Data\TlsTrust.dat in the user's folder. False if it could not be written.
bool SaveTlsTrust();
// Saves TlsTrust at exit, unless the file could not be read and nothing was saved since:
// an empty store would overwrite the user's file.
void SaveTlsTrustAtExit();

// The verdict for a TLS session with sHost whose certificate (fingerprint
// sFingerprint) had nProblem, under the user's certificate policy and the
// certificates the user accepted. bRequireValid accepts only a valid
// certificate, whatever the policy.
TlsVerdict EvaluateTlsPeer(TlsCertProblem nProblem, const CString& sHost, const CString& sFingerprint, bool bRequireValid);

// The text that says why a certificate was not valid: the reason the log and
// the certificate prompt give.
CString TlsProblemText(TlsCertProblem nProblem);

// The certificate prompts waiting for the user, so that several sources failing
// on the same host and certificate produce one prompt.
extern CTlsPendingPrompts TlsPendingPrompts;

// A question for the user: may the certificate with sFingerprint, which had
// nProblem, be trusted for sHost? Sent to the main window with WM_TLSPROMPT,
// which owns it from then on.
struct CTlsPromptRequest
{
	CString			sHost;
	CString			sFingerprint;
	TlsCertProblem	nProblem;
};

// Asks the user whether to trust the certificate with sFingerprint for sHost,
// unless the same question is already waiting for an answer. The answer reaches
// the sources through CDownloads::OnTlsDecision(). True if a question is waiting,
// false if none could be asked (the main window is gone): the certificate must
// then be rejected. Call with Transfers.m_pSection held: the answer is passed
// on under it, so a source that asks before the answer is waiting for it.
bool RequestTlsDecision(const CString& sHost, const CString& sFingerprint, TlsCertProblem nProblem);
