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

// The verdict for a TLS session with sHost whose certificate (fingerprint
// sFingerprint) had nProblem, under the user's certificate policy and the
// certificates the user accepted. bRequireValid accepts only a valid
// certificate, whatever the policy.
TlsVerdict EvaluateTlsPeer(TlsCertProblem nProblem, const CString& sHost, const CString& sFingerprint, bool bRequireValid);
