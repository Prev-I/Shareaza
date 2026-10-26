//
// TlsVerify.cpp
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

// Stubs: the tests that use them fail until they are implemented.

#include "TlsVerify.h"

TlsCertProblem VerifyServerCertificate(PCCERT_CONTEXT, const std::wstring&)
{
	return TlsCertProblem::None;
}

TlsCertProblem ProblemFromStatus(SECURITY_STATUS)
{
	return TlsCertProblem::Other;
}

std::wstring CertFingerprintSha256(PCCERT_CONTEXT)
{
	return std::wstring();
}

std::wstring TlsHostFromUrl(const std::wstring&)
{
	return std::wstring();
}

CTlsTrustStore::CTlsTrustStore()
{
	InitializeSRWLock( &m_oLock );
	InitializeSRWLock( &m_oSaveLock );
}

bool CTlsTrustStore::IsAccepted(const std::wstring&, const std::wstring&) const
{
	return false;
}

void CTlsTrustStore::Accept(const std::wstring&, const std::wstring&)
{
}

void CTlsTrustStore::Clear()
{
}

size_t CTlsTrustStore::Count() const
{
	return 0;
}

bool CTlsTrustStore::Load(const std::wstring&)
{
	return false;
}

bool CTlsTrustStore::Save(const std::wstring&) const
{
	return false;
}

CTlsPendingPrompts::CTlsPendingPrompts()
{
	InitializeSRWLock( &m_oLock );
}

bool CTlsPendingPrompts::Add(const std::wstring&, const std::wstring&)
{
	return false;
}

void CTlsPendingPrompts::Remove(const std::wstring&, const std::wstring&)
{
}
