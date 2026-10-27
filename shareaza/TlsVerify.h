//
// TlsVerify.h
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

// Server certificate evaluation for TLS sessions, the store of certificates
// the user accepted, and the host name a URL names. Uses only Win32 and the
// standard library, so it builds without MFC and without precompiled headers.
// Every function and class here is safe to use from any thread.

#pragma once

#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif

#include <windows.h>
#include <wincrypt.h>
#include <sspi.h>

#include <set>
#include <string>
#include <utility>

enum class TlsCertProblem
{
	None,			// the certificate is valid for the host
	Expired,		// outside its validity period
	WrongName,		// not issued for the host
	Untrusted,		// does not chain to a trusted root
	Revoked,		// revoked by its issuer
	Other,			// any other problem with the certificate
	Unverifiable	// the evaluation could not run: no certificate, no host, or a failing API
};

// Evaluates a server's certificate for sHost as Schannel's automatic
// validation does: the chain (intermediates from the certificate's own store,
// as the server sent them), the server-authentication usage, the dates, the
// host name and revocation. Revocation fails soft: missing or unreachable
// revocation information is not a problem, a certificate known to be revoked
// is. Revocation fetches give up after 10 seconds in total. May block for
// that long: do not call it while holding a lock other I/O needs.
// A NULL certificate, an empty host, or a chain the system could not build or
// check is TlsCertProblem::Unverifiable.
TlsCertProblem VerifyServerCertificate(PCCERT_CONTEXT pCert, const std::wstring& sHost);

// What to do with a server whose certificate was evaluated.
enum class TlsVerdict
{
	Accept,			// use the session
	Reject,			// close it
	AskUser			// ask the user whether to accept this certificate for the host
};

// The certificate policies the user can choose. The values are those of the
// Connection.TlsCertPolicy setting.
const DWORD TLS_POLICY_VALID	= 0;	// only valid certificates
const DWORD TLS_POLICY_ASK		= 1;	// ask about any other certificate, remember the answer
const DWORD TLS_POLICY_IGNORE	= 2;	// accept every certificate

// Decides whether a session whose certificate has nProblem may be used.
// TlsCertProblem::Unverifiable is rejected under every policy: there is no
// verified certificate to accept or to ask about.
// bRequireValid (a download that must come from a validated server) accepts
// only TlsCertProblem::None, whatever the policy and the user's answers.
// Otherwise TLS_POLICY_VALID accepts only None; TLS_POLICY_IGNORE accepts
// everything; TLS_POLICY_ASK accepts None or a certificate the user accepted
// for the host before (bRemembered) and asks about anything else. Any other
// nPolicy is TLS_POLICY_VALID.
TlsVerdict DecideTlsVerdict(TlsCertProblem nProblem, bool bRequireValid, DWORD nPolicy, bool bRemembered);

// The certificate problem a failed handshake's SECURITY_STATUS (or a
// CERT_E_* / CRYPT_E_* / TRUST_E_* code) reports. None if the status is not
// a certificate error.
TlsCertProblem ProblemFromStatus(SECURITY_STATUS nStatus);

// The SHA-256 fingerprint of the certificate's DER encoding, as 64 uppercase
// hex digits. Empty for a NULL certificate.
std::wstring CertFingerprintSha256(PCCERT_CONTEXT pCert);

// The host name of an https URL: lowercase, without userinfo, port, path,
// query or fragment, an IPv6 literal without its brackets, an
// internationalised name in its A-label (punycode) form. Empty unless the
// scheme is https, or if the URL names no valid host.
std::wstring TlsHostFromUrl(const std::wstring& sUrl);

// The certificates the user accepted, by host and fingerprint. Hosts are
// ASCII, as TlsHostFromUrl() returns them, and compare case-insensitively.
// Fingerprints are 64 hex digits, compared case-insensitively.
class CTlsTrustStore
{
public:
	CTlsTrustStore();

	bool	IsAccepted(const std::wstring& sHost, const std::wstring& sFingerprint) const;
	// Ignores an empty host, a host holding anything but printable ASCII
	// other than a space, and a fingerprint that is not 64 hex digits.
	void	Accept(const std::wstring& sHost, const std::wstring& sFingerprint);
	// Returns the number of entries removed.
	size_t	Clear();
	size_t	Count() const;

	// Replaces the store with the file's entries: UTF-8, one
	// "host<TAB>fingerprint" line per entry. Malformed lines, and lines
	// Accept() would ignore, are skipped.
	// A missing file is an empty store and returns true. False if the file
	// cannot be read; the store is then unchanged.
	bool	Load(const std::wstring& sPath);
	// Writes <path>.tmp, then replaces <path> with it. LF line ends.
	bool	Save(const std::wstring& sPath) const;

private:
	typedef std::pair< std::wstring, std::wstring > Entry;	// lowercase host, uppercase fingerprint

	mutable SRWLOCK		m_oLock;		// guards m_oEntries
	mutable SRWLOCK		m_oSaveLock;	// serialises Save()
	std::set< Entry >	m_oEntries;

	CTlsTrustStore(const CTlsTrustStore&) = delete;
	CTlsTrustStore& operator=(const CTlsTrustStore&) = delete;
};

// The certificate prompts waiting for the user, so that several sources
// failing on the same host and certificate produce one prompt. Hosts and
// fingerprints compare case-insensitively (ASCII).
class CTlsPendingPrompts
{
public:
	CTlsPendingPrompts();

	// Records a prompt for the host and fingerprint. False if one is already
	// pending: the caller must not show another.
	bool	Add(const std::wstring& sHost, const std::wstring& sFingerprint);
	void	Remove(const std::wstring& sHost, const std::wstring& sFingerprint);

private:
	typedef std::pair< std::wstring, std::wstring > Entry;	// lowercase host, uppercase fingerprint

	SRWLOCK				m_oLock;
	std::set< Entry >	m_oEntries;

	CTlsPendingPrompts(const CTlsPendingPrompts&) = delete;
	CTlsPendingPrompts& operator=(const CTlsPendingPrompts&) = delete;
};
