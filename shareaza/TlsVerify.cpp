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

// CERT_CHAIN_PARA has dwUrlRetrievalTimeout only with this defined, so it
// comes before the first wincrypt.h.
#define CERT_CHAIN_PARA_HAS_EXTRA_FIELDS
#include <windows.h>
#include <wincrypt.h>

#include "TlsVerify.h"

namespace
{
	typedef std::pair< std::wstring, std::wstring > TlsEntry;	// lowercase host, uppercase fingerprint

	// Revocation is checked for every certificate but the root, as Schannel
	// does. The time limit covers all the chain's URL retrievals together,
	// so an unreachable revocation server cannot block for long.
	const DWORD TLS_CHAIN_FLAGS = CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT |
		CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT;
	const DWORD TLS_URL_RETRIEVAL_TIMEOUT_MS = 10000;

	const size_t TLS_FINGERPRINT_LENGTH = 64;	// hex digits of a SHA-256 hash
	const LONGLONG TLS_TRUST_MAX_FILE = 4 * 1024 * 1024;

	class CSharedLock
	{
	public:
		explicit CSharedLock(SRWLOCK& oLock) : m_oLock( oLock ) { AcquireSRWLockShared( &m_oLock ); }
		~CSharedLock() { ReleaseSRWLockShared( &m_oLock ); }
		CSharedLock(const CSharedLock&) = delete;
		CSharedLock& operator=(const CSharedLock&) = delete;
	private:
		SRWLOCK& m_oLock;
	};

	class CExclusiveLock
	{
	public:
		explicit CExclusiveLock(SRWLOCK& oLock) : m_oLock( oLock ) { AcquireSRWLockExclusive( &m_oLock ); }
		~CExclusiveLock() { ReleaseSRWLockExclusive( &m_oLock ); }
		CExclusiveLock(const CExclusiveLock&) = delete;
		CExclusiveLock& operator=(const CExclusiveLock&) = delete;
	private:
		SRWLOCK& m_oLock;
	};

	// Case conversion of ASCII letters only, whatever the locale.
	std::wstring LowerAscii(std::wstring s)
	{
		for ( wchar_t& c : s )
		{
			if ( c >= L'A' && c <= L'Z' )
				c = static_cast< wchar_t >( c - L'A' + L'a' );
		}
		return s;
	}

	std::wstring UpperAscii(std::wstring s)
	{
		for ( wchar_t& c : s )
		{
			if ( c >= L'a' && c <= L'z' )
				c = static_cast< wchar_t >( c - L'a' + L'A' );
		}
		return s;
	}

	bool IsHexDigit(wchar_t c)
	{
		return ( c >= L'0' && c <= L'9' ) || ( c >= L'A' && c <= L'F' ) || ( c >= L'a' && c <= L'f' );
	}

	// The key of a trust store entry: false if Accept() must ignore it.
	bool MakeTrustEntry(const std::wstring& sHost, const std::wstring& sFingerprint, TlsEntry& oEntry)
	{
		if ( sHost.empty() || sFingerprint.size() != TLS_FINGERPRINT_LENGTH )
			return false;
		for ( wchar_t c : sHost )
		{
			if ( c <= L' ' || c >= 0x7F )
				return false;
		}
		for ( wchar_t c : sFingerprint )
		{
			if ( ! IsHexDigit( c ) )
				return false;
		}
		oEntry = TlsEntry( LowerAscii( sHost ), UpperAscii( sFingerprint ) );
		return true;
	}

	// The certificate problem a CertVerifyCertificateChainPolicy error
	// reports. Never None: an error this code does not know is Other.
	TlsCertProblem ProblemFromPolicyError(DWORD nError)
	{
		const TlsCertProblem nProblem = ProblemFromStatus( static_cast< SECURITY_STATUS >( nError ) );
		return nProblem == TlsCertProblem::None ? TlsCertProblem::Other : nProblem;
	}

	TlsCertProblem EvaluateChain(PCCERT_CHAIN_CONTEXT pChain, const std::wstring& sHost)
	{
		SSL_EXTRA_CERT_CHAIN_POLICY_PARA oSsl = {};
		oSsl.cbSize = sizeof( oSsl );
		oSsl.dwAuthType = AUTHTYPE_SERVER;
		oSsl.fdwChecks = 0;
		oSsl.pwszServerName = const_cast< wchar_t* >( sHost.c_str() );

		// Missing or unreachable revocation information is not an error; a
		// certificate known to be revoked is.
		CERT_CHAIN_POLICY_PARA oPolicy = {};
		oPolicy.cbSize = sizeof( oPolicy );
		oPolicy.dwFlags = CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS;
		oPolicy.pvExtraPolicyPara = &oSsl;

		CERT_CHAIN_POLICY_STATUS oStatus = {};
		oStatus.cbSize = sizeof( oStatus );
		if ( ! CertVerifyCertificateChainPolicy( CERT_CHAIN_POLICY_SSL, pChain, &oPolicy, &oStatus ) )
			return TlsCertProblem::Other;
		if ( oStatus.dwError != 0 )
			return ProblemFromPolicyError( oStatus.dwError );

#ifdef CERT_CHAIN_POLICY_SSL_F12
		// Weak cryptography in the chain (Windows 10 and later). Windows that
		// do not know this policy fail the call, and the check is skipped.
		SSL_F12_EXTRA_CERT_CHAIN_POLICY_STATUS oF12 = {};
		oF12.cbSize = sizeof( oF12 );
		CERT_CHAIN_POLICY_STATUS oF12Status = {};
		oF12Status.cbSize = sizeof( oF12Status );
		oF12Status.pvExtraPolicyStatus = &oF12;
		if ( CertVerifyCertificateChainPolicy( CERT_CHAIN_POLICY_SSL_F12, pChain, &oPolicy, &oF12Status ) &&
			oF12.dwErrorLevel == CERT_CHAIN_POLICY_SSL_F12_ERROR_LEVEL &&
			( oF12.dwErrorCategory & CERT_CHAIN_POLICY_SSL_F12_WEAK_CRYPTO_CATEGORY ) != 0 )
		{
			return TlsCertProblem::Other;
		}
#endif

		return TlsCertProblem::None;
	}

	// Parses one line of the trust store file, without its line end.
	bool ParseTrustLine(const std::string& sLine, TlsEntry& oEntry)
	{
		const size_t nTab = sLine.find( '\t' );
		if ( nTab == std::string::npos || sLine.find( '\t', nTab + 1 ) != std::string::npos )
			return false;
		// Bytes above 0x7F are not ASCII, and MakeTrustEntry refuses them.
		std::wstring sHost, sFingerprint;
		for ( size_t i = 0 ; i < nTab ; ++i )
			sHost += static_cast< wchar_t >( static_cast< unsigned char >( sLine[ i ] ) );
		for ( size_t i = nTab + 1 ; i < sLine.size() ; ++i )
			sFingerprint += static_cast< wchar_t >( static_cast< unsigned char >( sLine[ i ] ) );
		return MakeTrustEntry( sHost, sFingerprint, oEntry );
	}
}

TlsCertProblem VerifyServerCertificate(PCCERT_CONTEXT pCert, const std::wstring& sHost)
{
	if ( pCert == NULL || sHost.empty() )
		return TlsCertProblem::Other;

	// The usages Schannel requests for a server certificate.
	char szServerAuth[] = szOID_PKIX_KP_SERVER_AUTH;
	char szServerGated[] = szOID_SERVER_GATED_CRYPTO;
	char szNetscapeGated[] = szOID_SGC_NETSCAPE;
	LPSTR pUsages[] = { szServerAuth, szServerGated, szNetscapeGated };

	CERT_CHAIN_PARA oChainPara = {};
	oChainPara.cbSize = sizeof( oChainPara );
	oChainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
	oChainPara.RequestedUsage.Usage.cUsageIdentifier = static_cast< DWORD >( sizeof( pUsages ) / sizeof( pUsages[ 0 ] ) );
	oChainPara.RequestedUsage.Usage.rgpszUsageIdentifier = pUsages;
	oChainPara.dwUrlRetrievalTimeout = TLS_URL_RETRIEVAL_TIMEOUT_MS;

	// The certificate's own store holds the intermediates the server sent.
	PCCERT_CHAIN_CONTEXT pChain = NULL;
	if ( ! CertGetCertificateChain( NULL, pCert, NULL, pCert->hCertStore, &oChainPara,
		TLS_CHAIN_FLAGS, NULL, &pChain ) )
	{
		return TlsCertProblem::Other;
	}
	const TlsCertProblem nProblem = EvaluateChain( pChain, sHost );
	CertFreeCertificateChain( pChain );
	return nProblem;
}

TlsVerdict DecideTlsVerdict(TlsCertProblem nProblem, bool bRequireValid, DWORD nPolicy, bool bRemembered)
{
	if ( nProblem == TlsCertProblem::None )
		return TlsVerdict::Accept;
	if ( bRequireValid )
		return TlsVerdict::Reject;
	switch ( nPolicy )
	{
	case TLS_POLICY_IGNORE:
		return TlsVerdict::Accept;
	case TLS_POLICY_ASK:
		return bRemembered ? TlsVerdict::Accept : TlsVerdict::AskUser;
	default:
		return TlsVerdict::Reject;
	}
}

TlsCertProblem ProblemFromStatus(SECURITY_STATUS nStatus)
{
	switch ( static_cast< HRESULT >( nStatus ) )
	{
	case SEC_E_CERT_EXPIRED:
	case CERT_E_EXPIRED:
		return TlsCertProblem::Expired;

	case SEC_E_WRONG_PRINCIPAL:
	case CERT_E_CN_NO_MATCH:
		return TlsCertProblem::WrongName;

	// CERT_E_INVALID_NAME is a name-constraint violation: an authority in the
	// chain issued a name it is not trusted for.
	case CERT_E_INVALID_NAME:
	case SEC_E_UNTRUSTED_ROOT:
	case SEC_E_ISSUING_CA_UNTRUSTED:
	case CERT_E_UNTRUSTEDROOT:
	case CERT_E_UNTRUSTEDTESTROOT:
	case CERT_E_UNTRUSTEDCA:
	case CERT_E_CHAINING:
	case TRUST_E_EXPLICIT_DISTRUST:
		return TlsCertProblem::Untrusted;

	case CRYPT_E_REVOKED:
	case CERT_E_REVOKED:
		return TlsCertProblem::Revoked;

	case SEC_E_CERT_UNKNOWN:
	case SEC_E_CERT_WRONG_USAGE:
	case CERT_E_WRONG_USAGE:
	case CERT_E_PURPOSE:
	case CERT_E_ROLE:
	case CERT_E_CRITICAL:
	case CERT_E_PATHLENCONST:
	case CERT_E_VALIDITYPERIODNESTING:
	case CERT_E_ISSUERCHAINING:
	case CERT_E_MALFORMED:
	case CERT_E_INVALID_POLICY:
	case CERT_E_REVOCATION_FAILURE:
	case CRYPT_E_NO_REVOCATION_CHECK:
	case CRYPT_E_REVOCATION_OFFLINE:
	case TRUST_E_CERT_SIGNATURE:
	case TRUST_E_BASIC_CONSTRAINTS:
		return TlsCertProblem::Other;

	default:
		return TlsCertProblem::None;
	}
}

std::wstring CertFingerprintSha256(PCCERT_CONTEXT pCert)
{
	if ( pCert == NULL )
		return std::wstring();
	BYTE pHash[ 32 ];
	DWORD nHash = sizeof( pHash );
	if ( ! CryptHashCertificate2( L"SHA256", 0, NULL, pCert->pbCertEncoded, pCert->cbCertEncoded, pHash, &nHash ) ||
		nHash != sizeof( pHash ) )
	{
		return std::wstring();
	}
	static const wchar_t szDigits[] = L"0123456789ABCDEF";
	std::wstring sHex;
	sHex.reserve( TLS_FINGERPRINT_LENGTH );
	for ( DWORD i = 0 ; i < nHash ; ++i )
	{
		sHex += szDigits[ pHash[ i ] >> 4 ];
		sHex += szDigits[ pHash[ i ] & 0x0F ];
	}
	return sHex;
}

std::wstring TlsHostFromUrl(const std::wstring& sUrl)
{
	const std::wstring sScheme = L"https://";
	if ( sUrl.size() < sScheme.size() || LowerAscii( sUrl.substr( 0, sScheme.size() ) ) != sScheme )
		return std::wstring();

	// The authority ends at the path, the query or the fragment.
	const size_t nEnd = sUrl.find_first_of( L"/?#\\", sScheme.size() );
	std::wstring sAuthority = sUrl.substr( sScheme.size(),
		nEnd == std::wstring::npos ? std::wstring::npos : nEnd - sScheme.size() );

	// Userinfo ends at the last '@'.
	const size_t nAt = sAuthority.rfind( L'@' );
	if ( nAt != std::wstring::npos )
		sAuthority.erase( 0, nAt + 1 );

	if ( ! sAuthority.empty() && sAuthority[ 0 ] == L'[' )
	{
		// An IPv6 literal: hex digits, colons and dots (an embedded IPv4
		// address), then the end or a port.
		const size_t nClose = sAuthority.find( L']' );
		if ( nClose == std::wstring::npos || nClose == 1 )
			return std::wstring();
		if ( nClose + 1 < sAuthority.size() && sAuthority[ nClose + 1 ] != L':' )
			return std::wstring();
		const std::wstring sAddress = sAuthority.substr( 1, nClose - 1 );
		for ( wchar_t c : sAddress )
		{
			if ( ! IsHexDigit( c ) && c != L':' && c != L'.' )
				return std::wstring();
		}
		return LowerAscii( sAddress );
	}

	std::wstring sHost = LowerAscii( sAuthority.substr( 0, sAuthority.find( L':' ) ) );
	if ( sHost.empty() )
		return std::wstring();
	bool bAscii = true;
	for ( wchar_t c : sHost )
	{
		if ( c <= L' ' || c == 0x7F || c == L'[' || c == L']' )
			return std::wstring();
		if ( c > 0x7F )
			bAscii = false;
	}
	if ( bAscii )
		return sHost;

	// An internationalised name: its A-label form, at most 255 characters.
	wchar_t szAscii[ 256 ];
	const int nAscii = IdnToAscii( 0, sHost.c_str(), static_cast< int >( sHost.size() ),
		szAscii, static_cast< int >( sizeof( szAscii ) / sizeof( szAscii[ 0 ] ) ) );
	if ( nAscii <= 0 )
		return std::wstring();
	return LowerAscii( std::wstring( szAscii, static_cast< size_t >( nAscii ) ) );
}

// CTlsTrustStore

CTlsTrustStore::CTlsTrustStore()
{
	InitializeSRWLock( &m_oLock );
	InitializeSRWLock( &m_oSaveLock );
}

bool CTlsTrustStore::IsAccepted(const std::wstring& sHost, const std::wstring& sFingerprint) const
{
	TlsEntry oEntry;
	if ( ! MakeTrustEntry( sHost, sFingerprint, oEntry ) )
		return false;
	CSharedLock oLock( m_oLock );
	return m_oEntries.count( oEntry ) != 0;
}

void CTlsTrustStore::Accept(const std::wstring& sHost, const std::wstring& sFingerprint)
{
	TlsEntry oEntry;
	if ( ! MakeTrustEntry( sHost, sFingerprint, oEntry ) )
		return;
	CExclusiveLock oLock( m_oLock );
	m_oEntries.insert( oEntry );
}

size_t CTlsTrustStore::Clear()
{
	CExclusiveLock oLock( m_oLock );
	const size_t nCount = m_oEntries.size();
	m_oEntries.clear();
	return nCount;
}

size_t CTlsTrustStore::Count() const
{
	CSharedLock oLock( m_oLock );
	return m_oEntries.size();
}

bool CTlsTrustStore::Load(const std::wstring& sPath)
{
	const HANDLE hFile = CreateFileW( sPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
	if ( hFile == INVALID_HANDLE_VALUE )
	{
		const DWORD nError = GetLastError();
		if ( nError != ERROR_FILE_NOT_FOUND && nError != ERROR_PATH_NOT_FOUND )
			return false;
		Clear();
		return true;
	}

	std::string sText;
	LARGE_INTEGER nSize = {};
	bool bOk = GetFileSizeEx( hFile, &nSize ) && nSize.QuadPart <= TLS_TRUST_MAX_FILE;
	if ( bOk )
	{
		sText.resize( static_cast< size_t >( nSize.QuadPart ) );
		DWORD nRead = 0;
		bOk = sText.empty() || ( ReadFile( hFile, &sText[ 0 ], static_cast< DWORD >( sText.size() ), &nRead, NULL ) &&
			nRead == sText.size() );
	}
	CloseHandle( hFile );
	if ( ! bOk )
		return false;

	if ( sText.compare( 0, 3, "\xEF\xBB\xBF" ) == 0 )
		sText.erase( 0, 3 );

	std::set< TlsEntry > oEntries;
	size_t nStart = 0;
	while ( nStart < sText.size() )
	{
		size_t nLineEnd = sText.find( '\n', nStart );
		if ( nLineEnd == std::string::npos )
			nLineEnd = sText.size();
		std::string sLine = sText.substr( nStart, nLineEnd - nStart );
		if ( ! sLine.empty() && sLine.back() == '\r' )
			sLine.pop_back();
		TlsEntry oEntry;
		if ( ParseTrustLine( sLine, oEntry ) )
			oEntries.insert( oEntry );
		nStart = nLineEnd + 1;
	}

	CExclusiveLock oLock( m_oLock );
	m_oEntries.swap( oEntries );
	return true;
}

bool CTlsTrustStore::Save(const std::wstring& sPath) const
{
	CExclusiveLock oSaveLock( m_oSaveLock );

	// Every entry is ASCII, so the text is UTF-8 as it stands.
	std::string sText;
	{
		CSharedLock oLock( m_oLock );
		for ( const TlsEntry& oEntry : m_oEntries )
		{
			for ( wchar_t c : oEntry.first )
				sText += static_cast< char >( c );
			sText += '\t';
			for ( wchar_t c : oEntry.second )
				sText += static_cast< char >( c );
			sText += '\n';
		}
	}

	const std::wstring sTemp = sPath + L".tmp";
	const HANDLE hFile = CreateFileW( sTemp.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL, NULL );
	if ( hFile == INVALID_HANDLE_VALUE )
		return false;
	DWORD nWritten = 0;
	bool bOk = ( sText.empty() || ( WriteFile( hFile, sText.data(), static_cast< DWORD >( sText.size() ), &nWritten, NULL ) &&
			nWritten == sText.size() ) ) &&
		FlushFileBuffers( hFile );
	CloseHandle( hFile );

	if ( bOk )
		bOk = MoveFileExW( sTemp.c_str(), sPath.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH ) != FALSE;
	if ( ! bOk )
		DeleteFileW( sTemp.c_str() );
	return bOk;
}

// CTlsPendingPrompts

CTlsPendingPrompts::CTlsPendingPrompts()
{
	InitializeSRWLock( &m_oLock );
}

bool CTlsPendingPrompts::Add(const std::wstring& sHost, const std::wstring& sFingerprint)
{
	CExclusiveLock oLock( m_oLock );
	return m_oEntries.insert( TlsEntry( LowerAscii( sHost ), UpperAscii( sFingerprint ) ) ).second;
}

void CTlsPendingPrompts::Remove(const std::wstring& sHost, const std::wstring& sFingerprint)
{
	CExclusiveLock oLock( m_oLock );
	m_oEntries.erase( TlsEntry( LowerAscii( sHost ), UpperAscii( sFingerprint ) ) );
}
