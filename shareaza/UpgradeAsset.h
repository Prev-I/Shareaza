//
// UpgradeAsset.h
//
// Copyright (c) Shareaza Development Team, 2026.
// This file is part of SHAREAZA (shareaza.sourceforge.net)
//
// Shareaza is free software; you can redistribute it
// and/or modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// Shareaza is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Shareaza; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
//

// Chooses which asset of a GitHub release is the update installer, and the rules that
// keep the update download's exemption from IP filtering to the update itself.
// Header-only and free of MFC, so tests/release-notes/ can build it with any compiler.

#pragma once

#include <cwctype>
#include <string>
#include <vector>

namespace UpgradeAsset
{
	// True if a key/value pair of the release response names this build's installer:
	// an asset's download URL that names the platform and build type and ends in .exe.
	inline bool IsInstaller(const std::wstring& key, const std::wstring& url,
		const std::wstring& platform, const std::wstring& buildType)
	{
		if ( key.compare( 0, 5, L"asset" ) != 0 || key.find( L"browser_download_url" ) == std::wstring::npos )
			return false;

		if ( url.find( platform ) == std::wstring::npos || url.find( buildType ) == std::wstring::npos )
			return false;

		static const wchar_t szExt[] = L".exe";
		const size_t nExt = 4;
		if ( url.size() <= nExt )
			return false;

		for ( size_t i = 0; i < nExt; ++i )
		{
			if ( static_cast< wchar_t >( std::towlower( url[ url.size() - nExt + i ] ) ) != szExt[ i ] )
				return false;
		}
		return true;
	}

	// The URLs to give back to a resumed update download, so its official source redirects
	// afresh: the https pieces of the update check's source list, trimmed, or none unless the
	// download is the update the check found. A size of 0 or ~0 is unknown.
	inline std::vector< std::wstring > ReseedURLs(const std::wstring& downloadName,
		unsigned long long downloadSize, const std::wstring& upgradeFile,
		const std::wstring& upgradeSources, unsigned long long upgradeSize, bool versionNewer)
	{
		std::vector< std::wstring > urls;
		const unsigned long long unknown = ~0ull;

		if ( ! versionNewer || upgradeFile.empty() || downloadName != upgradeFile )
			return urls;
		if ( downloadSize != 0 && downloadSize != unknown &&
			 upgradeSize != 0 && upgradeSize != unknown && downloadSize != upgradeSize )
			return urls;

		static const wchar_t szWhite[] = L" \t\r\n";
		for ( size_t nStart = 0 ; nStart <= upgradeSources.size() ; )
		{
			size_t nEnd = upgradeSources.find( L',', nStart );
			if ( nEnd == std::wstring::npos )
				nEnd = upgradeSources.size();

			std::wstring url = upgradeSources.substr( nStart, nEnd - nStart );
			const size_t nFirst = url.find_first_not_of( szWhite );
			url = ( nFirst == std::wstring::npos ) ? std::wstring() :
				url.substr( nFirst, url.find_last_not_of( szWhite ) - nFirst + 1 );

			if ( url.compare( 0, 8, L"https://" ) == 0 && url.size() > 8 )
				urls.push_back( url );

			nStart = nEnd + 1;
		}
		return urls;
	}

	// A redirect target joins the exemption only when the source that redirected was exempt,
	// the download is the update, and the redirect came over TLS validated for the source's host.
	inline bool RedirectStaysExempt(bool sourceExempt, bool requireValidCert, bool tlsValidated)
	{
		return sourceExempt && requireValidCert && tlsValidated;
	}
}
