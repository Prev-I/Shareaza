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

// Chooses which asset of a GitHub release is the update installer.
// Header-only and free of MFC, so tests/release-notes/ can build it with any compiler.

#pragma once

#include <cwctype>
#include <string>

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
}
