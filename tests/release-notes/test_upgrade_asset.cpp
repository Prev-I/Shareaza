// Unit test for shareaza/UpgradeAsset.h, which has no MFC dependency.
// Build and run: g++ -std=c++17 -Wall -Wextra -Werror -I shareaza -o /tmp/ua tests/release-notes/test_upgrade_asset.cpp && /tmp/ua
#include "UpgradeAsset.h"
#include <cstdio>
#include <string>

static int failures = 0;
static void Expect(bool got, bool want, const char* what)
{
	if ( got != want )
	{
		++failures;
		std::printf( "FAIL %s\n  got:  %d\n  want: %d\n", what, got, want );
	}
}

int main()
{
	using UpgradeAsset::IsInstaller;

	const std::wstring base = L"https://github.com/Prev-I/Shareaza/releases/download/v2.7.11.6-previ.11/";
	const std::wstring key = L"assets.0.browser_download_url";

	Expect( IsInstaller( key, base + L"Shareaza_2.7.11.6_x64_Release.exe", L"x64", L"Release" ), true, "x64 installer" );
	Expect( IsInstaller( key, base + L"Shareaza_2.7.11.6_x64_Release.EXE", L"x64", L"Release" ), true, ".EXE, any case" );
	Expect( IsInstaller( key, base + L"Shareaza_2.7.11.6_Win32_Release.exe", L"Win32", L"Release" ), true, "Win32 installer" );
	Expect( IsInstaller( key, base + L"Shareaza_2.7.11.6_x64_Release.zip", L"x64", L"Release" ), false, "zip with Release in its name" );
	Expect( IsInstaller( key, base + L"Shareaza_2.7.11.6_x64_symbols.zip", L"x64", L"Release" ), false, "symbols zip" );
	Expect( IsInstaller( key, base + L"Shareaza_2.7.11.6_x64_Release.exe.sig", L"x64", L"Release" ), false, ".exe not at the end" );
	Expect( IsInstaller( key, base + L"Shareaza_2.7.11.6_Win32_Release.exe", L"x64", L"Release" ), false, "other platform" );
	Expect( IsInstaller( key, base + L"Shareaza_2.7.11.6_x64_Debug.exe", L"x64", L"Release" ), false, "other build type" );
	Expect( IsInstaller( L"assets.0.name", L"Shareaza_2.7.11.6_x64_Release.exe", L"x64", L"Release" ), false, "name key" );
	Expect( IsInstaller( L"body", base + L"Shareaza_2.7.11.6_x64_Release.exe", L"x64", L"Release" ), false, "body key" );
	Expect( IsInstaller( key, L".exe", L"x64", L"Release" ), false, "bare extension" );
	Expect( IsInstaller( key, L"", L"x64", L"Release" ), false, "empty URL" );

	if ( failures == 0 )
		std::printf( "all upgrade-asset tests passed\n" );
	return failures == 0 ? 0 : 1;
}
