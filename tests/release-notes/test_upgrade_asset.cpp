// Unit test for shareaza/UpgradeAsset.h, which has no MFC dependency.
// Build and run: g++ -std=c++17 -Wall -Wextra -Werror -I shareaza -o /tmp/ua tests/release-notes/test_upgrade_asset.cpp && /tmp/ua
#include "UpgradeAsset.h"
#include <cstdio>
#include <string>
#include <vector>

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

	// Re-seeding a resumed update download with the official URL
	using UpgradeAsset::ReseedURLs;
	const std::wstring file = L"iShareaza_2.7.11.6_x64.exe";
	const std::wstring official = base + file;
	const unsigned long long unknown = ~0ull;

	{
		const std::vector< std::wstring > got = ReseedURLs( file, unknown, file, official, 0, true );
		Expect( got.size() == 1 && got[ 0 ] == official, true, "matching update: the official URL" );
	}
	Expect( ReseedURLs( file, 1000, file, official, 1000, true ).size() == 1, true, "same known size" );
	Expect( ReseedURLs( file, 1000, file, official, 0, true ).size() == 1, true, "release size unknown" );
	Expect( ReseedURLs( file, 1000, file, official, 2000, true ).empty(), true, "different size" );
	Expect( ReseedURLs( file, unknown, file, official, 1000, true ).size() == 1, true, "download size unknown" );
	Expect( ReseedURLs( file, 0, file, official, 1000, true ).size() == 1, true, "download size 0 is unknown" );
	Expect( ReseedURLs( file, unknown, file, L"HTTPS://example.org/" + file, 0, true ).empty(), true, "scheme compared exactly" );
	Expect( ReseedURLs( L"iShareaza_2.7.11.5_x64.exe", unknown, file, official, 0, true ).empty(), true, "older release's file" );
	Expect( ReseedURLs( L"ISHAREAZA_2.7.11.6_X64.EXE", unknown, file, official, 0, true ).empty(), true, "name compared exactly" );
	Expect( ReseedURLs( file, unknown, file, official, 0, false ).empty(), true, "no newer version" );
	Expect( ReseedURLs( file, unknown, L"", official, 0, true ).empty(), true, "no update file" );
	Expect( ReseedURLs( file, unknown, file, L"", 0, true ).empty(), true, "no update source" );
	Expect( ReseedURLs( file, unknown, file, L"http://example.com/" + file, 0, true ).empty(), true, "plain http dropped" );
	{
		const std::vector< std::wstring > got = ReseedURLs( file, unknown, file,
			L" " + official + L" , http://example.com/x.exe,, https://example.org/y.exe", 0, true );
		Expect( got.size() == 2 && got[ 0 ] == official && got[ 1 ] == L"https://example.org/y.exe", true,
			"comma list: trimmed https pieces only" );
	}

	// A redirect keeps the exemption only from an exempt source of an update download over validated TLS
	using UpgradeAsset::RedirectStaysExempt;
	Expect( RedirectStaysExempt( true, true, true ), true, "exempt source, update, validated" );
	Expect( RedirectStaysExempt( false, true, true ), false, "source not exempt" );
	Expect( RedirectStaysExempt( true, false, true ), false, "not an update download" );
	Expect( RedirectStaysExempt( true, true, false ), false, "TLS not validated" );

	if ( failures == 0 )
		std::printf( "all upgrade-asset tests passed\n" );
	return failures == 0 ? 0 : 1;
}
