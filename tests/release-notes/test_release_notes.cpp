// Unit test for shareaza/ReleaseNotes.h, which has no MFC dependency.
// Build and run: g++ -std=c++17 -I shareaza -o /tmp/rn tests/release-notes/test_release_notes.cpp && /tmp/rn
// wchar_t is 32-bit on Linux; surrogate pairs are written out as two code units to test the cut.
#include "ReleaseNotes.h"
#include <cstdio>
#include <string>

static int failures = 0;
static void Expect(const std::wstring& got, const std::wstring& want, const char* what)
{
	if ( got != want )
	{
		++failures;
		std::printf( "FAIL %s\n  got:  [%ls]\n  want: [%ls]\n", what, got.c_str(), want.c_str() );
	}
}
static void ExpectTrue(bool ok, const char* what)
{
	if ( ! ok ) { ++failures; std::printf( "FAIL %s\n", what ); }
}

int main()
{
	using namespace ReleaseNotes;

	Expect( ToPlainText( L"**bold** and `code` [link](http://x) __under__" ), L"bold and code link under", "inline marks and links" );
	Expect( ToPlainText( L"# Head\n## Sub head" ), L"Head\nSub head", "headings" );
	Expect( ToPlainText( L"* a\n- b\n  * c" ), L"\x2022 a\n\x2022 b\n\x2022 c", "bullets" );
	Expect( ToPlainText( L"x <b>y</b> <br/> z" ), L"x y z", "html tags" );
	Expect( ToPlainText( L"![alt](http://img) after" ), L"alt after", "images" );
	Expect( ToPlainText( L"a\r\nb" ), L"a\nb", "CRLF" );
	Expect( ToPlainText( L"5 < 6 and 7 > 3" ), L"5 < 6 and 7 > 3", "comparisons are not tags" );

	Expect( Summary( L"First **para** line\ncontinues.\n\nSecond para." ), L"First para line continues.", "first paragraph" );
	Expect( Summary( L"\r\n\r\n  \r\nReal one.\r\n\r\nNext." ), L"Real one.", "leading blank lines, CRLF" );
	Expect( Summary( L"**\n\n##" ), L"", "markup only" );
	Expect( Summary( L"" ), L"", "empty" );
	Expect( Summary( L"**\n\nText after markup." ), L"Text after markup.", "skips a paragraph that is only markup" );

	std::wstring longPara;
	for ( int i = 0; i < 100; ++i ) longPara += L"word ";
	std::wstring s = Summary( longPara );
	ExpectTrue( s.size() <= 401, "cut length <= 401" );
	ExpectTrue( ! s.empty() && s.back() == L'\x2026', "cut ends with an ellipsis" );
	ExpectTrue( s.size() >= 2 && s[ s.size() - 2 ] == L'd', "cut at a word boundary (ends on 'word')" );

	std::wstring noSpaces( 399, L'a' );
	noSpaces += L"\xD83D\xDEE1";	// a surrogate pair straddling position 400
	noSpaces += std::wstring( 50, L'b' );
	s = Summary( noSpaces );
	ExpectTrue( s.size() >= 2 && s[ s.size() - 2 ] != L'\xD83D', "cut never leaves a lone high surrogate" );
	ExpectTrue( s.size() <= 401, "cut without spaces <= 401" );

	Expect( DatePart( L"2026-11-10T22:27:48Z" ), L"2026-11-10", "ISO date" );
	Expect( DatePart( L"yesterday" ), L"yesterday", "malformed date kept" );
	Expect( DatePart( L"" ), L"", "empty date" );

	std::printf( failures ? "%d FAILED\n" : "all release-notes tests passed\n", failures );
	return failures ? 1 : 0;
}
