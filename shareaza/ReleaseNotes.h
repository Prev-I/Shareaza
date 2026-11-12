//
// ReleaseNotes.h
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

// Turns a release's Markdown notes into short plain text for the update notice.
// Header-only and free of MFC, so tests/release-notes/ can build it with any compiler.

#pragma once

#include <cwctype>
#include <string>
#include <vector>

namespace ReleaseNotes
{
	namespace Detail
	{
		inline bool IsSpace(wchar_t c)
		{
			return c == L' ' || c == L'\t' || c == L'\r' || c == L'\n';
		}

		inline std::wstring Trim(const std::wstring& s)
		{
			size_t b = 0, e = s.size();
			while ( b < e && IsSpace( s[ b ] ) ) ++b;
			while ( e > b && IsSpace( s[ e - 1 ] ) ) --e;
			return s.substr( b, e - b );
		}

		// Collapses runs of spaces and tabs into one space, and trims.
		inline std::wstring Squeeze(const std::wstring& s)
		{
			std::wstring out;
			bool bSpace = false;
			for ( wchar_t c : s )
			{
				if ( c == L' ' || c == L'\t' )
				{
					bSpace = true;
					continue;
				}
				if ( bSpace && ! out.empty() ) out += L' ';
				bSpace = false;
				out += c;
			}
			return out;
		}

		inline std::vector< std::wstring > Lines(const std::wstring& s)
		{
			std::vector< std::wstring > lines;
			std::wstring line;
			for ( wchar_t c : s )
			{
				if ( c == L'\r' ) continue;
				if ( c == L'\n' )
				{
					lines.push_back( line );
					line.clear();
				}
				else
					line += c;
			}
			lines.push_back( line );
			return lines;
		}

		// Drops what is never summary text: fenced code blocks (``` or ~~~, any info string, fence
		// lines included; an unclosed fence runs to the end) and HTML comments (up to "-->", across
		// lines), and turns a thematic-break line (three or more of * - _, spaces allowed) into an
		// empty line. Done on the whole text, before it is cut into paragraphs, so that a block
		// holding blank lines cannot leak its inside into the summary.
		inline std::wstring RemoveBlocks(const std::wstring& markdown)
		{
			std::vector< std::wstring > kept;
			wchar_t cFence = 0;
			for ( const std::wstring& raw : Lines( markdown ) )
			{
				std::wstring line = Trim( raw );
				wchar_t c = line.empty() ? L'\0' : line[ 0 ];
				bool bFence = ( c == L'`' || c == L'~' ) && line.size() >= 3 &&
					line[ 1 ] == c && line[ 2 ] == c;
				// A backtick fence's info string holds no backtick: "```x``` is faster" is text
				if ( bFence && c == L'`' )
				{
					size_t nRun = 0;
					while ( nRun < line.size() && line[ nRun ] == c ) ++nRun;
					if ( line.find( L'`', nRun ) != std::wstring::npos ) bFence = false;
				}
				if ( cFence )
				{
					if ( bFence && c == cFence ) cFence = 0;	// the closing fence
					continue;
				}
				if ( bFence )
				{
					cFence = c;	// the opening fence
					continue;
				}
				kept.push_back( raw );
			}

			std::wstring text;
			for ( size_t i = 0 ; i < kept.size() ; ++i )
			{
				if ( i ) text += L'\n';
				text += kept[ i ];
			}

			// HTML comments: an unclosed one runs to the end
			std::wstring clean;
			for ( size_t i = 0 ; i < text.size() ; )
			{
				if ( text.compare( i, 4, L"<!--" ) == 0 )
				{
					size_t end = text.find( L"-->", i + 4 );
					if ( end == std::wstring::npos ) break;
					i = end + 3;
					continue;
				}
				clean += text[ i++ ];
			}

			// Thematic breaks: only marks of one kind and spaces, at least three marks
			std::wstring out;
			bool bFirst = true;
			for ( const std::wstring& line : Lines( clean ) )
			{
				wchar_t cMark = 0;
				size_t nMarks = 0;
				bool bRule = true;
				for ( wchar_t c : line )
				{
					if ( c == L' ' || c == L'\t' || c == L'\r' ) continue;
					if ( ( c == L'*' || c == L'-' || c == L'_' ) && ( cMark == 0 || cMark == c ) )
					{
						cMark = c;
						++nMarks;
					}
					else
					{
						bRule = false;
						break;
					}
				}
				if ( ! bFirst ) out += L'\n';
				bFirst = false;
				if ( ! ( bRule && nMarks >= 3 ) ) out += line;
			}
			return out;
		}

		// Inline Markdown and HTML of one line: links and images keep their text, emphasis and
		// code marks go, tags go. A '<' not followed by a letter, '/' or '!' is kept as text.
		inline std::wstring Inline(const std::wstring& s)
		{
			std::wstring out;
			for ( size_t i = 0 ; i < s.size() ; )
			{
				wchar_t c = s[ i ];

				if ( c == L'!' && i + 1 < s.size() && s[ i + 1 ] == L'[' )
				{
					++i;	// an image: keep its alt text like a link's text
					continue;
				}
				if ( c == L'[' )
				{
					size_t close = s.find( L']', i + 1 );
					if ( close != std::wstring::npos && close + 1 < s.size() && s[ close + 1 ] == L'(' )
					{
						size_t end = s.find( L')', close + 2 );
						if ( end != std::wstring::npos )
						{
							out += Inline( s.substr( i + 1, close - i - 1 ) );
							i = end + 1;
							continue;
						}
					}
				}
				if ( c == L'<' && i + 1 < s.size() &&
					( std::iswalpha( s[ i + 1 ] ) || s[ i + 1 ] == L'/' || s[ i + 1 ] == L'!' ) )
				{
					size_t end = s.find( L'>', i + 1 );
					if ( end != std::wstring::npos )
					{
						i = end + 1;
						continue;
					}
				}
				if ( c == L'\\' && i + 1 < s.size() && s[ i + 1 ] < 0x80 && std::iswpunct( s[ i + 1 ] ) )
				{
					out += s[ i + 1 ];	// an escape: the punctuation is literal text, the backslash goes
					i += 2;
					continue;
				}
				if ( c == L'`' )
				{
					++i;
					continue;
				}
				if ( ( c == L'*' || c == L'_' ) && i + 1 < s.size() && s[ i + 1 ] == c )
				{
					i += 2;
					continue;
				}
				if ( c == L'*' || c == L'_' )
				{
					// A single emphasis mark goes, unless it is part of a word (snake_case) or
					// stands alone between spaces (5 * 3).
					wchar_t p = i > 0 ? s[ i - 1 ] : L'\0', n = i + 1 < s.size() ? s[ i + 1 ] : L'\0';
					bool bWord = std::iswalnum( p ) && std::iswalnum( n );
					bool bAlone = p == L' ' && n == L' ';
					if ( ! bWord && ! bAlone )
					{
						++i;
						continue;
					}
				}
				out += c;
				++i;
			}
			return out;
		}

		// True when the text holds something readable: a letter or a digit, or a non-ASCII
		// character other than the bullet and the ellipsis this file adds itself.
		inline bool HasText(const std::wstring& s)
		{
			for ( wchar_t c : s )
				if ( std::iswalnum( c ) || ( c > 0x7F && c != 0x2022 && c != 0x2026 ) ) return true;
			return false;
		}

		inline bool IsHighSurrogate(wchar_t c)
		{
			return c >= 0xD800 && c <= 0xDBFF;
		}
	}

	// Markdown to plain text, line by line: headings lose their '#', list items become
	// "• item", links and images keep their text, emphasis, code marks and tags go.
	inline std::wstring ToPlainText(const std::wstring& markdown)
	{
		using namespace Detail;
		std::wstring out;
		bool bFirst = true;
		for ( std::wstring line : Lines( RemoveBlocks( markdown ) ) )
		{
			line = Trim( line );

			// Blockquote marks, nested or not, with the space after each
			while ( ! line.empty() && line[ 0 ] == L'>' )
			{
				line = line.substr( ( line.size() > 1 && line[ 1 ] == L' ' ) ? 2 : 1 );
				line = Trim( line );
			}

			size_t nHash = 0;
			while ( nHash < line.size() && line[ nHash ] == L'#' ) ++nHash;
			if ( nHash > 0 && ( nHash == line.size() || line[ nHash ] == L' ' ) )
				line = Trim( line.substr( nHash ) );

			std::wstring bullet;
			if ( line.size() >= 2 && ( line[ 0 ] == L'*' || line[ 0 ] == L'-' || line[ 0 ] == L'+' ) && line[ 1 ] == L' ' )
			{
				bullet = L"\x2022 ";
				line = line.substr( 2 );
			}

			line = Squeeze( Inline( line ) );
			if ( ! bullet.empty() ) line = bullet + line;

			if ( ! bFirst ) out += L'\n';
			out += line;
			bFirst = false;
		}
		return out;
	}

	// The first paragraph that has readable text, as one plain line, cut at a word boundary to
	// at most maxChars characters with an ellipsis. Paragraphs are separated by blank lines.
	inline std::wstring Summary(const std::wstring& markdown, size_t maxChars = 400)
	{
		using namespace Detail;
		std::vector< std::wstring > lines = Lines( RemoveBlocks( markdown ) );
		std::wstring para;

		auto flush = [&]() -> std::wstring
		{
			std::wstring text = ToPlainText( para );
			for ( wchar_t& c : text ) if ( c == L'\n' ) c = L' ';
			text = Squeeze( text );
			para.clear();
			return HasText( text ) ? text : std::wstring();
		};

		std::wstring summary;
		for ( size_t i = 0 ; i <= lines.size() && summary.empty() ; ++i )
		{
			if ( i == lines.size() || Trim( lines[ i ] ).empty() )
			{
				if ( ! para.empty() ) summary = flush();
				continue;
			}
			if ( ! para.empty() ) para += L'\n';
			para += lines[ i ];
		}

		if ( summary.size() <= maxChars ) return summary;

		size_t cut = summary.rfind( L' ', maxChars );
		if ( cut == std::wstring::npos || cut == 0 )
		{
			cut = maxChars;
			if ( IsHighSurrogate( summary[ cut - 1 ] ) ) --cut;	// never split a surrogate pair
		}
		return Trim( summary.substr( 0, cut ) ) + L"\x2026";
	}

	// The date part of an ISO 8601 timestamp ("2026-11-10T22:27:48Z" gives "2026-11-10");
	// anything else is returned unchanged.
	inline std::wstring DatePart(const std::wstring& iso8601)
	{
		if ( iso8601.size() >= 10 && iso8601[ 4 ] == L'-' && iso8601[ 7 ] == L'-' &&
			std::iswdigit( iso8601[ 0 ] ) && std::iswdigit( iso8601[ 9 ] ) )
			return iso8601.substr( 0, 10 );
		return iso8601;
	}

	// The text of the upgrade prompt: "Version <version>, released <date>. <summary>", the date
	// and the summary left out when empty, at most maxChars characters in all. The summary gets
	// what the rest leaves, less the space and the ellipsis; when that is too little for a
	// readable summary it is left out, and a prompt that is too long by itself is cut.
	inline std::wstring UpgradePrompt(const std::wstring& version, const std::wstring& isoDate,
		const std::wstring& markdown, size_t maxChars = 400)
	{
		std::wstring prompt = L"Version " + version;
		if ( ! isoDate.empty() ) prompt += L", released " + DatePart( isoDate );
		prompt += L".";

		// Never over maxChars: cut a too long prompt, keeping its closing period
		if ( prompt.size() > maxChars )
		{
			size_t cut = maxChars > 0 ? maxChars - 1 : 0;
			if ( cut > 0 && Detail::IsHighSurrogate( prompt[ cut - 1 ] ) ) --cut;	// never split a surrogate pair
			prompt = prompt.substr( 0, cut );
			if ( maxChars > 0 ) prompt += L".";
			return prompt;
		}

		const size_t kMinSummary = 8;
		if ( prompt.size() + 2 + kMinSummary > maxChars ) return prompt;

		std::wstring summary = Summary( markdown, maxChars - prompt.size() - 2 );
		if ( ! summary.empty() ) prompt += L" " + summary;
		return prompt;
	}
}
