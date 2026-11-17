# About dialog: full history and restored characters: design

Date: 2026-11-15. Status: approved by the owner on 2026-11-15; shipped in `v2.7.11.5-previ.10` (#47). The credits, the
owner's own line, approach A and the release were decided by the owner; items marked
*(designer's call)* were settled while writing.

## Intent

Help > About still looks like upstream's dialog. It shows `ï¿½` where © should be, it cuts the
first copyright line off at "All rights", it skips ivan386, it gives ansani the wrong years, and
it does not mention this fork. The change makes the dialog tell the project's real history, with
this fork as the last line, and puts back every character upstream lost.

## Cause of the missing characters

Upstream's "Bump release to 2.7.10.6" (55026f568, 2024-04-30) re-saved `shareaza/Shareaza.rc`
from Windows-1252 to UTF-8, which turned every non-ASCII byte into U+FFFD (`EF BF BD`). The
resource compiler still reads the file as code page 1252 (`#pragma code_page(1252)`), so each
U+FFFD shows as `ï¿½`. The damage covers:

- the © (`A9`) in the version info's `LegalCopyright` and in the two dialog lines;
- the non-breaking spaces (`A0`) in `IDS_SEARCH_PANEL_INPUT_5` (`" to"`) and in the spaced-out
  `IDS_MEDIA_TITLE`.

`setup/scripts/main.iss` lost its © the same way in 46767638b (2022-10-04). Inno Setup reads a
file without a BOM as ANSI, so the installer's copyright shows `ï¿½` too.

## Goals

- The dialog lists, in order:

  ```
  Copyright © Shareaza Development Team, 2002-2017
  Copyright © ivan386, 2013-2019
  Copyright © Salvatore Ansani, 2022-2024
  Copyright © Claudio Previtali (Prev-I), 2026
  ```

  The periods come from the commit history: the last SourceForge SVN commit is September 2017;
  ivan386's commits run from October 2013 to August 2019; ansani's from September 2022 to June
  2024; this fork's from October 2026. ivan386 is credited by handle, the only name his commits
  carry.
- No line is clipped, and no line overlaps another.
- The link reads `https://github.com/Prev-I/Shareaza`. A click already opens this fork's
  releases page (`WEB_SITE_T`), so only the displayed text changes.
- Every character lost in 55026f568 and 46767638b is restored, from its original byte in the
  parent revision.
- The version info and the installer carry the same history.

## Non-goals

- The `Copyright (c) Shareaza Development Team, 2002-2017.` headers in source files.
- `CompanyName` and the installer's `Publisher` stay "Shareaza Development Team".
- Other files with U+FFFD (`Languages/default-sv.*`, `ShareazaURL.cpp`, `zlibwapi/zlibwapi.rc`,
  a skin bitmap): separate damage, not this change.
- A new banner image.

## Release

Part of previ.10 (2.7.11.5), with the items deferred from previ.9. This change is its own pull
request into `main`; the version bump stays previ.10's separate, last pull request, as in earlier
releases.

## Approaches

- **A. The dialog states the history itself, and the file stays Windows-1252 (chosen by the
  owner).** The four lines are written in the dialog template, and `CAboutDlg` stops copying
  `LegalCopyright` into the first line. The version info and the installer get a one-line form.
  The characters return as their original single bytes. The trade-off is that the history is
  written twice, and an editor that saves as UTF-8 could break the file again. A guard (below)
  catches that.
- B. The same dialog, with `Shareaza.rc` switched to UTF-8 (`code_page(65001)`). This changes how
  the compiler reads the whole 4,600-line file. Only CI can build it, and it makes this file
  differ from every other `.rc` in the tree. Not chosen.
- C. The dialog keeps reading `LegalCopyright`, which would then hold four lines. Explorer shows
  that value as one run-on string. Dropped.

## The change

1. **`shareaza/Shareaza.rc`, `IDD_ABOUT`.** Title at y 15; four copyright `LTEXT`s with
   `IDC_STATIC`, 10 DLU tall and 10 DLU apart, from y 27; the GPL text, logo credit, MaxMind line
   and link move down by the space the extra lines take; the dialog grows to fit, with the OK
   button below the link rather than beside it *(designer's call: exact coordinates are left to
   the implementation, checked against the rules above)*. The duplicate `IDC_COPYRIGHT` IDs go.
2. **`shareaza/DlgAbout.cpp`.** Remove the `GetFileVersionInfo` / `VerQueryValue` block that
   overwrote the first line. `IDC_COPYRIGHT` stays defined in `resource.h`, unused.
3. **Version info `LegalCopyright`** and **installer `AppCopyright`**: one line, `Copyright ©
   Shareaza Development Team 2002-2017, ivan386 2013-2019, Salvatore Ansani 2022-2024, Claudio
   Previtali (Prev-I) 2026`. "All rights reserved." is dropped *(designer's call: the old line
   claimed it for one party, and the software is GPL)*.
4. **Restored bytes.** © as `A9`, and the non-breaking spaces in `IDS_SEARCH_PANEL_INPUT_5` and
   `IDS_MEDIA_TITLE` copied byte for byte from 55026f568's parent. After the change neither file
   contains `EF BF BD`, and both are valid Windows-1252.
5. **Guard** *(designer's call)*. A comment at the top of `Shareaza.rc` says it is Windows-1252.
   A step in `msbuild.yml` fails when `shareaza/Shareaza.rc` or `setup/scripts/main.iss` contains
   `EF BF BD`. A `.gitattributes` `encoding=cp1252` entry for both lets `gitk` and `git gui`
   display them correctly.

## Verification

- Byte checks in the pull request: no `EF BF BD` in either file; the restored strings match the
  parent revision's bytes.
- `msbuild.yml` builds x64 and Win32 green, the new guard included.
- The owner checks the About dialog, Explorer's file properties and the installer in a CI build.
  The Windows oracle's screenshots do not cover the About dialog.

## Left to the builder

The dialog coordinates, and the wording of the comment and of the CI step.
