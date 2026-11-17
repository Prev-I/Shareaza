# About dialog history and restored characters Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Help > About lists the project's whole history with this fork last, nothing in it is
clipped, and every character upstream's UTF-8 re-save destroyed is back.

**Architecture:** The dialog template in `shareaza/Shareaza.rc` states the four copyright lines
itself; `CAboutDlg` stops overwriting the first one from the version info. `Shareaza.rc` and
`setup/scripts/main.iss` stay Windows-1252, and a small check script, run by CI, fails the build if
either ever holds U+FFFD again.

**Tech Stack:** MFC resource script (rc.exe, code page 1252), C++ (MFC), Inno Setup 6, GitHub
Actions (`windows-2022`), Python 3 for the check.

**Spec:** `docs/superpowers/specs/2026-11-15-about-history-design.md`

## Global Constraints

- Both files stay Windows-1252 with no BOM; `#pragma code_page(1252)` is unchanged.
- © is the single byte `A9`; the non-breaking space is `A0`. Neither file may contain `EF BF BD`.
- Dialog lines, exactly (hyphen-minus, not en dash):
  `Copyright © Shareaza Development Team, 2002-2017` /
  `Copyright © ivan386, 2013-2019` / `Copyright © Salvatore Ansani, 2022-2024` /
  `Copyright © Claudio Previtali (Prev-I), 2026`.
- One-line form, for `LegalCopyright` and `AppCopyright`: `Copyright © Shareaza Development Team
  2002-2017, ivan386 2013-2019, Salvatore Ansani 2022-2024, Claudio Previtali (Prev-I) 2026`.
- Link text: `https://github.com/Prev-I/Shareaza`.
- No version change: previ.10's version bump is a separate pull request.
- Edit these files with byte-exact tools (Python reading and writing `bytes`). An editor that
  saves as UTF-8 is the defect being fixed.

## Review Focus

1. A line clipped or overlapping in the enlarged dialog at 100% DPI with the banner: every control
   fits 279 DLU and none overlaps the next (checked by coordinates in Task 2; the owner checks
   the real window).
2. Only the expected bytes change: the restore touches exactly the five damaged lines, and the
   rest of `Shareaza.rc` is byte-identical (Task 1, Step 4).
3. Explorer shows `LegalCopyright` from `StringFileInfo\000004b0`. The block and its
   `Translation` stay as they are, so the value is still found (Task 2, by diff).
4. Clicking the link still opens the releases page: `IDC_WEB` keeps its ID and `m_wndWeb` binding
   (Task 2, by diff).
5. The guard fails for real: it rejects a file with `EF BF BD` and a byte undefined in cp1252
   (Task 1, Step 1).

---

### Task 1: Restore the lost bytes and guard them

**Files:**
- Create: `tests/encoding/check-cp1252.py`
- Modify: `shareaza/Shareaza.rc` (lines 3599 and 4241: `EF BF BD` → `A0`; a header comment)
- Modify: `.github/workflows/msbuild.yml` (a step after "Checkout GIT sources")
- Modify: `.gitattributes`

**Interfaces:**
- Produces: `python tests/encoding/check-cp1252.py FILE...`. It exits 0 when every file decodes
  as strict cp1252 and holds no `EF BF BD`. Otherwise it exits 1 and prints `FILE:LINE: reason`
  for each fault. Task 2 runs it on both files.

- [ ] **Step 1: Write the check and prove it rejects bad input.** Run it against scratch files: one
  containing `b'\xef\xbf\xbd'`, one containing `b'\x81'`, one plain ASCII with `b'\xa9'`.
  Expected: exit 1, exit 1, exit 0.
- [ ] **Step 2: Run it on the tree.** `python3 tests/encoding/check-cp1252.py shareaza/Shareaza.rc`
  Expected: exit 1, faults on lines 293, 623, 624, 3599, 4241.
- [ ] **Step 3: Restore the non-breaking spaces** on lines 3599 (`IDS_SEARCH_PANEL_INPUT_5`) and
  4241 (`IDS_MEDIA_TITLE`): each `EF BF BD` becomes `A0`. Add after the first line of the file:
  `// Encoding: Windows-1252, no BOM (#pragma code_page(1252)). Save it in that encoding; an editor
  // that converts it to UTF-8 destroys the non-ASCII characters (CI checks).`
- [ ] **Step 4: Prove the restore is exact.** The restored `IDS_SEARCH_PANEL_INPUT_5` and
  `IDS_MEDIA_TITLE` lines equal the same lines (3576 and 4192) of `git show 55026f568^:shareaza/Shareaza.rc`, byte for byte. `git diff --stat` shows only
  the expected lines changed.
- [ ] **Step 5: Wire the guard.** Add a step named `Check resource and installer encoding` to
  `msbuild.yml`, right after checkout. It runs `python tests/encoding/check-cp1252.py
  shareaza/Shareaza.rc setup/scripts/main.iss`. Append this to `.gitattributes`:
  `shareaza/Shareaza.rc encoding=cp1252` and `setup/scripts/main.iss encoding=cp1252`.
- [ ] **Step 6: Commit** `fix: restore the non-breaking spaces lost when Shareaza.rc was re-saved as
  UTF-8, and check its encoding in CI`. The check still fails on the © lines; Task 2 clears
  them.

### Task 2: The About dialog, version info and installer

**Files:**
- Modify: `shareaza/Shareaza.rc`, the `LegalCopyright` value and the `IDD_ABOUT` block (both two
  lines lower after Task 1's header comment)
- Modify: `shareaza/DlgAbout.cpp:74-88`
- Modify: `setup/scripts/main.iss:167`

**Interfaces:**
- Consumes: `tests/encoding/check-cp1252.py` from Task 1.

- [ ] **Step 1: Rewrite `IDD_ABOUT`** as `DIALOGEX 0, 0, 293, 179` with the same style, caption and
  font, and these controls (x 7, width 279 unless stated):
  - `IDC_TITLE`, y 15, h 10, `SS_CENTERIMAGE` (unchanged)
  - four copyright `LTEXT`s, `IDC_STATIC`, h 10, at y 27, 37, 47, 57, text from Global
    Constraints
  - GPL text, `IDC_STATIC`, y 71, h 28
  - `Logo by Kid at pakkeimak.com`, y 103, h 10
  - MaxMind line, y 116, h 20
  - `IDC_WEB`, `https://github.com/Prev-I/Shareaza`, y 139, h 10
  - `DEFPUSHBUTTON "OK",IDOK,226,156,60,16`

  No control's y + h exceeds the next control's y, and the last ends at 172, inside 179. The GPL and MaxMind
  heights allow for the skin's 11 px font, not the template's 8 pt (final review).
- [ ] **Step 2: Set `LegalCopyright`** to the one-line form, with `A9`. Leave every other
  version-info value as it is.
- [ ] **Step 3: In `CAboutDlg::OnInitDialog`**, delete the `GetFileVersionInfoSize` …
  `pWnd->SetWindowText( (LPCTSTR)strCopyRight );` block. Leave the caption and title lines and
  `return TRUE;`.
- [ ] **Step 4: Set `AppCopyright=`** in `main.iss` to the one-line form, with `A9`.
- [ ] **Step 5: Verify bytes.** `python3 tests/encoding/check-cp1252.py shareaza/Shareaza.rc
  setup/scripts/main.iss` exits 0. `grep -c IDC_COPYRIGHT shareaza/Shareaza.rc` prints 0. The
  diff of `Shareaza.rc` touches only the header comment, `LegalCopyright`, the `IDD_ABOUT` block and the two string
  lines.
- [ ] **Step 6: Commit** `feat: About dialog lists the full history, from the Shareaza Development
  Team to this fork, with the © restored`.
- [ ] **Step 7: Build in CI.** Push the branch, open the pull request into `main` with `--repo
  Prev-I/Shareaza`, and wait for `msbuild.yml`. All four legs must be green, the encoding step
  included. Hand the installer to the owner, who checks Help > About, the exe's
  Properties > Details > Copyright, and the installer's copyright.
