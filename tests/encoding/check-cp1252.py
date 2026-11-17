#!/usr/bin/env python3
"""Check that files are valid Windows-1252 and hold no UTF-8 replacement character.

Shareaza.rc and the installer script are compiled as code page 1252. When an
editor re-saves one as UTF-8, every non-ASCII character (the copyright sign,
non-breaking spaces) turns into U+FFFD, stored as EF BF BD, which the compiler
then shows as three characters. That happened upstream in 2022 and 2024.

Usage: check-cp1252.py FILE...
Exits 0 when every file is clean, 1 otherwise, printing FILE:LINE: reason.
"""

import sys

REPLACEMENT = b"\xef\xbf\xbd"
BOM = b"\xef\xbb\xbf"


def faults(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        yield f"{path}:0: cannot read: {e.strerror}"
        return
    if data.startswith(BOM):
        yield f"{path}:1: starts with a UTF-8 byte order mark"
    if b"\x00" in data:
        yield f"{path}:1: holds NUL bytes: the file was saved as UTF-16"
    # A Windows-1252 file with a lone A9 or A0 is never valid UTF-8; one that
    # decodes as UTF-8 was converted (A9 became C2 A9, shown as two characters).
    if any(b >= 0x80 for b in data) and REPLACEMENT not in data:
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            pass
        else:
            yield f"{path}:1: is valid UTF-8 with non-ASCII characters: the file was saved as UTF-8"
    for number, line in enumerate(data.split(b"\n"), start=1):
        if REPLACEMENT in line:
            yield f"{path}:{number}: holds U+FFFD (EF BF BD): the file was saved as UTF-8"
        try:
            line.decode("cp1252")
        except UnicodeDecodeError as e:
            yield f"{path}:{number}: byte {line[e.start]:02X} is not defined in Windows-1252"


def main(paths):
    if not paths:
        print(__doc__.strip(), file=sys.stderr)
        return 1
    found = [fault for path in paths for fault in faults(path)]
    for fault in found:
        print(fault)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
