#!/usr/bin/env python3
"""Check shareaza/ShippedRules.h against the rules Shareaza used to ship.

Decodes Data/DefaultSecurity.dat as of commit ec36d58490f81c1448020e74327e02f39c9f7c97 (the 2011 file,
whose 60 GUIDs are the ones every install received), checks that the
client's kGuids table holds exactly those GUIDs, and checks that the
current Data/DefaultSecurity.dat is an empty rule set.

Run from the repository root with full history: python3 -I <this file>
"""

import re
import struct
import subprocess
import sys
import uuid

OLD_COMMIT = "ec36d58490f81c1448020e74327e02f39c9f7c97"
DAT_PATH = "Data/DefaultSecurity.dat"
HEADER_PATH = "shareaza/ShippedRules.h"
EXPECTED_RULES = 60
EMPTY_FILE = bytes([0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0])


class Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def take(self, n):
        if self.pos + n > len(self.data):
            raise ValueError("truncated archive at offset %d" % self.pos)
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return struct.unpack("<H", self.take(2))[0]

    def u32(self):
        return struct.unpack("<I", self.take(4))[0]

    def count(self):
        # MFC CArchive::ReadCount: WORD, or 0xFFFF then DWORD
        n = self.u16()
        if n == 0xFFFF:
            n = self.u32()
        return n

    def cstring(self):
        # MFC CString serialization: optional 0xFF 0xFFFE Unicode marker,
        # then the length as BYTE, or 0xFF + WORD, or 0xFF 0xFFFF + DWORD.
        unicode = False
        n = self.u8()
        if n == 0xFF:
            n = self.u16()
            if n == 0xFFFE:
                unicode = True
                n = self.u8()
                if n == 0xFF:
                    n = self.u16()
        if n == 0xFFFF:
            n = self.u32()
        if unicode:
            return self.take(2 * n).decode("utf-16-le")
        return self.take(n).decode("latin-1")


def decode_guids(data):
    r = Reader(data)
    version = r.u32()
    r.u32()  # deny policy
    if version != 5:
        raise ValueError("expected format version 5, got %d" % version)
    guids = []
    for _ in range(r.count()):
        r.u32()  # type
        r.u8()   # action
        r.cstring()  # comment
        raw = r.take(16)
        r.u32()  # expire
        r.u32()  # ever
        r.take(4)  # IP
        r.take(4)  # mask
        guids.append("{%s}" % str(uuid.UUID(bytes_le=raw)).upper())
    if r.pos != len(data):
        raise ValueError("%d trailing bytes" % (len(data) - r.pos))
    return guids


def main():
    failures = []

    old = subprocess.run(["git", "show", "%s:%s" % (OLD_COMMIT, DAT_PATH)],
                         check=True, stdout=subprocess.PIPE).stdout
    shipped = decode_guids(old)
    if len(shipped) != EXPECTED_RULES:
        failures.append("old file has %d rules, expected %d" % (len(shipped), EXPECTED_RULES))
    if len(set(shipped)) != len(shipped):
        failures.append("old file has duplicate GUIDs")

    try:
        with open(HEADER_PATH, encoding="ascii") as f:
            header = f.read()
    except FileNotFoundError:
        header = ""
        failures.append("%s is missing" % HEADER_PATH)
    table = re.findall(r'"(\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\})"', header)
    if header and len(table) != EXPECTED_RULES:
        failures.append("%s lists %d GUIDs, expected %d" % (HEADER_PATH, len(table), EXPECTED_RULES))
    if header and len(set(table)) != len(table):
        failures.append("%s has duplicate GUIDs" % HEADER_PATH)
    if header and set(table) != set(shipped):
        failures.append("%s differs from the old file: missing %s, extra %s"
                        % (HEADER_PATH, sorted(set(shipped) - set(table)),
                           sorted(set(table) - set(shipped))))

    with open(DAT_PATH, "rb") as f:
        current = f.read()
    if current != EMPTY_FILE:
        failures.append("%s is not the empty rule set (%d bytes)" % (DAT_PATH, len(current)))

    for failure in failures:
        print("FAIL: " + failure)
    if failures:
        return 1
    print("OK: %d shipped GUIDs match %s; %s is empty" % (len(shipped), HEADER_PATH, DAT_PATH))
    return 0


if __name__ == "__main__":
    sys.exit(main())
