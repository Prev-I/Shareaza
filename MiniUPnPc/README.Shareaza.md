# MiniUPnPc in Shareaza

`miniupnpc/` is upstream's `miniupnpc/` directory, unmodified. Everything else
in this folder (`MiniUPnPc_143.vcxproj`, `dlldata.c`, `MiniUPnPc.rc`,
`resource.h`, `targetver.h`, `miniupnpcstrings.h`) belongs to Shareaza.

## Vendored release

| | |
|---|---|
| Upstream | https://github.com/miniupnp/miniupnp, directory `miniupnpc/` |
| Release | miniupnpc 2.3.5 (API version 21), released 2026-11-16 |
| Tag | `miniupnpc_2_3_5` = commit `e1db7c47295d38b2b416c892779dae9afa434016` |
| Copied from | the tag's `miniupnpc/` directory |

2.3.4 (2026-11-15) was withdrawn by upstream for a packaging error; 2.3.5 is
the same code. The `LICENSE` file is a symbolic link to `../LICENSE` in the
upstream repository; it is stored here as a regular file with the same content
as the release tarball's `LICENSE`. Git line-ending normalisation
(`* text=auto`) stores `testdesc/new_LiveBox_desc.xml`, which upstream keeps
with CRLF line endings, with LF line endings. Neither file is compiled.

### Release tarball check

`miniupnpc-2.3.5.tar.gz` and `miniupnpc-2.3.5.tar.gz.sig`, downloaded from
https://miniupnp.tuxfamily.org/files/:

- tarball SHA-256 `b9a1e57233216c5f62572de6d628e73e910f50cdb71e9c0eb89b169ce154d256`
- `gpg --verify`: good signature, made 2026-11-16, by RSA key
  `751E 9FF6 944A 3B36 A543  2216 DB51 1043 A31A CAAF` ("miniupnp
  <miniupnp@free.fr>"), the same key that signed 2.3.3. The download page names
  `A31ACAAF` as the release signing key, and the same full fingerprint is
  published as a key of the `miniupnp` GitHub account
  (https://github.com/miniupnp.gpg). The key is not certified by any key in a
  web of trust.
- Contents against the tag: ignoring CVS `$Id$` lines (`diff -r -I '\$Id'`),
  the two trees differ only by files the tarball leaves out (three
  `.gitignore` files, `pymoduletest3.py`, `testreplyparse/invalid.xml` and
  `testreplyparse/invalid.namevalue`) and by one `sed` expression in the
  `Makefile`'s API-version rule. None of these is compiled.

## Upstream fixes since 2.3.3

Shareaza built 2.3.3 with three `src/minixml.c` fixes from upstream's `master`
applied by hand (CVE-2026-110655 in `parseatt`, CVE-2026-110656 and a 1-byte
out-of-bounds read in `parseelt`). 2.3.5 ships all three: its `src/minixml.c`
is byte-identical to the patched copy it replaces, so no local patch remains.

2.3.5 also carries upstream's `connecthostport.c` socket-timeout fix and the
`poll()`/`FD_SET` change. As before, they do not change the Shareaza build:
the timeout code sits inside `#ifdef MINIUPNPC_SET_SOCKET_TIMEOUT`, which
`MiniUPnPc_143.vcxproj` does not define, and the `FD_SET` checks are compiled
out under `_WIN32`. Among the other changes that reach the Windows build: `miniwget.c`
reads the HTTP status code and `Content-Length` with a parser bounded by the
header's end instead of `atoi`, `minissdpc.c` fixes device de-duplication,
and several C23 `const` fixes. The `build_absolute_url` scope fix is in code
compiled only outside Windows.

## Building

`MiniUPnPc_143.vcxproj` builds `MiniUPnPc.dll` from the 14 `src/*.c` files
upstream's `msvc/miniupnpc.vcxproj` compiles, with `MINIUPNP_EXPORTS`.
`miniupnpcstrings.h`, which upstream generates at build time, is the copy in
this folder. The projects and scripts inside `miniupnpc/` are upstream's and
are not used by the Shareaza build.
