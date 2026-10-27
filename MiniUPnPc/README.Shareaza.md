# MiniUPnPc in Shareaza

`miniupnpc/` is upstream's `miniupnpc/` directory, unmodified except for the
fixes listed under *Applied upstream fixes*. Everything else in this folder
(`MiniUPnPc_143.vcxproj`, `dlldata.c`, `MiniUPnPc.rc`, `resource.h`,
`targetver.h`, `miniupnpcstrings.h`) belongs to Shareaza.

## Vendored release

| | |
|---|---|
| Upstream | https://github.com/miniupnp/miniupnp, directory `miniupnpc/` |
| Release | miniupnpc 2.3.3 (API version 21), released 2025-05-27 |
| Tag | `miniupnpc_2_3_3` = commit `bf4215a7574f88aa55859db9db00e3ae58cf42d6` |
| Copied from | the tag's `miniupnpc/` directory |

The `LICENSE` file is a symbolic link to `../LICENSE` in the upstream
repository; it is stored here as a regular file with the same content as the
release tarball's `LICENSE`. Git line-ending normalisation (`* text=auto`)
stores `testdesc/new_LiveBox_desc.xml`, which upstream keeps with CRLF line
endings, with LF line endings. Neither file is compiled.

### Release tarball check

`miniupnpc-2.3.3.tar.gz` and `miniupnpc-2.3.3.tar.gz.sig`, downloaded from
https://miniupnp.tuxfamily.org/files/ (http://miniupnp.free.fr/files/ serves
the same bytes):

- tarball SHA-256 `d52a0afa614ad6c088cc9ddff1ae7d29c8c595ac5fdd321170a05f41e634bd1a`
- `gpg --verify`: good signature, made 2025-05-27, by RSA key
  `751E 9FF6 944A 3B36 A543  2216 DB51 1043 A31A CAAF` ("miniupnp
  <miniupnp@free.fr>"). The download page names `A31ACAAF` as the release
  signing key, and the same full fingerprint is published as a key of the
  `miniupnp` GitHub account (https://github.com/miniupnp.gpg). The key is not
  certified by any key in a web of trust.
- Contents against the tag: every file the tarball holds is byte-identical to
  the tag's, except for the CVS `$Id$` line that 31 files carry (the tarball is
  cut from upstream's CVS). Ignoring `$Id$` lines (`diff -r -I '\$Id'`), the two
  trees differ only by files the tarball leaves out: three `.gitignore` files
  and `pymoduletest3.py`. `src/minixml.c` is identical in both.

## Applied upstream fixes

Fixes from upstream's `master` branch, newer than 2.3.3, each applied to
`miniupnpc/src/minixml.c` as a separate Shareaza commit. With all three,
`src/minixml.c` is identical to upstream `master` at
`05bb29e78d882990efe13e8a5663b69313dc97fd` (2026-10-20).

| Upstream commit | Upstream subject | Advisory |
|---|---|---|
| `3cfb4fb78d5ac04ed0dadc8dd842fc9e448916db` | minixml.c: fix buffer read overflow | CVE-2026-110655 (`parseatt`) |
| `64ef08a12aabab57be0bf7e40f047c8f14dedf9c` | minixml: fix buffer overrun after namespace separator | CVE-2026-110656 (`parseelt`) |
| `42965d7e763b4f894986dd8feb19db7920ea0766` | minixml.c: fix 1-byte out-of-bounds read | none known (`parseelt`) |

## Upstream fixes not applied

Two later `connecthostport.c` changes on upstream `master` do not change the
Shareaza build, so they are left out:

- `f1fc7490a6f9d0b3ea5667b7db15385fd3253b60` "Fix Windows socket timeout
  handling in connecthostport.c" (and its follow-ups `13953fb`, `9de3fdf`,
  `9211ef8`, `bc36b22`): the code it fixes sits inside
  `#ifdef MINIUPNPC_SET_SOCKET_TIMEOUT`, which only upstream's Unix `Makefile`
  defines. Neither upstream's MSVC project nor `MiniUPnPc_143.vcxproj` defines
  it, so the Windows build never compiles that code.
- `c157807a13d3ea10ac2ccc1d29df0f4c6a4272db` "miniupnpc: Use poll() where
  possible + Fix FD_SET crash bug": the crash needs a POSIX descriptor at or
  above `FD_SETSIZE`. The new checks are compiled out under `_WIN32`, where
  `fd_set` is a counted array of sockets rather than a bitmap, and `poll()` is
  used on POSIX systems only.

## Building

`MiniUPnPc_143.vcxproj` builds `MiniUPnPc.dll` from the 14 `src/*.c` files
upstream's `msvc/miniupnpc.vcxproj` compiles, with `MINIUPNP_EXPORTS`.
`miniupnpcstrings.h`, which upstream generates at build time, is the copy in
this folder. The projects and scripts inside `miniupnpc/` are upstream's and
are not used by the Shareaza build.
