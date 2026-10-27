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
`miniupnpc/src/minixml.c` as a separate Shareaza commit:

| Upstream commit | Upstream subject | Advisory |
|---|---|---|
| `3cfb4fb78d5ac04ed0dadc8dd842fc9e448916db` | minixml.c: fix buffer read overflow | CVE-2026-110655 (`parseatt`) |
| `64ef08a12aabab57be0bf7e40f047c8f14dedf9c` | minixml: fix buffer overrun after namespace separator | CVE-2026-110656 (`parseelt`) |

## Building

`MiniUPnPc_143.vcxproj` builds `MiniUPnPc.dll` from the 14 `src/*.c` files
upstream's `msvc/miniupnpc.vcxproj` compiles, with `MINIUPNP_EXPORTS`.
`miniupnpcstrings.h`, which upstream generates at build time, is the copy in
this folder. The projects and scripts inside `miniupnpc/` are upstream's and
are not used by the Shareaza build.
