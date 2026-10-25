#!/bin/bash
# usage: cmpextra.sh <vendored dir>  ; compares each file against same-basename files in upstream trees (CRLF-insensitive, whitespace-insensitive)
V=$1
cd /tmp/shareaza-audit/provenance
for f in "${@:2}"; do
  p=$V/$f; b=$(basename "$f"); found=0
  for u in 1.2.12b 1.2.11 1.2.8 1.2.5 1.2.3; do
    for c in $(find x/zlib-$u -name "$b" -type f 2>/dev/null); do
      if diff -q -w --strip-trailing-cr "$c" "$p" >/dev/null; then echo "IDENTICAL(ws-insens) $f == ${c#x/}"; found=1; elif [ $found = 0 ]; then n=$(diff -w --strip-trailing-cr "$c" "$p" | grep -c '^[<>]'); echo "  diff-lines=$n $f vs ${c#x/}"; fi
    done
  done
  [ $found = 0 ] && echo "  >>> NO identical upstream match: $f"
done
