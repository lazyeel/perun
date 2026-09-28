#!/usr/bin/env python3
"""Pull the x86_64 native libraries straight from Apple's Apple Music APK.

Source: apps.mzstatic.com/content/android-apple-music-apk/applemusic.apk
(Apple Music 4.9.6, versionCode 1447 -- a universal APK carrying arm64-v8a,
armeabi-v7a, x86 and x86_64). This is the same engine the adi-engine branch
targets, with the classic ADI exports intact:
kq56gsgHG6, Sph98paBcz, nf92ngaK92, aslgmuibau, qi864985u0, rsegvyrt87,
uv5t6nhkui, jk24uiwqrg, p435tmhbla, tn46gtiuhw, fy34trz2st.

The APK is ~142 MB, so we read only the members we need: the zip central
directory via HTTP Range, then each x86_64 member's local header + deflate
stream, again by Range. No full download, no APK unpacking, and nothing
outside lib/x86_64/ is ever fetched.

    fetch_libs496.py <outdir>            # default: ./libs496
"""
import os
import struct
import sys
import urllib.request
import zlib

URL = "https://apps.mzstatic.com/content/android-apple-music-apk/applemusic.apk"
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36"}


def rng(a: int, b: int) -> bytes:
    req = urllib.request.Request(URL, headers={**UA, "Range": f"bytes={a}-{b}"})
    with urllib.request.urlopen(req, timeout=180) as f:
        return f.read()


def total_size() -> int:
    req = urllib.request.Request(URL, headers={**UA, "Range": "bytes=0-0"})
    with urllib.request.urlopen(req, timeout=60) as f:
        return int(f.headers["Content-Range"].split("/")[-1])


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else "libs496"
    os.makedirs(out, exist_ok=True)
    size = total_size()
    print(f"APK {size/1e6:.1f} MB; reading the central directory only", file=sys.stderr)

    tail = rng(size - 80_000, size - 1)
    i = tail.rfind(b"PK\x05\x06")
    if i < 0:
        print("no end-of-central-directory; is this a zip?", file=sys.stderr)
        return 1
    cdoff, = struct.unpack_from("<I", tail, i + 16)
    cdsize, = struct.unpack_from("<I", tail, i + 12)
    cd = rng(cdoff, cdoff + cdsize - 1)

    # index: name -> (compressed size, local header offset)
    members = {}
    p = 0
    while p < len(cd) and cd[p : p + 4] == b"PK\x01\x02":
        nl, el, cl = struct.unpack_from("<HHH", cd, p + 28)
        nm = cd[p + 46 : p + 46 + nl].decode("utf-8", "replace")
        members[nm] = (struct.unpack_from("<I", cd, p + 20)[0], struct.unpack_from("<I", cd, p + 42)[0])
        p += 46 + nl + el + cl

    def pull(nm: str) -> bytes:
        csz, lho = members[nm]
        lh = rng(lho, lho + 30)
        nl_, el_ = struct.unpack_from("<HH", lh, 26)
        data_off = lho + 30 + nl_ + el_
        return zlib.decompress(rng(data_off, data_off + csz), -15)

    got = 0
    for nm in sorted(members):
        if not nm.startswith("lib/x86_64/") or not nm.endswith(".so"):
            continue
        raw = pull(nm)
        base = os.path.basename(nm)
        with open(os.path.join(out, base), "wb") as f:
            f.write(raw)
        got += 1
        print(f"  {len(raw)/1e6:7.2f} MB  {base}", file=sys.stderr)

    # Android's NDK calls the C++ runtime libstdc++.so; Apple ships it as
    # libc++_shared.so. The alias is what makes the stack resolve.
    alias = os.path.join(out, "libstdc++.so")
    if not os.path.exists(alias):
        os.symlink("libc++_shared.so", alias)
    print(f"extracted {got} x86_64 libraries into {out}/", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
