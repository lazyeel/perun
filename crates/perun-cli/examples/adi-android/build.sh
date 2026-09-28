#!/usr/bin/env bash
# Build and run the Android CoreADI harness on this x86_64 host.
#
# Why this exists: CoreADI64.dll (Windows) and libCoreADI.so (Android) are the
# same library behind the same obfuscated exports -- vdfut768ig is the gate,
# cvu8io98wun the initialiser. The Windows half runs natively through perun;
# the Android half needs a Bionic-shaped libc, which is what this builds.
#
# Nothing in Apple's library is modified. libCoreADI.so is used as-is; the two
# shims below satisfy the loader, which otherwise refuses the object because it
# requires the Bionic version node LIBC:
#
#     dlopen: .../libc.so.6: version `LIBC' not found
#
# Usage:
#   build.sh                      build the shims and the harness
#   build.sh <spim.bin>           build, then run against a SPIM
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QEMU="${QEMU:-$(command -v qemu-aarch64-static || true)}"
SYSROOT="${SYSROOT:-/usr/aarch64-linux-gnu}"
CC="${CC:-aarch64-linux-gnu-gcc}"
SO="${SO:-$HERE/libCoreADI.so}"

# The Android library. It is NOT vendored: fetch it from a local extraction of
# an official APK, or point SO at a copy you already have.
if [ ! -f "$SO" ]; then
    for cand in "$HERE/libs-classic/libCoreADI.so" \
                "$HERE/lib/x86_64/libCoreADI.so"; do
        if [ -f "$cand" ]; then
            echo "using $cand"
            cp "$cand" "$SO"
            break
        fi
    done
fi
if [ ! -f "$SO" ]; then
    echo "error: libCoreADI.so not found. Extract it from an official APK or set SO=..." >&2
    exit 1
fi

echo "== building shims and harness =="
printf 'LIBC {\n  global: *;\n};\n' > "$HERE/libc.map"
"$CC" -O1 -fPIC -shared -o "$HERE/liblog.so" "$HERE/log_shim.c"
"$CC" -O1 -fPIC -shared -o "$HERE/libc.so"  "$HERE/libc_shim.c" \
       -Wl,--version-script="$HERE/libc.map" -ldl
"$CC" -O0 -o "$HERE/adi_run" "$HERE/adi_run.c" -ldl
# libCoreADI.so asks for "libc.so" and "libdl.so" by their Bionic names, which
# are not how the cross sysroot ships them. libc.so above IS our shim, so only
# libdl.so needs a link. dlsym lives in libc since glibc 2.34, making libdl a
# thin stub there.
ln -sf "$SYSROOT/lib/libdl.so.2" "$HERE/libdl.so"
echo "built."

if [ $# -ge 1 ]; then
    echo "== running against $1 =="
    export LD_LIBRARY_PATH="$HERE:$SYSROOT/lib"
    exec "$QEMU" -L "$SYSROOT" "$HERE/adi_run" "$1"
fi
