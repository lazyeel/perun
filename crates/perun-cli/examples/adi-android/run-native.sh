#!/usr/bin/env bash
# Build and run the Anisette v3 engine natively on x86_64 Linux.
#
# No Wine, no QEMU, no emulation of any kind: the engine is an x86_64 Android
# (Bionic) binary and the host is x86_64, so the Apple libraries execute
# directly. The only trick is that an Android binary names its loader
# /system/bin/linker64, a path that does not exist on Linux, so PT_INTERP is
# repointed at a Bionic linker64 extracted from an Android system image. The
# kernel then loads that linker as the interpreter -- the normal mechanism
# that starts every Bionic process on a device, used here for the same job.
set -euo pipefail

# Inputs (not vendored): an Apple Music APK carrying the x86_64 libs, and an
# Android x86_64 system image for the Bionic runtime. See README.md.
# Default: pull the x86_64 libraries straight from Apple's Apple Music APK
# (4.9.6) via fetch_libs496.py. Set APK_X86 to a config split .apk instead
# (e.g. the 3.9.0-beta arm64+x86_64 variant) to use that kit.
APK_X86="${APK_X86:-}"
SYS_IMG="${SYS_IMG:?set SYS_IMG to the x86_64 android-21 system.img}"
LIBS="${LIBS:-$PWD/libs}"
SYSROOT="${SYSROOT:-$PWD/sysroot}"
HERE="$(cd "$(dirname "$0")" && pwd)"

say() { printf '== %s\n' "$*"; }

if [ ! -d "$LIBS" ] || [ -z "$(ls -A "$LIBS" 2>/dev/null)" ]; then
  if [ -n "$APK_X86" ]; then
    say "extracting the x86_64 libraries from the APK split"
    mkdir -p "$LIBS"
    python3 - "$APK_X86" "$LIBS" <<'PY'
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
for n in z.namelist():
    if n.startswith("lib/x86_64/"):
        open(f"{sys.argv[2]}/{n.rsplit('/',1)[-1]}", "wb").write(z.read(n))
PY
  else
    say "fetching the x86_64 libraries from Apple (fetch_libs496.py)"
    python3 "$HERE/fetch_libs496.py" "$LIBS"
  fi
fi
# Android's NDK calls the C++ runtime libstdc++.so; Apple ships it as
# libc++_shared.so. The alias is what makes the stack resolve at all.
[ -e "$LIBS/libstdc++.so" ] || ln -sf libc++_shared.so "$LIBS/libstdc++.so"

if [ ! -x "$SYSROOT/bin/linker64" ]; then
  say "pulling the Bionic runtime out of the system image (ext4, no mount)"
  mkdir -p "$SYSROOT/lib64" "$SYSROOT/bin"
  D=/usr/sbin/debugfs
  for f in linker64:/bin libEGL.so:/lib64 libandroid_runtime.so:/lib64; do :; done
  for src in /bin/linker64 /lib64/libc.so /lib64/libdl.so /lib64/liblog.so \
             /lib64/libm.so /lib64/libz.so /lib64/libandroid.so \
             /lib64/libandroid_runtime.so /lib64/libEGL.so; do
    $D -R "dump -p $src $SYSROOT/$src" "$SYS_IMG" >/dev/null 2>&1 || true
  done
  # the rest of the platform, for whatever the Apple stack reaches for
  for n in $($D -R "ls /lib64" "$SYS_IMG" 2>/dev/null | grep -oE '[A-Za-z0-9_.+-]+\.so'); do
    [ -e "$SYSROOT/lib64/$n" ] || $D -R "dump -p /lib64/$n $SYSROOT/lib64/$n" "$SYS_IMG" >/dev/null 2>&1 || true
  done
fi

CC="${CC:-$(ls /opt/data/ndk/*/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android21-clang 2>/dev/null | head -1)}"
[ -n "$CC" ] || { echo "x86_64-linux-android21-clang not found" >&2; exit 1; }

say "building the engine for x86_64"
"$CC" -O2 -Wall -I"$HERE/curl_inc" -I"$HERE/openssl_inc" \
       -o "$PWD/adi_native.raw" "$HERE/adi_test.c" "$LIBS/libcurl.so" -ldl -lc

say "repointing PT_INTERP at the Bionic loader"
python3 - "$PWD/adi_native.raw" "$PWD/adi_native" "$SYSROOT/bin/linker64" <<'PY'
import os, shutil, sys
src, dst, linker = sys.argv[1:4]
d = bytearray(open(src, "rb").read())
# Locate PT_INTERP by its contents rather than by p_filesz: the field is zero
# in the binaries this NDK emits, and the string is the reliable marker.
marker = b"/system/bin/linker64\x00"
i = d.find(marker)
if i < 0:
    sys.exit("no PT_INTERP marker: this binary is not dynamically linked")
# a path that fits the existing slot, so no neighbouring header has to move
link = "/tmp/pa.so"
if os.path.islink(link) or os.path.exists(link):
    os.remove(link)
os.symlink(os.path.abspath(linker), link)
nb = link.encode() + b"\x00"
assert len(nb) <= len(marker), (len(nb), len(marker))
d[i:i + len(marker)] = nb + b"\x00" * (len(marker) - len(nb))
open(dst, "wb").write(d)
os.chmod(dst, 0o755)
print("   PT_INTERP ->", link)
PY

say "running"
# relative would resolve against the caller's cwd, not ours
if [ -z "${CA_BUNDLE:-}" ]; then
  if [ -f "$HERE/apple_chain.pem" ]; then CA_BUNDLE="$HERE/apple_chain.pem"
  else CA_BUNDLE="$PWD/apple_chain.pem"; fi
fi
export CA_BUNDLE LD_LIBRARY_PATH="$LIBS:$SYSROOT/lib64" \
       ANDROID_ROOT=/system ANDROID_DATA=/data \
       ANDROID_RUNTIME_ROOT=/apex/com.android.runtime
export ADI_RESOLVE="${ADI_RESOLVE:-gsa.apple.com:443:17.179.252.2}"
exec "$PWD/adi_native" "$LIBS"
