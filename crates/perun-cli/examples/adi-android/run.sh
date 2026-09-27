#!/usr/bin/env bash
# Run ipatool's Anisette engine locally on this x86_64 Linux host.
#
# The engine (adi_test.c, from the adi-engine branch of ipatool) is an aarch64
# Android binary. It is cross-compiled against Bionic and executed under
# qemu-aarch64 against a real Android sysroot, so the ADI libraries see the
# libc they were built for. That matters: libstoreservicescore.so builds its
# provisioning state out of Bionic and hands the flattened dispatcher a pointer
# to it. Under a glibc host the state is the wrong size and the dispatch walks
# off the end of it -- the "-45075" wall.
#
# Usage: adi-android/run.sh [<libs-classic dir>]
#
# Inputs it needs on the host:
#   * aarch64-linux-gnu-gcc / binutils  (debugfs for the image, e2fsprogs)
#   * the NDK (sysroot + clang)        -- see ANDROID_NDK below
#   * libcurl.so + libc++_shared.so extracted from the Apple Music APK
#   * the provisioning curl chain, CA_BUNDLE=apple_chain.pem
#
# One deviation from the stock adi_test.c, and it is load-bearing:
# CURLOPT_RESOLVE, driven by ADI_RESOLVE. Bionic does not read resolv.conf on
# this path -- android_getaddrinfo goes to netd over the dnsproxyd socket, and
# there is no netd under qemu-user. Resolving inside curl leaves the TLS path
# and the Host header untouched.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="${ADI_WORK:-/opt/data/adi-aarch64}"
SYSROOT="${ADI_SYSROOT:-/opt/data/android-sysroot}"
APK="${ADI_APK:-/opt/data/apk/am290.apk}"
LIBS="${1:-$WORK/libs-classic}"
QEMU="${QEMU:-$(command -v qemu-aarch64-static)}"
NPROC="$(nproc)"

log() { printf '[run] %s\n' "$*" >&2; }
die() { printf '[run] FATAL %s\n' "$*" >&2; exit 1; }

# ── the Android sysroot: real linker64 and real Bionic, from a system image ──
# The AOSP source mirrors carry no prebuilt linker; the sys-img repository does.
# The image is a plain ext4, so debugfs extracts it without mounting.
sysroot() {
  [ -x "$SYSROOT/system/bin/linker64" ] && { log "sysroot present"; return; }
  local img="$WORK/sysimg.zip"
  if [ ! -f "$img" ]; then
    log "downloading the android-21 arm64 system image (211 MB)"
    curl -sSL --max-time 900 -o "$img" \
      https://dl.google.com/android/repository/sys-img/android/arm64-v8a-21_r04.zip
  fi
  mkdir -p "$WORK/androidsys"
  [ -f "$WORK/androidsys/system.img" ] || unzip -p "$img" arm64-v8a/system.img > "$WORK/androidsys/system.img"
  mkdir -p "$SYSROOT/system/bin" "$SYSROOT/system/lib64" "$SYSROOT/etc"
  for lib in libc.so libm.so libz.so libdl.so liblog.so libandroid.so libc++.so \
             libandroid_runtime.so libEGL.so; do
    debugfs -R "dump -p /lib64/$lib $SYSROOT/system/lib64/$lib" \
             "$WORK/androidsys/system.img" 2>/dev/null || true
  done
  debugfs -R "dump -p /bin/linker64 $SYSROOT/system/bin/linker64" \
           "$WORK/androidsys/system.img" 2>/dev/null
  # the platform pulls in the rest of /lib64 transitively; take the lot
  mkdir -p "$WORK/run"
  for lib in $(debugfs -R "ls /lib64" "$WORK/androidsys/system.img" 2>/dev/null \
               | grep -oE '[A-Za-z0-9_.+-]+\.so' | sort -u); do
    [ -s "$SYSROOT/system/lib64/$lib" ] || \
      debugfs -R "dump -p /lib64/$lib $SYSROOT/system/lib64/$lib" \
               "$WORK/androidsys/system.img" 2>/dev/null || true
  done
  log "sysroot built"
}

# ── the Apple-side libraries: the APK's own curl and C++ runtime ──
apk_libs() {
  mkdir -p "$WORK/run"
  [ -s "$WORK/run/libcurl.so" ] && return
  log "extracting libcurl.so and libc++_shared.so from the APK"
  unzip -p "$APK" lib/arm64-v8a/libcurl.so       > "$WORK/run/libcurl.so"
  unzip -p "$APK" lib/arm64-v8a/libc++_shared.so > "$WORK/run/libc++_shared.so"
  # libstdc++.so does not exist in the APK: on Android the NDK name is an
  # alias for libc++_shared.so, and a symlink satisfies the link.
  ln -sf libc++_shared.so "$WORK/run/libstdc++.so"
}

build() {
  local clang="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang"
  [ -x "$clang" ] || die "NDK clang not found; set ANDROID_NDK"
  log "cross-compiling adi_test.c for aarch64 Bionic"
  "$clang" -O2 -Wall -I"$HERE/curlinc" -I"$HERE/openssl_inc" \
    -o "$WORK/bt/adi_test_bionic" "$HERE/adi_test.c" \
    -L"$WORK" -l:libcurl_apk.so
}

main() {
  : "${ANDROID_NDK:?set ANDROID_NDK to the NDK root}"
  : "${ADI_RESOLVE:?set ADI_RESOLVE, e.g. gsa.apple.com:443:17.179.252.2}"
  command -v qemu-aarch64-static >/dev/null || die "qemu-aarch64-static not found"
  command -v debugfs        >/dev/null || die "debugfs not found (apt install e2fsprogs)"

  sysroot
  apk_libs
  mkdir -p "$WORK/bt" "$WORK/run"
  cp "$HERE/curlinc" -r "$WORK/" 2>/dev/null || true
  cp "$HERE/openssl_inc" -r "$WORK/" 2>/dev/null || true
  build

  export LD_LIBRARY_PATH="$SYSROOT/system/lib64:$WORK/run:$LIBS"
  export ANDROID_ROOT=/system ANDROID_DATA="$WORK/run" TMPDIR="$WORK/run" \
         ANDROID_ASSETS_ROOT=/system/app EXTERNAL_STORAGE="$WORK/run"
  cd "$WORK/run"
  log "running the engine against $LIBS"
  exec "$QEMU" -L "$SYSROOT" "$WORK/bt/adi_test_bionic" "$LIBS"
}

main "$@"
