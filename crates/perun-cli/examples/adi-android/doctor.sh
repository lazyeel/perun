#!/usr/bin/env bash
# Preflight check for the native Anisette v3 lane (run-native.sh).
#
# WHY THIS EXISTS. The lane looks like it is "one command", but it is really a
# chain of seven preconditions, and a failure in any of them presents as the
# same two symptoms: the engine either hangs forever or exits silently with
# code 0 and no output. Both were chased for days as a suspected crypto
# barrier. `doctor.sh` names the broken link instead.
#
# The silent-exit case is the nasty one, because exit code 0 reads as success.
# Every check below therefore prints OK or FAIL and the script exits non-zero
# if anything failed, so it cannot pass by accident.
#
# Usage:
#   ./doctor.sh                 check only
#   ./doctor.sh --run           check, then run the engine
#
# Not committed inputs: NDK, system.img, libs/ and sysroot/ are extracted
# rather than vendored (see README.md). doctor.sh says which ones are missing
# instead of guessing.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FAIL=0
pass() { printf '  \033[32mOK\033[0m   %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAIL=1; }
warn() { printf '  \033[33mWARN\033[0m %s\n' "$*"; }
head_() { printf '\n== %s ==\n' "$*"; }

printf 'Anisette v3 native lane -- preflight\n'

# ── 1. Bionic runtime from an Android system image ──────────────────────────
head_ "Bionic runtime"
if [ -x "$HERE/sysroot/bin/linker64" ]; then
  pass "sysroot/bin/linker64 present"
else
  fail "sysroot/bin/linker64 MISSING -- run run-native.sh once, or extract /bin/linker64 from an x86_64 android-21 system.img"
fi
for lib in libc.so libm.so libz.so libdl.so; do
  [ -e "$HERE/sysroot/lib64/$lib" ] || fail "sysroot/lib64/$lib missing"
done

# ── 2. Apple's libraries from an APK ─────────────────────────────────────────
head_ "Apple libraries (from an APK)"
if [ -d "$HERE/libs" ] && [ -n "$(ls -A "$HERE/libs" 2>/dev/null)" ]; then
  pass "libs/ populated ($(ls -1 "$HERE/libs" | wc -l) files)"
  for so in libcurl.so libstoreservicescore.so libCoreADI.so libc++_shared.so; do
    [ -e "$HERE/libs/$so" ] || fail "libs/$so missing -- fetch the x86_64 APK libs with fetch_libs496.py"
  done
  # NDK names the C++ runtime libstdc++.so; Apple ships libc++_shared.so. The
  # alias is what makes the stack resolve at all.
  [ -e "$HERE/libs/libstdc++.so" ] || warn "libs/libstdc++.so alias absent -- libcurl.so will fail to load"
else
  fail "libs/ empty -- run fetch_libs496.py"
fi

# ── 3. Toolchain ────────────────────────────────────────────────────────────
head_ "Toolchain"
CC="${CC:-$(ls "${ANDROID_NDK:-${ANDROID_NDK_ROOT:-$HOME/ndk}}"/android-ndk-*/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android21-clang 2>/dev/null | head -1)}"
if [ -n "$CC" ] && [ -x "$CC" ]; then
  pass "clang: $CC"
else
  fail "x86_64-linux-android21-clang not found -- set CC, or ANDROID_NDK to the PARENT of android-ndk-* (not the build dir)"
fi
if command -v file >/dev/null 2>&1; then pass "file present"
else warn "file(1) missing -- PT_INTERP checks are degraded"; fi

# ── 4. TLS pin ──────────────────────────────────────────────────────────────
head_ "TLS"
if [ -r "$HERE/apple_chain.pem" ]; then
  if command -v openssl >/dev/null 2>&1; then
    if timeout 15 openssl s_client -connect gsa.apple.com:443 -servername gsa.apple.com \
         -CAfile "$HERE/apple_chain.pem" </dev/null 2>/dev/null | grep -q 'Verify return code: 0'; then
      pass "gsa.apple.com verifies against apple_chain.pem"
    else
      fail "gsa.apple.com does NOT verify against apple_chain.pem -- a MITM proxy in the path, or the pin is stale"
    fi
  else
    warn "openssl missing -- cannot verify the TLS pin"
  fi
else
  fail "apple_chain.pem missing -- provisioning needs the pinned Apple chain"
fi

# ── 5. DNS bypass ───────────────────────────────────────────────────────────
# Bionic's getaddrinfo talks to netd over /dev/socket/dnsproxyd, which does not
# exist off-device. Without ADI_RESOLVE the engine hangs inside a name lookup
# before it ever opens a socket, which reads exactly like a crypto barrier.
head_ "DNS bypass (the hang that is not a hang)"
RESOLVE="${ADI_RESOLVE:-gsa.apple.com:443:17.179.252.2}"
IP="${RESOLVE##*:}"
if [ -n "$IP" ] && [ "$IP" != "$RESOLVE" ]; then
  if timeout 8 bash -c "exec 3<>/dev/tcp/$IP/443" 2>/dev/null; then
    pass "ADI_RESOLVE=$RESOLVE reachable"
  else
    fail "ADI_RESOLVE=$RESOLVE not reachable -- update the pinned IP (Apple rotates these)"
  fi
else
  fail "ADI_RESOLVE malformed -- expected host:port:ip"
fi

# ── 6. Interpreter slot ─────────────────────────────────────────────────────
# The NDK emits PT_INTERP p_filesz == 0, so the string is the only marker, and
# the replacement path must fit the existing 21-byte slot or nothing moves.
head_ "ELF plumbing"
if [ -f "$HERE/adi_native.raw" ]; then
  if grep -qa '/system/bin/linker64' "$HERE/adi_native.raw"; then
    pass "adi_native.raw still has its original PT_INTERP marker"
  else
    warn "adi_native.raw marker not found -- was it already repointed?"
  fi
else
  warn "adi_native.raw absent (fine before the first build)"
fi
# A shell whose name shadows a coreutils binary and does not exec its argv
# will silently swallow output while exiting 0. `env` is the one that bit us.
if command -v env >/dev/null 2>&1; then
  ENV_REAL="$(PATH=/usr/bin:/bin command -v env)"
  if [ "$ENV_REAL" = "$(command -v env)" ]; then
    pass "env resolves to $ENV_REAL"
  else
    fail "env is shadowed by $(command -v env) -- any wrapper that fails to exec \$@ will eat output silently"
  fi
fi

# ── 7. State directory ──────────────────────────────────────────────────────
head_ "Provisioning state"
if [ -f "$HERE/adi-data/adi.pb" ]; then
  pass "adi-data/adi.pb present ($(wc -c <"$HERE/adi-data/adi.pb") bytes)"
else
  warn "adi-data/adi.pb absent -- the next run provisions from scratch (slower, but not fatal)"
fi

# ── verdict ─────────────────────────────────────────────────────────────────
printf '\n'
if [ "$FAIL" = 0 ]; then
  printf '\033[32mAll preconditions met.\033[0m\n'
else
  printf '\033[31mOne or more preconditions failed -- see FAIL above.\033[0m\n'
fi

if [ "${1:-}" = "--run" ] && [ "$FAIL" = 0 ]; then
  printf '\n== engine ==\n'
  exec "$HERE/run-native.sh"
fi
exit "$FAIL"