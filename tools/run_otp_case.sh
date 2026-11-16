#!/usr/bin/env bash
# run_otp_case.sh <name> [freeze flags...] -- isolated warm-OTP probe.
#
# Every case runs in its OWN directory with its OWN copy of the reference
# provisioned state (adi-data/) and its OWN ADI_CAPTURE_DIR, so runs cannot
# contaminate each other. Prints: case name, exit code, GetLoginCode verdict,
# and the freezer hit counters. Raw captures stay under /home/admin/rig (0700).
set -u
REF=/home/admin/rig/WORK
CASES=/home/admin/rig/cases
NAME=$1; shift
D=$CASES/$NAME
rm -rf "$D"; mkdir -p "$D/adi-data" "$D/cap"; chmod 700 "$D" "$D/cap"
cp -p "$REF/adi-data/adi.pb" "$D/adi-data/adi.pb"
cp -p "$REF/adi_identifier" "$D/adi_identifier"
STATE_REF=$(sha256sum "$REF/adi-data/adi.pb" | cut -c1-16)
cd "$D"
env ADI_CAPTURE_DIR="$D/cap" \
    CA_BUNDLE=/home/admin/rig/certs/apple_chain.pem \
    LD_LIBRARY_PATH="/home/admin/rig/WORK/libs:/home/admin/rig/WORK/sysroot/lib64" \
    ANDROID_ROOT=/system ANDROID_DATA=/data ANDROID_RUNTIME_ROOT=/apex/com.android.runtime \
    ADI_RESOLVE="gsa.apple.com:443:17.32.194.2,buy.itunes.apple.com:443:17.8.136.39" \
    timeout 60 /home/admin/rig/tools/adi_freeze "$@" -- /home/admin/rig/WORK/adi_native /home/admin/rig/WORK/libs \
    > "$D/console.log" 2> "$D/freeze.log"
rc=$?
code=$(grep -oE 'ADIGetLoginCode=-?[0-9]+ \((not provisioned|provisioned)\)' "$D/console.log" | tail -1)
echo "$NAME rc=$rc state_ref=$STATE_REF state_now=$(sha256sum "$D/adi-data/adi.pb" 2>/dev/null | cut -c1-16) :: $code"
grep -o '"adi_freeze".*' "$D/freeze.log" | tail -1
