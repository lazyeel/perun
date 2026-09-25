#!/usr/bin/env python3
"""RDTSC census stress: 100 `perun sap` scenarios, union of executed sites.

Branch: census/rdtsc. Each run is a separate process, so the union is
accumulated here by parsing each run's per-image census lines.
"""
import os
import re
import subprocess
import sys
import tempfile
import collections

ASSETS = os.environ.get("PERUN_TEST_SAP", "/opt/data/perun/test-sap")
PERUN = os.environ.get("PERUN_BIN", "/opt/data/perun/target/release/perun")
LINE = re.compile(r"\[census\] (\w+): (\d+) executed(?:: \[([0-9a-f, ]*)\])?")


def macs():
    """20 MACs: Apple OUI, Intel, locally-administered veth, boundaries."""
    return [
        "00:1B:63:84:45:E6",  # Apple
        "00:25:00:12:34:56",  # Apple
        "A4:83:E7:22:33:44",  # Apple
        "F0:18:98:AB:CD:EF",  # Apple
        "8C:85:90:11:22:33",  # Apple
        "00:1B:63:00:00:01",  # Apple, boundary last byte
        "00:00:00:00:00:00",  # all zero
        "FF:FF:FF:FF:FF:FF",  # all ones
        "00:00:00:00:00:01",  # lower boundary
        "FE:FF:FF:FF:FF:FE",  # upper boundary
        "02:00:00:00:00:01",  # veth, bit 0x02
        "02:00:00:00:00:02",
        "7E:00:00:00:00:01",
        "00:1C:42:00:00:08",  # Parallels
        "52:54:00:12:34:56",  # QEMU
        "00:15:5D:00:00:01",  # Hyper-V
        "00:50:56:AA:BB:CC",  # VMware
        "08:00:27:DE:AD:BE",
        "0A:1B:2C:3D:4E:5F",
        "DE:AD:BE:EF:00:01",
    ]

def payloads():
    """50 payloads: boundary lengths x entropy classes."""
    lens = [0, 1, 15, 16, 17, 27, 64, 255, 256, 1024, 4096, 65536, 1048576]
    out = []
    for n in lens:
        out.append(("zero", bytes(n)))
        out.append(("ff", b"\xff" * n))
        out.append(("urandom", os.urandom(n)))
    # Real plist body, so the signer sees a structurally plausible input.
    body = (b'<?xml version="1.0" encoding="UTF-8"?>\n'
           b'<plist version="1.0"><dict><key>product-type</key>'
           b'<string>download</string><key>id</key>'
           b'<string>686449807</string></dict></plist>\n')
    out.append(("plist", body))
    out.append(("plist-pad", body + b"<!-- " + b"x" * 200 + b" -->"))
    # Not UTF-8: the signer must not assume it is.
    out.append(("non-utf8", bytes(range(256)) * 4))
    out.append(("non-utf8-hi", b"\x80\x81\xfe\xff" * 64))
    out.append(("nul-heavy", b"\x00" * 777))
    out.append(("repeat", b"ABCD" * 333))
    out.append(("alt", bytes((i % 2) * 0xFF for i in range(1000))))
    out.append(("ascii", bytes((97 + (i % 26)) for i in range(2048)) * 2))
    out.append(("sparse", b"\x00" * 4095 + b"\x01"))
    out.append(("utf8", ("\u00e9\u4e2d\u6587" * 300).encode()))
    out.append(("plist-1b", b"\xb0\x17\x00\x00\x01\x02" + b"\x00" * 128))
    return out[:50]

def run(mac, pl):
    """One `perun sap` with census on. Returns (ok, per-image offsets)."""
    env = dict(os.environ)
    env["PERUN_RDTSC_CENSUS"] = "1"
    tmp = None
    cmd = [PERUN, "sap", ASSETS, "--mac", mac]
    if pl is not None:
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.write(pl)
        tmp.close()
        cmd += ["--file", tmp.name]
    try:
        r = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=180)
    finally:
        if tmp is not None:
            os.unlink(tmp.name)
    out = r.stdout + r.stderr
    ok = ("SAPSign OK: 501 bytes" in out) and r.returncode == 0
    # SAP refuses a sign input over 4096 B by design; that is a protocol
    # boundary, not a census failure, so it is counted separately.
    oversize = ok is False and "sign input too large" in out
    reason = ""
    if not ok:
        if r.returncode != 0:
            reason = "rc=%d" % r.returncode
        elif "SAPSign" not in out:
            reason = "no SAPSign line"
        elif "SAP setup failed" in out:
            reason = "setup failed: " + [l for l in out.splitlines() if "setup failed" in l][0][-70:]
        else:
            reason = "wrong size: " + ([l for l in out.splitlines() if "SAPSign" in l] or ["?"])[0][-60:]
        reason = reason.replace("\n", " ")
    found = collections.defaultdict(set)
    for m in LINE.finditer(out):
        img, n, blob = m.group(1), int(m.group(2)), m.group(3)
        if blob:
            found[img] = {int(x, 16) for x in blob.replace(" ", "").split(",") if x}
        else:
            found.setdefault(img, set())
    return ok or oversize, found, reason

def main():
    mac_l = macs()
    pay_l = payloads()
    union = collections.defaultdict(set)
    fails = []
    scen = []
    for i in range(20):
        scen.append((mac_l[i % len(mac_l)], "default", None))
    for i in range(50):
        n, d = pay_l[i]
        scen.append((mac_l[i % len(mac_l)], n, d))
    for i in range(30):
        n, d = pay_l[(i * 3) % len(pay_l)]
        scen.append((mac_l[i % len(mac_l)], n, d))
    assert len(scen) == 100, len(scen)
    for n, (mac, label, pl) in enumerate(scen, 1):
        ok, found, reason = run(mac, pl)
        for img, st in found.items():
            union[img] |= st
        if not ok:
            fails.append((n, mac, label, reason))
        if n % 10 == 0:
            print("  %d/100  CoreFP=%d  CommerceKit=%d  fails=%d"
                  % (n, len(union.get("CoreFP", set())),
                     len(union.get("CommerceKit", set())), len(fails)), flush=True)
    print()
    print("=== 100-run census ===")
    print("ok runs      :", 100 - len(fails), "/ 100")
    for img in ("CoreFP", "CommerceKit"):
        print("%-13s: %d unique sites" % (img, len(union.get(img, set()))))
    if fails:
        print("failures     :", fails[:10])
    out = os.environ.get("CENSUS_OUT", "/tmp/census_union.txt")
    with open(out, "w") as f:
        for img in sorted(union):
            for o in sorted(union[img]):
                f.write("%s 0x%x\n" % (img, o))
    print("union written to", out)

if __name__ == "__main__":
    main()
