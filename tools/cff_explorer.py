#!/usr/bin/env python3
"""CFF cartographer for CoreADI64.dll's flattened dispatcher.

This image defeats a linear sweep: blocks are entered by computed jumps, so a
sweep desynchronises and decodes the middle of an instruction as plausible
nonsense. Everything here therefore works from *recorded execution*, not from
guessing an entry point -- perun's step ring is ground truth about where the
processor actually was, and `PERUN_STEP_UNTIL` stops it cleanly at a chosen
address.

What it produces:

* ``blocks`` -- every distinct RIP the run visited, with the register file at it
* ``publishers`` -- blocks that load an ADI status constant, cross-referenced
  against the AdiErrorCode table so each one is named
* ``edges`` -- the transition relation, and its strongly connected components
* ``hot`` -- the addresses that repeat, which is where a spun loop would show

Usage:

    python3 cff_explorer.py run --steps 2000000 [--stop 0x8f59a]
    python3 cff_explorer.py report [--graph cff_graph.json]

The `run` phase shells out to perun, because the ring is the only reliable
source of instruction boundaries in this image.
"""

import argparse
import json
import os
import re
import struct
import subprocess
import sys
from collections import Counter, defaultdict

import capstone
import networkx as nx
from capstone import x86

IMAGE = "/opt/data/adi-pe/extracted/itunes_extracted/iTunes/CoreADI64.dll"
PERUN = "/opt/data/perun/target/release/perun"
RING = "/opt/data/il/cff_ring.txt"
GRAPH = "/opt/data/il/cff_graph.json"

IMAGE_BASE = 0x7C800000
TEXT_RVA, TEXT_OFF, TEXT_SIZE = 0x1000, 0x400, 0x140B70
EXPORT_RVA = 0x5AFC0                      # vdfut768ig
BODY_END_RVA = TEXT_RVA + TEXT_SIZE

# The dispatcher table the flattened blocks index into. Two different bases are
# in use in this image (0x7c95fc90 and 0x8f6f0 region); both are collected.
TABLE_HINTS = [0xCF6DC, 0xD01C3, 0xD0183]

# AdiErrorCode, from apple_developer_kit's port of the ADIError enum.
ERRORS = {
    -45001: "invalidParams",
    -45002: "invalidParams2",
    -45003: "invalidTrustKey",
    -45006: "ptmTkNotMatchingState",
    -45018: "invalidInputDataParamHeader",
    -45019: "unknownAdiFunction",
    -45020: "invalidInputDataParamBody",
    -45025: "unknownSession",
    -45026: "emptySession",
    -45031: "invalidDataHeader",
    -45032: "dataTooShort",
    -45033: "invalidDataBody",
    -45034: "unknownAdiCallFlags",
    -45036: "timeError",
    -45046: "emptyHardwareIds",
    -45054: "filesystemError",
    -45061: "notProvisioned",
    -45062: "noProvisioningToErase",
    -45063: "pendingSession",
    -45066: "sessionAlreadyDone",
    -45075: "libraryLoadingFailed",
}

data = open(IMAGE, "rb").read()
cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
cs.detail = True


def rva2off(rva):
    return TEXT_OFF + (rva - TEXT_RVA)


def decode_at(rip, count=1):
    """Decode exactly one instruction at a recorded RIP.

    A recorded RIP is a real instruction boundary by construction, so this cannot
    desynchronise the way a sweep does.
    """
    rva = rip - IMAGE_BASE
    if not (TEXT_RVA <= rva < TEXT_RVA + TEXT_SIZE):
        return None
    off = rva2off(rva)
    if off < 0 or off + 16 > len(data):
        return None
    return next(cs.disasm(data[off:off + 16], rip, count=count), None)


EPILOGUE_RVAS = []


def scan_epilogue():
    """The single exit of vdfut768ig: `add rsp,0x16a8` then the pops.

    The frame is 0x16a8 for the whole call, which is what makes `[rsp+off]`
    resolvable from the run's own stop address. Only one such sequence exists in
    `.text`, so it is the reliable epilogue marker even though the image holds
    584 `ret` overall.
    """
    code = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    pat = bytes.fromhex("4881c4a8160000")   # add $0x16a8,%rsp
    out = []
    i = 0
    while True:
        i = code.find(pat, i)
        if i < 0:
            break
        out.append(TEXT_RVA + i)
        i += 1
    return out


def scan_publishers():
    """Every `mov reg, imm` whose immediate is an ADI status.

    This is the exhaustive half of the answer and it does not need execution:
    the publishers are literal loads, so a byte scan finds all of them, while the
    ring only finds the ones this particular run reached. It is also how the
    RVA-0x66c2d `-45034` site was found, and why the opcode constants are
    absent -- a flattened dispatcher never compares them literally.
    """
    code = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    out = defaultdict(list)
    for i in range(len(code) - 5):
        if 0xB8 <= code[i] <= 0xBF:            # mov r32, imm32
            v = struct.unpack_from("<i", code, i + 1)[0]
            if v in ERRORS:
                out[v].append(TEXT_RVA + i)
    return out


def collect_ring(steps, stop_rva, packet):
    """Drive perun and capture its step ring."""
    env = dict(os.environ)
    env["PERUN_TRACE"] = "1"
    env["PERUN_TRACE_FILE"] = RING
    env["PERUN_TRACE_TAIL"] = str(steps)
    env["PERUN_ADI_DIR"] = "/opt/data/il/adi3"
    cmd = [PERUN, "call", IMAGE, "vdfut768ig", packet["opcode"], "ctx", "0", "0",
           "--load=SP=" + packet["file"],
           "--poke=ctx+0x0=SP", "--poke=ctx+0x8=0x30",
           "--poke=ctx+0xc=0x4", "--poke=ctx+0x18=0x00226564",
           "--poke=ctx+0x20=0x1", "--poke=ctx+0x48=0x2"]
    if stop_rva:
        env["PERUN_STEPS"] = "4000000"
        env["PERUN_STEP_UNTIL"] = stop_rva
    out = subprocess.run(cmd, env=env, capture_output=True, timeout=900)
    if not os.path.exists(RING):
        sys.stderr.write(out.stderr.decode("utf-8", "replace")[-2000:])
        raise SystemExit("perun produced no ring")
    return out.returncode


def read_ring(path):
    cols = ("k rip rsp edi rax rdx rcx r10 r9 r11 r14 r8 rsi rdi r12 "
            "al bl cl dl r13 r15 rbp").split()
    rows = []
    with open(path) as fh:
        for line in fh:
            p = line.split()
            if len(p) != len(cols):
                continue
            try:
                rows.append({c: int(v, 16) for c, v in zip(cols, p)})
            except ValueError:
                continue
    return rows


def build(rows):
    g = nx.DiGraph()
    blocks = {}
    hot = Counter()
    for i, r in enumerate(rows):
        rip = r["rip"]
        hot[rip] += 1
        ins = decode_at(rip)
        if ins is None:
            continue
        blocks[rip] = {
            "rip": rip,
            "rva": rip - IMAGE_BASE,
            "mnemonic": ins.mnemonic,
            "op_str": ins.op_str,
            "size": ins.size,
            "regs": {k: r[k] for k in
                     ("edi", "rax", "rdx", "rcx", "r9", "r12", "r15", "rbp")},
            "step": i,
        }
        # Edges: the next executed RIP, when it is a branch target rather than a
        # fallthrough, is where control actually went.
        if i + 1 < len(rows):
            nxt = rows[i + 1]["rip"]
            if nxt != rip + ins.size:
                g.add_edge(rip, nxt)
    # Publishers: any block whose immediate looks like an ADI status.
    publishers = []
    for rip, b in blocks.items():
        for op in b["regs"].values():
            if op in ERRORS:
                publishers.append({**b, "code": op, "name": ERRORS[op]})
                break
    return g, blocks, hot, publishers


def dump(g, blocks, hot, publishers, rows):
    total = len(rows)
    uniq = len(hot)
    print("== recorded execution ==")
    print("  steps recorded      : %d" % total)
    print("  distinct RIPs       : %d" % uniq)
    print("  branch edges        : %d" % g.number_of_edges())
    if total:
        print("  worst repetition    : %d (rva 0x%x)" %
              (hot.most_common(1)[0][1], hot.most_common(1)[0][0] - IMAGE_BASE))
    sccs = [c for c in nx.strongly_connected_components(g) if len(c) > 1]
    print("  cycles (SCC > 1)    : %d" % len(sccs))
    for c in sorted(sccs, key=len, reverse=True)[:5]:
        print("      loop of %d blocks, e.g. rva 0x%x" %
              (len(c), sorted(x - IMAGE_BASE for x in c)[0]))

    print()
    print("== status publishers ==")
    print("  blocks publishing an ADI code: %d" % len(publishers))
    for p in sorted(publishers, key=lambda x: x["rva"]):
        print("    rva 0x%-7x %6d  %d %s" %
              (p["rva"], hot.get(p["rip"], 1), p["code"], p["name"]))

    print()
    print("== hottest addresses (a spun loop shows here) ==")
    for rip, n in hot.most_common(12):
        b = blocks.get(rip)
        txt = ("%s %s" % (b["mnemonic"], b["op_str"])) if b else "(outside .text)"
        print("    rva 0x%-7x x%-6d %s" % (rip - IMAGE_BASE, n, txt[:70]))

    # Literals that look like status codes, gathered from the decoded bodies.
    lits = Counter()
    for b in blocks.values():
        for m in re.finditer(r"0x([0-9a-f]{4,8})", b["op_str"]):
            v = int(m.group(1), 16)
            sv = v - (1 << 32) if v > 0xFFFF0000 else v
            if sv in ERRORS:
                lits[sv] += 1
    print()
    print("== ADI literals present in decoded blocks ==")
    for v, n in lits.most_common():
        print("    %d %-28s x%d" % (v, ERRORS[v], n))

    # Which of the exhaustive publishers did this run actually reach? The
    # difference is the useful part: a publisher that is never hit on a given
    # packet tells you the packet never reached that check.
    reached = {b["rva"] for b in blocks.values()}
    pubs_all_r = scan_publishers()
    hit, missed = [], []
    for v, rs in pubs_all_r.items():
        (hit if any(r in reached for r in rs) else missed).append(v)
    print()
    print("== publisher reachability on this packet ==")
    print("  reached   : %s" % ", ".join("%d %s" % (v, ERRORS[v]) for v in sorted(hit)))
    print("  not reached: %s" % ", ".join("%d %s" % (v, ERRORS[v]) for v in sorted(missed)))

    eps = scan_epilogue()
    print()
    print("== epilogue ==")
    print("  add rsp,0x16a8 sites: %d -> %s"
          % (len(eps), ", ".join("0x%x" % e for e in eps)))

    pubs_all = scan_publishers()
    print()
    print("== exhaustive status-publisher scan (all `mov reg, imm`) ==")
    for v in sorted(pubs_all):
        rs = pubs_all[v]
        print("    %6d %-28s x%-4d %s" %
              (v, ERRORS[v], len(rs), ", ".join("0x%x" % r for r in rs[:6])))

    payload = {
        "image": IMAGE,
        "publishers_all": [
            {"code": v, "name": ERRORS[v], "rvas": rs}
            for v, rs in sorted(pubs_all.items())
        ],
        "image_base": IMAGE_BASE,
        "export_rva": EXPORT_RVA,
        "steps_recorded": total,
        "distinct_rips": uniq,
        "blocks": [
            {**b, "rip": "0x%x" % b["rip"],
             "regs": {k: "0x%x" % v for k, v in b["regs"].items()}}
            for b in blocks.values()
        ],
        "edges": [["0x%x" % a, "0x%x" % b] for a, b in g.edges()],
        "cycles": [[ "0x%x" % x for x in c] for c in
                   nx.strongly_connected_components(g) if len(c) > 1],
        "publishers": [
            {"rva": p["rva"], "code": p["code"], "name": p["name"],
             "mnemonic": p["mnemonic"], "op_str": p["op_str"],
             "visits": hot.get(p["rip"], 1)}
            for p in sorted(publishers, key=lambda x: x["rva"])
        ],
        "hot": [{"rip": "0x%x" % r, "rva": r - IMAGE_BASE, "count": n}
                for r, n in hot.most_common(200)],
    }
    with open(GRAPH, "w") as fh:
        json.dump(payload, fh, indent=1)
    print()
    print("wrote %s (%d bytes)" % (GRAPH, os.path.getsize(GRAPH)))


DEFAULT_PACKET = {
    "opcode": "0xcfe0b46a",
    "file": "/opt/data/il/variants/win_ctx.bin",
}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="drive perun and capture the ring")
    r.add_argument("--steps", type=int, default=200000)
    r.add_argument("--stop", default=None,
                   help="RVA to stop at, e.g. 0x8f59a (hex, no 0x)")
    r.add_argument("--opcode", default=DEFAULT_PACKET["opcode"])
    r.add_argument("--packet", default=DEFAULT_PACKET["file"])

    sub.add_parser("report", help="decode a captured ring")

    a = ap.parse_args()
    if a.cmd == "run":
        packet = {"opcode": a.opcode, "file": a.packet}
        stop = a.stop
        if stop and stop.startswith("0x"):
            stop = stop[2:]
        rc = collect_ring(a.steps, stop, packet)
        rows = read_ring(RING)
        if not rows:
            raise SystemExit("ring is empty (perun rc=%d)" % rc)
        g, blocks, hot, pubs = build(rows)
        dump(g, blocks, hot, pubs, rows)
    else:
        rows = read_ring(RING)
        if not rows:
            raise SystemExit("no ring at %s" % RING)
        g, blocks, hot, pubs = build(rows)
        dump(g, blocks, hot, pubs, rows)


if __name__ == "__main__":
    main()
