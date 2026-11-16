#!/usr/bin/env python3
"""step_trace_defuse -- parse and diff adi_freeze whole-function batch traces.

Trace file layout (sequential, little-endian), produced by tools/adi_freeze.c:

  trec (152 B, struct trec):
    u64 ip;                              # +0
    u64 r[16];                           # +8   rax rbx rcx rdx rsi rdi
                                         #      rbp rsp r8 r9 r10 r11 r12 r13 r14 r15
    u64 orig_rax;                        # +136
    u32 tid;                             # +144
    u8  kind;                            # +148 (1=entry 2=step 3=returned 4=cap-hit)
    u8  pad[3];
  xs_len B: raw NT_X86_XSTATE blob captured right after the step (per record).

XSAVE blob map (AMD EPYC 7402, AVX2, xs_len=832):
    0..31    control: FCW/FSW/FTW/FOP/FIP/FDP/MXCSR/MXCSR_MASK
    32..159  ST0..ST7 / MMX
    160..415 XMM0..XMM15 (16 B each, XMMi at 160+16i)
    416..511 reserved
    512..575 XSAVE header (XSTATE_BV at +512, XCOMP_BV at +520)
    576..831 YMM0..YMM15 upper halves (YMMi upper at 576+16i)

Commands:
  compare A B   align per-tid instruction streams of two traces and report the
                first diverging record (GP regs and XSAVE blob) for each tid.
  dump A [IDX]  print one record (default: entry record) of a trace.
"""

import argparse
import os
import struct
import sys

TREC = 152
OFF_IP = 0
OFF_REGS = 8
OFF_ORIG = 136
OFF_TID = 144
OFF_KIND = 148
REGN = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
        'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
KIND = {1: 'entry', 2: 'step', 3: 'returned', 4: 'cap-hit', 5: 'memwrite'}
XS_CANDIDATES = (0, 256, 288, 320, 512, 576, 832, 1088, 2440, 2560, 2696)


def detect_xs_len(path):
    """Deduce the per-record XSAVE blob size: total size must split into an
    integral number of (144+xs) records whose kinds/ips parse sanely."""
    size = os.path.getsize(path)
    hits = []
    for xs in XS_CANDIDATES:
        rec = TREC + xs
        if rec == 0 or size % rec:
            continue
        n = size // rec
        if n < 3:
            continue
        with open(path, 'rb') as f:
            ok = True
            kinds = []
            for k in range(3):
                b = f.read(rec)
                if len(b) < rec:
                    ok = False
                    break
                (ip,) = struct.unpack_from('<Q', b, OFF_IP)
                kind = b[OFF_KIND]
                if not ip or ip >> 48 or kind not in KIND:
                    ok = False
                    break
                kinds.append(kind)
            if ok and kinds[0] == 1 and kinds[1] == 2:
                hits.append((xs, n))
    if not hits:
        raise SystemExit(f'{path}: no consistent record size found')
    if len(hits) > 1:
        raise SystemExit(f'{path}: ambiguous record size {hits}')
    return hits[0]


def read_headers(path, rec):
    """One pass: per record keep (ip, kind, tid, file offset) and the raw GP
    register block. Returns (meta list, regs bytearray, xs_len)."""
    xs = rec - TREC
    size = os.path.getsize(path)
    n = size // rec
    meta = []
    regs = bytearray(n * (OFF_ORIG - OFF_REGS))
    with open(path, 'rb') as f:
        for i in range(n):
            off = i * rec
            f.seek(off)
            b = f.read(TREC)
            if len(b) < TREC:
                break
            (ip,) = struct.unpack_from('<Q', b, OFF_IP)
            tid, = struct.unpack_from('<I', b, OFF_TID)
            kind = b[OFF_KIND]
            meta.append((ip, kind, tid, off))
            regs[i * (OFF_ORIG - OFF_REGS):(i + 1) * (OFF_ORIG - OFF_REGS)] = \
                b[OFF_REGS:OFF_ORIG]
    return meta, regs, xs


def blob_region(off):
    if off < 32:
        return f'ctrl+{off}'
    if off < 160:
        return f'st{(off - 32) // 16}+{(off - 32) % 16}'
    if off < 416:
        i = (off - 160) // 16
        return f'xmm{i}+{(off - 160) % 16}'
    if off < 512:
        return f'legacy_rsvd+{off - 416}'
    if off < 576:
        return f'xsave_hdr+{off - 512}'
    return f'ymm{(off - 576) // 16}_hi+{(off - 576) % 16}'


def rec_at(f, rec, idx):
    f.seek(idx * rec)
    return f.read(rec)


def dual_scan(pa, pb, rec, n):
    """Lockstep scan of two aligned traces. Returns (first_gp_record,
    first_blob_record). The header compare excludes tid (always differs
    between runs); it covers ip, GP regs, orig_rax, kind."""
    first_gp = first_blob = None
    with open(pa, 'rb') as fa, open(pb, 'rb') as fb:
        for i in range(n):
            ba = fa.read(rec)
            bb = fb.read(rec)
            if len(ba) < rec or len(bb) < rec:
                break
            if first_gp is None:
                da = ba[:OFF_TID] + ba[OFF_TID + 4:TREC]
                db = bb[:OFF_TID] + bb[OFF_TID + 4:TREC]
                if da != db:
                    first_gp = i
            if first_blob is None and ba[TREC:] != bb[TREC:]:
                first_blob = i
            if first_gp is not None and first_blob is not None:
                break
    return first_gp, first_blob


def gp_diffs(ba, bb):
    out = []
    (ipa,) = struct.unpack_from('<Q', ba, OFF_IP)
    (ipb,) = struct.unpack_from('<Q', bb, OFF_IP)
    if ipa != ipb:
        out.append(('ip', ipa, ipb))
    va = struct.unpack_from('<16Q', ba, OFF_REGS)
    vb = struct.unpack_from('<16Q', bb, OFF_REGS)
    out.extend((REGN[i], va[i], vb[i])
               for i in range(15) if va[i] != vb[i])
    (oa,) = struct.unpack_from('<Q', ba, OFF_ORIG)
    (ob,) = struct.unpack_from('<Q', bb, OFF_ORIG)
    if oa != ob:
        out.append(('orig_rax', oa, ob))
    return out


def blob_diffs(bla, blb):
    return [j for j in range(min(len(bla), len(blb))) if bla[j] != blb[j]]


def show_vec_diffs(name, bla, blb, lo, hi, limit=6):
    shown = 0
    for r in range((hi - lo) // 16):
        va = bla[lo + 16 * r:lo + 16 * r + 16]
        vb = blb[lo + 16 * r:lo + 16 * r + 16]
        if va != vb:
            print(f'  {name}{r}: A={va.hex()} B={vb.hex()}')
            shown += 1
            if shown >= limit:
                print(f'  ... more {name} diffs suppressed')
                break


def fmt_regblk(rb, base=0):
    vals = struct.unpack_from('<16Q', rb, base)
    return ' '.join(f'{n}={v:#x}' for n, v in zip(REGN, vals))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)

    c = sub.add_parser('compare', help='diff two traces per tid')
    c.add_argument('trace_a')
    c.add_argument('trace_b')
    c.add_argument('--window', type=int, default=5,
                   help='records around divergence to blob-diff (default 5)')
    c.add_argument('--max-blob-diffs', type=int, default=8)

    d = sub.add_parser('dump', help='print one record')
    d.add_argument('trace')
    d.add_argument('index', nargs='?', type=int, default=0)

    args = ap.parse_args(argv)

    if args.cmd == 'dump':
        xs, n = detect_xs_len(args.trace)
        rec = TREC + xs
        with open(args.trace, 'rb') as f:
            f.seek(args.index * rec)
            b = f.read(rec)
        ip, = struct.unpack_from('<Q', b, OFF_IP)
        tid, = struct.unpack_from('<I', b, OFF_TID)
        kind = b[OFF_KIND]
        orig, = struct.unpack_from('<Q', b, OFF_ORIG)
        print(f'record {args.index} tid={tid} kind={KIND.get(kind, kind)} '
              f'ip={ip:#x} orig_rax={orig:#x}')
        print('regs ' + fmt_regblk(b, OFF_REGS))
        if xs:
            blob = b[TREC:]
            print(f'xstate {xs}B xstate_bv={struct.unpack_from("<Q", blob, 512)[0]:#x}')
            for i in range(16):
                xmm = blob[160 + 16 * i:176 + 16 * i]
                print(f'  xmm{i:<2} {xmm.hex()}')
        return 0

    # compare
    xs_a, n_a = detect_xs_len(args.trace_a)
    xs_b, n_b = detect_xs_len(args.trace_b)
    if xs_a != xs_b:
        raise SystemExit(f'record sizes differ: {xs_a} vs {xs_b}')
    rec = TREC + xs_a
    n = min(n_a, n_b)
    print(f'record size {rec} B (trec {TREC} + xstate {xs_a}), '
          f'{n_a} vs {n_b} records')

    first_gp, first_blob = dual_scan(args.trace_a, args.trace_b, rec, n)
    if first_gp is None and first_blob is None:
        print(f'fully identical across {n} records (tid excluded from the '
              f'header compare)')
        return 0
    print(f'first GP/header divergence: '
          f'{"record " + str(first_gp) if first_gp is not None else "none"}; '
          f'first xstate blob divergence: '
          f'{"record " + str(first_blob) if first_blob is not None else "none"}')

    focus = min(x for x in (first_gp, first_blob) if x is not None)
    anchor, = struct.unpack_from('<Q', rec_at(open(args.trace_a, 'rb'), rec, 0),
                                OFF_IP)
    win = range(max(0, focus - args.window), focus + args.window + 1)
    with open(args.trace_a, 'rb') as fa, open(args.trace_b, 'rb') as fb:
        for k in win:
            if k >= n:
                break
            ba = rec_at(fa, rec, k)
            bb = rec_at(fb, rec, k)
            gp = gp_diffs(ba, bb)
            bd = blob_diffs(ba[TREC:], bb[TREC:])
            if not gp and not bd:
                continue
            ip, = struct.unpack_from('<Q', ba, OFF_IP)
            kind = ba[OFF_KIND]
            print(f'\n-- record {k} (kind={KIND.get(kind, kind)}, '
                  f'ip={ip:#x}, base+{ip - anchor:#x}) --')
            for nm, va, vb in gp:
                print(f'  {nm}: A={va:#x} B={vb:#x}')
            if bd:
                print(f'  blob differs in {len(bd)} byte(s):')
                for j in bd[:args.max_blob_diffs]:
                    print(f'    blob+{j:#x} ({blob_region(j)}): '
                          f'A={ba[TREC:][j]:02x} B={bb[TREC:][j]:02x}')
                show_vec_diffs('XMM', ba[TREC:], bb[TREC:], 160, 416)
                show_vec_diffs('YMM_hi', ba[TREC:], bb[TREC:], 576, 832)
    return 0


if __name__ == '__main__':
    sys.exit(main())
