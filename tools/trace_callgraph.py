#!/usr/bin/env python3
"""trace_callgraph -- map adi_freeze traced ips to module file offsets.

Load biases are read from the `[maps]` lines a tracer run dumps with
ADI_FREEZE_DEBUG_MAPS=1 (under --no-aslr the biases are stable across runs).
For each module the load bias is `mapping.start - mapping.file_offset`.

Commands:
  hot TRACE [--maps TRACE_LOG] [--top N]   hottest instruction addresses,
                                           grouped by module/RVA
  diverge A B [--maps TRACE_LOG]           first ip-stream divergence with
                                           module/RVA annotation (e.g. two
                                           frozen epochs)
"""

import argparse
import collections
import os
import re
import struct

TREC = 152
XS = 832
REC = TREC + XS
MAP_RE = re.compile(r'^\[maps\] ([0-9a-f]+)-([0-9a-f]+) \S+ ([0-9a-f]+) \S+ \S+\s+(.*)$')


def load_biases(log_path):
    biases = {}
    with open(log_path) as f:
        for line in f:
            m = MAP_RE.match(line.rstrip('\n'))
            if not m:
                continue
            start, _end, off, path = int(m.group(1), 16), int(m.group(2), 16), \
                                     int(m.group(3), 16), m.group(4)
            b = start - off
            if path not in biases:
                biases[path] = b
            else:
                biases[path] = min(biases[path], b)
    if not biases:
        raise SystemExit(f'no [maps] lines in {log_path} (run with ADI_FREEZE_DEBUG_MAPS=1)')
    return sorted(biases.items(), key=lambda kv: -kv[1])


def mapper(biases):
    def f(ip):
        for path, bias in biases:
            if bias <= ip < bias + (1 << 26):   # 64 MiB window per module
                return os.path.basename(path), ip - bias
        return '?', ip
    return f


def ips(path, want=None):
    with open(path, 'rb') as f:
        i = 0
        while True:
            b = f.read(TREC)
            if len(b) < TREC:
                break
            if want is None or i in want:
                yield i, struct.unpack_from('<Q', b, 0)[0]
            f.seek(XS, os.SEEK_CUR)
            i += 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    h = sub.add_parser('hot')
    h.add_argument('trace')
    h.add_argument('--maps', required=True)
    h.add_argument('--top', type=int, default=30)
    d = sub.add_parser('diverge')
    d.add_argument('trace_a')
    d.add_argument('trace_b')
    d.add_argument('--maps', required=True)
    d.add_argument('--window', type=int, default=6)
    args = ap.parse_args(argv)

    mapfn = mapper(load_biases(args.maps))
    if args.cmd == 'hot':
        counts = collections.Counter()
        for _i, ip in ips(args.trace):
            mod, rva = mapfn(ip)
            counts[(mod, rva)] += 1
        print(f'{sum(counts.values())} instructions, {len(counts)} distinct ips')
        for (mod, rva), n in counts.most_common(args.top):
            print(f'{n:8d}  {mod}:0x{rva:x}')
        return 0

    # diverge
    ia = [(i, ip) for i, ip in ips(args.trace_a)]
    ib = [(i, ip) for i, ip in ips(args.trace_b)]
    print(f'lengths {len(ia)} vs {len(ib)}')
    n = min(len(ia), len(ib))
    first = None
    for k in range(n):
        if ia[k][1] != ib[k][1]:
            first = k
            break
    if first is None:
        print('ip streams identical up to', n)
        return 0
    print(f'first ip divergence at record {first}:')
    for k in range(max(0, first - args.window), min(n, first + args.window)):
        ma, ra = mapfn(ia[k][1])
        mb, rb = mapfn(ib[k][1])
        print(f'  [{k}] A {ma}:0x{ra:x} | B {mb}:0x{rb:x}')
    return 0


if __name__ == '__main__':
    main()
