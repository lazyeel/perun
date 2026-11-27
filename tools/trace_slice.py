#!/usr/bin/env python3
"""trace_slice -- backward register-provenance slice over an adi_freeze trace.

Given a trace (trec 152 B + 832 B xstate per record), a record index and a
register, walk backwards to the instruction that produced the current value,
then follow its input registers recursively (BFS). Disassembly is read from
the module ELF at file offset == RVA (true for the r-xp mappings on this rig).

Commands:
  last TRACE MODULE_BASE REC REG          last writer of REG before REC
  slice TRACE MODULE_BASE REC REG [--depth N] [--module-rx START:END]
                                          recursive backward slice (BFS print)
  trace-reg TRACE MODULE_BASE REC REG     print REG value around REC
"""
import argparse
import bisect
import os
import re
import struct
import subprocess
import sys

TREC = 152
XS = 832
REC = TREC + XS
REGNAMES = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
            'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
REGIDX = {n: i for i, n in enumerate(REGNAMES)}

SO = {
    'ca': '/home/admin/rig/WORK/libs/libCoreADI.so',
    'ss': '/home/admin/rig/WORK/libs/libstoreservicescore.so',
    'libc': '/home/admin/rig/WORK/sysroot/lib64/libc.so',
}


def records(path, lo=0, hi=None):
    """yield (index, ip, regs tuple) for records in [lo, hi)"""
    hi = hi if hi is not None else os.path.getsize(path) // REC
    with open(path, 'rb') as f:
        f.seek(lo * REC)
        for i in range(lo, hi):
            b = f.read(TREC)
            if len(b) < TREC:
                return
            ip, = struct.unpack_from('<Q', b, 0)
            regs = struct.unpack_from('<16Q', b, 8)
            yield i, ip, regs


def load_disasm(rva_lo, rva_hi, module):
    """disassemble [rva_lo, rva_hi) of module, return {rva: (text, bytes)}"""
    so = SO[module]
    out = subprocess.run(['objdump', '-d', f'--start-address={rva_lo:#x}',
                          f'--stop-address={rva_hi:#x}', so],
                         capture_output=True, text=True).stdout
    m = {}
    for line in out.splitlines():
        mm = re.match(r'^\s*([0-9a-f]+):\t([0-9a-f ]+)\t(.*)$', line)
        if mm:
            addr = int(mm.group(1), 16)
            m[addr] = (mm.group(3).split('#')[0].strip(), mm.group(2).split())
    return m


class Slicer:
    def __init__(self, trace, base, module='ca'):
        self.trace = trace
        self.base = base
        self.module = module
        self.nrec = os.path.getsize(trace) // REC
        self.dcache = {}

    def rva(self, ip):
        return ip - self.base

    def dis(self, ip):
        rva = self.rva(ip)
        key = rva >> 12
        if key not in self.dcache:
            self.dcache[key] = load_disasm(key << 12, (key << 12) + 0x1000,
                                           self.module)
        return self.dcache[key].get(rva)

    def reg_at(self, rec, ridx):
        with open(self.trace, 'rb') as f:
            f.seek(rec * REC + 8 + 8 * ridx)
            return struct.unpack('<Q', f.read(8))[0]

    def ip_at(self, rec):
        with open(self.trace, 'rb') as f:
            f.seek(rec * REC)
            return struct.unpack('<Q', f.read(8))[0]

    def last_writer(self, rec, ridx):
        """producer record for regs[ridx] at `rec`: single-step stop i logs
        rip = address of the NEXT instruction, so the instruction that changed
        the register between stops i and i+1 sits at record i's ip. Walk back
        to the first record where the value differs (i) and return i (the
        record whose ip IS the producing instruction)."""
        if rec <= 0:
            return None
        val = self.reg_at(rec, ridx)
        i = rec - 1
        with open(self.trace, 'rb') as f:
            f.seek(i * REC + 8 + 8 * ridx)
            while i >= 0:
                v = struct.unpack('<Q', f.read(8))[0]
                if v != val:
                    return i
                if i == 0:
                    break
                i -= 1
                f.seek(i * REC + 8 + 8 * ridx)
        return None

    def regs_at(self, rec):
        with open(self.trace, 'rb') as f:
            f.seek(rec * REC + 8)
            return struct.unpack('<16Q', f.read(128))

    def mem_ea(self, tok, regs, next_ip=None):
        m = re.match(r'^([+-]?0x[0-9a-f]+|\d*)?\((%[a-z0-9]+)?'
                     r'(?:,(%[a-z0-9]+)(?:,(\d+))?)?\)$', tok)
        if not m:
            return None
        disp = int(m.group(1), 0) if m.group(1) else 0
        if m.group(2) == '%rip':
            return (next_ip + disp) & 0xffffffffffffffff if next_ip else None
        addr = disp
        if m.group(2):
            addr += regs[REGIDX[MAP64[m.group(2)[1:]]]]
        if m.group(3):
            sc = int(m.group(4)) if m.group(4) else 1
            addr += regs[REGIDX[MAP64[m.group(3)[1:]]]] * sc
        return addr & 0xffffffffffffffff

    def mem_size(self, mnem):
        sz = {'movzbl': 1, 'movzwl': 2, 'movsbl': 1, 'movswl': 2,
              'movslq': 4}.get(mnem)
        if sz is None:
            sz = {'b': 1, 'w': 2, 'l': 4, 'q': 8}.get(mnem[-1], 4)
        return sz

    def ops_of_text(self, text):
        parts = text.split(None, 1)
        mnem = parts[0]
        rest = parts[1] if len(parts) > 1 else ''
        toks = [o.strip() for o in rest.split(',')]
        fixed = []
        for o in toks:
            if fixed and ('(' in fixed[-1] and ')' not in fixed[-1]):
                fixed[-1] = fixed[-1] + ',' + o
            else:
                fixed.append(o)
        return mnem, fixed

    def build_store_index(self, lo, hi):
        """one pass: dict byte-addr -> sorted [(rec, ea, sz)]"""
        idx = {}
        with open(self.trace, 'rb') as f:
            f.seek(lo * REC)
            for i in range(lo, hi):
                b = f.read(TREC)
                if len(b) < TREC:
                    break
                ip, = struct.unpack_from('<Q', b, 0)
                regs = struct.unpack_from('<16Q', b, 8)
                f.seek(XS, 1)
                d = self.dis(ip)
                if not d:
                    continue
                mnem, ops = self.ops_of_text(d[0])
                stores = []
                next_ip = ip + len(d[1])
                for k, o in enumerate(ops):
                    if '(' not in o:
                        continue
                    ea = self.mem_ea(o, regs, next_ip)
                    if ea is None:
                        continue
                    if mnem == 'lea':
                        continue
                    is_store = (k == len(ops) - 1)
                    if mnem == 'push':
                        is_store = True
                    if mnem == 'pop':
                        is_store = False
                    if is_store:
                        stores.append((ea, self.mem_size(mnem)))
                if mnem == 'push':
                    stores.append((regs[7] - 8, 8))
                for (ea, sz) in stores:
                    for bb in range(ea, ea + sz):
                        idx.setdefault(bb, []).append((i, ea, sz))
        for k in idx:
            idx[k].sort()
        return idx

    def last_store_to(self, rec, ea, sz, idx):
        cands = []
        for bb in range(ea, ea + sz):
            lst = idx.get(bb)
            if not lst:
                continue
            # bisect on rec: entries sorted by rec
            import bisect
            j = bisect.bisect_left(lst, (rec, 0, 0))
            for (r2, ea2, sz2) in reversed(lst[:j]):
                if ea2 < ea + sz and ea < ea2 + sz2:
                    cands.append((r2, ea2, sz2))
                    break
        if not cands:
            return None
        return max(cands, key=lambda c: c[0])

    def inputs_of(self, rec):
        """registers read by the instruction at `rec` (AT&T: src first).
        Returns (set of reg indices, mem operand string or None)."""
        ip = self.ip_at(rec)
        d = self.dis(ip)
        if not d:
            return set(), None
        text = d[0]
        # strip suffixes, find register tokens
        ops = text.split(None, 1)
        operands = ops[1] if len(ops) > 1 else ''
        regs = set()
        mem = None
        for tok in re.findall(r'%[a-z0-9]+|\([^)]*\)', operands):
            if tok.startswith('%'):
                wide = MAP64.get(tok[1:])
                if wide in REGIDX:
                    regs.add(REGIDX[wide])
            else:
                mem = tok
                for r in re.findall(r'%([a-z0-9]+)', tok):
                    wide = MAP64.get(r)
                    if wide in REGIDX:
                        regs.add(REGIDX[wide])
        return regs, mem


MAP64 = {}
for _i in range(8, 16):
    for _sfx in ('', 'd', 'w', 'b'):
        MAP64[f'r{_i}{_sfx}'] = f'r{_i}'
for _n, _w in [('rax', 'rax'), ('rbx', 'rbx'), ('rcx', 'rcx'), ('rdx', 'rdx'),
               ('rsi', 'rsi'), ('rdi', 'rdi'), ('rbp', 'rbp'), ('rsp', 'rsp'),
               ('eax', 'rax'), ('ebx', 'rbx'), ('ecx', 'rcx'), ('edx', 'rdx'),
               ('esi', 'rsi'), ('edi', 'rdi'), ('ebp', 'rbp'), ('esp', 'rsp'),
               ('ax', 'rax'), ('bx', 'rbx'), ('cx', 'rcx'), ('dx', 'rdx'),
               ('si', 'rsi'), ('di', 'rdi'), ('bp', 'rbp'), ('sp', 'rsp'),
               ('al', 'rax'), ('bl', 'rbx'), ('cl', 'rcx'), ('dl', 'rdx'),
               ('ah', 'rax'), ('bh', 'rbx'), ('ch', 'rcx'), ('dh', 'rdx'),
               ('sil', 'rsi'), ('dil', 'rdi'), ('bpl', 'rbp'), ('spl', 'rsp')]:
    MAP64[_n] = _w


def cmd_last(a):
    sl = Slicer(a.trace, a.base, a.module)
    w = sl.last_writer(a.rec, REGIDX[a.reg])
    if w is None:
        print('no writer found (register constant through the whole trace)')
        return
    ip = sl.ip_at(w)
    d = sl.dis(ip)
    print(f'producer of {a.reg} at rec {a.rec}: instruction at rec {w} '
          f'{a.module}:0x{sl.rva(ip):x}  {d[0] if d else "?"}')
    print(f'  produced value {a.reg} = {sl.reg_at(a.rec, REGIDX[a.reg]):#x} '
          f'(was {sl.reg_at(w, REGIDX[a.reg]):#x} at rec {w})')


def cmd_slice(a):
    sl = Slicer(a.trace, a.base, a.module)
    seen = set()
    queue = [(a.rec, REGIDX[a.reg], 0)]
    while queue:
        rec, ridx, depth = queue.pop(0)
        if depth > a.depth:
            continue
        key = (rec, ridx)
        if key in seen:
            continue
        seen.add(key)
        w = sl.last_writer(rec, ridx)
        if w is None:
            continue
        ip = sl.ip_at(w)
        d = sl.dis(ip)
        rva = sl.rva(ip)
        regs, mem = sl.inputs_of(w)
        txt = d[0] if d else '(unknown)'
        print(f'd{depth} rec {w:>7} {a.module}:0x{rva:06x} {txt:<44} '
              f'-> {REGNAMES[ridx]}={sl.reg_at(rec, ridx):#x}'
              + (f'  mem={mem}' if mem else ''))
        for ri in sorted(regs):
            queue.append((w, ri, depth + 1))


def cmd_slice_mem(a):
    """backward slice that follows memory writes (load -> last store)."""
    sl = Slicer(a.trace, a.base, a.module)
    lo, hi = 0, min(sl.nrec, a.rec + 1)
    print(f'building store index over [{lo}..{hi}) ...', file=sys.stderr)
    idx = sl.build_store_index(lo, hi)
    print(f'store index: {len(idx)} bytes covered', file=sys.stderr)
    seen = set()
    budget = [a.budget]
    # node kinds: ('reg', rec, ridx) or ('mem', rec, (ea, sz))
    def push(kind, rec, x, depth):
        if budget[0] <= 0:
            return
        key = (kind, rec, x)
        if key in seen:
            return
        seen.add(key)
        queue.append((kind, rec, x, depth))
    queue = []
    push('reg', a.rec, REGIDX[a.reg], 0)
    while queue and budget[0] > 0:
        kind, rec, x, depth = queue.pop()      # DFS
        budget[0] -= 1
        pad = '  ' * depth
        if kind == 'reg':
            w = sl.last_writer(rec, x)
            if w is None:
                print(f'{pad}rec {rec}: {REGNAMES[x]} constant to trace start')
                continue
            ip = sl.ip_at(w)
            d = sl.dis(ip)
            rva = sl.rva(ip)
            regs, mem = sl.inputs_of(w)
            txt = d[0] if d else '(unknown)'
            print(f'{pad}rec {w:>7} {a.module}:0x{rva:06x} {txt:<38} '
                  f'-> {REGNAMES[x]}={sl.reg_at(rec, x):#x}')
            for ri in sorted(regs):
                push('reg', w, ri, depth + 1)
            if mem:
                regs_at_w = sl.regs_at(w)
                ipw = sl.ip_at(w)
                dw = sl.dis(ipw)
                next_ip = ipw + (len(dw[1]) if dw else 0)
                ea = sl.mem_ea(mem, regs_at_w, next_ip)
                if ea is not None:
                    sz = sl.mem_size(d[0] if d else 'movl')
                    push('mem', w, (ea, sz), depth + 1)
        else:
            ea, sz = x
            st = sl.last_store_to(rec, ea, sz, idx)
            if st is None:
                print(f'{pad}rec {rec:>7} EXTERNAL SEED mem[{ea:#x}..{ea+sz:#x})')
                continue
            w, ea2, sz2 = st
            ip = sl.ip_at(w)
            d = sl.dis(ip)
            txt = d[0] if d else '(unknown)'
            print(f'{pad}rec {w:>7} {a.module}:0x{sl.rva(ip):06x} {txt:<38} '
                  f'-> mem[{ea:#x}] {sz2}B')
            regs, mem = sl.inputs_of(w)
            for ri in sorted(regs):
                push('reg', w, ri, depth + 1)


def cmd_trace_reg(a):
    sl = Slicer(a.trace, a.base, a.module)
    lo = max(0, a.rec - a.window)
    hi = min(sl.nrec, a.rec + a.window)
    for i, ip, regs in records(a.trace, lo, hi):
        r = sl.rva(ip)
        if a.module == 'ca' and not (0 <= r < 0x190000):
            continue
        print(f'{i:>7} {a.module}:0x{r:06x} {REGNAMES[REGIDX[a.reg]]}='
              f'{regs[REGIDX[a.reg]]:#x}')


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--base', required=True, type=lambda x: int(x, 0))
    ap.add_argument('--module', default='ca')
    sub = ap.add_subparsers(dest='cmd', required=True)
    l = sub.add_parser('last')
    l.add_argument('trace')
    l.add_argument('rec', type=int)
    l.add_argument('reg')
    s = sub.add_parser('slice')
    s.add_argument('trace')
    s.add_argument('rec', type=int)
    s.add_argument('reg')
    s.add_argument('--depth', type=int, default=4)
    sm = sub.add_parser('slice-mem')
    sm.add_argument('trace')
    sm.add_argument('rec', type=int)
    sm.add_argument('reg')
    sm.add_argument('--depth', type=int, default=6)
    sm.add_argument('--budget', type=int, default=300)
    t = sub.add_parser('trace-reg')
    t.add_argument('trace')
    t.add_argument('rec', type=int)
    t.add_argument('reg')
    t.add_argument('--window', type=int, default=8)
    args = ap.parse_args(argv)
    if args.cmd == 'last':
        cmd_last(args)
    elif args.cmd == 'slice':
        cmd_slice(args)
    elif args.cmd == 'slice-mem':
        cmd_slice_mem(args)
    else:
        cmd_trace_reg(args)


if __name__ == '__main__':
    main()
