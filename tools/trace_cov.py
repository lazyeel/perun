#!/usr/bin/env python3
"""trace_cov -- decode executed ips from an adi_freeze trace and classify
memory traffic to find what must be dumped/pre-seeded for a Rust VM lift.

Outputs:
  - mnemonic histogram of the executed subset
  - distinct executed ips per module
  - load-EA coverage: which read addresses are never covered by an in-trace
    store ("external reads" -> must come from dumped memory or static data)
"""
import argparse
import collections
import os
import re
import struct
import subprocess

TREC = 152
XS = 832
REC = TREC + XS

MODULES = {
    'ss': ('/home/admin/rig/WORK/libs/libstoreservicescore.so',
           0x7ffff742c000, 0x239000),
    'ca': ('/home/admin/rig/WORK/libs/libCoreADI.so',
           0x7ffff7679000, 0x186000),
    'libc': ('/home/admin/rig/WORK/sysroot/lib64/libc.so',
             0x7ffff7b5d000, 0x200000),
    'cpp': ('/home/admin/rig/WORK/libs/libc++_shared.so',
            0x7ffff7a22000, 0x69000),
    'main': ('/home/admin/rig/WORK/adi_native', 0x555555554000, 0x19000),
}

# AT&T operand parsing ---------------------------------------------------------
SREG = {'rax': 'rax', 'eax': 'rax', 'ax': 'rax', 'al': 'rax', 'ah': 'rax',
        'rbx': 'rbx', 'ebx': 'rbx', 'bx': 'rbx', 'bl': 'rbx', 'bh': 'rbx',
        'rcx': 'rcx', 'ecx': 'rcx', 'cx': 'rcx', 'cl': 'rcx', 'ch': 'rcx',
        'rdx': 'rdx', 'edx': 'rdx', 'dx': 'rdx', 'dl': 'rdx', 'dh': 'rdx',
        'rsi': 'rsi', 'esi': 'rsi', 'si': 'rsi', 'sil': 'rsi',
        'rdi': 'rdi', 'edi': 'rdi', 'di': 'rdi', 'dil': 'rdi',
        'rbp': 'rbp', 'ebp': 'rbp', 'bp': 'rbp', 'bpl': 'rbp',
        'rsp': 'rsp', 'esp': 'rsp', 'sp': 'rsp', 'spl': 'rsp'}
for _i in range(8, 16):
    for _s in ('', 'd', 'w', 'b'):
        SREG[f'r{_i}{_s}'] = f'r{_i}'

IDX = {'rax': 0, 'rbx': 1, 'rcx': 2, 'rdx': 3, 'rsi': 4, 'rdi': 5,
       'rbp': 6, 'rsp': 7, 'r8': 8, 'r9': 9, 'r10': 10, 'r11': 11,
       'r12': 12, 'r13': 13, 'r14': 14, 'r15': 15}


def parse_mem(tok, regs):
    """disp(base,index,scale) -> address, or None"""
    m = re.match(r'^([+-]?0x[0-9a-f]+|\d*)?\((%[a-z0-9]+)?(?:,(%[a-z0-9]+)(?:,(\d+))?)?\)$', tok)
    if not m:
        return None
    disp = 0
    if m.group(1):
        disp = int(m.group(1), 0)
    base = SREG.get(m.group(2)[1:]) if m.group(2) else None
    index = SREG.get(m.group(3)[1:]) if m.group(3) else None
    scale = int(m.group(4)) if m.group(4) else 1
    addr = disp
    if base:
        addr += regs[IDX[base]]
    if index:
        addr += regs[IDX[index]] * scale
    return addr & 0xffffffffffffffff


def ops_of(text):
    """split 'movzbl -0x503245bf(%r13,%r11,1),%edi' -> (mnem, [operands])"""
    text = text.split('#')[0].strip()
    parts = text.split(None, 1)
    mnem = parts[0]
    rest = parts[1] if len(parts) > 1 else ''
    operands = [o.strip() for o in rest.split(',')]
    # rejoin operands that contain commas inside parens: (%r13,%r11,1)
    fixed = []
    for o in operands:
        if fixed and ('(' in fixed[-1] and ')' not in fixed[-1]):
            fixed[-1] = fixed[-1] + ',' + o
        else:
            fixed.append(o)
    return mnem, fixed


def disasm_batch(ips_by_page, module):
    """{page: [rvas]} -> {rva: (mnem, operands, raw_bytes)}"""
    so = MODULES[module][0]
    out = {}
    for page, rvas in sorted(ips_by_page.items()):
        lo, hi = page << 12, (page << 12) + 0x1000
        r = subprocess.run(['objdump', '-d', f'--start-address={lo:#x}',
                            f'--stop-address={hi:#x}', so],
                           capture_output=True, text=True).stdout
        m = {}
        for line in r.splitlines():
            mm = re.match(r'^\s*([0-9a-f]+):\t([0-9a-f ]+?)\t\s*(.*)$', line)
            if mm:
                addr = int(mm.group(1), 16)
                if addr in rvas:
                    txt = mm.group(3).split('#')[0].strip()
                    mnem, ops = ops_of(txt)
                    nbytes = len(mm.group(2).split())
                    m[addr] = (mnem, ops, nbytes)
        out[page] = m
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('trace')
    ap.add_argument('--out', default=None, help='write classified ips here')
    ap.add_argument('--ext-reads', action='store_true',
                    help='report external read regions')
    a = ap.parse_args()

    nrec = os.path.getsize(a.trace) // REC
    ips = []
    with open(a.trace, 'rb') as f:
        for _ in range(nrec):
            b = f.read(TREC)
            ip, = struct.unpack_from('<Q', b, 0)
            ips.append(ip)
            f.seek(XS, 1)

    distinct = sorted(set(ips))
    by_module = collections.defaultdict(set)
    for ip in distinct:
        for m, (_so, bias, sz) in MODULES.items():
            if bias <= ip < bias + sz:
                by_module[m].add(ip - bias)
    print(f'{nrec} records, {len(distinct)} distinct ips')
    for m, s in by_module.items():
        print(f'  {m}: {len(s)} distinct')

    # batch disassemble
    dis = {}
    for m, rvas in by_module.items():
        pages = collections.defaultdict(list)
        for rva in rvas:
            pages[rva >> 12].append(rva)
        d = disasm_batch(pages, m)
        merged = {}
        for pg, mm in d.items():
            merged.update(mm)
        dis[m] = merged
        print(f'  disasm {m}: {len(merged)}/{len(rvas)} decoded')

    if a.out:
        import json
        with open(a.out, 'w') as f:
            json.dump({m: {f'{r:#x}': {'m': v[0], 'o': v[1], 'n': v[2]}
                           for r, v in mm.items()}
                       for m, mm in dis.items()}, f)
        print(f'wrote {a.out}')

    if not a.ext_reads:
        return

    # EA coverage walk -------------------------------------------------------
    # simulate in order; memory reads not covered by earlier writes = external
    all_reads = []           # (rec, module, rva, mnem, addr, size)
    external = []
    written = {}             # byte addr -> last write record
    REGN = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
            'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
    with open(a.trace, 'rb') as f:
        f.seek(0)
        for i in range(nrec):
            b = f.read(TREC)
            ip, = struct.unpack_from('<Q', b, 0)
            regs = struct.unpack_from('<16Q', b, 8)
            f.seek(XS, 1)
            for m, (_so, bias, sz) in MODULES.items():
                if bias <= ip < bias + sz:
                    rva = ip - bias
                    break
            else:
                continue
            d = dis[m].get(rva)
            if not d:
                continue
            mnem, ops, nbytes = d
            # every operand containing '(' is a memory operand (lea = pure
            # arithmetic, no memory access; RMW ops both read and write)
            for k, o in enumerate(ops):
                if '(' not in o:
                    continue
                ea = parse_mem(o, regs)
                if ea is None:
                    continue
                # size: suffix of mnemonic (b/w/l/q), default q; movslq->q
                sz = {'movzbl': 1, 'movzwl': 2, 'movsbl': 1, 'movswl': 2,
                      'movslq': 4}.get(mnem)
                if sz is None:
                    suf = mnem[-1]
                    sz = {'b': 1, 'w': 2, 'l': 4, 'q': 8}.get(suf, 4)
                if mnem == 'lea':
                    continue
                is_store = (k == len(ops) - 1)
                if mnem in ('push',):
                    is_store = True
                if mnem in ('pop',):
                    is_store = False
                if is_store:
                    for bb in range(ea, ea + sz):
                        written[bb] = i
                    if mnem in ('add', 'sub', 'and', 'or', 'xor', 'adc',
                                'sbb', 'inc', 'dec', 'neg', 'not'):
                        all_reads.append((i, m, rva, mnem, ea, sz))
                else:
                    all_reads.append((i, m, rva, mnem, ea, sz))
                    for bb in range(ea, ea + sz):
                        if bb not in written:
                            external.append((i, m, rva, mnem, ea, sz))
                            break
            if mnem in ('push',):
                for bb in range(regs[7] - 8, regs[7]):
                    written[bb] = i
    # coverage
    print(f'external read instances: {len(external)} of {len(all_reads)}')
    reg = collections.defaultdict(list)
    for (i, m, rva, mnem, ea, sz) in external:
        reg[(m, rva, mnem, sz)].append(ea)
    for k, eas in sorted(reg.items(), key=lambda kv: -len(kv[1]))[:40]:
        m, rva, mnem, sz = k
        lo, hi = min(eas), max(eas)
        print(f'  {m}:0x{rva:06x} {mnem} sz{sz}: {len(eas)} hits, '
              f'EA {lo:#x}..{hi:#x}')


if __name__ == '__main__':
    main()
