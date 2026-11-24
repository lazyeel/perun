#!/usr/bin/env python3
"""trace_lift -- translate the executed instruction stream of ADI traces into
a Rust-VM program (warmvm).

Pipeline:
  1. decode   full-file objdump per module + anchored re-decode for ips the
              linear sweep skipped (CFF junk regions desync it).
  2. validate trace fallthrough deltas must equal decoded instruction lengths;
              direct-branch targets must match the next executed ip.
  3. translate mnemonics -> IR ops with tagged operands (strict: unknown
              patterns are fatal, never guessed).
  4. emit     program.bin (IR), stubs_<case>.json (libc call-site replays),
              seeds.json (memory manifest per case), meta.json.

The VM contract: record i logs rip = NEXT instruction and the register state
before it executes. The VM starts at (trace[0].ip, trace[0].regs) and must
reproduce (trace[i+1].ip, trace[i+1].regs) at every step. libc crossings are
replaced by stub events replaying the callee's post-state (full GP+XMM regs
at the return record); VM memory is seeded from entry-state dumps.
"""
import argparse
import collections
import json
import os
import re
import struct
import subprocess
import sys
import time

TREC = 152
XS = 832
REC = TREC + XS

MODULES = {
    'ss':  dict(so='/home/admin/rig/WORK/libs/libstoreservicescore.so',
                bias=0x7ffff742c000, size=0x24c0a0, idx=0),
    'ca':  dict(so='/home/admin/rig/WORK/libs/libCoreADI.so',
                bias=0x7ffff7679000, size=0x186168, idx=1),
    'libc': dict(so='/home/admin/rig/WORK/sysroot/lib64/libc.so',
                 bias=0x7ffff7b5d000, size=0x200000, idx=2),
}

DEFAULT_CASES = ['tM', 'tI', 'tE1794862200', 'tE1794863400', 'tE1794865200']


def trace_path(case):
    """The trace a case is lifted from and verified against.

    v2 runs write `otp-trace.new.bin` next to the seeds they were captured with,
    so prefer it when present: the bundle picks its seeds up from `seeds2/` and
    entry state from this very file, and mixing an old trace with new seeds
    would diverge at record 0 for reasons that have nothing to do with the VM.
    """
    root = f'/home/admin/rig/cases/{case}'
    for name in ('otp-trace.new.bin', 'otp-trace.bin'):
        p = os.path.join(root, name)
        if os.path.exists(p) and os.path.getsize(p) > 0:
            return p
    return os.path.join(root, 'otp-trace.bin')
# fake-clock epochs the corpus was captured with (see rig/run_seeds.sh)
EPOCHS = {
    'tM': 1794862800,
    'tI': 1794864600,
    'tE1794862200': 1794862200,
    'tE1794863400': 1794863400,
    'tE1794865200': 1794865200,
    'tb-end1': 1794862800,
    'tb-end2': 1794862800,
}
SEED_RANGES = [
    ('ca_rodata', 0x7ffff7679000, 0x4f000),
    # 0x5000, not 0x3200: libCoreADI's .bss ends at +0x186168 and holds
    # ctor flags the cipher reads; a short seed makes them read as 0.
    ('ca_rw',     0x7ffff77fb000, 0x5000),
    ('ss_ro',     0x7ffff742c000, 0x238320),
    ('ss_rw',     0x7ffff7665320, 0x13000),
    ('stack',     0x7ffffffef000, 0x10000),
    # the full jemalloc arena, not one 256 KiB window inside it: the
    # engine walks backwards into metadata below its allocation cursor
    ('heap',      0x7ffff77ff000, 0x201000),
    ('main_data', 0x555555554000, 0x19000),
]

# ---------------------------------------------------------------------------
# IR opcodes
(MOV, MOVZX, MOVSX, LEA, ADD, SUB, AND, OR, XOR, ADC, SBB, CMP, TEST, NEG,
 NOT, MUL, IMUL1, IMUL2, IMUL3, DIV, IDIV,
 SHL, SHR, SAR, ROL, ROR, SHLD, SHRD,
 SETCC, CMOVCC, JCC, JMP, CALL, RET, PUSH, POP, RDTSC, SYSCALL, NOP,
 BSWAP) = range(1, 41)
BASE_SSE = 41
(SSE_MOVDQA, SSE_MOVDQU, SSE_MOVUPS, SSE_MOVQ, SSE_MOVD,
 SSE_PADDD, SSE_PSUBD, SSE_PAND, SSE_POR, SSE_PXOR, SSE_PMULLD, SSE_PMULLW,
 SSE_PSHUFD, SSE_PSHUFB, SSE_PMOVZX, SSE_PINSRD, SSE_PEXTRD, SSE_PEXTRQ,
 SSE_PACKUSDW, SSE_PACKUSWB, SSE_PUNPCKLQDQ, SSE_PCMPEQD, SSE_PSLLD,
 SSE_PSRLD, SSE_BLENDVPS) = range(BASE_SSE, BASE_SSE + 25)

OPNAMES = {v: k for k, v in list(globals().items()) if isinstance(v, int) and 1 <= v < BASE_SSE + 25}

# x86 condition codes (low nibble of jcc/setcc opcode)
CC = {'o': 0, 'no': 1, 'b': 2, 'c': 2, 'ae': 3, 'e': 4, 'ne': 5, 'be': 6,
      'a': 7, 's': 8, 'ns': 9, 'p': 10, 'np': 11, 'l': 12, 'ge': 13,
      'le': 14, 'g': 15}

# operand tags
OP_NONE, OP_REG, OP_MEM, OP_IMM, OP_XMM, OP_TARGET = range(6)

PREFIXES = {'data16', 'cs', 'ds', 'es', 'fs', 'gs', 'ss', 'lock', 'rep',
            'repe', 'repne', 'repz', 'repnz', 'notrack', 'bnd'}
for _i in range(16):
    PREFIXES.add(f'rex{"" if _i == 0 else chr(0x41 + _i)}')


# ---------------------------------------------------------------------------
def ops_of(text):
    """'movzbl -0x503245bf(%r13,%r11,1),%edi' -> (mnem, [operands]) with
    memory operands rejoined across commas."""
    text = text.split('#')[0].strip()
    parts = text.split(None, 1)
    mnem = parts[0]
    rest = parts[1] if len(parts) > 1 else ''
    while mnem in PREFIXES:
        nxt = rest.split(None, 1)
        if not nxt:
            return None, []          # lone prefix: junk byte
        mnem, rest = nxt[0], (nxt[1] if len(nxt) > 1 else '')
    if mnem == '.byte':
        return None, []
    toks = [o.strip() for o in rest.split(',')] if rest else []
    fixed = []
    for o in toks:
        if fixed and ('(' in fixed[-1] and ')' not in fixed[-1]):
            fixed[-1] = fixed[-1] + ',' + o
        else:
            fixed.append(o)
    return mnem, fixed


SREG = {}
# Size code 17 means "high byte" (bits 8..15): ah/ch/dh/bh must not be
# confused with al/cl/dl/bl, the VM decodes 17 specially.
HB = 17
# The trace and the VM number registers the way ptrace's user_regs_struct
# does: rax,rbx,rcx,rdx,rsi,rdi,rbp,rsp,r8..r15.  The x86 *encoding* order is
# ax,cx,dx,bx,sp,bp,si,di and must not leak out of this table -- objdump only
# ever gives us names, so this is the single place where they are mapped.
PTRACE_ORDER = {
    'ax': 0, 'bx': 1, 'cx': 2, 'dx': 3,
    'si': 4, 'di': 5, 'bp': 6, 'sp': 7,
}
for _n, _i in PTRACE_ORDER.items():
    SREG[f'r{_n}'] = (_i, 8)
    SREG[f'e{_n}'] = (_i, 4)
    SREG[_n] = (_i, 2)
    SREG[(_n[:-1] if _n.endswith('x') else _n) + 'l'] = (_i, 1)
SREG['ah'] = (PTRACE_ORDER['ax'], HB)
SREG['ch'] = (PTRACE_ORDER['cx'], HB)
SREG['dh'] = (PTRACE_ORDER['dx'], HB)
SREG['bh'] = (PTRACE_ORDER['bx'], HB)
for _i in range(8, 16):
    SREG[f'r{_i}'] = (_i, 8)
    SREG[f'r{_i}d'] = (_i, 4)
    SREG[f'r{_i}w'] = (_i, 2)
    SREG[f'r{_i}b'] = (_i, 1)
# REX byte-register names for the classic rsp/rbp/rsi/rdi slots
SREG['spl'] = (7, 1); SREG['bpl'] = (6, 1)
SREG['sil'] = (4, 1); SREG['dil'] = (5, 1)


def reg_parse(tok):
    """'%r13d' -> (idx, size) or None"""
    if not tok.startswith('%'):
        return None
    return SREG.get(tok[1:])


def xmm_parse(tok):
    m = re.match(r'^%xmm([0-9]|1[0-5])$', tok)
    return int(m.group(1)) if m else None


def mem_parse(tok, next_ip=None):
    """'disp(base,index,scale)' or bare disp (absolute). Returns dict or None."""
    if tok.startswith('*'):
        tok = tok[1:]
    m = re.match(r'^([+-]?0x[0-9a-f]+|[+-]?\d+)?\((%[a-z0-9]+)?'
                 r'(?:,(%[a-z0-9]+)(?:,(\d+))?)?\)$', tok)
    if m:
        disp = int(m.group(1), 0) if m.group(1) else 0
        base = idx = 255
        scale = int(m.group(4)) if m.group(4) else 1
        if m.group(2):
            if m.group(2) == '%rip':
                if next_ip is None:
                    return None
                disp += next_ip      # caller adds insn len
            else:
                base = reg_parse(m.group(2))[0]
        if m.group(3):
            idx = reg_parse(m.group(3))[0]
        return dict(kind='mem', base=base, index=idx, scale=scale, disp=disp)
    # absolute (no parens, not register/immediate)
    if re.match(r'^[+-]?(0x[0-9a-f]+|\d+)$', tok):
        return dict(kind='mem', base=255, index=255, scale=1,
                    disp=int(tok, 0) if tok.startswith('0x') or tok.startswith('-0x')
                    else int(tok))
    return None


def imm_parse(tok):
    if tok.startswith('$'):
        return int(tok[1:], 0)
    return None


def target_parse(tok):
    """direct branch target '1c77a2 <sym+0x40>' -> address"""
    m = re.match(r'^([0-9a-f]+)(?:\s|<|$)', tok)
    return int(m.group(1), 16) if m else None


def strip_sfx(mnem, names):
    """objdump appends the operand size to registerless forms (divl/shrl/...).
    Returns the base mnemonic or None if not in `names`."""
    if mnem in names:
        return mnem
    if mnem[-1] in 'bwql' and mnem[:-1] in names:
        return mnem[:-1]
    return None


def operand_kind(tok, next_ip=None):
    """classify one AT&T operand token"""
    if tok.startswith('*'):
        tok = tok[1:]
    r = reg_parse(tok)
    if r is not None:
        return dict(kind='reg', idx=r[0], size=r[1])
    x = xmm_parse(tok)
    if x is not None:
        return dict(kind='xmm', idx=x)
    v = imm_parse(tok)
    if v is not None:
        return dict(kind='imm', val=v)
    m = mem_parse(tok, next_ip)
    if m is not None:
        return m
    t = target_parse(tok)
    if t is not None:
        return dict(kind='target', addr=t)
    return None


def mem_size_of(o):
    return dict(kind='mem', base=o['base'], index=o['index'], scale=o['scale'],
                size=o['size'], disp=o['disp'])


class Lifter:
    def __init__(self, args):
        self.args = args
        self.dis = {}        # module -> rva -> (mnem, [ops], nbytes)
        self.errors = []
        self.unknown = collections.Counter()

    # ---- stage 1: decode ------------------------------------------------
    def decode_all(self):
        t0 = time.time()
        full = {}
        if os.path.exists(self.args.full_dis) and not self.args.regen:
            full = json.load(open(self.args.full_dis))
        todo = [n for n in MODULES if n not in full or self.args.regen]
        for name in todo:
            mo = MODULES[name]
            r = subprocess.run(['objdump', '-d', mo['so']],
                               capture_output=True, text=True).stdout
            m = {}
            prev_addr = None
            for line in r.splitlines():
                z = re.match(r'^\s*([0-9a-f]+):\t([0-9a-f ]+?)(?:\t(.*))?$', line)
                if z:
                    addr = int(z.group(1), 16)
                    raw = z.group(2).strip()
                    if not raw:
                        continue
                    txt = (z.group(3) or '').split('#')[0].strip()
                    nb = len(raw.split())
                    if txt == '' and prev_addr is not None:
                        # continuation line of a wrapped long instruction
                        m[prev_addr] = (m[prev_addr][0], m[prev_addr][1] + nb)
                        continue
                    m[addr] = (txt, nb)
                    prev_addr = addr
            full[name] = {hex(a): v for a, v in m.items()}
        if todo:
            json.dump(full, open(self.args.full_dis, 'w'))
        for name, mo in MODULES.items():
            mm = {}
            for k, (txt, nb) in full[name].items():
                mnem, ops = ops_of(txt)
                if mnem is None:
                    continue
                mm[int(k, 16)] = (mnem, ops, nb)
            self.dis[name] = mm
            print(f'  decode {name}: {len(mm)} from full-file sweep')

        # executed ips across all cases
        self.cases = self.args.cases
        self.ips = {}
        self.nrec = {}
        for case in self.cases:
            p = trace_path(case)
            n = os.path.getsize(p) // REC
            ips = []
            with open(p, 'rb') as f:
                for _ in range(n):
                    b = f.read(TREC)
                    if len(b) < TREC:
                        break
                    ips.append(struct.unpack('<Q', b[0:8])[0])
                    f.seek(XS, 1)
            self.ips[case] = ips
            self.nrec[case] = len(ips)

        executed = collections.defaultdict(set)
        for case, ips in self.ips.items():
            for ip in ips:
                for name, mo in MODULES.items():
                    if mo['bias'] <= ip < mo['bias'] + mo['size']:
                        executed[name].add(ip - mo['bias'])
                        break
        self.executed = executed
        # anchored re-decode for anything the sweep missed
        cache_file = os.path.join(self.args.out, 'anchored_cache.json')
        cache = json.load(open(cache_file)) if os.path.exists(cache_file) else {}
        for name, rvas in executed.items():
            miss = [r for r in rvas if r not in self.dis[name]]
            print(f'  {name}: {len(rvas)} executed ips, {len(miss)} need anchored decode')
            for r in miss:
                key = f'{name}:{r:#x}'
                if key in cache:
                    txt, nb = cache[key]
                else:
                    txt, nb = self._anchored(name, r)
                    if txt is not None:
                        cache[key] = [txt, nb]
                if txt is None:
                    self.errors.append(f'{name}:{r:#x} undecodable')
                    continue
                mnem, ops = ops_of(txt)
                if mnem is None:
                    self.errors.append(f'{name}:{r:#x} anchored junk: {txt!r}')
                    continue
                self.dis[name][r] = (mnem, ops, nb)
        if cache:
            os.makedirs(self.args.out, exist_ok=True)
            json.dump(cache, open(cache_file, 'w'))
        self._reconcile()
        print(f'  decode done ({time.time()-t0:.1f}s), errors: {len(self.errors)}')
        for e in self.errors[:20]:
            print('   ', e)

    def _reconcile(self):
        """The linear sweep desyncs inside CFF junk regions, so some executed
        ips carry a bogus decode. Re-anchor every executed ip in such clusters
        whose observed successor contradicts the decoded instruction length."""
        for rnd in range(4):
            bad = set()
            for case, ips in self.ips.items():
                n = len(ips)
                for i in range(n - 1):
                    a, b = ips[i], ips[i + 1]
                    ma = self._module_of(a)
                    if ma is None or ma[0] == 'libc':
                        continue
                    name, rva = ma
                    d = self.dis[name].get(rva)
                    if not d:
                        continue
                    mnem, ops, nb = d
                    delta = (b - a) & 0xffffffffffffffff
                    if delta > 15:
                        continue
                    if (mnem.startswith('j') or mnem.startswith('call')
                            or mnem == 'ret'):
                        continue
                    if delta != nb:
                        bad.add((name, rva))
            if not bad:
                break
            # cluster bad rvas per module, then re-anchor all executed ips
            # inside each cluster with a margin
            todo = set()
            for name in {n for n, _ in bad}:
                rvas = sorted(r for n, r in bad if n == name)
                clusters = [[rvas[0], rvas[0]]]
                for r in rvas[1:]:
                    if r - clusters[-1][1] <= 0x200:
                        clusters[-1][1] = r
                    else:
                        clusters.append([r, r])
                for lo, hi in clusters:
                    for r in self.executed[name]:
                        if lo - 0x100 <= r <= hi + 0x100:
                            todo.add((name, r))
            changed = 0
            for name, rva in todo:
                txt, nb = self._anchored(name, rva)
                if txt is None:
                    continue
                mnem, ops = ops_of(txt)
                if mnem is None:
                    continue
                if self.dis[name].get(rva) != (mnem, ops, nb):
                    self.dis[name][rva] = (mnem, ops, nb)
                    changed += 1
            print(f'  reconcile round {rnd+1}: {len(bad)} bad lengths, '
                  f'{len(todo)} ips re-anchored, {changed} changed')

    def _anchored(self, module, rva):
        so = MODULES[module]['so']
        r = subprocess.run(['objdump', '-d', f'--start-address={rva:#x}',
                            f'--stop-address={rva+32:#x}', so],
                           capture_output=True, text=True).stdout
        lines = r.splitlines()
        for idx, line in enumerate(lines):
            z = re.match(r'^\s*([0-9a-f]+):\t([0-9a-f ]+?)(?:\t(.*))?$', line)
            if z and int(z.group(1), 16) == rva:
                nb = len(z.group(2).strip().split())
                # objdump wraps long instructions: next line repeats the
                # remaining bytes with no mnemonic (and no trailing tab)
                if idx + 1 < len(lines):
                    z2 = re.match(r'^\s*([0-9a-f]+):\t([0-9a-f ]+?)\s*$',
                                  lines[idx + 1])
                    if z2 and int(z2.group(1), 16) == rva + nb:
                        nb += len(z2.group(2).strip().split())
                return (z.group(3) or '').split('#')[0].strip(), nb
        return None, None

    # ---- stage 2: validate ----------------------------------------------
    def validate(self):
        bad = collections.Counter()
        samples = collections.defaultdict(list)
        for case, ips in self.ips.items():
            n = len(ips)
            for i in range(n - 1):
                a, b = ips[i], ips[i + 1]
                mod_a = self._module_of(a)
                if mod_a is None or mod_a[0] == 'libc':
                    continue                     # libc runs are stubbed away
                name, rva = mod_a
                d = self.dis[name].get(rva)
                if not d:
                    bad['nodecode'] += 1
                    continue
                mnem, ops, nb = d
                delta = (b - a) & 0xffffffffffffffff
                if delta > 15:
                    continue                     # branch/ret/other module
                is_branch = (mnem.startswith('j') or mnem.startswith('call')
                             or mnem == 'ret')
                if is_branch:
                    if mnem.startswith('j') and mnem != 'jmp':
                        cc = mnem[1:]
                        if cc in CC and len(ops) == 1:
                            t = target_parse(ops[0])
                            # objdump prints the ABSOLUTE target (module rva)
                            taken = (t is not None
                                     and MODULES[name]['bias'] + t == b)
                            fall = a + nb == b
                            if not (taken or fall):
                                bad['jcc_next'] += 1
                                if len(samples['jcc_next']) < 5:
                                    samples['jcc_next'].append(
                                        (case, i, f'{name}:{rva:#x}', mnem, nb,
                                         hex(a), hex(b)))
                    continue
                if delta != nb:
                    bad['fallthrough_len'] += 1
                    if len(samples['fallthrough_len']) < 5:
                        samples['fallthrough_len'].append(
                            (case, i, f'{name}:{rva:#x}', mnem, nb, hex(a), hex(b)))
        print('  validate:', dict(bad) or 'clean')
        for k, v in samples.items():
            for s in v:
                print('   ', k, s)
        self.bad = bad

    def _module_of(self, ip):
        for name, mo in MODULES.items():
            if mo['bias'] <= ip < mo['bias'] + mo['size']:
                return name, ip - mo['bias']
        return None

    # ---- stage 3: translate ---------------------------------------------
    def translate(self):
        self.prog = {}
        unknown = collections.Counter()
        for name, rvas in self.executed.items():
            if name == 'libc':
                continue                     # libc is replaced by stub events
            for rva in rvas:
                d = self.dis[name].get(rva)
                if not d:
                    continue
                mnem, ops, nb = d
                try:
                    enc = self.encode(name, rva, mnem, ops, nb)
                except KeyError as e:
                    unknown[(mnem, tuple(ops))] += 1
                    enc = None
                if enc is not None:
                    if len(enc) == 2:
                        enc = enc + (0,)
                    self.prog[(name, rva)] = (enc[0], enc[1], enc[2], nb)
        if unknown:
            print(f'  translate: {len(unknown)} unknown patterns '
                  f'({sum(unknown.values())} ips)')
            for (mnem, ops), n in unknown.most_common(40):
                print(f'    {mnem} {list(ops)}  x{n}')
        else:
            print(f'  translate: all {len(self.prog)} ips encoded')

    # -- encoding helpers --------------------------------------------------
    @staticmethod
    def _opsz(mnem, ops):
        """operand size for GP alu/mov ops"""
        for o in ops:
            r = reg_parse(o)
            if r is not None:
                return 1 if r[1] == HB else r[1]
        suffix = {'b': 1, 'w': 2, 'l': 4, 'q': 8}.get(mnem[-1])
        return suffix if suffix else 4

    def encode(self, module, rva, mnem, ops, nb):
        next_ip = rva + nb
        O = [operand_kind(o, next_ip) for o in ops]
        for o in O:
            if o is None:
                raise KeyError('bad operand')

        def dst_src(sz=None):
            return O[0], O[1]

        # --- control flow ---
        if mnem == 'nop' or mnem == 'nopl' or mnem == 'nopw' or mnem.startswith('nop'):
            return (NOP, [])
        if mnem == 'jmp':
            if ops[0].startswith('*'):
                o = O[0]
                if o['kind'] in ('reg', 'mem'):
                    if o['kind'] == 'mem':
                        o = dict(o, size=8)
                    return (JMP, [o])
                raise KeyError('jmp ind')
            t = target_parse(ops[0])
            if t is None:
                raise KeyError('jmp direct')
            tm = self._module_of(MODULES[module]['bias'] + t)
            return (JMP, [dict(kind='target', module=tm[0], rva=tm[1])])
        if mnem.startswith('j') and mnem != 'jmp':
            cc = mnem[1:]
            if cc not in CC:
                raise KeyError('jcc')
            t = target_parse(ops[0])
            if t is None:
                raise KeyError('jcc direct')
            tm = self._module_of(MODULES[module]['bias'] + t)
            return (JCC, [dict(kind='target', module=tm[0], rva=tm[1])], CC[cc])
        if mnem == 'call':
            if ops[0].startswith('*'):
                o = O[0]
                if o['kind'] in ('reg', 'mem'):
                    if o['kind'] == 'mem':
                        o = dict(o, size=8)
                    return (CALL, [o])
                raise KeyError('call ind')
            t = target_parse(ops[0])
            if t is None:
                raise KeyError('call direct')
            tm = self._module_of(MODULES[module]['bias'] + t)
            return (CALL, [dict(kind='target', module=tm[0], rva=tm[1])])
        if mnem == 'ret':
            return (RET, [])
        if mnem == 'push':
            return (PUSH, [self._with_size(O[0], 8)])
        if mnem == 'pop':
            return (POP, [self._with_size(O[0], 8)])
        if mnem == 'rdtsc':
            return (RDTSC, [])
        if mnem == 'syscall':
            return (SYSCALL, [])

        # --- data movement ---
        if mnem in ('mov', 'movabs', 'movl', 'movq', 'movb', 'movw'):
            x = xmm_parse(ops[0]) if ops else None
            y = xmm_parse(ops[1]) if len(ops) > 1 else None
            if x is not None or y is not None:
                return self._encode_sse_mov(mnem, O)
            sz = 8 if mnem == 'movabs' else self._opsz(mnem, ops)
            if O[0]['kind'] == 'imm' and O[0]['val'] > 0x7fffffffffffffff:
                sz = 8
            # IR convention: dst-first
            return (MOV, [self._with_size(O[1], sz),
                          self._with_size(O[0], sz)])
        if mnem in ('movzbl', 'movzwl', 'movzbq', 'movzwq'):
            # 'movz' + size char (index 4) + dst size char (index 5)
            src_sz = 1 if mnem[4] == 'b' else 2
            dst_sz = reg_parse(ops[1])[1]
            return (MOVZX, [self._with_size(O[1], dst_sz), self._with_size(O[0], src_sz)])
        if mnem in ('movsbl', 'movsbq', 'movswl', 'movswq', 'movslq'):
            src_sz = 1 if mnem[4] == 'b' else (2 if mnem[4] == 'w' else 4)
            dst_sz = reg_parse(ops[1])[1]
            return (MOVSX, [self._with_size(O[1], dst_sz), self._with_size(O[0], src_sz)])
        if mnem == 'cltq':
            return (MOVSX, [dict(kind='reg', idx=0, size=8), dict(kind='reg', idx=0, size=4)])
        if mnem == 'cqto':
            # rdx = sign(rax) (the 128-bit dividend high half); indices are
            # ptrace slots, so rdx is 3 and rax is 0
            return (MOVSX, [dict(kind='reg', idx=3, size=8),
                            dict(kind='reg', idx=0, size=8)])
        if mnem == 'cltd':
            return (MOVSX, [dict(kind='reg', idx=3, size=4),
                            dict(kind='reg', idx=0, size=4)])
        if mnem == 'bswap':
            return (BSWAP, [self._with_size(O[0], self._opsz(mnem, ops))])
        if mnem == 'lea':
            return (LEA, [self._with_size(O[1], reg_parse(ops[1])[1]),
                          self._with_size(O[0], 8)])

        # --- alu ---
        ALU = {'add': ADD, 'sub': SUB, 'and': AND, 'or': OR, 'xor': XOR,
               'adc': ADC, 'sbb': SBB, 'cmp': CMP, 'test': TEST}
        base = mnem[:-1] if mnem[-1] in 'bwql' and mnem[:-1] in ALU else mnem
        if base in ALU:
            sz = self._opsz(mnem, ops)
            # IR convention: dst-first
            return (ALU[base], [self._with_size(O[1], sz),
                                self._with_size(O[0], sz)])
        # objdump appends a size suffix to registerless forms: negl/divl/shrl/...
        one = strip_sfx(mnem, ('neg', 'not'))
        if one:
            return ({'neg': NEG, 'not': NOT}[one],
                    [self._with_size(O[0], self._opsz(mnem, ops))])
        two = strip_sfx(mnem, ('mul', 'div', 'idiv'))
        if two:
            return ({'mul': MUL, 'div': DIV, 'idiv': IDIV}[two],
                    [self._with_size(O[0], self._opsz(mnem, ops))])
        if strip_sfx(mnem, ('imul',)):
            if len(ops) == 1:
                return (IMUL1, [self._with_size(O[0], self._opsz(mnem, ops))])
            if len(ops) == 2:
                return (IMUL2, [self._with_size(O[1], self._opsz(mnem, ops)),
                                self._with_size(O[0], self._opsz(mnem, ops))])
            if len(ops) == 3:
                return (IMUL3, [self._with_size(O[2], self._opsz(mnem, ops)),
                                self._with_size(O[1], self._opsz(mnem, ops)),
                                self._with_size(O[0], 8)])
        sh = strip_sfx(mnem, ('shl', 'shr', 'sar', 'sal', 'rol', 'ror'))
        if sh:
            op = {'sal': SHL, 'shl': SHL, 'shr': SHR, 'sar': SAR,
                  'rol': ROL, 'ror': ROR}[sh]
            cnt = self._count_operand(O[0])
            return (op, [self._with_size(O[1], self._opsz(mnem, ops[1:])), cnt])
        dsh = strip_sfx(mnem, ('shld', 'shrd'))
        if dsh:
            op = SHLD if dsh == 'shld' else SHRD
            cnt = self._count_operand(O[0])
            return (op, [self._with_size(O[2], self._opsz(mnem, ops[1:])),
                         self._with_size(O[1], self._opsz(mnem, ops[1:])), cnt])

        # --- flags / conditional ---
        if mnem.startswith('set'):
            cc = mnem[3:]
            if cc not in CC:
                raise KeyError('setcc')
            return (SETCC, [self._with_size(O[0], 1)], CC[cc])
        if mnem.startswith('cmov'):
            cc = mnem[4:]
            if cc not in CC:
                raise KeyError('cmovcc')
            return (CMOVCC, [self._with_size(O[1], self._opsz(mnem, ops)),
                             self._with_size(O[0], self._opsz(mnem, ops))], CC[cc])

        # --- SSE ---
        if mnem in ('movd', 'movq'):
            return self._encode_sse_mov(mnem, O)
        if mnem in ('movdqa', 'movdqu', 'movups', 'blendvps'):
            return self._encode_sse(mnem, O)
        if mnem.startswith('p'):
            return self._encode_sse(mnem, O)

        raise KeyError('mnem')

    @staticmethod
    def _count_operand(o):
        if o['kind'] == 'imm':
            return dict(kind='imm', val=o['val'], size=1)
        if o['kind'] == 'reg':
            return dict(kind='reg', idx=o['idx'], size=o['size'])
        if o['kind'] == 'xmm':
            return dict(kind='xmm', idx=o['idx'])
        raise KeyError('count')

    @staticmethod
    def _with_size(o, sz):
        if o['kind'] == 'reg':
            return dict(kind='reg', idx=o['idx'],
                        size=o['size'] if o['size'] == HB else sz)
        if o['kind'] == 'mem':
            return dict(kind='mem', base=o['base'], index=o['index'],
                        scale=o['scale'], size=sz, disp=o['disp'])
        if o['kind'] == 'imm':
            return dict(kind='imm', val=o['val'], size=sz)
        return o

    @staticmethod
    def _memsz(o, sz):
        if o['kind'] == 'mem':
            return dict(o, size=sz)
        return o

    def _encode_sse_mov(self, mnem, O):
        a, b = O[0], O[1]
        if a['kind'] == 'xmm' and b['kind'] == 'xmm':
            # AT&T order: src,dst -> normalize to dst-first
            return (SSE_MOVQ if mnem in ('movq',) else SSE_MOVD, [b, a])
        if a['kind'] == 'xmm' and b['kind'] == 'reg':
            return (SSE_MOVQ if mnem == 'movq' else SSE_MOVD, [b, a])
        if a['kind'] == 'reg' and b['kind'] == 'xmm':
            return (SSE_MOVQ if mnem == 'movq' else SSE_MOVD, [b, a])
        if a['kind'] == 'xmm' and b['kind'] == 'mem':
            return (SSE_MOVQ if mnem == 'movq' else SSE_MOVD,
                    [self._memsz(b, 8 if mnem == 'movq' else 4), a])
        if a['kind'] == 'mem' and b['kind'] == 'xmm':
            return (SSE_MOVQ if mnem == 'movq' else SSE_MOVD,
                    [b, self._memsz(a, 8 if mnem == 'movq' else 4)])
        raise KeyError('sse mov')

    def _encode_sse(self, mnem, O):
        IMM_FIRST = {'pshufd', 'pextrd', 'pextrq', 'pinsrd'}
        if mnem in ('movdqa', 'movdqu', 'movups'):
            a, b = O[0], O[1]
            op = {'movdqa': SSE_MOVDQA, 'movdqu': SSE_MOVDQU,
                  'movups': SSE_MOVUPS}[mnem]
            if a['kind'] == 'xmm' and b['kind'] in ('xmm', 'mem'):
                # normalize dst-first: AT&T puts src first
                return (op, [self._memsz(b, 16), a])
            if a['kind'] == 'mem' and b['kind'] == 'xmm':
                return (op, [b, self._memsz(a, 16)])
            raise KeyError('movdq')
        if mnem in ('paddd', 'psubd', 'pand', 'por', 'pxor', 'pmulld',
                    'pmullw', 'pshufb', 'punpcklqdq', 'pcmpeqd',
                    'packusdw', 'packuswb'):
            op = {'paddd': SSE_PADDD, 'psubd': SSE_PSUBD, 'pand': SSE_PAND,
                  'por': SSE_POR, 'pxor': SSE_PXOR, 'pmulld': SSE_PMULLD,
                  'pmullw': SSE_PMULLW, 'pshufb': SSE_PSHUFB,
                  'punpcklqdq': SSE_PUNPCKLQDQ, 'pcmpeqd': SSE_PCMPEQD,
                  'packusdw': SSE_PACKUSDW, 'packuswb': SSE_PACKUSWB}[mnem]
            if O[1]['kind'] == 'xmm' and O[0]['kind'] in ('xmm', 'mem'):
                return (op, [O[1], self._memsz(O[0], 16)])
            raise KeyError(mnem)
        if mnem == 'pshufd':
            if O[0]['kind'] == 'imm' and O[2]['kind'] == 'xmm':
                return (SSE_PSHUFD, [O[2], self._memsz(O[1], 16)],
                        O[0]['val'] & 0xff)
            raise KeyError('pshufd')
        if mnem in ('pmovzxbd', 'pmovzxbw', 'pmovzxdq'):
            kind = {'pmovzxbd': 0, 'pmovzxbw': 1, 'pmovzxdq': 2}[mnem]
            if O[0]['kind'] in ('xmm', 'mem') and O[1]['kind'] == 'xmm':
                src = O[0]
                if src['kind'] == 'mem':
                    src = mem_size_of(dict(src, size=4 if kind == 0 else 8))
                return (SSE_PMOVZX, [O[1], src], kind)
            raise KeyError(mnem)
        if mnem == 'pinsrd':
            if O[0]['kind'] == 'imm' and O[2]['kind'] == 'xmm':
                src = O[1]
                if src['kind'] == 'mem':
                    src = mem_size_of(dict(src, size=4))
                return (SSE_PINSRD, [O[2], src], O[0]['val'] & 0xff)
            raise KeyError('pinsrd')
        if mnem in ('pextrd', 'pextrq'):
            if O[0]['kind'] == 'imm' and O[1]['kind'] == 'xmm':
                dst = O[2]
                if dst['kind'] == 'mem':
                    dst = mem_size_of(dict(dst, size=4 if mnem == 'pextrd' else 8))
                elif dst['kind'] == 'reg':
                    dst = dict(dst, size=4 if mnem == 'pextrd' else 8)
                return (SSE_PEXTRD if mnem == 'pextrd' else SSE_PEXTRQ,
                        [dst, O[1]], O[0]['val'] & 0xff)
            raise KeyError(mnem)
        if mnem in ('pslld', 'psrld'):
            op = SSE_PSLLD if mnem == 'pslld' else SSE_PSRLD
            if O[0]['kind'] == 'imm' and O[1]['kind'] == 'xmm':
                return (op, [O[1], dict(kind='imm', val=O[0]['val'], size=1)])
            if O[0]['kind'] == 'xmm' and O[1]['kind'] == 'xmm':
                return (op, [O[1], O[0]])
            raise KeyError(mnem)
        if mnem == 'blendvps':
            # SSE4.1 form: implicit %xmm0 mask; objdump may print it
            # explicitly as the first operand (3-operand listing) or omit it
            if (len(O) == 2 and O[0]['kind'] in ('xmm', 'mem')
                    and O[1]['kind'] == 'xmm'):
                src, dst = O[0], O[1]
            elif (len(O) == 3 and O[0]['kind'] == 'xmm' and O[0]['idx'] == 0
                    and O[1]['kind'] in ('xmm', 'mem') and O[2]['kind'] == 'xmm'):
                src, dst = O[1], O[2]
            else:
                raise KeyError('blendvps')
            if src['kind'] == 'mem':
                src = mem_size_of(dict(src, size=16))
            return (SSE_BLENDVPS, [dst, src])
        raise KeyError(mnem)

    # ---- stage 4: stubs --------------------------------------------------
    def extract_stubs(self):
        self.stubs = {}
        LIBC = MODULES['libc']
        for case, ips in self.ips.items():
            n = self.nrec[case]
            stop = self._stop_rec(case)
            events = []
            i = 0
            while i < n:
                ip = ips[i]
                if not (LIBC['bias'] <= ip < LIBC['bias'] + LIBC['size']):
                    i += 1
                    continue
                # entry into libc at record i
                if LIBC['bias'] <= ips[i - 1] < LIBC['bias'] + LIBC['size']:
                    i += 1
                    continue
                pred = self._decode_abs(ips[i - 1])
                if pred is None:
                    self.errors.append(f'{case}: stub pred undecodable @{i}')
                    i += 1
                    continue
                pmnem, pops, pnb = pred
                push = True
                call_rec = i - 1
                if pmnem == 'jmp' and pops and pops[0].startswith('*'):
                    # plt-mediated: walk back to the call
                    j = i - 1
                    while True:
                        d2 = self._decode_abs(ips[j])
                        if d2 and d2[0] == 'jmp' and d2[1] and d2[1][0].startswith('*'):
                            j -= 1
                            continue
                        break
                    pred2 = self._decode_abs(ips[j])
                    if not (pred2 and pred2[0] == 'call'):
                        self.errors.append(
                            f'{case}: plt walk failed @{i} -> {j} {pred2}')
                        i += 1
                        continue
                    site, ret, pnb = ips[j], ips[j] + pred2[2], pred2[2]
                    call_rec = j
                elif pmnem == 'call':
                    site, ret = ips[i - 1], ips[i - 1] + pnb
                    call_rec = i - 1
                elif pmnem == 'jmp':
                    # direct tail-jmp into libc: no push
                    site, ret, push = ips[i - 1], None, False
                    call_rec = i - 1
                else:
                    self.errors.append(
                        f'{case}: unexpected pred {pmnem} @{i}')
                    i += 1
                    continue
                if push:
                    k = None
                    for r in range(i + 1, min(i + 400000, n)):
                        if ips[r] == ret:
                            k = r
                            break
                    if k is None:
                        self.errors.append(f'{case}: no return for stub @{i}')
                        i += 1
                        continue
                    # all records between must be libc
                    bad = [r for r in range(i, k)
                           if not (LIBC['bias'] <= ips[r] < LIBC['bias'] + LIBC['size'])]
                    if bad:
                        self.errors.append(
                            f'{case}: stub span crosses ss/ca at {bad[:4]} (entry {i} ret {k})')
                else:
                    k = i + 1
                regs, xmm = self._record_state(case, k)
                events.append(dict(rec_entry=i, rec_call=call_rec, rec_ret=k,
                                   site=site, ret=ret, push=push,
                                   regs=list(regs), xmm=xmm.hex()))
                i = k + 1
            self.stubs[case] = events
            print(f'  stubs {case}: {len(events)} events')

    def _stop_rec(self, case):
        p = trace_path(case)
        with open(p, 'rb') as f:
            n = self.nrec[case]
            for i in range(n):
                f.seek(i * REC + 148)
                k = f.read(1)[0]
                if k == 3:
                    return i
        return n

    def _memdeltas(self, case):
        """Words the libc calls wrote, from adi_freeze --trace-mem-out.

        One line per changed 8-byte word: rec_call rec_ret addr value.  The
        two record indices are decimal (they come from a %llu counter), the
        address and the value are hex.  rec_ret is the record whose ip is first
        back in the engine, which is exactly the stub return record computed
        above, so the VM can key on it without knowing which libc function ran.
        """
        p = f'/home/admin/rig/cases/{case}/memdelta.txt'
        out = []
        if not os.path.exists(p):
            return out
        with open(p) as f:
            for line in f:
                q = line.split()
                if len(q) != 4:
                    continue
                try:
                    out.append((int(q[0], 10), int(q[1], 10),
                                int(q[2], 16), int(q[3], 16)))
                except ValueError:
                    continue
        return out

    def _decode_abs(self, ip):
        for name, mo in MODULES.items():
            if mo['bias'] <= ip < mo['bias'] + mo['size']:
                d = self.dis[name].get(ip - mo['bias'])
                if d:
                    return d
                txt, nb = self._anchored(name, ip - mo['bias'])
                if txt:
                    mnem, ops = ops_of(txt)
                    if mnem:
                        self.dis[name][ip - mo['bias']] = (mnem, ops, nb)
                        return (mnem, ops, nb)
        return None

    def _record_state(self, case, rec):
        p = trace_path(case)
        with open(p, 'rb') as f:
            f.seek(rec * REC)
            b = f.read(TREC)
            regs = struct.unpack_from('<16Q', b, 8)
            xs = f.read(XS)
        return regs, xs[160:416]

    # ---- stage 5: emit ---------------------------------------------------
    def emit(self):
        os.makedirs(self.args.out, exist_ok=True)
        # program.bin v3: dst-first operands, instruction length, module table
        # (the VM needs load biases to turn module RVAs into absolute addresses)
        out = bytearray()
        mods = sorted(MODULES.values(), key=lambda m: m['idx'])
        out += struct.pack('<IIII', 0x50564d50, 3, len(self.prog), len(mods))
        for mo in mods:
            out += struct.pack('<BQQ', mo['idx'], mo['bias'], mo['size'])
        for (name, rva), (op, operands, extra, ilen) in sorted(
                self.prog.items(), key=lambda kv: (MODULES[kv[0][0]]['idx'], kv[0][1])):
            blob = bytearray()
            blob.append(MODULES[name]['idx'])
            blob += struct.pack('<H', op)
            blob += struct.pack('<BBB', len(operands),
                                extra if extra is not None else 0, ilen)
            blob += struct.pack('<Q', rva)
            for o in operands:
                blob += encode_operand(o, MODULES[name]['bias'])
            out += bytes(blob)
        with open(os.path.join(self.args.out, 'program.bin'), 'wb') as f:
            f.write(out)
        print(f'  emitted program.bin: {len(self.prog)} insns, {len(out)} bytes')

        meta = dict(
            modules={n: dict(bias=mo['bias'], so=mo['so'], size=mo['size'],
                             idx=mo['idx']) for n, mo in MODULES.items()},
            cases=self.cases,
            entry_ip={c: self.ips[c][0] for c in self.cases},
            seed_ranges=[dict(name=n, addr=a, size=s) for n, a, s in SEED_RANGES],
            epochs={c: EPOCHS[c] for c in self.cases if c in EPOCHS},
            traces={c: trace_path(c) for c in self.cases},
        )
        json.dump(meta, open(os.path.join(self.args.out, 'meta.json'), 'w'), indent=1)
        for case, evs in self.stubs.items():
            json.dump(evs, open(os.path.join(self.args.out, f'stubs_{case}.json'), 'w'))
        seeds = dict(
            (c, [dict(name=n, addr=a, size=s,
                      file=os.path.join('/home/admin/rig/cases', c, 'seeds2', f'{n}.bin'))
                 for n, a, s in SEED_RANGES])
            for c in self.cases)
        json.dump(seeds, open(os.path.join(self.args.out, 'seeds.json'), 'w'), indent=1)
        self.emit_case_bundles()
        print('  emitted meta/stubs/seeds/bundles')

    def emit_case_bundles(self):
        """case_<case>.bin: everything warmvm needs for one run, in one file.

        layout (LE):
          "PVMC" u32, ver=3 u32, entry_ip u64, stop_rec u64, tsc_base u64,
          otp_addr u64, otp_len u32, otp bytes,
          regs[16] u64, xmm[16][16] u8,
          nseeds u32, { addr u64, len u64, bytes } * nseeds,
          nstubs u32, { rec_call u64, rec_ret u64, ret u64, push u8,
                        regs[16] u64, xmm[16][16] u8 } * nstubs,
          nmem u32, { rec_call u64, rec_ret u64, addr u64, value u64 } * nmem"""
        OTP_ADDR = 0x7ffff78b0340
        for c in self.cases:
            regs, xmm = self._record_state(c, 0)
            otp = open(f'/home/admin/rig/cases/{c}/cap/otp.bin', 'rb').read()
            buf = bytearray()
            buf += struct.pack('<IIQQQQI', 0x43564d50, 3, self.ips[c][0],
                               self._stop_rec(c),
                               (EPOCHS[c] << 21) & 0xffffffffffffffff,
                               OTP_ADDR, len(otp))
            buf += otp
            buf += struct.pack('<16Q', *regs)
            buf += xmm
            seeds = []
            for name, addr, size in SEED_RANGES:
                p = os.path.join('/home/admin/rig/cases', c, 'seeds2',
                                 f'{name}.bin')
                data = open(p, 'rb').read()
                if len(data) != size:
                    self.errors.append(
                        f'{c}: seed {name} size {len(data)} != {size}')
                    continue
                seeds.append((addr, data))
            # The last CoreADI RW page is also the first heap page.  A dump
            # made at a shifted heap base otherwise overwrites that page in
            # Memory::seed and produces a plausible but corrupt bundle.
            if len(seeds) == len(SEED_RANGES):
                for right in range(len(seeds)):
                    right_addr, right_data = seeds[right]
                    for left in range(right):
                        left_addr, left_data = seeds[left]
                        start = max(left_addr, right_addr)
                        end = min(left_addr + len(left_data),
                                  right_addr + len(right_data))
                        if start >= end:
                            continue
                        if (left_data[start - left_addr:end - left_addr] !=
                                right_data[start - right_addr:end - right_addr]):
                            self.errors.append(
                                f'{c}: seed overlap {SEED_RANGES[left][0]}/'
                                f'{SEED_RANGES[right][0]} differs at {start:#x}')
            buf += struct.pack('<I', len(seeds))
            for addr, data in seeds:
                buf += struct.pack('<QQ', addr, len(data)) + data
            evs = self.stubs[c]
            buf += struct.pack('<I', len(evs))
            for e in evs:
                buf += struct.pack('<QQQB', e['rec_call'], e['rec_ret'],
                                   e['ret'] or 0, 1 if e['push'] else 0)
                buf += struct.pack('<16Q', *e['regs'])
                buf += bytes.fromhex(e['xmm'])
            changes = self._memdeltas(c)
            buf += struct.pack('<I', len(changes))
            for call, ret, addr, value in changes:
                buf += struct.pack('<QQQQ', call, ret, addr, value)
            p = os.path.join(self.args.out, f'case_{c}.bin')
            with open(p, 'wb') as f:
                f.write(buf)
            print(f'  bundle {c}: {len(buf)} bytes, {len(seeds)} seeds, '
                  f'{len(evs)} stubs, {len(changes)} mem words')


def encode_operand(o, bias):
    """tagged operand -> bytes"""
    k = o['kind']
    if k == 'reg':
        return struct.pack('<BBB', OP_REG, o['idx'], o['size'])
    if k == 'xmm':
        return struct.pack('<BB', OP_XMM, o['idx'])
    if k == 'imm':
        # tag, value, width: the VM masks immediates by width, so a 9-byte
        # form here would shift every following operand by one.
        return struct.pack('<BQB', OP_IMM, o['val'] & 0xffffffffffffffff,
                           o.get('size', 8) & 0xff)
    if k == 'mem':
        disp = o['disp']
        # A base-less operand is either rip-relative or absolute; objdump's
        # linear sweep proved every executed one is rip-relative, so the
        # lifter folded the module RVA into disp.  Add the load bias here:
        # the VM only ever sees absolute addresses.
        if o['base'] == 255 and o['index'] == 255:
            disp += bias
        return struct.pack('<BBBBbq', OP_MEM, o['base'], o['index'],
                           o['scale'], o['size'], disp)
    if k == 'target':
        return struct.pack('<BQ', OP_TARGET,
                           (MODULES[o['module']]['bias'] + o['rva'])
                           & 0xffffffffffffffff)
    if k == 'none':
        return struct.pack('<B', OP_NONE)
    raise ValueError(o)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default='/home/admin/rig/lift')
    ap.add_argument('--cases', default=','.join(DEFAULT_CASES))
    ap.add_argument('--full-dis', default='/home/admin/rig/full_dis.json')
    ap.add_argument('--regen', action='store_true')
    a = ap.parse_args()
    a.cases = a.cases.split(',')
    lift = Lifter(a)
    lift.decode_all()
    if lift.errors:
        print(f'FATAL: {len(lift.errors)} decode errors', file=sys.stderr)
        sys.exit(1)
    lift.validate()
    lift.translate()
    lift.extract_stubs()
    if lift.errors:
        print(f'FATAL: {len(lift.errors)} lift errors', file=sys.stderr)
        for e in lift.errors[:30]:
            print('  ', e, file=sys.stderr)
        sys.exit(1)
    lift.emit()
    if lift.errors:
        print(f'FATAL: {len(lift.errors)} emit errors', file=sys.stderr)
        for e in lift.errors[:30]:
            print('  ', e, file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
