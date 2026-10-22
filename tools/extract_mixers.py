#!/usr/bin/env python3
"""Extract the depot mixer constants from libCoreADI.so (the Android
ADI engine), the CPIM body A + digest depot filler.

One linear block at RVA +0xe6b41..(+~0xe7100): per byte, a session-key
byte selects a planter row through an XOR mask, then a per-mixer
arithmetic chain (mul / add-masked-read / xor, shapes vary per mixer)
lands the byte in the depot.

The tool walks the block ONCE and emits EVERY byte-store with its
constants as far as the pattern decodes automatically:

  key_sel   which byte of the cycle key feeds the planter select
  key_xor   the select mask
  planter   the [planter + sel + OFF] row window read
  planter_xor the mask on the planter byte (any destination reg)
  arith     the arithmetic chain between the planter byte and the store
  read_disp the masked history read ([X + c + DISP]), when present
  final_xor the last mask before the store

Usage:
  python3 extract_mixers.py <libCoreADI.so> [--json out.json]
"""
import sys
import json
import capstone

BLOCK_START = 0xE6B41
BLOCK_END = 0xE70F1

SELECT_MN = ('movzx', 'mov', 'shr', 'xor')


def extract(so, json_out=None):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    insns = list(md.disasm(so[BLOCK_START:BLOCK_END], BLOCK_START))
    mixers = []
    cur = None
    for insn in insns:
        m, o = insn.mnemonic, insn.op_str
        # Новый микшер: селектор ключевого байта (movzx eax,bl/bh или
        # mov eax,ebx перед shr) ИЛИ xor ebx (первый).
        if m == 'xor' and (o.startswith('ebx, ') or o.startswith('rbx, ')):
            cur = {'start_rva': insn.address}
            continue
        if cur is None and m == 'movzx' and o.startswith('eax,'):
            cur = {'start_rva': insn.address}
        if cur is None:
            continue
        if m == 'movzx' and o.startswith('eax,') and insn.address != cur['start_rva']:
            # второй селектор без store между ними -- новый микшер (после мусора)
            if 'store_rva' in cur:
                mixers.append(cur)
            cur = {'start_rva': insn.address}
        if m == 'mov' and o.startswith('eax, ebx') and 'store_rva' in cur:
            mixers.append(cur)
            cur = {'start_rva': insn.address}
        addr, _ = insn.address, None
        if m == 'movzx' and o.startswith('eax,'):
            cur.setdefault('key_sel', []).append((hex(addr), o))
        elif m == 'xor' and o.startswith('rax,') and 'key_xor' not in cur and 'key_sel' in cur:
            cur['key_xor'] = (hex(addr), o)
        elif m == 'movzx' and 'byte ptr [rcx + rax' in o:
            cur.setdefault('planter', []).append((hex(addr), o))
        elif m == 'xor' and ('rcx,' in o or 'rdx,' in o or 'rax,' in o) and 'planter' in cur and 'planter_xor' not in cur:
            cur['planter_xor'] = (hex(addr), o)
        elif m == 'mul':
            cur.setdefault('arith', []).append((hex(addr), 'mul ' + o))
        elif m == 'add' and o.startswith('al, byte ptr ['):
            cur['read_disp'] = (hex(addr), o)
            cur.setdefault('arith', []).append((hex(addr), o))
        elif m == 'xor' and o.startswith('al,') and 'arith' in cur:
            cur.setdefault('final_xor', []).append((hex(addr), o))
        elif m in ('or', 'sub', 'shl', 'and', 'lea', 'neg') and 'key_sel' in cur:
            # арифметический хвост произвольной формы
            if m in ('sub', 'or', 'shl', 'and') and (o.startswith('al,') or o.startswith('cl,') or o.startswith('dl,') or o.startswith('bl,')):
                cur.setdefault('arith', []).append((hex(addr), m + ' ' + o))
        elif m == 'mov' and o.startswith('byte ptr ['):
            cur['store_rva'] = hex(addr)
            cur['store'] = o
            mixers.append(cur)
            cur = None
    result = {
        'block': [hex(BLOCK_START), hex(BLOCK_END)],
        'mixers': [{k: v for k, v in mm.items()} for mm in mixers],
        'count': len(mixers),
    }
    if json_out:
        with open(json_out, 'w') as f:
            json.dump(result, f, indent=1)
    return result


def fmt(v):
    if isinstance(v, list):
        return '; '.join(f"{a}:{s}" for a, s in v)
    if isinstance(v, tuple):
        return f"{v[0]}:{v[1]}"
    return str(v)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    so = open(sys.argv[1], 'rb').read()
    jo = None
    if '--json' in sys.argv:
        jo = sys.argv[sys.argv.index('--json') + 1]
    r = extract(so, jo)
    print(f"block {r['block'][0]}..{r['block'][1]}: {r['count']} byte-stores")
    for mm in r['mixers']:
        print(f"--- store @ {mm['store_rva']}: {mm['store']}")
        for k in ('key_sel', 'key_xor', 'planter', 'planter_xor', 'arith', 'read_disp', 'final_xor'):
            if k in mm:
                print(f"    {k}: {fmt(mm[k])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
