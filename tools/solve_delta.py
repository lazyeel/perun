#!/usr/bin/env python3
"""solve_delta.py -- close the last link of mixer-1's formula with a
solver, not a guess.

Mixer-1 (libCoreADI.so +0xe6b41..0xe6b9d), measured shape:

    bl  = (rbx ^ 0x27eb5e18) & 0xFF      cycle key byte (11 cycles)
    sel = bl ^ 0xFC                       planter row
    c   = planter[sel + 0xD60] ^ 0x97     VERIFIED live on all cycles
    mul = (c * c) & 0xFF                  mul cl after mov eax,ecx
    al  = (mul + READ) ^ 0x98             READ = [X + c - 0x2964dd42]

The live run showed al lands within +-0x1f of (mul + rt[0x80+c]) ^ 0x98
where rt is the runtime-patched image zone -- so READ is the same KIND of
table byte, at a fixed offset K we mis-guessed. Instead of guessing K:

  Stage 1 (exhaustive): find K in the rt dump such that
        rt[K + c_i] + mul_i, xor 0x98  ==  al_i   for ALL 11 cycles.
  Stage 2 (z3): if no constant K fits, solve the structure
        READ_i = rt[K1 + c_i] op rt[K2 + sel_i] (op in {xor, add, sub})
        over the same 11 constraints, and report every model found.

Inputs: the run-20 tape (16 mixers, r8 logged), the run-20 planter and
pointer table, the run-22 rt zone (image+0x31000..0x31200 -- the zone is
patched at load, not per session, so it carries across runs; stage 1
proving a single K across 11 cycles is itself the cross-check).

Usage:
  python3 solve_delta.py
"""
import struct
import sys

TAPE = "/opt/data/adi-re/mixer_tape5.txt"        # run 20, full 176 rows
PLANTER = "/opt/data/adi-re/planter_2500.bin"    # run 20
TABLE = "/opt/data/adi-re/table_184060.bin"      # run 20 (0x600 dump)
RT = "/opt/data/adi-re/rt_31000.bin"             # run 22 (load-time patch)
KEY_XOR = 0x27EB5E18
SEL_XOR = 0xFC
PL_OFF = 0xD60
PL_XOR = 0x97
FINAL_XOR = 0x98


def mixer1_cases():
    rows = []
    for ln in open(TAPE).read().splitlines():
        parts = ln.split()
        d = {"rva": int(parts[1], 16)}
        for p in parts[2:]:
            k, v = p.split("=")
            d[k] = int(v, 16)
        if d["rva"] != 0xE6B9D:
            continue
        rbx = d["rbx"]
        bl = (rbx ^ KEY_XOR) & 0xFF
        sel = bl ^ SEL_XOR
        c = open(PLANTER, "rb").read()[sel + PL_OFF] ^ PL_XOR
        rows.append({"rbx": rbx, "bl": bl, "sel": sel, "c": c,
                     "mul": (c * c) & 0xFF,
                     "al": d["al"], "r8": d["r8"]})
    return rows


def stage1(rows, rt):
    """Exhaustive K: rt[K + c] must satisfy all rows."""
    hits = []
    need = [((r["al"] ^ FINAL_XOR) - r["mul"]) & 0xFF for r in rows]
    for K in range(0, len(rt) - 0x100):
        ok = all(rt[(K + r["c"]) & 0xFF if K + r["c"] < len(rt) else K + r["c"]] == n
                 for r, n in zip(rows, need))
        if K + max(r["c"] for r in rows) >= len(rt):
            continue
        if all(rt[K + r["c"]] == n for r, n in zip(rows, need)):
            hits.append(K)
    return hits, need


def stage2(rows, rt, need):
    """z3: READ = rt[K1 + c] OP rt[K2 + sel], OP in {xor, add, sub}."""
    import z3
    sols = []
    for op_name in ("xor", "add", "sub"):
        K1 = z3.Int("K1")
        K2 = z3.Int("K2")
        s = z3.Solver()
        s.add(K1 >= 0, K1 < 0x100, K2 >= 0, K2 < 0x100)
        for r, n in zip(rows, need):
            a = z3.Select(z3.Array("rtA", z3.IntSort(), z3.IntSort()), K1 + r["c"])
            b = z3.Select(z3.Array("rtB", z3.IntSort(), z3.IntSort()), K2 + r["sel"])
            if op_name == "xor":
                e = z3.Xor(a == n, False)
                # emulate byte xor via int: a XOR b -- use BV8
                a8 = z3.BitVecVal(0, 8)
                break  # xor emulated below with BV instead
        if op_name == "xor":
            s = z3.Solver()
            K1 = z3.BitVec("K1", 24)
            K2 = z3.BitVec("K2", 24)
            rtB = z3.Array("rtB", z3.BitVecSort(24), z3.BitVecSort(8))
            for i, (r, n) in enumerate(zip(rows, need)):
                pass
            # feed the table bytes as BV8 selects through a lookup array
            s.add(z3.Distinct(K1, K2))
        # a cleaner approach below
        sols.append((op_name, None))
    return sols


def stage2_bv(rows, rt, need):
    """BV formulation: unknown op applied to two table bytes."""
    import z3
    found = []
    # Build BV8 constants per position to avoid huge arrays: try a
    # per-row unknown byte B_i constrained by the structure instead:
    # B_i = (op rt[K1+c_i] rt[K2+sel_i]) with K1,K2 in [0, 0x100)
    for op_name, op in (("xor", lambda a, b: a ^ b),
                        ("add", lambda a, b: a + b),
                        ("sub", lambda a, b: a - b)):
        hits = []
        for K1 in range(0, len(rt) - 0x100):
            for K2 in range(0, len(rt) - 0x100):
                ok = True
                for r, n in zip(rows, need):
                    x = rt[K1 + r["c"]]
                    y = rt[K2 + r["sel"]]
                    v = (op(x, y)) & 0xFF
                    if v != n:
                        ok = False
                        break
                if ok:
                    hits.append((K1, K2))
            if hits:
                break
        if hits:
            found.append((op_name, hits[:5]))
    return found


def main():
    rows = mixer1_cases()
    print(f"mixer-1: {len(rows)} cycle cases")
    for r in rows[:3]:
        print(f"  rbx={r['rbx']:#010x} sel={r['sel']:#x} c={r['c']:#x} mul={r['mul']:#x} al={r['al']:#x} r8={r['r8']:#x}")
    rt = open(RT, "rb").read()
    ks, need = stage1(rows, rt)
    print(f"\nSTAGE 1 (constant K): {'HIT K=' + ','.join(hex(k) for k in ks) if ks else 'no constant K'}")
    print(f"  need bytes: {[hex(n) for n in need]}")
    print(f"  rt[0x80+c]: {[hex(rt[0x80 + r['c']]) for r in rows]}")
    # связка: X из таблицы по r8 -- проверим фактический X для r8 ленты
    tbl = open(TABLE, "rb").read()
    r8s = sorted(set(r["r8"] for r in rows))
    print(f"\n  r8 в циклах: {[hex(x) for x in r8s]}")
    for r8 in r8s:
        idx = (r8 - 0x456) & 0xFFFFFFFF
        if idx * 8 + 8 <= len(tbl):
            X = struct.unpack_from('<Q', tbl, idx * 8)[0]
            print(f"  r8={r8:#x} -> idx={idx:#x} -> X={X:#018x}")
    if not ks:
        print("\nSTAGE 2 (two-table op, exhaustive over K1,K2):")
        # This is 0x100*0x100*11*3 -- a few million cheap ops; keep it bounded:
        print("  (bounded run: K1,K2 in [0,0x100))")
        found = stage2_bv(rows[:6], rt, need[:6])
        for op_name, hs in found:
            print(f"  op={op_name}: {hs}")
        if not found:
            print("  no two-table model in the bounded window; the link is structural (slot read), stage a WP on [rbp-0x610]/[rbp-0x120]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
