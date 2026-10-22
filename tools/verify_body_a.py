#!/usr/bin/env python3
"""verify_body_a.py -- the full-conveyor check of the sixteen-mixer
body A cascade, on the live-session measurements.

Inputs (all measured, one session unless noted):
  sel25_tape.txt   the selector tape (11 cycles x 16 mixers)
  planter_2500.bin the planter (same session as the selector tape)
  fam{1..4}_zone.bin  the four read zones (load-stable across runs)
  live_prov_out.bin   the CPIM the same-cycle produced

The sixteen mixer formulas (decoded from the block disassembly,
every mask per-mixer):

  lane A (planter +0xD60):  c = planter[sel+0xD60]^PX; byte = ((c*c + zone1[c-0x10]) ^ FX
  lane B (planter +0x1A00): c = planter[sel+0x1A00]^PX; byte = ((c*c + zone2[c-0x2E]) ^ FX
  lane C (planter +0x2460): c3 = planter[sel+0x2460]^PX; byte = ((read - (c3|0x35)) ^ (((read-(c3|0x15))<<3)&0xFF) ^ FX, read = zone3[c3-0x30]
  lane D (planter +0x1390): c4 = planter[sel+0x1390]^PX; byte = ((read - (c4|0xA2)) ^ FX, read = zone4[c4-0x49]

Per-mixer masks (PX, FX):
  m1  A: PX=0x97 FX=0x98   m2  B: PX=0xD8 FX=0xB8   m3  C: FX=0x5F   m4  D: nibble-tail FX=0x6D
  m5  A: PX=0x49 FX=0x85   m6  B: PX=0x75 FX=0x64   m7  C: FX=0x54   m8  D: FX=0x17
  m9  A: PX=0xE5 FX=0x65   m10 B: PX=0xBD FX=0x7C   m11 C: FX=0xE2   m12 D: FX=0x12
  m13 A: PX=0x1E FX=0x4E   m14 B: PX=0x8D FX=0xF2   m15 C: FX=0x70   m16 D: FX=0xBD
m4's tail: byte = (((read-(c4|0xA2))&0xF0) | ((read-(c4|2))&0x0F)) ^ 0x6D.

Zone offsets into the four dumps (dump bases vs read bases):
  zone1: c-0x10   zone2: c-0x2E   zone3: c3-0x30   zone4: c4-0x49

The position ladder: cycle k, mixer j -> depot[row_pos[j] + 0x10*(k-1)],
row_pos = 3,2,1,0,7,6,5,4,B,A,9,8,F,E,D,C; depot[p] == cpim[0x18+p].

Usage: python3 verify_body_a.py [cycles]
"""
import sys

STORES = [0xE6B9D, 0xE6BE2, 0xE6C47, 0xE6CA0, 0xE6D06, 0xE6D3E, 0xE6D8B,
          0xE6DC1, 0xE6E28, 0xE6E5F, 0xE6EAA, 0xE6EE4, 0xE6F42, 0xE6F73,
          0xE6FC4, 0xE7023]
# (lane, planter_xor, final_xor)
MIX = {0xE6B9D: ('A', 0x97, 0x98), 0xE6BE2: ('B', 0xD8, 0xB8),
       0xE6C47: ('C', 0xCF, 0x5F), 0xE6CA0: ('D', 0x05, 0x6D),
       0xE6D06: ('A', 0x49, 0x85), 0xE6D3E: ('B', 0x75, 0x64),
       0xE6D8B: ('C', 0x7A, 0x54), 0xE6DC1: ('D', 0x07, 0x17),
       0xE6E28: ('A', 0xE5, 0x65), 0xE6E5F: ('B', 0xBD, 0x7C),
       0xE6EAA: ('C', 0xD6, 0xE2), 0xE6EE4: ('D', 0xDD, 0x12),
       0xE6F42: ('A', 0x1E, 0x4E), 0xE6F73: ('B', 0x8D, 0xF2),
       0xE6FC4: ('C', 0x28, 0x70), 0xE7023: ('D', 0x48, 0xBD)}
PL_OFF = {'A': 0xD60, 'B': 0x1A00, 'C': 0x2460, 'D': 0x1390}
Z_OFF = {'A': 0x10, 'B': 0x2E, 'C': 0x30, 'D': 0x49}
ROW_POS = [3, 2, 1, 0, 7, 6, 5, 4, 0xB, 0xA, 9, 8, 0xF, 0xE, 0xD, 0xC]


def load():
    pl = open('/opt/data/adi-re/planter_2500.bin', 'rb').read()
    zones = {L: open(f'/opt/data/adi-re/fam{["A","B","C","D"].index(L)+1}_zone.bin', 'rb').read()
             for L in 'ABCD'}
    cpim = open('/opt/data/adi-re/live_prov_out.bin', 'rb').read()
    rows = []
    for ln in open('/opt/data/adi-re/sel25_tape.txt').read().splitlines():
        d = {}
        for p in ln.split()[1:]:
            k, v = p.split('=')
            d[k] = int(v, 16)
        rows.append(d)
    return pl, zones, cpim, rows


def mixer_byte(store, sel, pl, zones):
    lane, px, fx = MIX[store]
    if lane in ('A', 'B'):
        c = pl[sel + PL_OFF[lane]] ^ px
        mul = (c * c) & 0xFF
        z = zones[lane]
        off = c - Z_OFF[lane]
        if not 0 <= off < len(z):
            return None
        return ((mul + z[off]) & 0xFF) ^ fx
    if lane == 'C':
        if sel + PL_OFF[lane] >= len(pl):
            return None  # planter window past the dump edge
        c3 = pl[sel + PL_OFF[lane]] ^ px
        z = zones[lane]
        off = c3 - Z_OFF[lane]
        if not 0 <= off < len(z):
            return None
        read = z[off]
        return (((read - (c3 | 0x35)) & 0xFF) ^ ((((read - (c3 | 0x15)) & 0xFF) << 3) & 0xFF) ^ fx) & 0xFF
    # lane D: the tape's "sel" is ALREADY c4 (the BP sits on the zone read,
    # after the planter xor) -- no planter step.
    c4 = sel
    z = zones[lane]
    off = c4 - Z_OFF[lane]
    if not 0 <= off < len(z):
        return None
    read = z[off]
    if store == 0xE6CA0:  # the nibble tail (m4 only)
        return ((((read - (c4 | 0xA2)) & 0xF0) | ((read - (c4 | 2)) & 0x0F)) ^ fx) & 0xFF
    return (((read - (c4 | 0xA2)) & 0xFF) ^ fx) & 0xFF


def main():
    n_cycles = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    pl, zones, cpim, rows = load()
    cycles = [rows[i:i + 16] for i in range(0, len(rows), 16)]
    print(f"selector rows: {len(rows)} ({len(cycles)} cycles)")
    ok = tot = skipped = 0
    bad = []
    for k, cyc in enumerate(cycles[:n_cycles], 1):
        for j, d in enumerate(cyc):
            store = d['store']
            sel = d['sel']
            b = mixer_byte(store, sel, pl, zones)
            pos = ROW_POS[j] + 0x10 * (k - 1)
            actual = cpim[0x18 + pos]
            if b is None:
                skipped += 1
                continue
            tot += 1
            if b == actual:
                ok += 1
            else:
                bad.append((k, j + 1, hex(store), hex(sel), hex(b), hex(actual), hex(pos)))
    print(f"BODY A CHECK: {ok}/{tot} (skipped {skipped})")
    if bad:
        print("mismatches (first 8):")
        for m in bad[:8]:
            print(f"  cycle {m[0]} mixer {m[1]} store {m[2]} sel={m[3]}: pred {m[4]} vs cpim {m[5]} (depot+{m[6]})")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
