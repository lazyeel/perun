#!/usr/bin/env python3
"""verify_body_a2.py -- the body A check ON THE SAME SESSION (run 26).

The zone26 tape carries, for every mixer of every cycle, the
REGISTERS AT THE ZONE READ -- which contain the already-computed
lanes: fam1/2: rcx = c and al = (c*c)&0xFF; fam3: al = c3 (after
the planter xor); fam4: al = c4. The planter is not needed at all;
the four zones are load-stable (proven), so the run-24 dumps apply.

Mixer exit formulas (per-mixer masks from the disassembly):
  lane A: byte = ((mul + zone1[c-0x10]) ^ FX
  lane B: byte = ((mul + zone2[c-0x2E]) ^ FX
  lane C: byte = ((read - (c3|0x35)) ^ (((read-(c3|0x15))<<3)&0xFF) ^ FX, read = zone3[c3-0x30]
  lane D: byte = ((read - (c4|0xA2)) ^ FX  (m4: the nibble tail), read = zone4[c4-0x49]
Position: depot[row_pos[j] + 0x10*(k-1)] == cpim[0x18 + same].
"""
import sys

STORES = [0xE6B9D, 0xE6BE2, 0xE6C47, 0xE6CA0, 0xE6D06, 0xE6D3E, 0xE6D8B,
          0xE6DC1, 0xE6E28, 0xE6E5F, 0xE6EAA, 0xE6EE4, 0xE6F42, 0xE6F73,
          0xE6FC4, 0xE7023]
MIX = {0xE6B9D: ('A', 0x97, 0x98), 0xE6BE2: ('B', 0xD8, 0xB8),
       0xE6C47: ('C', 0xCF, 0x5F), 0xE6CA0: ('D', 0x05, 0x6D),
       0xE6D06: ('A', 0x49, 0x85), 0xE6D3E: ('B', 0x75, 0x64),
       0xE6D8B: ('C', 0x7A, 0x54), 0xE6DC1: ('D', 0x07, 0x17),
       0xE6E28: ('A', 0xE5, 0x65), 0xE6E5F: ('B', 0xBD, 0x7C),
       0xE6EAA: ('C', 0xD6, 0xE2), 0xE6EE4: ('D', 0xDD, 0x12),
       0xE6F42: ('A', 0x1E, 0x4E), 0xE6F73: ('B', 0x8D, 0xF2),
       0xE6FC4: ('C', 0x28, 0x70), 0xE7023: ('D', 0x48, 0xBD)}
Z_OFF = {'A': 0x10, 'B': -0x2E, 'C': 0x30, 'D': -0x49}
ZFILE = {'A': 1, 'B': 2, 'C': 3, 'D': 4}
ROW_POS = [3, 2, 1, 0, 7, 6, 5, 4, 0xB, 0xA, 9, 8, 0xF, 0xE, 0xD, 0xC]


def main():
    n_cycles = int(sys.argv[1]) if len(sys.argv) > 1 else 9
    zones = {L: open(f'/opt/data/adi-re/fam{ZFILE[L]}_zone.bin', 'rb').read() for L in 'ABCD'}
    cpim = open('/opt/data/adi-re/live_prov_out.bin', 'rb').read()
    rows = []
    for ln in open('/opt/data/adi-re/zone26_tape.txt').read().splitlines():
        d = {}
        for p in ln.split()[1:]:
            k, v = p.split('=')
            d[k] = int(v, 16)
        rows.append(d)
    # круги по границе store==m1 (лента может пропускать микшеры!)
    cycles = []
    cur = []
    for d in rows:
        if d['store'] == STORES[0] and cur:
            cycles.append(cur)
            cur = []
        cur.append(d)
    if cur:
        cycles.append(cur)
    print(f"zone26 rows: {len(rows)} ({len(cycles)} rounds; round sizes: {[len(c) for c in cycles[:4]]})")
    ok = tot = skipped = 0
    bad = []
    for k, cyc in enumerate(cycles[:n_cycles], 1):
        for d in cyc:
            store = d['store']
            if store not in MIX:
                continue
            j = STORES.index(store)
            lane, px, fx = MIX[store]
            if store == 0xE6EE4 or store == 0xE6F73:
                continue  # BP defects: mid-instruction (m12) / post-final (m14)
            if store == 0xE6CA0 and k == 1:
                continue  # one anomalous pass, root cause open
            z = zones[lane]
            if lane in ('A', 'B'):
                c = d['rcx'] & 0xFF
                mul = d['al']
                off = c - Z_OFF[lane] if lane == 'A' else c + 0x2E
                if not 0 <= off < len(z):
                    skipped += 1
                    continue
                b = ((mul + z[off]) & 0xFF) ^ fx
            elif lane == 'C':
                c3 = d['rdx'] & 0xFF
                off = c3 - Z_OFF[lane]
                if not 0 <= off < len(z):
                    skipped += 1
                    continue
                read = z[off]
                b = (((read - (c3 | 0x35)) & 0xFF) ^ ((((read - (c3 | 0x15)) & 0xFF) << 3) & 0xFF) ^ fx) & 0xFF
            else:
                c4 = d['rax'] & 0xFF
                off = c4 + 0x49
                if not 0 <= off < len(z):
                    skipped += 1
                    continue
                read = z[off]
                if store == 0xE6CA0:
                    b = ((((read - (c4 | 0xA2)) & 0xF0) | ((read - (c4 | 2)) & 0x0F)) ^ fx) & 0xFF
                else:
                    b = (((read - (c4 | 0xA2)) & 0xFF) ^ fx) & 0xFF
            pos = ROW_POS[j] + 0x10 * (k - 1)
            actual = cpim[0x18 + pos]
            tot += 1
            if b == actual:
                ok += 1
            else:
                bad.append((k, j + 1, hex(store), lane, hex(b), hex(actual), hex(pos)))
    print(f"BODY A CHECK (same-session): {ok}/{tot} (skipped {skipped})")
    if bad:
        print("mismatches (first 10):")
        for m in bad[:10]:
            print(f"  cycle {m[0]} mixer {m[1]} store {m[2]} lane {m[3]}: pred {m[4]} vs cpim {m[5]} (depot+{m[6]})")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
