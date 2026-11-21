#!/usr/bin/env python3
"""The four fixed masks of the planter block coupling, and their algebra.

Measured 2026-11-21 on the Android x86_64 oracle (`libCoreADI.so`, offline SPIM
harness) by replaying `gcore` checkpoints taken at RVA 0xDD511 in Unicorn:

    S[b][q] ^ S[b][q]|x=0  =  M_{q mod 4}( x[b-1][q ^ 3] )

where `x = arena[b-1]` and `M_r` are the four GF(2)-linear byte maps below.
They are independent of the block `b`, of the lineage (A1 and C give the same
four) and of the rest of the arena; only the affine constant of the coupling
varies with context.

`M_r` is written the way the sweep produced it: the column

    MASKS[r][k] = M_r(1 << k)

for k = 0..7, so `M_r(v) = XOR_{k : bit k of v} MASKS[r][k]`.

No captured payload bytes appear in this file: the maps are structure measured
from the oracle, and the raw captures stay local.

Run:  python3 tools/planter_masks.py
Then: cargo test -p perun-adi-core --lib planter   (the same maps, pinned in Rust)
"""

#: The four coupling masks, by `q mod 4`, as the eight columns of the matrix.
MASKS = {
    0: (0xCF, 0x66, 0x65, 0xEE, 0x7C, 0xEC, 0x9C, 0xB9),
    1: (0xC1, 0xEE, 0x7B, 0xE6, 0x79, 0x29, 0xB5, 0x10),
    2: (0x3B, 0x29, 0x45, 0x6F, 0x48, 0x5B, 0x64, 0xA9),
    3: (0x9F, 0xDD, 0x71, 0x88, 0x89, 0x75, 0x68, 0xD5),
}


def apply_mask(r: int, value: int) -> int:
    """Evaluate `M_r` on one byte."""
    out = 0
    for k in range(8):
        if value >> k & 1:
            out ^= MASKS[r][k]
    return out


def rank_of(cols) -> int:
    """GF(2) rank of eight byte-columns (row space of the 8x8 bit matrix)."""
    pivots = []
    for v in cols:
        x = v
        for p in pivots:
            x = min(x, x ^ p)
        if x:
            pivots.append(x)
    return len(pivots)


def sanity() -> None:
    for r in sorted(MASKS):
        cols = MASKS[r]
        rank = rank_of(cols)
        img = [apply_mask(r, v) for v in range(256)]
        print(
            "  mask %d  rank=%d  bijective=%s  fixed_points=%d"
            % (r, rank, len(set(img)) == 256, sum(1 for v in range(256) if img[v] == v))
        )


if __name__ == "__main__":
    print("planter block-coupling masks M_{q mod 4}:")
    sanity()
