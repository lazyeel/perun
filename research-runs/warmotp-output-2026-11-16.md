# Track A step 2 — OTP payload output boundary, decoded serializer

Date: 2026-11-16 · Branch: `rnd/phase1-standalone-anisette`.
Privacy: only hashes/RVAs/hex words of public test vectors; raw captures/traces local (0700).

## Corpus (deterministic, native-matching, two epochs)

| epoch | runs | OTP (full capture hash) | MID | trace records |
|---|---|---|---|---|
| 1794862800 | tG, tH | `f3fd95eb831438fa…` | `93ef3da7102f969d…` | 622,386 each |
| 1794864600 | tI, tJ | `cf9da8e18d38f5f5…` | `93ef3da7102f969d…` | 622,499 each |

Each pair is byte-identical in instruction stream and XSAVE blobs, and each OTP
equals the corresponding plain frozen run. Flow length depends slightly on the
epoch and on the bionic rwlock bookkeeping (TLS tid), but the output is stable.

## Hardware watchpoint instrumentation

`tools/adi_freeze.c` gained `--otp-buf=ADDR` and per-thread x86 debug registers
(DR0–DR3 with `RW=write, LEN=8`): DR3 watches the `otp*` pointer variable
(`rcx` at entry — the harness passes `&otp`, a pointer-to-pointer); when the
engine allocates the buffer the address is logged; with `--no-aslr` the heap
address is stable (`0x7ffff78b0340`), so `--otp-buf` arms DR0–2 on the real
payload (`buf+8 .. buf+24`) from entry. Every watched store is recorded as
`kind=5` in the trace. Pitfall: the engine *fills the buffer before storing the
pointer into `*otp`*, so a watch installed only after the pointer trap misses
the payload writes.

Two store groups were located (load biases from the `[maps]` dump of tI;
libCoreADI bias `0x7ffff7679000`):

1. **Payload serialization**: libCoreADI RVA `0x139931..0x139aaf` — 16
   byte stores into `buf+0..buf+15` (8 of them produce DR6 hits because of
   8-byte watch granularity), interleaved with byte extraction/XOR.
2. **Trailer**: libCoreADI RVA `0xcca65..0xcca93` — writes `00 00 00 04`
   (dword indices 0x19/0x1a/0x1b, plus the length dword) at `buf+16..+19`.

A dump of the buffer at the harness capture (tM) confirms it equals the
captured OTP file byte-for-byte:
`buf+0 = 15faab1c d791cf7e` → payload `7e cf 91 d7 1c ab fa 15`,
`buf+8 = 52345869 3854ce72` → payload `72 ce 54 38 69 58 34 52`.

## Decoded serializer (verified against the captured payload)

At the serialization point four 32-bit words hold the payload raw material:
`r15d`, `r13d`, `r9d` and `ebx` (the last computed at RVA `0x1399b4..0x1399bd`:
`ebx = [rbp-0x2f0] ^ ecx ^ 0x3804687c`). Each output byte is one byte of one
word XOR a constant:

```text
p[0]  = (r15 >> 24) ^ 0x4a      p[8]  = (r9  >> 24) ^ 0xf2
p[1]  = (r15 >> 16) ^ 0x29      p[9]  = (r9  >> 8)  ^ 0xe3
p[2]  = (r15 >> 8)  ^ 0x1a      p[10] = (r9  >> 16) ^ 0x29
p[3]  = (r15)       ^ 0xfd      p[11] = (r9)        ^ 0x5e
p[4]  = (r13 >> 24) ^ 0x74      p[12] = (ebx >> 24) ^ 0x70
p[5]  = (r13 >> 16) ^ 0x64      p[13] = (ebx >> 16) ^ 0x04
p[6]  = (r13 >> 8)  ^ 0xf6      p[14] = (ebx >> 8)  ^ 0x70
p[7]  = (r13)       ^ 0xf4      p[15] = (ebx)       ^ 0x3e
```

All 16 equations were verified by substituting the register values read from
the trace at RVA `0x1399b4` and comparing with the captured payload.

The four words at that point, per epoch (record 619092 in both flows):

| epoch | r15d | r13d | r9d |
|---|---|---|---|
| 1794862800 | `34e68b2a` | `68cf0ce1` | `80e7b766` |
| 1794864600 | `e3e03242` | `66fcc1d7` | `af412741` |

`ebx` is derived from `ecx` at RVA `0x1399b4` (`ecx = 0x51e9cc35` for epoch
2800; `ebx = 0x195c446c`).

## Remaining lift targets (measured, not guessed)

- Time enters at libstoreservicescore RVA `0x1c77a2` (first ip-stream
  divergence between epochs 2800/4600, record 13135): a computed-goto
  dispatcher `jmp *%rax` at RVA `0x1c779d`, index derived from the frozen
  realtime — the epoch-dependent branch into the obfuscated generator.
- The hottest loop (384 iterations) is libCoreADI RVA `0x12e53f..0x12e5a7`:
  a byte-wise mixer with table lookup and constants (`0x751ff76a`,
  `0x2e6b1e92`, `0x17358f49`, `0x3d69e0e8`, `0xd73b2fac`, `0xa52884a`,
  `0x5a263127`, `0xafcdba41`, …) — the main arithmetic to port.
- Target for `perun-adi-core`: `fn warm_otp(state, epoch) -> [u8;16]`
  computing r15d/r13d/r9d/ebx then applying the serializer above; gate =
  byte-exact output on ≥3 states × ≥3 epochs vs native.
