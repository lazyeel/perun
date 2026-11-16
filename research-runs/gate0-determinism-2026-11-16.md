# Gate 0 — warm-path determinism and entropy attribution

Date: 2026-11-16 · Branch: `rnd/phase1-standalone-anisette` · Tool: `tools/adi_freeze.c`
Rig: local NixOS x86_64 (Apple Music 4.9.6 libs, Bionic sysroot from `x86_64-21_r05`, NDK r27c).
Raw captures remain local under `/home/admin/rig/cases` (0700); this report carries only
sizes, hashes, counters, and call counts.

## Verdict

**Gate 0 acceptance met for the warm OTP path.** With the full freeze active
(getrandom + `/dev/urandom` + AT_RANDOM + vDSO-disabled + CLOCK_REALTIME frozen),
five consecutive replays (N=5) over the same provisioned state produce byte-identical
outputs:

| run | frozen epoch | MID sha256[0:16] | OTP sha256[0:16] |
|---|---|---|---|
| vfix1 | 1794862800 | `93ef3da7102f969d` | `f3fd95eb831438fa` |
| vfix2 | 1794862800 | `93ef3da7102f969d` | `f3fd95eb831438fa` |
| vfix3 (+70 s real time) | 1794862800 | `93ef3da7102f969d` | `f3fd95eb831438fa` |
| vfix4 | 1794862800 | `93ef3da7102f969d` | `f3fd95eb831438fa` |
| vfix5 | 1794862800 | `93ef3da7102f969d` | `f3fd95eb831438fa` |
| vfix-epoch2 | 1794864600 | `93ef3da7102f969d` | `cf9da8e18d38f5f5` |

State file unchanged in every run (sha256 `99147e4d6e461dcb…`, 617 B, before == after).

## Attribution (each line = a controlled differential)

1. **MID (60 B) = f(state) only.** Identical across all nine frozen/unfrozen runs,
   both epochs, repeat probes (warm1: primary + 4 probes all identical).
2. **OTP (28 B) = f(state, CLOCK_REALTIME).** Frozen-epoch differential changes OTP
   and not MID. Unfrozen probes put the quantum at ~60 s (t+1 s same, t+31 s same,
   t+62 s changed → consistent with a 60 s bucket, NOT floor(t/30)).
3. **Entropy does not feed the warm OTP.** `--no-rng` bisect (real urandom, real
   AT_RANDOM) leaves MID and OTP identical to full-freeze runs in the same window.
   The engine's warm-path entropy reads — urandom 40 B, AT_RANDOM 16 B — are therefore
   dead inputs for OTP (seed hardening / unrelated init).
4. **Time enters through the vDSO.** With vDSO live (bug below), clock syscalls are
   0 and OTP followed real time between run groups. With vDSO killed, the engine
   surfaces `clock_gettime`×2 + `gettimeofday`×3 and OTP locks to the frozen epoch.
   No `time(2)` calls, no monotonic reads in the warm path.
5. **Warm path never calls getrandom.** A 32 B `getrandom` hit appears only when the
   run degenerates into provisioning.

## Instrument bugs found and fixed while getting here (all in `tools/adi_freeze.c`)

1. **fd-table leak poisoned unrelated reads.** `/dev/urandom` fds were tracked at
   open but never forgotten at `close(2)`; the next `open(2)` reused the number and
   the freezer's deterministic fill was applied to an innocent buffer — the engine's
   own 269 B `adi.pb` header read was being overwritten with 0xA5, which is why every
   frozen run collapsed into `-45061` reprovisioning. Fix: close/dup/dup2/dup3
   tracking (`forget_urandom_fd`, `close_fd` per process). Post-fix counter for the
   same run: urandom 1 hit / 40 B instead of the bogus 2 / 657 B.
2. **vDSO patch never fired (silent).** The auxv scan searched for TWO consecutive
   NULL words to find the envp terminator, but with a non-empty environment the
   terminator is a SINGLE NULL followed directly by the first auxv entry; the scan
   ran off into stack padding and reported success optimistically. Fix: walk
   argc → argv NULL → envp NULL → auxv pairs, and **verify the zero-write by reading
   it back**; the report now says `patched` / `patch-failed` / `auxv-scan-failed`
   instead of an unconditional `disabled`. Rule reinforced: an unverified patch is
   not a controlled source.

## Path-binding of the provisioned state (new open question for Track B)

The same `adi.pb` bytes are accepted (`GetLoginCode=0`) in the directory where
provisioning happened and rejected (`-45061` → reprovisioning) after a byte-identical
copy to a different directory — while a state freshly provisioned in that other
directory is accepted there. The engine binds state validity to the **absolute
provisioning path** handed to `SetProvisioningPath` (realpath). Consequences:

- Every differential replay must run in the provisioning directory (or be
  re-provisioned there); `tools/run_otp_case.sh` does per-case directories.
- Track B (state format lift) must recover this binding: either the state embeds a
  MAC over the path, or GetLoginCode recomputes one from path + state.

## Measured engine call profile (warm path, one run, vDSO killed)

`clock_gettime` 2 · `gettimeofday` 3 · `time` 0 · `getpid` 0 · `gettid` 8 ·
`getrandom` 0 (0 B) · urandom reads 1 (40 B) · AT_RANDOM 16 B.
State reads: header 269 B of 617 B (full read only at provisioning).
