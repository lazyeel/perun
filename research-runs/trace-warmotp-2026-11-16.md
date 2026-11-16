# Track A step 1 — whole-function batch trace of the warm OTPRequest

Date: 2026-11-16 · Branch: `rnd/phase1-standalone-anisette` · Tools: `tools/adi_freeze.c`
(trace mode), `tools/step_trace_defuse.py` (trace parser/differ).
Privacy: raw traces and captures stay local under `/home/admin/rig/cases` (0700);
this report carries only sizes, hashes, RVAs, opcodes and counters.

## Milestone

**A traced warm-OTP run now reproduces the plain frozen OTP byte-for-byte and is
deterministic across runs.** Two independent traced runs (tG, tH: `--epoch=1794862800
--no-aslr`, trace of `qi864985u0` at libstoreservicescore RVA `0x1c53c0`) produced

- OTP payload bytes identical to the plain frozen runs (`7e cf 91 d7 1c ab fa 15
  72 ce 54 38 69 58 34 52` = sha256 head `f3fd95eb…`),
- identical instruction streams (622,386 records = 622,384 steps + entry +
  returned; 612,427,824 B per trace file),
- identical XSAVE blobs (832 B per record; zero divergence across all records),
- state file unchanged (`99147e4d6e461dcb…`, 617 B).

The remaining register divergence between the two traced runs is exactly the
**thread id** (record 738 onward, `rax`/`rcx` = 0xaa90 vs 0xaab1 = the two tids
read from TLS); it demonstrably does not reach the OTP payload — the gold
reference for the lift is a single deterministic trace, and cross-run diffs
must ignore tid-derived registers.

## Corpus

- Trace target: `qi864985u0` (82-byte wrapper) at libstoreservicescore RVA
  `0x1c53c0`; the wrapper calls into libCoreADI, which does the work.
- Entry args: `rdi=0xfffffffffffffffe` (DS_ID), `rsi=&mid`, `rdx=&mid_n`,
  `rcx=&otp`, `r8=&otp_n` (all stack pointers).
- Record format (after this round of fixes): 152 B `trec` (ip, 16 GP regs
  rax..r15, orig_rax, tid, kind) + 832 B NT_X86_XSTATE blob, sequential.
- The traced call executes ~622k instructions and crosses exactly **one**
  `gettimeofday` and one `newfstatat` in the winning flow class.

## Three invisible time/identity sources found (all syscall-free or boundary-free)

1. **`rdtsc` (0f 31) at libstoreservicescore RVA `0x1c6419`.** The engine reads
   the raw TSC inside the warm path: `rax = TSC; rcx = TSC; r15 = TSC % 7`
   (magic `0x2492492492492493`, standard /7 sequence) then `r15 <<= 4` — a
   16-byte-granular selector on `TSC % 7`; separately a stack-address mod 3.
   One rdtsc inside libss plus two more inside libCoreADI = 3 rewrites per run
   under the freezer. A userspace instruction no syscall freezer can see.
2. **`gettimeofday` executed *inside* the traced window without a boundary
   stop.** Under `PTRACE_SINGLESTEP` a `syscall` instruction executes the
   whole call and no `SIGTRAP|0x80` boundary is delivered, so the boundary
   rewriter never froze it (observed at record ~240,836: unfrozen host clock).
   This was the **actual OTP divergence source**: after extending the freezer
   to rewrite time answers at single-step crossings, traced OTP == plain OTP.
3. **Thread id from TLS.** Record 738 loads the engine's own tid (bionic TLS,
   no syscall) into `rax`; it flows through the dataflow but provably cancels
   (identical OTPs across runs with different tids).

Fixes in `tools/adi_freeze.c` for this milestone:

- rdtsc/rdtscp freeze: at every single-step stop, check the instruction just
  executed (PEEKDATA at `prev_ip`) and rewrite `rax`/`rdx` with a fake clock
  `base + reads*step` (`--tsc-base=`, `--tsc-step=`, `--no-tsc-freeze`; base
  defaults to `epoch << 21`, step 4096). The trace record is written *after*
  the rewrite, so the log shows the value the engine saw.
- single-step syscall freeze: after a `syscall` instruction crossing under
  trace, rewrite `clock_gettime(CLOCK_REALTIME)`/`gettimeofday` buffers and
  `time(2)` (word + return value) exactly like the boundary path, with honest
  hit counters.
- trace re-arm hole: after `trace_stop_all`, `trace_try_arm` used to re-plant
  the INT3 and re-`fopen(…,"wb")` the trace file **truncating it** — the
  earlier tA–tF traces were destroyed by this (files full of zeros plus a
  672-byte exit-flush tail). Added `trc.done`: one trace per run, never arm or
  reopen again. Rule: a tool must make silent data loss impossible.
- trace record now carries `r15` (needed: the TSC%7 result lives in r15) and
  `tid`; XSAVE blob per record; the `[trace] armed` report is file-verified.

## Earlier (void) result, kept for the record

The tA/tB "identical GP streams, different OTP" analysis was an artifact of
the truncation bug — both files were all zeros, and comparing zeros with zeros
reports no divergence. The tracer-side rule stands: **a captured corpus must
be validated before any conclusion is drawn from it** (here: record-count /
size check + non-zero spot checks, now in `step_trace_defuse.py`).

## What the deterministic corpus enables

The single-trace def-use lift (next step): parse tG, follow entry args
(state pointers) through to the 16-byte OTP payload stores, and lift the warm
OTP = f(state, frozen realtime) into Rust (`perun-adi-core`), validated
byte-exact against native on ≥3 states × ≥3 time points.
