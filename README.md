# Perun

A native binary projection runtime for Linux, in Rust. It maps foreign
binaries straight into a Linux process and runs them on the bare CPU — no
Wine, no QEMU, no instruction emulation. Two guests are supported today:

- **64-bit Windows PE images** (`.dll`), with the Win32 surface translated
  into POSIX: file I/O, virtual memory, synchronization, registry, TLS/FLS.
- **64-bit Mach-O images** from macOS (framework binaries), with the
  libSystem/Mach surface translated into Linux equivalents — including a
  full FairPlay **SAP** session: the `X-Apple-ActionSignature` handshake
  that Apple's storefront endpoints require, executed natively against the
  live servers.

Calls across the guest/host boundary are translated at the API level; guest
code runs at native speed, and overhead exists only at each boundary
crossing.

## What it does

**Windows side (`perun run`, `perun call`)** — loads a real Windows DLL,
applies relocations, resolves imports against the shim table, installs a
per-thread TEB, and runs `DllMain`. On Apple's `CoreADI64.dll` (iTunes for
Windows, x86_64, static MSVC CRT) the image initializes with every import
resolved — 111 Win32 APIs implemented — and the ADI dispatcher runs
end-to-end up to its provisioning gate. See [STATUS.md](STATUS.md).

**macOS side (`perun sap`)** — maps the 2013 commerce pair (CoreFP,
CommerceCore, CommerceKit) from Apple's public OS X 10.9 update package,
drives the FairPlay SAP protocol against `play.itunes.apple.com`, and
produces the 501-byte action signature. One command, no arguments beyond
the MAC you want to sign with:

```bash
./target/release/perun sap --mac AA:BB:CC:DD:EE:FF
```

The first run fetches the required images itself (~32 MB range-read from
Apple's public 1.28 GB update package, SHA-256-pinned, cached under
`~/.cache/perun/sap/`); every later run is warm. The full specification —
binary map, memory invariants, protocol wire format, benchmarks — is
[RESEARCH.md](RESEARCH.md).

## Performance

Against the reference Unicorn-based signer (stock build of
t0rr3sp3dr0/sapsigner, same live endpoints, same guest images, N=3 each):

| | Unicorn reference | Perun |
|---|---|---|
| Whole-process wall | 9.09 s | **0.25 s** |
| CPU (user + sys) | 7.46 s | **0.096 s** |
| Peak RSS | 234 MiB | **26.8 MiB** |

Measurement method and reproduction commands: [RESEARCH.md § 6](RESEARCH.md).
The signatures are accepted by the live endpoints; parity with the reference
engine was verified byte-for-byte (context address, exchange buffers, FNV
state, dispatch decisions).

## Design pillars

**Binary projection** — PE32+ and Mach-O headers/sections mapped with correct
alignment, relocations/binds applied, per-page protections enforced. The
10.9 images are never modified on disk; the runtime's adjustments (timing
normalization) happen once, in memory, on the working copy.

**Hardware ABI bridge** — shims are plain Rust functions compiled as
`extern "win64"` (PE) or plain SysV functions (Mach-O), so argument
registers, shadow space, and callee-saved handling are emitted by LLVM
itself; a resolved import is a direct `call`, nothing else. On the Windows
side a per-thread TEB lives behind the `GS` base (`arch_prctl(ARCH_SET_GS)`);
`FS` stays untouched for glibc.

**Translation matrix** — the guest API surface implemented over POSIX and
Linux syscalls: Win32 (virtual memory, typed handles, sync, UTF-16 strings,
entropy, time, registry) and macOS libSystem (CF/IOKit/DiskArbitration with
deterministic degenerate answers, the custom guest heap, the ICXS container
service).

**Trap-and-scaffold extensibility** — imports without an implementation land
on generated micro-stubs that trap on first call and report the missing
symbol with its arguments. Adding an API is one declarative macro invocation
in its own file; contributors never need to understand the loader.

## Usage

```bash
cargo build --release -p perun-cli

# Mach-O / FairPlay SAP (zero-config; first run fetches the images):
./target/release/perun sap --mac AA:BB:CC:DD:EE:FF
#   or with an explicit assets directory holding CoreFP, CommerceCore,
#   CommerceKit, CoreFP.icxs:
./target/release/perun sap <assets-dir> --mac AA:BB:CC:DD:EE:FF
#   sign a custom payload instead of the built-in smoke string:
./target/release/perun sap <assets-dir> --sign <hex>   # or --file <path>

# Windows PE:
./target/release/perun info   /path/to/CoreADI64.dll
./target/release/perun run    /path/to/CoreADI64.dll --verbose
./target/release/perun call   /path/to/CoreADI64.dll vdfut768ig 0 scratch --verbose

# Mach-O inspection:
./target/release/perun mach info /path/to/MachO.bin
```

The `call` command accepts `--verbose` (image summary), `--patch=RVA=HEX`
(in-memory code patch), `--poke=RVA=VALUE`, `--peek=RVA` and
`--peek-ptr=RVA` (read guest memory / dereference and dump after the call) —
the inspection tooling used in STATUS.md is part of the shipped binary.

Building SAP binaries requires `curl` on PATH (the fetcher and the protocol
shells out to it) and network access to Apple endpoints. A stable Rust
toolchain (tested with 1.98) is enough; there is no unsafe external
dependency — the whole runtime is pure Rust plus libc.

## Documentation map

| File | What it covers |
|---|---|
| [RESEARCH.md](RESEARCH.md) | Phase 2: the Mach-O/FairPlay SAP work — binary map, entry points, memory invariants, protocol specification, benchmarks, prior-art credits |
| [STATUS.md](STATUS.md) | Phase 1: the Win32/PE runtime and the ADI provisioning-gate analysis, with a per-claim verification log |

## Obtaining guest binaries

This repository does not include and does not distribute any proprietary
binaries. Guests are obtained by each user directly from Apple's public
distribution servers.

**For the SAP path**, nothing to do: the built-in fetcher range-reads the
images from the public OS X 10.9 update package on first use and verifies
each SHA-256 against the digests pinned in [RESEARCH.md § 2](RESEARCH.md).
Cache location: `~/.cache/perun/sap/` (override with `PERUN_SAP_DIR`).

**For the Windows path**, extract a test DLL from the iTunes for Windows
installer:

```bash
curl -o iTunes64Setup.exe \
  "https://secure-appldnld.apple.com/itunes12/001-80053-20210422-E8A3B28C-A3B2-11EB-BE07-CE1B67FC6302/iTunes64Setup.exe"
cabextract iTunes64Setup.exe -d extracted/
msiextract extracted/iTunes64.msi -C itunes/
cp itunes/iTunes/CoreADI64.dll .
```

Requires `cabextract` and `msiextract` (package `msitools`).

## License

* **Code:** the loader, shim, and CLI code authored by **lazyeel** is
  licensed under the **[Apache License, Version 2.0](LICENSE)** with a
  **[`NOTICE`](NOTICE)** file.
* **Research & documentation** (RESEARCH.md, STATUS.md, and the analysis
  herein) by **lazyeel** is licensed under
  **[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)**.

Third-party code compiled into the binary (all permissive — MIT,
Apache-2.0, Zlib; the full table with authors and SPDX expressions is in
[RESEARCH.md § 8.1](RESEARCH.md)):

| Crate | License | Purpose |
|---|---|---|
| `libc` | MIT OR Apache-2.0 | host libc ABI |
| `linkme` | MIT OR Apache-2.0 | shim-table registration |
| `bzip2-rs` | MIT OR Apache-2.0 | first-run asset fetcher |
| `crc32fast`, `cfg-if`, `tinyvec` | MIT/Apache-2.0/Zlib | under bzip2-rs |

The reference measurement oracle used in the benchmarks
(t0rr3sp3dr0/sapsigner, Apache-2.0) and its Unicorn engine (GPL-2.0) are
third-party projects; no code from either is linked into, derived from, or
redistributed with this repository — Perun exists precisely because that
approach was measured and found too slow. Credits and the precise legal
statement are in [RESEARCH.md § 8](RESEARCH.md).

### Attribution & downstream use

Both open-source and commercial/proprietary projects are welcome to use,
adapt, and embed this codebase. Pursuant to **Section 4(d) of the Apache
License 2.0**, any distribution of derivative works (in source or binary
form) must reproduce the attribution notices defined in [`NOTICE`](NOTICE)
within your product's About dialog, third-party legal notices, or
documentation.

Suggested attribution:
> *"Perun native binary projection runtime based on research and code by
> lazyeel (https://github.com/lazyeel/perun)."*

Apple, macOS, OS X, StoreKit, FairPlay, iTunes and related marks are
trademarks of Apple Inc. This independent research project is not
affiliated with, endorsed by, or sponsored by Apple Inc.
