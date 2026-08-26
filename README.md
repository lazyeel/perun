# Perun

A native user-space Windows micro-runtime for Linux, in Rust.

Perun maps 64-bit PE images (`.dll`) directly into a Linux process memory and
executes them natively on the CPU — no Wine, no QEMU, no instruction
emulation. Calls across the Windows/Linux boundary are translated at the
Win32 API level into POSIX: file I/O, virtual memory, synchronization,
entropy, time. The guest code runs at full native speed; overhead exists only
at each Win32 boundary crossing.

## Design pillars

**Binary projection** — PE32+ headers/sections mapped with correct alignment,
base relocations applied, per-page protections enforced.

**Hardware ABI bridge** — shims are plain Rust functions compiled as
`extern "win64"`, so argument registers (`RCX/RDX/R8/R9`), shadow space and
callee-saved register handling are emitted by LLVM itself; a resolved import
is a direct `call`, nothing else. Per-thread TEB lives behind the `GS` base
(`arch_prctl(ARCH_SET_GS)`); `FS` stays untouched for glibc.

**Translation matrix** — Win32 surface implemented over POSIX: virtual
memory, typed handle table, events/mutexes/critical sections, UTF-16 string
conversion, entropy, time, a synthetic registry.

**Trap-and-scaffold extensibility** — imports without an implementation land
on generated micro-stubs that trap on first call, report the missing symbol
with its arguments, and offer a command that scaffolds a ready-to-fill Rust
implementation. Adding an API is one declarative macro invocation in its own
file; contributors never need to understand the loader.

## Status

The Rust runtime loads and initializes a real Windows DLL. On Apple's
`CoreADI64.dll` (iTunes for Windows, x86_64, statically linked MSVC CRT),
`perun run` maps the image at its preferred base, resolves all imports against
the shim table, installs a per-thread TEB, and `DllMain(DLL_PROCESS_ATTACH)`
returns `TRUE` with no unresolved-import traps. 106 Win32 APIs are implemented.

See [ROADMAP.md](ROADMAP.md) for what remains.

## Building

Requires a stable Rust toolchain (tested with 1.98):

```bash
cargo build --release -p perun-cli
```

## License

* **Code:** All loader, shim, and CLI code authored by **lazyeel** is licensed
  under the **[Apache License, Version 2.0](LICENSE)** with a
  **[`NOTICE`](NOTICE)** file.
* **Research & Documentation:** The reverse-engineering documentation,
  protocol analysis, and architectural write-ups authored by **lazyeel** are
  licensed under the
  **[Creative Commons Attribution 4.0 International License (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/)**.

See [`LICENSE`](LICENSE) for the full Apache-2.0 terms and
[`NOTICE`](NOTICE) for mandatory downstream attribution requirements.

This repository does not include and does not distribute any proprietary
binaries. To obtain a test DLL for local experiments, extract one from an
iTunes for Windows installer:

```bash
curl -o iTunes64Setup.exe \
  "https://secure-appldnld.apple.com/itunes12/001-80053-20210422-E8A3B28C-A3B2-11EB-BE07-CE1B67FC6302/iTunes64Setup.exe"
cabextract iTunes64Setup.exe -d extracted/
msiextract extracted/iTunes64.msi -C itunes/
cp itunes/iTunes/CoreADI64.dll .
```

Requires `cabextract` and `msiextract` (package `msitools`).

### Attribution & Downstream Use

Both open-source and commercial/proprietary projects are welcome to use,
adapt, and embed this codebase. Pursuant to **Section 4(d) of the Apache
License 2.0**, any distribution of derivative works (in source or binary form)
must reproduce the attribution notices defined in [`NOTICE`](NOTICE) within
your product's About dialog, third-party legal notices, or documentation.

Suggested attribution:
> *"Perun native PE micro-runtime based on research and code by lazyeel
> (https://github.com/lazyeel/perun)."*
