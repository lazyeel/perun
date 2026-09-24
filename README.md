# Perun

A native FairPlay runtime and a self-contained App Store client for Linux, in Rust. Perun does not emulate anything: it maps Apple's Mach-O and Microsoft's PE binaries into the Linux address space and runs them on the bare CPU, translating the guest API surface at the boundary. No Wine, no QEMU, no Unicorn, no instruction interpreter.

On top of that runtime sits a working App Store client — login with 2FA, search, purchase, download, purchase history — and a strict `ipatool`-compatible persona that reproduces the reference tool's grammar, output shapes and exit codes. It is a drop-in replacement for `ipatool` on the surface it implements; the one known gap is macOS `.pkg` packages, and it is listed below rather than hidden.

## Performance

The FairPlay SAP session, measured against the stock Unicorn-based reference signer (`t0rr3sp3dr0/sapsigner`, unmodified, same live endpoints, same guest images):

| Metric | Unicorn reference (N=3) | Perun (N=10) |
|---|---|---|
| Whole-process wall | 9.09 s | **0.26 s** |
| CPU (user + sys) | 7.46 s | **0.083 s** |
| Peak RSS | 234 MiB | **27.1 MiB** |

The two columns were measured in different sessions — perun re-measured at N=10 on 2026-09-24, the oracle carried over from 2026-09-02 at N=3, because its build vendors a pinned Unicorn blob from `ghcr.io` that no longer pulls anonymously. Read the ratio as an order of magnitude, not a measurement.

This is a **protocol-session** comparison: both sides run the same image corpus through the same steps — init, two exchange rounds, 501-byte signature — and the oracle reads its payload on stdin, so the comparison is at the process level. It is not a client-versus-client benchmark; no other App Store client was measured. Method, ranges and one reproduction command per side are in [RESEARCH.md § 6](RESEARCH.md).

## Quickstart

```bash
cargo install --git https://github.com/lazyeel/perun
# or build in place: cargo build --release -p perun-cli
# (from a local build, substitute 'perun' with './target/release/perun')

# 1. authenticate — password is typed with echo off, then the 2FA code if Apple asks:
perun auth login -e you@example.com

# 2. find an app:
perun search telegram -l 5

# 3. take the license and download in one step — the bare word resolves by
#    search first, so a name, a bundle id or an app id all work here:
perun download signal --purchase -o .
#    the long form, when you want to be explicit about the bundle id:
perun download -b org.whispersystems.signal --purchase -o .

# machine-readable output for scripting:
perun search telegram --format json
perun list-purchases --format json
```

`--format json` is available on every store command, in both personas.

## What it does

**Three layers, one binary.** The binary projection runtime is the foundation; the SAP session and the Store client are built on it.

- **64-bit Windows PE images** (`.dll`), with the Win32 surface translated into POSIX: file I/O, virtual memory, synchronization, registry, TLS/FLS.
- **64-bit Mach-O images** from macOS, with the libSystem/Mach surface translated into Linux equivalents — including a full FairPlay **SAP** session, the `X-Apple-ActionSignature` handshake, executed natively against the live servers.
- **An App Store client** on the same SAP session: `X-Apple-ActionSignature` is produced by the same native runtime that the benchmark above measures.

### App Store client

Login is MZFinance password auth with out-of-band 2FA: the code from push or SMS is appended to the password on the retry round. Search goes through the public iTunes Search and Lookup APIs. Purchase is free-license only. Download streams with a progress bar and replicates the package.

```bash
# running from a local build? substitute 'perun' with './target/release/perun'
perun auth login -e you@example.com          # interactive, masked password
perun auth login -e you@example.com -p <password> --auth-code <code>   # unattended
perun auth login -e you@example.com --remember-password
#   --remember-password stores the password in the encrypted vault, which is what
#   lets an unattended run relogin by itself when the token expires (failure 2034):
perun auth info
perun auth revoke

perun search telegram -l 5
perun search Telegram --developer   # artistName/sellerName  (alias: -dev)
perun search 686450210 --id         # a developer's whole catalog
perun search encrypted --description                            # (alias: -desc)

perun purchase -b org.whispersystems.signal
perun purchase -i 686450210
perun download -b org.whispersystems.signal -o .
perun download telegram             # positional: id, bundle id, or free text
perun download 686450210 --purchase
perun list-purchases
perun list-versions -b org.whispersystems.signal
perun get-version-metadata -b org.whispersystems.signal --external-version-id <id>
```

The `perun` persona adds three search scopes on top of the plain search, each with the optional `-l/--limit` (default 5, integer 1–200; visionOS caps at 12 because the backend does):

- `search Telegram --developer` / `-dev` — client filter on the developer's name (`artistName`/`sellerName`); the backend gets the full page and the limit is applied after the filter, so a filter can never shrink the page you asked for.
- `search 686450210 --id` — the full catalog of one developer via the Lookup API by artist id.
- `search encrypted --description` / `-desc` — client filter on the description text.
- plain `search` stays the default Apple search across all fields.

The scopes are mutually exclusive, and the `ipatool` persona does not carry them.

**Every storefront value comes from the account.** `country` is read from the session's `storeFront`, and lookup, purchase and license all follow it; the egress IP gates nothing, the account's storefront does. There is no region-override flag or variable, so an app absent from the account's storefront fails at lookup before a byte of payload flows. The 134 storefront IDs are table-driven in `store/storefronts.rs`.

Endpoints are bag-driven (fetched per session), the account is stored encrypted (AES-256-GCM under PBKDF2-HMAC-SHA256, 100 000 rounds, keyed to the pinned machine address), and every signature-gated request is signed natively.

**Transfers are resumable.** An interrupted download keeps its `.tmp` partial and the next run continues it with an HTTP `Range` request, after the 206/416/200 answer is validated — a server that ignored the range can never append onto a good prefix.

**Packages are rebuilt with a real ZIP64 writer** (end-of-central-directory record plus locator, placeholders regenerated rather than truncated), so archives past 4 GB or 65 535 entries are written correctly instead of silently clipped. The streaming path uses the OTA framing Apple's kernel expects, with general-purpose flag bit 3 and the sizes and CRC in a trailing data descriptor. Replication stays well below package size: the input is memory-mapped and walked with `MADV_SEQUENTIAL`, so the kernel retires pages behind the scan instead of holding the archive. Measured with `wait4`/`ru_maxrss`: a 3.14 GB package peaks at 1.0–1.1 GiB of RSS, not 3.14 GB. Exercised live on **31 real App Store packages** (32.3 GB downloaded in total). Verified live across 31 production packages up to 3.89 GB (PUBG Mobile) and 47,007 entries in a single archive (Tanks Blitz) with zero errors. Reading a ZIP64 *central directory* is still refused: the writer emits it, the reader does not accept one.

**Download URLs resolve through a three-step recovery chain** — the legacy `volumeStoreDownloadProduct`, then `redownloadProduct` when the legacy call returns a silent empty `songList`, then `updateProduct` when that answers an empty HTTP 500. This mirrors the reference tool's recovery since Apple's 2026 migration, when the legacy call began returning empty song lists for newer apps.

### ipatool persona

The same source builds under two names and the persona is picked from argv[0] (busybox-style), so symlinks and copies both work:

```bash
cargo build --release        # produces BOTH target/release/perun and target/release/ipatool
ipatool search telegram --limit 3 --format json
```

Invoked as `ipatool`, the tool runs the strict majd/ipatool v2 grammar — command for command, flag for flag, output format for output format: the exact cobra command surface (`auth login|info|revoke`, `search <term>`, `purchase`, `download`, `list-purchases`, `list-versions`, `get-version-metadata`, `completion`, `help`), the global flags (`--format text|json`, `--verbose`, `--non-interactive`, `--keychain-passphrase`, `-h/--help`, `-v/--version`), all platform spellings (`iphone`/`ios`, `ipad`/`ipados`, `appletv`/`apple-tv`/`tvos`, `vision`/`visionos`/`visionpro`/`xros`/`realitydevice`, `mac`/`macos`/`osx`), the zerolog text and JSON output shapes byte-for-byte, the progress bar, the exit codes (cobra's flat 1), and the silent relogin on password-token expiry. `--purchase` acquires a license mid-download when Apple demands one; tvOS and visionOS downloads resolve the latest external version id on their own.

The `perun` name keeps the native grammar, with three search scopes, `--remember-password`, and stricter usage errors (exit 2).

macOS packages are the one gap: `download --platform macos` fails with an explicit message rather than pretending, because native StoreAgent decryption is a separate piece of work.

One deliberate difference from the reference: reached through the legacy `ipatool` name, a one-line nudge suggests switching to `perun`. It goes to **stderr**, only when stderr is a real terminal, and stays silent when stderr is a pipe, under `--non-interactive`, and under `--format json` — so a captured transcript or a JSON pipeline is byte-identical to the reference.

## Installation

```bash
# from source — installs BOTH `perun` and the `ipatool` persona:
cargo install --git https://github.com/lazyeel/perun
#   add --locked to resolve exactly the versions in Cargo.lock instead of floating:
cargo install --git https://github.com/lazyeel/perun --locked
```

The build needs a stable Rust toolchain (edition 2024) and nothing else — no C or C++ dependency. The SAP lane downloads its guest images on first use, over the same in-process client as the rest of the tool; no external program is required at runtime.

There is no prebuilt release published yet: the GitHub Releases page for this repository is empty, so install from source or build with `cargo build --release`.

## Design pillars

**Binary projection** — PE32+ and Mach-O headers/sections mapped with correct alignment, relocations/binds applied, per-page protections enforced. The 10.9 images are never modified on disk; the runtime's adjustments (timing normalization) happen once, in memory, on the working copy.

**Hardware ABI bridge** — shims are plain Rust functions compiled as `extern "win64"` (PE) or plain SysV functions (Mach-O), so argument registers, shadow space, and callee-saved handling are emitted by LLVM itself; a resolved import is a direct `call`, nothing else. On the Windows side a per-thread TEB lives behind the `GS` base (`arch_prctl(ARCH_SET_GS)`); `FS` stays untouched for glibc.

**Translation matrix** — the guest API surface implemented over POSIX and Linux syscalls: Win32 (virtual memory, typed handles, sync, UTF-16 strings, entropy, time, registry) and macOS libSystem (CF/IOKit/DiskArbitration with deterministic degenerate answers, the custom guest heap, the ICXS container service).

**Trap-and-report extensibility** — imports without an implementation land on generated micro-stubs that trap on first call and report the missing symbol with its arguments. Adding an API is one declarative macro invocation in its own file; contributors never need to understand the loader. `perun scaffold` turns a trap line — or the hint's quoted `DLL!func(args)` payload pasted back verbatim — into a compiling `win32_api!` skeleton with the observed arguments and the owning source-file hint.

## Researcher's toolkit

The commands below exist to drive and inspect guest binaries. They are the same tooling the per-claim verification log in [RESEARCH.md § 6.7](RESEARCH.md) runs on, and they are not needed for ordinary App Store use.

### Mach-O / FairPlay SAP

```bash
# running from a local build? substitute 'perun' with './target/release/perun'
perun sap                            # zero-config; fetches the images on first run
perun sap --mac AA:BB:CC:DD:EE:FF    # force the machine address for one run
perun sap --sign <hex>                # sign a custom payload  (or --file <path>)
perun mach info /path/to/MachO.bin    # header, segments, sections, symbols
```

The machine address is auto-detected: the first physical, up interface (veth/bridge/tunnel links are skipped), or — on hosts without one, like containers — a deterministic pseudo-MAC derived from the machine anchor (machine ID, else hostname). The first resolution is pinned under `~/.local/state/perun/machine`, so the identity and the account store keyed by it survive NIC changes and container restarts. Two overrides sit above that pin: `--mac` forces a specific address for one run of the bare `perun sap`, and `PERUN_MAC` does the same for every lane. Neither ever rewrites the pin, so neither can silently re-key the account store.

The first run fetches the required images itself (~32 MB range-read from Apple's public 1.28 GB update package, SHA-256-pinned, cached under `~/.cache/perun/sap/`); every later run is warm. All network I/O goes through one in-process client (`ureq` over rustls), so connections are pooled and no external program is required. The full specification — binary map, memory invariants, protocol wire format, benchmarks — is [RESEARCH.md](RESEARCH.md).

### Windows PE

```bash
perun info   /path/to/CoreADI64.dll
perun run    /path/to/CoreADI64.dll --verbose
perun call   /path/to/CoreADI64.dll vdfut768ig 0 scratch --verbose
#   feed a file as a named guest buffer, then use the name as a value:
perun call   /path/to/CoreADI64.dll vdfut768ig 0 scratch \
    --load=spim=/path/to/spim.bin --poke=scratch+0x0=spim --poke=scratch+0x8=0x15b
PERUN_SEQ=3 perun call /path/to/CoreADI64.dll vdfut768ig 0 scratch
perun seq    /path/to/CoreADI64.dll vdfut768ig --script=session.txt
perun scaffold 'KERNEL32!FooBar(0x1, 0x0, 0x0, 0x0)'
```

On Apple's `CoreADI64.dll` (iTunes for Windows, x86_64, static MSVC CRT) the image initializes with every import resolved — 111 Win32 APIs implemented — and the ADI dispatcher runs end-to-end up to its provisioning gate.

`run` takes `--verbose`, `--trace` (log the instrumented Win32 call sites — partial coverage, not every shim), `--trace-file F` (redirect stderr to a file, where the trace lines land) and `--no-teb` (skip TEB initialization when reproducing a load that hangs before it).

`call` accepts `--load=NAME=FILE`, `--patch=RVA=HEX`, `--poke=TARGET=VALUE`, `--poke-ptr=RVA=VALUE`, `--peek=RVA` and `--peek-ptr=RVA`. `TARGET` in a poke is a guest RVA, `scratch+OFF` or `ctx+OFF`; values may be numbers or the `scratch`/`ctx` tokens. Option values resolve after the whole command line is parsed, so a buffer registered by `--load` is usable as a value no matter where its `--load` sits — the price is that a malformed poke value is rejected only after parsing completes. Each invocation prints as `call#N <export>(...)` and the scratch page dumps per non-zero qword, so a sweep can tell which output fields the guest actually wrote.

`seq` loads one image and runs `DllMain` once, then drives a script of export calls in the same process so guest state carries between them. One verb per line, `#` starts a comment: `load NAME FILE`, `poke TARGET VALUE`, `call [EXPORT] A0 A1 A2 A3` (arguments are tokens; the export defaults to `vdfut768ig`), `zero scratch|ctx`, and `dump` (every non-zero qword of scratch and ctx). Use it when each call in the session should differ — `PERUN_SEQ=N` covers the case where they are identical. Export names match the export table case-sensitively.

**The provisioning gate is characterized, not bypassed** — and that is the actual result. The check is an in-memory provisioning-state flag consulted before command dispatch; the header validator behind the second failure exit is decoded down to its four byte-reads and OR-fold; and the outcome was shown to gate on missing provisioned state rather than on any forgeable input. Two-trampoline zeroing, a clean ZF flip, register canaries and live session content all leave the outcome unchanged, and a valid header is not obtainable offline. The real caller is CoreFP's eight-call session cluster rather than a single call, which is what `perun seq` exists to reproduce. The full analysis is [RESEARCH.md](RESEARCH.md) (§ 2.2, § 4.7, § 5.8, § 6.7).

### Research harnesses

The ADI findings are reproduced by four example binaries, not only by hand:

| Example | What it establishes |
|---|---|
| `examples/chain.rs` | init-then-operation sequencing in one address space, with `.data` snapshots |
| `examples/feed_spim.rs` | live spim fed through honest pointers across layout and command matrices, one child process per case |
| `examples/fpdi_emul.rs` | the `fpdi` transport rules cell by cell, with local stub, live probe and self-checks |
| `examples/watch.rs` | mprotect watchpoints attributing first touches to exact RVAs |

Run one with `cargo run --release --example chain`.

### Environment

Everything is optional; the defaults are zero-config.

| Variable | Effect |
|---|---|
| `PERUN_SAP_DIR` | asset cache location (default `~/.cache/perun/sap`) |
| `PERUN_STORE_DIR` | vault and cookie-jar location |
| `PERUN_APPDATA` | guest appdata root (default `$HOME/.perun/appdata`) |
| `PERUN_TRACE=1` | logs the instrumented Win32 call sites (partial coverage, not global) |
| `PERUN_STORE_HTTP_DEBUG=1` | HTTP wire dump, also enabled by `--verbose` |
| `PERUN_STORE_ZIP_DEBUG=1` | zip replicator debug output |
| `PERUN_SEQ=N` | repeat one `call` in-process N times |
| `PERUN_MAC` | override the machine address for this run, e.g. `AA:BB:CC:DD:EE:FF` — takes priority over the pin file and never rewrites it, so exporting it cannot re-key the account store |

`--trace-file F` redirects stderr onto a file through `dup2`, so trace and trap lines land there instead of the console; there is no environment variable behind it.

Credentials are deliberately **not** read from the environment. There is no `PERUN_EMAIL`, `PERUN_PASSWORD` or `*_2FA_CODE` variable in this tool: the email, password and 2FA code come from `auth login` flags or from a masked prompt, and the account then persists in the encrypted vault. Keeping secrets out of the process environment means they never land in `/proc/*/environ` for another process to read. The machine address is not a secret and does have an override: `--mac` on the bare `perun sap`, or `PERUN_MAC` for every lane (see the table above).

## Development

A stable Rust toolchain is enough. The workspace is edition 2024, which needs rustc 1.85 or newer; it is developed and verified against 1.98.1. There is no C or C++ dependency and no FFI beyond libc — the runtime is Rust plus a small set of permissive crates, listed with versions and SPDX expressions in [RESEARCH.md § 8.1](RESEARCH.md) and in [`NOTICE`](NOTICE). The SAP path needs network access to Apple endpoints on first use, to fetch its guest images.

```bash
cargo test --workspace              # 210 tests across the workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check          # the tree is rustfmt-clean; this must exit 0
```

`.git-blame-ignore-revs` lists the workspace-wide reformat, so `git blame` attributes reformatted lines to the commit that last changed them logically. GitHub honors the file natively; in a local clone enable it once per clone with:

```bash
git config blame.ignoreRevsFile .git-blame-ignore-revs
```

## Documentation map

| File | What it covers |
|---|---|
| [RESEARCH.md](RESEARCH.md) | The unified specification: the Mach-O/FairPlay SAP lane (binary map, entry points, memory invariants, protocol, benchmarks, prior-art credits) and the Win32/PE ADI lane (runtime invariants, provisioning-gate analysis, 20-row verification log — § 2.2, § 4.7, § 5.8, § 6.7) |
| [NOTICE](NOTICE) | Attribution for the code and for third-party components compiled into the binary |

## Obtaining guest binaries

This repository does not include and does not distribute any proprietary binaries. Guests are obtained by each user directly from Apple's public distribution servers.

**For the SAP path**, nothing to do: the built-in fetcher range-reads the images from the public OS X 10.9 update package on first use and verifies each SHA-256 against the digests pinned in [RESEARCH.md § 2](RESEARCH.md). Cache location: `~/.cache/perun/sap/` (override with `PERUN_SAP_DIR`).

**For the Windows path**, extract a test DLL from the iTunes for Windows installer:

```bash
curl -o iTunes64Setup.exe \
  "https://secure-appldnld.apple.com/itunes12/001-80053-20210422-E8A3B28C-A3B2-11EB-BE07-CE1B67FC6302/iTunes64Setup.exe"
cabextract iTunes64Setup.exe -d extracted/
msiextract extracted/iTunes64.msi -C itunes/
cp itunes/iTunes/CoreADI64.dll .
```

Requires `cabextract` and `msiextract` (package `msitools`).

## License

* **Code:** the loader, shim, and CLI code authored by **lazyeel** is licensed under the **[Apache License, Version 2.0](LICENSE)** with a **[`NOTICE`](NOTICE)** file.
* **Research & documentation** (RESEARCH.md and the analysis herein) by **lazyeel** is licensed under **[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)**.

Third-party code compiled into the binary (all permissive; the full table with versions, authors and SPDX expressions is in [RESEARCH.md § 8.1](RESEARCH.md)):

| Crate | License | Purpose |
|---|---|---|
| `libc` | MIT OR Apache-2.0 | host libc ABI |
| `linkme` + `linkme-impl` | MIT OR Apache-2.0 | shim-table registration |
| `bzip2-rs` | MIT OR Apache-2.0 | first-run asset fetcher |
| `crc32fast`, `cfg-if`, `tinyvec` | MIT/Apache-2.0/Zlib | under bzip2-rs |
| `memmap2` | MIT OR Apache-2.0 | memory-mapped IPA input in the replicator |

The reference measurement oracle used in the benchmarks (t0rr3sp3dr0/sapsigner, Apache-2.0) and its Unicorn engine (GPL-2.0) are third-party projects; no code from either is linked into, derived from, or redistributed with this repository — Perun exists precisely because that approach was measured and found too slow. Credits and the precise legal statement are in [RESEARCH.md § 8](RESEARCH.md).

### Attribution & downstream use

Open-source and commercial/proprietary projects may use, adapt, and embed this codebase. Pursuant to **Section 4(d) of the Apache License 2.0**, any distribution of derivative works (in source or binary form) must reproduce the attribution notices defined in [`NOTICE`](NOTICE) within your product's About dialog, third-party legal notices, or documentation.

Suggested attribution: > *"Perun native binary projection runtime based on research and code by lazyeel (https://github.com/lazyeel/perun)."*

Apple, macOS, OS X, StoreKit, FairPlay, iTunes and related marks are trademarks of Apple Inc. This independent research project is not affiliated with, endorsed by, or sponsored by Apple Inc.
