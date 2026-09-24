# Perun

A native binary projection runtime for Linux, in Rust. It maps foreign binaries straight into a Linux process and runs them on the bare CPU — no Wine, no QEMU, no instruction emulation. Two guests are supported today:

- **64-bit Windows PE images** (`.dll`), with the Win32 surface translated into POSIX: file I/O, virtual memory, synchronization, registry, TLS/FLS.
- **64-bit Mach-O images** from macOS (framework binaries), with the libSystem/Mach surface translated into Linux equivalents — including a full FairPlay **SAP** session: the `X-Apple-ActionSignature` handshake, executed natively against the live servers.

Calls across the guest/host boundary are translated at the API level; guest code runs at native speed, and overhead exists only at each boundary crossing.

## What it does

**Windows side (`perun run`, `perun call`, `perun seq`)** — loads a real Windows DLL, applies relocations, resolves imports against the shim table, installs a per-thread TEB, and runs `DllMain`. On Apple's `CoreADI64.dll` (iTunes for Windows, x86_64, static MSVC CRT) the image initializes with every import resolved — 111 Win32 APIs implemented — and the ADI dispatcher runs end-to-end up to its provisioning gate.

The gate itself is characterized rather than bypassed, which is the actual result: the check is an in-memory provisioning-state flag consulted before command dispatch, the header validator behind the second failure exit is decoded down to its four byte-reads and OR-fold, and the outcome was shown to gate on missing provisioned state rather than on any forgeable input. Two-trampoline zeroing, a clean ZF flip, register canaries and live session content all leave the outcome unchanged; a valid header is not obtainable offline. The real caller is CoreFP's eight-call session cluster, not a single call, so `perun seq` exists to drive that shape — one image load, one `DllMain`, a script of calls in one process.

The full analysis — binary ground truth, runtime invariants, the gate RVA chain, and a 20-row per-claim verification log — is [RESEARCH.md](RESEARCH.md) (§ 2.2, § 4.7, § 5.8, § 6.7).

**macOS side (`perun sap`)** — maps the 2013 commerce pair (CoreFP, CommerceCore, CommerceKit) from Apple's public OS X 10.9 update package, drives the FairPlay SAP protocol against `play.itunes.apple.com`, and produces the 501-byte action signature. With no arguments it uses the cached assets, fetching them on the first run:

```bash
./target/release/perun sap
```

The machine address is auto-detected: the first physical, up interface (veth/bridge/tunnel links are skipped), or — on hosts without one, like containers — a deterministic pseudo-MAC derived from the machine anchor (machine ID, else hostname). The first resolution is pinned under `~/.local/state/perun/machine`, so the identity and the account store keyed by it survive NIC changes and container restarts. `--mac` forces a specific address for one run, for differential testing, and never touches the pin.

The first run fetches the required images itself (~32 MB range-read from Apple's public 1.28 GB update package, SHA-256-pinned, cached under `~/.cache/perun/sap/`); every later run is warm. All network I/O shells out to `curl`, which is the only external program required. The full specification — binary map, memory invariants, protocol wire format, benchmarks — is [RESEARCH.md](RESEARCH.md).

**App Store client (`perun store` / bare aliases)** — a full Store lane on top of the same native SAP session: login via MZFinance with 2FA (the code arrives by push/SMS out of band and is appended to the password on the retry round), iTunes Search API lookup, free-app purchase, streaming IPA download with a progress bar, sinf replication, purchase history, and version metadata. Transfers are resumable: an interrupted download keeps its `.tmp` partial and the next run continues it with an HTTP `Range` request, after the 206/416/200 answer is validated so a server that ignored the range can never append onto a good prefix. Packages are rebuilt with a real ZIP64 writer (end-of-central-directory record plus locator, placeholders regenerated instead of truncated), so archives past 4 GB or 65 535 entries are written correctly rather than silently clipped; the streaming path uses the OTA framing Apple's kernel expects, with general-purpose flag bit 3 and the sizes and CRC in a trailing data descriptor instead of the local header. Replication is memory-flat regardless of package size: the input is memory-mapped and walked with `MADV_SEQUENTIAL`, so RSS tracks the buffer rather than the archive — a 3.14 GiB Tanks Blitz rebuilds in under tens of MiB. Reading a ZIP64 *central directory* is still refused — the writer emits it, the reader does not accept one. Download URLs come from a three-step recovery chain: the legacy `volumeStoreDownloadProduct`, then `redownloadProduct` when the legacy call returns a silent empty `songList`, then `updateProduct` when that answers an empty HTTP 500 — the same escalation the reference tool performs since Apple's 2026 migration.

```bash
./target/release/perun auth login -e you@example.com   # then a 2FA code
./target/release/perun search telegram -l 5
./target/release/perun purchase -b org.whispersystems.signal
./target/release/perun download -b org.whispersystems.signal -o .
./target/release/perun list-purchases
./target/release/perun list-versions -b org.whispersystems.signal
./target/release/perun get-version-metadata -b org.whispersystems.signal --external-version-id <id>
```

The perun persona adds search scopes on top of the plain search, each with the optional `-l/--limit` (default 5, integer 1–200; visionOS searches cap at 12 because the backend does):

- `search Telegram --developer` — client filter on the developer's name (`artistName`/`sellerName`); the backend gets the full page and the requested limit is applied after the filter, so a filter can never shrink the page you asked for.
- `search 686450210 --id` — the full catalog of one developer via the Lookup API by artist id.
- `search encrypted --description` — client filter on the description text.
- plain `search` stays the default Apple search across all fields.

The scopes are mutually exclusive; the ipatool persona does not carry them.

**Every storefront value comes from the account.** `country` is read from the session's `storeFront`, and lookup, purchase and license all follow it; the egress IP does not gate anything, the account's storefront does. There is no region-override flag or variable, so an app absent from the account's storefront fails at lookup before a byte of payload flows — a US-only title is simply invisible to an account signed into another storefront. The 134 storefront IDs are table-driven in `store/storefronts.rs`.

Endpoints are bag-driven (fetched per session, never hardcoded past the fallback), the account is stored encrypted (AES-256-GCM under PBKDF2-HMAC-SHA256, 100 000 rounds, keyed to the pinned machine address), and every signature-gated request is signed natively — the same runtime, one binary.

### ipatool persona

The same source builds under two names, and the persona is picked from argv[0] (busybox-style), so symlinks and copies both work:

```bash
cargo build --release        # produces BOTH target/release/perun and target/release/ipatool
ipatool search telegram --limit 3 --format json
```

Invoked as `ipatool`, the tool runs the strict majd/ipatool v2 grammar instead — command for command, flag for flag, output format for output format. In this mode it is a drop-in replacement: the exact cobra command surface (`auth login|info|revoke`, `search <term>`, `purchase`, `download`, `list-purchases`, `list-versions`, `get-version-metadata`, `completion`, `help`), the global flags (`--format text|json`, `--verbose`, `--non-interactive`, `--keychain-passphrase`, `-h/--help`, `-v/--version`), all platform spellings (`iphone`/`ios`, `ipad`/`ipados`, `appletv`/`apple-tv`/`tvos`, `vision`/`visionos`/`visionpro`/`xros`/`realitydevice`, `mac`/`macos`/`osx`), the zerolog text and JSON output shapes byte-for-byte, the progress bar, the exit codes (cobra's flat 1), and the silent relogin on password-token expiry. `--purchase` acquires a license mid-download when Apple demands one; tvOS and visionOS downloads resolve the latest external version id on their own (the MDM lockup API and the storefront product page respectively). The `perun` name keeps the native grammar and its stricter usage errors (exit 2).

macOS packages are the one gap: `download --platform macos` fails with an explicit message rather than pretending, because native StoreAgent decryption is a separate piece of work.

One deliberate difference from the reference: reached through the legacy `ipatool` name, a one-line nudge suggests switching to `perun`. It goes to **stderr**, only when stderr is a real terminal, and it stays silent when stderr is a pipe, under `--non-interactive`, and under `--format json` — so a captured transcript or a JSON pipeline is byte-identical to the reference.

## Performance

Against the reference Unicorn-based signer (stock build of t0rr3sp3dr0/sapsigner, same live endpoints, same guest images, N=3 each):

| | Unicorn reference | Perun |
|---|---|---|
| Whole-process wall | 9.09 s | **0.25 s** |
| CPU (user + sys) | 7.46 s | **0.096 s** |
| Peak RSS | 234 MiB | **26.8 MiB** |

Measurement method, ranges and reproduction commands: [RESEARCH.md § 6](RESEARCH.md). The signatures are accepted by the live endpoints; parity with the reference engine was verified byte-for-byte (context address, exchange buffers, FNV state, dispatch decisions). The oracle's wall and CPU figures include a full asset fetch on every run, because upstream ships no cache; Perun's are the warm path.

## Design pillars

**Binary projection** — PE32+ and Mach-O headers/sections mapped with correct alignment, relocations/binds applied, per-page protections enforced. The 10.9 images are never modified on disk; the runtime's adjustments (timing normalization) happen once, in memory, on the working copy.

**Hardware ABI bridge** — shims are plain Rust functions compiled as `extern "win64"` (PE) or plain SysV functions (Mach-O), so argument registers, shadow space, and callee-saved handling are emitted by LLVM itself; a resolved import is a direct `call`, nothing else. On the Windows side a per-thread TEB lives behind the `GS` base (`arch_prctl(ARCH_SET_GS)`); `FS` stays untouched for glibc.

**Translation matrix** — the guest API surface implemented over POSIX and Linux syscalls: Win32 (virtual memory, typed handles, sync, UTF-16 strings, entropy, time, registry) and macOS libSystem (CF/IOKit/DiskArbitration with deterministic degenerate answers, the custom guest heap, the ICXS container service).

**Trap-and-report extensibility** — imports without an implementation land on generated micro-stubs that trap on first call and report the missing symbol with its arguments. Adding an API is one declarative macro invocation in its own file; contributors never need to understand the loader. `perun scaffold` turns a trap line — or the hint's quoted `DLL!func(args)` payload pasted back verbatim — into a compiling `win32_api!` skeleton with the observed arguments and the owning source-file hint.

## Installation

```bash
# from source — installs BOTH `perun` and the `ipatool` persona:
cargo install --git https://github.com/lazyeel/perun
#   add --locked to resolve exactly the versions in Cargo.lock instead of floating:
cargo install --git https://github.com/lazyeel/perun --locked
```

The build needs a stable Rust toolchain (edition 2024) and nothing else — no C or C++ dependency. The SAP lane additionally shells out to `curl` at runtime, and downloads its guest images on first use.

There is no prebuilt release published: the GitHub Releases page for this repository is empty, so install from source or build with `cargo build --release` (see [Development](#development)).

## Usage

```bash
cargo build --release -p perun-cli

# App Store (StoreKit):
#   interactive login: email as a flag, password typed with echo off,
#   then the 2FA code when Apple asks for it:
./target/release/perun auth login -e you@example.com
#   fully non-interactive (scripts, CI, keychain-less automation):
./target/release/perun auth login -e you@example.com -p <password> --auth-code <code>
#   --remember-password stores the password in the encrypted vault, which is what
#   lets an unattended run relogin by itself when the token expires (failure 2034):
./target/release/perun auth login -e you@example.com --remember-password
./target/release/perun auth info
./target/release/perun auth revoke

#   plain search; the perun persona adds three client-side scopes:
./target/release/perun search telegram -l 5
./target/release/perun search Telegram --developer   # artistName/sellerName
./target/release/perun search 686450210 --id         # the developer's whole catalog
./target/release/perun search encrypted --description

./target/release/perun purchase -b org.whispersystems.signal
./target/release/perun purchase -i 686450210
#   -o picks the output directory; a killed or network-dropped transfer leaves a
#   .tmp partial that the next run resumes with an HTTP Range request:
./target/release/perun download -b org.whispersystems.signal -o .
./target/release/perun download -i 686450210 -o . --purchase
#   a bare word is resolved by search first — id, bundle id, or free text:
./target/release/perun download telegram
./target/release/perun download 686450210 --purchase
./target/release/perun list-purchases
./target/release/perun list-versions -b org.whispersystems.signal
./target/release/perun get-version-metadata -b org.whispersystems.signal --external-version-id <id>

# Mach-O / FairPlay SAP (zero-config; first run fetches the images):
./target/release/perun sap
#   force a specific machine address for one run (differential testing;
#   the auto-detected pin under ~/.local/state/perun/machine is kept):
./target/release/perun sap --mac AA:BB:CC:DD:EE:FF
#   sign a custom payload instead of the built-in smoke string
#   (works with or without an assets directory):
./target/release/perun sap --sign <hex>   # or --file <path>

# Windows PE:
./target/release/perun info   /path/to/CoreADI64.dll
./target/release/perun run    /path/to/CoreADI64.dll --verbose
./target/release/perun call   /path/to/CoreADI64.dll vdfut768ig 0 scratch --verbose
#   feed a file as a named guest buffer, and use the name as a value:
./target/release/perun call   /path/to/CoreADI64.dll vdfut768ig 0 scratch \
    --load=spim=/path/to/spim.bin --poke=scratch+0x0=spim --poke=scratch+0x8=0x15b
#   repeat one call in-process so state set by an earlier call carries over:
PERUN_SEQ=3 ./target/release/perun call /path/to/CoreADI64.dll vdfut768ig 0 scratch
#   drive a whole session from a script (one image load, one DllMain):
./target/release/perun seq    /path/to/CoreADI64.dll vdfut768ig --script=session.txt
# Turn an unresolved-import trap report into a ready-to-fill shim stub:
./target/release/perun scaffold 'KERNEL32!FooBar(0x1, 0x0, 0x0, 0x0)'

# Mach-O inspection:
./target/release/perun mach info /path/to/MachO.bin
```

The `call` command accepts `--verbose` (image summary), `--patch=RVA=HEX` (in-memory code patch), `--poke=TARGET=VALUE` and `--poke-ptr=RVA=VALUE`, `--peek=RVA` and `--peek-ptr=RVA` (read guest memory / dereference and dump after the call), and `--load=NAME=FILE` — the same inspection tooling the RESEARCH.md verification log (§ 6.7) runs on. `TARGET` in a poke is a guest RVA, `scratch+OFF` or `ctx+OFF`.

`perun run` takes `--verbose`, `--trace` (log the instrumented Win32 call sites — partial coverage, not every shim), `--trace-file F` (redirect stderr to a file, which is where the trace lines land) and `--no-teb` (skip TEB initialization when reproducing a load that hangs before it).

Option values resolve after the whole command line is parsed, so a buffer registered by `--load` is usable as a value no matter where its `--load` sits. The price is that a malformed poke value is rejected only after parsing completes.

`perun seq` reads a script, one verb per line, `#` starting a comment: `load NAME FILE`, `poke TARGET VALUE`, `call [EXPORT] A0 A1 A2 A3` (arguments are tokens; the export defaults to `vdfut768ig`), `zero scratch|ctx`, and `dump` (every non-zero qword of both regions). Use it when each call in the session should differ — `PERUN_SEQ` covers the case where they are identical. Export names are matched case-sensitively against the export table, so `vdfut768ig` resolves and `VDFUT768IG` does not.

`call` prints each invocation as `call#N <export>(...)` and dumps the scratch page per non-zero qword, so a sweep can tell which output fields the guest actually wrote.

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

`--trace-file F` redirects stderr onto a file through `dup2`, so trace and trap lines land there instead of the console; there is no environment variable behind it.

Credentials are deliberately **not** read from the environment. There is no `PERUN_EMAIL`, `PERUN_PASSWORD` or `*_2FA_CODE` variable in this tool: the email, password and 2FA code come from `auth login` flags, or from a masked prompt when they are omitted, and the account then persists in the encrypted vault. Keeping secrets out of the process environment means they never land in `/proc/*/environ` for another process to read.

## Development

A stable Rust toolchain is enough. The workspace is edition 2024, which needs rustc 1.85 or newer; it is developed and verified against 1.98.1. There is no C or C++ dependency and no FFI beyond libc — the runtime is Rust plus a small set of permissive crates, listed with versions and SPDX expressions in [RESEARCH.md § 8.1](RESEARCH.md) and in [`NOTICE`](NOTICE). Building the SAP path additionally needs `curl` on `PATH` and network access to Apple endpoints.

```bash
cargo test --workspace              # 188 tests across the workspace
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
