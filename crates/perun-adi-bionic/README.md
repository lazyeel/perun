# perun-adi-bionic

Anisette v3 against the Android Bionic runtime, un-emulated on x86_64.

    perun adi-android headers
    X-Apple-I-MD:   AAAABQAAABCzoEoVhvOziHjBnzmYfpCpAAAABA==
    X-Apple-I-MD-M: DdoxcOY8roy7RV0sW/s9FlR6P25t75utTt3L+j4FORmFbKf+GHAOCfBpPjCyjsujQj2LoESfVfB37dNM

One call:

```rust
let h = perun_adi_bionic::generate_headers()?;
```

Anisette is anonymous machine attestation: no account, no password, no SMS.
Nothing in this crate handles a credential, because there is none to handle.

## What "un-emulated" means, and what it does not

Say **"no emulation, on native x86_64, in an Android (Bionic) userland"**.
Three separate claims, and none of them is "it is native Linux":

| claim | holds | evidence |
|---|---|---|
| no instruction emulation | yes | the running process is `comm=adi_native`, not `qemu-*`; `qemu` appears nowhere in this crate |
| native x86_64 | yes | every `.so` is `ELF 64-bit x86-64`, mapped straight into the host address space |
| native Linux userland | **no** | libc is Bionic: `SONAME libc.so`, against `libc.so.6` for glibc. Not one byte of glibc is in the lane. |

**Bionic is a requirement, not a workaround.** `libstoreservicescore.so` is
built for the Android ABI and sizes its provisioning state from the libc
underneath it. Under glibc that state comes out the wrong size, the dispatch
index walks off the end of it, and the library answers `-45075`. Replacing
Bionic with glibc cannot work by construction.

## How it runs

The ADI libraries need a Bionic loader, a Bionic libc and Bionic libcurl. A
Rust process is glibc, and two libcs in one address space is not something a
loader supports. So the harness runs as its own process inside a private mount
namespace, and this crate parses what it printed:

    perun_adi_bionic::generate_headers()
      -> StandPaths::check()      // say what is missing, and how to build it
      -> stand::run()            // sudo unshare -m, bind-mount, exec
      -> parse_headers()         // the two banner lines

The banner is the contract. The stand prints `X-Apple-I-MD` and
`X-Apple-I-MD-M` and nothing after them, so a run that reached them cannot be
confused with a run that died earlier.

## The five patches

All five are defects in specific Android-21 binaries, located by measurement,
and they live in `patches.rs` as data rather than as advice. Each entry knows
the pristine bytes it expects, so `apply()` refuses a foreign image and is
idempotent — a rebuild script that runs it twice must not break.

| site | offset | what |
|---|---|---|
| `linker64` | file `0x16040` | `g_dl_mutex` ships as `0x4000`, so `dlopen` never returns |
| `libc.so` | `0x23A20`, `0x23A60` | `flockfile`/`funlockfile` are a tail call to `pthread_mutex_lock` |
| `libc.so` | `0x2B230` | `sysconf` counts CPUs through a path that needs the allocator it is initialising |
| `libLLVM.so` | `0xB75765` | `MutexImpl::acquire` on a mutex that is never initialised |

The two `flockfile` patches are the load-bearing ones: on this runtime every
stdio call that locks a stream blocks forever, which is `fgets` inside
`BIO_gets` reading the CA bundle, and `fclose` on any file.

## What is not vendored

The runtime, exactly like the Store lane's assets:

- `linker64` and 213 Bionic libraries, from an `android-21` system image;
- 19 Apple libraries, from an Apple Music APK.

`crates/perun-cli/examples/adi-android/run.sh` builds the stand from both.
Until that has run, `generate_headers()` returns `AdiError::StandMissing`
naming the command rather than a path in a tree you are not standing in.

## Isolation

This crate depends on neither `perun-core`, nor `perun-shims`, nor
`perun-cli`. It must not inherit anything from the projection runtime: the two
lanes share a protocol and nothing else. The Windows counterpart is
`perun-adi-win32`, which lives on the research branch.

## Tests

`cargo test -p perun-adi-bionic` covers the patch table and the output parser.
It does not, and cannot, prove that the lane provisions: that needs the runtime
above. `cargo run -p perun-adi-bionic --bin live` is the check that does, and
it prints the live headers.