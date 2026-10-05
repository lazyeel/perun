# Local Anisette (Anisette v3) on x86_64 Linux

Produces `X-Apple-I-MD` / `X-Apple-I-MD-M` locally, without Wine, without a
remote re-signing server. Verified against the real Apple endpoints:
`gsa.apple.com/grandslam/GsService2/lookup` and
`MidService/{start,finish}MachineProvisioning`, all HTTP 200, with
`<key>ec</key><integer>0</integer>` from Apple, and `ADIGetLoginCode == 0`
afterwards.

## How

    ./run.sh [<libs-classic dir>]

Needs `ANDROID_NDK`, `ANDROID_NDK` pointing at an NDK root, `ADI_APK` at an
Apple Music APK, and `ADI_RESOLVE` set, e.g.

    export ADI_RESOLVE="gsa.apple.com:443:17.179.252.2,buy.itunes.apple.com:443:17.8.136.39"
    ANDROID_NDK=$HOME/ndk/android-ndk-r27c ./run.sh

The first run builds an Android sysroot from the `sys-img` repository: a 211 MB
`android-21` arm64 image, extracted with `debugfs` (the image is plain ext4, so
no mount is needed) to obtain a real `linker64` and the real Bionic `.so` set.
Those are not in the AOSP source mirrors; they only exist in built images.

## Why the runtime is Android and not Windows

`adi_test.c` is the engine from the `adi-engine` branch of ipatool. It drives
`libstoreservicescore.so` (Apple Music <=5.x) through the classic obfuscated
exports -- `rsegvyrt87` = ProvisioningStart, `Sph98paBcz` = SetAndroidID,
`nf92ngaK92` = SetProvisioningPath, `aslgmuibau` = GetLoginCode.

That library builds its provisioning state out of the libc underneath it and
hands the flattened dispatcher a pointer to that state as its second argument.
Under a glibc host the state is a few KB while the dispatch index computed from
the call seed is on the order of 168 MB, so the table read leaves the process
and the library reports `-45075` (`libraryLoadingFailed`). Under real Bionic
the index lands in range, `ADILoadLibraryWithPath` returns 0, and
`ADISetAndroidID` accepts the 16-hex form. Nothing is patched in Apple's code:
the same unmodified `.so` files behave differently only because the libc under
them differs.

## Deviations from the stock adi_test.c

Two, both recorded inline:

* `CURLOPT_RESOLVE` driven by `ADI_RESOLVE`. Bionic does not read
  `resolv.conf` on this path -- `android_getaddrinfo` goes to netd over the
  `dnsproxyd` socket, and there is no netd under qemu-user. Resolving inside
  curl leaves the TLS path and the Host header untouched.
* `ADI_DUMP_LOOKUP` / `ADI_DUMP_START` write the raw GrandSlam response bodies
  to files, for checking `ec` by hand.

Separately worth reporting upstream: `adi_test.c` reads `r2` after `free(r2)`
in the `finishMachineProvisioning` branch, in the error path only.

## Library source (default)

`run-native.sh` fetches the x86_64 native libraries straight from Apple's
Apple Music APK (4.9.6, versionCode 1447) with `fetch_libs496.py`, reading
only the zip central directory and the needed members via HTTP Range — no
142 MB download and nothing outside `lib/x86_64/`. That APK is universal
(arm64-v8a, armeabi-v7a, x86, x86_64) and carries the classic ADI exports
(`kq56gsgHG6` … `fy34trz2st`) plus a `libCoreADI.so` exporting
`vdfut768ig`/`cvu8io98wun`, identical to the older 
split. The arm64 kit also runs under `run.sh` via `qemu-aarch64-static`,
but the native x86_64 path is the one that needs no emulator.
