# The C prototype

This directory preserves the original C proof of concept that validated the
approach: a minimal PE32+ loader for Linux, a Win32 shim layer over POSIX,
and a test harness. It resolved all 103 imports of its target DLL and reached
the point where `DllMain` runs without crashing.

The code here is historical reference only; it is not part of the Rust
workspace and is not built by `cargo`. The active implementation lives in
`crates/`.

## Files

- `pe_loader.c/.h` — PE32+ mapping, relocations, IAT patching
- `win32_types.h`, `win32_shims.c/.h`, `shim_table.c` — Win32-over-POSIX layer
- `adi_test.c` — test harness (load → DllMain → export call)
- `Makefile` — `make && ./adi_pe_loader ./CoreADI64.dll`

## Building

```bash
cd prototype
make
./adi_pe_loader ./CoreADI64.dll   # place the DLL next to it yourself
```

The proprietary DLL is not included and not distributed with this project.
Extract it from an iTunes for Windows installer for local experiments:

```bash
curl -o iTunes64Setup.exe \
  "https://secure-appldnld.apple.com/itunes12/001-80053-20210422-E8A3B28C-A3B2-11EB-BE07-CE1B67FC6302/iTunes64Setup.exe"
cabextract iTunes64Setup.exe -d extracted/
msiextract extracted/iTunes64.msi -C itunes/
cp itunes/iTunes/CoreADI64.dll .
```

Requires `cabextract` and `msiextract` (package `msitools`).
