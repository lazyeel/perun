#!/usr/bin/env python3
"""Remove the LIBC version *requirement* from a Bionic-linked aarch64 .so.

The Apple libraries are Bionic-linked and require the version node "LIBC",
which aarch64 glibc does not define. Fabricating a libc.so that carries a
LIBC node, or aliasing glibc's symbols into one, both fail for reasons
recorded in FINDINGS.md.

This removes the requirement instead. Two edits, both load-time only:

1. Zero the .gnu.version table. Every dynsym then reads back as index 0,
   VER_NDX_GLOBAL, so the loader binds it to the first provider in scope --
   glibc -- regardless of what any verneed record claims.
2. Drop the DT_VERNEED and DT_VERNEEDNUM entries from .dynamic by shifting
   the remaining tags down.

**DT_VERSYM is deliberately left alone.** Pointing it at 0 makes the loader
dereference NULL while applying relocations, which crashes inside ld.so
rather than inside the library under test. The table it names is now all
zeros, which is exactly what we want, so the pointer stays valid.

An earlier version of this script rewrote the dropped tags as tag 0, on the
mistaken belief that a zero tag is ignored. It is not: 0 is DT_NULL, the end
of the .dynamic list, so the loader stopped parsing there and never applied
DT_INIT_ARRAY. That fault presented as a SIGSEGV inside ld-linux-aarch64.so.1
while loading libxml2 -- a crash in the loader, not in the library.

No instruction is touched; .text stays byte-identical, and the original is
kept beside the output.
"""
import hashlib
import shutil
import struct
import sys

DT_NULL, DT_DEBUG, DT_STRTAB = 0, 21, 5
DT_VERSYM, DT_VERNEED, DT_VERNEEDNUM = 0x6FFFFFF0, 0x6FFFFFFE, 0x6FFFFFFF
SHT_GNU_versym = 0x6FFFFFFF


def sha(b):
    return hashlib.sha256(b).hexdigest()


def sections(d):
    """(name, type, vaddr, offset, size) per section header.

    The name is returned as raw bytes, never decoded: a malformed sh_name in
    a stripped Android build can point anywhere, and decoding it raises before
    the caller ever reaches the .dynamic work it came for.
    """
    sh_off = struct.unpack_from("<Q", d, 0x28)[0]
    sh_entsz = struct.unpack_from("<H", d, 0x3A)[0]
    sh_num = struct.unpack_from("<H", d, 0x3C)[0]
    sh_str = struct.unpack_from("<H", d, 0x3E)[0]
    stro_base = sh_off + sh_str
    out = []
    for i in range(sh_num):
        o = sh_off + i * sh_entsz
        name_off, typ = struct.unpack_from("<II", d, o)
        addr = struct.unpack_from("<Q", d, o + 16)[0]
        off = struct.unpack_from("<Q", d, o + 24)[0]
        size = struct.unpack_from("<Q", d, o + 32)[0]
        end = d.find(b"\0", stro_base + name_off)
        raw = bytes(d[stro_base + name_off:end]) if end > 0 else b""
        out.append((raw, typ, addr, off, size))
    return out


def unversion(src, dst):
    d = bytearray(open(src, "rb").read())
    before = sha(d)
    secs = sections(d)
    dyn = next((s for s in secs if s[1] == 6), None)   # SHT_DYNAMIC
    if dyn is None:
        sys.exit("no .dynamic section")
    doff, dsize = dyn[3], dyn[4]
    n = dsize // 16

    # vaddr -> file offset, so a DT_STRTAB vaddr can be located.
    segs = [(s[2], s[3], s[4]) for s in secs if s[1] == 1]  # SHT_PROGBITS
    prog = [(s[2], s[3], s[4]) for s in secs]                  # any alloc

    def to_off(vaddr):
        for seg_addr, seg_off, seg_size in segs:
            if seg_addr <= vaddr < seg_addr + seg_size:
                return seg_off + (vaddr - seg_addr)
        for seg_addr, seg_off, seg_size in prog:
            if seg_addr <= vaddr < seg_addr + seg_size:
                return seg_off + (vaddr - seg_addr)
        return None

    strtab = None
    for i in range(n):
        tag, val = struct.unpack_from("<qQ", d, doff + i * 16)
        if tag == DT_STRTAB:
            strtab = val
        if tag == DT_NULL:
            break
    if strtab is None:
        sys.exit("no DT_STRTAB")
    stro = to_off(strtab)
    if stro is None:
        sys.exit("cannot map DT_STRTAB vaddr to a file offset")

    # 1. zero the version-index table
    # Every entry becomes VER_NDX_GLOBAL, which is 1 -- not 0. Zero is
    # VER_NDX_LOCAL, and an undefined LOCAL symbol cannot be resolved at all.
    vs = next((s for s in secs if s[1] == SHT_GNU_versym), None)
    if vs is not None:
        d[vs[3]:vs[3] + vs[4]] = b"\x01\x00" * (vs[4] // 2)  # Elf64_Half = 1

    # 2. compact .dynamic: drop the two requirement tags, keep everything else
    kept = []
    dropped = []
    for i in range(n):
        o = doff + i * 16
        tag, val = struct.unpack_from("<qQ", d, o)
        if tag == DT_NULL:
            break
        if tag in (DT_VERNEED, DT_VERNEEDNUM):
            dropped.append(hex(tag))
            continue
        kept.append((tag, val))
    kept.append((DT_NULL, 0))
    for i, (tag, val) in enumerate(kept):
        struct.pack_into("<qQ", d, doff + i * 16, tag, val)
    for i in range(len(kept), n):
        struct.pack_into("<qQ", d, doff + i * 16, DT_NULL, 0)

    after = sha(d)
    shutil.copyfile(src, dst + ".orig")
    open(dst, "wb").write(d)
    print(f"dropped {dropped}  .dynamic {n} -> {len(kept)} entries")
    print(f"sha256 {before} -> {after}")
    print(f"patched written to {dst}   original at {dst}.orig")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: unversion.py <in.so> <out.so>")
    unversion(sys.argv[1], sys.argv[2])
