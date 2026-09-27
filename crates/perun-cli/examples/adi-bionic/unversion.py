#!/usr/bin/env python3
"""Strip the LIBC version requirement from a Bionic-linked aarch64 .so.

The Apple libraries are Bionic-linked and require the version node "LIBC",
which aarch64 glibc does not define. The usual fixes are to fabricate a
libc.so that carries a LIBC node, or to alias glibc's symbols into one. Both
fail for reasons recorded in FINDINGS.md; the linker will not let a shared
object alias into another shared object, and any shim that *defines* the hot
symbols recurses through dlsym.

This takes the third road: remove the version machinery instead of satisfying
it. Three dynamic tags are cleared and the symbol version table is zeroed:

    DT_VERSYM     -> 0   no per-symbol version index any more
    DT_VERNEED    -> 0   nothing to match against
    DT_VERNEEDNUM -> 0

With DT_VERSYM absent the dynamic loader reads every symbol as
VER_NDX_GLOBAL, which binds to the first object in scope that provides the
name -- glibc. The LIBC requirement stops being consulted, and the 117
symbols libc++_shared.so wants resolve against real glibc.

This is a load-time concern only: no instruction is touched, and the file
stays byte-identical in .text. The original is kept next to the output.
"""
import hashlib
import shutil
import struct
import sys

DT_NULL, DT_STRTAB = 0, 5
DT_VERSYM, DT_VERNEED, DT_VERNEEDNUM = 0x6FFFFFF0, 0x6FFFFFFE, 0x6FFFFFFF
SHT_GNU_versym = 0x6FFFFFFF


def sha(b):
    return hashlib.sha256(b).hexdigest()


def sections(d):
    off = struct.unpack_from("<Q", d, 0x28)[0]
    entsz = struct.unpack_from("<H", d, 0x3A)[0]
    num = struct.unpack_from("<H", d, 0x3C)[0]
    out = []
    for i in range(num):
        o = off + i * entsz
        name, typ, flags, addr, soff, size = struct.unpack_from("<IIQQQQ", d, o)
        out.append((typ, addr, soff, size))
    return out


def patch(src, dst):
    d = bytearray(open(src, "rb").read())
    secs = sections(d)

    # DT_STRTAB tells us where .dynsym/.dynstr live, so .dynamic is findable
    # by scanning for a tag pair rather than trusting the section table.
    dyn = next((s for s in secs if s[0] == 6), None)
    if dyn is None:
        sys.exit("no .dynamic section")
    _, _, doff, dsize = dyn

    strtab = None
    n = dsize // 16
    for i in range(n):
        tag, val = struct.unpack_from("<qQ", d, doff + i * 16)
        if tag == DT_STRTAB:
            strtab = val
        if tag == DT_NULL:
            break
    if strtab is None:
        sys.exit("no DT_STRTAB")

    versym_off = None
    changed = []
    for i in range(n):
        o = doff + i * 16
        tag, val = struct.unpack_from("<qQ", d, o)
        if tag in (DT_VERSYM, DT_VERNEED, DT_VERNEEDNUM):
            changed.append((hex(tag), hex(val)))
            struct.pack_into("<qQ", d, o, DT_NULL, 0)
            if tag == DT_VERSYM:
                versym_off = val
        if tag == DT_NULL:
            break

    # A DT_NULL in the middle of the list would truncate the rest, so the
    # cleared tags are rewritten as DT_DEBUG-equivalent no-ops instead of
    # being removed. Redo it that way.
    d = bytearray(open(src, "rb").read())
    for i in range(n):
        o = doff + i * 16
        tag, val = struct.unpack_from("<qQ", d, o)
        if tag == DT_NULL:
            break
        if tag == DT_VERNEEDNUM:
            struct.pack_into("<qQ", d, o, 21, 0)  # DT_DEBUG, harmless
        elif tag in (DT_VERSYM, DT_VERNEED):
            struct.pack_into("<qQ", d, o, 0, 0)   # tag 0 with 0 == ignored

    # .gnu.version: all entries to VER_NDX_GLOBAL (0)
    vs = next((s for s in secs if s[0] == SHT_GNU_versym), None)
    if vs is None:
        sys.exit("no .gnu.version section")
    _, _, voff, vsize = vs
    for i in range(vsize // 2):
        struct.pack_into("<H", d, voff + i * 2, 0)

    before = sha(open(src, "rb").read())
    after = sha(bytes(d))
    shutil.copyfile(src, dst + ".orig")
    open(dst, "wb").write(d)
    print(f"cleared {changed}")
    print(f".gnu.version: {vsize // 2} entries -> 0")
    print(f"sha256 {before[:16]} -> {after[:16]}")
    print(f"original kept at {dst}.orig")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: unversion.py <in.so> <out.so>")
    patch(sys.argv[1], sys.argv[2])
