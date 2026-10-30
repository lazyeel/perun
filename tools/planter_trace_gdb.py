#!/usr/bin/env python3
"""Dynamic planter-genesis tracer for libCoreADI.so (GDB Python, v7).

Canonical project copy: tools/planter_trace_gdb.py.

Run inside the existing GDB session for adi_native, after the inferior is
loaded but before its first vdfut768ig call:

    (gdb) source /path/to/planter_trace_gdb_v6.py
    (gdb) run

Optional output directory:
    PERUN_TRACE_DIR=/tmp/perun-trace gdb ...

This tracer deliberately avoids fixed stack/heap addresses. It derives the
ELF load base from the first vdfut768ig entry, obtains the malloc buffer from
RAX at RVA 0xDD83B. The source pointer is captured at 0xDD511 from RCX,
before the first post-pointer CFF writes. The planter base is captured at known
base-load sites or from an actual family-store operand. Two direct staging
writer sites (0xFA9C1/0xFAA8F) log the computed byte stream independently of
software watchpoint timing.
The [RBP-0x30] slot is separately watched because it is a mutable CFF carrier.
The entry breakpoint tracks vdfut768ig opcodes, so init/config calls are not
mistaken for the provisioning transform.

Wide software watchpoints are intentionally slow. They are used because the
CFF writer path is session-dependent and a small number of hardware
watchpoints cannot cover the buffers. Software watchpoints report *value
changes*; writes that store the byte already present are not visible through
watchpoints, so known static writer sites are also instrumented directly.
"""

import gdb
import os
import time

ENTRY_RVA = 0x87554
SOURCE_SLOT_STORE_RVA = 0xDD511
POST_MALLOC_RVA = 0xDD83B
COPY_ENTRY_RVA = 0xFB022
TRANSFORM_OPCODE = 0x716BD86C

# Exact writer sites observed in the Android x86_64 libCoreADI.so.
# Each tuple: (name, base-register, index-register, displacement, value-register).
# The first two are the rolling writes into malloc(0xC8)'s staging buffer;
# the remaining six target the planter's known windows.
WRITERS = {
    0xFA9C1: ("staging_write_a", "$r9",  "$rsi", 0,      "$rbx"),
    0xFAA8F: ("staging_write_b", "$r11", "$rdx", 0,      "$rsi"),
    0xE24C9: ("fifth_1f30", "$rdi", "$r15", 0x1F30, "$rcx"),
    0xE250C: ("fam2",       "$rdi", "$rcx", 0x1A00, "$r14"),
    0xE25C2: ("fam3",       "$rdi", "$rax", 0x2460, "$r8"),
    0xE26AE: ("fam4",       "$r8",  "$rax", 0x1390, "$r13"),
    0xFB05B: ("fam1_a",     "$r12", "$rsi", 0x0D60, "$rdx"),
    0xFB075: ("fam1_b",     "$r12", "$rsi", 0x0D60, "$rdx"),
}

# Selector/mixer read sites. The first reachable one gives a valid in-frame
# [RBP-0x30] planter pointer and marks the completed planter for final dump.
MIXER_READS = [
    0xE6B54, 0xE6BAB, 0xE6BF7, 0xE6C76,
    0xE6CDE, 0xE6D16, 0xE6D53, 0xE6DAA,
    0xE6E01, 0xE6E38, 0xE6E74, 0xE6ECD,
    0xE6F20, 0xE6F4E, 0xE6F84, 0xE7004,
]

TABLES = [
    ("fam1", 0x0D60),
    ("fam2", 0x1A00),
    ("fam3", 0x2460),
    ("fam4", 0x1390),
]
WINDOW_SIZE = 256
PLANTER_SIZE = 0x2700
# 0xE24C9 is only known to write at base + 0x1F30 + R15.  We do NOT yet
# know that R15 is restricted to [0, 255], so observe the entire remaining
# captured planter tail rather than prematurely naming a 256-byte S-box.
# The fifth writer starts at +0x1F30, but its R15 index range is unknown.
# Watch the complete planter with non-overlapping regions; it may reach fam3.
UNKNOWN_RANGES = [
    ("unknown_e60_1390", 0x0E60, 0x1390 - 0x0E60),
    ("unknown_1490_1a00", 0x1490, 0x1A00 - 0x1490),
    ("unknown_1b00_1f30", 0x1B00, 0x1F30 - 0x1B00),
    ("unknown_1f30_2460", 0x1F30, 0x2460 - 0x1F30),
    ("unknown_2560_2700", 0x2560, 0x2700 - 0x2560),
]
FIFTH_WRITER_BASE_OFFSET = 0x1F30
FIFTH_WRITER_MAX_OFFSET = 0x2700 - FIFTH_WRITER_BASE_OFFSET

OUT_ROOT = os.environ.get("PERUN_TRACE_DIR", "/tmp/perun-planter-trace")
# Never mix a new capture with stale binary dumps from an earlier attempt.
# Each GDB invocation gets its own child directory; the exact path is logged.
RUN_ID = f"run-{int(time.time() * 1_000_000)}-{os.getpid()}"
OUT = os.path.join(OUT_ROOT, RUN_ID)
os.makedirs(OUT, exist_ok=False)
LOG = os.path.join(OUT, "trace.log")

STATE = {
    "base": None,
    "entry_bp": None,
    "base_load_bps": [],
    "active_op": None,
    "source_init_bp": None,
    "source_init": None,
    "postmalloc_bp": None,
    "copy_entry_bp": None,
    "writer_bps": [],
    "mixer_bps": [],
    "watchers": [],
    "src": None,
    "dst": None,
    "dst_size": 200,  # allocator request; not the observed access span
    "dst_span": 256,
    "planter": None,
    "planter_watch_armed": False,
    "final_dumped": False,
    "postmalloc_seen": False,
    "slot_watch_armed": False,
    "writer_stats": {},
    "planter_mismatch": False,
    "started": time.time(),
}


def log(message):
    stamp = time.strftime("%H:%M:%S")
    line = f"[{stamp}] {message}"
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    gdb.write(line + "\n")


def rv(expr):
    return int(gdb.parse_and_eval(expr)) & 0xFFFFFFFFFFFFFFFF


def read_mem(addr, size):
    return bytes(gdb.selected_inferior().read_memory(addr, size))


def read_u64(addr):
    return int.from_bytes(read_mem(addr, 8), "little")


def mapped_rw_span(addr, size):
    """Return True only if one current RW VMA fully contains [addr, addr+size)."""
    try:
        pid = gdb.selected_inferior().pid
        with open(f"/proc/{pid}/maps", "r", encoding="ascii") as f:
            for line in f:
                fields = line.split()
                lo_s, hi_s = fields[0].split("-", 1)
                lo, hi = int(lo_s, 16), int(hi_s, 16)
                perms = fields[1]
                if "r" in perms and "w" in perms and lo <= addr and addr + size <= hi:
                    return True
    except Exception:
        pass
    return False


def ptr_ok(addr, size):
    if addr == 0 or not mapped_rw_span(addr, size):
        return False
    try:
        read_mem(addr, size)
        return True
    except Exception:
        return False


def ptr_from_slot(rbp, disp):
    try:
        return read_u64(rbp + disp)
    except Exception:
        return 0


def write_blob(name, data):
    path = os.path.join(OUT, name)
    with open(path, "wb") as f:
        f.write(data)
    log(f"dump {name}: {len(data)} bytes")


def reg_snapshot():
    regs = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
            "rbp", "rsp", "rip")
    out = []
    for reg in regs:
        try:
            out.append(f"{reg}={rv('$' + reg):#x}")
        except Exception:
            pass
    return " ".join(out)


def arm_region_watch(name, addr, size):
    """Install a value-change watchpoint over an arbitrary memory span."""
    if not ptr_ok(addr, size):
        log(f"WATCH SKIP {name}: unreadable/non-RW span addr={addr:#x} size={size:#x}")
        return None
    base_name = name
    suffix = 1
    while True:
        same_name = [w for w in STATE["watchers"] if w.name == name and w.is_valid()]
        if not same_name:
            break
        for existing in same_name:
            if existing.addr == addr and existing.size == size:
                log(f"WATCH ALREADY ARMED {name}: addr={existing.addr:#x} size={existing.size:#x}")
                return existing
        name = f"{base_name}_alt{suffix}"
        suffix += 1
    try:
        prev = read_mem(addr, size)
        obj = RegionWatch(name, addr, size, prev)
        STATE["watchers"].append(obj)
        write_blob(f"{name}.initial.bin", prev)
        log(f"WATCH ARMED {name}: addr={addr:#x} size={size} (software)")
        return obj
    except Exception as e:
        log(f"WATCH ERROR {name} @ {addr:#x}: {e}")
        return None


class RegionWatch(gdb.Breakpoint):
    """Software watchpoint on a complete byte array; callback only observes."""
    def __init__(self, name, addr, size, previous):
        self.name = name
        self.addr = addr
        self.size = size
        self.previous = previous
        self.hits = 0
        spec = f"-location *(unsigned char (*)[{size}])0x{addr:x}"
        super().__init__(spec, gdb.BP_WATCHPOINT, gdb.WP_WRITE, internal=False)
        self.silent = True

    def stop(self):
        try:
            current = read_mem(self.addr, self.size)
            changes = [(i, a, b) for i, (a, b) in enumerate(zip(self.previous, current)) if a != b]
            self.previous = current
            self.hits += 1
            pc = rv("$pc")
            # A software watchpoint detects the changed value while single-stepping.
            # Record PC-after and a small disassembly window; do not guess the exact
            # store PC where GDB has not exposed it.
            try:
                dis = gdb.execute(f"x/8i {max(0, pc - 0x18):#x}", to_string=True).strip()
                dis = " | ".join(x.strip() for x in dis.splitlines())
            except Exception:
                dis = "<disassembly unavailable>"
            preview = ",".join(f"{i:#x}:{a:02x}>{b:02x}" for i, a, b in changes[:48])
            extra = " ..." if len(changes) > 48 else ""
            log(f"CHANGE {self.name} hit={self.hits} pc_after={pc:#x} "
                f"rva_after={(pc - (STATE['base'] or 0)):#x} "
                f"changed={len(changes)} [{preview}{extra}] {reg_snapshot()}")
            log(f"  DIS {dis}")
        except Exception as e:
            log(f"WATCH CALLBACK ERROR {self.name}: {e}")
        # False means continue; the inferior state was not modified.
        return False


class WriterSiteBP(gdb.Breakpoint):
    """Exact breakpoints on statically identified byte-store instructions."""
    def __init__(self, rva, spec):
        self.rva = rva
        self.name, self.base_reg, self.index_reg, self.disp, self.value_reg = spec
        super().__init__(f"*{STATE['base'] + rva:#x}", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        if STATE["active_op"] != TRANSFORM_OPCODE:
            return False
        base = None
        try:
            base = rv(self.base_reg)
            index = rv(self.index_reg)
            value = rv(self.value_reg) & 0xFF
            ea = (base + index + self.disp) & 0xFFFFFFFFFFFFFFFF
            try:
                before = read_mem(ea, 1)[0]
                before_s = f"{before:02x}"
            except Exception:
                before_s = "??"
            log(f"STORE_SITE {self.name} rva={self.rva:#x} ea={ea:#x} "
                f"before={before_s} value={value:02x} base={base:#x} "
                f"index={index:#x} disp={self.disp:#x} {reg_snapshot()}")
            # Per-instruction CSV captures even same-value stores.
            with open(os.path.join(OUT, "writer_events.csv"), "a", encoding="utf-8") as f:
                if f.tell() == 0:
                    f.write("rva,name,ea,before,value,base,index,disp,active_opcode\n")
                f.write(f"{self.rva:#x},{self.name},{ea:#x},{before_s},{value:02x},"
                        f"{base:#x},{index:#x},{self.disp:#x},{STATE['active_op']:#x}\n")
            st = STATE["writer_stats"].setdefault(self.name, {
                "hits": 0, "min_index": None, "max_index": None,
                "min_ea": None, "max_ea": None, "changed": 0,
                "base_match_hits": 0, "index_in_expected_span": 0,
            })
            st["hits"] += 1
            st["min_index"] = index if st["min_index"] is None else min(st["min_index"], index)
            st["max_index"] = index if st["max_index"] is None else max(st["max_index"], index)
            st["min_ea"] = ea if st["min_ea"] is None else min(st["min_ea"], ea)
            st["max_ea"] = ea if st["max_ea"] is None else max(st["max_ea"], ea)
            expected_base = STATE["planter"]
            base_match = expected_base is not None and base == expected_base
            span_limit = FIFTH_WRITER_MAX_OFFSET if self.rva == 0xE24C9 else WINDOW_SIZE
            index_ok = 0 <= index < span_limit
            staging_match = self.rva in (0xFA9C1, 0xFAA8F) and STATE["dst"] is not None and base == STATE["dst"]
            staging_index_ok = self.rva in (0xFA9C1, 0xFAA8F) and 0 <= index < 256
            if base_match:
                st["base_match_hits"] += 1
            if index_ok:
                st["index_in_expected_span"] += 1
            if staging_match:
                st["staging_base_match_hits"] = st.get("staging_base_match_hits", 0) + 1
            if staging_index_ok:
                st["staging_index_in_range_hits"] = st.get("staging_index_in_range_hits", 0) + 1
            log(f"  writer_validation expected_base={expected_base!r} "
                f"base_match={base_match} index_ok_0_{span_limit - 1}={index_ok} "
                f"staging_base_match={staging_match} staging_index_ok={staging_index_ok}")
            if before_s != "??" and int(before_s, 16) != value:
                st["changed"] += 1
        except Exception as e:
            log(f"STORE_SITE ERROR rva={self.rva:#x}: {e}")

        # The first two sites write the malloc staging buffer, not the planter.
        # Only the six statically identified family/tail stores may nominate a
        # planter base. This avoids mistaking a large RW heap VMA for an object:
        # ptr_ok() alone proves mapping, not allocation identity.
        planter_writer_sites = {0xE24C9, 0xE250C, 0xE25C2, 0xE26AE, 0xFB05B, 0xFB075}
        if (self.rva in planter_writer_sites and base is not None
                and not STATE["planter_watch_armed"] and ptr_ok(base, PLANTER_SIZE)):
            rbp = rv("$rbp")
            slot_ptr = ptr_from_slot(rbp, -0x30)
            src = STATE["src"]
            overlap_ok = src is not None and base == src + 32
            log(f"PLANTER WRITER CANDIDATE: site={self.rva:#x} base_operand={base:#x} "
                f"slot_now={slot_ptr:#x} slot_eq_base={slot_ptr == base} "
                f"source={src!r} source_plus_32_match={overlap_ok}")
            if overlap_ok:
                if src and ptr_ok(src, 256):
                    sb = read_mem(src, 256)
                    pb = read_mem(base, 224)
                    equal = sb[32:256] == pb
                    mismatches = sum(a != b for a, b in zip(sb[32:256], pb))
                    log(f"SOURCE/PLANTER OVERLAP src_plus_32_eq_base={src + 32 == base} "
                        f"source[32:256] == planter[0:224]: {equal} mismatches={mismatches}")
                gdb.post_event(lambda p=base: arm_planter_and_continue(p))
                return True
            expected = (src + 32) if src is not None else None
            log(f"REJECTING PLANTER CANDIDATE {base:#x}: "
                f"source+0x20={expected!r} (source pointer must be captured first)")
        return False


class SourceSlotStoreBP(gdb.Breakpoint):
    """Capture RCX before mov [RBP-0x11A8],RCX and watch source from its birth."""
    def __init__(self):
        super().__init__(f"*{STATE['base'] + SOURCE_SLOT_STORE_RVA:#x}",
                         gdb.BP_BREAKPOINT, internal=False)
        self.silent = True
        self.done = False

    def stop(self):
        if self.done or STATE["active_op"] != TRANSFORM_OPCODE:
            return False
        self.done = True
        src = rv("$rcx")
        rbp = rv("$rbp")
        slot_before = ptr_from_slot(rbp, -0x11A8)
        STATE["source_init"] = src
        STATE["src"] = src
        log(f"SOURCE SLOT STORE rva={SOURCE_SLOT_STORE_RVA:#x} "
            f"RCX_source={src:#x} prior_slot={slot_before:#x} rbp={rbp:#x}")
        gdb.post_event(lambda p=src, f=rbp: arm_source_and_continue(p, f))
        return True


def arm_source_and_continue(src, rbp):
    try:
        STATE["src"] = src
        if ptr_ok(src, 256):
            if STATE["planter_watch_armed"] and src + 32 == STATE["planter"]:
                arm_region_watch("source_frame_prefix_32", src, 32)
            else:
                arm_region_watch("source_256", src, 256)
            log("SOURCE WATCH ARMED AT 0xDD511 (before subsequent CFF source writes)")
        else:
            log(f"SOURCE WATCH DEFERRED: RCX={src:#x} does not span 256 RW bytes")
        # Observe the mutable CFF carrier from this early point, before malloc.
        if not STATE["slot_watch_armed"]:
            obj = arm_region_watch("frame_slot_rbp_minus_30", rbp - 0x30, 8)
            STATE["slot_watch_armed"] = obj is not None
    finally:
        gdb.execute("continue")


class PostMallocBP(gdb.Breakpoint):
    """At 0xDD83B, RAX is malloc(0xC8)'s result, before it is saved to [RBP-3F8]."""
    def __init__(self):
        super().__init__(f"*{STATE['base'] + POST_MALLOC_RVA:#x}", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True
        self.done = False

    def stop(self):
        if self.done or STATE["active_op"] != TRANSFORM_OPCODE:
            return False
        self.done = True
        rbp = rv("$rbp")
        src = ptr_from_slot(rbp, -0x11A8)
        dst = rv("$rax")
        init_src = STATE["source_init"]
        log(f"POST_MALLOC rva={POST_MALLOC_RVA:#x} rbp={rbp:#x} "
            f"source=[rbp-0x11a8]={src:#x} source_at_0xdd511={init_src!r} "
            f"source_pointer_unchanged={init_src is None or init_src == src} "
            f"destination=rax={dst:#x}")
        gdb.post_event(lambda s=src, d=dst, r=rbp: arm_buffers_and_continue(s, d, r))
        return True


class CopyEntryBP(gdb.Breakpoint):
    """Snapshot the staging region at the first known fam1 copy-entry site."""
    def __init__(self):
        super().__init__(f"*{STATE['base'] + COPY_ENTRY_RVA:#x}", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True
        self.done = False

    def stop(self):
        if self.done or STATE["active_op"] != TRANSFORM_OPCODE:
            return False
        self.done = True
        rbp = rv("$rbp")
        slot_dst = ptr_from_slot(rbp, -0x3F8)
        n = 256 if ptr_ok(slot_dst, 256) else (200 if ptr_ok(slot_dst, 200) else 0)
        log(f"COPY_ENTRY rva={COPY_ENTRY_RVA:#x} [rbp-0x3f8]={slot_dst:#x} "
            f"saved_dst={STATE['dst'] or 0:#x} span={n}")
        if n:
            data = read_mem(slot_dst, n)
            write_blob(f"staging.copy_entry.{n}.bin", data)
            requested = data[:200]
            log(f"COPY_ENTRY unique={len(set(data))}/{n} "
                f"first64={data[:64].hex()} requested200_unique={len(set(requested))}/200")
            if STATE["dst"] and slot_dst != STATE["dst"]:
                log("WARNING: copy-entry staging pointer differs from post-malloc RAX")
        else:
            log("COPY_ENTRY staging span is not readable")
        return False


def has_planter_signature(addr):
    """Known final signature: the four documented 256-byte windows are bijections."""
    if not addr or not ptr_ok(addr, PLANTER_SIZE):
        return False
    try:
        inf = gdb.selected_inferior()
        for _name, off in TABLES:
            if len(set(bytes(inf.read_memory(addr + off, WINDOW_SIZE)))) != 256:
                return False
        return True
    except Exception:
        return False


class FirstMixerReadBP(gdb.Breakpoint):
    def __init__(self, rva):
        self.rva = rva
        super().__init__(f"*{STATE['base'] + rva:#x}", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        if STATE["final_dumped"] or STATE["active_op"] != TRANSFORM_OPCODE:
            return False
        rbp = rv("$rbp")
        slot_ptr = ptr_from_slot(rbp, -0x30)
        p = STATE["planter"] if has_planter_signature(STATE["planter"]) else None
        slot_signature = has_planter_signature(slot_ptr)
        if p is None and slot_signature:
            p = slot_ptr
        log(f"FIRST MIXER READ rva={self.rva:#x} rbp={rbp:#x} "
            f"slot_now={slot_ptr:#x} slot_signature={slot_signature} "
            f"writer_base={STATE['planter'] or 0:#x} "
            f"writer_base_signature={has_planter_signature(STATE['planter'])} "
            f"selected_planter={p or 0:#x}")
        if p and has_planter_signature(p):
            STATE["final_dumped"] = True
            data = read_mem(p, PLANTER_SIZE)
            write_blob("planter.final.bin", data)
            for name, off in TABLES:
                w = data[off:off + WINDOW_SIZE]
                log(f"FINAL {name}: unique={len(set(w))}/256 first32={w[:32].hex()}")
                write_blob(f"{name}.final.bin", w)
            for name, off, size in UNKNOWN_RANGES:
                region = data[off:off + size]
                log(f"FINAL {name}: offset={off:#x} size={size:#x} "
                    f"unique={len(set(region))}/256 first64={region[:64].hex()}")
                write_blob(f"{name}.final.bin", region)
            with open(os.path.join(OUT, "writer_stats.txt"), "w", encoding="utf-8") as f:
                for name, st in sorted(STATE["writer_stats"].items()):
                    f.write(f"{name}: {st}\n")
        else:
            log("MIXER CANDIDATE REJECTED: no verified four-permutation planter; "
                "retrying at next mixer-read site")
            return False
        if STATE["src"] and ptr_ok(STATE["src"], 256):
            write_blob("source.final.bin", read_mem(STATE["src"], 256))
        if STATE["dst"] and STATE["dst_span"]:
            n = STATE["dst_span"]
            if ptr_ok(STATE["dst"], n):
                data = read_mem(STATE["dst"], n)
                write_blob(f"staging.final.span_{n}.bin", data)
                if n >= 200:
                    write_blob("staging.final.requested_200.bin", data[:200])
                if n >= 256:
                    write_blob("staging.final.adjacent_56.bin", data[200:256])
        log(f"TRACE COMPLETE elapsed={time.time() - STATE['started']:.1f}s; GDB left stopped")
        return True


class PlanterBaseLoadBP(gdb.Breakpoint):
    """At known mov reg,[rbp-0x30] sites, capture the pointer before stores."""
    def __init__(self, rva, reg_name):
        self.rva = rva
        self.reg_name = reg_name
        super().__init__(f"*{STATE['base'] + rva:#x}", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        if STATE["active_op"] != TRANSFORM_OPCODE or STATE["planter_watch_armed"]:
            return False
        rbp = rv("$rbp")
        slot = ptr_from_slot(rbp, -0x30)
        src = STATE["src"]
        relation_ok = src is not None and slot == src + 32
        if ptr_ok(slot, PLANTER_SIZE) and relation_ok:
            log(f"PLANTER BASE-LOAD SITE rva={self.rva:#x} target_reg={self.reg_name} "
                f"slot={slot:#x} source={src:#x} source_plus_32_match=True; arming before instruction")
            gdb.post_event(lambda p=slot: arm_planter_and_continue(p))
            return True
        if ptr_ok(slot, PLANTER_SIZE) and src is None:
            log(f"BASE-LOAD DEFERRED rva={self.rva:#x}: candidate {slot:#x} mapped, "
                "but source pointer not known yet; wait for direct writer validation")
            return False
        log(f"BASE-LOAD REJECTED rva={self.rva:#x}: [rbp-0x30]={slot:#x} "
            f"not a validated source+0x20 planter span")
        return False


def arm_planter_windows(planter):
    if STATE["planter_watch_armed"]:
        return
    if not ptr_ok(planter, PLANTER_SIZE):
        log(f"PLANTER WATCH NOT ARMED: base {planter:#x} is not a readable RW 0x2700 span")
        return
    STATE["planter"] = planter
    required = ["planter_head_0000_0d60"] + [name for name, _ in TABLES] + [name for name, _, _ in UNKNOWN_RANGES]
    arm_region_watch("planter_head_0000_0d60", planter, 0x0D60)
    for name, off in TABLES:
        arm_region_watch(name, planter + off, WINDOW_SIZE)
    for name, off, size in UNKNOWN_RANGES:
        arm_region_watch(name, planter + off, size)

    # The measured layout has source[32:256] == planter[0:224]. Once the
    # planter base is known, avoid watching that same 224-byte span twice:
    # retain a separate watch only for source[0:32], while the planter-head
    # watch covers the overlapping remainder.
    src = STATE["src"]
    if src and src + 32 == planter:
        for w in STATE["watchers"]:
            if w.name == "source_256" and w.is_valid():
                w.enabled = False
                log("WATCH DISABLED source_256: source[32:256] aliases planter[0:224]")
        arm_region_watch("source_frame_prefix_32", src, 32)

    armed = {w.name for w in STATE["watchers"] if w.is_valid() and w.enabled}
    missing = [name for name in required if name not in armed]
    STATE["planter_watch_armed"] = not missing
    if missing:
        log(f"PLANTER WATCHES INCOMPLETE at base={planter:#x}; missing={missing}")
    else:
        log(f"PLANTER WATCHES ARMED at base={planter:#x}; "
            "full object partitioned into head, four known windows, and five unknown gaps")


def arm_planter_and_continue(planter):
    try:
        arm_planter_windows(planter)
    finally:
        gdb.execute("continue")


def arm_buffers_and_continue(src, dst, rbp):
    try:
        STATE["src"] = src
        STATE["dst"] = dst
        if ptr_ok(src, 256):
            if STATE["planter_watch_armed"] and src + 32 == STATE["planter"]:
                arm_region_watch("source_frame_prefix_32", src, 32)
            else:
                arm_region_watch("source_256", src, 256)
        else:
            log(f"SOURCE WATCH SKIP: {src:#x} does not span 256 readable RW bytes")
        # malloc requested 0xC8 (200) bytes, while a later operation reads 256.
        # If adjacent bytes are mapped, sample them as adjacent memory, not as
        # proven members of the same allocation.
        if ptr_ok(dst, 256):
            STATE["dst_span"] = 256
            arm_region_watch("staging_span_256", dst, 256)
            log("STAGING EXTENT: requested=200 observed_RW_span=256; bytes[200:256] "
                "are adjacent mapped memory, not proven part of malloc object")
        elif ptr_ok(dst, 200):
            STATE["dst_span"] = 200
            arm_region_watch("staging_requested_200", dst, 200)
            log("STAGING EXTENT: only requested 200-byte span is readable")
        else:
            STATE["dst_span"] = 0
            log(f"STAGING WATCH SKIP: {dst:#x} does not span 200 readable RW bytes")

        # The slot itself is repeatedly rewritten by flattened CFF blocks.
        # Track its qword without assuming every value is a planter pointer.
        slot_addr = rbp - 0x30
        slot_watch = arm_region_watch("frame_slot_rbp_minus_30", slot_addr, 8)
        STATE["slot_watch_armed"] = STATE["slot_watch_armed"] or slot_watch is not None

        # This is only a diagnostic sample. The slot is a mutable CFF carrier;
        # base discovery occurs at known base-load sites or at a verified store
        # operand, not by treating this one qword snapshot as authoritative.
        planter = ptr_from_slot(rbp, -0x30)
        log(f"PLANTER SLOT SNAPSHOT at post-malloc: [rbp-0x30]={planter:#x}; "
            "not accepted as a base until confirmed at a known load/store site")
    except Exception as e:
        log(f"ARM BUFFERS ERROR: {e}")
    gdb.execute("continue")


def install_after_entry(base):
    log("INSTALL STAGE: callback entered")
    try:
        gdb.execute("set language c", to_string=True)
        log("INSTALL STAGE: language configured")
        # Wide arrays cannot fit x86 debug-register watchpoints. Force GDB's
        # software implementation, which single-steps and compares the region.
        gdb.execute("set can-use-hw-watchpoints 0", to_string=True)
        log("INSTALL STAGE: software watchpoints selected")
        STATE["source_init_bp"] = SourceSlotStoreBP()
        log("INSTALL STAGE: source-slot breakpoint created")
        STATE["postmalloc_bp"] = PostMallocBP()
        log("INSTALL STAGE: post-malloc breakpoint created")
        STATE["copy_entry_bp"] = CopyEntryBP()
        log("INSTALL STAGE: copy-entry breakpoint created")
        for rva, reg_name in ((0xE243D, "$rdi"), (0xFAC8A, "$r12")):
            bp = PlanterBaseLoadBP(rva, reg_name)
            STATE["base_load_bps"].append(bp)
            log(f"INSTALL STAGE: base-load breakpoint {rva:#x} created")
        for rva, spec in WRITERS.items():
            bp = WriterSiteBP(rva, spec)
            STATE["writer_bps"].append(bp)
            log(f"INSTALL STAGE: writer breakpoint {rva:#x} created")
        for rva in MIXER_READS:
            bp = FirstMixerReadBP(rva)
            STATE["mixer_bps"].append(bp)
            log(f"INSTALL STAGE: mixer-read breakpoint {rva:#x} created")
        log(f"BASE={base:#x}; armed source-slot @{SOURCE_SLOT_STORE_RVA:#x}, "
            f"post-malloc @{POST_MALLOC_RVA:#x}, copy-entry @{COPY_ENTRY_RVA:#x}, "
            f"base-load sites 0xe243d/0xfac8a, "
            f"{len(WRITERS)} writer sites, "
            f"{len(MIXER_READS)} mixer-read sites; "
            f"unknown ranges={UNKNOWN_RANGES}")
    except Exception as e:
        log(f"INSTALL ERROR: {e}")
    log("INSTALL STAGE: requesting continue")
    gdb.execute("continue")


class EntryBP(gdb.Breakpoint):
    def __init__(self):
        # Keep this breakpoint enabled: vdfut768ig is called with several
        # opcodes (configuration/init and the actual transform). The later
        # static sites must only be attributed to the transform opcode.
        super().__init__("vdfut768ig", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True
        self.installed = False

    def stop(self):
        pc = rv("$pc")
        opcode = rv("$rdi") & 0xFFFFFFFF
        STATE["active_op"] = opcode
        if not self.installed:
            base = pc - ENTRY_RVA
            STATE["base"] = base
            self.installed = True
            log(f"FIRST vdfut768ig entry: pc={pc:#x} base={base:#x} opcode={opcode:#010x}")
            log("ENTRY STAGE: posting installer callback")
            gdb.post_event(lambda b=base: install_after_entry(b))
            log("ENTRY STAGE: installer callback queued")
            # Hold at the function's first instruction until all RVAs are armed.
            return True
        log(f"vdfut768ig entry: opcode={opcode:#010x} "
            f"transform={opcode == TRANSFORM_OPCODE}")
        return False


# Keep a handle to the entry BP and initialize a clean log.
with open(LOG, "w", encoding="utf-8") as f:
    f.write("planter trace started\n")

with open(os.path.join(OUT, "run.json"), "w", encoding="utf-8") as f:
    import json
    json.dump({"run_id": RUN_ID, "pid": os.getpid(), "created_unix": time.time(),
               "script_version": "v7", "entry_rva": ENTRY_RVA, "transform_opcode": TRANSFORM_OPCODE,
               "planter_size": PLANTER_SIZE, "tables": TABLES,
               "unknown_ranges": UNKNOWN_RANGES,
               "staging_requested": 200, "staging_observed_copy_span": 256},
              f, indent=2)

gdb.execute("set confirm off", to_string=True)
gdb.execute("set pagination off", to_string=True)
gdb.execute("set breakpoint pending on", to_string=True)
log(f"armed; output={OUT}; waiting for first vdfut768ig call")
STATE["entry_bp"] = EntryBP()