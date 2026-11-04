#!/usr/bin/env python3
"""Dynamic planter-genesis tracer for libCoreADI.so (GDB Python, v30).

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
watchpoint timing. At each mixer-read stop, the tracer samples the actual
[RBP-0x30] slot and preserves the object when it agrees with source+0x20 and
the known writer base, independently of the legacy four-permutation test.
The entry breakpoint tracks vdfut768ig opcodes, so init/config calls are not
mistaken for the provisioning transform.

Wide software watchpoints are deliberately disabled on the production trace
path: experiments showed that they destabilize the Bionic inferior. A bounded
set of three one-byte write probes is used only for sparse-window provenance;
each is retained only when GDB confirms a hardware watchpoint, with no software
fallback. Known static writer sites remain instrumented directly, and the
mutable frame slot is sampled at the sixteen mixer-read instruction sites.
"""

import csv
import gdb
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from planter_access import (SPARSE_WRITE_PROBE_OFFSETS, analyze_intel_address,
                            classify_mapped_address, parse_intel_memory_operands,
                            parse_proc_maps)

ENTRY_RVA = 0x87554
SOURCE_SLOT_STORE_RVA = 0xDD511
POST_MALLOC_RVA = 0xDD83B
COPY_ENTRY_RVA = 0xFB022
TRANSFORM_OPCODE = 0x716BD86C
MODULE_RVA_LIMIT = 0x200000
ZONE_PROBE_RVA = 0x24070
ZONE_PROBE_SIZE = 0x300

# Exact writer sites observed in the Android x86_64 libCoreADI.so.
# Each tuple: (name, base-register, index-register, displacement, value-register).
# The first two are the rolling writes into malloc(0xC8)'s staging buffer;
# the remaining six target the planter's known windows.
WRITERS = {
    0xFA9C1: ("staging_write_a", "$r9",  "$rsi", 0,      "$rbx"),
    0xFAA8F: ("staging_write_b", "$r11", "$rdx", 0,      "$rsi"),
    0xE24C9: ("fifth_1f30", "$rdi", "$r15", 0x1F30, "$rcx"),
    # Hardware tail probe at +0x1AFF confirmed this store by matching
    # its effective address and PC-after boundary in run 41378982858.
    0xE2508: ("fam2",       "$rdi", "$rcx", 0x1A00, "$r14"),
    # Hardware tail probe at +0x148F identified this exact byte store.
    0xE26AA: ("fam4",       "$r8",  "$rax", 0x1390, "$r13"),
    0xE25C2: ("fam3",       "$rdi", "$rax", 0x2460, "$r8"),
    0xFB05B: ("fam1_a",     "$r12", "$rsi", 0x0D60, "$rdx"),
    0xFB075: ("fam1_b",     "$r12", "$rsi", 0x0D60, "$rdx"),
}

# Selector/mixer read sites. Each reachable site samples the actual in-frame
# [RBP-0x30] object; a slot-anchored snapshot is distinct from the legacy
# four-permutation "final planter" classification.
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
    "module_region_24070_dumped": False,
    "global_install_started": False,
    "global_install_complete": False,
    "rva_install_started": False,
    "rva_install_complete": False,
    "entry_bp": None,
    "base_load_bps": [],
    "active_op": None,
    "source_init_bp": None,
    "source_init": None,
    "source_initial": None,
    "postmalloc_bp": None,
    "copy_entry_bp": None,
    "writer_bps": [],
    "fam1_candidate_bp": None,
    "mixer_bps": [],
    "watchers": [],
    "sparse_write_bps": [],
    "sparse_write_probe_status": {},
    "sparse_write_hits": {},
    "src": None,
    "dst": None,
    "dst_size": 200,  # allocator request; not the observed access span
    "dst_span": 256,
    "planter": None,
    "pre_planter_base": None,
    "pre_planter_snapshot": None,
    "slot_sample_count": 0,
    "slot_last_ptr": None,
    "slot_last_data": None,
    "slot_anchor_dumped": False,
    "planter_watch_armed": False,
    "final_dumped": False,
    "postmalloc_seen": False,
    "slot_watch_armed": False,
    "slot_pointer_watch_bp": None,
    "slot_pointer_watch_addr": None,
    "slot_pointer_watch_initial": None,
    "slot_pointer_watch_hits": 0,
    "writer_stats": {},
    "writer_callback_hits": {},
    "writer_bases": {},
    "mixer_candidate_addrs": set(),
    "reader_hits": {},
    "planter_scan_done": False,
    "planter_scan_base": None,
    "planter_mismatch": False,
    "signal_seen": False,
    "started": time.time(),
}


def log(message):
    stamp = time.strftime("%H:%M:%S")
    line = f"[{stamp}] {message}"
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    gdb.write(line + "\n")


def writer_callback_event(event, rva, name, status):
    """Audit direct writer breakpoint lifecycle independently of writer_events."""
    try:
        pc = rv("$pc")
        base = STATE.get("base")
        pc_rva = f"{pc - base:#x}" if base is not None and pc >= base else "na"
        opcode = STATE.get("active_op")
        path = os.path.join(OUT, "writer_callback_events.csv")
        with open(path, "a", newline="", encoding="utf-8") as stream:
            csv.writer(stream).writerow([
                event, f"{rva:#x}", name,
                f"{opcode:#x}" if opcode is not None else "na",
                pc_rva, status,
            ])
    except Exception as exc:
        log(f"WRITER CALLBACK AUDIT ERROR: {name} {type(exc).__name__}: {exc}")


def rv(expr):
    return int(gdb.parse_and_eval(expr)) & 0xFFFFFFFFFFFFFFFF


def capture_zone_probe_region():
    """Capture 0x300 bytes around the live module-relative fourth-family read base."""
    if STATE["module_region_24070_dumped"]:
        return
    try:
        module_base = STATE.get("base")
        if module_base is None:
            return
        address = module_base + ZONE_PROBE_RVA
        data = bytes(gdb.selected_inferior().read_memory(address, ZONE_PROBE_SIZE))
        path = os.path.join(OUT, "module_region_24070.bin")
        with open(path, "wb") as stream:
            stream.write(data)
        STATE["module_region_24070_dumped"] = True
        log(f"MODULE REGION CAPTURE: rva=+{ZONE_PROBE_RVA:#x} size={len(data):#x}")
    except Exception as exc:
        log(f"MODULE REGION CAPTURE ERROR: {type(exc).__name__}: {exc}")


def capture_mixer_memory_operands(site_rva, object_base):
    """Record dynamic effective addresses and classify their backing mappings."""
    try:
        disassembly = gdb.execute("x/i $pc", to_string=True).strip()
        instruction = disassembly.split(":", 1)[1].strip() if ":" in disassembly else disassembly
        operands = parse_intel_memory_operands(instruction)
        hit = STATE["reader_hits"].get(site_rva, 0) + 1
        STATE["reader_hits"][site_rva] = hit
        if not operands:
            log(f"MIXER ACCESS site={site_rva:#x} hit={hit}: no Intel memory operand parsed")
            return
        register_names = (
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        )
        registers = {}
        for name in register_names:
            try:
                registers[name] = rv("$" + name)
            except Exception:
                pass
        pid = gdb.selected_inferior().pid
        with open(f"/proc/{pid}/maps", "r", encoding="ascii", errors="replace") as maps_file:
            mappings = parse_proc_maps(maps_file.read())
        path = os.path.join(OUT, "reader_events.csv")
        new_file = not os.path.exists(path)
        with open(path, "a", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            if new_file:
                writer.writerow([
                    "site_rva", "hit", "operand_number", "expression",
                    "effective_address", "object_offset", "anchor_register",
                    "table_base_offset", "index_offset", "index_registers",
                    "mapping_label", "mapping_kind", "mapped_offset",
                    "mapped_base_offset", "mapped_anchor_register",
                    "mapped_index_offset", "mapped_index_registers",
                    "module_base_offset", "module_anchor_register",
                    "module_index_offset", "module_index_registers",
                    "operand_expression", "width", "instruction",
                ])
            for number, (expression, width) in enumerate(operands):
                result = analyze_intel_address(
                    expression, registers, object_base, PLANTER_SIZE,
                    module_base=STATE["base"], module_size=MODULE_RVA_LIMIT,
                )
                if result is None:
                    writer.writerow([
                        f"{site_rva:#x}", hit, number, expression, "na", "na",
                        "na", "na", "na", "na", "unresolved", "unresolved",
                        "na", "na", "na", "na", "na", expression,
                        width or "na", instruction,
                    ])
                    log(f"MIXER ACCESS site={site_rva:#x} hit={hit} "
                        f"operand={number} parse=unsupported width={width or 'unknown'}")
                    continue
                effective = result["effective_address"]
                if result["module_base_offset"] == ZONE_PROBE_RVA:
                    capture_zone_probe_region()
                mapping_info = classify_mapped_address(
                    effective, mappings, STATE["base"], MODULE_RVA_LIMIT
                )
                mapping_label = mapping_info["label"] if mapping_info else "unmapped"
                mapping_kind = mapping_info["kind"] if mapping_info else "unmapped"
                mapping_offset = mapping_info["offset"] if mapping_info else None
                if mapping_info and mapping_info.get("mapping") is not None:
                    result = analyze_intel_address(
                        expression, registers, object_base, PLANTER_SIZE,
                        mapping_info["mapping"], STATE["base"], MODULE_RVA_LIMIT,
                    )
                object_offset = result["object_offset"]
                table_base = result["table_base_offset"]
                index_offset = result["index_offset"]
                mapped_base = result["mapped_base_offset"]
                mapped_index = result["mapped_index_offset"]
                writer.writerow([
                    f"{site_rva:#x}", hit, number, expression, f"{effective:#x}",
                    f"{object_offset:#x}" if object_offset is not None else "outside",
                    result["anchor_register"] or "na",
                    f"{table_base:+#x}" if table_base is not None else "na",
                    f"{index_offset:+#x}" if index_offset is not None else "na",
                    ",".join(result["index_registers"]) or "na",
                    mapping_label, mapping_kind,
                    f"{mapping_offset:#x}" if mapping_offset is not None else "na",
                    f"{mapped_base:+#x}" if mapped_base is not None else "na",
                    result["mapped_anchor_register"] or "na",
                    f"{mapped_index:+#x}" if mapped_index is not None else "na",
                    ",".join(result["mapped_index_registers"]) or "na",
                    f"{result['module_base_offset']:+#x}" if result["module_base_offset"] is not None else "na",
                    result["module_anchor_register"] or "na",
                    f"{result['module_index_offset']:+#x}" if result["module_index_offset"] is not None else "na",
                    ",".join(result["module_index_registers"]) or "na",
                    expression, width or "na", instruction,
                ])
                offset_text = f"{object_offset:#x}" if object_offset is not None else "outside"
                if table_base is not None:
                    target_text = f"planter{table_base:+#x}"
                    index_text = f"{index_offset:+#x}"
                elif result["module_base_offset"] is not None:
                    target_text = f"libCoreADI.so{result['module_base_offset']:+#x}"
                    index_text = f"{result['module_index_offset']:+#x}"
                elif mapped_base is not None:
                    target_text = f"{mapping_label}:{mapped_base:+#x}"
                    index_text = f"{mapped_index:+#x}"
                else:
                    target_text = f"{mapping_label}@{mapping_offset if mapping_offset is not None else 'na'}"
                    index_text = "unresolved"
                log(f"MIXER ACCESS site={site_rva:#x} hit={hit} operand={number} "
                    f"target={target_text} index={index_text} "
                    f"object_offset={offset_text} width={width or 'unknown'} "
                    f"expression={expression}")
    except Exception as exc:
        log(f"MIXER ACCESS ERROR site={site_rva:#x}: {type(exc).__name__}: {exc}")


def on_inferior_stop(event):
    """Record crash-site RVAs without persisting absolute addresses/registers."""
    signal = getattr(event, "stop_signal", None)
    if signal not in ("SIGSEGV", "SIGBUS", "SIGILL", "SIGABRT"):
        return
    if STATE["signal_seen"]:
        return
    STATE["signal_seen"] = True
    try:
        pc = rv("$pc")
        base = STATE.get("base")
        if base is not None and base <= pc < base + MODULE_RVA_LIMIT:
            pc_text = f"{pc - base:#x}"
        else:
            pc_text = "outside-module"
        opcode = STATE.get("active_op")
        opcode_text = f"{opcode:#010x}" if opcode is not None else "unknown"
        log(f"SIGNAL STOP: name={signal} pc_rva={pc_text} active_opcode={opcode_text}")

        # Raw disassembly/backtrace stays only in the ephemeral runner log.
        # The published report extracts module-relative frame offsets only.
        try:
            disassembly = gdb.execute("x/8i $pc", to_string=True)
            for raw in disassembly.splitlines():
                match = re.search(r":\s*(.*)$", raw)
                if match and match.group(1).strip():
                    log("SIGNAL INSTRUCTION: " + match.group(1).strip())
        except Exception as exc:
            log(f"SIGNAL DISASSEMBLY ERROR: {type(exc).__name__}")

        try:
            backtrace = gdb.execute("bt 12", to_string=True)
            for raw in backtrace.splitlines():
                match = re.match(r"#(\d+)\s+0x([0-9a-fA-F]+)(?:\s+in\s+([^ (]+))?", raw.strip())
                if not match:
                    continue
                frame_no = int(match.group(1))
                address = int(match.group(2), 16)
                if base is not None and base <= address < base + MODULE_RVA_LIMIT:
                    location = f"rva={address - base:#x}"
                else:
                    location = "external"
                symbol = match.group(3) or "unknown"
                log(f"SIGNAL FRAME: n={frame_no} {location} symbol={symbol[:100]}")
        except Exception as exc:
            log(f"SIGNAL BACKTRACE ERROR: {type(exc).__name__}")
    except Exception as exc:
        log(f"SIGNAL HANDLER ERROR: {type(exc).__name__}")


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
        # Count callback entry before register/memory reads. This separates
        # "breakpoint never fired" from "callback fired but sampling failed".
        STATE["writer_callback_hits"][self.name] = (
            STATE["writer_callback_hits"].get(self.name, 0) + 1
        )
        writer_callback_event("enter", self.rva, self.name, "entered")
        log(f"WRITER CALLBACK ENTER: name={self.name} rva={self.rva:#x} "
            f"hit={STATE['writer_callback_hits'][self.name]}")
        # These static store sites are shared by preparatory/configuration
        # vdfut768ig calls as well as the final transform. Record every opcode.
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
            # Per-instruction CSV captures even same-value stores. Publish only
            # base-minus-source deltas in the redacted report.
            src_now = STATE["src"]
            source_delta = base - src_now if src_now is not None else None
            STATE["writer_bases"][self.name] = base
            with open(os.path.join(OUT, "writer_events.csv"), "a", encoding="utf-8") as f:
                if f.tell() == 0:
                    f.write("rva,name,ea,before,value,base,index,disp,active_opcode,source_delta\n")
                delta_text = f"{source_delta:+#x}" if source_delta is not None else "na"
                f.write(f"{self.rva:#x},{self.name},{ea:#x},{before_s},{value:02x},"
                        f"{base:#x},{index:#x},{self.disp:#x},{STATE['active_op']:#x},{delta_text}\n")
            st = STATE["writer_stats"].setdefault(self.name, {
                "hits": 0, "min_index": None, "max_index": None,
                "min_ea": None, "max_ea": None, "changed": 0,
                "base_match_hits": 0, "index_in_expected_span": 0,
                "source_delta_min": None, "source_delta_max": None,
            })
            if source_delta is not None:
                st["source_delta_min"] = (source_delta if st["source_delta_min"] is None
                                          else min(st["source_delta_min"], source_delta))
                st["source_delta_max"] = (source_delta if st["source_delta_max"] is None
                                          else max(st["source_delta_max"], source_delta))
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
            writer_callback_event("sampled", self.rva, self.name, "ok")
        except Exception as e:
            writer_callback_event("sample-error", self.rva, self.name, "callback-error")
            log(f"STORE_SITE ERROR rva={self.rva:#x}: {type(e).__name__}: {e}")

        # The first two sites write the malloc staging buffer, not the planter.
        # Only the six statically identified family/tail stores may nominate a
        # planter base. This avoids mistaking a large RW heap VMA for an object:
        # ptr_ok() alone proves mapping, not allocation identity.
        planter_writer_sites = {0xE24C9, 0xE2508, 0xE25C2, 0xE26AA, 0xFB05B, 0xFB075}
        if (self.rva in planter_writer_sites and base is not None
                and STATE["planter"] is None and ptr_ok(base, PLANTER_SIZE)):
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
                STATE["planter"] = base
                log(f"PLANTER BASE IDENTIFIED: method=writer-operand site={self.rva:#x} "
                    f"source_plus_0x20=True; snapshot=0x{PLANTER_SIZE:x}")
                write_blob("planter.at_writer_candidate.bin", read_mem(base, PLANTER_SIZE))
                return False
            expected = (src + 32) if src is not None else None
            log(f"REJECTING PLANTER CANDIDATE {base:#x}: "
                f"source+0x20={expected!r} (source pointer must be captured first)")
        return False


class SparseWindowWriteBP(gdb.Breakpoint):
    """Single-byte write probe; reject GDB's software-watchpoint fallback."""
    def __init__(self, name, object_offset, address):
        self.name = name
        self.object_offset = object_offset
        self.address = address
        super().__init__(f"*(unsigned char *)0x{address:x}",
                         gdb.BP_WATCHPOINT, gdb.WP_WRITE, internal=False)
        self.silent = True
        STATE["sparse_write_hits"][name] = 0

    def stop(self):
        try:
            count = STATE["sparse_write_hits"].get(self.name, 0) + 1
            STATE["sparse_write_hits"][self.name] = count
            pc = rv("$pc")
            base = STATE.get("base")
            pc_rva = f"{pc - base:#x}" if base is not None and pc >= base else "na"
            probe_writer_names = {
                "fam2_tail": "fam2",
                "fam4_tail": "fam4",
                "fam3_control_tail": "fam3",
            }
            writer_name = probe_writer_names.get(self.name)
            expected_rva = next(
                (rva for rva, spec in WRITERS.items() if spec[0] == writer_name),
                None,
            )
            instruction = "na"
            effective_address_match = "na"
            software_bp_enabled = "na"
            pc_after_matches_next = "na"
            observed_store_rva = "na"
            observed_store_instruction = "na"
            observed_store_width = "na"
            observed_store_ea_match = "na"
            if expected_rva is not None and base is not None:
                try:
                    dis = gdb.execute(
                        f"x/2i {base + expected_rva:#x}", to_string=True
                    ).strip().splitlines()
                    parsed = []
                    for line in dis:
                        match = re.match(
                            r"^\s*(?:=>\s*)?(0x[0-9a-fA-F]+)(?:\s+<[^>]+>)?:\s*(.*)$",
                            line,
                        )
                        if match:
                            parsed.append((int(match.group(1), 16), match.group(2).strip()))
                    if parsed:
                        instruction = parsed[0][1]
                    if len(parsed) >= 2:
                        instruction_length = parsed[1][0] - (base + expected_rva)
                        pc_after_matches_next = (
                            "yes" if instruction_length > 0
                            and pc == base + expected_rva + instruction_length else "no"
                        )
                except Exception as exc:
                    instruction = f"disassembly-error:{type(exc).__name__}"
                candidate_bp = next(
                    (bp for bp in STATE["writer_bps"]
                     if getattr(bp, "rva", None) == expected_rva),
                    None,
                )
                if candidate_bp is not None:
                    software_bp_enabled = "yes" if candidate_bp.enabled else "no"
                try:
                    spec = WRITERS[expected_rva]
                    candidate_base = rv(spec[1])
                    candidate_index = rv(spec[2])
                    candidate_ea = (candidate_base + candidate_index + spec[3]) & 0xFFFFFFFFFFFFFFFF
                    effective_address_match = "yes" if candidate_ea == self.address else "no"
                except Exception:
                    effective_address_match = "unavailable"

            # Resolve the store using a trusted instruction boundary first.
            # E24C9 is a confirmed instruction start (fifth_1f30 writer BP).
            # Linear disassembly from there avoids accepting arbitrary x86
            # decodes that begin in the middle of another instruction.
            register_values = {
                name: rv("$" + name)
                for name in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                             "rbp", "rsp", "r8", "r9", "r10", "r11",
                             "r12", "r13", "r14", "r15", "eflags")
            }
            observed_store_method = "not-found"
            pc_instruction = "na"
            near_pc_disassembly = "na"
            actual_candidates = []

            def parse_disassembly(output):
                decoded = []
                for line in output.splitlines():
                    match = re.match(
                        r"^\s*(?:=>\s*)?(0x[0-9a-fA-F]+)(?:\s+<[^>]+>)?:\s*(.*)$",
                        line,
                    )
                    if match:
                        decoded.append((int(match.group(1), 16), match.group(2).strip()))
                return decoded

            def candidate_for_instruction(start_pc, asm):
                for expression, width in parse_intel_memory_operands(asm):
                    resolved = analyze_intel_address(expression, register_values)
                    if resolved is None:
                        continue
                    ea = resolved["effective_address"]
                    size = width or 1
                    if ea <= self.address < ea + size:
                        return (start_pc, asm, width, ea, "explicit")
                # REP string stores can leave RIP on the instruction itself;
                # their implicit destination is ES:RDI and RDI is advanced
                # after the element that triggered the debug exception.
                tokens = asm.lower().replace(",", " ").split()
                while tokens and tokens[0] in (
                    "rep", "repe", "repz", "repne", "repnz", "lock"
                ):
                    tokens.pop(0)
                if tokens:
                    mnemonic = tokens[0]
                    string_widths = {
                        "stosb": 1, "stosw": 2, "stosd": 4, "stosq": 8,
                        "movsb": 1, "movsw": 2, "movsd": 4, "movsq": 8,
                    }
                    width = string_widths.get(mnemonic)
                    if width is not None:
                        direction = -1 if register_values["eflags"] & 0x400 else 1
                        last_ea = (
                            register_values["rdi"] - direction * width
                        ) & 0xFFFFFFFFFFFFFFFF
                        if last_ea <= self.address < last_ea + width:
                            return (start_pc, asm, width, last_ea, "implicit-string")
                return None

            try:
                current = parse_disassembly(
                    gdb.execute(f"x/1i {pc:#x}", to_string=True)
                )
                if current:
                    pc_instruction = current[0][1]
                near = parse_disassembly(
                    gdb.execute(f"x/32i {max(0, pc - 0x80):#x}", to_string=True)
                )
                near_pc_disassembly = "; ".join(
                    f"{addr - base:+#x} {asm}" if addr >= base else f"{addr:#x} {asm}"
                    for addr, asm in near
                )

                # E24C9 is a directly observed, enabled writer instruction and
                # lies before all three current watchpoint PCs in this function.
                anchor = base + 0xE24C9
                anchored = parse_disassembly(
                    gdb.execute(f"x/4096i {anchor:#x}", to_string=True)
                )
                anchored_matches = []
                for index, (addr, asm) in enumerate(anchored):
                    next_is_pc = (
                        index + 1 < len(anchored)
                        and anchored[index + 1][0] == pc
                    )
                    same_pc_rep = addr == pc
                    if not (next_is_pc or same_pc_rep):
                        continue
                    candidate = candidate_for_instruction(addr, asm)
                    if candidate is not None:
                        anchored_matches.append(candidate)

                if anchored_matches:
                    actual_candidates.extend(anchored_matches)
                    observed_store_method = "linear-from-confirmed-E24C9"
                else:
                    # Fallback only: a local backwards sweep is useful for
                    # diagnostics but is not treated as a trusted boundary.
                    for back in range(1, 16):
                        candidate_pc = pc - back
                        decoded = parse_disassembly(
                            gdb.execute(f"x/2i {candidate_pc:#x}", to_string=True)
                        )
                        if len(decoded) < 2 or decoded[1][0] != pc:
                            continue
                        candidate = candidate_for_instruction(decoded[0][0], decoded[0][1])
                        if candidate is not None:
                            actual_candidates.append(candidate)
                    if actual_candidates:
                        observed_store_method = "unaligned-local-backscan"

                unique = {
                    (item[0], item[1], item[2], item[3], item[4])
                    for item in actual_candidates
                }
                if len(unique) == 1:
                    start_pc, asm, width, _ea, kind = next(iter(unique))
                    observed_store_rva = (
                        f"{start_pc - base:#x}" if start_pc >= base else "outside-module"
                    )
                    observed_store_instruction = asm
                    observed_store_width = str(width) if width is not None else "unknown"
                    observed_store_ea_match = "yes"
                    observed_store_method += ":" + kind
                elif len(unique) > 1:
                    observed_store_rva = f"ambiguous:{len(unique)}"
                    observed_store_ea_match = "ambiguous"
                else:
                    observed_store_ea_match = "no-store-candidate-matched"
            except Exception as exc:
                observed_store_ea_match = f"scan-error:{type(exc).__name__}"
                observed_store_method = "scan-error"
            path = os.path.join(OUT, "sparse_write_events.csv")
            with open(path, "a", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerow([
                    "hit", "ok", self.name, f"{self.object_offset:#x}",
                    count, pc_rva,
                    f"{expected_rva:#x}" if expected_rva is not None else "na",
                    instruction, software_bp_enabled, effective_address_match,
                    pc_after_matches_next, observed_store_rva,
                    observed_store_instruction, observed_store_width,
                    observed_store_ea_match, observed_store_method,
                    pc_instruction, near_pc_disassembly,
                ])
            log(f"SPARSE WRITE PROBE HIT: name={self.name} "
                f"object_offset={self.object_offset:#x} hit={count} "
                f"pc_after_rva={pc_rva} candidate_store_rva={expected_rva!r} "
                f"candidate_instruction={instruction!r} "
                f"software_bp_enabled={software_bp_enabled} "
                f"candidate_ea_matches_watch_address={effective_address_match} "
                f"pc_after_is_next_instruction={pc_after_matches_next} "
                f"observed_store_rva={observed_store_rva} "
                f"observed_store_instruction={observed_store_instruction!r} "
                f"observed_store_width={observed_store_width} "
                f"observed_store_ea_match={observed_store_ea_match} "
                f"observed_store_method={observed_store_method} "
                f"pc_instruction={pc_instruction!r} "
                f"near_pc_disassembly={near_pc_disassembly!r}")
        except Exception as exc:
            log(f"SPARSE WRITE PROBE CALLBACK ERROR: name={self.name} "
                f"{type(exc).__name__}: {exc}")
        return False



def bounded_source_delta(value, source):
    """Return only small source-relative offsets; suppress unrelated stack/scalar data."""
    if source is None:
        return "na"
    delta = value - source
    return f"{delta:+#x}" if abs(delta) <= 0x100000 else "na"


class SlotPointerWriteBP(gdb.Breakpoint):
    """Hardware-only write watchpoint for the active frame's [RBP-0x30] qword."""
    def __init__(self, address, initial):
        self.address = address
        self.previous = initial
        self.hits = 0
        super().__init__(
            f"*(unsigned long long *)0x{address:x}",
            gdb.BP_WATCHPOINT,
            gdb.WP_WRITE,
            internal=False,
        )
        self.silent = True

    def stop(self):
        try:
            current = int.from_bytes(read_mem(self.address, 8), "little")
            previous = self.previous
            self.previous = current
            self.hits += 1
            STATE["slot_pointer_watch_hits"] = self.hits

            source = STATE.get("src")
            old_delta = bounded_source_delta(previous, source)
            new_delta = bounded_source_delta(current, source)
            matches = source is not None and current == source + 0x20
            mapped = bool(current and ptr_ok(current, PLANTER_SIZE))

            pc = rv("$pc")
            base = STATE.get("base")
            pc_rva = f"{pc - base:#x}" if base is not None and pc >= base else "na"
            path = os.path.join(OUT, "slot_pointer_events.csv")
            with open(path, "a", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerow([
                    "hit", "ok", pc_rva, old_delta, new_delta,
                    "yes" if matches else "no", "yes" if mapped else "no",
                    "yes" if current != previous else "no",
                ])
            log(
                f"SLOT POINTER WRITE: hit={self.hits} pc_after_rva={pc_rva} "
                f"old_source_delta={old_delta} new_source_delta={new_delta} "
                f"matches_source_plus_0x20={matches} span_0x2700_mapped={mapped} "
                f"value_changed={current != previous}"
            )
            if matches:
                # This watchpoint is anchored to a stack address, not a
                # lifetime-tracked variable. Once the target pointer is seen,
                # later writes may be reuse of the same stack slot by other frames.
                self.enabled = False
                log("SLOT POINTER WATCH DISABLED: source+0x20 anchor captured")
            elif self.hits >= 128:
                self.enabled = False
                log("SLOT POINTER WATCH DISABLED: 128-hit safety limit reached")
        except Exception as exc:
            log(f"SLOT POINTER WATCH CALLBACK ERROR: {type(exc).__name__}: {exc}")
        return False


def arm_slot_pointer_hardware_watchpoint():
    """Arm one hardware-only qword watchpoint; never accept GDB's software fallback."""
    address = STATE.get("slot_pointer_watch_addr")
    initial = STATE.get("slot_pointer_watch_initial")
    path = os.path.join(OUT, "slot_pointer_events.csv")
    with open(path, "w", newline="", encoding="utf-8") as stream:
        csv.writer(stream).writerow([
            "event", "status", "pc_after_rva", "old_source_delta",
            "new_source_delta", "new_is_source_plus_20",
            "new_span_mapped", "value_changed",
        ])

    if address is None or initial is None or not ptr_ok(address, 8):
        with open(path, "a", newline="", encoding="utf-8") as stream:
            csv.writer(stream).writerow([
                "setup", "no-slot-anchor", "na", "na", "na", "no", "no", "no"
            ])
        log("SLOT POINTER WATCH NOT ARMED: initial frame-slot qword unavailable")
        return

    stage = "enable-hardware-watchpoints"
    try:
        gdb.execute("set can-use-hw-watchpoints 1", to_string=True)
        stage = "create-watchpoint"
        bp = SlotPointerWriteBP(address, initial)
        stage = "inspect-watchpoint"
        details = gdb.execute(f"info breakpoints {bp.number}", to_string=True)
        if not re.search(r"(?:hardware|hw)\s+watchpoint", details, re.IGNORECASE):
            bp.delete()
            with open(path, "a", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerow([
                    "setup", "software-rejected", "na", "na", "na", "no", "no", "no"
                ])
            log("SLOT POINTER WATCH REJECTED: GDB did not create a hardware watchpoint")
            return

        stage = "record-setup"
        STATE["slot_pointer_watch_bp"] = bp
        STATE["slot_watch_armed"] = True
        source = STATE.get("src")
        delta = bounded_source_delta(initial, source)
        initial_match = source is not None and initial == source + 0x20
        initial_mapped = bool(initial and ptr_ok(initial, PLANTER_SIZE))
        with open(path, "a", newline="", encoding="utf-8") as stream:
            csv.writer(stream).writerow([
                "setup", "hardware", "na", "na", delta,
                "yes" if initial_match else "no",
                "yes" if initial_mapped else "no", "no",
            ])
        log(
            f"SLOT POINTER WATCH ARMED: hardware=yes initial_source_delta={delta} "
            f"initial_matches_source_plus_0x20={initial_match} "
            f"initial_span_0x2700_mapped={initial_mapped}"
        )
    except Exception as exc:
        status = f"setup-error:{stage}:{type(exc).__name__}"
        with open(path, "a", newline="", encoding="utf-8") as stream:
            csv.writer(stream).writerow([
                "setup", status, "na", "na", "na", "no", "no", "no"
            ])
        log(f"SLOT POINTER WATCH SETUP ERROR: stage={stage} "
            f"type={type(exc).__name__}: {exc}")

def arm_sparse_window_write_probes():
    """Arm three 1-byte hardware probes after the pre-transform anchor exists."""
    path = os.path.join(OUT, "sparse_write_events.csv")
    with open(path, "w", newline="", encoding="utf-8") as stream:
        csv.writer(stream).writerow([
            "event", "status", "name", "object_offset", "hit", "pc_after_rva",
            "candidate_writer_rva", "candidate_instruction", "software_bp_enabled",
            "candidate_ea_matches_watch_address", "pc_after_matches_next_instruction",
            "observed_store_rva", "observed_store_instruction", "observed_store_width",
            "observed_store_ea_match", "observed_store_method",
            "pc_instruction", "near_pc_disassembly",
        ])

    def record_setup(name, status, offset):
        with open(path, "a", newline="", encoding="utf-8") as stream:
            csv.writer(stream).writerow([
                "setup", status, name, f"{offset:#x}", 0, "na",
                "na", "na", "na", "na", "na", "na", "na", "na", "na", "na", "na", "na",
            ])

    source = STATE.get("src")
    early = STATE.get("pre_planter_snapshot")
    base = source + 0x20 if source is not None else None
    if base is None or early is None or len(early) != PLANTER_SIZE:
        log("SPARSE WRITE PROBES NOT ARMED: pre-transform source+0x20 snapshot unavailable")
        for name, offset in SPARSE_WRITE_PROBE_OFFSETS:
            STATE["sparse_write_probe_status"][name] = "no-anchor"
            record_setup(name, "no-anchor", offset)
        return

    try:
        gdb.execute("set can-use-hw-watchpoints 1", to_string=True)
    except Exception as exc:
        log(f"SPARSE WRITE PROBES NOT ARMED: hardware-watchpoint setting failed "
            f"({type(exc).__name__})")
        for name, offset in SPARSE_WRITE_PROBE_OFFSETS:
            STATE["sparse_write_probe_status"][name] = "setting-error"
            record_setup(name, "setting-error", offset)
        return

    for name, offset in SPARSE_WRITE_PROBE_OFFSETS:
        address = base + offset
        if not ptr_ok(address, 1):
            STATE["sparse_write_probe_status"][name] = "unmapped"
            record_setup(name, "unmapped", offset)
            log(f"SPARSE WRITE PROBE NOT ARMED: name={name} "
                f"object_offset={offset:#x} byte_not_mapped")
            continue
        bp = None
        try:
            bp = SparseWindowWriteBP(name, offset, address)
            details = gdb.execute(f"info breakpoints {bp.number}", to_string=True)
            if not re.search(r"(?:hardware|hw)\s+watchpoint", details, re.IGNORECASE):
                bp.delete()
                STATE["sparse_write_probe_status"][name] = "software-rejected"
                record_setup(name, "software-rejected", offset)
                log(f"SPARSE WRITE PROBE REJECTED: name={name} "
                    f"object_offset={offset:#x} gdb_did_not_create_hardware_watchpoint")
                continue
            STATE["sparse_write_bps"].append(bp)
            STATE["sparse_write_probe_status"][name] = "hardware"
            record_setup(name, "hardware", offset)
            log(f"SPARSE WRITE PROBE ARMED: name={name} "
                f"object_offset={offset:#x} hardware=yes")
        except Exception as exc:
            STATE["sparse_write_probe_status"][name] = "setup-error"
            record_setup(name, "setup-error", offset)
            log(f"SPARSE WRITE PROBE SETUP ERROR: name={name} "
                f"object_offset={offset:#x} {type(exc).__name__}: {exc}")
            try:
                if bp is not None and bp.is_valid():
                    bp.delete()
            except Exception:
                pass


class SourceSlotStoreBP(gdb.Breakpoint):
    """Capture RCX at 0xDD511; continue through a GDB command list."""
    def __init__(self):
        super().__init__(f"*{STATE['base'] + SOURCE_SLOT_STORE_RVA:#x}",
                         gdb.BP_BREAKPOINT, internal=False)
        self.silent = True
        self.done = False
        # Command lists run after stop() returns; no nested continue is posted
        # back into GDB's Python UI event loop.
        self.commands = """silent
python
arm_slot_pointer_hardware_watchpoint()
arm_sparse_window_write_probes()
end
continue
"""

    def stop(self):
        if self.done or STATE["active_op"] != TRANSFORM_OPCODE:
            return False
        self.done = True
        src = rv("$rcx")
        rbp = rv("$rbp")
        slot_addr = rbp - 0x30
        STATE["slot_pointer_watch_addr"] = slot_addr
        try:
            STATE["slot_pointer_watch_initial"] = int.from_bytes(
                read_mem(slot_addr, 8), "little"
            )
        except Exception as exc:
            STATE["slot_pointer_watch_initial"] = None
            log(f"SLOT POINTER INITIAL READ ERROR: {type(exc).__name__}: {exc}")
        slot_before = ptr_from_slot(rbp, -0x11A8)
        STATE["source_init"] = src
        STATE["src"] = src
        log(f"SOURCE SLOT STORE rva={SOURCE_SLOT_STORE_RVA:#x} "
            f"RCX_source={src:#x} prior_slot={slot_before:#x} rbp={rbp:#x}")
        if ptr_ok(src, 256):
            initial = read_mem(src, 256)
            STATE["source_initial"] = initial
            write_blob("source.at_dd511.bin", initial)
            log("SOURCE INITIAL SNAPSHOT: captured 256 bytes at the source-slot store")
        else:
            log("SOURCE INITIAL SNAPSHOT: skipped; source is not a readable RW 256-byte span")

        # Preserve the full source+0x20 candidate before the transform writes
        # its tables. The 256-byte source overlap alone cannot distinguish a
        # true planter from a similarly shaped CFF object.
        early_base = src + 0x20
        if ptr_ok(early_base, PLANTER_SIZE):
            STATE["pre_planter_base"] = early_base
            STATE["pre_planter_snapshot"] = read_mem(early_base, PLANTER_SIZE)
            write_blob("planter.source_plus_20.at_dd511.bin",
                       STATE["pre_planter_snapshot"])
            slot_now = ptr_from_slot(rbp, -0x30)
            log(f"EARLY PLANTER SOURCE-ANCHOR: mapped=True "
                f"slot_eq_source_plus_0x20={slot_now == early_base}")
        else:
            log("EARLY PLANTER SOURCE-ANCHOR: mapped=False")
        return True


class PostMallocBP(gdb.Breakpoint):
    """At 0xDD83B, snapshot allocator buffers without installing software watchpoints."""
    def __init__(self):
        super().__init__(f"*{STATE['base'] + POST_MALLOC_RVA:#x}", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True
        self.done = False
        self.commands = """silent
continue
"""

    def stop(self):
        if self.done or STATE["active_op"] != TRANSFORM_OPCODE:
            return False
        self.done = True
        rbp = rv("$rbp")
        src = ptr_from_slot(rbp, -0x11A8)
        dst = rv("$rax")
        init_src = STATE["source_init"]
        STATE["src"] = src
        STATE["dst"] = dst
        log(f"POST_MALLOC rva={POST_MALLOC_RVA:#x} "
            f"source_pointer_unchanged={init_src is None or init_src == src} "
            f"destination_valid_200={ptr_ok(dst, 200)}")

        early_source = STATE.get("source_initial")
        if early_source is not None and ptr_ok(src, 256):
            current_source = read_mem(src, 256)
            changed = [i for i, (a, b) in enumerate(zip(early_source, current_source)) if a != b]
            log(f"SOURCE DELTA to post-malloc: changed={len(changed)}/256; "
                f"first_indices={[hex(i) for i in changed[:24]]}")
            write_blob("source.at_postmalloc.bin", current_source)

        if ptr_ok(dst, 256):
            STATE["dst_span"] = 256
            write_blob("staging.at_postmalloc.span_256.bin", read_mem(dst, 256))
            log("STAGING INITIAL SNAPSHOT: 256 mapped bytes; bytes[200:256] remain adjacent memory, not proven allocation-owned")
        elif ptr_ok(dst, 200):
            STATE["dst_span"] = 200
            write_blob("staging.at_postmalloc.span_200.bin", read_mem(dst, 200))
            log("STAGING INITIAL SNAPSHOT: requested 200-byte span")
        else:
            STATE["dst_span"] = 0
            log("STAGING INITIAL SNAPSHOT: skipped; destination is not a readable RW span")

        slot = ptr_from_slot(rbp, -0x30)
        log(f"PLANTER SLOT SNAPSHOT at post-malloc: mapped={ptr_ok(slot, PLANTER_SIZE)}; "
            "mutable CFF carrier, not accepted as planter base")
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


def scan_planter_memory(rbp, rsp, rva):
    """Find the four-permutation planter signature in mapped RW memory.

    Mirrors tools/planter_scan.py but prefers a pointer referenced from the
    active frame. Raw candidates are written only to the ephemeral run dir.
    """
    if STATE["planter_scan_done"]:
        return STATE["planter_scan_base"]
    STATE["planter_scan_done"] = True

    inf = gdb.selected_inferior()
    pid = inf.pid
    stack_refs = {}
    stack_map = None
    try:
        stack_low = rsp & ~0xFFF
        stack_high = rbp + 0x200
        if stack_high > stack_low and ptr_ok(stack_low, stack_high - stack_low):
            stack_data = bytes(inf.read_memory(stack_low, stack_high - stack_low))
            for offset in range(0, len(stack_data) - 7, 8):
                value = int.from_bytes(stack_data[offset:offset + 8], "little")
                stack_refs.setdefault(value, []).append(stack_low + offset - rbp)
    except Exception as exc:
        log(f"PLANTER SCAN: stack pointer-hunt unavailable ({type(exc).__name__})")

    mappings = []
    try:
        with open(f"/proc/{pid}/maps", "r", encoding="ascii", errors="replace") as maps_file:
            for line in maps_file:
                if "rw-p" not in line:
                    continue
                parts = line.split()
                bounds = parts[0].split("-", 1)
                low, high = int(bounds[0], 16), int(bounds[1], 16)
                size = high - low
                if size < PLANTER_SIZE or size > 0x1000000:
                    continue
                name = parts[-1] if len(parts) > 5 else "anonymous"
                mapping = (low, high, name)
                if low <= rbp < high or low <= rsp < high:
                    stack_map = mapping
                mappings.append(mapping)
    except Exception as exc:
        log(f"PLANTER SCAN: maps unavailable ({type(exc).__name__})")
        return None

    # Search the active stack mapping first, then all remaining RW regions.
    mappings.sort(key=lambda item: 0 if item == stack_map else 1)
    scanned_regions = 0
    scanned_bytes = 0
    matches = []
    chosen = None
    for low, high, name in mappings:
        size = high - low
        try:
            data = bytes(inf.read_memory(low, size))
        except Exception:
            continue
        scanned_regions += 1
        scanned_bytes += size
        last = size - PLANTER_SIZE
        for offset in range(0, last + 1, 16):
            valid = True
            for _family, table_offset in TABLES:
                window = data[offset + table_offset:offset + table_offset + WINDOW_SIZE]
                if len(window) != WINDOW_SIZE or len(set(window)) != WINDOW_SIZE:
                    valid = False
                    break
            if not valid:
                continue

            candidate = low + offset
            refs = stack_refs.get(candidate, [])
            relative = candidate - STATE["src"] if STATE["src"] is not None else None
            log(f"PLANTER SCAN MATCH: rva={rva:#x} source_relative_base="
                f"{relative if relative is not None else 'unknown'} "
                f"stack_ref_rbp_deltas={[hex(x) for x in refs[:8]]}")
            matches.append((candidate, data[offset:offset + PLANTER_SIZE], refs, name))
            if -0x30 in refs or candidate == ptr_from_slot(rbp, -0x30):
                chosen = matches[-1]
                break
            if len(matches) >= 8:
                break
        if chosen is not None or len(matches) >= 8:
            break

    # If the coarse aligned scan missed, exhaustively inspect the active frame.
    # The frame is about 0x44a8 bytes; ±0x10000 covers it with margin.
    if not matches and stack_map is not None:
        map_low, map_high, _ = stack_map
        low = max(map_low, rbp - 0x10000)
        high = min(map_high, rbp + 0x200)
        size = high - low
        if size >= PLANTER_SIZE:
            try:
                data = bytes(inf.read_memory(low, size))
                scanned_bytes += size
                for offset in range(0, size - PLANTER_SIZE + 1):
                    valid = True
                    for _family, table_offset in TABLES:
                        window = data[offset + table_offset:offset + table_offset + WINDOW_SIZE]
                        if len(window) != WINDOW_SIZE or len(set(window)) != WINDOW_SIZE:
                            valid = False
                            break
                    if valid:
                        candidate = low + offset
                        refs = stack_refs.get(candidate, [])
                        relative = candidate - STATE["src"] if STATE["src"] is not None else None
                        log(f"PLANTER SCAN MATCH (unaligned stack): rva={rva:#x} "
                            f"source_relative_base={relative if relative is not None else 'unknown'} "
                            f"stack_ref_rbp_deltas={[hex(x) for x in refs[:8]]}")
                        matches.append((candidate, data[offset:offset + PLANTER_SIZE], refs, "stack-frame"))
                        chosen = matches[-1]
                        break
            except Exception as exc:
                log(f"PLANTER SCAN: frame fallback unavailable ({type(exc).__name__})")

    # The original planter_scan.py also performs a full byte-aligned pass
    # after the fast 16-byte pass. This covers non-aligned bases and RW maps
    # larger than 16 MiB (up to 32 MiB), without assuming allocator alignment.
    wide_regions = 0
    wide_bytes = 0
    if not matches:
        log("PLANTER SCAN: stride16 missed; running exhaustive step=1 scan")
        try:
            with open(f"/proc/{pid}/maps", "r", encoding="ascii", errors="replace") as maps_file:
                wide_mappings = []
                for line in maps_file:
                    if "rw-p" not in line:
                        continue
                    parts = line.split()
                    bounds = parts[0].split("-", 1)
                    low, high = int(bounds[0], 16), int(bounds[1], 16)
                    size = high - low
                    if PLANTER_SIZE <= size <= 0x2000000:
                        wide_mappings.append((low, high, parts[-1] if len(parts) > 5 else "anonymous"))
            wide_mappings.sort(key=lambda item: 0 if item[0] <= rbp < item[1] or item[0] <= rsp < item[1] else 1)
            for low, high, name in wide_mappings:
                size = high - low
                try:
                    data = bytes(inf.read_memory(low, size))
                except Exception:
                    continue
                wide_regions += 1
                wide_bytes += size
                for offset in range(0, size - PLANTER_SIZE + 1):
                    if offset % 16 == 0:
                        continue  # already covered by the fast pass
                    valid = True
                    for _family, table_offset in TABLES:
                        window = data[offset + table_offset:offset + table_offset + WINDOW_SIZE]
                        if len(window) != WINDOW_SIZE or len(set(window)) != WINDOW_SIZE:
                            valid = False
                            break
                    if not valid:
                        continue
                    candidate = low + offset
                    refs = stack_refs.get(candidate, [])
                    relative = candidate - STATE["src"] if STATE["src"] is not None else None
                    log(f"PLANTER SCAN MATCH (wide step=1): rva={rva:#x} "
                        f"source_relative_base={relative if relative is not None else 'unknown'} "
                        f"stack_ref_rbp_deltas={[hex(x) for x in refs[:8]]}")
                    matches.append((candidate, data[offset:offset + PLANTER_SIZE], refs, name))
                    chosen = matches[-1]
                    break
                if chosen is not None:
                    break
        except Exception as exc:
            log(f"PLANTER SCAN: exhaustive pass unavailable ({type(exc).__name__})")

    if chosen is None and matches:
        # Four independent bijective windows are an overwhelming signature.
        chosen = next((item for item in matches if -0x30 in item[2]), matches[0])

    if chosen is None:
        log(f"PLANTER SCAN: no four-permutation candidate; "
            f"regions={scanned_regions + wide_regions} bytes={scanned_bytes + wide_bytes}")
        return None

    candidate, blob, refs, map_name = chosen
    STATE["planter_scan_base"] = candidate
    STATE["planter"] = candidate
    write_blob(f"mixer_scan_candidate_{rva:x}.bin", blob)
    source_overlap = "unknown"
    if STATE["src"] is not None and ptr_ok(STATE["src"], 256):
        source_bytes = read_mem(STATE["src"], 256)
        mismatches = sum(a != b for a, b in zip(source_bytes[32:256], blob[:224]))
        source_overlap = f"{mismatches}/224 mismatches"
    log(f"PLANTER SCAN SELECTED: source_relative_base="
        f"{candidate - STATE['src'] if STATE['src'] is not None else 'unknown'} "
        f"source_overlap={source_overlap} pointer_at_rbp_minus_0x30="
        f"{(-0x30 in refs or candidate == ptr_from_slot(rbp, -0x30))} "
        f"matches={len(matches)}")
    return candidate


class FirstMixerReadBP(gdb.Breakpoint):
    def __init__(self, rva):
        self.rva = rva
        super().__init__(f"*{STATE['base'] + rva:#x}", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        if STATE["active_op"] != TRANSFORM_OPCODE:
            return False
        rbp = rv("$rbp")
        slot_ptr = ptr_from_slot(rbp, -0x30)
        capture_mixer_memory_operands(self.rva, slot_ptr)
        p = STATE["planter"] if has_planter_signature(STATE["planter"]) else None
        slot_signature = has_planter_signature(slot_ptr)
        if p is None and slot_signature:
            p = slot_ptr

        # Snapshot mapped candidates at every selector read. Raw bytes stay
        # on the ephemeral runner; only aggregate statistics are published.
        candidate_sources = [("slot", slot_ptr), ("writer_base", STATE["planter"])]
        for kind, candidate in candidate_sources:
            if candidate and ptr_ok(candidate, PLANTER_SIZE):
                key = (kind, candidate, self.rva)
                if key not in STATE["mixer_candidate_addrs"]:
                    STATE["mixer_candidate_addrs"].add(key)
                    write_blob(f"mixer_{kind}_candidate_{self.rva:x}.bin",
                               read_mem(candidate, PLANTER_SIZE))
                    src_now = STATE["src"]
                    rel = candidate - src_now if src_now is not None else None
                    log(f"MIXER CANDIDATE SNAPSHOT: kind={kind} rva={self.rva:#x} "
                        f"source_relative_base={rel if rel is not None else 'unknown'}")

        # Independently sample each known window via the base register captured
        # at its static writer site. A single 0x2700 contiguous allocation is
        # not assumed.
        windows = [
            ("fam1", "fam1_a", 0x0D60),
            ("fam2", "fam2", 0x1A00),
            ("fam3", "fam3", 0x2460),
            ("fam4", "fam4", 0x1390),
            ("fifth_1f30", "fifth_1f30", 0x1F30),
        ]
        for label, writer_name, off in windows:
            writer_base = STATE["writer_bases"].get(writer_name)
            window_addr = writer_base + off if writer_base is not None else 0
            if window_addr and ptr_ok(window_addr, WINDOW_SIZE):
                data = read_mem(window_addr, WINDOW_SIZE)
                write_blob(f"window_{label}_at_{self.rva:x}.final_candidate.bin", data)
                rel = writer_base - STATE["src"] if STATE["src"] is not None else "unknown"
                log(f"WINDOW SNAPSHOT: {label} unique={len(set(data))}/256 "
                    f"source_relative_base={rel}")

        # The true base candidate is the mutable [RBP-0x30] slot. Sample
        # this object directly at every mixer read, independently of the
        # source+0x20 writer-base hypothesis. Never publish pointer values.
        slot_span = ptr_ok(slot_ptr, PLANTER_SIZE)
        slot_source_match = STATE["src"] is not None and slot_ptr == STATE["src"] + 0x20
        slot_writer_match = STATE["planter"] is not None and slot_ptr == STATE["planter"]
        previous_ptr = STATE.get("slot_last_ptr")
        previous_data = STATE.get("slot_last_data")
        pointer_changed = (None if previous_ptr is None else previous_ptr != slot_ptr)
        same_ptr_changed = None
        slot_values = {}
        slot_data = None
        STATE["slot_sample_count"] += 1
        if slot_span:
            slot_data = read_mem(slot_ptr, PLANTER_SIZE)
            for name, off in TABLES:
                slot_values[name] = len(set(slot_data[off:off + WINDOW_SIZE]))
            slot_values["fifth_1f30"] = len(set(
                slot_data[0x1F30:0x1F30 + WINDOW_SIZE]))
            if previous_ptr == slot_ptr and previous_data is not None:
                same_ptr_changed = sum(a != b for a, b in zip(previous_data, slot_data))
            if STATE["slot_sample_count"] == 1:
                write_blob("planter.from_rbp_minus_30.first.bin", slot_data)
                # Characterize each window without publishing byte values.
                # Index topology can distinguish an incomplete fill from a
                # wrong offset or a window that is not a permutation.
                early = STATE.get("pre_planter_snapshot")
                window_specs = list(TABLES) + [("fifth_1f30", 0x1F30)]
                for name, off in window_specs:
                    now = slot_data[off:off + WINDOW_SIZE]
                    frequencies = {}
                    for value in now:
                        frequencies[value] = frequencies.get(value, 0) + 1
                    changed_indices = []
                    if early is not None and STATE.get("pre_planter_base") == slot_ptr:
                        before = early[off:off + WINDOW_SIZE]
                        changed_indices = [i for i, (a, b) in enumerate(zip(before, now)) if a != b]
                    runs = sum(1 for i, idx in enumerate(changed_indices)
                               if i == 0 or idx != changed_indices[i - 1] + 1)
                    cmin = min(changed_indices) if changed_indices else -1
                    cmax = max(changed_indices) if changed_indices else -1
                    log(f"SLOT WINDOW DETAIL {name}: unique={len(frequencies)}/256 "
                        f"zero_count={frequencies.get(0, 0)} "
                        f"max_multiplicity={max(frequencies.values())} "
                        f"changed={len(changed_indices)} changed_min={cmin} "
                        f"changed_max={cmax} changed_runs={runs}")
            STATE["slot_last_ptr"] = slot_ptr
            STATE["slot_last_data"] = slot_data

            # Once the live slot, source+0x20, and known writer base agree,
            # preserve this exact runtime object even if the historical
            # four-permutation signature does not hold in this session.
            if (not STATE["slot_anchor_dumped"] and slot_source_match
                    and slot_writer_match):
                STATE["slot_anchor_dumped"] = True
                write_blob("planter.slot_anchored.bin", slot_data)
                for name, off in TABLES:
                    window = slot_data[off:off + WINDOW_SIZE]
                    log(f"SLOT ANCHORED WINDOW {name}: unique={len(set(window))}/256")
                fifth = slot_data[0x1F30:0x1F30 + WINDOW_SIZE]
                log(f"SLOT ANCHORED WINDOW fifth_1f30: unique={len(set(fifth))}/256")
                with open(os.path.join(OUT, "writer_stats.txt"), "w", encoding="utf-8") as f:
                    for name, st in sorted(STATE["writer_stats"].items()):
                        f.write(f"{name}: {st}\n")
                log("SLOT ANCHOR VERIFIED: rbp_minus_0x30 == source_plus_0x20 "
                    "== writer_base; contiguous_span=0x2700")

        log(f"MIXER SLOT SAMPLE n={STATE['slot_sample_count']} "
            f"span_mapped={slot_span} slot_eq_source_plus_20={slot_source_match} "
            f"slot_eq_writer_base={slot_writer_match} "
            f"slot_pointer_changed={pointer_changed if pointer_changed is not None else 'unknown'} "
            f"same_ptr_changed={same_ptr_changed if same_ptr_changed is not None else 'unknown'} "
            + " ".join(f"{name}_unique={slot_values.get(name, 'na')}/256"
                       for name in ("fam1", "fam2", "fam3", "fam4", "fifth_1f30")))

        log(f"FIRST MIXER READ rva={self.rva:#x} rbp={rbp:#x} "
            f"slot_mapped={slot_span} slot_signature={slot_signature} "
            f"writer_base_signature={has_planter_signature(STATE['planter'])} "
            f"selected_planter={p or 0:#x}")

        # Compare the candidate at every mixer-read stop with its pre-transform
        # image. This is the decisive way to tell whether incomplete windows
        # are still being filled, or whether the old four-window layout is wrong
        # for this live route. Only counts/uniqueness are emitted to trace.log.
        early = STATE.get("pre_planter_snapshot")
        early_base = STATE.get("pre_planter_base")
        candidate_base = STATE.get("planter") or (STATE["src"] + 0x20 if STATE["src"] else None)
        if (early is not None and candidate_base == early_base
                and ptr_ok(candidate_base, PLANTER_SIZE)):
            current = read_mem(candidate_base, PLANTER_SIZE)
            compare_windows = list(TABLES) + [("fifth_1f30", 0x1F30)]
            for name, off in compare_windows:
                old = early[off:off + WINDOW_SIZE]
                now = current[off:off + WINDOW_SIZE]
                changed = sum(a != b for a, b in zip(old, now))
                log(f"PLANTER DELTA {name}: changed={changed}/256 "
                    f"pre_unique={len(set(old))}/256 "
                    f"now_unique={len(set(now))}/256 "
                    f"now_permutation={len(set(now)) == 256}")
        elif early is not None:
            log("PLANTER DELTA: candidate base differs from pre-transform source+0x20 anchor")

        if p is None:
            scanned = scan_planter_memory(rbp, rv("$rsp"), self.rva)
            if scanned is not None:
                p = scanned
        if p and has_planter_signature(p):
            # A validated snapshot is a durable capture milestone, not the
            # end of the experiment. Earlier v30 stopped the inferior here,
            # on the first mixer read that happened to satisfy the historical
            # four-window signature. That prevented the remaining mixer
            # reads and ProvisioningStart's return from being observed.
            if not STATE["final_dumped"]:
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
                if STATE["src"] and ptr_ok(STATE["src"], 256):
                    write_blob("source.final.bin", read_mem(STATE["src"], 256))
                if STATE["dst"] and STATE["dst_span"]:
                    n = STATE["dst_span"]
                    if ptr_ok(STATE["dst"], n):
                        staging = read_mem(STATE["dst"], n)
                        write_blob(f"staging.final.span_{n}.bin", staging)
                        if n >= 200:
                            write_blob("staging.final.requested_200.bin", staging[:200])
                        if n >= 256:
                            write_blob("staging.final.adjacent_56.bin", staging[200:256])
                log(f"VALIDATED PLANTER SNAPSHOT at mixer read {self.rva:#x}; "
                    "continuing through the remaining reads and ProvisioningStart")
            else:
                log(f"VALIDATED PLANTER remains present at mixer read {self.rva:#x}; continuing")
        elif STATE["slot_anchor_dumped"]:
            log("MIXER SLOT OBJECT RETAINED: pointer anchor is verified; "
                "legacy four-permutation signature is not satisfied in this session; continuing")
        else:
            log("MIXER CANDIDATE REJECTED: no verified four-permutation planter; "
                "retrying at next mixer-read site")

        # Every mixer-read breakpoint is observational. Never stop the
        # inferior merely because a candidate has been captured or validated.
        return False


class PlanterBaseLoadBP(gdb.Breakpoint):
    """Identify the planter base at a known load site without watchpoints."""
    def __init__(self, rva, reg_name):
        self.rva = rva
        self.reg_name = reg_name
        super().__init__(f"*{STATE['base'] + rva:#x}", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        if STATE["active_op"] != TRANSFORM_OPCODE or STATE["planter"] is not None:
            return False
        rbp = rv("$rbp")
        slot = ptr_from_slot(rbp, -0x30)
        src = STATE["src"]
        relation_ok = src is not None and slot == src + 32
        if ptr_ok(slot, PLANTER_SIZE) and relation_ok:
            STATE["planter"] = slot
            if ptr_ok(src, 256):
                source_bytes = read_mem(src, 256)
                planter_head = read_mem(slot, 224)
                mismatches = sum(a != b for a, b in zip(source_bytes[32:256], planter_head))
                log(f"SOURCE/PLANTER OVERLAP source_plus_0x20=True "
                    f"equal={mismatches == 0} mismatches={mismatches}")
            log(f"PLANTER BASE IDENTIFIED: method=base-load site={self.rva:#x} "
                f"source_plus_0x20=True; snapshot=0x{PLANTER_SIZE:x}")
            write_blob("planter.at_base_load.bin", read_mem(slot, PLANTER_SIZE))
            return False
        if ptr_ok(slot, PLANTER_SIZE) and src is None:
            log(f"BASE-LOAD DEFERRED rva={self.rva:#x}: mapped candidate; source pointer not known yet")
            return False
        log(f"BASE-LOAD REJECTED rva={self.rva:#x}: source+0x20 relation not validated")
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
        early_source = STATE.get("source_initial")
        if early_source is not None and ptr_ok(src, 256):
            current_source = read_mem(src, 256)
            changed = [i for i, (a, b) in enumerate(zip(early_source, current_source)) if a != b]
            log(f"SOURCE DELTA to post-malloc: changed={len(changed)}/256; "
                f"first_indices={[hex(i) for i in changed[:24]]}")
            write_blob("source.at_postmalloc.bin", current_source)
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


def install_global_probes(base):
    """Install source/allocator and direct byte-store probes before any prep opcode runs."""
    log("GLOBAL INSTALL STAGE: command list entered")
    try:
        gdb.execute("set language c", to_string=True)
        log("GLOBAL INSTALL STAGE: language configured")
        STATE["source_init_bp"] = SourceSlotStoreBP()
        log("GLOBAL INSTALL STAGE: source-slot breakpoint created")
        STATE["postmalloc_bp"] = PostMallocBP()
        log("GLOBAL INSTALL STAGE: post-malloc breakpoint created")
        STATE["copy_entry_bp"] = CopyEntryBP()
        log("GLOBAL INSTALL STAGE: copy-entry breakpoint created")
        for rva, spec in WRITERS.items():
            bp = WriterSiteBP(rva, spec)
            STATE["writer_bps"].append(bp)
            writer_callback_event("setup", rva, spec[0],
                                  "enabled" if bp.enabled else "disabled")
            details = gdb.execute(f"info breakpoints {bp.number}", to_string=True)
            resolved = "pending" if "<PENDING>" in details.upper() else "resolved"
            writer_callback_event("resolution", rva, spec[0], resolved)
            log(f"GLOBAL INSTALL STAGE: writer breakpoint {rva:#x} "
                f"created enabled={bp.enabled} resolution={resolved}")
        log(f"BASE={base:#x}; global source/allocator probes and "
            f"{len(WRITERS)} writer sites armed for all vdfut768ig opcodes")
        STATE["global_install_complete"] = True
    except Exception as exc:
        log(f"GLOBAL INSTALL ERROR: {type(exc).__name__}: {exc}")



class Fam1CandidateBP(gdb.Breakpoint):
    """Read-only observer for the unverified 0xE2441 fam1 writer candidate."""
    MAX_HITS = 1024

    def __init__(self, address):
        self.rva = 0xE2441
        self.hits = 0
        super().__init__(f"*{address:#x}", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True
        self.path = os.path.join(OUT, "fam1_candidate_events.csv")
        with open(self.path, "w", newline="", encoding="utf-8") as stream:
            csv.writer(stream).writerow([
                "active_opcode", "rva", "mnemonic", "destination_is_memory",
                "memory_expression", "width", "object_offset", "fam1_index",
                "anchor_register", "index_registers", "resolution",
            ])

    def stop(self):
        self.hits += 1
        try:
            line = gdb.execute("x/i $pc", to_string=True).strip()
            match = re.search(r":\s*(.*)$", line)
            instruction = match.group(1).strip() if match else ""
            parts = instruction.split(None, 1)
            mnemonic = parts[0].lower() if parts else "unknown"
            operands_text = parts[1] if len(parts) > 1 else ""
            destination = operands_text.split(",", 1)[0].strip()
            destination_is_memory = "[" in destination and "]" in destination
            memory_operands = parse_intel_memory_operands(instruction)

            expression, width = memory_operands[0] if memory_operands else ("", None)
            registers = {}
            for name in (
                "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
            ):
                try:
                    registers[name] = rv("$" + name)
                except Exception:
                    pass

            source = STATE.get("src")
            object_base = source + 0x20 if source is not None else None
            resolved = (
                analyze_intel_address(
                    expression, registers, object_base=object_base,
                    object_size=PLANTER_SIZE,
                )
                if expression else None
            )
            object_offset = (
                resolved.get("object_offset") if resolved is not None else None
            )
            fam1_index = (
                object_offset - 0x0D60
                if object_offset is not None and 0x0D60 <= object_offset < 0x0E60
                else None
            )
            if not memory_operands:
                resolution = "no-memory-operand"
            elif not destination_is_memory:
                resolution = "memory-not-destination"
            elif object_base is None:
                resolution = "source-anchor-unavailable"
            elif resolved is None or object_offset is None:
                resolution = "outside-or-unresolved-planter"
            elif fam1_index is not None:
                resolution = "source-anchored-fam1-window"
            else:
                resolution = "source-anchored-other-planter-offset"

            with open(self.path, "a", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerow([
                    f"{STATE.get('active_op', 0):#x}",
                    f"{self.rva:#x}",
                    mnemonic,
                    "yes" if destination_is_memory else "no",
                    expression,
                    width if width is not None else "unknown",
                    f"{object_offset:#x}" if object_offset is not None else "na",
                    f"{fam1_index:#x}" if fam1_index is not None else "na",
                    resolved.get("anchor_register") or "na" if resolved else "na",
                    ",".join(resolved.get("index_registers", ())) if resolved else "na",
                    resolution,
                ])
            log(
                f"FAM1 CANDIDATE HIT: opcode={STATE.get('active_op')} "
                f"rva={self.rva:#x} mnemonic={mnemonic} "
                f"destination_is_memory={destination_is_memory} "
                f"object_offset={object_offset!r} fam1_index={fam1_index!r} "
                f"resolution={resolution}"
            )
        except Exception as exc:
            # Keep potentially sensitive GDB exception details out of the report.
            log(f"FAM1 CANDIDATE CALLBACK ERROR: {type(exc).__name__}")
        if self.hits >= self.MAX_HITS:
            self.enabled = False
            log("FAM1 CANDIDATE BP DISABLED: hit safety limit reached")
        return False


def install_transform_probes(base):
    """Install the target transform's frame/base and mixer-read probes."""
    log("TRANSFORM INSTALL STAGE: command list entered")
    try:
        # 0xE2441 is only a candidate fam1 writer. Install it only if a
        # two-instruction decode from the known 0xE243D boundary confirms it.
        try:
            decoded = []
            output = gdb.execute(f"x/2i {base + 0xE243D:#x}", to_string=True)
            for raw in output.splitlines():
                match = re.match(
                    r"^\s*(?:=>\s*)?(0x[0-9a-fA-F]+)(?:\s+<[^>]+>)?:\s*(.*)$",
                    raw,
                )
                if match:
                    decoded.append(int(match.group(1), 16))
            if (len(decoded) >= 2 and decoded[0] == base + 0xE243D
                    and decoded[1] == base + 0xE2441):
                STATE["fam1_candidate_bp"] = Fam1CandidateBP(base + 0xE2441)
                log("FAM1 CANDIDATE BP: installed boundary=verified rva=0xe2441")
            else:
                log("FAM1 CANDIDATE BP: not installed boundary=unverified")
        except Exception as exc:
            log(f"FAM1 CANDIDATE BP: not installed boundary-check-error={type(exc).__name__}")

        for rva, reg_name in ((0xE243D, "$rdi"), (0xFAC8A, "$r12")):
            bp = PlanterBaseLoadBP(rva, reg_name)
            STATE["base_load_bps"].append(bp)
            log(f"TRANSFORM INSTALL STAGE: base-load breakpoint {rva:#x} created")
        for rva in MIXER_READS:
            bp = FirstMixerReadBP(rva)
            STATE["mixer_bps"].append(bp)
            log(f"TRANSFORM INSTALL STAGE: mixer-read breakpoint {rva:#x} created")
        log(f"BASE={base:#x}; target transform armed with "
            f"{len(STATE['base_load_bps'])} base-load sites and "
            f"{len(MIXER_READS)} mixer-read sites")
        STATE["rva_install_complete"] = True
    except Exception as exc:
        log(f"TRANSFORM INSTALL ERROR: {type(exc).__name__}: {exc}")


class EntryBP(gdb.Breakpoint):
    def __init__(self):
        # Keep this breakpoint enabled: vdfut768ig is called with several
        # opcodes (configuration/init and the actual transform). Do not install
        # RVA breakpoints until the target transform opcode is reached.
        super().__init__("vdfut768ig", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True
        self.installed = False
        # GDB forbids changing the breakpoint set from Breakpoint.stop().
        # The attached command list runs after stop() returns and owns the
        # deferred breakpoint installation and resume operation.
        self.commands = """silent
python
if not STATE["global_install_started"]:
    STATE["global_install_started"] = True
    log("ENTRY COMMAND: installing global writer probes")
    install_global_probes(STATE["base"])
if STATE["active_op"] == TRANSFORM_OPCODE and not STATE["rva_install_started"]:
    STATE["rva_install_started"] = True
    log("ENTRY COMMAND: installing target transform probes")
    install_transform_probes(STATE["base"])
else:
    log(f"ENTRY COMMAND: skipped opcode={STATE['active_op']:#010x}; global writer probes remain active")
end
continue
"""

    def stop(self):
        pc = rv("$pc")
        opcode = rv("$rdi") & 0xFFFFFFFF
        STATE["active_op"] = opcode
        STATE["src"] = None
        STATE["source_init"] = None
        STATE["source_initial"] = None
        STATE["dst"] = None
        STATE["dst_span"] = 0
        STATE["writer_bases"] = {}
        STATE["planter"] = None
        STATE["pre_planter_base"] = None
        STATE["pre_planter_snapshot"] = None
        STATE["slot_sample_count"] = 0
        STATE["slot_last_ptr"] = None
        STATE["slot_last_data"] = None
        STATE["slot_anchor_dumped"] = False
        if opcode == TRANSFORM_OPCODE:
            STATE["final_dumped"] = False
            STATE["planter_scan_done"] = False
            STATE["planter_scan_base"] = None
        if not self.installed:
            base = pc - ENTRY_RVA
            STATE["base"] = base
            self.installed = True
            log(f"FIRST vdfut768ig entry: pc={pc:#x} base={base:#x} opcode={opcode:#010x}")
        else:
            log(f"vdfut768ig entry: opcode={opcode:#010x} "
                f"transform={opcode == TRANSFORM_OPCODE}")
        # Stop so GDB can run the attached command list outside this callback.
        return True


# Keep a handle to the entry BP and initialize a clean log.
with open(LOG, "w", encoding="utf-8") as f:
    f.write("planter trace started\n")

with open(os.path.join(OUT, "writer_callback_events.csv"), "w",
          newline="", encoding="utf-8") as f:
    csv.writer(f).writerow([
        "event", "rva", "name", "active_opcode", "pc_rva", "status",
    ])

with open(os.path.join(OUT, "run.json"), "w", encoding="utf-8") as f:
    import json
    json.dump({"run_id": RUN_ID, "pid": os.getpid(), "created_unix": time.time(),
               "script_version": "v33", "entry_rva": ENTRY_RVA, "transform_opcode": TRANSFORM_OPCODE,
               "planter_size": PLANTER_SIZE, "tables": TABLES,
               "unknown_ranges": UNKNOWN_RANGES,
               "staging_requested": 200, "staging_observed_copy_span": 256},
              f, indent=2)

gdb.execute("set confirm off", to_string=True)
gdb.execute("set pagination off", to_string=True)
gdb.execute("set disassembly-flavor intel", to_string=True)
gdb.execute("set breakpoint pending on", to_string=True)
for _signal in ("SIGSEGV", "SIGBUS", "SIGILL", "SIGABRT"):
    gdb.execute(f"handle {_signal} stop print nopass", to_string=True)
gdb.events.stop.connect(on_inferior_stop)
log(f"armed; output={OUT}; waiting for first vdfut768ig call")
STATE["entry_bp"] = EntryBP()