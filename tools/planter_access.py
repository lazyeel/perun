#!/usr/bin/env python3
"""Parse and resolve Intel-syntax x86-64 memory operands for GDB traces."""
from __future__ import annotations
import os
import re
from typing import Mapping

_REGISTERS = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
}
_OPERAND = re.compile(
    r"(?:(byte|word|dword|qword|tbyte|xmmword|ymmword|zmmword)\s+ptr\s*)?"
    r"\[([^\]]+)\]", re.IGNORECASE,
)
_WIDTHS = {"byte": 1, "word": 2, "dword": 4, "qword": 8,
           "tbyte": 10, "xmmword": 16, "ymmword": 32, "zmmword": 64}

# One-byte hardware-write probes for two sparse windows and a dense control.
SPARSE_WRITE_PROBE_OFFSETS = (
    ("fam2_tail", 0x1A00 + 0xFF),
    ("fam4_tail", 0x1390 + 0xFF),
    ("fam3_control_tail", 0x2460 + 0xFF),
)


def parse_intel_memory_operands(instruction: str) -> list[tuple[str, int | None]]:
    result = []
    for match in _OPERAND.finditer(instruction):
        kind, expression = match.groups()
        result.append((expression.strip(), _WIDTHS.get(kind.lower()) if kind else None))
    return result


def parse_proc_maps(text: str) -> list[dict]:
    """Parse /proc/PID/maps without retaining directory paths."""
    mappings = []
    for line in text.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) < 5:
            continue
        try:
            low_s, high_s = fields[0].split("-", 1)
            low, high = int(low_s, 16), int(high_s, 16)
            file_offset = int(fields[2], 16)
        except (ValueError, IndexError):
            continue
        raw_name = fields[5].strip() if len(fields) == 6 else "anonymous"
        label = os.path.basename(raw_name) if raw_name.startswith("/") else raw_name
        mappings.append({
            "start": low, "end": high, "perms": fields[1],
            "file_offset": file_offset, "label": label,
            "file_backed": len(fields) == 6 and raw_name.startswith("/"),
        })
    return mappings


def classify_mapped_address(address: int, mappings: list[dict],
                            module_base: int | None = None,
                            module_size: int = 0x200000) -> dict | None:
    """Map an address to a stable module/file offset or anonymous-map offset."""
    if module_base is not None and module_base <= address < module_base + module_size:
        return {"label": "libCoreADI.so", "offset": address - module_base,
                "kind": "module-rva", "mapping": None}
    for mapping in mappings:
        if mapping["start"] <= address < mapping["end"]:
            offset = (
                mapping["file_offset"] + address - mapping["start"]
                if mapping["file_backed"] else address - mapping["start"]
            )
            return {
                "label": mapping["label"], "offset": offset,
                "kind": "file-offset" if mapping["file_backed"] else "mapping-offset",
                "mapping": mapping,
            }
    return None


def _address_terms(expression: str):
    compact = expression.strip().lower().replace(" ", "")
    if not compact or ":" in compact or "rip" in compact or "eip" in compact:
        return None
    parsed = []
    for raw in re.findall(r"[+-]?[^+-]+", compact):
        sign = -1 if raw.startswith("-") else 1
        body = raw.lstrip("+-")
        if not body:
            return None
        if "*" in body:
            parts = body.split("*")
            if len(parts) != 2 or parts[0] not in _REGISTERS:
                return None
            try:
                scale = int(parts[1], 0)
            except ValueError:
                return None
            if scale not in (1, 2, 4, 8):
                return None
            parsed.append(("reg", sign, parts[0], scale))
        elif body in _REGISTERS:
            parsed.append(("reg", sign, body, 1))
        else:
            try:
                parsed.append(("const", sign, int(body, 0), 1))
            except ValueError:
                return None
    return parsed


def analyze_intel_address(expression: str, registers: Mapping[str, int],
                          object_base: int | None = None,
                          object_size: int = 0x2700,
                          mapping: Mapping | None = None,
                          module_base: int | None = None,
                          module_size: int = 0x200000) -> dict | None:
    """Resolve address; infer planter-relative or mapping-relative base/index."""
    terms = _address_terms(expression)
    if terms is None:
        return None
    effective = constant = 0
    register_terms = []
    for kind, sign, value, scale in terms:
        if kind == "const":
            contribution = sign * value
            effective += contribution
            constant += contribution
        else:
            if value not in registers:
                return None
            contribution = sign * int(registers[value]) * scale
            effective += contribution
            register_terms.append((value, sign, scale, contribution))
    effective &= (1 << 64) - 1

    object_offset = None
    table_base_offset = None
    anchor_register = None
    index_offset = None
    index_registers = []
    if object_base is not None and object_base <= effective < object_base + object_size:
        object_offset = effective - object_base
    anchors = [
        (name, int(registers[name]) - object_base)
        for name, sign, scale, _ in register_terms
        if object_base is not None and object_base <= int(registers[name]) < object_base + object_size
        and sign == 1 and scale == 1
    ]
    if len(anchors) == 1:
        anchor_register, anchor_delta = anchors[0]
        table_base_offset = anchor_delta + constant
        index_offset = 0
        for name, sign, _scale, contribution in register_terms:
            if name != anchor_register:
                index_offset += contribution
                index_registers.append(name if sign > 0 else "-" + name)

    mapped_offset = mapped_base_offset = mapped_index_offset = None
    mapped_anchor_register = None
    mapped_index_registers = []
    if mapping is not None:
        start, end = int(mapping["start"]), int(mapping["end"])
        if start <= effective < end:
            mapped_offset = (
                int(mapping["file_offset"]) + effective - start
                if mapping["file_backed"] else effective - start
            )
            map_anchors = [
                (name, int(registers[name]) - start)
                for name, sign, scale, _ in register_terms
                if start <= int(registers[name]) < end and sign == 1 and scale == 1
            ]
            if len(map_anchors) == 1:
                mapped_anchor_register, anchor_delta = map_anchors[0]
                mapped_base_offset = (
                    (int(mapping["file_offset"]) if mapping["file_backed"] else 0)
                    + anchor_delta + constant
                )
                mapped_index_offset = 0
                for name, sign, _scale, contribution in register_terms:
                    if name != mapped_anchor_register:
                        mapped_index_offset += contribution
                        mapped_index_registers.append(name if sign > 0 else "-" + name)
    module_base_offset = None
    module_anchor_register = None
    module_index_offset = None
    module_index_registers = []
    if module_base is not None:
        module_anchors = [
            (name, int(registers[name]) + constant - module_base)
            for name, sign, scale, _ in register_terms
            if sign == 1 and scale == 1
            and module_base <= int(registers[name]) + constant < module_base + module_size
        ]
        if len(module_anchors) == 1:
            module_anchor_register, module_base_offset = module_anchors[0]
            module_index_offset = 0
            for name, sign, _scale, contribution in register_terms:
                if name != module_anchor_register:
                    module_index_offset += contribution
                    module_index_registers.append(name if sign > 0 else "-" + name)
    return {
        "effective_address": effective,
        "object_offset": object_offset,
        "anchor_register": anchor_register,
        "table_base_offset": table_base_offset,
        "index_offset": index_offset,
        "index_registers": tuple(index_registers),
        "mapped_offset": mapped_offset,
        "mapped_base_offset": mapped_base_offset,
        "mapped_anchor_register": mapped_anchor_register,
        "mapped_index_offset": mapped_index_offset,
        "mapped_index_registers": tuple(mapped_index_registers),
        "module_base_offset": module_base_offset,
        "module_anchor_register": module_anchor_register,
        "module_index_offset": module_index_offset,
        "module_index_registers": tuple(module_index_registers),
    }
