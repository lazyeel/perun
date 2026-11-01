#!/usr/bin/env python3
"""Small, testable helpers for resolving Intel-syntax x86-64 memory operands."""
from __future__ import annotations

import re
from typing import Mapping

_REGISTERS = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
}
_OPERAND = re.compile(
    r"(?:(byte|word|dword|qword|tbyte|xmmword|ymmword|zmmword)\s+ptr\s*)?"
    r"\[([^\]]+)\]",
    re.IGNORECASE,
)
_WIDTHS = {
    "byte": 1, "word": 2, "dword": 4, "qword": 8, "tbyte": 10,
    "xmmword": 16, "ymmword": 32, "zmmword": 64,
}


def parse_intel_memory_operands(instruction: str) -> list[tuple[str, int | None]]:
    """Return (address expression, access width) for bracketed Intel operands."""
    result = []
    for match in _OPERAND.finditer(instruction):
        kind, expression = match.groups()
        width = _WIDTHS.get(kind.lower()) if kind else None
        result.append((expression.strip(), width))
    return result


def _address_terms(expression: str):
    compact = expression.strip().lower().replace(" ", "")
    if not compact or ":" in compact or "rip" in compact or "eip" in compact:
        return None
    terms = re.findall(r"[+-]?[^+-]+", compact)
    parsed = []
    for raw in terms:
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


def analyze_intel_address(
    expression: str,
    registers: Mapping[str, int],
    object_base: int | None = None,
    object_size: int = 0x2700,
) -> dict | None:
    """Resolve an Intel address and, when possible, split table base from index.

    A register whose current value lies inside the anchored object is treated as
    the object-relative base term only when exactly one such register occurs and
    it has a positive unit coefficient. Remaining register terms form the index.
    """
    terms = _address_terms(expression)
    if terms is None:
        return None

    effective = 0
    constant = 0
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
    anchor_register = None
    table_base_offset = None
    index_offset = None
    index_registers = []
    if object_base is not None and object_base <= effective < object_base + object_size:
        object_offset = effective - object_base

    anchors = []
    if object_base is not None:
        for name, sign, scale, contribution in register_terms:
            value = int(registers[name])
            if object_base <= value < object_base + object_size and sign == 1 and scale == 1:
                anchors.append((name, value - object_base))
    if len(anchors) == 1:
        anchor_register, anchor_delta = anchors[0]
        table_base_offset = anchor_delta + constant
        index_offset = 0
        for name, sign, scale, contribution in register_terms:
            if name == anchor_register:
                continue
            index_offset += contribution
            index_registers.append(name if sign > 0 else "-" + name)
    return {
        "effective_address": effective,
        "object_offset": object_offset,
        "anchor_register": anchor_register,
        "table_base_offset": table_base_offset,
        "index_offset": index_offset,
        "index_registers": tuple(index_registers),
    }
