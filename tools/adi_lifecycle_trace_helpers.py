#!/usr/bin/env python3
"""Pure helpers for decoding ABI out-parameter slots from lifecycle traces.

Kept independent of GDB so address parsing and failure behavior are testable
in ordinary CPython and in CI.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any


def parse_out_slot_address(value: object) -> int:
    """Parse an x86-64 out-slot address stored as an int or textual integer."""
    if isinstance(value, bool):
        raise TypeError("boolean is not an address")
    if isinstance(value, int):
        address = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("empty address")
        try:
            address = int(text, 0)
        except ValueError:
            # Decimal values with leading zeroes are still unambiguous here.
            address = int(text, 10)
    else:
        raise TypeError(f"unsupported address type: {type(value).__name__}")

    if not 0 <= address <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("address is outside the unsigned 64-bit range")
    return address


def resolve_output_buffer(
    pointer_slot: object,
    length_slot: object,
    *,
    read_u64_at: Callable[[int], int],
    read_u32_at: Callable[[int], int],
    capture_bytes: Callable[[int, int, int], dict[str, Any]],
    limit: int,
) -> dict[str, Any]:
    """Resolve pointer/length out-slots after an export returns.

    Both integers and hexadecimal strings are accepted because the Start
    tracer records slot addresses as hex while OTPRequest records them as ints.
    Errors are returned as structured trace data instead of escaping a GDB
    breakpoint callback and interrupting the inferior.
    """
    try:
        pointer_slot_address = parse_out_slot_address(pointer_slot)
        length_slot_address = parse_out_slot_address(length_slot)
    except (TypeError, ValueError) as exc:
        return {
            "pointer": 0,
            "length": 0,
            "data": {"status": f"out-slot-parse-error:{type(exc).__name__}"},
        }

    try:
        pointer = read_u64_at(pointer_slot_address)
        length = read_u32_at(length_slot_address)
    except Exception as exc:
        return {
            "pointer": 0,
            "length": 0,
            "data": {"status": f"out-slot-read-error:{type(exc).__name__}"},
        }

    return {
        "pointer": pointer,
        "length": length,
        "data": capture_bytes(pointer, length, limit),
    }
