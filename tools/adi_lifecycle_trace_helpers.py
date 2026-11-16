#!/usr/bin/env python3
"""Pure helpers for decoding ABI out-parameter slots from lifecycle traces.

Kept independent of GDB so address parsing and failure behavior are testable
in ordinary CPython and in CI.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
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



def remember_output_allocation(
    allocations: dict[int, list[dict[str, Any]]],
    pointer: object,
    *,
    kind: str,
    call_id: int,
    length: int,
) -> bool:
    """Track one live ADI output allocation by its returned pointer.

    A pointer may be reused after Dispose, so each address owns a FIFO of
    allocations rather than a single latest MID/OTP slot.
    """
    if type(pointer) is not int or pointer <= 0:
        return False
    allocations.setdefault(pointer, []).append({
        "kind": kind,
        "call_id": call_id,
        "length": length,
    })
    return True


def peek_output_allocation(
    allocations: dict[int, list[dict[str, Any]]],
    pointer: object,
) -> dict[str, Any] | None:
    """Inspect the oldest live allocation without consuming it."""
    if type(pointer) is not int or pointer <= 0:
        return None
    owners = allocations.get(pointer)
    if not owners:
        return None
    return dict(owners[0])


def take_output_allocation(
    allocations: dict[int, list[dict[str, Any]]],
    pointer: object,
) -> dict[str, Any] | None:
    """Consume the oldest live allocation associated with a Dispose pointer."""
    if type(pointer) is not int or pointer <= 0:
        return None
    owners = allocations.get(pointer)
    if not owners:
        return None
    owner = owners.pop(0)
    if not owners:
        del allocations[pointer]
    return dict(owner)




def validate_api_event_stream(events: Any) -> dict[str, Any]:
    """Validate entry/terminal pairing and nesting in private lifecycle JSONL.

    Only event metadata is returned. Captured arguments, pointers and token
    bytes are never copied into the validation report.
    """
    entries: dict[int, dict[str, Any]] = {}
    active: list[int] = []
    seen_terminal: set[int] = set()
    live_outputs: dict[int, list[dict[str, Any]]] = {}
    tracked_outputs = 0
    disposed_outputs = 0
    errors: list[dict[str, Any]] = []
    counts = {
        "api_entry": 0,
        "api_return": 0,
        "api_unwind": 0,
        "api_return_probe_error": 0,
        "opcode_arguments": 0,
    }

    def issue(index: int, code: str, call_id: object = None) -> None:
        row: dict[str, Any] = {"event_index": index, "code": code}
        if isinstance(call_id, int) and not isinstance(call_id, bool):
            row["call_id"] = call_id
        errors.append(row)

    def valid_id(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and value > 0

    for index, event in enumerate(events):
        if not isinstance(event, Mapping):
            issue(index, "event-is-not-an-object")
            continue
        kind = event.get("event")
        if not isinstance(kind, str) or kind not in counts:
            continue
        counts[kind] += 1

        if kind == "api_entry":
            call_id = event.get("call_id")
            if not valid_id(call_id):
                issue(index, "invalid-entry-call-id", call_id)
                continue
            if call_id in entries:
                issue(index, "duplicate-entry-call-id", call_id)
                continue
            expected_parent = active[-1] if active else None
            actual_parent = event.get("parent_call_id")
            parent_matches = (
                actual_parent is None if expected_parent is None
                else valid_id(actual_parent) and actual_parent == expected_parent
            )
            if not parent_matches:
                issue(index, "entry-parent-does-not-match-active-frame", call_id)
            api_name = event.get("api")
            if not isinstance(api_name, str) or not api_name:
                issue(index, "entry-api-name-missing", call_id)
            entry_record: dict[str, Any] = {
                "api": api_name,
                "parent_call_id": actual_parent,
            }
            if api_name == "jk24uiwqrg":
                arguments = event.get("arguments")
                if not isinstance(arguments, Mapping):
                    issue(index, "dispose-arguments-missing", call_id)
                    entry_record["dispose_pointer"] = None
                    entry_record["dispose_owner"] = None
                else:
                    try:
                        dispose_pointer = parse_out_slot_address(arguments.get("pointer"))
                    except (TypeError, ValueError):
                        dispose_pointer = None
                        issue(index, "dispose-pointer-invalid", call_id)
                    expected_owners = live_outputs.get(dispose_pointer, []) if dispose_pointer else []
                    expected_owner = dict(expected_owners[0]) if expected_owners else None
                    recorded_owner = arguments.get("otp_output_owner")
                    if recorded_owner != expected_owner:
                        issue(index, "dispose-entry-owner-mismatch", call_id)
                    entry_record["dispose_pointer"] = dispose_pointer
                    entry_record["dispose_owner"] = expected_owner
            entries[call_id] = entry_record
            active.append(call_id)
            continue

        if kind in ("api_return", "api_unwind"):
            call_id = event.get("call_id")
            if not valid_id(call_id):
                issue(index, "invalid-terminal-call-id", call_id)
                continue
            entry = entries.get(call_id)
            if entry is None:
                issue(index, "terminal-without-entry", call_id)
                continue
            if call_id in seen_terminal:
                issue(index, "duplicate-terminal-event", call_id)
                continue
            if call_id not in active:
                issue(index, "terminal-for-inactive-call", call_id)
                continue
            if active[-1] != call_id:
                issue(index, "terminal-is-not-current-stack-top", call_id)
                continue
            if event.get("api") != entry["api"]:
                issue(index, "terminal-api-name-mismatch", call_id)
            expected_parent = entry["parent_call_id"]
            actual_parent = event.get("parent_call_id")
            parent_matches = (
                actual_parent is None if expected_parent is None
                else valid_id(actual_parent) and actual_parent == expected_parent
            )
            if not parent_matches:
                issue(index, "terminal-parent-id-mismatch", call_id)

            if kind == "api_return" and entry["api"] == "qi864985u0":
                outputs = event.get("outputs")
                if isinstance(outputs, Mapping):
                    for output_kind in ("mid", "otp"):
                        output = outputs.get(output_kind)
                        if not isinstance(output, Mapping):
                            continue
                        pointer = output.get("pointer")
                        length = output.get("length")
                        if (type(pointer) is int and pointer > 0
                                and type(length) is int and length >= 0):
                            live_outputs.setdefault(pointer, []).append({
                                "kind": output_kind,
                                "call_id": call_id,
                                "length": length,
                            })
                            tracked_outputs += 1

            if kind == "api_return" and entry["api"] == "jk24uiwqrg":
                expected_owner = entry.get("dispose_owner")
                returned_owner = event.get("disposed_output_owner")
                if returned_owner != expected_owner:
                    issue(index, "dispose-return-owner-mismatch", call_id)
                elif expected_owner is not None:
                    pointer = entry.get("dispose_pointer")
                    owners = live_outputs.get(pointer, []) if pointer else []
                    if owners and owners[0] == expected_owner:
                        owners.pop(0)
                        disposed_outputs += 1
                        if not owners:
                            del live_outputs[pointer]
                    else:
                        issue(index, "dispose-owner-not-live", call_id)

            active.pop()
            seen_terminal.add(call_id)
            continue

        if kind == "api_return_probe_error":
            call_id = event.get("call_id")
            if not valid_id(call_id) or call_id not in active:
                issue(index, "return-probe-error-for-inactive-call", call_id)
            else:
                issue(index, "return-probe-creation-failed", call_id)
            continue

        if kind == "opcode_arguments":
            call_id = event.get("api_call_id")
            if call_id is None:
                continue
            if not valid_id(call_id) or not active or active[-1] != call_id:
                issue(index, "opcode-capture-call-id-not-current-frame", call_id)

    outstanding_owners = [
        {"kind": owner["kind"], "call_id": owner["call_id"], "length": owner["length"]}
        for owners in live_outputs.values()
        for owner in owners
    ]
    for owner in outstanding_owners:
        issue(index + 1 if "index" in locals() else 0,
              "output-allocation-not-disposed", owner.get("call_id"))

    return {
        "valid": bool(entries) and not errors and not active,
        "event_count": index + 1 if "index" in locals() else 0,
        "api_entry_count": counts["api_entry"],
        "api_return_count": counts["api_return"],
        "api_unwind_count": counts["api_unwind"],
        "return_probe_error_count": counts["api_return_probe_error"],
        "opcode_arguments_count": counts["opcode_arguments"],
        "tracked_output_allocations": tracked_outputs,
        "disposed_output_allocations": disposed_outputs,
        "outstanding_output_allocations": len(outstanding_owners),
        "open_call_ids": list(active),
        "errors": errors,
    }


def validate_api_event_log(path: "Path") -> dict[str, Any]:
    """Read a private JSONL trace and return a metadata-only validation report."""
    import json
    from pathlib import Path as _Path

    source = _Path(path)
    events: list[object] = []
    parse_errors: list[dict[str, int | str]] = []
    try:
        with source.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    parse_errors.append({
                        "line": line_number,
                        "code": "invalid-json",
                    })
    except OSError as exc:
        return {
            "valid": False,
            "event_count": 0,
            "errors": [{"code": f"input-read-error:{type(exc).__name__}"}],
            "jsonl_parse_errors": parse_errors,
        }

    summary = validate_api_event_stream(events)
    summary["jsonl_parse_errors"] = parse_errors
    if parse_errors:
        summary["valid"] = False
    return summary
