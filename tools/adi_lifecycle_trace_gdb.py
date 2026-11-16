#!/usr/bin/env python3
"""Low-distortion GDB trace of the complete Android ADI lifecycle.

The default trace records only the harness phase, public export name and
vdfut opcode. It does not record pointers, register contents, memory, SPIM,
CPIM, ptm/tk, device identity, MID or OTP bytes.

An opt-in private argument capture is available through
`ADI_LIFECYCLE_ARGS_LOG`. It records candidate argument registers and bounded
memory snapshots only for ProvisioningEnd and the OTP dispatch opcodes. This
data can contain protocol secrets and must remain in a mode-0700 directory,
be age-encrypted before upload, and never appear in a public log or manifest.

Run through run-native.sh with:
  ADI_GDB=1
  GDB_SCRIPT=tools/adi_lifecycle_trace_gdb.py
  ADI_LIFECYCLE_TRACE_LOG=<private path>
  ADI_LIFECYCLE_ARGS_LOG=<private path>

Harness phase markers are defined by g_adi_phase:
  0 setup, 1 ProvisioningStart, 2 ProvisioningEnd,
  3 post-End ADIGetLoginCode, 4 OTPRequest.
"""

from __future__ import annotations

import json
import os
import sys
import gdb

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

from adi_lifecycle_trace_helpers import (
    parse_out_slot_address,
    peek_output_allocation,
    remember_output_allocation,
    resolve_output_buffer,
    take_output_allocation,
)

LOG_PATH = os.environ.get("ADI_LIFECYCLE_TRACE_LOG")
if not LOG_PATH:
    raise RuntimeError("ADI_LIFECYCLE_TRACE_LOG must point inside the private capture directory")

parent = os.path.dirname(os.path.abspath(LOG_PATH))
os.makedirs(parent, mode=0o700, exist_ok=True)
flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_CLOEXEC", 0)
flags |= getattr(os, "O_NOFOLLOW", 0)
LOG_FD = os.open(LOG_PATH, flags, 0o600)
os.fchmod(LOG_FD, 0o600)

# Optional raw register/pointer snapshots. This file must remain private and
# must be encrypted before it leaves the ephemeral runner.
ARGS_LOG_PATH = os.environ.get("ADI_LIFECYCLE_ARGS_LOG")
ARGS_FD = None
if ARGS_LOG_PATH:
    args_parent = os.path.dirname(os.path.abspath(ARGS_LOG_PATH))
    os.makedirs(args_parent, mode=0o700, exist_ok=True)
    args_flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_CLOEXEC", 0)
    args_flags |= getattr(os, "O_NOFOLLOW", 0)
    ARGS_FD = os.open(ARGS_LOG_PATH, args_flags, 0o600)
    os.fchmod(ARGS_FD, 0o600)

PHASES = {
    0: "setup",
    1: "provisioning_start",
    2: "provisioning_end",
    3: "login_code_after_end",
    4: "otp_request",
    5: "dispose",
}
API_PHASES = {
    "rsegvyrt87": 1,  # ProvisioningStart
    "uv5t6nhkui": 2,  # ProvisioningEnd
    "aslgmuibau": 3,  # GetLoginCode
    "qi864985u0": 4,  # OTPRequest
    "jk24uiwqrg": 5,  # ADI_Dispose
}
STATE = {
    "vdfut": 0,
    "cvu": 0,
    "api": 0,
    "last_api_phase": 0,
    "login_code_calls": 0,
    "api_call_seq": 0,
    "api_stack": [],
    "api_records": {},
    "pending_api_return": None,
    "api_return_bps": [],
    "last_otp_call_id": None,
    "otp_allocations": {},
}


def emit(kind: str, phase: int, detail: str) -> None:
    phase_name = PHASES.get(phase, "unknown")
    active_call_id = STATE["api_stack"][-1] if STATE["api_stack"] else 0
    line = (
        f"phase={phase} phase_name={phase_name} "
        f"api_call_id={active_call_id} {kind}={detail}\n"
    )
    os.write(LOG_FD, line.encode("ascii", "replace"))


def read_int(expression: str, default: int = -1) -> int:
    try:
        return int(gdb.parse_and_eval(expression))
    except Exception:
        return default


# Argument snapshots are limited to the End opcode and the three OTP
# dispatches. Capturing every vdfut entry in these phases would produce large,
# mostly irrelevant traces and obscure the two repeated OTP operations.
CAPTURE_ARGUMENT_OPCODES = {
    0x0B2B3196,  # ProvisioningEnd
    0xCFE0B46A,  # OTPRequest stage 0
    0x3E58E7F9,  # OTPRequest repeated stage
}


def capture_opcode_arguments(phase: int, opcode: int) -> None:
    """Capture bounded candidate ABI state for selected private opcodes."""
    if (ARGS_FD is None or phase not in (2, 4)
            or opcode not in CAPTURE_ARGUMENT_OPCODES):
        return

    names = ("rsi", "rdx", "rcx", "r8", "r9", "rsp")
    regs = {
        name: read_int(f"${name}", 0) & 0xFFFFFFFFFFFFFFFF
        for name in names
    }
    memory: dict[str, dict[str, object]] = {}
    inferior = gdb.selected_inferior()

    # These are candidate pointer values, not asserted argument types.
    for name in names:
        address = regs[name]
        if address < 0x10000 or address >= 0x0000800000000000:
            continue
        width = 128 if name == "rsp" else 256
        try:
            data = bytes(inferior.read_memory(address, width))
            memory[name] = {"bytes": len(data), "hex": data.hex()}
        except Exception as exc:
            memory[name] = {"read_error": type(exc).__name__}

    record = {
        "event": "opcode_arguments",
        "phase_id": phase,
        "phase": PHASES.get(phase, "unknown"),
        "api_call_id": STATE["api_stack"][-1] if STATE["api_stack"] else None,
        "opcode": f"0x{opcode:08x}",
        "pc": f"0x{read_int('$pc', 0) & 0xFFFFFFFFFFFFFFFF:016x}",
        "registers": {
            name: f"0x{value:016x}" for name, value in regs.items()
        },
        "memory": memory,
    }
    payload = (json.dumps(record, separators=(",", ":")) + "\n").encode("ascii")
    os.write(ARGS_FD, payload)


class VdfutBreakpoint(gdb.Breakpoint):
    def __init__(self) -> None:
        super().__init__("vdfut768ig", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self) -> bool:
        phase = read_int("g_adi_phase")
        if phase < 0:
            phase = STATE["last_api_phase"]
        opcode = read_int("$rdi", 0) & 0xFFFFFFFF
        STATE["vdfut"] += 1
        emit("opcode", phase, f"0x{opcode:08x}")
        capture_opcode_arguments(phase, opcode)
        return False


class CvuBreakpoint(gdb.Breakpoint):
    def __init__(self) -> None:
        super().__init__("cvu8io98wun", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self) -> bool:
        phase = read_int("g_adi_phase")
        STATE["cvu"] += 1
        emit("coreadi_init", phase, "cvu8io98wun")
        return False




# Export-level call correlation. The C harness prototypes in adi_test.c define
# the x86-64 SysV argument contract. We record entry AND return so output
# pointers/lengths are resolved after the engine has populated them. Raw
# buffers are written only to ADI_LIFECYCLE_ARGS_LOG (mode 0600); the public
# trace contains call IDs and status, never pointer or token material.
API_GPRS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9", "rsp")
MAX_CAPTURE_INPUT = 8192
MAX_CAPTURE_OUTPUT = 4096


def read_u64_at(address: int) -> int:
    if address <= 0x10000:
        return 0
    return int.from_bytes(bytes(gdb.selected_inferior().read_memory(address, 8)), "little")


def read_u32_at(address: int) -> int:
    if address <= 0x10000:
        return 0
    return int.from_bytes(bytes(gdb.selected_inferior().read_memory(address, 4)), "little")


def capture_bytes(address: int, length: int, limit: int = MAX_CAPTURE_INPUT) -> dict[str, object]:
    if address <= 0x10000 or length < 0 or length > limit:
        return {"address": f"0x{address:x}", "length": length, "status": "rejected-bound"}
    try:
        data = bytes(gdb.selected_inferior().read_memory(address, length))
        return {
            "address": f"0x{address:x}",
            "length": length,
            "status": "ok",
            "hex": data.hex(),
        }
    except Exception as exc:
        return {
            "address": f"0x{address:x}",
            "length": length,
            "status": f"read-error:{type(exc).__name__}",
        }


def write_private_event(record: dict[str, object]) -> None:
    if ARGS_FD is None:
        return
    payload = (json.dumps(record, separators=(",", ":")) + "\n").encode("ascii")
    os.write(ARGS_FD, payload)


def api_entry_record(symbol: str, phase: int) -> dict[str, object]:
    """Capture ABI-defined call arguments while keeping raw data private."""
    STATE["api_call_seq"] += 1
    call_id = STATE["api_call_seq"]
    parent_id = STATE["api_stack"][-1] if STATE["api_stack"] else None
    regs = {
        name: read_int("$" + name, 0) & 0xFFFFFFFFFFFFFFFF
        for name in API_GPRS
    }
    record: dict[str, object] = {
        "event": "api_entry",
        "call_id": call_id,
        "parent_call_id": parent_id,
        "api": symbol,
        "phase_id": phase,
        "phase": PHASES.get(phase, "unknown"),
        "pc": f"0x{read_int('$pc', 0) & 0xFFFFFFFFFFFFFFFF:016x}",
        "registers": {name: f"0x{value:016x}" for name, value in regs.items()},
        "arguments": {},
    }
    args = record["arguments"]
    assert isinstance(args, dict)

    if symbol == "rsegvyrt87":  # ADI_ProvisioningStart
        spim_ptr, spim_len = regs["rsi"], regs["rdx"] & 0xFFFFFFFF
        args.update({
            "ds_id": f"0x{regs['rdi']:016x}",
            "spim": capture_bytes(spim_ptr, spim_len),
            "cpim_out_slot": f"0x{regs['rcx']:x}",
            "cpim_len_out_slot": f"0x{regs['r8']:x}",
            "session_out_slot": f"0x{regs['r9']:x}",
        })
    elif symbol == "uv5t6nhkui":  # ADI_ProvisioningEnd
        ptm_ptr, ptm_len = regs["rsi"], regs["rdx"] & 0xFFFFFFFF
        tk_ptr, tk_len = regs["rcx"], regs["r8"] & 0xFFFFFFFF
        args.update({
            "session": regs["rdi"] & 0xFFFFFFFF,
            "ptm": capture_bytes(ptm_ptr, ptm_len),
            "tk": capture_bytes(tk_ptr, tk_len),
        })
    elif symbol == "qi864985u0":  # ADI_OTPRequest
        args.update({
            "ds_id": f"0x{regs['rdi']:016x}",
            "mid_out_slot": regs["rsi"],
            "mid_len_out_slot": regs["rdx"],
            "otp_out_slot": regs["rcx"],
            "otp_len_out_slot": regs["r8"],
        })
    elif symbol == "aslgmuibau":  # ADI_GetLoginCode
        args["ds_id"] = f"0x{regs['rdi']:016x}"
    elif symbol == "jk24uiwqrg":  # ADI_Dispose
        ptr = regs["rdi"]
        owner = peek_output_allocation(STATE["otp_allocations"], ptr)
        args.update({
            "pointer": f"0x{ptr:x}",
            "otp_output_owner": owner,
        })

    STATE["api_records"][call_id] = record
    STATE["api_stack"].append(call_id)
    if symbol == "qi864985u0":
        STATE["last_otp_call_id"] = call_id
    STATE["pending_api_return"] = record
    write_private_event(record)
    emit("api_entry", phase, f"{symbol}:call_id={call_id}:parent={parent_id or 0}")
    return record


def api_output_from_slots(record: dict[str, object]) -> dict[str, object]:
    """Resolve C out-parameters after return, not from their pre-call values."""
    symbol = str(record["api"])
    args = record.get("arguments", {})
    if not isinstance(args, dict):
        return {}
    result: dict[str, object] = {}

    def output(name: str, pointer_slot_key: str, length_slot_key: str) -> dict[str, object]:
        return resolve_output_buffer(
            args[pointer_slot_key],
            args[length_slot_key],
            read_u64_at=read_u64_at,
            read_u32_at=read_u32_at,
            capture_bytes=capture_bytes,
            limit=MAX_CAPTURE_OUTPUT,
        )

    if symbol == "qi864985u0":
        result["mid"] = output("mid", "mid_out_slot", "mid_len_out_slot")
        result["otp"] = output("otp", "otp_out_slot", "otp_len_out_slot")
        for name in ("mid", "otp"):
            item = result[name]
            assert isinstance(item, dict)
            remember_output_allocation(
                STATE["otp_allocations"],
                item.get("pointer"),
                kind=name,
                call_id=int(record["call_id"]),
                length=int(item.get("length", 0)),
            )
    elif symbol == "rsegvyrt87":
        result["cpim"] = resolve_output_buffer(
            args["cpim_out_slot"],
            args["cpim_len_out_slot"],
            read_u64_at=read_u64_at,
            read_u32_at=read_u32_at,
            capture_bytes=capture_bytes,
            limit=MAX_CAPTURE_OUTPUT,
        )
        try:
            session_slot = parse_out_slot_address(args["session_out_slot"])
            result["session"] = read_u32_at(session_slot)
        except (TypeError, ValueError, Exception) as exc:
            result["session"] = {"status": f"session-out-slot-error:{type(exc).__name__}"}
    return result


def remove_api_call(call_id: int) -> None:
    stack = STATE["api_stack"]
    if call_id in stack:
        # An out-of-scope finish breakpoint means this frame and any nested
        # frames above it did not return through their normal epilogues.
        del stack[stack.index(call_id):]
    STATE["api_records"].pop(call_id, None)


class ApiReturnBreakpoint(gdb.FinishBreakpoint):
    """One return probe per export invocation; correlates output slots to call_id."""
    def __init__(self, record: dict[str, object]) -> None:
        super().__init__(gdb.newest_frame(), internal=True)
        self.record = record

    def stop(self) -> bool:
        record = self.record
        symbol = str(record["api"])
        phase = int(record["phase_id"])
        return_value = read_int("$rax", 0) & 0xFFFFFFFF
        outputs = api_output_from_slots(record)
        disposed_owner = None
        if symbol == "jk24uiwqrg":
            args = record.get("arguments", {})
            try:
                pointer = parse_out_slot_address(args.get("pointer"))
                disposed_owner = take_output_allocation(
                    STATE["otp_allocations"], pointer
                )
            except (TypeError, ValueError):
                pass
        result: dict[str, object] = {
            "event": "api_return",
            "call_id": record["call_id"],
            "parent_call_id": record["parent_call_id"],
            "api": symbol,
            "phase_id": phase,
            "phase": PHASES.get(phase, "unknown"),
            "return_value": return_value if symbol != "jk24uiwqrg" else None,
            "outputs": outputs,
            "disposed_output_owner": disposed_owner,
        }
        write_private_event(result)
        if symbol == "qi864985u0":
            mid = outputs.get("mid", {})
            otp = outputs.get("otp", {})
            mid_len = mid.get("length", -1) if isinstance(mid, dict) else -1
            otp_len = otp.get("length", -1) if isinstance(otp, dict) else -1
            emit(
                "api_return",
                phase,
                f"{symbol}:call_id={record['call_id']}:rc={return_value}:mid_len={mid_len}:otp_len={otp_len}",
            )
        else:
            emit("api_return", phase, f"{symbol}:call_id={record['call_id']}:rc={return_value}")
        remove_api_call(int(record["call_id"]))
        return False

    def out_of_scope(self) -> None:
        record = self.record
        result = {
            "event": "api_unwind",
            "call_id": record["call_id"],
            "parent_call_id": record["parent_call_id"],
            "api": record["api"],
            "phase_id": record["phase_id"],
            "status": "out-of-scope",
        }
        write_private_event(result)
        emit("api_unwind", int(record["phase_id"]), f"{record['api']}:call_id={record['call_id']}")
        remove_api_call(int(record["call_id"]))


def arm_api_return() -> None:
    """Run from a breakpoint command list because GDB cannot mutate BPs in stop()."""
    record = STATE.pop("pending_api_return", None)
    if record is None:
        emit("api_trace_error", 0, "return probe requested without pending API entry")
        return
    try:
        bp = ApiReturnBreakpoint(record)
        STATE["api_return_bps"].append(bp)
    except Exception as exc:
        write_private_event({
            "event": "api_return_probe_error",
            "call_id": record["call_id"],
            "api": record["api"],
            "error": type(exc).__name__,
        })
        emit("api_trace_error", int(record["phase_id"]), f"{record['api']}:call_id={record['call_id']}:{type(exc).__name__}")


class ExportBreakpoint(gdb.Breakpoint):
    def __init__(self, symbol: str) -> None:
        self.symbol = symbol
        super().__init__(symbol, gdb.BP_BREAKPOINT, internal=False)
        self.silent = True
        # Defer FinishBreakpoint creation until after stop() returns; GDB does
        # not permit mutating the breakpoint set directly inside stop().
        self.commands = """silent
python
arm_api_return()
end
continue
"""

    def stop(self) -> bool:
        phase = read_int("g_adi_phase")
        if self.symbol == "jk24uiwqrg":
            phase = 5
        elif phase < 0:
            if self.symbol == "aslgmuibau":
                # adi_test.c checks login status once before configuration
                # and once after SetAndroidID; the third call follows End.
                STATE["login_code_calls"] += 1
                phase = 3 if STATE["login_code_calls"] >= 3 else 0
            else:
                phase = API_PHASES.get(self.symbol, -1)
        STATE["last_api_phase"] = phase
        STATE["api"] += 1
        api_entry_record(self.symbol, phase)
        return True


gdb.execute("set pagination off", to_string=True)
gdb.execute("set confirm off", to_string=True)
gdb.execute("set breakpoint pending on", to_string=True)
gdb.execute("set print thread-events off", to_string=True)
gdb.execute("set breakpoint auto-hw on", to_string=True)

with os.fdopen(os.dup(LOG_FD), "w", encoding="ascii") as stream:
    stream.write("adi lifecycle trace v1\n")
    stream.flush()

# These are the exact exports resolved by adi_test.c. Pending breakpoints are
# resolved when dlopen maps the Apple library; unresolved symbols remain
# harmless and are visible in the final breakpoint table if needed.
for symbol in ("rsegvyrt87", "uv5t6nhkui", "qi864985u0", "aslgmuibau", "jk24uiwqrg"):
    try:
        ExportBreakpoint(symbol)
    except Exception as exc:
        emit("breakpoint_error", 0, f"{symbol}:{type(exc).__name__}")

VdfutBreakpoint()
CvuBreakpoint()
emit("trace", 0, "armed")
