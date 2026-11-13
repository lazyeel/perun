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
import gdb

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
}
API_PHASES = {
    "rsegvyrt87": 1,  # ProvisioningStart
    "uv5t6nhkui": 2,  # ProvisioningEnd
    "aslgmuibau": 3,  # GetLoginCode
    "qi864985u0": 4,  # OTPRequest
}
STATE = {
    "vdfut": 0,
    "cvu": 0,
    "api": 0,
    "last_api_phase": 0,
    "login_code_calls": 0,
}


def emit(kind: str, phase: int, detail: str) -> None:
    phase_name = PHASES.get(phase, "unknown")
    line = f"phase={phase} phase_name={phase_name} {kind}={detail}\n"
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
        "phase_id": phase,
        "phase": PHASES.get(phase, "unknown"),
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


class ExportBreakpoint(gdb.Breakpoint):
    def __init__(self, symbol: str) -> None:
        self.symbol = symbol
        super().__init__(symbol, gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self) -> bool:
        phase = read_int("g_adi_phase")
        if phase < 0:
            if self.symbol == "aslgmuibau":
                # adi_test.c checks login status once before configuration
                # and once after SetAndroidID; the third call follows End.
                STATE["login_code_calls"] += 1
                phase = 3 if STATE["login_code_calls"] >= 3 else 0
            else:
                phase = API_PHASES.get(self.symbol, -1)
        STATE["last_api_phase"] = phase
        STATE["api"] += 1
        emit("api", phase, self.symbol)
        return False


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
for symbol in ("rsegvyrt87", "uv5t6nhkui", "qi864985u0", "aslgmuibau"):
    try:
        ExportBreakpoint(symbol)
    except Exception as exc:
        emit("breakpoint_error", 0, f"{symbol}:{type(exc).__name__}")

VdfutBreakpoint()
CvuBreakpoint()
emit("trace", 0, "armed")
