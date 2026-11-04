# gdb-python: КАУЗАЛЬНЫЙ ТЕСТ «ВРЕМЯ/rdtsc = КЛЮЧ», версия 2.
#
# Проба 1 (только gettimeofday) НЕ стабилизировала CPIM. Теперь
# замораживаем ВСЕ источники: gettimeofday из vdfut (tv = константа)
# + все три подтверждённых rdtsc внутри vdfut (0xDE36A, 0xF3DB5,
# 0xF43E6 — валидированы objdump'ом; ложные 0f31 внутри других
# инструкций исключены). Если два прогона с ОДНИМИ константами дают
# одинаковый CPIM — вход доказан. Доктрина: прямые BPs, stop() -> False.
import gdb

LOG = "/opt/data/adi-re/rdtsc_freeze.log"
FROZEN_SEC = 1793783000
FROZEN_USEC = 123456
FROZEN_RAX = 0x11111111
FROZEN_RDX = 0x22222222
RDTSC_SITES = [0xDE36A, 0xF3DB5, 0xF43E6]  # RVA внутри vdfut768ig
VDFUT_DELTA = 0x87550
STATE = {"gt": 0, "poked": 0, "rd": 0, "rdp": 0, "base": None}


def log(msg):
    with open(LOG, "a") as f:
        f.write(msg + "\n")


def ru(expr):
    return int(gdb.parse_and_eval(expr)) & 0xFFFFFFFFFFFFFFFF


class GtBP(gdb.Breakpoint):
    def __init__(self):
        super().__init__("gettimeofday", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        STATE["gt"] += 1
        try:
            caller = gdb.execute("bt 2", to_string=True)
        except Exception:  # noqa: BLE001
            caller = ""
        if "vdfut768ig" in caller:
            tv = ru("$rdi")
            gdb.execute("set {unsigned long long}%d = %d" % (tv, FROZEN_SEC))
            gdb.execute("set {unsigned long long}%d = %d" % (tv + 8, FROZEN_USEC))
            STATE["poked"] += 1
            log("POKE timeval #%d" % STATE["poked"])
        else:
            log("gt #%d outside vdfut (left)" % STATE["gt"])
        return False


class RdtscBP(gdb.Breakpoint):
    """Пропускаем rdtsc (0F 31, 2 байта) и подставляем константу EDX:EAX."""

    def __init__(self, addr):
        super().__init__("*%#x" % addr, gdb.BP_BREAKPOINT, internal=False)
        self.silent = True
        self.addr = addr

    def stop(self):
        STATE["rd"] += 1
        STATE["rdp"] += 1
        if STATE["rdp"] <= 6:
            try:
                log("RDTSC freeze @%#x (hit #%d)" % (self.addr, STATE["rd"]))
            except Exception:  # noqa: BLE001
                pass
        try:
            gdb.execute("set $rax = %#x" % FROZEN_RAX)
            gdb.execute("set $rdx = %#x" % FROZEN_RDX)
            gdb.execute("set $pc = %#x" % (self.addr + 2))
        except Exception as e:  # noqa: BLE001
            log("rdtsc poke ERR %s" % e)
        return False


class ArmBP(gdb.Breakpoint):
    def __init__(self):
        super().__init__("vdfut768ig", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        if STATE["base"] is not None:
            return False
        sym = ru("&vdfut768ig")
        STATE["base"] = sym - VDFUT_DELTA
        log("armed base=%#x" % STATE["base"])
        for rva in RDTSC_SITES:
            RdtscBP(STATE["base"] + rva)
        return False


gdb.execute("set pagination off")
gdb.execute("set confirm off")
gdb.execute("set breakpoint pending on")

import os as _os

_raw = gdb.parameter("args")
_args = (_raw.string if hasattr(_raw, "string") else str(_raw)).split()
if _args and _args[0].endswith("adi_native"):
    _prog, _rest = _os.path.abspath(_args[0]), _args[1:]
else:
    _prog, _rest = _os.path.join(_os.getcwd(), "adi_native"), _args
_root = _os.path.dirname(_prog)
_libs = _os.path.abspath(_rest[0]) if _rest else _root + "/libs"
_sysroot = _root + "/sysroot"
open(LOG, "w").write("rdtsc freeze start\n")
for _k, _v in {
    "LD_LIBRARY_PATH": _libs + ":" + _sysroot + "/lib64",
    "ANDROID_ROOT": "/system",
    "ANDROID_DATA": "/data",
    "ANDROID_RUNTIME_ROOT": "/apex/com.android.runtime",
    "CA_BUNDLE": _root + "/apple_chain.pem",
    "ADI_RESOLVE": "gsa.apple.com:443:17.179.252.2",
}.items():
    gdb.execute("set environment %s=%s" % (_k, _v))

GtBP()
ArmBP()
log("armed: tv=%d.%d rdtsc=0x%x:%x sites=%s"
    % (FROZEN_SEC, FROZEN_USEC, FROZEN_RDX, FROZEN_RAX, [hex(s) for s in RDTSC_SITES]))