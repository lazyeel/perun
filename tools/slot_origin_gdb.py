# gdb-python: ОТКУДА ВАРИАТИВНЫЕ СЛОТЫ — сторы или мусор кадра?
#
# Пять читаемых филлом слотов ([rbp-0x218/-0x2f0/-0x318/-0x340/-0x358])
# меняются между прогонами при замороженных time/rdtsc. Статически им
# соответствуют сторы в кластерах 0x9C2xx (ранняя фаза) и 0xE0C80..0xE12F4
# (байтовые сторы перед филлом). Если ни один стор НЕ выполняется —
# слоты = неинициализированный мусор кадра (источник вариативности).
# Доктрина: прямые BPs, stop() -> False.
import gdb

LOG = "/opt/data/adi-re/slot_origin.log"
VDFUT_DELTA = 0x87550
STATE = {"base": None, "hits": {}}

# (RVA, слот) — сторы вариативных слотов из objdump-поиска
STORES = [
    (0x9C2B1, "q218_9c"), (0x9C360, "q2f0_9c"), (0x9C47C, "q318_9c"),
    (0x9C340, "q340_9c"), (0x9C5AC, "q358_9c"),
    (0xE0C80, "b340_e0c80"), (0xE0C89, "b2f0_e0c89"),
    (0xE0D8B, "b218_e0d8b"), (0xE10E4, "b318_e10e4"),
    (0xE12F0, "x218_e12f0"), (0xE1DF5, "d218_e1df5"),
    (0xE43A4, "d218_e43a4"),
    (0xAFDAF, "q218_afd"), (0xEBA69, "q318_eba"),
]


def log(msg):
    with open(LOG, "a") as f:
        f.write(msg + "\n")


def ru(expr):
    return int(gdb.parse_and_eval(expr)) & 0xFFFFFFFFFFFFFFFF


class StoreBP(gdb.Breakpoint):
    def __init__(self, addr, name):
        super().__init__("*%#x" % addr, gdb.BP_BREAKPOINT, internal=False)
        self.silent = True
        self.name = name

    def stop(self):
        STATE["hits"][self.name] = STATE["hits"].get(self.name, 0) + 1
        n = STATE["hits"][self.name]
        if n == 1:
            try:
                bt = gdb.execute("bt 4", to_string=True)
            except Exception:  # noqa: BLE001
                bt = "?"
            log("FIRST STORE %s (total will grow) bt:\n%s" % (self.name, bt))
        if n <= 200 and n % 50 == 0:
            log("store %s count=%d" % (self.name, n))
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
        for rva, name in STORES:
            StoreBP(STATE["base"] + rva, name)
        log("armed base=%#x stores=%d" % (STATE["base"], len(STORES)))
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
open(LOG, "w").write("slot origin start\n")
for _k, _v in {
    "LD_LIBRARY_PATH": _libs + ":" + _sysroot + "/lib64",
    "ANDROID_ROOT": "/system",
    "ANDROID_DATA": "/data",
    "ANDROID_RUNTIME_ROOT": "/apex/com.android.runtime",
    "CA_BUNDLE": _root + "/apple_chain.pem",
    "ADI_RESOLVE": "gsa.apple.com:443:17.179.252.2",
}.items():
    gdb.execute("set environment %s=%s" % (_k, _v))

ArmBP()
# Итоговые счётчики добираются из FIRST STORE/count-строк лога; BP на exit
# в PIE-плт зависал inferior на старте (futex-deadlock под ptrace) — не ставим.
log("armed: %s" % [n for _, n in STORES])