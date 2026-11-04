# gdb-python: КАУЗАЛЬНЫЙ ТЕСТ «ВРЕМЯ = КЛЮЧ».
#
# gettimeofday из vdfut768ig (единственный обращение движка к часам)
# подменяется на фиксированное значение tv. Если два прогона с ОДНИМИ
# и теми же замороженными часами дают ОДИНАКОВЫЙ CPIM — время доказано
# как вариативный вход генезиса. Доктрина: прямые BPs, stop() -> False.
import gdb
import os as _os

LOG = _os.environ.get("ADI_PROBE_LOG", "/opt/data/adi-re/time_freeze.log")
FROZEN_SEC = 1793783000
FROZEN_USEC = 123456
STATE = {"gt": 0, "poked": 0}


def log(msg):
    with open(LOG, "a") as f:
        f.write(msg + "\n")


def return_from_gettimeofday(tv):
    """Write a deterministic timeval and emulate a successful function return."""
    rsp = ru("$rsp")
    ret = ru("*(unsigned long long*)%#x" % rsp)
    if tv:
        gdb.execute("set {unsigned long long}%d = %d" % (tv, FROZEN_SEC))
        gdb.execute("set {unsigned long long}%d = %d" % (tv + 8, FROZEN_USEC))
    gdb.execute("set $rax = 0")
    gdb.execute("set $rsp = %#x" % (rsp + 8))
    gdb.execute("set $pc = %#x" % ret)
    return ret


class GtBP(gdb.Breakpoint):
    def __init__(self):
        super().__init__("gettimeofday", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        STATE["gt"] += 1
        try:
            caller = gdb.execute("bt 4", to_string=True)
        except Exception:  # noqa: BLE001
            caller = ""
        if "vdfut768ig" in caller:
            try:
                tv = ru("$rdi")
                return_from_gettimeofday(tv)
                STATE["poked"] += 1
                log("POKE gettimeofday #%d" % STATE["poked"])
            except Exception as e:  # noqa: BLE001
                log("gettimeofday freeze ERR %s" % type(e).__name__)
                return True
        else:
            log("gt call #%d outside vdfut (left)" % STATE["gt"])
        return False

gdb.execute("set pagination off")
gdb.execute("set confirm off")
gdb.execute("set breakpoint pending on")

_raw = gdb.parameter("args")
_args = (_raw.string if hasattr(_raw, "string") else str(_raw)).split()
if _args and _args[0].endswith("adi_native"):
    _prog, _rest = _os.path.abspath(_args[0]), _args[1:]
else:
    _prog, _rest = _os.path.join(_os.getcwd(), "adi_native"), _args
_root = _os.path.dirname(_prog)
_libs = _os.path.abspath(_rest[0]) if _rest else _root + "/libs"
_sysroot = _root + "/sysroot"
open(LOG, "w").write("time freeze start\n")
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
log("armed: freeze tv -> %d.%d" % (FROZEN_SEC, FROZEN_USEC))