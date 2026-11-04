# gdb-python: КАКОЙ ВХОД ВАРИАТИВЕН — время или случайность?
#
# CPIM/session16/плантер меняются от прогона к прогону при фиксированных
# (spim, identity). Дискриминация: ловим обращения движка к clock--API
# (clock_gettime/gettimeofday/time) и к /dev/urandom во время pStart.
# Доктрина: прямые BPs, stop() -> False, никаких watchpoints/post_event.
import gdb

LOG = "/opt/data/adi-re/input_probe.log"
STATE = {"armed": False, "cp": 0, "gt": 0, "tm": 0, "ur": 0, "gr": 0}


def log(msg):
    with open(LOG, "a") as f:
        f.write(msg + "\n")


def ru(expr):
    return int(gdb.parse_and_eval(expr)) & 0xFFFFFFFFFFFFFFFF


class SymBP(gdb.Breakpoint):
    """Обычный символ (clock_gettime / gettimeofday / time / getrandom)."""

    def __init__(self, spec, key):
        super().__init__(spec, gdb.BP_BREAKPOINT, internal=False)
        self.silent = True
        self.key = key

    def stop(self):
        STATE[self.key] += 1
        n = STATE[self.key]
        if n <= 5:
            try:
                bt = gdb.execute("bt 3", to_string=True)
            except Exception:  # noqa: BLE001
                bt = "?"
            log("CALL %s #%d\n%s" % (self.key, n, bt))
        return False


class OpenBP(gdb.Breakpoint):
    """open/openat: фильтруем /dev/urandom и clock-файлы по аргументу пути."""

    def __init__(self, spec, pathreg):
        super().__init__(spec, gdb.BP_BREAKPOINT, internal=False)
        self.silent = True
        self.pathreg = pathreg

    def stop(self):
        try:
            p = int(gdb.parse_and_eval("*(char**)(%s)" % self.pathreg))
            if p == 0:
                return False
            path = gdb.execute("x/s %d" % p, to_string=True).split('"')[1]
        except Exception:  # noqa: BLE001
            return False
        if "/dev/urandom" in path or "/dev/random" in path or "timezone" in path or "tzdata" in path:
            STATE["ur"] += 1
            if STATE["ur"] <= 5:
                try:
                    bt = gdb.execute("bt 3", to_string=True)
                except Exception:  # noqa: BLE001
                    bt = "?"
                log("OPEN %s #%d\n%s" % (path, STATE["ur"], bt))
        return False


gdb.execute("set pagination off")
gdb.execute("set confirm off")
gdb.execute("set breakpoint pending on")

# env inferiorу (gdb 16.3 выкидывает LD_LIBRARY_PATH — см. genesis_probe)
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
open(LOG, "w").write("input probe start\n")
for _k, _v in {
    "LD_LIBRARY_PATH": _libs + ":" + _sysroot + "/lib64",
    "ANDROID_ROOT": "/system",
    "ANDROID_DATA": "/data",
    "ANDROID_RUNTIME_ROOT": "/apex/com.android.runtime",
    "CA_BUNDLE": _root + "/apple_chain.pem",
    "ADI_RESOLVE": "gsa.apple.com:443:17.179.252.2",
}.items():
    gdb.execute("set environment %s=%s" % (_k, _v))

# bionic libc выгружен в sysroot — символы разрешатся после загрузки
SymBP("clock_gettime", "cp")
SymBP("gettimeofday", "gt")
SymBP("time", "tm")
SymBP("getrandom", "gr")
OpenBP("open", "rdi")
OpenBP("openat", "rsi")      # openat(dirfd, path) -> rsi
log("probes armed")