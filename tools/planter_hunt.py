# gdb-python v24: ОХОТА НА ПИСАТЕЛЯ ПЛАНТЕРА.
# Плантер живёт на детерминированном адресе в gdb-прогонах (~0x7fffffff4a90..4af0).
# Ставим hardware watchpoint на начало этого региона С МОМЕНТА загрузки libCoreADI
# и логируем КАЖДЫЙ писатель до transform.
import gdb

LOG = "/opt/data/adi-re/planter_hunt.log"
STATE = {"base": None, "n": 0, "planter_addr": None, "done": False}
VDFUT_ENTRY_DELTA = 0x87554
# Плантер из прошлых gdb-прогонов: 0x7fffffff4a90 / 0x7fffffff4af0 (окно стабильное).
PLANTER_PROBE = 0x7FFFFFFF4A90


def log(msg):
    with open(LOG, "a") as f:
        f.write(msg + "\n")
    print("[ph] " + msg, flush=True)


def rv(expr):
    return int(gdb.parse_and_eval(expr)) & 0xFFFFFFFFFFFFFFFF


class LibLoadBP(gdb.Breakpoint):
    """Ловим момент загрузки libCoreADI (первый solib event), ставим WP на плантер."""
    def __init__(self):
        super().__init__("vdfut768ig", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True
        self.first = True

    def stop(self):
        if STATE["base"] is None:
            STATE["base"] = rv("$rip") - VDFUT_ENTRY_DELTA
            log(f"libCoreADI base={STATE['base']:#x}")
        # На ПЕРВОМ вызове vdfut (init): найти плантер-адрес через скан [rbp-0x30]
        # соседних фреймов НЕЛЬЗЯ (init ≠ transform frame). Вместо этого:
        # прочитать регистры и поискать плантер в известном окне.
        if self.first:
            self.first = False
            self.delete()
            # Смотрим на адрес из прошлых прогонов (gdb ASLR-off => детерминирован).
            # Проверяем: жива ли страница?
            try:
                b = rv(f"*(unsigned char*)({PLANTER_PROBE:#x})")
                log(f"planter probe {PLANTER_PROBE:#x} readable, byte={b:#x}")
            except Exception:
                log(f"planter probe {PLANTER_PROBE:#x} NOT readable at init entry")
                return False
            # Ставим WP на 8 байт в начале плантера
            PlanterWP(PLANTER_PROBE)
            # И второй WP на середину (окно fam2/fam3)
            PlanterWP(PLANTER_PROBE + 0x2000)
            log(f"WP armed: {PLANTER_PROBE:#x} (+0x2000)")
        return False


class PlanterWP(gdb.Breakpoint):
    def __init__(self, addr):
        super().__init__(f"*(unsigned long long*){addr:#x}", gdb.BP_WATCHPOINT, gdb.WP_WRITE, internal=False)
        self.addr = addr
        self.silent = True

    def stop(self):
        if STATE["done"]:
            return False
        STATE["n"] += 1
        rip = rv("$rip") - (STATE["base"] or 0)
        val = rv(f"*(unsigned long long*){self.addr:#x}")
        # Полный стек писателя
        try:
            frames = gdb.execute("bt 12", to_string=True)
            bt_lines = [l.strip()[:110] for l in frames.splitlines()[:12]]
        except Exception:
            bt_lines = []
        with open("/opt/data/adi-re/planter_writers.txt", "a") as f:
            f.write(f"hit{STATE['n']} addr={self.addr:#x} rip=+{rip:#x} val={val:#018x}\n")
            for l in bt_lines:
                f.write(f"  BT {l}\n")
            f.write(f"  RAX={rv('$rax'):#x} RBX={rv('$rbx') & 0xFFFFFFFF:#x} RCX={rv('$rcx'):#x} RDX={rv('$rdx'):#x}\n")
            f.write(f"  RSI={rv('$rsi'):#x} RDI={rv('$rdi'):#x} R8={rv('$r8'):#x} R9={rv('$r9'):#x}\n")
            f.write(f"  RBP={rv('$rbp'):#x} RSP={rv('$rsp'):#x}\n\n")
        if STATE["n"] <= 6:
            log(f"WP#{STATE['n']}: rip=+{rip:#x}")
        if STATE["n"] >= 200:
            STATE["done"] = True
            log(f"limit reached ({STATE['n']})")
        return False


class TransformBP(gdb.Breakpoint):
    """transform-вход: забрать точный плантер-адрес и включить запись слов."""
    def __init__(self):
        super().__init__("vdfut768ig", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        if rv("$rdi") == 0x716BD86C and not STATE["done"]:
            rbp = rv("$rbp")
            p = rv(f"*(unsigned long long*)({rbp - 0x30:#x})")
            STATE["planter_addr"] = p
            log(f"TRANSFORM: planter at {p:#x} (probe was {PLANTER_PROBE:#x}, delta={p - PLANTER_PROBE:+#x})")
            STATE["done"] = True
            return False
        return False


gdb.execute("set confirm off")
gdb.execute("set pagination off")
gdb.execute("set breakpoint pending on")
open(LOG, "w").close()
open("/opt/data/adi-re/planter_writers.txt", "w").close()
log("armed: planter hunt")
LibLoadBP()
TransformBP()