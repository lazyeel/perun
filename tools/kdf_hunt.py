# gdb-python v26: ЗАХВАТ KDF-ГЕНЕРАТОРА ПЛАНТЕРА СО СТАРТА ПРОЦЕССА.
# Плантер = BSS-глобаль adi_native+0x62f0 (детерминирован в gdb: 0x5555555562f0).
# WP на первое S-box окно (+0xD60) взводится ДО вызова 1.
import gdb

LOG = "/opt/data/adi-re/kdf_hunt.log"
STATE = {"base": None, "n": 0, "wp_hits": 0, "done": False}
VDFUT_ENTRY_DELTA = 0x87554
PLANTER = 0x5555555562F0  # adi_native+0x62f0 (BSS)
INIT_OPCODE = 0xB0EDA7AF
TRANSFORM_OPCODE = 0x716BD86C


def log(msg):
    with open(LOG, "a") as f:
        f.write(msg + "\n")
    print("[kdf] " + msg, flush=True)


def rv(expr):
    return int(gdb.parse_and_eval(expr)) & 0xFFFFFFFFFFFFFFFF


class StartBP(gdb.Breakpoint):
    """Первая остановка после загрузки: взводим WP на плантер ДО любого кода."""
    def __init__(self):
        super().__init__("*0x555555558560", gdb.BP_BREAKPOINT, internal=False)  # main
        self.silent = True

    def stop(self):
        log("main reached; arming WP on planter+0xD60 BEFORE any init call")
        # Дамп плантера ДО init (BSS = нули?)
        try:
            b = rv(f"*(unsigned long long*)({PLANTER + 0xD60:#x})")
            log(f"planter+0xD60 BEFORE init: {b:#018x}")
        except Exception as e:
            log(f"read err: {e}")

        # WP на 4 байта в начале fam1-окна
        PlanterWP(PLANTER + 0xD60, "fam1")
        # WP на fam4-окно (наиболее интересное — S-box с xor-хвостом)
        PlanterWP(PLANTER + 0x1390, "fam4")

        self.delete()
        return False


class PlanterWP(gdb.Breakpoint):
    """HW-WP на S-box окно: каждый хит = запись в плантер."""
    def __init__(self, addr, name):
        super().__init__(f"*(unsigned int*){addr:#x}", gdb.BP_WATCHPOINT, gdb.WP_WRITE, internal=False)
        self.addr = addr
        self.name = name
        self.silent = True

    def stop(self):
        if STATE["done"]:
            return False
        STATE["wp_hits"] += 1
        rip = rv("$rip")
        # базу вычислим по libCoreADI (не всегда известна в init)
        val = rv(f"*(unsigned int*){self.addr:#x}")

        # Полный стек + регистры
        try:
            frames = gdb.execute("bt 15", to_string=True)
            bt = [l.strip()[:120] for l in frames.splitlines()[:15]]
        except Exception:
            bt = []

        with open("/opt/data/adi-re/kdf_writers.txt", "a") as f:
            f.write(f"hit{STATE['wp_hits']} {self.name} @{self.addr:#x} rip={rip:#x} val={val:#010x}\n")
            for l in bt:
                f.write(f"  BT {l}\n")
            f.write(f"  RAX={rv('$rax'):#x} RBX={rv('$rbx'):#x} RCX={rv('$rc'):#x} RDX={rv('$rdx'):#x}\n")
            f.write(f"  RSI={rv('$rsi'):#x} RDI={rv('$rdi'):#x} R8={rv('$r8'):#x} R9={rv('$r9'):#x}\n")
            f.write(f"  R10={rv('$r10'):#x} R11={rv('$r11'):#x} R12={rv('$r12'):#x} R13={rv('$r13'):#x}\n")
            f.write(f"  R14={rv('$r14'):#x} R15={rv('$r15'):#x} RBP={rv('$rbp'):#x}\n\n")

        if STATE["wp_hits"] <= 5:
            log(f"WP {self.name} #{STATE['wp_hits']}: rip={rip:#x} val={val:#010x}")
        if STATE["wp_hits"] >= 500:
            STATE["done"] = True
            log(f"WP limit ({STATE['wp_hits']})")
        return False


class VdfutBP(gdb.Breakpoint):
    """Логируем вызовы для контекста."""
    def __init__(self):
        super().__init__("vdfut768ig", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        if STATE["done"]:
            return False
        STATE["n"] += 1
        rdi = rv("$rdi") & 0xFFFFFFFF
        log(f"vdfut #{STATE['n']}: opcode={rdi:#x} wp_hits={STATE['wp_hits']}")
        if rdi == TRANSFORM_OPCODE:
            # Плантер уже заполнен; снимаем WP
            STATE["done"] = True
            log(f"TRANSFORM reached; wp_hits={STATE['wp_hits']}")
            # Дамп плантера
            try:
                inf = gdb.selected_inferior()
                with open("/opt/data/adi-re/kdf_planter_final.bin", "wb") as f:
                    f.write(bytes(inf.read_memory(PLANTER, 0x2700)))
                log(f"planter final dumped ({PLANTER:#x}, 0x2700)")
            except Exception as e:
                log(f"dump err: {e}")
            self.delete()
        return False


gdb.execute("set confirm off")
gdb.execute("set pagination off")
gdb.execute("set breakpoint pending on")
open(LOG, "w").close()
open("/opt/data/adi-re/kdf_writers.txt", "w").close()
log(f"armed: KDF hunt (WP on {PLANTER:#x}+0xD60 and +0x1390 from main)")
StartBP()
VdfutBP()