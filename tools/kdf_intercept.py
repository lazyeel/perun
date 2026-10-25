# gdb-python v27: ПЕРЕХВАТ KDF ЧЕРЕЗ ТОЧКУ ГЕНЕЗИСА 0x80016.
# Двухступенчатая ловушка: BP на 0x80016 (плантер-база вычислена!) → WP на живой адрес.
import gdb

LOG = "/opt/data/adi-re/kdf_intercept.log"
STATE = {"base": None, "wp_hits": 0, "done": False}
VDFUT_ENTRY_DELTA = 0x87554
TRANSFORM_OPCODE = 0x716BD86C
GENESIS_RVA = 0x80016


def log(msg):
    with open(LOG, "a") as f:
        f.write(msg + "\n")
    print("[ki] " + msg, flush=True)


def rv(expr):
    return int(gdb.parse_and_eval(expr)) & 0xFFFFFFFFFFFFFFFF


class TransformBP(gdb.Breakpoint):
    def __init__(self):
        super().__init__("vdfut768ig", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        if STATE["base"] is None:
            STATE["base"] = rv("$rip") - VDFUT_ENTRY_DELTA
        if rv("$rdi") != TRANSFORM_OPCODE or STATE["done"]:
            return False
        log(f"transform; base={STATE['base']:#x}; arming genesis BP at +{GENESIS_RVA:#x}")
        GenesisBP()
        return False


class GenesisBP(gdb.Breakpoint):
    """Точка 0x80016: плантер-база ТОЛЬКО ЧТО вычислена в rax."""
    def __init__(self):
        super().__init__(f"*{STATE['base'] + GENESIS_RVA:#x}", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        if STATE["done"]:
            return False
        r15 = rv("$r15")
        r13 = rv("$r13")
        planter = (r15 + (r13 & 0xFFFFFFFFFFFFFFFF) * 4) & 0xFFFFFFFFFFFFFFFF
        rax = rv("$rax")
        log(f"GENESIS HIT: r15={r15:#x} r13={r13:#x} → planter_base={planter:#x} (rax={rax:#x})")
        # Проверка: это стек?
        if not (0x7f0000000000 <= planter < 0x800000000000):
            log(f"WARNING: плантер НЕ на стеке! ({planter:#x})")
        # Прочитать первые байты ДО заполнения
        try:
            pre = rv(f"*(unsigned long long*)({planter:#x})")
            log(f"planter BEFORE fill: {pre:#018x}")
        except Exception:
            log("planter not readable yet")

        # Взводим HW-WP на первое S-box окно (+0xD60) и fam4 (+0x1390)
        KdfWP(planter + 0xD60, "fam1")
        KdfWP(planter + 0x1390, "fam4")
        log(f"WP armed: {planter + 0xD60:#x} (fam1), {planter + 0x1390:#x} (fam4)")
        self.delete()
        return False


class KdfWP(gdb.Breakpoint):
    """Каждый хит = одна запись в S-box окно."""
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
        val = rv(f"*(unsigned int*){self.addr:#x}")

        with open("/opt/data/adi-re/kdf_tape.txt", "a") as f:
            f.write(f"{STATE['wp_hits']} {self.name} rip={rip:#x} val={val:#010x} "
                    f"rax={rv('$rax'):#x} rbx={rv('$rbx'):#x} rcx={rv('$rcx'):#x} rdx={rv('$rdx'):#x} "
                    f"rsi={rv('$rsi'):#x} rdi={rv('$rdi'):#x} r8={rv('$r8'):#x} r9={rv('$r9'):#x} "
                    f"r10={rv('$r10'):#x} r11={rv('$r11'):#x} r12={rv('$r12'):#x} r13={rv('$r13'):#x} "
                    f"r14={rv('$r14'):#x} r15={rv('$r15'):#x} rbp={rv('$rbp'):#x}\n")

        if STATE["wp_hits"] <= 3:
            log(f"KDF-WP #{STATE['wp_hits']} {self.name}: rip={rip:#x} val={val:#010x}")
            # BT на первых хитах
            try:
                frames = gdb.execute("bt 10", to_string=True)
                for l in frames.splitlines()[:10]:
                    log(f"  BT {l.strip()[:110]}")
            except Exception:
                pass

        # Останов после 300 хитов (не замедлять прогон до смерти)
        if STATE["wp_hits"] >= 300:
            STATE["done"] = True
            log(f"KDF tape complete ({STATE['wp_hits']} hits)")
            # Дамп плантера
            try:
                inf = gdb.selected_inferior()
                pb = rv("$r15 + $r13*4")
                with open("/opt/data/adi-re/kdf_planter_live.bin", "wb") as f:
                    f.write(bytes(inf.read_memory(pb, 0x2700)))
                log(f"planter live dumped from {pb:#x}")
            except Exception as e:
                log(f"dump err: {e}")
        return False


gdb.execute("set confirm off")
gdb.execute("set pagination off")
gdb.execute("set breakpoint pending on")
open(LOG, "w").close()
open("/opt/data/adi-re/kdf_tape.txt", "w").close()
log("armed: KDF intercept (genesis 0x80016)")
TransformBP()