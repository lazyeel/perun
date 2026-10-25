# gdb-python v28: ДВУХСТУПЕНЧАТАЯ ЛОВУШКА НА СЛОТ [rbp-0x38].
# Этап А: BP ПОСЛЕ пролога (base+0x87565) → читаем живой rbp transform-кадра → WP на слот.
# Этап Б: слот-WP срабатывает → удаляем → читаем плантер-базу → WP на S-box окно → KDF.
import gdb

LOG = "/opt/data/adi-re/slot_trap.log"
STATE = {"base": None, "stage": 0, "kdf_hits": 0, "done": False}
VDFUT_ENTRY_DELTA = 0x87554
POST_PROLOGUE_RVA = 0x87565  # сразу после sub rsp,0x44a8
TRANSFORM_OPCODE = 0x716BD86C


def log(msg):
    with open(LOG, "a") as f:
        f.write(msg + "\n")
    print("[st] " + msg, flush=True)


def rv(expr):
    return int(gdb.parse_and_eval(expr)) & 0xFFFFFFFFFFFFFFFF


class TransformEntryBP(gdb.Breakpoint):
    def __init__(self):
        super().__init__("vdfut768ig", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        if STATE["base"] is None:
            STATE["base"] = rv("$rip") - VDFUT_ENTRY_DELTA
        if rv("$rdi") != TRANSFORM_OPCODE or STATE["stage"] > 0:
            return False
        STATE["stage"] = 1
        # BP ПОСЛЕ пролога — rbp уже принадлежит transform-кадру
        PostPrologueBP()
        log(f"transform entry; arming post-prologue BP at +{POST_PROLOGUE_RVA:#x}")
        return False


class PostPrologueBP(gdb.Breakpoint):
    """rbp = transform frame. Ставим WP на сам слот [rbp-0x38]."""
    def __init__(self):
        super().__init__(f"*{STATE['base'] + POST_PROLOGUE_RVA:#x}", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        rbp = rv("$rbp")
        slot = rbp - 0x38
        log(f"POST-PROLOGUE: rbp={rbp:#x}, slot [rbp-0x38]={slot:#x}")
        # Читаем текущее значение слота (мусор до записи)
        try:
            cur = rv(f"*(unsigned long long*)({slot:#x})")
            log(f"  slot current: {cur:#x}")
        except Exception:
            log("  slot not readable")
        # ЭТАП А: WP на слот
        SlotWP(slot)
        log(f"  SLOT-WP armed on {slot:#x}")
        self.delete()
        return False


class SlotWP(gdb.Breakpoint):
    """ЭТАП Б: слот [rbp-0x38] записан → читаем плантер-базу → WP на S-box."""
    def __init__(self, slot_addr):
        super().__init__(f"*(unsigned long long*){slot_addr:#x}", gdb.BP_WATCHPOINT, gdb.WP_WRITE, internal=False)
        self.slot_addr = slot_addr
        self.silent = True

    def stop(self):
        if STATE["stage"] != 1:
            return False
        STATE["stage"] = 2
        # НЕМЕДЛЕННО удаляем слот-WP (освободить DR-регистр)
        self.delete()
        # Читаем записанную плантер-базу
        planter = rv(f"*(unsigned long long*)({self.slot_addr:#x})")
        log(f"SLOT HIT: planter_base = {planter:#x}")
        # Проверка на стек
        if not (0x7f0000000000 <= planter < 0x800000000000):
            log(f"WARNING: не стек ({planter:#x})")
        # Дамп буфера ДО заполнения
        try:
            pre = rv(f"*(unsigned long long*)({planter:#x})")
            log(f"  planter pre-fill: {pre:#018x}")
        except Exception:
            log("  planter not readable (normal — buffer may not be zero yet)")

        # ЭТАП Б-2: WP на первое S-box окно
        SBoxWP(planter + 0xD60, "fam1")
        log(f"  SBOX-WP armed on {planter + 0xD60:#x} (fam1)")
        return False


class SBoxWP(gdb.Breakpoint):
    """Каждый хит = одна запись в S-box окно → KDF-лента."""
    def __init__(self, addr, name):
        super().__init__(f"*(unsigned int*){addr:#x}", gdb.BP_WATCHPOINT, gdb.WP_WRITE, internal=False)
        self.addr = addr
        self.name = name
        self.silent = True

    def stop(self):
        if STATE["done"]:
            return False
        STATE["kdf_hits"] += 1
        rip = rv("$rip") - (STATE["base"] or 0)
        val = rv(f"*(unsigned int*){self.addr:#x}")

        with open("/opt/data/adi-re/kdf_cycle_tape.txt", "a") as f:
            f.write(f"{STATE['kdf_hits']} {self.name} rip=+{rip:#x} val={val:#010x} "
                    f"rax={rv('$rax'):#x} rbx={rv('$rbx'):#x} rcx={rv('$rcx'):#x} rdx={rv('$rdx'):#x} "
                    f"rsi={rv('$rsi'):#x} rdi={rv('$rdi'):#x} r8={rv('$r8'):#x} r9={rv('$r9'):#x} "
                    f"r10={rv('$r10'):#x} r11={rv('$r11'):#x} r12={rv('$r12'):#x} r13={rv('$r13'):#x} "
                    f"r14={rv('$r14'):#x} r15={rv('$r15'):#x} rbp={rv('$rbp'):#x}\n")

        if STATE["kdf_hits"] <= 5:
            log(f"KDF #{STATE['kdf_hits']}: rip=+{rip:#x} val={val:#010x}")
            try:
                frames = gdb.execute("bt 8", to_string=True)
                for l in frames.splitlines()[:8]:
                    log(f"  BT {l.strip()[:110]}")
            except Exception:
                pass

        if STATE["kdf_hits"] >= 256:
            STATE["done"] = True
            log(f"KDF COMPLETE ({STATE['kdf_hits']} writes)")
            # Дамп финального плантера
            try:
                inf = gdb.selected_inferior()
                pb = rv("$r15") + (rv("$r13") & 0xFFFFFFFFFFFFFFFF) * 4
                if not (0x7f0000000000 <= pb < 0x800000000000):
                    pb = self.addr - 0xD60  # fallback
                with open("/opt/data/adi-re/kdf_planter_final.bin", "wb") as f:
                    f.write(bytes(inf.read_memory(pb, 0x2700)))
                log(f"planter final dumped from {pb:#x}")
            except Exception as e:
                log(f"dump err: {e}")
        return False


gdb.execute("set confirm off")
gdb.execute("set pagination off")
gdb.execute("set breakpoint pending on")
open(LOG, "w").close()
open("/opt/data/adi-re/kdf_cycle_tape.txt", "w").close()
log("armed: two-stage slot trap")
TransformEntryBP()