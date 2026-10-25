# gdb-python v29: СЕМЬ СОФТВЕРНЫХ BP НА ПИСАТЕЛЕЙ [rbp-0x38].
# Обход gdb-бага: только software BP (никаких HW-WP!). Ловим ЛЮБОЙ CFF-маршрут.
import gdb

LOG = "/opt/data/adi-re/seven_bp.log"
STATE = {"base": None, "n": 0, "done": False}
VDFUT_ENTRY_DELTA = 0x87554
TRANSFORM_OPCODE = 0x716BD86C
# Все 7 писателей [rbp-0x38] из capstone-свипа
WRITERS = [0x80016, 0x80234, 0x812E9, 0x815C7, 0x81921, 0x82B6B, 0x82AB3]


def log(msg):
    with open(LOG, "a") as f:
        f.write(msg + "\n")
    print("[7bp] " + msg, flush=True)


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
        STATE["done"] = True
        log(f"transform; base={STATE['base']:#x}; rbp at entry={rv('$rbp'):#x}")
        # Читаем rbp ПОСЛЕ пролога — он уже = transform frame
        rbp = rv("$rbp")
        slot = rbp - 0x38
        cur = rv(f"*(unsigned long long*)({slot:#x})")
        log(f"  slot [rbp-0x38]={slot:#x}, current value: {cur:#x}")

        # Ставим 7 software BP (не hardware WP — gdb не упадёт)
        for rva in WRITERS:
            WriterBP(rva)
        log(f"  {len(WRITERS)} software BP armed: {[hex(r) for r in WRITERS]}")
        return False


class WriterBP(gdb.Breakpoint):
    """Software BP на писателя [rbp-0x38] — ЛЮБОЙ CFF-маршрут."""
    def __init__(self, rva):
        super().__init__(f"*{STATE['base'] + rva:#x}", gdb.BP_BREAKPOINT, internal=False)
        self.rva = rva
        self.silent = True

    def stop(self):
        STATE["n"] += 1
        rbp = rv("$rbp")
        slot_val = rv(f"*(unsigned long long*)({rbp - 0x38:#x})")
        rax = rv("$rax")
        # Проверяем: rax = плантер-база?
        is_stack = 0x7f0000000000 <= rax < 0x800000000000
        log(f"HIT #{STATE['n']} at +{self.rva:#x}: rax={rax:#x} slot=[rbp-0x38]={slot_val:#x} "
            f"{'STACK!' if is_stack else 'not stack'}")

        with open("/opt/data/adi-re/seven_bp_tape.txt", "a") as f:
            f.write(f"{STATE['n']} rva=+{self.rva:#x} rax={rax:#x} slot={slot_val:#x} "
                    f"rbp={rbp:#x} rip={rv('$rip') - STATE['base']:#x}\n")

        # Если это выглядит как плантер-база — дампим!
        if is_stack and STATE["n"] <= 7:
            try:
                inf = gdb.selected_inferior()
                with open(f"/opt/data/adi-re/seven_bp_planter_{STATE['n']}.bin", "wb") as f:
                    f.write(bytes(inf.read_memory(rax, 0x2700)))
                log(f"  planter dumped from rax={rax:#x} → seven_bp_planter_{STATE['n']}.bin")
            except Exception as e:
                log(f"  dump err: {e}")

        # Больше 20 хитов не нужно
        if STATE["n"] >= 20:
            log(f"done ({STATE['n']} hits)")
            gdb.execute("delete")
        return False


gdb.execute("set confirm off")
gdb.execute("set pagination off")
gdb.execute("set breakpoint pending on")
open(LOG, "w").close()
open("/opt/data/adi-re/seven_bp_tape.txt", "w").close()
log(f"armed: 7 software BP on [rbp-0x38] writers")
TransformBP()