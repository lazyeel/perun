# gdb-python v18: СИНХРОННЫЙ ПРОГОН — слова узла + итоговый депо + писатели 0xA0/0xB0/0xBD.
# BP на 0xfbf2d (слова W1..W7, включая [rbp-0xc0]=W7 пролога);
# WriterBP: дамп итогового депо (0x100) + live_prov_out уже сохранит adi_native;
# WP-карусель (по одному): хиты на окна [0xA0..0xA8), [0xB0..0xB8), [0xBD..0xC0).
import gdb

LOG = "/opt/data/adi-re/pair30.log"
STATE = {"base": None, "n": 0, "writer_seen": False, "depot": None,
         "wp_phase": None, "wp_n": 0}
VDFUT_ENTRY_DELTA = 0x87554
NODE_WORD_PT = 0xFBF2D
WRITER_STORE = 0xDC716
BAKED_DEPOT = 0x7FFFF7817E40  # в gdb-прогонах стабилен; перевзвод по rdi
CUR = {"wp": None}


def log(msg):
    with open(LOG, "a") as f:
        f.write(msg + "\n")
    print("[p30] " + msg, flush=True)


def rv(expr):
    return int(gdb.parse_and_eval(expr)) & 0xFFFFFFFFFFFFFFFF


def dump(addr, size, path):
    inf = gdb.selected_inferior()
    with open(path, "wb") as f:
        f.write(bytes(inf.read_memory(addr, size)))


def swap_wp(new_wp):
    if CUR["wp"] is not None:
        try:
            CUR["wp"].delete()
        except Exception:
            pass
    CUR["wp"] = new_wp


class VdfutBP(gdb.Breakpoint):
    def __init__(self):
        super().__init__("vdfut768ig", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        if STATE["base"] is None:
            STATE["base"] = rv("$rip") - VDFUT_ENTRY_DELTA
        if rv("$rdi") != 0x716BD86C:
            return False
        log(f"transform; base={STATE['base']:#x}")
        WordBP()
        WriterBP()
        return False


class WordBP(gdb.Breakpoint):
    """0xfbf2d: все семь слов (+W7=[rbp-0xc0] пролога)."""

    def __init__(self):
        super().__init__(f"*{STATE['base'] + NODE_WORD_PT:#x}", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        STATE["n"] += 1
        rbp = rv("$rbp")
        w = {
            "rcx_b8": rv(f"*(unsigned long long*)({rbp - 0xb8:#x})") & 0xFFFFFFFF,
            "r14": rv("$r14") & 0xFFFFFFFF,
            "r9_40": rv(f"*(unsigned long long*)({rbp - 0x40:#x})") & 0xFFFFFFFF,
            "r8": rv("$r8") & 0xFFFFFFFF,
            "rbx_68": rv(f"*(unsigned long long*)({rbp - 0x68:#x})") & 0xFFFFFFFF,
            "r13": rv("$r13") & 0xFFFFFFFF,
            "r_c0": rv(f"*(unsigned long long*)({rbp - 0xc0:#x})") & 0xFFFFFFFF,
            "buf368": rv(f"*(unsigned long long*)({rbp - 0x368:#x})"),
        }
        with open("/opt/data/adi-re/pair_words.txt", "a") as f:
            f.write(f"{STATE['n']} " + " ".join(f"{k}={v:#x}" for k, v in w.items()) + "\n")
        if STATE["n"] == 1:
            log(f"words: W1={w['rcx_b8']:#x} W2={w['r14']:#x} W3={w['r9_40']:#x} "
                f"W4={w['r8']:#x} W5={w['rbx_68']:#x} W6={w['r13']:#x} W7={w['r_c0']:#x} "
                f"buf={w['buf368']:#x}")
            try:
                depot = rv("$rcx")  # на 0xfbf2d rcx = буфер! проверим по rdi-логике ниже
                # депо надёжнее взять из m1-хвостов — но для WP возьмём BAKED (стабилен в gdb)
                STATE["depot"] = BAKED_DEPOT
                log(f"depot (baked): {BAKED_DEPOT:#x}")
            except Exception as e:
                log(f"depot err: {e}")
            # WP-карусель: сначала окно 0xA0
            STATE["wp_phase"] = "A0"
            swap_wp(WinWP(BAKED_DEPOT + 0xA0))
            log("WP armed: depot+0xA0")
        if STATE["n"] >= 4:
            self.delete()
        return False


class WinWP(gdb.Breakpoint):
    """8-байтное окно: лог всех писателей с rip+значением."""

    def __init__(self, addr):
        super().__init__(f"*(unsigned long long*){addr:#x}", gdb.BP_WATCHPOINT, gdb.WP_WRITE, internal=False)
        self.addr = addr
        self.silent = True

    def stop(self):
        rip = rv("$rip") - STATE["base"]
        val = rv(f"*(unsigned long long*){self.addr:#x}")
        STATE["wp_n"] += 1
        off = self.addr - STATE["depot"] if STATE["depot"] else 0
        with open("/opt/data/adi-re/pair_wp_tape.txt", "a") as f:
            f.write(f"{STATE['wp_n']} phase={STATE['wp_phase']} off=+{off:#x} rip=+{rip:#x} "
                    f"val={val:#018x} rcx={rv('$rcx') & 0xFFFFFFFF:#x} rax={rv('$rax') & 0xFF:02x} "
                    f"r13={rv('$r13') & 0xFFFFFFFF:#x} r14={rv('$r14') & 0xFFFFFFFF:#x} "
                    f"r8={rv('$r8') & 0xFFFFFFFF:#x}\n")
        if STATE["wp_n"] <= 2:
            log(f"WP[{STATE['wp_phase']}] #{STATE['wp_n']}: rip=+{rip:#x}")
        # ротация фаз: 12 хитов -> следующее окно
        if STATE["wp_n"] >= 12:
            STATE["wp_n"] = 0
            nxt = {"A0": "B0", "B0": "BD"}.get(STATE["wp_phase"])
            if nxt:
                STATE["wp_phase"] = nxt
                swap_wp(WinWP(STATE["depot"] + (0xB0 if nxt == "B0" else 0xBD)))
                log(f"WP rotate -> depot+{nxt}")
            else:
                swap_wp(None)
                log("WP done")
        return False


class WriterBP(gdb.Breakpoint):
    def __init__(self):
        super().__init__(f"*{STATE['base'] + WRITER_STORE:#x}", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        if not STATE["writer_seen"]:
            STATE["writer_seen"] = True
            B = rv("$r11")
            log(f"writer start: B={B:#x}")
            try:
                dump(B, 0x100, "/opt/data/adi-re/pair_depot_final.bin")
                log("depot_final dumped (pair_depot_final.bin)")
                # и сам депо (r14-таблица)
                dump(STATE["depot"], 0x100, "/opt/data/adi-re/pair_depot.bin")
                log("depot dumped (pair_depot.bin)")
            except Exception as e:
                log(f"dump err: {e}")
            # маркер пары: слова + депо ОДНОЙ сессии
            with open("/opt/data/adi-re/pair_marker.txt", "w") as f:
                f.write("READY\n")
            log("PAIR READY (words + depot same session)")
        return False


gdb.execute("set confirm off")
gdb.execute("set pagination off")
gdb.execute("set breakpoint pending on")
open(LOG, "w").close()
open("/opt/data/adi-re/pair_words.txt", "w").close()
open("/opt/data/adi-re/pair_wp_tape.txt", "w").close()
log("armed: pair30")
VdfutBP()