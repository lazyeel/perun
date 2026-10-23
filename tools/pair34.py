# gdb-python v23: ЕДИНЫЙ финальный прогон одной сессии: гигант-хиты (al-лента для mixer_byte)
# + плантер-хиты (селекторы + кормушки каскадов) + WP-слова дайджеста + плантер-дамп + срез депо.
import gdb

LOG = "/opt/data/adi-re/pair34.log"
STATE = {"base": None, "z": 0, "s": 0, "writer": False, "zdone": False, "sdone": False}
VDFUT_ENTRY_DELTA = 0x87554
BAKED_DEPOT = 0x7FFFF7817E40
ZONE_READS = {0xE6B9D: 0xE6B86, 0xE6BE2: 0xE6BD2, 0xE6C47: 0xE6C1F, 0xE6CA0: 0xE6C76,
              0xE6D06: 0xE6CF5, 0xE6D3E: 0xE6D2D, 0xE6D8B: 0xE6D71, 0xE6DC1: 0xE6DB3,
              0xE6E28: 0xE6E14, 0xE6E5F: 0xE6E4B, 0xE6EAA: 0xE6E90, 0xE6EE4: 0xE6EC8,
              0xE6F42: 0xE6F31, 0xE6F73: 0xE6F6C, 0xE6FC4: 0xE6FC2, 0xE7023: 0xE7000}
PLANter_READS = {0xE6B9D: 0xE6B54, 0xE6BE2: 0xE6BAB, 0xE6C47: 0xE6BF7, 0xE6CA0: 0xE6C76,
                 0xE6D06: 0xE6CDE, 0xE6D3E: 0xE6D16, 0xE6D8B: 0xE6D53, 0xE6DC1: 0xE6DAA,
                 0xE6E28: 0xE6E01, 0xE6E5F: 0xE6E38, 0xE6EAA: 0xE6E74, 0xE6EE4: 0xE6ECD,
                 0xE6F42: 0xE6F20, 0xE6F73: 0xE6F4E, 0xE6FC4: 0xE6F84, 0xE7023: 0xE7004}
WRITER_STORE = 0xDC716
WINDOWS = [("A0", 0xA0), ("A8", 0xA8), ("B0", 0xB0)]


def log(msg):
    with open(LOG, "a") as f:
        f.write(msg + "\n")
    print("[p34] " + msg, flush=True)


def rv(expr):
    return int(gdb.parse_and_eval(expr)) & 0xFFFFFFFFFFFFFFFF


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
        for store, read in ZONE_READS.items():
            ZoneBP(store, read)
        for store, read in PLANter_READS.items():
            SelBP(store, read)
        for name, off in WINDOWS:
            WinWP(name, BAKED_DEPOT + off)
        WriterBP()
        return False


class ZoneBP(gdb.Breakpoint):
    def __init__(self, store_rva, read_rva):
        super().__init__(f"*{STATE['base'] + read_rva:#x}", gdb.BP_BREAKPOINT, internal=False)
        self.store_rva = store_rva
        self.silent = True

    def stop(self):
        if STATE["zdone"]:
            return False
        STATE["z"] += 1
        with open("/opt/data/adi-re/zone26_tape.txt", "a") as f:
            f.write(f"{STATE['z']} store={self.store_rva:#x} read={rv('$rip') - STATE['base']:#x} "
                    f"al={rv('$rax') & 0xFF:02x} cl={rv('$rcx') & 0xFF:02x} dl={rv('$rdx') & 0xFF:02x} "
                    f"rdi={rv('$rdi'):#x} r10={rv('$r10'):#x} r15={rv('$r15'):#x} "
                    f"r8={rv('$r8'):#x} r14={rv('$r14'):#x} rax={rv('$rax'):#x} rdx={rv('$rdx'):#x} "
                    f"rcx={rv('$rcx'):#x} rbx={rv('$rbx') & 0xFFFFFFFF:#x}\n")
        if STATE["z"] >= 400:
            STATE["zdone"] = True
        return False


class SelBP(gdb.Breakpoint):
    def __init__(self, store_rva, read_rva):
        super().__init__(f"*{STATE['base'] + read_rva:#x}", gdb.BP_BREAKPOINT, internal=False)
        self.store_rva = store_rva
        self.silent = True

    def stop(self):
        if STATE["sdone"]:
            return False
        STATE["s"] += 1
        rbp = rv("$rbp")
        if STATE["s"] == 1:
            try:
                inf = gdb.selected_inferior()
                p = rv("*(unsigned long long*)($rbp - 0x30)")
                with open("/opt/data/adi-re/planter34.bin", "wb") as f:
                    f.write(bytes(inf.read_memory(p, 0x2500)))
                log(f"planter dumped: {p:#x}")
            except Exception as e:
                log(f"planter dump err: {e}")
        with open("/opt/data/adi-re/sel34_tape.txt", "a") as f:
            f.write(f"{STATE['s']} store={self.store_rva:#x} read={rv('$rip') - STATE['base']:#x} "
                    f"sel={rv('$rax') & 0xFF:02x} rax={rv('$rax'):#x} "
                    f"rbx={rv('$rbx') & 0xFFFFFFFF:#x} rcx={rv('$rcx'):#x} "
                    f"esi={rv('$rsi') & 0xFFFFFFFF:#x} edx={rv('$rdx') & 0xFFFFFFFF:#x} "
                    f"r9d={rv('$r9') & 0xFFFFFFFF:#x} r10d={rv('$r10') & 0xFFFFFFFF:#x} "
                    f"r12d={rv('$r12') & 0xFFFFFFFF:#x} r13d={rv('$r13') & 0xFFFFFFFF:#x} "
                    f"r15d={rv('$r15') & 0xFFFFFFFF:#x} r8d={rv('$r8') & 0xFFFFFFFF:#x} "
                    f"eax={rv('$rax') & 0xFFFFFFFF:#x} "
                    f"f8={rv(f'*(unsigned int*)({rbp - 0xf8:#x})'):#x} "
                    f"f78={rv(f'*(unsigned int*)({rbp - 0x78:#x})'):#x} "
                    f"f148={rv(f'*(unsigned int*)({rbp - 0x148:#x})'):#x}\n")
        if STATE["s"] >= 400:
            STATE["sdone"] = True
        return False


class WinWP(gdb.Breakpoint):
    def __init__(self, name, addr):
        super().__init__(f"*(unsigned long long*){addr:#x}", gdb.BP_WATCHPOINT, gdb.WP_WRITE, internal=False)
        self.name = name
        self.addr = addr
        self.n = 0
        self.silent = True

    def stop(self):
        if STATE["writer"]:
            return False
        rip = rv("$rip") - STATE["base"]
        val = rv(f"*(unsigned long long*){self.addr:#x}")
        self.n += 1
        rbp = rv("$rbp")
        with open("/opt/data/adi-re/pair_wp_words.txt", "a") as f:
            f.write(f"hit{self.n} window={self.name} rip=+{rip:#x} val={val:#018x} "
                    f"W1={rv(f'*(unsigned long long*)({rbp - 0xb8:#x})') & 0xFFFFFFFF:#x} "
                    f"W2={rv('$r14') & 0xFFFFFFFF:#x} "
                    f"W3={rv(f'*(unsigned long long*)({rbp - 0x40:#x})') & 0xFFFFFFFF:#x} "
                    f"W4={rv('$r8') & 0xFFFFFFFF:#x} "
                    f"W5={rv(f'*(unsigned long long*)({rbp - 0x68:#x})') & 0xFFFFFFFF:#x} "
                    f"W6={rv('$r13') & 0xFFFFFFFF:#x} "
                    f"W7={rv(f'*(unsigned long long*)({rbp - 0xc0:#x})') & 0xFFFFFFFF:#x} "
                    f"W8={rv('$rdx') & 0xFFFFFFFF:#x}\n")
        return False


class WriterBP(gdb.Breakpoint):
    def __init__(self):
        super().__init__(f"*{STATE['base'] + WRITER_STORE:#x}", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        if STATE["writer"]:
            return False
        STATE["writer"] = True
        try:
            inf = gdb.selected_inferior()
            with open("/opt/data/adi-re/pair_depot.bin", "wb") as f:
                f.write(bytes(inf.read_memory(BAKED_DEPOT, 0x100)))
            log("writer: depot slice dumped")
        except Exception as e:
            log(f"dump err: {e}")
        log("PAIR READY (giant + planter + words + depot + cpim, one session)")
        return False


gdb.execute("set confirm off")
gdb.execute("set pagination off")
gdb.execute("set breakpoint pending on")
open(LOG, "w").close()
open("/opt/data/adi-re/zone26_tape.txt", "w").close()
open("/opt/data/adi-re/sel34_tape.txt", "w").close()
open("/opt/data/adi-re/pair_wp_words.txt", "w").close()
log("armed: pair34")
VdfutBP()