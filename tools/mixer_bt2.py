import gdb
LOG = "/opt/data/adi-re/mixer_bt2.log"
def log(m):
    with open(LOG, "a") as f: f.write(m + "\n")
    print("[m2] " + m, flush=True)
def rv(e):
    return int(gdb.parse_and_eval(e)) & 0xFFFFFFFFFFFFFFFF
STATE = {"base": None, "first": True, "done": False}

READS = {0xE6B9D: 0xE6B54, 0xE6BE2: 0xE6BAB, 0xE6C47: 0xE6BF7, 0xE6CA0: 0xE6C76,
         0xE6D06: 0xE6CDE, 0xE6D3E: 0xE6D16, 0xE6D8B: 0xE6D53, 0xE6DC1: 0xE6DAA,
         0xE6E28: 0xE6E01, 0xE6E5F: 0xE6E38, 0xE6EAA: 0xE6E74, 0xE6EE4: 0xE6ECD,
         0xE6F42: 0xE6F20, 0xE6F73: 0xE6F4E, 0xE6FC4: 0xE6F91, 0xE7023: 0xE7004}

class VdfutBP(gdb.Breakpoint):
    def __init__(self):
        super().__init__("vdfut768ig", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True
    def stop(self):
        if STATE["base"] is None:
            STATE["base"] = rv("$rip") - 0x87554
        if rv("$rdi") != 0x716BD86C or STATE["done"]:
            return False
        log(f"transform; base={STATE['base']:#x}")
        for store, read in READS.items():
            SelBP(store, read)
        return False

class SelBP(gdb.Breakpoint):
    def __init__(self, store_rva, read_rva):
        super().__init__(f"*{STATE['base'] + read_rva:#x}", gdb.BP_BREAKPOINT, internal=False)
        self.store_rva = store_rva
        self.silent = True
    def stop(self):
        if STATE["done"]:
            return False
        if STATE["first"]:
            STATE["first"] = False
            rbp = rv("$rbp")
            planter = rv(f"*(unsigned long long*)({rbp - 0x30:#x})")
            log(f"FIRST MIXER HIT: rbp={rbp:#x}, [rbp-0x30]={planter:#x}")
            log(f"  rip={rv('$rip'):#x}")
            # Полный стектрейс
            try:
                frames = gdb.execute("bt 20", to_string=True)
                for l in frames.splitlines()[:20]:
                    log(f"  BT {l.strip()[:120]}")
            except Exception as e:
                log(f"  bt err: {e}")
            # Ключевые регистры
            for reg in ['rsp', 'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi']:
                try: log(f"  {reg}={rv('$'+reg):#x}")
                except: pass
            # Дамп первых 16 байт fam1
            try:
                inf = gdb.selected_inferior()
                w = bytes(inf.read_memory(planter + 0xD60, 16))
                log(f"  fam1[0:16]: {w.hex()}")
            except: log(f"  fam1 read err")
            # Дамп плантера
            try:
                inf = gdb.selected_inferior()
                with open("/opt/data/adi-re/mixer_bt_planter.bin", "wb") as f:
                    f.write(bytes(inf.read_memory(planter, 0x2700)))
                log(f"  planter dumped ({planter:#x})")
            except Exception as e:
                log(f"  dump err: {e}")
            # Достаточно — останавливаемся
            STATE["done"] = True
            gdb.execute("delete")
            return True  # ОСТАНОВИТЬ для анализа
        return False

gdb.execute("set confirm off")
gdb.execute("set pagination off")
gdb.execute("set breakpoint pending on")
open(LOG, "w").close()
log("armed")
VdfutBP()
