import gdb
LOG = "/opt/data/adi-re/kdf3.log"
def log(m):
    with open(LOG, "a") as f: f.write(m + "\n")
    print("[k3] " + m, flush=True)
def rv(e):
    return int(gdb.parse_and_eval(e)) & 0xFFFFFFFFFFFFFFFF

BASE = 0x7ffff7582000
gdb.execute("set confirm off")
gdb.execute("set pagination off")

class PostMallocBP(gdb.Breakpoint):
    def __init__(self):
        super().__init__(f"*{BASE + 0xDD83B:#x}", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True
        self.done = False
    def stop(self):
        if self.done: return False
        self.done = True
        rax = rv("$rax")
        log(f"POST-MALLOC 0xdd83b: rax = {rax:#x}")
        # Дамп 200 байт свежего буфера
        try:
            inf = gdb.selected_inferior()
            buf = bytes(inf.read_memory(rax, 200))
            log(f"fresh buffer 200B: first 32: {buf[:32].hex()}")
            log(f"fresh buffer: last 32: {buf[-32:].hex()}")
            uniq = len(set(buf))
            zeros = buf.count(0)
            log(f"uniqueness: {uniq}/200, zeros: {zeros}/200")
            with open("/opt/data/il/fresh_malloc_buf.bin", "wb") as f:
                f.write(buf)
        except Exception as e:
            log(f"dump err: {e}")
        # Аппаратный watchpoint на первый байт
        try:
            gdb.execute(f"watch *(unsigned char*)({rax:#x})")
            log(f"HW watchpoint armed on {rax:#x} byte0")
        except Exception as e:
            log(f"watchpoint err: {e}")
        self.delete()
        return False

class WPHandler(gdb.Breakpoint):
    pass

# После watchpoint срабатывания — gdb остановится сам (watchpoint = останов)
# Дальше: логируем rip/регистры/bt в batch-команде

PostMallocBP()
log("armed")
