import gdb
LOG = "/opt/data/adi-re/kdf_target.log"
def log(m):
    with open(LOG, "a") as f: f.write(m + "\n")
    print("[kt] " + m, flush=True)
def rv(e):
    return int(gdb.parse_and_eval(e)) & 0xFFFFFFFFFFFFFFFF

BASE = 0x7ffff7582000
gdb.execute("set confirm off")
gdb.execute("set pagination off")

# Этап 1: BP на call-сайте 0xdd826
class CallSiteBP(gdb.Breakpoint):
    def __init__(self):
        super().__init__(f"*{BASE + 0xDD826:#x}", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True
        self.done = False
    def stop(self):
        if self.done:
            return False
        self.done = True
        rbp = rv("$rbp")
        target = rv(f"*(unsigned long*)({rbp - 0x168:#x})")
        rva = target - BASE
        log(f"CALL SITE 0xdd826 reached:")
        log(f"  rbp = {rbp:#x}")
        log(f"  target_fn = {target:#x}")
        log(f"  target_rva = {rva:#x}")
        # Символ?
        try:
            sym = gdb.execute(f"info symbol {target:#x}", to_string=True).strip()
            log(f"  symbol: {sym}")
        except Exception as e:
            log(f"  symbol lookup err: {e}")
        # Регистры аргументов
        rdi = rv("$rdi")
        unmasked = (rdi ^ 0x45e5a56a) & 0xFFFFFFFF
        log(f"  rdi = {rdi:#x} (unmasked ^0x45e5a56a = {unmasked:#x})")
        log(f"  rsi = {rv('$rsi'):#x}")
        log(f"  rdx = {rv('$rdx'):#x}")
        log(f"  rcx = {rv('$rcx'):#x}")
        log(f"  r8  = {rv('$r8'):#x}")
        log(f"  r9  = {rv('$r9'):#x}")
        log(f"  rax_before = {rv('$rax'):#x}")
        # Слот [rbp-0xa0]
        a0 = rv(f"*(unsigned long*)({rbp - 0xa0:#x})")
        log(f"  [rbp-0xa0] = {a0:#x}")
        log(f"  [rbp-0x3f8] before = {rv(f'*(unsigned long*)({rbp - 0x3f8:#x})'):#x}")
        # Слот [rbp-0x168]
        log(f"  [rbp-0x168] = {target:#x}")
        # Активируем BP на точке возврата
        RetBP()
        self.delete()
        return False

class RetBP(gdb.Breakpoint):
    def __init__(self):
        super().__init__(f"*{BASE + 0xDD83B:#x}", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True
        self.done = False
    def stop(self):
        if self.done:
            return False
        self.done = True
        rax = rv("$rax")
        rbp = rv("$rbp")
        log(f"RETURN SITE 0xdd83b reached:")
        log(f"  rax (buffer ptr) = {rax:#x}")
        # Дамп 256 байт
        try:
            inf = gdb.selected_inferior()
            buf = bytes(inf.read_memory(rax, 256))
            with open("/opt/data/il/raw_source_fam1.bin", "wb") as f:
                f.write(buf)
            uniq = len(set(buf))
            log(f"  dumped 256B -> /opt/data/il/raw_source_fam1.bin")
            log(f"  uniqueness: {uniq}/256")
            log(f"  first 64: {buf[:64].hex()}")
            if uniq == 256:
                log(f"  *** IT IS A FULL PERMUTATION! ***")
            else:
                log(f"  not yet a permutation ({uniq}/256) — transforms later")
        except Exception as e:
            log(f"  dump err: {e}")
        # Слот [rbp-0xa0]
        a0 = rv(f"*(unsigned long*)({rbp - 0xa0:#x})")
        log(f"  [rbp-0xa0] = {a0:#x}")
        # Слот [rbp-0x3f8]
        f8 = rv(f"*(unsigned long*)({rbp - 0x3f8:#x})")
        log(f"  [rbp-0x3f8] after = {f8:#x}")
        self.delete()
        return True  # ОСТАНОВ для анализа

CallSiteBP()
log("armed")
