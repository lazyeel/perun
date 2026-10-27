import gdb
LOG = "/opt/data/adi-re/online_kdf.log"
def log(m):
    with open(LOG, "a") as f: f.write(m + "\n")
    print("[ok] " + m, flush=True)
def rv(e):
    return int(gdb.parse_and_eval(e)) & 0xFFFFFFFFFFFFFFFF

# Пролог: 6 stepi (5 push + sub rsp)
for pi in range(6):
    gdb.execute("stepi", to_string=True)

rbp = rv("$rbp")
rsp = rv("$rsp")
fam1 = rsp + 0xD90
init = rv(f"*(unsigned int*)({fam1:#x})")
log(f"POST-PROLOGUE: rbp={rbp:#x} rsp={rsp:#x} fam1={fam1:#x} init={init:#x}")

for i in range(200000):
    try:
        gdb.execute("stepi", to_string=True)
    except Exception:
        break
    try:
        cur = rv(f"*(unsigned int*)({fam1:#x})")
        if cur != init:
            rip = rv("$rip")
            base = 0x7ffff7582000
            rva = rip - base
            log(f"KDF FIRST WRITE at step {i}: fam1 {init:#x} -> {cur:#x}")
            log(f"  rip = {rip:#x} rva = {rva:#x}")
            for reg in ['rax','rbx','rcx','rdx','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15','rsp','rbp']:
                try: log(f"  {reg} = {rv('$'+reg):#x}")
                except: pass
            # 30 инструкций вокруг
            try:
                dis = gdb.execute(f"x/30i {rip - 40:#x}", to_string=True)
                for l in dis.splitlines()[:30]:
                    log(f"  DIS {l.strip()[:120]}")
            except: pass

            # Логируем КАЖДУЮ запись в fam1 (первые 200)
            prev = cur
            for j in range(i+1, min(i+500, 200000)):
                try:
                    gdb.execute("stepi", to_string=True)
                except: break
                try:
                    cur2 = rv(f"*(unsigned int*)({fam1:#x})")
                    if cur2 != prev:
                        log(f"  step +{j-i}: fam1 -> {cur2:#010x}, rip rva={rv('$rip') - base:#x}")
                        prev = cur2
                except: pass

            # Финальный дамп плантера
            try:
                inf = gdb.selected_inferior()
                planter = rsp + 0x30
                with open("/opt/data/adi-re/online_planter_kdf.bin", "wb") as f:
                    f.write(bytes(inf.read_memory(planter, 0x2700)))
                log(f"planter dumped from rsp+0x30 = {planter:#x}")
                # Проверка перестановок
                for wname, woff in [("fam1",0xD60),("fam2",0x1A00),("fam3",0x2460),("fam4",0x1390)]:
                    w = bytes(inf.read_memory(planter + woff, 256))
                    uniq = len(set(w))
                    log(f"  {wname}: {uniq}/256 unique, first 32: {w[:32].hex()}")
            except Exception as e:
                log(f"dump err: {e}")
            break
    except Exception:
        pass
else:
    log(f"no fill in 200000 steps; fam1 = {rv(f'*(unsigned int*)({fam1:#x})'):#x}")

log("done")
