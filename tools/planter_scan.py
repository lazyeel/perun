import gdb
LOG = "/opt/data/adi-re/scan.log"
def log(m):
    with open(LOG, "a") as f: f.write(m + "\n")
    print("[ps] " + m, flush=True)
def rv(e):
    return int(gdb.parse_and_eval(e)) & 0xFFFFFFFFFFFFFFFF

rbp = rv("$rbp")
rsp = rv("$rsp")
log(f"FIRST MIXER: rbp={rbp:#x} rsp={rsp:#x}")

inf = gdb.selected_inferior()

# Сигнатура: 4 окна по 256 байт, каждое = перестановка (256 уникальных)
OFFSETS = [0xD60, 0x1A00, 0x2460, 0x1390]

def check_planter(base):
    try:
        for off in OFFSETS:
            data = bytes(inf.read_memory(base + off, 256))
            if len(set(data)) != 256:
                return False
        return True
    except Exception:
        return False

# Скан 1: /proc maps — все rw-p страницы
pid = inf.pid
found = []
try:
    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            if "rw-p" not in line:
                continue
            parts = line.split()
            addrs = parts[0].split("-")
            lo = int(addrs[0], 16)
            hi = int(addrs[1], 16)
            sz = hi - lo
            # Пропускаем слишком большие регионы (> 16MB)
            if sz > 0x1000000:
                continue
            name = parts[-1] if len(parts) > 5 else "?"
            # Сканируем с шагом 1 байт по всем rw-страницам
            # (база может быть НЕ выровнена)
            try:
                data = bytes(inf.read_memory(lo, sz))
            except Exception:
                continue
            # Ищем базу: перебираем каждые 0x10 байт (быстрее чем 1)
            for b in range(0, sz - 0x2700, 0x10):
                base = lo + b
                ok = True
                for off in OFFSETS:
                    win = data[b + off : b + off + 256]
                    if len(set(win)) != 256:
                        ok = False
                        break
                if ok:
                    found.append((base, name))
                    log(f"PLANTER FOUND: {base:#x} ({name})")
                    for off, wname in [(0xD60,"fam1"),(0x1A00,"fam2"),(0x2460,"fam3"),(0x1390,"fam4")]:
                        w = data[b+off:b+off+32]
                        log(f"  {wname}[0:32]: {w.hex()}")
            if len(found) >= 3:
                break
except Exception as e:
    log(f"maps scan err: {e}")

# Скан 2: если не найдено — перебираем ВСЕ rw-страницы с шагом 1
if not found:
    log("wide scan: step=1")
    try:
        with open(f"/proc/{pid}/maps") as f:
            for line in f:
                if "rw-p" not in line:
                    continue
                parts = line.split()
                addrs = parts[0].split("-")
                lo = int(addrs[0], 16)
                hi = int(addrs[1], 16)
                sz = hi - lo
                if sz > 0x2000000:
                    continue
                try:
                    data = bytes(inf.read_memory(lo, sz))
                except Exception:
                    continue
                for b in range(0, sz - 0x2700):
                    base = lo + b
                    ok = True
                    for off in OFFSETS:
                        win = data[b + off : b + off + 256]
                        if len(set(win)) != 256:
                            ok = False
                            break
                    if ok:
                        found.append((base, "?"))
                        log(f"PLANTER FOUND (wide): {base:#x}")
                        break
                if found:
                    break
    except Exception as e:
        log(f"wide scan err: {e}")

if found:
    planter_base = found[0][0]
    log(f"PLANTER BASE: {planter_base:#x}")

    # Pointer Hunt: ищем слот на стеке, содержащий planter_base
    log("POINTER HUNT: scanning stack...")
    stack_lo = rsp & ~0xFFF
    stack_hi = rbp + 0x200
    try:
        stack_data = bytes(inf.read_memory(stack_lo, stack_hi - stack_lo))
        for off in range(0, len(stack_data) - 8, 8):
            val = int.from_bytes(stack_data[off:off+8], 'little')
            if val == planter_base:
                addr = stack_lo + off
                log(f"  EXACT: [{addr:#x}] = {val:#x} (rbp{addr - rbp:+d})")
            # Маскированные варианты (старшие байты)
            elif (val & 0xFFFFFFFFFFFF) == (planter_base & 0xFFFFFFFFFFFF) and val != planter_base:
                addr = stack_lo + off
                log(f"  MASKED: [{addr:#x}] = {val:#x} (rbp{addr - rbp:+d})")
    except Exception as e:
        log(f"  stack scan err: {e}")

    # Дамп плантера
    try:
        with open("/opt/data/adi-re/planter_scan_result.bin", "wb") as f:
            f.write(bytes(inf.read_memory(planter_base, 0x2700)))
        log(f"planter dumped -> planter_scan_result.bin")
    except Exception as e:
        log(f"dump err: {e}")
else:
    log("NO PLANTER FOUND in rw-p regions")

log("done")
