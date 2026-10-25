# gdb-python v25: ДИНАМИЧЕСКАЯ ОХОТА НА ПЛАНТЕР-ГЕНЕЗИС.
# Инициализационный опкод — Configuration (0xb0eda7af). Плантер пишется в init.
# Стратегия: НЕ хардкодить адрес — на КАЖДОМ init-вызове сканировать кадр
# на [rbp-0x30]-слот (гость мапит слоты последовательно), и после последнего
# init-вызова (перед transform) дампить то, что нашлось. ПЛЮС: hardware WP
# на плантер-адрес, найденный живьём при transform, ловит любые ПОЗДНИЕ записи.
import gdb

LOG = "/opt/data/adi-re/genesis_hunt.log"
STATE = {"base": None, "n": 0, "init_n": 0, "transform_seen": False,
         "planter_addr": None, "done": False}
VDFUT_ENTRY_DELTA = 0x87554
INIT_OPCODE = 0xB0EDA7AF
TRANSFORM_OPCODE = 0x716BD86C


def log(msg):
    with open(LOG, "a") as f:
        f.write(msg + "\n")
    print("[gh] " + msg, flush=True)


def rv(expr):
    return int(gdb.parse_and_eval(expr)) & 0xFFFFFFFFFFFFFFFF


class VdfutAllBP(gdb.Breakpoint):
    """Все vdfut-вызовы: логируем опкод + сканируем кадр на плантер-слот."""
    def __init__(self):
        super().__init__("vdfut768ig", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        if STATE["done"]:
            return False
        if STATE["base"] is None:
            STATE["base"] = rv("$rip") - VDFUT_ENTRY_DELTA
        STATE["n"] += 1
        rdi = rv("$rdi") & 0xFFFFFFFF
        rbp = rv("$rbp")

        if rdi == TRANSFORM_OPCODE:
            STATE["transform_seen"] = True
            # Плантер-адрес из transform-кадра
            p = rv(f"*(unsigned long long*)({rbp - 0x30:#x})")
            STATE["planter_addr"] = p
            log(f"TRANSFORM #{STATE['n']}: planter at {p:#x}")

            # Сравнить: что было в этом адресе ДО (мы не успели поймать init)
            # Но: дампим плантер сейчас — это ЭТАЛОН
            try:
                inf = gdb.selected_inferior()
                with open("/opt/data/adi-re/genesis_planter_transform.bin", "wb") as f:
                    f.write(bytes(inf.read_memory(p, 0x2700)))
                log(f"planter dumped at transform: {p:#x} (0x2700)")
            except Exception as e:
                log(f"planter dump err: {e}")

            # Инициализация уже прошла; смотрим: есть ли ещё записи
            # (transform сам пишет в плантер? — проверить WP)
            if STATE["planter_addr"]:
                GenesisWP(STATE["planter_addr"] + 0xD60)
                log(f"WP armed on planter+0xD60 = {STATE['planter_addr'] + 0xD60:#x}")

            STATE["done"] = True
            self.delete()
            return False

        # init-вызовы (не transform): логируем опкод и кадр
        STATE["init_n"] += 1
        log(f"call #{STATE['n']}: rdi={rdi:#x} rbp={rbp:#x}")

        # Сканируем кадр на слоты, похожие на плантер-указатели
        # (0x2700-буфер живёт на стеке или в куче; ищем указатели с допустимым размером)
        try:
            for off in range(-0x400, 0x100, 8):
                try:
                    v = rv(f"*(unsigned long long*)({rbp + off:#x})")
                    if 0x7f0000000000 < v < 0x800000000000:
                        # Прочитаем байт по этому адресу — жива ли страница
                        b = rv(f"*(unsigned char*)({v:#x})")
                        # Если это плантер — запишем
                        if off == -0x30:
                            log(f"  [rbp{off:+d}] = {v:#x} (byte={b:#x}) <<< плантер-слот")
                        elif STATE["init_n"] <= 3:
                            pass  # не спамим
                except Exception:
                    pass
        except Exception:
            pass

        # На init-выходе: дампить память вокруг rbp-0x30 (если читается)
        if off == -0x30 and not STATE["planter_addr"]:
            try:
                v = rv(f"*(unsigned long long*)({rbp - 0x30:#x})")
                if 0x7f0000000000 < v < 0x800000000000:
                    STATE["planter_addr"] = v
                    log(f"  init кадр: плантер-адрес = {v:#x}")
            except Exception:
                pass

        return False


class GenesisWP(gdb.Breakpoint):
    """WP на плантер+0xD60 после transform — ловит поздние записи (если есть)."""
    def __init__(self, addr):
        super().__init__(f"*(unsigned long long*){addr:#x}", gdb.BP_WATCHPOINT, gdb.WP_WRITE, internal=False)
        self.addr = addr
        self.silent = True
        self.hits = 0

    def stop(self):
        rip = rv("$rip") - (STATE["base"] or 0)
        val = rv(f"*(unsigned long long*){self.addr:#x}")
        self.hits += 1
        log(f"WP(planter+0xD60) #{self.hits}: rip=+{rip:#x} val={val:#018x}")
        try:
            frames = gdb.execute("bt 10", to_string=True)
            for l in frames.splitlines()[:10]:
                log(f"  BT {l.strip()[:110]}")
        except Exception:
            pass
        return False


gdb.execute("set confirm off")
gdb.execute("set pagination off")
gdb.execute("set breakpoint pending on")
open(LOG, "w").close()
log("armed: genesis hunt (dynamic planter discovery)")
VdfutAllBP()