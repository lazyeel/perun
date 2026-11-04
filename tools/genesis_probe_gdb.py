# gdb-python: ПРОБА ГЕНЕЗИСА ПЛАНТЕРА — живой пиннинг входов генератора.
#
# Вопрос: чем питается генератор семи окон (0xE2441..0xE26AA)? Указатели
# [rbp-0xc0/-0xa0/-0x88/-0xe0/-0x180] и состояние [rbp-0x38]/[rbp-0x40] —
# это SPIM, идентичность или производные страницы?
#
# Доктрина трассера (v30): никаких software-watchpoints, никаких
# gdb.post_event/continue. Прямые RVA-брейки, stop() возвращает False,
# лог append-файлом. Дампы — только при ПЕРВОМ хите писателя.
import gdb

LOG = "/opt/data/adi-re/genesis_probe.log"
STATE = {"armed": False, "first": False}
VDFUT_DELTA = 0x87550  # RVA символа vdfut768ig в libCoreADI.so

# (RVA, имя, регистр-индекса, регистр-значения) — из дисассемблирования
# кластера 0xE2441..0xE26AE и транспорта 0xFB05B/0xFB075.
WRITERS = [
    (0xE2441, "fam1_+0xd60", "rax", "r10"),
    (0xE24C9, "fifth_+0x1f30", "r15", "rcx"),
    (0xE2508, "fam2_+0x1a00", "rcx", "r14"),
    (0xE25A4, "w_+0xc50", "r15", "rcx"),
    (0xE25C2, "fam3_+0x2460", "rax", "r8"),
    (0xE2626, "w_+0x1280", "r15", "rax"),
    (0xE26AA, "fam4_+0x1390", "rax", "r13"),
    (0xFB05B, "transport_a", "rax", "rdx"),
    (0xFB075, "transport_b", "rax", "rdx"),
]


def log(msg):
    with open(LOG, "a") as f:
        f.write(msg + "\n")


def ru(expr):
    return int(gdb.parse_and_eval(expr)) & 0xFFFFFFFFFFFFFFFF


class WriterBP(gdb.Breakpoint):
    def __init__(self, addr, name, ireg, vreg):
        super().__init__("*%#x" % addr, gdb.BP_BREAKPOINT, internal=False)
        self.silent = True
        self.name = name
        self.ireg = ireg
        self.vreg = vreg

    def stop(self):
        try:
            STATE["total_hits"] = STATE.get("total_hits", 0) + 1
            idx = ru("$" + self.ireg) & 0xFF
            val = ru("$" + self.vreg) & 0xFF
            ctr = ru("*(unsigned long long*)($rbp-0xd8)")
            s38 = ru("*(unsigned int*)($rbp-0x38)")
            s40 = ru("*(unsigned long long*)($rbp-0x40)")
            log("hit %-14s idx=%#04x val=%#04x ctr=%d s38=%#010x s40=%#010x"
                % (self.name, idx, val, ctr, s38, s40))
            if not STATE["first"]:
                STATE["first"] = True
                dump_first_hit()
            # 257-й хит fam1 = старт блока №2 — дампим кадр в этот момент
            if self.name.startswith("fam1"):
                STATE["fam1n"] = STATE.get("fam1n", 0) + 1
                if STATE["fam1n"] == 257:
                    try:
                        rbp = ru("$rbp")
                        gdb.execute("dump binary memory /opt/data/adi-re/gp_frame_block2.bin %#x %#x"
                                    % (rbp - 0x600, rbp + 0x10))
                        log("BLOCK2 frame dumped rbp=%#x s38=%#x"
                            % (rbp, ru("*(unsigned long long*)($rbp-0x38)")))
                    except Exception as e:  # noqa: BLE001
                        log("block2 frame ERR %s" % e)
        except Exception as e:  # noqa: BLE001 — gdb-исключения не должны ронять прогон
            log("ERR %s: %s" % (self.name, e))
        return False


def dump_first_hit():
    log("=== FIRST WRITER HIT: slot dump ===")
    try:
        log("bt:\n" + gdb.execute("bt 8", to_string=True))
    except Exception as e:  # noqa: BLE001
        log("bt failed: %s" % e)
    slots = [
        ("-0x30", "anchor_planter_base"),
        ("-0x38", "state_38"),
        ("-0x40", "state_40"),
        ("-0xc0", "ptr_c0"),
        ("-0xa0", "ptr_a0"),
        ("-0x88", "ptr_88"),
        ("-0xe0", "ptr_e0"),
        ("-0x180", "ptr_180"),
        ("-0xd8", "counter_d8"),
        ("-0xb0", "state_b0"),
        ("-0x1a8", "state_1a8"),
    ]
    for off, name in slots:
        try:
            v = ru("*(unsigned long long*)($rbp%s)" % off)
            log("slot %s (%s) = %#x" % (name, off, v))
            # цели указателей — дампим по 0x200 байт (SPIM-подобные буферы)
            if off in ("-0xc0", "-0xa0", "-0x88", "-0xe0", "-0x180") and 0x10000 < v < 0x800000000000:
                out = "/opt/data/adi-re/gp_%s.bin" % name
                gdb.execute("dump binary memory %s %#x %#x" % (out, v, v + 0x200))
                log("dumped %s -> %s" % (name, out))
        except Exception as e:  # noqa: BLE001
            log("slot %s ERR %s" % (name, e))
    # сам плантер ДО заливки окон (первый же хит — до записи)
    try:
        base = ru("*(unsigned long long*)($rbp-0x30)")
        gdb.execute("dump binary memory /opt/data/adi-re/gp_planter_pre.bin %#x %#x"
                    % (base, base + 0x2700))
        log("planter base=%#x pre-state dumped" % base)
    except Exception as e:  # noqa: BLE001
        log("planter dump ERR %s" % e)
    # ВЕСЬ кадр — все слоты состояния разом (не угадывать слоты)
    try:
        gdb.execute("dump binary memory /opt/data/adi-re/gp_frame_first.bin %#x %#x"
                    % (ru("$rbp") - 0x600, ru("$rbp") + 0x10))
        log("frame window rbp-0x600..rbp+0x10 dumped")
    except Exception as e:  # noqa: BLE001
        log("frame dump ERR %s" % e)


class PostBP(gdb.Breakpoint):
    """Первый giant-read окна (+0xD60 @ 0xE6B54): филл уже завершён."""

    def __init__(self, addr):
        super().__init__("*%#x" % addr, gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        n = STATE.get("postn", 0) + 1
        STATE["postn"] = n
        if n > 8:
            return False
        try:
            rbp = ru("$rbp")
            base = ru("*(unsigned long long*)($rbp-0x30)")
            log("GIANT#%d: rbp=%#x anchor=%#x" % (n, rbp, base))
            gdb.execute("dump binary memory /opt/data/adi-re/gp_giant_%d.bin %#x %#x"
                        % (n, base, base + 0x2700))
        except Exception as e:  # noqa: BLE001
            log("giant dump ERR %s" % e)
        return False


# Четыре fam1-цикла чтения: какой из них (и после какого блока) питает
# микшеры тела A. Дамп объекта при первом входе в каждый цикл.
READERS = [
    (0xE6B54, "read_loop1"),
    (0xE6CE2, "read_loop2"),
    (0xE6E05, "read_loop3"),
    (0xE6F25, "read_loop4"),
]


class ReadBP(gdb.Breakpoint):
    def __init__(self, addr, name):
        super().__init__("*%#x" % addr, gdb.BP_BREAKPOINT, internal=False)
        self.silent = True
        self.rname = name

    def stop(self):
        if STATE.get("rd_" + self.rname):
            return False
        STATE["rd_" + self.rname] = True
        try:
            rbp = ru("$rbp")
            base = ru("*(unsigned long long*)($rbp-0x30)")
            hits_so_far = STATE.get("total_hits", 0)
            log("READLOOP %s at hits=%d rbp=%#x base=%#x" % (self.rname, hits_so_far, rbp, base))
            gdb.execute("dump binary memory /opt/data/adi-re/gp_read_%s.bin %#x %#x"
                        % (self.rname, base, base + 0x2700))
        except Exception as e:  # noqa: BLE001
            log("readloop ERR %s" % e)
        return False


class Block2EndBP(gdb.Breakpoint):
    """512-й хит fam4 = конец блока №2: финальное состояние объекта."""

    def __init__(self, addr):
        super().__init__("*%#x" % addr, gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        STATE["fam4n"] = STATE.get("fam4n", 0) + 1
        if STATE["fam4n"] != 512:
            return False
        try:
            rbp = ru("$rbp")
            base = ru("*(unsigned long long*)($rbp-0x30)")
            log("BLOCK2END rbp=%#x base=%#x" % (rbp, base))
            gdb.execute("dump binary memory /opt/data/adi-re/gp_planter_b2end.bin %#x %#x"
                        % (base, base + 0x2700))
        except Exception as e:  # noqa: BLE001
            log("b2end ERR %s" % e)
        return False


class MixerBP(gdb.Breakpoint):
    """Стор тела A / фидов (0xE6B9D): позиция микшеров в потоке."""

    def __init__(self, addr):
        super().__init__("*%#x" % addr, gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        n = STATE.get("mixn", 0) + 1
        STATE["mixn"] = n
        if n <= 3 or n == 160 or n == 161:
            log("MIXER#%d at hits=%d rbp=%#x" % (n, STATE.get("total_hits", 0), ru("$rbp")))
            if n == 1:
                try:
                    rbp = ru("$rbp")
                    base = ru("*(unsigned long long*)($rbp-0x30)")
                    gdb.execute("dump binary memory /opt/data/adi-re/gp_planter_atmixer1.bin %#x %#x"
                                % (base, base + 0x2700))
                    gdb.execute("dump binary memory /opt/data/adi-re/gp_frame_atmixer1.bin %#x %#x"
                                % (rbp - 0x600, rbp + 0x10))
                    log("mixer1 dumps done base=%#x" % base)
                except Exception as e:  # noqa: BLE001
                    log("mixer1 dump ERR %s" % e)
        return False


class SelHeadBP(gdb.Breakpoint):
    """Первое чтение кластера e37xx (окна +0xc50/+0x1280/+0x1f30)."""

    def __init__(self, addr):
        super().__init__("*%#x" % addr, gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        if STATE.get("selhead"):
            return False
        STATE["selhead"] = True
        log("SELCLUSTER at hits=%d rbp=%#x" % (STATE.get("total_hits", 0), ru("$rbp")))
        try:
            rbp = ru("$rbp")
            base = ru("*(unsigned long long*)($rbp-0x30)")
            gdb.execute("dump binary memory /opt/data/adi-re/gp_planter_atsel.bin %#x %#x"
                        % (base, base + 0x2700))
        except Exception as e:  # noqa: BLE001
            log("sel dump ERR %s" % e)
        return False


class ArmBP(gdb.Breakpoint):
    """Однократное взведение писателей при первом входе vdfut768ig."""

    def __init__(self):
        super().__init__("vdfut768ig", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        if STATE["armed"]:
            return False
        STATE["armed"] = True
        entry = ru("$pc")
        # entry может быть внутри функции; RVA символа берём из info
        sym = int(gdb.parse_and_eval("(unsigned long long)&vdfut768ig")) & 0xFFFFFFFFFFFFFFFF
        base = sym - VDFUT_DELTA
        log("armed: vdfut768ig=%#x base=%#x" % (sym, base))
        for rva, name, ireg, vreg in WRITERS:
            WriterBP(base + rva, name, ireg, vreg)
        for rva, rname in READERS:
            ReadBP(base + rva, rname)
        Block2EndBP(base + 0xE26AA)
        PostBP(base + 0xE6B54)  # legacy giant-read (дублирует read_loop1)
        MixerBP(base + 0xE6B9D)  # стор тела A / фидов
        SelHeadBP(base + 0xE37D9)  # кластер чтения +0xc50/+0x1280/+0x1f30
        return False


gdb.execute("set pagination off")
gdb.execute("set confirm off")
gdb.execute("set breakpoint pending on")

# gdb 16.3 (Debian) выбрасывает LD_LIBRARY_PATH из собственного окружения
# ещё на старте — inferior без него падает с "CANNOT LINK EXECUTABLE".
# Ставим весь env inferiorу явно; пути выводим из argv (--args).
import os as _os

_raw = gdb.parameter("args")
_args = (_raw.string if hasattr(_raw, "string") else str(_raw)).split()
# args может прийти и с именем программы, и без — фиксируем по adi_native
if _args and _args[0].endswith("adi_native"):
    _prog, _rest = _os.path.abspath(_args[0]), _args[1:]
else:
    _prog, _rest = _os.path.join(_os.getcwd(), "adi_native"), _args
_root = _os.path.dirname(_prog)
_libs = _os.path.abspath(_rest[0]) if _rest else _root + "/libs"
_sysroot = _root + "/sysroot"
_env = {
    "LD_LIBRARY_PATH": _libs + ":" + _sysroot + "/lib64",
    "ANDROID_ROOT": "/system",
    "ANDROID_DATA": "/data",
    "ANDROID_RUNTIME_ROOT": "/apex/com.android.runtime",
    "CA_BUNDLE": _root + "/apple_chain.pem",
    "ADI_RESOLVE": "gsa.apple.com:443:17.179.252.2",
}
open(LOG, "w").write("genesis probe start\n")
for _k, _v in _env.items():
    gdb.execute("set environment %s=%s" % (_k, _v))
log("env set: %s" % _env)

ArmBP()