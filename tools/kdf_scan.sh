#!/bin/bash
# Single-step KDF scan: от BP после пролога (base+0x87565) шагаем и опрашиваем [rbp-0x38].
# Каждый шаг: если слот изменился → ЛОВУШКА. Также опрашиваем плантер-регион.
# Медленно, но ни один CFF-маршрут не уйдёт.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# libs живут в adi-android (аргумент $2), не здесь
STAGE="${STAGE:-/opt/data/adi-mnt/stage}"
elf="${1:-$HERE/adi_native}"
LIBS="${2:-$HERE/libs}"
shift 2>/dev/null || true

export CA_BUNDLE="${CA_BUNDLE:-$HERE/apple_chain.pem}"
export ANDROID_ROOT=/system ANDROID_DATA="$STAGE" TMPDIR="$STAGE" \
       ANDROID_ASSETS_ROOT=/system/app EXTERNAL_STORAGE="$STAGE" \
       ADI_RESOLVE="${ADI_RESOLVE:-gsa.apple.com:443:17.179.252.2,buy.itunes.apple.com:443:17.8.136.39}"

if [ ! -e /tmp/pa.so ]; then
  ln -sf "$STAGE/bin/linker64" /tmp/pa.so
fi

# НЕ ИСПОЛЬЗУЕМ gdb — пишем маленький gdb-скрипт только для BP+dump
cat > /tmp/kdf_scan.py <<'PYEOF'
import gdb

LOG = "/opt/data/adi-re/scan_kdf.log"
STATE = {"base": None, "steps": 0, "slot_prev": None, "found": False, "planter": None}
VDFUT_DELTA = 0x87554
POST_PROLOGUE = 0x87565
TRANSFORM_OP = 0x716BD86C

def log(m):
    with open(LOG, "a") as f: f.write(m + "\n")
    print("[scan] " + m, flush=True)

def rv(e):
    return int(gdb.parse_and_eval(e)) & 0xFFFFFFFFFFFFFFFF

class EntryBP(gdb.Breakpoint):
    def __init__(self):
        super().__init__("vdfut768ig", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True
    def stop(self):
        if STATE["base"] is None:
            STATE["base"] = rv("$rip") - VDFUT_DELTA
        if rv("$rdi") != TRANSFORM_OP or STATE["found"]:
            return False
        STATE["found"] = True
        rbp = rv("$rbp")
        slot = rbp - 0x38
        STATE["slot_prev"] = rv(f"*(unsigned long long*)({slot:#x})")
        log(f"transform rbp={rbp:#x} slot={slot:#x} prev={STATE['slot_prev']:#x}")
        # Вставляем single-step цикл ВНУТРИ stop()
        # Пошагово опрашиваем слот каждые 50 шагов (быстрее, чем каждый шаг)
        for i in range(50000):
            # stepi — один шаг
            try:
                gdb.execute("stepi", to_string=True)
            except Exception:
                break
            STATE["steps"] += 1
            if STATE["steps"] % 50 == 0:
                try:
                    cur = rv(f"*(unsigned long long*)({slot:#x})")
                    if cur != STATE["slot_prev"]:
                        log(f"SLOT CHANGED at step {STATE['steps']}: {STATE['slot_prev']:#x} -> {cur:#x}")
                        log(f"  rip={rv('$rip') - STATE['base']:#x}")
                        STATE["planter"] = cur
                        # Дамп первых 256 байт по новому адресу
                        try:
                            inf = gdb.selected_inferior()
                            pre = bytes(inf.read_memory(cur, 256))
                            log(f"  planter first 256: {pre[:32].hex()}")
                        except:
                            pass
                        # Больше не шагаем
                        break
                except Exception:
                    break
            # Останов на первом микшере (плантер заполнен)
            if STATE["steps"] > 20000:
                rip = rv("$rip") - STATE["base"]
                if 0xE6B00 <= rip <= 0xE6C00:
                    log(f"reached mixer at step {STATE['steps']}, rip=+{rip:#x}")
                    break
        log(f"scan done: {STATE['steps']} steps, planter={STATE.get('planter')}")
        return False

gdb.execute("set confirm off")
gdb.execute("set pagination off")
gdb.execute("set breakpoint pending on")
open(LOG, "w").close()
log("armed: single-step KDF scan")
EntryBP()
PYEOF

sudo -n unshare -m --propagation private /bin/sh -c '
  set -u
  mkdir -p /system /vendor
  mount --bind "$1" /system || exit 90
  mount --bind "$1" /vendor || exit 91
  [ -e /dev/__properties__ ] || : > /dev/__properties__
  shift
  cd "$1" || exit 92
  shift
  exec "$@"
' _ "$STAGE" "$STAGE" /usr/bin/gdb -q --batch \
    -ex "source /tmp/kdf_scan.py" \
    -ex run \
    --args "$elf" "${LIBS:-$HERE/libs}"
rc=$?
sudo -n rm -rf /system /vendor 2>/dev/null
exit $rc