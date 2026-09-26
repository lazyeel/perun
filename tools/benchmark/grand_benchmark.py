#!/usr/bin/env python3
"""Three-way benchmark: PERun vs the stock Unicorn sapsigner vs majd/ipatool.

Every measurement goes through `rsswait`, a C measuring parent built from
`rsswait.c` next to this file, because `fork()`+`exec()` makes a child inherit
the parent's high-water mark: a Python parent reports 5 752 KiB for
`/bin/true`. The C parent's own floor is 1 216 KiB and is reported with the
results. Build it with:

    cc -O2 -o tmp/rsswait tools/benchmark/rsswait.c

What each participant can actually do, and where that leaves the matrix:

  metric                perun    sapsigner    majd
  SAP session              y           y          -      (majd has no SAP)
  search / store lane      y           -          y      (needs an Apple ID)
  package replication      y           -          y      (part of download)
  cold asset fetch         y           y          -      (majd has no SAP assets)

A cell that a participant cannot do at all is reported as `n/a` with the
reason. It is not measured as zero and not quietly dropped: the point of the
table is where the work exists, and pretending the oracle does a store lane it
has no code for would be the whole benchmark being wrong.

Usage:
    python3 tools/benchmark/grand_benchmark.py --sap-runs 10
    python3 tools/benchmark/grand_benchmark.py --only sap --report tmp/bench/sap.json

The two comparison binaries are not vendored: build them into `tmp/` first
(`ORACLE` / `MAJD` below), or the affected rows report `n/a` with the reason.
"""

import argparse
import json
import os
import pathlib
import re
import shutil
import statistics
import subprocess
import sys
import time

REPO = pathlib.Path(__file__).resolve().parents[2]
TMP = REPO / "tmp"
RSSWAIT = TMP / "rsswait"
PERUN = REPO / "target" / "release" / "perun"
ORACLE = TMP / "sapsigner-2.1.1"
MAJD = TMP / "majd-v2.6.0"
BENCH = TMP / "bench"
# majd keeps its keyring in a file and asks for a passphrase on every run; the
# login driver provisions it, and the store lane is then fully headless.
MAJD_KEYCHAIN = os.environ.get("MAJD_KEYCHAIN", "bench-keyring-2026")

# The fetcher's cache is under XDG, not in the repo; the first run printed
# "[fetcher] assets cached at /opt/data/home/.cache/perun/sap", and measuring
# "cold" against a path that does not exist silently measures warm twice.
SAP_CACHE = pathlib.Path(os.environ.get("XDG_CACHE_HOME",
                                         "/opt/data/home/.cache")) / "perun" / "sap"

# Both signers must be given the same bytes, and perun's built-in payload is
# exactly this string, so neither side gets an input the other cannot produce.
PAYLOAD = b"perun native SAP smoke test"
# The oracle takes its FairPlay id from `net.Interfaces()[0].HardwareAddr`,
# which in a container is `lo` with an EMPTY address. Pinning perun to the
# matching all-zero MAC is the closest match that does not patch the oracle.
MACHINE_MAC = "00:00:00:00:00:00"


MEASURE = re.compile(
    r"^M rss_kib=(\d+) user_ms=(\d+) sys_ms=(\d+) wall_ms=(\d+) status=(\d+)", re.M)


class Participant:
    def __init__(self, name, argv, stdin=None, env=None, note=""):
        self.name = name
        self.argv = argv
        self.stdin = stdin
        self.env = env
        self.note = note

    def present(self):
        return pathlib.Path(self.argv[0]).exists()


def run_once(argv, stdin_bytes=None, env=None, timeout=1800, cwd=None):
    """One measured run. Returns a dict, never raises on a non-zero exit."""
    full = [str(RSSWAIT)] + [str(a) for a in argv]
    merged = dict(os.environ)
    if env:
        merged.update(env)
    t0 = time.monotonic()
    try:
        p = subprocess.run(
            full,
            input=stdin_bytes,
            capture_output=True,
            timeout=timeout,
            env=merged,
            cwd=cwd,
        )
    except subprocess.TimeoutExpired:
        return {"status": -1, "timeout": True,
                "wall_s": time.monotonic() - t0}
    wall = time.monotonic() - t0
    m = MEASURE.search(p.stderr.decode("utf-8", "replace"))
    rec = {
        "wall_s": wall,
        "status": p.returncode,
        "stdout_len": len(p.stdout),
        "stderr_tail": p.stderr.decode("utf-8", "replace")[-400:],
    }
    if m:
        rec.update({
            "rss_kib": int(m.group(1)),
            "user_ms": int(m.group(2)),
            "sys_ms": int(m.group(3)),
            "measured_wall_ms": int(m.group(4)),
            "status": int(m.group(5)),
        })
        rec["cpu_ms"] = rec["user_ms"] + rec["sys_ms"]
    return rec


def stats(values):
    if not values:
        return None
    return {
        "n": len(values),
        "mean": statistics.fmean(values),
        "min": min(values),
        "max": max(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
    }


def summarise(runs):
    ok = [r for r in runs if r.get("status") == 0 and not r.get("timeout")]
    out = {
        "runs": len(runs),
        "ok": len(ok),
        "failed": [
            {"status": r.get("status"), "timeout": r.get("timeout", False),
             "stderr_tail": r.get("stderr_tail", "")[-200:]}
            for r in runs if r not in ok
        ],
    }
    if not ok:
        return out
    out["wall_s"] = stats([r["wall_s"] for r in ok])
    if "cpu_ms" in ok[0]:
        out["cpu_s"] = stats([r["cpu_ms"] / 1000.0 for r in ok])
        out["peak_rss_mib"] = stats([r["rss_kib"] / 1024.0 for r in ok])
    out["samples"] = ok
    return out


# ── the SAP session: the one metric two participants share ────────────────────

def clear_sap_cache():
    """Cold start means the asset cache is empty. Perun keeps the fetched
    images; the oracle has no cache at all and re-streams them every run, so
    its 'warm' number is the same as its cold one. That asymmetry is the
    project's own documented finding, not an artefact of this harness."""
    if SAP_CACHE.exists():
        for p in SAP_CACHE.iterdir():
            if p.is_file():
                p.unlink()
        return True
    return False


def perun_sap_argv():
    """`perun sap` pinned to the same machine id as the oracle and fed the same
    bytes, so the two measure the same protocol work."""
    return [PERUN, "sap", "--mac", MACHINE_MAC, "--sign", PAYLOAD.hex()]


def bench_sap(runs):
    print(f"\n=== SAP session, N={runs} ===")
    print(f"    payload {len(PAYLOAD)} B to both, perun --mac {MACHINE_MAC}")
    out = {}

    # perun, warm (its own cache populated by the first run)
    warm = [run_once(perun_sap_argv()) for _ in range(runs)]
    out["perun_sap_warm"] = summarise(warm)
    print("  perun (warm cache)      :", _line(out["perun_sap_warm"]))

    # perun, cold: empty cache, the run has to fetch the assets itself
    cold = []
    fetched = []
    for i in range(runs):
        cleared = clear_sap_cache()
        rec = run_once(perun_sap_argv(), timeout=3600)
        rec["cache_cleared"] = cleared
        cold.append(rec)
        if i == 0:
            fetched = [p for p in SAP_CACHE.glob("*") if p.is_file()] \
                if SAP_CACHE.exists() else []
    out["perun_sap_cold"] = summarise(cold)
    out["perun_sap_cold_cache_cleared"] = all(r.get("cache_cleared") for r in cold)
    out["perun_sap_cold_fetched_bytes"] = sum(p.stat().st_size for p in fetched)
    print("  perun (cold, no cache) :", _line(out["perun_sap_cold"]),
          f"fetched {out['perun_sap_cold_fetched_bytes']/1e6:.1f} MB",
          f"(cache cleared: {out['perun_sap_cold_cache_cleared']})")

    if ORACLE.exists():
        ora = [run_once([ORACLE], stdin_bytes=PAYLOAD, timeout=3600)
               for _ in range(runs)]
        out["sapsigner_emu"] = summarise(ora)
        print("  sapsigner (Unicorn 2.1.1):", _line(out["sapsigner_emu"]))
        sigs = [r["stdout_len"] for r in ora if r.get("status") == 0]
        if sigs:
            out["sapsigner_signature_bytes"] = sigs[0]
            print(f"    signature bytes: {sigs[0]}")
        uniq = {r.get("stdout_len") for r in ora}
        out["sapsigner_output_stable_across_runs"] = len(uniq) == 1
    else:
        out["sapsigner_emu"] = {"unavailable": "binary not built"}

    if MAJD.exists():
        # majd has no SAP surface at all: the cell is structurally empty.
        v = subprocess.run([str(MAJD), "--version"], capture_output=True,
                           text=True, timeout=60).stdout.strip()
        out["majd_sap"] = {"n/a": "majd has no SAP signing surface",
                           "version": v}
        print(f"  majd v2.6.0            : n/a ({v}) — no SAP surface")
    return out


def _line(s):
    if not s.get("ok"):
        return f"0/{s.get('runs')} ok, first failure: {s.get('failed', [{}])[:1]}"
    w, c, r = s["wall_s"], s.get("cpu_s"), s.get("peak_rss_mib")
    return (f"{s['ok']}/{s['runs']} ok  wall mean {w['mean']:.3f}s "
            f"(min {w['min']:.3f} max {w['max']:.3f} sd {w['stdev']:.3f})"
            + (f"  cpu {c['mean']:.3f}s" if c else "")
            + (f"  rss {r['mean']:.1f} MiB (max {r['max']:.1f})" if r else ""))


# ── the store lane ───────────────────────────────────────────────────────────

APPS = [
    # (label, bundle id, what it is for, pinned external version id)
    # The pin matters: majd v2.6.0 cannot resolve the latest iOS version for
    # these apps on the RU storefront ("platform version lookup returned no
    # app"), while perun does and falls back from an empty legacy songList to
    # DownloadDispatch. Pinning both sides to one id makes them fetch the
    # identical package, which is the only way the timings compare.
    ("small", "com.minsvyaz.gosuslugi", "React Native, 515 MB", "890651808"),
    ("mid", "ph.telegra.Telegraph", "Swift, many small resources", "891105604"),
    ("large", "com.tanksblitz", "3.14 GB, 47 007 entries, Unity", "889766342"),
]


def bench_store(runs, only=None):
    print(f"\n=== store lane, N={runs} ===")
    out = {}
    for label, bundle, why, vid in APPS:
        if only and label not in only:
            continue
        row = {"bundle": bundle, "external_version_id": vid}
        recs = []
        for i in range(runs):
            dst = BENCH / f"{label}-{i}.ipa"
            dst.parent.mkdir(parents=True, exist_ok=True)
            if dst.exists():
                dst.unlink()
            rec = run_once([PERUN, "download", "-b", bundle,
                            "--external-version-id", vid, "-o", str(dst)],
                           timeout=3600)
            if i == 0 and dst.exists():
                row["out_bytes"] = dst.stat().st_size
            if dst.exists():
                dst.unlink()
            recs.append(rec)
        row["perun_download"] = summarise(recs)
        print(f"  [{label}] perun download:", _line(row["perun_download"]),
              f"-> {row.get('out_bytes', 0)/1e6:.1f} MB  ({why})")
        row["majd_download"] = summarise(
            majd_runs(label, bundle, vid, runs))
        print(f"  [{label}] majd    download:", _line(row["majd_download"]))
        pw, mw = row["perun_download"].get("wall_s"), row["majd_download"].get("wall_s")
        if pw and mw:
            row["majd_over_perun_wall"] = mw["mean"] / pw["mean"]
            print(f"  [{label}] majd is {row['majd_over_perun_wall']:.2f}x perun's wall time")
        out[label] = row
    return out


def majd_runs(label, bundle, vid, runs):
    """The same download through majd, with its keyring unlocked.

    majd writes to a directory, not a file, so the destination is a scratch
    directory per run and the payload is measured by what lands in it.
    """
    recs = []
    for i in range(runs):
        d = BENCH / f"majd-{label}-{i}"
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)
        d.mkdir(parents=True, exist_ok=True)
        recs.append(run_once(
            [MAJD, "--keychain-passphrase", MAJD_KEYCHAIN,
             "download", "-b", bundle, "--external-version-id", vid,
             "-o", str(d)],
            timeout=3600))
        shutil.rmtree(d, ignore_errors=True)
    return recs


def bench_search(runs):
    print(f"\n=== search (public iTunes API), N={runs} ===")
    out = {}
    out["perun"] = summarise(
        [run_once([PERUN, "search", "telegram", "--limit", "5"],
                  timeout=300) for _ in range(runs)])
    print("  perun search:", _line(out["perun"]))
    out["majd"] = {"n/a": "resolves the storefront from the account, so search "
                         "needs an Apple ID too; no session in this container"}
    print("  majd  search: n/a — needs an Apple ID session")
    out["sapsigner"] = {"n/a": "no HTTP surface at all: the oracle signs a "
                               "payload on stdin and nothing else"}
    print("  sapsigner   : n/a — signs stdin, no store surface")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sap-runs", type=int, default=10)
    ap.add_argument("--store-runs", type=int, default=10)
    ap.add_argument("--search-runs", type=int, default=10)
    ap.add_argument("--only", default=None,
                    help="comma list: sap,store,search")
    ap.add_argument("--report", default=str(BENCH / "grand_benchmark.json"))
    args = ap.parse_args()
    only = set(args.only.split(",")) if args.only else None

    for p in (PERUN, RSSWAIT):
        if not p.exists():
            raise SystemExit(f"missing {p}")
    BENCH.mkdir(parents=True, exist_ok=True)
    floor = run_once(["/bin/true"])
    print(f"measuring parent: {RSSWAIT}   floor: "
          f"{floor.get('rss_kib')} KiB for /bin/true")
    for p, label in ((PERUN, "perun"), (ORACLE, "sapsigner"), (MAJD, "majd")):
        print(f"  {label:11s} {'present' if p.exists() else 'ABSENT':8s} "
              f"{p if p.exists() else ''}")

    report = {
        "host": "AMD EPYC 7742, Linux, 4 vCPU visible",
        "measuring_parent": str(RSSWAIT),
        "floor_rss_kib": floor.get("rss_kib"),
        "participants": {
            "perun": {"path": str(PERUN), "bytes": PERUN.stat().st_size},
            "sapsigner": {"path": str(ORACLE),
                          "bytes": ORACLE.stat().st_size if ORACLE.exists() else None,
                          "unicorn": "2.1.1, built from GitHub source",
                          "build_note": "upstream Makefile vendors the "
                                        "library from ghcr, which answers 401 "
                                        "anonymously; the same pinned version "
                                        "was built from the GitHub tag and "
                                        "linked with -lm"},
            "majd": {"path": str(MAJD),
                     "bytes": MAJD.stat().st_size if MAJD.exists() else None,
                     "version": "v2.6.0 (latest tag)",
                     "build_note": "no SAP surface; store lane needs an Apple ID"},
        },
        "payload_bytes": len(PAYLOAD),
    }
    if not only or "sap" in only:
        report["sap"] = bench_sap(args.sap_runs)
    if not only or "search" in only:
        report["search"] = bench_search(args.search_runs)
    if not only or "store" in only:
        report["store"] = bench_store(args.store_runs)

    out = pathlib.Path(args.report)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(f"\nreport: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
