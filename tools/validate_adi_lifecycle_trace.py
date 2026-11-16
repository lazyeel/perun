#!/usr/bin/env python3
"""Validate entry/return pairing in a private ADI lifecycle JSONL capture."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from adi_lifecycle_trace_helpers import validate_api_event_log


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path, help="private adi-lifecycle-args.jsonl")
    parser.add_argument(
        "--output",
        type=Path,
        help="write the metadata-only report to this path (mode 0600)",
    )
    args = parser.parse_args()
    report = validate_api_event_log(args.capture)
    report["status"] = "passed" if report["valid"] else "failed"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_name(args.output.name + ".tmp")
        temporary.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.chmod(temporary, 0o600)
        temporary.replace(args.output)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
