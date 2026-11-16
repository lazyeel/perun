#!/usr/bin/env python3
"""Validate entry/return pairing in a private ADI lifecycle JSONL capture."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from adi_lifecycle_trace_helpers import validate_api_event_log


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path, help="private adi-lifecycle-args.jsonl")
    args = parser.parse_args()
    report = validate_api_event_log(args.capture)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
