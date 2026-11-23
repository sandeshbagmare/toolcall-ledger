"""Command line entry point: ``toolcall-ledger`` or ``python -m toolcall_ledger``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import Ledger, LedgerCorrupted


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="toolcall-ledger",
        description="Inspect and verify an agent tool-call ledger.",
    )
    parser.add_argument("path", type=Path, metavar="FILE")
    parser.add_argument("--json", action="store_true", help="print records as JSON")
    parser.add_argument("--tool", help="only records for this tool")
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the hash chain and print only the outcome",
    )
    args = parser.parse_args(argv)

    if not args.path.is_file():
        print(f"no such ledger: {args.path}", file=sys.stderr)
        return 2
    try:
        ledger = Ledger(args.path)
        ledger.verify()
    except LedgerCorrupted as error:
        print(f"{args.path}: {error}", file=sys.stderr)
        return 1

    records = ledger.records
    if args.tool:
        records = [record for record in records if record.tool == args.tool]

    if args.check:
        print(f"{len(ledger)} record(s), chain ok", file=sys.stderr)
        return 0
    if args.json:
        print(json.dumps([record.as_dict() for record in records], indent=2, ensure_ascii=False))
        return 0
    for record in records:
        status = "ok" if record.ok else ("fail" if record.ok is False else "?")
        duration = f" {record.duration * 1000:.1f}ms" if record.duration is not None else ""
        print(f"{record.index:4d} {record.tool} [{status}]{duration} {record.key[:12]}")
    print(f"{len(records)} record(s), chain ok", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
