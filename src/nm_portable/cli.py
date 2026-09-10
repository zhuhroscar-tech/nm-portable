"""nm-portable CLI."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .core import audit_directory, audit_profile, write_portable_copy


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nm-portable",
        description=(
            "Find and fix NetworkManager .nmconnection profiles that are pinned "
            "to specific hardware (MAC address, interface name), so they can be "
            "safely copied to a different machine."
        ),
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="Report portability blockers, change nothing.")
    audit.add_argument("path", type=Path, help="A .nmconnection file or a directory containing them.")
    audit.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")

    fix = sub.add_parser("fix", help="Write portable copies with hardware pins removed.")
    fix.add_argument("path", type=Path, help="A .nmconnection file or a directory containing them.")
    fix.add_argument("--out", type=Path, required=True, help="Output directory for portable copies.")
    fix.add_argument(
        "--strip-static-ip", action="store_true",
        help="Also reset static IPv4/IPv6 configuration to 'auto' (off by default).",
    )
    fix.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")

    return p


def _collect_paths(path: Path) -> list:
    if path.is_dir():
        return sorted(path.glob("*.nmconnection"))
    return [path]


def _cmd_audit(args) -> int:
    paths = _collect_paths(args.path)
    reports = [audit_profile(p) for p in paths]
    any_blockers = any(r.has_portability_blockers for r in reports)

    if args.json:
        payload = [
            {
                "path": str(r.path),
                "has_portability_blockers": r.has_portability_blockers,
                "findings": [{"level": f.level, "field": f.field, "message": f.message} for f in r.findings],
            }
            for r in reports
        ]
        print(json.dumps(payload, indent=2))
    else:
        if not reports:
            print(f"No .nmconnection files found at {args.path}")
        for r in reports:
            print(f"\n{r.path}")
            if not r.findings:
                print("  [ok] no portability blockers found")
            for f in r.findings:
                tag = "[warn]" if f.level == "warn" else "[info]"
                print(f"  {tag} {f.field}: {f.message}")

    return 1 if any_blockers else 0


def _cmd_fix(args) -> int:
    paths = _collect_paths(args.path)
    results = []
    for p in paths:
        dest, changes = write_portable_copy(p, args.out, strip_static_ip=args.strip_static_ip)
        results.append({"source": str(p), "dest": str(dest), "changes": changes})

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        if not results:
            print(f"No .nmconnection files found at {args.path}")
        for r in results:
            print(f"\n{r['source']} -> {r['dest']}")
            if not r["changes"]:
                print("  (no changes needed)")
            for c in r["changes"]:
                print(f"  - {c}")
        print(
            f"\n{len(results)} portable copy(ies) written to {args.out}. "
            "Review before copying into /etc/NetworkManager/system-connections/ "
            "on the destination machine -- this tool never touches that "
            "directory or reloads NetworkManager itself."
        )

    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "audit":
        return _cmd_audit(args)
    if args.command == "fix":
        return _cmd_fix(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
