#!/usr/bin/env python3
"""HeadsUp launcher — run from the repo root or via the `headsup` CLI.

Usage:
  headsup                  Live threat-memory dashboard (TUI)
  headsup --copilot        Natural-language AI security copilot
  headsup --resolve        Dashboard with reverse-DNS on remote IPs
  headsup --once           Render one snapshot and exit (CI / smoke test)
  headsup timeline [N]     Print the recent memory timeline and exit
  headsup intel            Ingest + print latest threat intelligence and exit
  headsup reset [-y]       Clear local HydraDB memory (asks to confirm; -y skips)
"""
import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "core"))

# Import the TUI module unambiguously as `core.headsup` — importing it as plain
# `headsup` collides with this launcher module when run via the installed
# console script (both would be named `headsup`).
from core import headsup as _hu  # noqa: E402


def main() -> None:
    args = sys.argv[1:]

    if args and args[0] == "reset":
        from hydradb import get_db
        db = get_db()
        force = "-y" in args or "--yes" in args
        total = sum(db.count(t) for t in db._TABLES)
        if total == 0:
            print(f"HydraDB local memory is already empty ({db.location}).")
            return
        if not force:
            print(f"This will permanently clear {total} local memory record(s) at:")
            print(f"  {db.location}")
            if db.cloud_active:
                print("  (HydraDB cloud memory will NOT be affected.)")
            try:
                ans = input("Proceed? [y/N] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                ans = ""
            if ans not in ("y", "yes"):
                print("Reset cancelled.")
                return
        counts = db.reset()
        print(f"Cleared HydraDB local memory ({db.location}):")
        for table, n in counts.items():
            if n:
                print(f"  - {table}: {n}")
        if db.cloud_active:
            print("HydraDB cloud memory was left untouched.")
        return

    if args and args[0] == "timeline":
        from hydradb import get_db
        db = get_db()
        limit = int(args[1]) if len(args) > 1 and args[1].isdigit() else 20
        for ev in db.timeline(limit):
            print(f"{ev['ts'][11:19]}  [{ev['kind']:<8}] {ev['summary']}  (risk {ev['risk_score']})")
        return

    if args and args[0] == "intel":
        from hydradb import get_db
        from analyst import HeadsUpAnalyst
        from anakin import Anakin
        db = get_db()
        anakin = Anakin(db, HeadsUpAnalyst(db))
        n = anakin.ingest()
        print(f"Ingested {n} new campaign(s) from {anakin.source}.\n")
        for it in db.recent_intel(15):
            print(f"  [{it['severity']:<8}] {it['threat_name']}  —  {it['source']}")
        return

    if "--copilot" in args:
        _hu.run_copilot()
        return

    threading.Thread(target=_hu._fetch_public_ip, daemon=True).start()
    _hu.run_monitor(
        resolve="--resolve" in args,
        auto="--auto" in args,
        once="--once" in args,
    )


if __name__ == "__main__":
    main()
