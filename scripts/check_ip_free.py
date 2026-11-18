#!/usr/bin/env python3
"""
scripts/check_ip_free.py

One-off / recurring backfill script: runs multi-port TCP liveness checks against
every IP already stored in the subdomains table and stamps ip_free /
ip_free_checked_at on each row.

Usage
-----
  # Check all subdomains that have IPs but no ip_free verdict yet
  python scripts/check_ip_free.py

  # Re-check everything (ignore existing ip_free values)
  python scripts/check_ip_free.py --force

  # Check from a plain-text file instead of the DB (one IP per line)
  python scripts/check_ip_free.py --file ips.txt

  # Limit concurrency (default: 20)
  python scripts/check_ip_free.py --concurrency 10

  # Dry run — print results, don't write to DB
  python scripts/check_ip_free.py --dry-run

Output
------
  Each result line:
    [FREE ]  1.2.3.4   → subdomain.example.com
    [TAKEN]  5.6.7.8   → api.example.com
    [???? ]  9.10.11.12 → old.example.com   (inconclusive)

  Summary at end:
    Checked: 1500 IPs across 820 subdomains
    Free:    312   Taken: 450   Inconclusive: 58   Errors: 0
"""

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Load .env from project root BEFORE any app module is imported.
# app.db.session creates the SQLAlchemy engine at import time using whatever
# credentials settings holds at that moment -- if .env has not been read yet,
# pydantic-settings falls back to defaults (postgres/postgres) which won't
# match a real DB. Fix: load .env explicitly here, before the first
# `from app.` import, regardless of the current working directory.

_SCRIPT_DIR   = Path(__file__).resolve().parent   # .../scripts/
_PROJECT_ROOT = _SCRIPT_DIR.parent                # .../STOscanner/
_DOTENV_PATH  = _PROJECT_ROOT / ".env"

if _DOTENV_PATH.exists():
    try:
        from dotenv import load_dotenv
        load_dotenv(dotenv_path=_DOTENV_PATH, override=False)
        print(f"  Loaded .env from {_DOTENV_PATH}", flush=True)
    except ImportError:
        # python-dotenv not installed -- parse manually
        with open(_DOTENV_PATH) as _f:
            for _line in _f:
                _line = _line.strip()
                if not _line or _line.startswith("#") or "=" not in _line:
                    continue
                _k, _, _v = _line.partition("=")
                _k = _k.strip()
                _v = _v.strip().strip('"').strip("'")
                os.environ.setdefault(_k, _v)
        print(f"  Loaded .env from {_DOTENV_PATH} (manual parser)", flush=True)
else:
    print(f"  WARNING: .env not found at {_DOTENV_PATH} -- relying on env vars only", flush=True)

# Add project root to sys.path so `from app.xxx import` works anywhere
sys.path.insert(0, str(_PROJECT_ROOT))

from app.core.config import settings  # noqa: E402  (must come after env load)
from app.probing.ip_check import check_ip, _get_ports, _get_timeout  # noqa: E402


# ── Counters ──────────────────────────────────────────────────────────────────

class _Stats:
    checked = 0
    free    = 0
    taken   = 0
    unclear = 0
    errors  = 0


stats = _Stats()
_sem: asyncio.Semaphore | None = None


# ── Core worker ───────────────────────────────────────────────────────────────

# Progress flush interval — print a progress line every N checks
_PROGRESS_INTERVAL = 1000
_progress_lock: asyncio.Lock | None = None


async def _check_one_ip(ip: str, label: str, dry_run: bool) -> tuple[str, bool | None]:
    """
    Check a single IP across all configured ports.
    Returns (ip, result) where result is True/False/None.
    """
    global stats
    async with _sem:
        result = await check_ip(ip)

    async with _progress_lock:
        stats.checked += 1
        if result is True:
            stats.free += 1
            tag = "FREE "
        elif result is False:
            stats.taken += 1
            tag = "TAKEN"
        else:
            stats.unclear += 1
            tag = "???? "

        print(f"  [{tag}]  {ip:<18}  → {label}")

        # Progress counter every 1000 checks
        if stats.checked % _PROGRESS_INTERVAL == 0:
            print(
                f"\n  ── Progress: {stats.checked} checked │ "
                f"{stats.free} free │ {stats.taken} taken │ "
                f"{stats.unclear} inconclusive ──\n",
                flush=True,
            )

    return ip, result


async def _process_db_rows(force: bool, concurrency: int, dry_run: bool) -> None:
    """Pull subdomains with IPs from the DB and check each one."""
    from sqlalchemy import select, update
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    # Build a fresh engine directly from settings so this script works
    # regardless of whether app.db.session was imported before .env loaded.
    _engine = create_async_engine(settings.DATABASE_URL, pool_pre_ping=True)
    _Session = async_sessionmaker(bind=_engine, class_=AsyncSession, expire_on_commit=False)

    # Load rows
    async with _Session() as session:
        from app.db.db_models import Subdomain
        stmt = select(
            Subdomain.id,
            Subdomain.name,
            Subdomain.ip_addresses,
            Subdomain.ip_free,
        ).where(
            Subdomain.ip_addresses.isnot(None)
        )
        if not force:
            # Default: only check rows that have never been checked at all
            # (ip_free_checked_at IS NULL). This avoids re-checking rows that
            # were already verified in a previous run. Use --force to re-check
            # everything regardless.
            stmt = stmt.where(Subdomain.ip_free_checked_at.is_(None))
        result = await session.execute(stmt)
        rows = result.all()

    if not rows:
        print("No subdomains with IPs to check (use --force to re-check all).")
        return

    print(f"  Found {len(rows)} subdomain(s) with IP(s) to check.\n")

    # Fan out — one task per (subdomain, ip) pair
    tasks = []
    row_map: dict[str, int] = {}  # ip → subdomain_id (for DB update)

    for sd_id, sd_name, ip_json, _ in rows:
        try:
            ips = json.loads(ip_json)
        except Exception:
            continue
        for ip in ips:
            tasks.append(_check_one_ip(ip, sd_name, dry_run))
            row_map[ip] = sd_id

    results: list[tuple[str, bool | None]] = await asyncio.gather(*tasks)

    if dry_run:
        print("\n  [dry-run] No DB writes.")
        return

    # ── Aggregate per-subdomain: if ANY ip is taken → taken; else free if any free ──
    # Aggregate per-subdomain verdict.
    # Any IP taken -> subdomain taken; else free if any free; else None.
    # We always write back so ip_free=True can flip to False if a server reappears.
    sd_verdict: dict[int, bool | None] = {}
    for ip, verdict in results:
        sd_id = row_map[ip]
        existing = sd_verdict.get(sd_id)
        if existing is False:
            continue  # already confirmed taken -- worse result wins
        if verdict is False:
            sd_verdict[sd_id] = False
        elif verdict is True and existing is None:
            sd_verdict[sd_id] = True
        elif verdict is None and existing is None:
            sd_verdict[sd_id] = None  # inconclusive -- still stamp checked_at

    # Write back -- always update ip_free_checked_at so we know when last verified.
    # For None verdicts: only stamp checked_at, do not overwrite an existing verdict.
    now = datetime.utcnow()
    written = 0
    async with _Session() as session:
        from app.db.db_models import Subdomain
        for sd_id, verdict in sd_verdict.items():
            if verdict is None:
                # Inconclusive -- stamp checked_at only, preserve existing ip_free
                await session.execute(
                    update(Subdomain)
                    .where(Subdomain.id == sd_id)
                    .values(ip_free_checked_at=now)
                )
            else:
                await session.execute(
                    update(Subdomain)
                    .where(Subdomain.id == sd_id)
                    .values(ip_free=verdict, ip_free_checked_at=now)
                )
                written += 1
        await session.commit()

    print(f"\n  DB updated: {written} subdomain(s) verdict written, {len(sd_verdict)-written} checked_at-only.")


async def _process_file(path: str, concurrency: int, dry_run: bool) -> None:
    """Read IPs from a plain-text file and check each one (no DB writes)."""
    with open(path) as fh:
        ips = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

    if not ips:
        print("File is empty or contains no valid IPs.")
        return

    print(f"  Loaded {len(ips)} IP(s) from {path}.\n")
    tasks = [_check_one_ip(ip, ip, dry_run) for ip in ips]
    await asyncio.gather(*tasks)


# ── Entry point ───────────────────────────────────────────────────────────────

async def main() -> None:
    global _sem

    parser = argparse.ArgumentParser(
        description="Backfill ip_free column via multi-port TCP liveness checks."
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Re-check subdomains that already have an ip_free value.",
    )
    parser.add_argument(
        "--file", metavar="PATH",
        help="Read IPs from a plain-text file instead of the DB (one IP per line).",
    )
    parser.add_argument(
        "--concurrency", type=int,
        default=int(getattr(settings, "IP_CHECK_CONCURRENCY", 20)),
        help="Max parallel IP checks (default: 20).",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print results but do not write anything to the DB.",
    )
    args = parser.parse_args()

    ports   = _get_ports()
    timeout = _get_timeout()
    print(f"  Ports:       {', '.join(str(p) for p in ports)}")
    print(f"  Timeout:     {timeout}s per port")
    print(f"  Concurrency: {args.concurrency}")
    if args.dry_run:
        print("  Mode: DRY RUN (no DB writes)")
    print()

    global _progress_lock
    _sem = asyncio.Semaphore(args.concurrency)
    _progress_lock = asyncio.Lock()

    if args.file:
        await _process_file(args.file, args.concurrency, args.dry_run)
    else:
        await _process_db_rows(args.force, args.concurrency, args.dry_run)

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "─" * 60)
    print(f"  Checked:      {stats.checked}")
    print(f"  FREE  (no open ports):      {stats.free}")
    print(f"  TAKEN (open port found):    {stats.taken}")
    print(f"  Inconclusive:               {stats.unclear}")
    print("─" * 60)

    if stats.free:
        print(f"\n  ✓ {stats.free} IP(s) look free — worth attempting cloud IP takeover.")


if __name__ == "__main__":
    asyncio.run(main())