"""
scripts/check_providers.py

Loads ALL IPs from the DB (ip_free=True and ip_free=False), runs them through
the CIDR index, and prints a free-vs-taken density breakdown by provider and
region — so you can see where to hunt next.

Stub providers (Hetzner, Vultr, Linode, OVHcloud, Scaleway, UpCloud, Oracle,
Alibaba) are fetched and indexed here for reporting only.  No hunter is
implemented for them — this script exists to tell you WHICH ONE to implement.

Usage:
    python -m scripts.check_providers
    # or from project root:
    python check_providers.py
"""

import asyncio
import ipaddress
import json
import os
import sys
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import aiohttp

# ── Load .env BEFORE any app import ──────────────────────────────────────────
# app.db.session creates the SQLAlchemy engine at import time using whatever
# credentials settings holds at that moment — load .env first so pydantic-settings
# picks up the real DATABASE_URL instead of falling back to defaults.

_SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_SCRIPT_DIR, ".."))
_DOTENV_PATH  = os.path.join(_PROJECT_ROOT, ".env")

if os.path.exists(_DOTENV_PATH):
    try:
        from dotenv import load_dotenv
        load_dotenv(dotenv_path=_DOTENV_PATH, override=False)
        print(f"  Loaded .env from {_DOTENV_PATH}")
    except ImportError:
        # python-dotenv not installed — parse manually
        with open(_DOTENV_PATH) as _f:
            for _line in _f:
                _line = _line.strip()
                if not _line or _line.startswith("#") or "=" not in _line:
                    continue
                _k, _, _v = _line.partition("=")
                _k = _k.strip()
                _v = _v.strip().strip('"').strip("'")
                os.environ.setdefault(_k, _v)
        print(f"  Loaded .env from {_DOTENV_PATH} (manual parser)")
else:
    print(f"  WARNING: .env not found at {_DOTENV_PATH} — relying on env vars only")

sys.path.insert(0, _PROJECT_ROOT)

# ── Provider sources ──────────────────────────────────────────────────────────
#
# Fully implemented in hunter.py — allocation API exists:
_IMPLEMENTED = {"aws", "azure", "gcp", "digitalocean"}

# Stub providers — CIDR fetched here for density reporting only.
# Format: provider_name → list of RIPE ASNs
_STUB_BGP: Dict[str, List[str]] = {
    "hetzner":  ["AS24940"],
    "vultr":    ["AS20473"],
    "linode":   ["AS63949"],
    "ovh":      ["AS16276"],
    "scaleway": ["AS12876"],
    "upcloud":  ["AS36007"],
    "alibaba":  ["AS45102", "AS37963"],
}

_RIPE_URL   = "https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
_ORACLE_URL = "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json"
_TIMEOUT    = aiohttp.ClientTimeout(total=30)


# ── Minimal CIDR index (self-contained, no cidr_index.py dependency) ─────────

@dataclass
class _Entry:
    network:  ipaddress.IPv4Network
    provider: str
    region:   str


class _LocalIndex:
    """
    IP-to-provider lookup with O(32) hash lookups per IP.

    Instead of scanning all entries linearly, we index every entry by its
    (network_int, prefixlen) key in a dict.  For any given IP we generate all
    32 possible supernets (from /32 down to /0), compute their network address,
    and do a single dict lookup for each — at most 32 probes regardless of how
    many total prefixes are loaded.
    """

    def __init__(self) -> None:
        # (network_address_as_int, prefixlen) → _Entry
        # When two entries share the same key the more-specific one wins;
        # since we iterate prefixlen high→low in lookup() the first hit is
        # already the most specific, so collision handling isn't needed.
        self._table: Dict[Tuple[int, int], _Entry] = {}

    def add(self, cidr: str, provider: str, region: str) -> None:
        if ":" in cidr:          # skip IPv6
            return
        try:
            net = ipaddress.IPv4Network(cidr, strict=False)
        except ValueError:
            return
        key = (int(net.network_address), net.prefixlen)
        # Keep first entry seen for a given key (avoids overwriting a more
        # specific entry from an implemented provider with a stub's aggregate).
        if key not in self._table:
            self._table[key] = _Entry(network=net, provider=provider, region=region)

    def finalise(self) -> None:
        pass   # nothing to sort — lookup is hash-based

    def lookup(self, ip_str: str) -> Optional[_Entry]:
        try:
            addr_int = int(ipaddress.IPv4Address(ip_str))
        except ValueError:
            return None
        # Probe from most-specific (/32) to least-specific (/0).
        # First hit is the longest-prefix match.
        for prefixlen in range(32, -1, -1):
            mask        = (0xFFFFFFFF << (32 - prefixlen)) & 0xFFFFFFFF
            network_int = addr_int & mask
            entry = self._table.get((network_int, prefixlen))
            if entry is not None:
                return entry
        return None

    def __len__(self) -> int:
        return len(self._table)


# ── Fetchers ──────────────────────────────────────────────────────────────────

async def _get_json(session: aiohttp.ClientSession, url: str) -> dict:
    async with session.get(url) as r:
        r.raise_for_status()
        return json.loads(await r.read())


async def _build_local_index() -> _LocalIndex:
    """
    Fetch CIDR ranges for ALL providers (implemented + stubs) and return a
    populated _LocalIndex.  Failures on any single provider are non-fatal.
    """
    index = _LocalIndex()

    async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:

    # Delegate to the existing CIDRIndex for the 4 implemented providers
        # so we don't duplicate their (more complex) parsing logic here.
        try:
            from app.takeover.ip_hunter.cidr_index import CIDRIndex
            ci = await CIDRIndex.build()
            for e in ci._entries:
                index.add(e.cidr, e.provider, e.region)
            print(f"  Loaded implemented providers via CIDRIndex  "
                  f"({len(ci._entries)} prefixes)")
        except Exception as exc:
            print(f"  WARNING: CIDRIndex failed ({exc}) — implemented providers may be missing")

        # ── Oracle — structured JSON with real region names ───────────────
        try:
            data = await _get_json(session, _ORACLE_URL)
            n = 0
            for region_block in data.get("regions", []):
                region = region_block.get("region", "global") or "global"
                for cidr_entry in region_block.get("cidrs", []):
                    cidr = cidr_entry.get("cidr", "")
                    if cidr:
                        index.add(cidr, "oracle", region)
                        n += 1
            print(f"  oracle          {n:>6} prefixes")
        except Exception as exc:
            print(f"  WARNING: oracle fetch failed: {exc}")

        # ── BGP-based stubs via RIPE stat API ─────────────────────────────
        for provider, asns in _STUB_BGP.items():
            total = 0
            for asn in asns:
                try:
                    data = await _get_json(session, _RIPE_URL.format(asn=asn))
                    for item in data.get("data", {}).get("prefixes", []):
                        cidr = item.get("prefix", "")
                        if cidr:
                            index.add(cidr, provider, asn.lower())
                            total += 1
                except Exception as exc:
                    print(f"  WARNING: {provider}/{asn} fetch failed: {exc}")
            if total:
                print(f"  {provider:<16}{total:>6} prefixes")

    index.finalise()
    return index


# ── DB loader ─────────────────────────────────────────────────────────────────

async def _load_all_ips() -> List[Tuple[str, Optional[bool]]]:
    """
    Return every (ip, ip_free) pair from subdomains that have IPs.
    ip_free is True / False / None (never checked).
    """
    from app.db.session import get_session
    from app.db.db_models import Subdomain
    from sqlalchemy import select

    pairs: List[Tuple[str, Optional[bool]]] = []
    async with get_session() as session:
        result = await session.execute(
            select(Subdomain.ip_addresses, Subdomain.ip_free).where(
                Subdomain.ip_addresses.isnot(None)
            )
        )
        for ip_json, ip_free in result.all():
            try:
                for ip in json.loads(ip_json or "[]"):
                    pairs.append((ip, ip_free))
            except Exception:
                pass
    return pairs


# ── Report printer ────────────────────────────────────────────────────────────

def _print_report(
    pairs: List[Tuple[str, Optional[bool]]],
    index: _LocalIndex,
) -> None:
    """
    Cross-reference every IP against the index and print:
      - per-provider summary  (free / taken / unchecked / total / free%)
      - per-region breakdown  (top 10 regions per provider)
    """
    # provider -> region -> {"free": int, "taken": int, "unk": int}
    counts: Dict[str, Dict[str, Dict[str, int]]] = defaultdict(
        lambda: defaultdict(lambda: {"free": 0, "taken": 0, "unk": 0})
    )
    unmatched = {"free": 0, "taken": 0, "unk": 0}

    for ip, ip_free in pairs:
        entry = index.lookup(ip)
        slot  = "free" if ip_free is True else ("taken" if ip_free is False else "unk")
        if entry is None:
            unmatched[slot] += 1
        else:
            counts[entry.provider][entry.region][slot] += 1

    total_ips = len(pairs)

    # per-provider aggregates
    prov_totals: Dict[str, Dict[str, int]] = {}
    for prov, regions in counts.items():
        agg: Dict[str, int] = {"free": 0, "taken": 0, "unk": 0}
        for rc in regions.values():
            for k in agg:
                agg[k] += rc[k]
        prov_totals[prov] = agg

    def _sort_key(p: str) -> tuple:
        t = prov_totals[p]
        total = t["free"] + t["taken"] + t["unk"]
        return (0, -total, p) if p in _IMPLEMENTED else (1, -t["free"], p)

    sorted_providers = sorted(prov_totals.keys(), key=_sort_key)
    prov_w = max((len(p) for p in sorted_providers), default=8)
    prov_w = max(prov_w, 12)

    sep = "  " + "─" * 74
    hdr = (f"  {'Provider':<{prov_w}}  {'Free':>6}  {'Taken':>6}  "
           f"{'Unk':>6}  {'Total':>6}  {'Free%':>6}  {'Impl?':>6}")

    print("\n\n" + "=" * 78)
    print(f"  PROVIDER DENSITY REPORT   ({total_ips} total IPs across all subdomains)")
    print("=" * 78)
    print("  Free  = ip_free=True    Taken = ip_free=False    Unk = never checked")
    print("  Free% = free / (free + taken)  —  excludes unchecked rows")
    print("=" * 78)
    print(hdr)
    print(sep)

    for prov in sorted_providers:
        t     = prov_totals[prov]
        total = t["free"] + t["taken"] + t["unk"]
        dec   = t["free"] + t["taken"]
        pct   = f"{t['free']/dec*100:.1f}%" if dec else "  n/a"
        impl  = "YES" if prov in _IMPLEMENTED else "stub"
        print(
            f"  {prov:<{prov_w}}  {t['free']:>6}  {t['taken']:>6}  "
            f"{t['unk']:>6}  {total:>6}  {pct:>6}  {impl:>6}"
        )

        regions = sorted(
            counts[prov].items(),
            key=lambda kv: -(kv[1]["free"] + kv[1]["taken"] + kv[1]["unk"]),
        )
        for region, rc in regions[:10]:
            rtotal = rc["free"] + rc["taken"] + rc["unk"]
            rdec   = rc["free"] + rc["taken"]
            rpct   = f"{rc['free']/rdec*100:.1f}%" if rdec else "n/a"
            print(
                f"    {region:<{prov_w+2}}  {rc['free']:>6}  {rc['taken']:>6}  "
                f"{rc['unk']:>6}  {rtotal:>6}  {rpct:>6}"
            )
        if len(regions) > 10:
            print(f"    ... and {len(regions) - 10} more regions")

    # unmatched summary row
    um_total = unmatched["free"] + unmatched["taken"] + unmatched["unk"]
    um_dec   = unmatched["free"] + unmatched["taken"]
    um_pct   = f"{unmatched['free']/um_dec*100:.1f}%" if um_dec else "  n/a"
    print(sep)
    print(
        f"  {'(unmatched)':<{prov_w}}  {unmatched['free']:>6}  {unmatched['taken']:>6}  "
        f"{unmatched['unk']:>6}  {um_total:>6}  {um_pct:>6}  {'—':>6}"
    )
    print("=" * 78)
    print(
        "\n  Stub providers with the highest Free count are the best next"
        " implementation targets."
    )
    print(
        "  To promote a stub: add to _SUPPORTED_PROVIDERS in hunter.py"
        " and write providers/<name>.py\n"
    )


# ── Entry point ───────────────────────────────────────────────────────────────

async def main() -> None:
    print("\nBuilding CIDR index (implemented providers + stubs)...")
    index = await _build_local_index()
    print(f"  Index finalised — {len(index)} total prefixes\n")

    print("Loading all IPs from DB...")
    pairs = await _load_all_ips()
    print(f"  Loaded {len(pairs)} IP(s)\n")

    if not pairs:
        print("No IPs found in DB — nothing to report.")
        return

    _print_report(pairs, index)


if __name__ == "__main__":
    asyncio.run(main())