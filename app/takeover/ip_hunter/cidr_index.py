"""
app/takeover/ip_hunter/cidr_index.py

Cloud provider IP range index.

Downloads and parses published CIDR tables from each provider, then builds
an ipaddress-based lookup index so any IPv4 or IPv6 address can be instantly
resolved to its provider name and region.

Provider sources
----------------
Fully-implemented (hunter can allocate IPs):
  AWS     https://ip-ranges.amazonaws.com/ip-ranges.json
  Azure   scraped from https://www.microsoft.com/en-us/download/details.aspx?id=56519
  GCP     https://www.gstatic.com/ipranges/cloud.json
  DO      RIPE BGP — AS14061, AS393406, AS62567

Stub providers (indexed for density reporting only — hunter NOT yet implemented):
  Oracle    https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json
  Hetzner   RIPE BGP — AS24940
  Vultr     RIPE BGP — AS20473
  Linode    RIPE BGP — AS63949
  OVH       RIPE BGP — AS16276
  Scaleway  RIPE BGP — AS12876
  UpCloud   RIPE BGP — AS36007
  Alibaba   RIPE BGP — AS45102, AS37963

Stub providers are fully indexed so check_ip_free.py can report per-provider
density (free vs taken counts).  hunter.py skips them because their provider
name is not in _SUPPORTED_PROVIDERS.  Promote a stub to fully-implemented by
adding its name to _SUPPORTED_PROVIDERS in hunter.py and writing a provider
module under app/takeover/ip_hunter/providers/.

IPv6 support
------------
Azure publishes both IPv4 and IPv6 prefixes in ServiceTags_Public_*.json.
Both are now indexed.  lookup() and lookup_all() accept IPv6 addresses and
use a 128-bit prefix walk (O(128) hash probes) identical in structure to the
IPv4 O(32) walk.  All other providers remain IPv4-only — their range files
either don't include IPv6 or it isn't relevant for dangling-IP detection.

Usage:
    index = await CIDRIndex.build()
    result = index.lookup("52.90.127.32")
    # → CIDRMatch(provider="aws", region="us-east-1", cidr="52.90.0.0/15", service="EC2")

    result6 = index.lookup("2603:1026:302:14::8")
    # → CIDRMatch(provider="azure", region="...", cidr="2603:1026:302::/48", service="...")

    # Refresh weekly — provider ranges change several times per week
    await index.refresh()

Config keys (.env):
    CIDR_INDEX_CACHE_PATH    str   default "files/cidr_cache"
    CIDR_INDEX_MAX_AGE_HOURS int   default 24
"""

import asyncio
import ipaddress
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import aiohttp

from app.core.config import settings
from app.core.logging import logger


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CIDRMatch:
    provider: str           # "aws" | "azure" | "gcp" | "digitalocean"
    region:   str           # provider-specific region string e.g. "us-east-1"
    cidr:     str           # the matched prefix e.g. "52.90.0.0/15"
    service:  str           # provider-specific service tag e.g. "EC2", "AZURE", "GCP"


@dataclass
class _IndexEntry:
    network:  Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
    provider: str
    region:   str
    cidr:     str
    service:  str


# ---------------------------------------------------------------------------
# Download helpers
# ---------------------------------------------------------------------------

_AZURE_DOWNLOAD_PAGE = "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
_AWS_URL             = "https://ip-ranges.amazonaws.com/ip-ranges.json"
_GCP_URL             = "https://www.gstatic.com/ipranges/cloud.json"

# DigitalOcean does not publish a structured IP range file.
# We pull announced BGP prefixes from the RIPE stat API for each of DO's ASNs:
#   AS14061  — primary (bulk of DO infrastructure)
#   AS393406 — DigitalOcean LLC (additional ranges)
#   AS62567  — DigitalOcean (additional ranges)
_DO_RIPE_URL_TMPL = (
    "https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
)
_DO_ASNS = ("AS14061", "AS393406", "AS62567")

# ---------------------------------------------------------------------------
# Stub providers — indexed for density reporting, hunter NOT yet implemented.
# Key  = provider name used in CIDRMatch.provider.
# Value = tuple of RIPE ASNs to pull BGP prefixes from.
# To promote a stub to a real provider:
#   1. Add its name to _SUPPORTED_PROVIDERS in hunter.py
#   2. Write a provider module under app/takeover/ip_hunter/providers/
# ---------------------------------------------------------------------------

_STUB_BGP_PROVIDERS: Dict[str, tuple] = {
    "hetzner":  ("AS24940",),
    "vultr":    ("AS20473",),
    "linode":   ("AS63949",),
    "ovh":      ("AS16276",),
    "scaleway": ("AS12876",),
    "upcloud":  ("AS36007",),
    "alibaba":  ("AS45102", "AS37963"),
}

# Oracle publishes a proper structured JSON — more precise than raw BGP.
_ORACLE_URL = "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json"

_TIMEOUT = aiohttp.ClientTimeout(total=60)

# RIPE stat disconnects requests without a User-Agent and rate-limits
# rapid anonymous connections — both cause empty ServerDisconnectedError.
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; STOscanner/1.0; "
        "+https://github.com/stoscanner/stoscanner)"
    ),
    "Accept": "application/json",
}

# Minimum delay between consecutive RIPE stat requests.
_RIPE_REQUEST_DELAY = 1.2   # seconds


async def _fetch(url: str, headers: Optional[dict] = None, retries: int = 3) -> bytes:
    """
    Fetch a URL with retries and exponential backoff.

    repr(exc) is used in log messages so exceptions that stringify to ""
    (aiohttp.ServerDisconnectedError, ClientConnectorError) show their
    class name rather than a blank error string.
    """
    h = {**_HEADERS, **(headers or {})}
    last_exc: Optional[Exception] = None
    for attempt in range(retries):
        try:
            async with aiohttp.ClientSession(timeout=_TIMEOUT, headers=h) as session:
                async with session.get(url) as resp:
                    resp.raise_for_status()
                    return await resp.read()
        except Exception as exc:
            last_exc = exc
            if attempt < retries - 1:
                backoff = 2 ** attempt
                logger.debug(
                    "cidr_index: fetch attempt %d/%d failed for %s: %r — retrying in %ds",
                    attempt + 1, retries, url, exc, backoff,
                )
                await asyncio.sleep(backoff)
    raise last_exc  # type: ignore[misc]


async def _fetch_json(url: str, headers: Optional[dict] = None) -> dict:
    raw = await _fetch(url, headers=headers)
    return json.loads(raw)


async def _resolve_azure_url() -> str:
    """
    Scrape the Azure ServiceTags download page to find the current JSON URL.
    The filename changes weekly (ServiceTags_Public_YYYYMMDD.json) so we can't
    hardcode it — we grab the page and extract the download link.
    """
    raw = (await _fetch(_AZURE_DOWNLOAD_PAGE)).decode("utf-8", errors="replace")
    # The download link appears as: https://download.microsoft.com/.../ServiceTags_Public_YYYYMMDD.json
    match = re.search(
        r'https://download\.microsoft\.com[^"\']+ServiceTags_Public_\d{8}\.json',
        raw,
    )
    if not match:
        raise RuntimeError(
            "Could not find Azure ServiceTags download URL on the Microsoft page. "
            "The page layout may have changed."
        )
    return match.group(0)


# ---------------------------------------------------------------------------
# Per-provider parsers
# ---------------------------------------------------------------------------

def _parse_aws(data: dict) -> List[_IndexEntry]:
    """
    Parse ip-ranges.amazonaws.com/ip-ranges.json.
    Only index EC2 prefixes with real region identifiers.
    GLOBAL entries are excluded — they match services like CloudFront/S3 that
    span all regions and cannot be targeted by EIP allocation in any specific region.
    """
    _AWS_REGION_RE = re.compile(r'^[a-z]{2,}-[a-z]+-[0-9]+$')
    entries = []
    for prefix in data.get("prefixes", []):
        service = prefix.get("service", "")
        if service != "EC2":
            continue
        cidr   = prefix.get("ip_prefix", "")
        region = prefix.get("region", "")
        if not cidr or not region:
            continue
        # Skip GLOBAL and other non-region strings
        if not _AWS_REGION_RE.match(region):
            continue
        try:
            net = ipaddress.IPv4Network(cidr, strict=False)
        except ValueError:
            continue
        entries.append(_IndexEntry(
            network=net, provider="aws", region=region,
            cidr=cidr, service=service,
        ))
    logger.debug("cidr_index: parsed %d AWS prefixes", len(entries))
    return entries


def _parse_azure(data: dict) -> List[_IndexEntry]:
    """
    Parse Azure ServiceTags JSON.
    Each value entry has 'name', 'id', 'properties' → 'addressPrefixes'.
    We index all public entries — Azure public IPs (IPv4 + IPv6) are allocated
    from these.  IPv6 prefixes (2603::/18 and related) are common in Azure;
    indexing them avoids falling back to the slower ASN lookup path.
    """
    entries = []
    for value in data.get("values", []):
        props  = value.get("properties", {})
        region = props.get("region", "global") or "global"
        name   = value.get("name", "")
        for cidr in props.get("addressPrefixes", []):
            try:
                if ":" in cidr:
                    net = ipaddress.IPv6Network(cidr, strict=False)
                else:
                    net = ipaddress.IPv4Network(cidr, strict=False)
            except ValueError:
                continue
            entries.append(_IndexEntry(
                network=net, provider="azure", region=region,
                cidr=cidr, service=name,
            ))
    ipv4_count = sum(1 for e in entries if isinstance(e.network, ipaddress.IPv4Network))
    ipv6_count = len(entries) - ipv4_count
    logger.debug(
        "cidr_index: parsed %d Azure prefixes (%d IPv4, %d IPv6)",
        len(entries), ipv4_count, ipv6_count,
    )
    return entries


def _parse_gcp(data: dict) -> List[_IndexEntry]:
    """
    Parse cloud.json from GCP.
    Structure: { "prefixes": [ {"ipv4Prefix": "...", "service": "...", "scope": "..."} ] }
    """
    entries = []
    for prefix in data.get("prefixes", []):
        cidr   = prefix.get("ipv4Prefix", "")
        region = prefix.get("scope", "global") or "global"
        service = prefix.get("service", "GCP")
        if not cidr:
            continue
        try:
            net = ipaddress.IPv4Network(cidr, strict=False)
        except ValueError:
            continue
        entries.append(_IndexEntry(
            network=net, provider="gcp", region=region,
            cidr=cidr, service=service,
        ))
    logger.debug("cidr_index: parsed %d GCP prefixes", len(entries))
    return entries


def _parse_digitalocean_ripe(data: dict, asn: str) -> List[_IndexEntry]:
    """
    Parse a RIPE stat announced-prefixes response for one DigitalOcean ASN.

    Response structure:
        {
          "data": {
            "prefixes": [
              {"prefix": "192.0.2.0/24", "timelines": [...]},
              ...
            ]
          }
        }

    RIPE does not carry per-datacenter region metadata, so region is set to
    the ASN string.  The hunter uses region for scoring only; missing it does
    not affect whether a hit is detected.
    """
    entries = []
    prefixes = data.get("data", {}).get("prefixes", [])
    for item in prefixes:
        cidr = item.get("prefix", "")
        if not cidr or ":" in cidr:   # skip empty or IPv6
            continue
        try:
            net = ipaddress.IPv4Network(cidr, strict=False)
        except ValueError:
            continue
        entries.append(_IndexEntry(
            network=net,
            provider="digitalocean",
            region=asn.lower(),   # e.g. "as14061" — best available granularity
            cidr=cidr,
            service="DO",
        ))
    logger.debug(
        "cidr_index: parsed %d DigitalOcean prefixes from %s", len(entries), asn
    )
    return entries


def _parse_bgp_ripe(data: dict, provider: str, asn: str) -> List[_IndexEntry]:
    """
    Generic RIPE stat announced-prefixes parser for any provider.

    Reused by all stub providers (Hetzner, Vultr, Linode, OVH, Scaleway,
    UpCloud, Alibaba).  Region is set to the ASN string since RIPE carries
    no datacenter metadata — sufficient for density reporting.
    """
    entries = []
    for item in data.get("data", {}).get("prefixes", []):
        cidr = item.get("prefix", "")
        if not cidr or ":" in cidr:
            continue
        try:
            net = ipaddress.IPv4Network(cidr, strict=False)
        except ValueError:
            continue
        entries.append(_IndexEntry(
            network=net,
            provider=provider,
            region=asn.lower(),
            cidr=cidr,
            service=provider.upper(),
        ))
    logger.debug(
        "cidr_index: parsed %d %s prefixes from %s", len(entries), provider, asn
    )
    return entries


def _parse_oracle(data: dict) -> List[_IndexEntry]:
    """
    Parse Oracle Cloud public_ip_ranges.json.

    Structure:
        {
          "regions": [
            {
              "region": "us-ashburn-1",
              "cidrs": [
                {"cidr": "129.213.0.0/16", "tags": ["OCI"]},
                ...
              ]
            },
            ...
          ]
        }
    """
    entries = []
    for region_block in data.get("regions", []):
        region = region_block.get("region", "global") or "global"
        for cidr_entry in region_block.get("cidrs", []):
            cidr = cidr_entry.get("cidr", "")
            if not cidr or ":" in cidr:
                continue
            try:
                net = ipaddress.IPv4Network(cidr, strict=False)
            except ValueError:
                continue
            entries.append(_IndexEntry(
                network=net,
                provider="oracle",
                region=region,
                cidr=cidr,
                service="OCI",
            ))
    logger.debug("cidr_index: parsed %d Oracle prefixes", len(entries))
    return entries


# ---------------------------------------------------------------------------
# CIDRIndex
# ---------------------------------------------------------------------------

class CIDRIndex:
    """
    In-memory IP-to-provider lookup index.

    Built once at startup, refreshed on demand.

    Lookup algorithm — O(32) or O(128) hash probes, not O(n) linear scan:
        For any IP address, generate all possible supernets (/max → /0),
        compute each network address with a bitmask, and do one dict probe per
        prefix length.  At most 32 probes for IPv4, 128 for IPv6, regardless
        of index size.

        83k-entry index, 23k candidate lookups:
          Before (linear): 23,276 × 83,776 ≈ 1.95 billion comparisons → ~65s
          After  (hash):   23,276 × 32     ≈ 744k  probes             → <1s

    IPv6:
        Azure IPv6 prefixes (2603::/18 et al.) are indexed using the same
        (int(network_address), prefixlen) key scheme — Python integers are
        arbitrary precision so 128-bit network addresses fit naturally.
        lookup() detects IPv6 via isinstance() and uses the 128-bit walk.
    """

    def __init__(self) -> None:
        # (network_address_int, prefixlen) → _IndexEntry
        # Most-specific prefix wins: lookup() probes /max → /0 and returns
        # on first hit, so the first match is always the longest prefix.
        self._table: Dict[Tuple[int, int], "_IndexEntry"] = {}
        self._built_at: float = 0.0
        self._cache_path = Path(
            getattr(settings, "CIDR_INDEX_CACHE_PATH", "files/cidr_cache")
        )
        self._max_age_hours = int(
            getattr(settings, "CIDR_INDEX_MAX_AGE_HOURS", 24)
        )

    # keep _entries as a read-only property so external code that iterates
    # ci._entries (check_providers.py, tests) continues to work unchanged.
    @property
    def _entries(self) -> List["_IndexEntry"]:
        return list(self._table.values())

    def _add_entry(self, entry: "_IndexEntry") -> None:
        key = (int(entry.network.network_address), entry.network.prefixlen)
        # First writer wins — keeps more-specific provider entries from being
        # overwritten by wider aggregates loaded later.
        self._table.setdefault(key, entry)

    # ── public API ──────────────────────────────────────────────────────────

    @classmethod
    async def build(cls) -> "CIDRIndex":
        """Download all provider ranges and build the index."""
        index = cls()
        await index.refresh()
        return index

    async def refresh(self) -> None:
        """Re-download and rebuild. Safe to call while the index is in use."""
        entries: List[_IndexEntry] = []
        errors:  List[str]         = []

        # AWS
        try:
            data = await _fetch_json(_AWS_URL)
            entries.extend(_parse_aws(data))
            self._save_cache("aws.json", data)
        except Exception as exc:
            logger.warning("cidr_index: AWS fetch failed: %r — trying cache", exc)
            cached = self._load_cache("aws.json")
            if cached:
                entries.extend(_parse_aws(cached))
            else:
                errors.append(f"aws: {exc}")

        # Azure
        try:
            azure_url = await _resolve_azure_url()
            data = await _fetch_json(azure_url)
            entries.extend(_parse_azure(data))
            self._save_cache("azure.json", data)
        except Exception as exc:
            logger.warning("cidr_index: Azure fetch failed: %r — trying cache", exc)
            cached = self._load_cache("azure.json")
            if cached:
                entries.extend(_parse_azure(cached))
            else:
                errors.append(f"azure: {exc}")

        # GCP
        try:
            data = await _fetch_json(_GCP_URL)
            entries.extend(_parse_gcp(data))
            self._save_cache("gcp.json", data)
        except Exception as exc:
            logger.warning("cidr_index: GCP fetch failed: %r — trying cache", exc)
            cached = self._load_cache("gcp.json")
            if cached:
                entries.extend(_parse_gcp(cached))
            else:
                errors.append(f"gcp: {exc}")

        # DigitalOcean — pull announced BGP prefixes from RIPE for each DO ASN.
        # Cache file per ASN so a single stale ASN doesn't invalidate the others.
        # Inter-request delay avoids RIPE stat rate-limiting across multiple ASNs.
        for i, asn in enumerate(_DO_ASNS):
            if i > 0:
                await asyncio.sleep(_RIPE_REQUEST_DELAY)
            cache_file = f"do_{asn.lower()}.json"
            try:
                url  = _DO_RIPE_URL_TMPL.format(asn=asn)
                data = await _fetch_json(url)
                entries.extend(_parse_digitalocean_ripe(data, asn))
                self._save_cache(cache_file, data)
            except Exception as exc:
                logger.warning(
                    "cidr_index: DO/%s fetch failed: %r — trying cache", asn, exc
                )
                cached = self._load_cache(cache_file)
                if cached:
                    entries.extend(_parse_digitalocean_ripe(cached, asn))
                else:
                    errors.append(f"digitalocean/{asn}: {repr(exc)}")

        if errors and not entries:
            raise RuntimeError(f"CIDRIndex: all providers failed: {'; '.join(errors)}")

        if errors:
            logger.warning("cidr_index: some providers failed: %s", "; ".join(errors))

        # Oracle — structured JSON (more precise than raw BGP).
        try:
            data = await _fetch_json(_ORACLE_URL)
            entries.extend(_parse_oracle(data))
            self._save_cache("oracle.json", data)
        except Exception as exc:
            logger.warning("cidr_index: Oracle fetch failed: %r — trying cache", exc)
            cached = self._load_cache("oracle.json")
            if cached:
                entries.extend(_parse_oracle(cached))
            else:
                logger.warning("cidr_index: Oracle cache also missing — skipping")

        # Stub BGP providers — indexed for density reporting only.
        # Failures are non-fatal: log and continue.
        # Delay between each RIPE request to avoid rate-limiting.
        for provider, asns in _STUB_BGP_PROVIDERS.items():
            for asn in asns:
                await asyncio.sleep(_RIPE_REQUEST_DELAY)
                cache_file = f"{provider}_{asn.lower()}.json"
                try:
                    url  = _DO_RIPE_URL_TMPL.format(asn=asn)
                    data = await _fetch_json(url)
                    entries.extend(_parse_bgp_ripe(data, provider, asn))
                    self._save_cache(cache_file, data)
                except Exception as exc:
                    logger.warning(
                        "cidr_index: %s/%s fetch failed: %r — trying cache",
                        provider, asn, exc,
                    )
                    cached = self._load_cache(cache_file)
                    if cached:
                        entries.extend(_parse_bgp_ripe(cached, provider, asn))
                    else:
                        logger.warning(
                            "cidr_index: %s/%s cache also missing — skipping",
                            provider, asn,
                        )

        # Build the hash table — most-specific prefix wins (setdefault).
        # Sort entries by prefixlen descending before inserting so that when
        # two providers share a CIDR the more-specific (longer) prefix is
        # inserted first and setdefault keeps it.
        entries.sort(key=lambda e: e.network.prefixlen, reverse=True)

        new_table: Dict[Tuple[int, int], _IndexEntry] = {}
        for e in entries:
            key = (int(e.network.network_address), e.network.prefixlen)
            new_table.setdefault(key, e)

        self._table    = new_table
        self._built_at = time.monotonic()

        def _count(p: str) -> int:
            return sum(1 for e in new_table.values() if e.provider == p)

        def _count6(p: str) -> int:
            return sum(
                1 for e in new_table.values()
                if e.provider == p and isinstance(e.network, ipaddress.IPv6Network)
            )

        all_providers = (
            ["aws", "azure", "gcp", "digitalocean", "oracle"]
            + list(_STUB_BGP_PROVIDERS.keys())
        )
        parts = []
        for p in all_providers:
            c = _count(p)
            if p == "azure":
                c6 = _count6(p)
                parts.append(f"azure={c - c6}  azure_ipv6={c6}")
            else:
                parts.append(f"{p}={c}")
        summary = "  ".join(parts)
        logger.info(
            "cidr_index: built index with %d total prefixes  [%s]",
            len(entries),
            summary,
        )

    def lookup(self, ip_str: str) -> Optional[CIDRMatch]:
        """
        Look up an IPv4 or IPv6 address.

        IPv4: O(32)  — probes /32  → /0, first hit wins.
        IPv6: O(128) — probes /128 → /0, first hit wins.
        """
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return None

        if isinstance(addr, ipaddress.IPv6Address):
            addr_int  = int(addr)
            full_mask = (1 << 128) - 1
            for prefixlen in range(128, -1, -1):
                mask        = (full_mask << (128 - prefixlen)) & full_mask
                network_int = addr_int & mask
                entry = self._table.get((network_int, prefixlen))
                if entry is not None:
                    return CIDRMatch(
                        provider=entry.provider,
                        region=entry.region,
                        cidr=entry.cidr,
                        service=entry.service,
                    )
            return None

        # IPv4 path (unchanged)
        addr_int = int(addr)
        for prefixlen in range(32, -1, -1):
            mask        = (0xFFFFFFFF << (32 - prefixlen)) & 0xFFFFFFFF
            network_int = addr_int & mask
            entry = self._table.get((network_int, prefixlen))
            if entry is not None:
                return CIDRMatch(
                    provider=entry.provider,
                    region=entry.region,
                    cidr=entry.cidr,
                    service=entry.service,
                )
        return None

    def lookup_all(self, ip_str: str) -> List[CIDRMatch]:
        """Return all matching provider entries for an IP (may overlap)."""
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return []

        results = []

        if isinstance(addr, ipaddress.IPv6Address):
            addr_int  = int(addr)
            full_mask = (1 << 128) - 1
            for prefixlen in range(128, -1, -1):
                mask        = (full_mask << (128 - prefixlen)) & full_mask
                network_int = addr_int & mask
                entry = self._table.get((network_int, prefixlen))
                if entry is not None:
                    results.append(CIDRMatch(
                        provider=entry.provider,
                        region=entry.region,
                        cidr=entry.cidr,
                        service=entry.service,
                    ))
            return results

        # IPv4 path (unchanged)
        addr_int = int(addr)
        for prefixlen in range(32, -1, -1):
            mask        = (0xFFFFFFFF << (32 - prefixlen)) & 0xFFFFFFFF
            network_int = addr_int & mask
            entry = self._table.get((network_int, prefixlen))
            if entry is not None:
                results.append(CIDRMatch(
                    provider=entry.provider,
                    region=entry.region,
                    cidr=entry.cidr,
                    service=entry.service,
                ))
        return results

    def is_stale(self) -> bool:
        """True if the index is older than CIDR_INDEX_MAX_AGE_HOURS."""
        if self._built_at == 0.0:
            return True
        age_hours = (time.monotonic() - self._built_at) / 3600
        return age_hours > self._max_age_hours

    def provider_entries(self, provider: str) -> List[_IndexEntry]:
        """Return all entries for a specific provider (for range-scanning)."""
        return [e for e in self._table.values() if e.provider == provider]

    # ── cache helpers ────────────────────────────────────────────────────────

    def _save_cache(self, filename: str, data: dict) -> None:
        try:
            self._cache_path.mkdir(parents=True, exist_ok=True)
            (self._cache_path / filename).write_text(
                json.dumps(data), encoding="utf-8"
            )
        except Exception as exc:
            logger.debug("cidr_index: cache write failed for %s: %s", filename, exc)

    def _save_cache_raw(self, filename: str, data: bytes) -> None:
        try:
            self._cache_path.mkdir(parents=True, exist_ok=True)
            (self._cache_path / filename).write_bytes(data)
        except Exception as exc:
            logger.debug("cidr_index: cache write failed for %s: %s", filename, exc)

    def _load_cache(self, filename: str) -> Optional[dict]:
        path = self._cache_path / filename
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.debug("cidr_index: cache read failed for %s: %s", filename, exc)
            return None

    def _load_cache_raw(self, filename: str) -> Optional[bytes]:
        path = self._cache_path / filename
        if not path.exists():
            return None
        try:
            return path.read_bytes()
        except Exception as exc:
            logger.debug("cidr_index: cache read failed for %s: %s", filename, exc)
            return None


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
# Lazy-initialised by hunter.py on first use.  Other modules can import and
# await get_index() to get the shared instance.

_index: Optional[CIDRIndex] = None


async def get_index() -> CIDRIndex:
    """Return the module-level CIDRIndex, building or refreshing as needed."""
    global _index
    if _index is None:
        _index = CIDRIndex()
        await _index.refresh()
    elif _index.is_stale():
        await _index.refresh()
    return _index