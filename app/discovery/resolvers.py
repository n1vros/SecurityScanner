"""
app/discovery/resolvers.py

Resolver-pool management shared by discovery, DNS probing and the NS sweep.

Sources, in merge order:

1. ``DNS_RESOLVERS``      — comma/whitespace separated, always available
2. ``DNS_RESOLVER_FILES`` — comma-separated paths to local lists
3. ``DNS_RESOLVER_URLS``  — comma-separated URLs (trickest, public-dns.info, …)

The merged, validated pool is cached at ``DNS_RESOLVER_CACHE`` and refreshed
after ``DNS_RESOLVER_REFRESH_HOURS``. When every remote source fails, the
existing cache (or the configured defaults) is used — a daemon start must never
depend on a third-party URL being reachable.

Consumers get a plain list of IPs via :func:`get_resolver_list`, and the
puredns/alterx subprocesses get a file via :func:`get_resolvers_file`.
"""

from __future__ import annotations

import asyncio
import atexit
import ipaddress
import os
import random
import tempfile
import time
from pathlib import Path
from typing import Iterable, List, Optional

from app.core.config import settings
from app.core.logging import logger

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8"]

_pool: Optional[List[str]] = None
_resolvers_file: Optional[str] = None
_lock: Optional[asyncio.Lock] = None
_warm_lock: Optional[asyncio.Lock] = None


# ---------------------------------------------------------------------------
# Paths and parsing
# ---------------------------------------------------------------------------

def _resolve_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else _PROJECT_ROOT / path


def _cache_path() -> Path:
    return _resolve_path(getattr(settings, "DNS_RESOLVER_CACHE", "files/resolvers_cache.txt"))


def _parse_resolvers(raw: str) -> List[str]:
    """Parse a comma/whitespace/newline separated list into validated IPs."""
    result: List[str] = []
    seen: set[str] = set()
    for token in raw.replace(",", " ").split():
        token = token.strip()
        if not token:
            continue
        try:
            ip = str(ipaddress.ip_address(token))
        except ValueError:
            logger.debug("resolvers: ignoring invalid address %r", token)
            continue
        if ip not in seen:
            seen.add(ip)
            result.append(ip)
    return result


def _read_cache() -> Optional[List[str]]:
    path = _cache_path()
    try:
        if not path.is_file():
            return None
        resolvers = _parse_resolvers(path.read_text(encoding="utf-8"))
        return resolvers or None
    except OSError as exc:
        logger.debug("resolvers: cannot read cache %s: %s", path, exc)
        return None


def _cache_is_fresh() -> bool:
    path = _cache_path()
    try:
        age_hours = (time.time() - path.stat().st_mtime) / 3600
    except OSError:
        return False
    refresh_hours = float(getattr(settings, "DNS_RESOLVER_REFRESH_HOURS", 48.0))
    return age_hours < refresh_hours


# ---------------------------------------------------------------------------
# Public accessors
# ---------------------------------------------------------------------------

def get_resolver_list() -> List[str]:
    """
    Return the active resolver pool.

    The list itself is shared; callers must not mutate it. It is populated from
    the cache (or ``DNS_RESOLVERS``) on first use.
    """
    global _pool
    if _pool is None:
        _pool = _read_cache() or _parse_resolvers(
            getattr(settings, "DNS_RESOLVERS", "") or ""
        )
        if not _pool:
            _pool = list(_DEFAULT_RESOLVERS)
            logger.warning(
                "resolvers: no valid DNS_RESOLVERS configured — falling back to %s",
                ", ".join(_pool),
            )
        logger.debug("resolvers: pool ready with %d address(es)", len(_pool))
    return _pool


def get_resolvers_file() -> str:
    """
    Write the active pool to a temp file for puredns/massdns and return its
    path. The file is created once per process and removed at exit.
    """
    global _resolvers_file
    if _resolvers_file and Path(_resolvers_file).is_file():
        return _resolvers_file

    fd, path = tempfile.mkstemp(prefix="stoscanner-resolvers-", suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("\n".join(get_resolver_list()))
            handle.write("\n")
    except Exception:
        os.unlink(path)
        raise

    _resolvers_file = path
    atexit.register(_cleanup_resolvers_file, path)
    return path


def _cleanup_resolvers_file(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def set_resolver_list(resolvers: Iterable[str]) -> List[str]:
    """Replace the in-memory pool (used by tests and warm-pool pruning)."""
    global _pool
    parsed = [str(ipaddress.ip_address(r)) for r in resolvers]
    _pool = parsed or list(_DEFAULT_RESOLVERS)
    return _pool


def reload_resolver_pool() -> List[str]:
    """Drop the in-memory pool so the next access re-reads cache/config."""
    global _pool
    _pool = None
    return get_resolver_list()


# ---------------------------------------------------------------------------
# Refresh from files/URLs
# ---------------------------------------------------------------------------

def _get_lock() -> asyncio.Lock:
    global _lock
    if _lock is None:
        _lock = asyncio.Lock()
    return _lock


async def _fetch_urls(urls: List[str]) -> List[str]:
    import httpx

    collected: List[str] = []
    timeout = httpx.Timeout(20.0, connect=10.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        for url in urls:
            try:
                response = await client.get(url)
                response.raise_for_status()
                collected.extend(_parse_resolvers(response.text))
                logger.debug("resolvers: fetched %d from %s", len(collected), url)
            except Exception as exc:
                logger.warning("resolvers: failed to fetch %s: %s", url, exc)
    return collected


def _read_files(paths: List[str]) -> List[str]:
    collected: List[str] = []
    for raw in paths:
        path = _resolve_path(raw)
        try:
            collected.extend(_parse_resolvers(path.read_text(encoding="utf-8")))
            logger.debug("resolvers: read %s", path)
        except OSError as exc:
            logger.warning("resolvers: failed to read %s: %s", path, exc)
    return collected


async def ensure_resolver_pool(force: bool = False) -> List[str]:
    """
    Refresh the resolver pool from the configured sources when the cache is
    stale — or unconditionally with ``force``. Never raises: on failure the
    current pool is kept.
    """
    async with _get_lock():
        if not force and _cache_is_fresh():
            cached = _read_cache()
            if cached:
                logger.info("resolvers: using cached pool (%d addresses)", len(cached))
                return set_resolver_list(cached)

        urls = [u.strip() for u in str(getattr(settings, "DNS_RESOLVER_URLS", "") or "").split(",") if u.strip()]
        files = [f.strip() for f in str(getattr(settings, "DNS_RESOLVER_FILES", "") or "").split(",") if f.strip()]

        merged: List[str] = _parse_resolvers(str(getattr(settings, "DNS_RESOLVERS", "") or ""))
        if files:
            merged.extend(_read_files(files))
        if urls:
            try:
                merged.extend(await _fetch_urls(urls))
            except Exception as exc:
                logger.warning("resolvers: remote refresh failed: %s", exc)

        if not merged:
            fallback = _read_cache() or list(_DEFAULT_RESOLVERS)
            logger.warning(
                "resolvers: refresh produced no addresses — keeping %d fallback resolver(s)",
                len(fallback),
            )
            return set_resolver_list(fallback)

        # Preserve order while removing duplicates.
        deduped: List[str] = []
        seen: set[str] = set()
        for ip in merged:
            if ip not in seen:
                seen.add(ip)
                deduped.append(ip)

        try:
            cache = _cache_path()
            cache.parent.mkdir(parents=True, exist_ok=True)
            tmp = cache.with_suffix(cache.suffix + ".tmp")
            tmp.write_text("\n".join(deduped) + "\n", encoding="utf-8")
            tmp.replace(cache)
        except OSError as exc:
            logger.warning("resolvers: could not write cache %s: %s", _cache_path(), exc)

        logger.info("resolvers: refreshed pool with %d address(es)", len(deduped))
        return set_resolver_list(deduped)


# ---------------------------------------------------------------------------
# Health check (used by NS_SWEEP_WARM_POOL_ENABLED)
# ---------------------------------------------------------------------------

async def warm_resolver_pool() -> List[str]:
    """
    Sample the pool and keep only resolvers that answer a real DNS query.

    Pruning only happens when at least ``NS_SWEEP_WARM_POOL_MIN`` resolvers stay
    alive, so a broken network path does not wipe the whole pool. Returns the
    active pool.
    """
    global _warm_lock
    if _warm_lock is None:
        _warm_lock = asyncio.Lock()

    async with _warm_lock:
        pool = list(get_resolver_list())
        if not pool:
            return pool

        sample_size = int(getattr(settings, "NS_SWEEP_WARM_POOL_SAMPLE", 200))
        timeout = float(getattr(settings, "NS_SWEEP_WARM_POOL_TIMEOUT", 1.0))
        min_live = int(getattr(settings, "NS_SWEEP_WARM_POOL_MIN", 8))
        concurrency = int(getattr(settings, "NS_SWEEP_WARM_POOL_CONCURRENCY", 200))

        sample = random.sample(pool, min(sample_size, len(pool)))
        sem = asyncio.Semaphore(max(1, concurrency))

        async def probe(address: str) -> bool:
            async with sem:
                return await _resolver_answers(address, timeout)

        results = await asyncio.gather(*[probe(ip) for ip in sample], return_exceptions=True)
        alive = {ip for ip, ok in zip(sample, results) if ok is True}

        if len(alive) < min_live:
            logger.warning(
                "resolvers: warm pool kept only %d/%d sampled resolvers — "
                "keeping the full pool (min=%d)",
                len(alive), len(sample), min_live,
            )
            return pool

        pruned = [ip for ip in pool if ip not in set(sample) or ip in alive]
        logger.info(
            "resolvers: warm pool kept %d/%d sampled resolvers (pool %d -> %d)",
            len(alive), len(sample), len(pool), len(pruned),
        )
        return set_resolver_list(pruned)


async def _resolver_answers(address: str, timeout: float) -> bool:
    """Best-effort single DNS query against one resolver."""
    try:
        import dns.message
        import dns.query
        import dns.rdatatype
    except ImportError:
        return True

    loop = asyncio.get_running_loop()

    def query() -> bool:
        request = dns.message.make_query("example.com", dns.rdatatype.A)
        try:
            dns.query.udp(request, address, timeout=timeout)
            return True
        except Exception:
            return False

    try:
        return await asyncio.wait_for(loop.run_in_executor(None, query), timeout=timeout + 0.5)
    except Exception:
        return False
