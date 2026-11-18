"""
Rate limiting per domain (token bucket, coroutine-safe).

CDN-aware rate limiting
-----------------------
Some CDNs (Akamai, Cloudflare, Fastly, etc.) sit in front of many target
subdomains at once. Hitting 20 subdomains simultaneously when they all route
through the same CDN edge network is effectively hitting that CDN at 20× your
per-domain rate — which is exactly what triggers WAF blocks.

This module adds a second tier of rate limiting keyed by CDN provider rather
than root domain. Each CDN gets its own token bucket configured via .env:

    AKAMAI_RATE_LIMIT=1.0       # max 1 req/s across ALL Akamai-proxied subdomains
    CLOUDFLARE_RATE_LIMIT=2.0   # max 2 req/s across ALL Cloudflare-proxied subdomains
    FASTLY_RATE_LIMIT=1.0
    CLOUDFRONT_RATE_LIMIT=2.0
    INCAPSULA_RATE_LIMIT=1.0
    SUCURI_RATE_LIMIT=1.0

Set to 0 or leave empty to SKIP subdomains behind that CDN entirely
(they will be skipped during this iteration and retried next scan cycle).

Detection is done from the CNAME chain and resolved IPs returned by the DNS
prober. CNAME patterns are checked first (fast, reliable). IP-range checks
are intentionally not implemented — they require maintaining ASN/prefix tables
and the CNAME patterns catch the vast majority of cases.
"""

import asyncio
import re
import time
from typing import Dict, Optional, Tuple

from app.core.config import settings
from app.core.logging import logger


# ---------------------------------------------------------------------------
# CDN fingerprint patterns — matched against the full CNAME chain
# ---------------------------------------------------------------------------
#
# Each entry: (provider_key, [regex, ...])
# provider_key must match the settings attribute: <KEY>_RATE_LIMIT
#
# Patterns are checked in order — put more specific ones first.

_CDN_CNAME_PATTERNS: list[Tuple[str, list[re.Pattern]]] = [
    ("akamai", [
        re.compile(r"\.akamai(?:edge)?\.net\.?$",       re.IGNORECASE),
        re.compile(r"\.akamaized\.net\.?$",             re.IGNORECASE),
        re.compile(r"\.akamaihd\.net\.?$",              re.IGNORECASE),
        re.compile(r"\.akadns\.net\.?$",                re.IGNORECASE),
        re.compile(r"\.edgesuite\.net\.?$",             re.IGNORECASE),
        re.compile(r"\.edgekey\.net\.?$",               re.IGNORECASE),
        re.compile(r"\.srip\.net\.?$",                  re.IGNORECASE),
        re.compile(r"\.akagtm\.net\.?$",                re.IGNORECASE),
    ]),
    ("cloudflare", [
        re.compile(r"\.cloudflare\.com\.?$",            re.IGNORECASE),
        re.compile(r"\.cloudflare\.net\.?$",            re.IGNORECASE),
        re.compile(r"\.workers\.dev\.?$",               re.IGNORECASE),
        re.compile(r"\.pages\.dev\.?$",                 re.IGNORECASE),
    ]),
    ("fastly", [
        re.compile(r"\.fastly\.net\.?$",                re.IGNORECASE),
        re.compile(r"\.fastlylb\.net\.?$",              re.IGNORECASE),
        re.compile(r"\.global\.ssl\.fastly\.net\.?$",   re.IGNORECASE),
    ]),
    ("cloudfront", [
        re.compile(r"\.cloudfront\.net\.?$",            re.IGNORECASE),
    ]),
    ("incapsula", [
        re.compile(r"\.incapdns\.net\.?$",              re.IGNORECASE),
        re.compile(r"\.imperva\.com\.?$",               re.IGNORECASE),
        re.compile(r"\.impervadns\.net\.?$",            re.IGNORECASE),
    ]),
    ("sucuri", [
        re.compile(r"\.sucuri\.net\.?$",                re.IGNORECASE),
        re.compile(r"\.sucuridns\.net\.?$",             re.IGNORECASE),
    ]),
]

# Flat lookup for fast provider → patterns access
_CDN_PATTERN_MAP: Dict[str, list[re.Pattern]] = {
    provider: patterns for provider, patterns in _CDN_CNAME_PATTERNS
}

# All known CDN provider keys — used to iterate settings
CDN_PROVIDERS = [p for p, _ in _CDN_CNAME_PATTERNS]


# ---------------------------------------------------------------------------
# CDN detection
# ---------------------------------------------------------------------------

def detect_cdn_from_cname(cname: Optional[str]) -> Optional[str]:
    """
    Return the CDN provider key if the CNAME matches a known CDN, else None.
    Only called when dns_data has a cname — O(providers × patterns) but tiny.
    """
    if not cname:
        return None
    cname = cname.lower().rstrip(".")
    for provider, patterns in _CDN_CNAME_PATTERNS:
        for pattern in patterns:
            if pattern.search(cname):
                return provider
    return None


def get_cdn_rate_limit(provider: str) -> Optional[float]:
    """
    Return the configured rate limit for a CDN provider.
      > 0   → use this many req/s for the CDN bucket
      == 0  → skip subdomains behind this CDN
      None  → provider not configured, no CDN-level throttle applied
    """
    attr = f"{provider.upper()}_RATE_LIMIT"
    val  = getattr(settings, attr, None)
    if val is None:
        return None
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Token bucket
# ---------------------------------------------------------------------------

class TokenBucket:
    """Coroutine-safe token bucket rate limiter."""

    def __init__(self, rate: float, capacity: int):
        self.rate     = rate        # tokens per second
        self.capacity = capacity
        self.tokens   = float(capacity)
        self.last_update = time.monotonic()
        self._lock    = asyncio.Lock()

    def _add_tokens(self):
        """Add tokens based on elapsed time (call with lock held)."""
        now          = time.monotonic()
        elapsed      = now - self.last_update
        self.tokens  = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_update = now

    async def acquire(self, tokens: int = 1) -> None:
        """Acquire tokens, waiting if necessary. Coroutine-safe."""
        while True:
            async with self._lock:
                self._add_tokens()
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return
                wait_time = (tokens - self.tokens) / self.rate
            await asyncio.sleep(wait_time)


# ---------------------------------------------------------------------------
# Domain-level rate limiter (existing, unchanged behaviour)
# ---------------------------------------------------------------------------

class DomainRateLimiter:
    """Rate limiter keyed by root domain."""

    def __init__(self):
        self.buckets: dict[str, TokenBucket] = {}
        self._buckets_lock = asyncio.Lock()

    @staticmethod
    def _root_domain(subdomain: str) -> str:
        parts = subdomain.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else subdomain

    async def _get_or_create_bucket(self, domain: str) -> TokenBucket:
        async with self._buckets_lock:
            if domain not in self.buckets:
                self.buckets[domain] = TokenBucket(
                    rate=settings.RATE_LIMIT_PER_DOMAIN,
                    capacity=settings.RATE_LIMIT_BUCKET_SIZE,
                )
                logger.debug(
                    "Created token bucket for domain %s (rate=%.1f/s, capacity=%d)",
                    domain, settings.RATE_LIMIT_PER_DOMAIN, settings.RATE_LIMIT_BUCKET_SIZE,
                )
            return self.buckets[domain]

    async def acquire(self, subdomain: str) -> None:
        """Wait for a rate-limit token for the root domain of subdomain."""
        domain = self._root_domain(subdomain)
        bucket = await self._get_or_create_bucket(domain)
        await bucket.acquire()

    def stats(self) -> dict:
        return {
            domain: {
                "tokens":   round(bucket.tokens, 2),
                "rate":     bucket.rate,
                "capacity": bucket.capacity,
            }
            for domain, bucket in self.buckets.items()
        }


# ---------------------------------------------------------------------------
# CDN-level rate limiter (new)
# ---------------------------------------------------------------------------

class CDNRateLimiter:
    """
    Rate limiter keyed by CDN provider.

    One shared token bucket per CDN — all subdomains behind the same CDN
    compete for the same pool of tokens, preventing burst traffic across
    the CDN edge regardless of how many different root domains are involved.
    """

    def __init__(self):
        self._buckets: Dict[str, TokenBucket] = {}
        self._lock    = asyncio.Lock()

    async def _get_or_create_bucket(self, provider: str, rate: float) -> TokenBucket:
        async with self._lock:
            if provider not in self._buckets:
                # Capacity = rate (1 second worth of tokens) so the bucket
                # never accumulates a big burst after an idle period.
                capacity = max(1, int(rate))
                self._buckets[provider] = TokenBucket(rate=rate, capacity=capacity)
                logger.info(
                    "CDN rate limiter: created bucket for %s (%.2f req/s, capacity=%d)",
                    provider, rate, capacity,
                )
            return self._buckets[provider]

    async def acquire(self, provider: str, rate: float) -> None:
        """Wait for a CDN-level token. rate is the configured req/s."""
        bucket = await self._get_or_create_bucket(provider, rate)
        await bucket.acquire()

    def stats(self) -> dict:
        return {
            provider: {
                "tokens":   round(b.tokens, 2),
                "rate":     b.rate,
                "capacity": b.capacity,
            }
            for provider, b in self._buckets.items()
        }


# ---------------------------------------------------------------------------
# RateLimitManager — unified public API
# ---------------------------------------------------------------------------

class RateLimitManager:
    """
    Singleton manager. Lazily initialises rate limiters so all asyncio
    primitives are always created inside a running event loop.

    Public API
    ----------
    await rate_limit_manager.wait_for_domain(subdomain)
        — existing per-domain throttle (unchanged)

    result = await rate_limit_manager.check_cdn(cname)
        — CDN detection + throttle.
        Returns ("skip", provider)  if CDN rate limit == 0
        Returns ("wait", provider)  after acquiring CDN token (rate > 0)
        Returns (None,   None)      if CNAME doesn't match any CDN or CDN not configured
    """

    _instance: Optional["RateLimitManager"] = None

    def __new__(cls) -> "RateLimitManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._domain_limiter: Optional[DomainRateLimiter] = None
            cls._instance._cdn_limiter:    Optional[CDNRateLimiter]    = None
        return cls._instance

    @property
    def limiter(self) -> DomainRateLimiter:
        if self._domain_limiter is None:
            self._domain_limiter = DomainRateLimiter()
        return self._domain_limiter

    @property
    def cdn_limiter(self) -> CDNRateLimiter:
        if self._cdn_limiter is None:
            self._cdn_limiter = CDNRateLimiter()
        return self._cdn_limiter

    async def wait_for_domain(self, subdomain: str) -> None:
        """Existing per-domain rate limit — unchanged."""
        await self.limiter.acquire(subdomain)

    async def check_cdn(
        self, cname: Optional[str]
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Detect CDN from CNAME and apply the configured rate limit.

        Returns
        -------
        ("skip", provider)   CDN rate limit is 0 → caller should skip this subdomain
        ("wait", provider)   Token acquired → caller may proceed
        (None,   None)       CNAME doesn't match a CDN, or CDN not configured in .env
        """
        provider = detect_cdn_from_cname(cname)
        if provider is None:
            return None, None

        rate = get_cdn_rate_limit(provider)
        if rate is None:
            # CDN detected but no rate limit configured — no CDN throttle applied.
            # Per-domain bucket still applies as usual.
            logger.debug("CDN %s detected but no rate limit configured — no CDN throttle", provider)
            return None, None

        if rate == 0:
            logger.debug("CDN %s: rate limit is 0 — skipping subdomain", provider)
            return "skip", provider

        # rate > 0 — acquire a CDN-level token before proceeding
        await self.cdn_limiter.acquire(provider, rate)
        return "wait", provider

    def stats(self) -> dict:
        return {
            "domain":  self.limiter.stats()    if self._domain_limiter else {},
            "cdn":     self.cdn_limiter.stats() if self._cdn_limiter    else {},
        }


# Global singleton — limiters created lazily on first call
rate_limit_manager = RateLimitManager()