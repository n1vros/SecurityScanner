"""
app/discovery/js_scrape.py

JS file scraping for subdomain discovery.

Pipeline (per scope, runs after passive discovery):
  1. gau + waybackurls  — fetch historical JS URLs from archives (passive, fast)
  2. katana             — live JS crawl of the root domain (bounded depth/pages)
  3. aiohttp            — fetch each unique JS URL in-process
  4. regex extraction   — pull subdomain references from JS bodies
  5. upsert             — feed into ActiveDiscovery.upsert_subdomains

This enricher is intentionally scope-level (not per-subdomain) to keep
runtime bounded. Historical URL fetching is cheap; live crawling is capped
by JSSCRAPE_KATANA_DEPTH and JSSCRAPE_KATANA_PAGES.

Config knobs (all optional, all in settings):
  JSSCRAPE_ENABLED             bool  default True
  JSSCRAPE_GAU_BINARY          str   default "gau"
  JSSCRAPE_WAYBACKURLS_BIN     str   default "waybackurls"
  JSSCRAPE_KATANA_BINARY       str   default "katana"
  JSSCRAPE_KATANA_DEPTH        int   default 2
  JSSCRAPE_KATANA_PAGES        int   default 50
  JSSCRAPE_FETCH_CONCURRENCY   int   default 5
  JSSCRAPE_FETCH_TIMEOUT       int   default 15
  JSSCRAPE_TOOL_TIMEOUT        int   default 60
  JSSCRAPE_MAX_JS_SIZE         int   default 524288
  JSSCRAPE_FETCH_STAGGER_MS    int   default 200
  JSSCRAPE_FETCH_JITTER_MS     int   default 300

PROXY NOTE:
  Subprocess tools (gau, waybackurls, katana) do not use proxychains.
  In-process aiohttp JS fetches use HTTP_PROXY from settings.
  Set HTTP_PROXY=socks5://127.0.0.1:1080 in .env to route fetches via proxy.

RATE LIMITING:
  Each JS fetch goes through two rate-limit tiers:
    1. Per-domain bucket (RATE_LIMIT_PER_DOMAIN) — same bucket used by HTTP
       probing, so JS fetches and subdomain probes share one throttle per domain.
    2. CDN bucket — if the JS URL hostname belongs to a known CDN
       (e.g. foo.akamaized.net, bar.cloudfront.net) the CDN-level rate limit
       is also applied. Target-hosted JS (e.g. static.monzo.com) is covered
       by tier 1 only; check_cdn returns (None, None) for those.
"""

import asyncio
import random
import re
from typing import List, Optional, Set
from urllib.parse import urlparse

import aiohttp
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import logger
from app.core.ratelimit import rate_limit_manager
from app.db.db_models import DiscoverySource, Scope
from app.discovery.active import ActiveDiscovery
from app.discovery.js_secrets import (
    JsSecretScanner,
    notify_js_secrets,
    persist_js_secret_findings,
)


# ---------------------------------------------------------------------------
# Subdomain extraction regex
# ---------------------------------------------------------------------------

_LABEL     = r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
_SUBDOMAIN = re.compile(
    rf'(?<![.\w])({_LABEL}(?:\.{_LABEL}){{1,8}})',
    re.ASCII,
)

_NOISE = re.compile(
    r"""
    ^\d+(\.\d+){1,3}$       # 1.2 / 1.2.3 / 1.2.3.4
  | ^[0-9a-f]{8,}$          # hex hash
  | ^[0-9a-f]{8}-           # UUID prefix
  | \.min\.js$              # minified file reference
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _extract_subdomains(body: str, scope_domain: str) -> Set[str]:
    found: Set[str] = set()
    suffix = f".{scope_domain}"
    for m in _SUBDOMAIN.finditer(body):
        candidate = m.group(1).lower()
        if not candidate.endswith(suffix) and candidate != scope_domain:
            continue
        if _NOISE.search(candidate):
            continue
        found.add(candidate)
    return found


def _dedup_by_stem(urls: Set[str]) -> Set[str]:
    """
    Deduplicate JS URLs by filename stem, ignoring cache-bust hashes.
    app.abc123.js and app.def456.js are the same bundle — keep one.
    """
    seen_stems: Set[str] = set()
    result:     Set[str] = set()
    for url in urls:
        path     = urlparse(url).path
        filename = path.rsplit("/", 1)[-1]
        stem     = filename
        stem = re.sub(r'\.[0-9a-f]{6,}\b', '', stem, flags=re.I)
        stem = re.sub(r'[-_][0-9a-f]{6,}\b', '', stem, flags=re.I)
        stem = re.sub(r'[-_v]\d+(\.\d+)*\b', '', stem, flags=re.I)
        stem = re.sub(r'[-_.](min|bundle|chunk|vendor|legacy)\.js$', '', stem, flags=re.I)
        stem = re.sub(r'\.js$', '', stem, flags=re.I)
        stem = stem.lower() or filename
        if stem not in seen_stems:
            seen_stems.add(stem)
            result.add(url)
    return result


# ---------------------------------------------------------------------------
# JSDiscovery
# ---------------------------------------------------------------------------

class JSDiscovery:
    """
    Scrape JS files for hardcoded subdomains.

    Fetches share the per-domain and per-CDN rate-limit buckets used by HTTP
    probing, are staggered with jitter to avoid WAF burst detection, and are
    routed through HTTP_PROXY when configured. Concurrency is bounded by
    JSSCRAPE_FETCH_CONCURRENCY.
    """

    def __init__(self) -> None:
        self._gau_bin       = getattr(settings, "JSSCRAPE_GAU_BINARY",       "gau")
        self._wayback_bin   = getattr(settings, "JSSCRAPE_WAYBACKURLS_BIN",  "waybackurls")
        self._katana_bin    = getattr(settings, "JSSCRAPE_KATANA_BINARY",    "katana")
        self._katana_depth  = getattr(settings, "JSSCRAPE_KATANA_DEPTH",     2)
        self._katana_pages  = getattr(settings, "JSSCRAPE_KATANA_PAGES",     50)
        self._fetch_timeout = getattr(settings, "JSSCRAPE_FETCH_TIMEOUT",    15)
        self._tool_timeout  = getattr(settings, "JSSCRAPE_TOOL_TIMEOUT",     60)
        self._max_js_size   = getattr(settings, "JSSCRAPE_MAX_JS_SIZE",      512 * 1024)
        self._stagger_ms    = getattr(settings, "JSSCRAPE_FETCH_STAGGER_MS", 200)
        self._jitter_ms     = getattr(settings, "JSSCRAPE_FETCH_JITTER_MS",  300)
        self._proxy         = getattr(settings, "HTTP_PROXY", None)
        self._secret_scanner = JsSecretScanner()

        fetch_concurrency = getattr(settings, "JSSCRAPE_FETCH_CONCURRENCY", 5)
        self._fetch_sem   = asyncio.Semaphore(fetch_concurrency)
        logger.debug(
            "JSDiscovery: fetch semaphore initialised with concurrency=%d, "
            "stagger=%dms, jitter=%dms, proxy=%s",
            fetch_concurrency, self._stagger_ms, self._jitter_ms,
            self._proxy or "none",
        )

    # ── Public API ─────────────────────────────────────────────────────────────

    async def enrich(self, session: AsyncSession, scope: Scope) -> List[str]:
        """Full JS scrape pipeline for a scope. Returns newly upserted names."""
        if not getattr(settings, "JSSCRAPE_ENABLED", True):
            return []

        domain = scope.domain
        logger.info("js_scrape: starting for %s", domain)

        # Step 1 — collect JS URLs from archives + live crawl (run in parallel)
        gau_urls, wayback_urls, katana_urls = await asyncio.gather(
            self._run_gau(domain),
            self._run_waybackurls(domain),
            self._run_katana(domain),
            return_exceptions=True,
        )

        js_urls: Set[str] = set()
        for result in (gau_urls, wayback_urls, katana_urls):
            if isinstance(result, Exception):
                logger.debug("js_scrape: tool error for %s: %s", domain, result)
            else:
                js_urls.update(result)

        if not js_urls:
            logger.debug("js_scrape: no JS URLs found for %s", domain)
            return []

        # Deduplicate by filename stem — app.abc123.js and app.def456.js are
        # the same bundle at different cache-bust hashes; only fetch one.
        js_urls = _dedup_by_stem(js_urls)

        max_urls = getattr(settings, "JSSCRAPE_MAX_URLS", 500)
        if len(js_urls) > max_urls:
            logger.warning(
                "js_scrape: capping %d JS URLs to %d for %s",
                len(js_urls), max_urls, domain,
            )
            js_urls = set(list(js_urls)[:max_urls])

        logger.info("js_scrape: %d unique JS URLs to fetch for %s", len(js_urls), domain)

        # Step 2 — fetch JS files and extract subdomains.
        extracted: Set[str] = set()
        fetch_tasks = [
            self._fetch_and_extract(url, domain, task_index=i)
            for i, url in enumerate(js_urls)
        ]
        results = await asyncio.gather(*fetch_tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.debug("js_scrape: fetch error: %s", result)
            elif result:
                extracted.update(result)

        if not extracted:
            logger.debug("js_scrape: no subdomains extracted for %s", domain)
            return []

        logger.info(
            "js_scrape: extracted %d candidate subdomains for %s",
            len(extracted), domain,
        )

        # Step 3 — upsert (reuses ActiveDiscovery path, tagged JS_SCRAPE)
        upserted = await ActiveDiscovery.upsert_subdomains(
            session, domain, list(extracted), source=DiscoverySource.JS_SCRAPE.value
        )

        if upserted:
            logger.info(
                "js_scrape: %d new subdomains found for %s: %s",
                len(upserted), domain, upserted,
            )
        return upserted

    # ── URL collection ─────────────────────────────────────────────────────────

    async def _run_gau(self, domain: str) -> Set[str]:
        """Run gau (GetAllUrls) and return JS file URLs for the domain."""
        cmd = [
            self._gau_bin,
            domain,
            "--subs",
            "--blacklist", "css,png,jpg,jpeg,gif,svg,woff,woff2,ttf,eot,pdf,zip",
        ]
        output = await self._run_tool(cmd, "gau", domain)
        return self._filter_js_urls(output, domain)

    async def _run_waybackurls(self, domain: str) -> Set[str]:
        """Run waybackurls and return JS file URLs."""
        cmd = [self._wayback_bin, domain]
        output = await self._run_tool(cmd, "waybackurls", domain)
        return self._filter_js_urls(output, domain)

    async def _run_katana(self, domain: str) -> Set[str]:
        """
        Run katana for live JS crawling of the root domain. Concurrency (-c)
        follows JSSCRAPE_FETCH_CONCURRENCY.
        """
        fetch_concurrency = getattr(settings, "JSSCRAPE_FETCH_CONCURRENCY", 5)
        cmd = [
            self._katana_bin,
            "-u", f"https://{domain}",
            "-jc",
            "-d",  str(self._katana_depth),
            "-ps", str(self._katana_pages),
            "-c",  str(fetch_concurrency),
            "-silent",
        ]
        output = await self._run_tool(cmd, "katana", domain)
        return self._filter_js_urls(output, domain)

    def _filter_js_urls(self, lines: List[str], domain: str) -> Set[str]:
        """Filter a list of URLs to only in-scope .js files."""
        js_urls: Set[str] = set()
        suffix = f".{domain}"
        for url in lines:
            if not url.endswith(".js"):
                continue
            if "://" not in url:
                continue
            try:
                host = urlparse(url).hostname or ""
            except Exception:
                continue
            if host == domain or host.endswith(suffix):
                js_urls.add(url)
        return js_urls

    async def _run_tool(self, cmd: List[str], tool_name: str, domain: str) -> List[str]:
        """
        Run an external tool subprocess and return stdout lines.
        Returns [] gracefully on timeout, missing binary, or non-zero exit.
        """
        logger.debug("js_scrape: running %s for %s: %s", tool_name, domain, " ".join(cmd))
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=self._tool_timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                logger.warning(
                    "js_scrape: %s timed out after %ds for %s",
                    tool_name, self._tool_timeout, domain,
                )
                return []

            lines = stdout.decode(errors="ignore").splitlines()
            logger.debug(
                "js_scrape: %s returned %d lines for %s", tool_name, len(lines), domain
            )
            return lines

        except FileNotFoundError:
            logger.warning(
                "js_scrape: %s binary not found at '%s' — skipping. "
                "Install: https://github.com/lc/%s",
                tool_name, cmd[0], tool_name,
            )
            return []
        except Exception as e:
            logger.debug("js_scrape: %s error for %s: %s", tool_name, domain, e)
            return []

    # ── JS fetching + extraction ───────────────────────────────────────────────

    async def _fetch_and_extract(
        self,
        url: str,
        scope_domain: str,
        task_index: int = 0,
    ) -> Set[str]:
        if self._stagger_ms > 0 or self._jitter_ms > 0:
            stagger_s = min(task_index * self._stagger_ms / 1000.0, 10.0)
            jitter_s  = random.uniform(0, self._jitter_ms / 1000.0)
            delay     = stagger_s + jitter_s
            if delay > 0:
                await asyncio.sleep(delay)

        try:
            js_host = urlparse(url).hostname or ""
        except Exception:
            js_host = ""

        # per-domain rate limit — same bucket as HTTP probing.
        # Prevents JS fetches from bypassing the per-domain throttle entirely.
        if js_host:
            await rate_limit_manager.wait_for_domain(js_host)

        # CDN rate limit — applies when JS is hosted on a CDN origin directly
        # (e.g. foo.akamaized.net, bar.cloudfront.net). For target-hosted JS
        # (e.g. static.monzo.com) check_cdn returns (None, None) — correct,
        # since those are already covered by the per-domain bucket above.
        cdn_action, cdn_provider = await rate_limit_manager.check_cdn(js_host)

        if cdn_action == "skip":
            logger.debug(
                "js_scrape: CDN skip %s (behind %s, rate=0)", url, cdn_provider
            )
            return set()

        if cdn_action == "wait":
            logger.debug(
                "js_scrape: CDN throttle acquired for %s (behind %s)", url, cdn_provider
            )

        # use instance semaphore, not module-level global
        async with self._fetch_sem:
            try:
                timeout = aiohttp.ClientTimeout(total=self._fetch_timeout)
                headers = {
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/124.0.0.0 Safari/537.36"
                    ),
                    "Accept": "*/*",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Referer": f"https://{scope_domain}/",
                }

                # route in-process JS fetches through proxy.
                # self._proxy is None if HTTP_PROXY not set — aiohttp treats
                # proxy=None as direct connection, so this is always safe.
                async with aiohttp.ClientSession(timeout=timeout, headers=headers) as http:
                    async with http.get(url, proxy=self._proxy) as resp:
                        if resp.status != 200:
                            return set()

                        content_length = resp.content_length
                        if content_length and content_length > self._max_js_size:
                            logger.debug(
                                "js_scrape: skipping %s — content-length %d > max %d",
                                url, content_length, self._max_js_size,
                            )
                            return set()

                        body = await resp.text(errors="ignore")

                        if len(body) > self._max_js_size:
                            body = body[: self._max_js_size]

                        extracted = _extract_subdomains(body, scope_domain)

                        # JS secret scanning — runs on same body, zero extra HTTP requests
                        if getattr(settings, "JS_SECRET_SCAN_ENABLED", True):
                            secret_findings = await self._secret_scanner.scan_body_async(
                                body=body,
                                url=url,
                                scope_domain=scope_domain,
                            )
                            if secret_findings:
                                # Persist + notify without blocking the subdomain return.
                                asyncio.create_task(
                                    persist_js_secret_findings(
                                        secret_findings, scope_domain=scope_domain
                                    )
                                )
                                asyncio.create_task(notify_js_secrets(secret_findings))

                        return extracted

            except asyncio.TimeoutError:
                logger.debug("js_scrape: fetch timeout for %s", url)
                return set()
            except Exception as e:
                logger.debug("js_scrape: fetch error for %s: %s", url, e)
                return set()