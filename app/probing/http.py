"""
HTTP probing for subdomains.

TLS fingerprint evasion
-----------------------
Python's ssl module produces a static, instantly-recognisable JA3/JA4 hash
that Cloudflare, Akamai, DataDome and similar WAFs block before a single
header is read.  We replace httpx with `tls_client`, a Python wrapper around
the Go `uTLS` library that replays the exact TLS ClientHello — cipher suite
order, extension list, elliptic curves, GREASE values, H/2 SETTINGS frames —
of a real browser build.

`tls_client` is synchronous, so each probe runs in an executor thread
(same pattern used in dns_scanner.py for raw UDP).  One thread per probe
is fine — probes are already I/O-bound and the thread pool prevents blocking
the event loop.

Install:  pip install tls-client
"""

import asyncio
import hashlib
import random
import re
from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import logger
from app.db.db_models import Subdomain


# ---------------------------------------------------------------------------
# TLS client identifiers — each maps to a verified browser TLS + H/2 profile
# ---------------------------------------------------------------------------
# tls_client replays the exact ClientHello (cipher suites, extensions, curves,
# GREASE, session ticket, H/2 SETTINGS + WINDOW_UPDATE) for the chosen build.
# Rotating across several profiles prevents trivial JA3 clustering on a single
# scanner fingerprint.
#
# Full list: https://github.com/bogdanfinn/tls-client#supported-client-profiles
# ---------------------------------------------------------------------------

_TLS_PROFILES = [
    "chrome_124",
    "chrome_120",
    "firefox_120",
    "firefox_117",
    "safari_16_0",
    "edge_101",
]

# Matching UA strings — must stay in sync with _TLS_PROFILES so the User-Agent
# header is consistent with the TLS fingerprint being presented.
_PROFILE_UA: Dict[str, str] = {
    "chrome_124": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "chrome_120": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "firefox_120": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) "
        "Gecko/20100101 Firefox/120.0"
    ),
    "firefox_117": (
        "Mozilla/5.0 (X11; Linux x86_64; rv:117.0) "
        "Gecko/20100101 Firefox/117.0"
    ),
    "safari_16_0": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/16.0 Safari/605.1.15"
    ),
    "edge_101": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edg/101.0.1210.53"
    ),
}


def _browser_headers(ua: str) -> Dict[str, str]:
    """
    Return a full browser header set paired with the given User-Agent.
    Sec-Fetch-* and Accept-* must look consistent with a real navigation
    request or header-based bot detectors will flag the mismatch.
    """
    return {
        "User-Agent":                ua,
        "Accept":                    (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7"
        ),
        "Accept-Language":           "en-US,en;q=0.9",
        "Accept-Encoding":           "gzip, deflate, br",
        "Connection":                "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest":            "document",
        "Sec-Fetch-Mode":            "navigate",
        "Sec-Fetch-Site":            "none",
        "Sec-Fetch-User":            "?1",
        "DNT":                       "1",
    }


# ---------------------------------------------------------------------------
# Synchronous probe worker (runs in executor thread)
# ---------------------------------------------------------------------------

def _sync_probe(url: str, proxy: Optional[str]) -> Optional[Dict[str, Any]]:
    """
    Perform a single GET using tls_client.  Returns a result dict on success,
    None on any connection / protocol failure.

    Runs synchronously — must be called via run_in_executor so it does not
    block the event loop.
    """
    try:
        import tls_client
    except ImportError as e:
        raise RuntimeError(
            f"tls_client not installed — run: pip install tls-client (import error: {e})"
        )

    profile = random.choice(_TLS_PROFILES)
    ua      = _PROFILE_UA[profile]

    session = tls_client.Session(
        client_identifier=profile,
        # Randomise TLS extension order within the chosen profile — different
        # real browser instances vary slightly; this prevents a static ordering
        # from acting as a secondary fingerprint beyond JA3.
        random_tls_extension_order=True,
    )

    # Proxy — tls_client accepts socks5h:// / http:// strings.
    # Use socks5h:// (not socks5://) so hostname resolution happens inside
    # the proxy — the local resolver never sees the target domain (OPSEC).
    if proxy:
        session.proxies = {"https": proxy, "http": proxy}

    # Combined connect+read timeout in seconds
    session.timeout_seconds = 11

    try:
        response = session.get(
            url,
            headers=_browser_headers(ua),
            allow_redirects=True,
        )
    except Exception:
        # Any connection-level error (TCP refused, timeout, TLS alert, proxy
        # error) — caller decides whether to retry on http://
        return None

    try:
        body = response.text
    except Exception:
        body = ""

    body_bytes = body.encode(errors="replace")
    body_hash  = hashlib.sha256(body_bytes).hexdigest()
    final_url  = str(getattr(response, "url", url))

    return {
        "status_code":    response.status_code,
        "headers":        dict(response.headers),
        "body":           body,
        "body_hash":      body_hash,
        "content_length": len(body_bytes),
        "url":            final_url,
        "tls_profile":    profile,   # logged for debugging unexpected blocks
    }


# ---------------------------------------------------------------------------
# HTTPProber
# ---------------------------------------------------------------------------

class HTTPProber:
    """
    HTTP probing for subdomains.

    Each probe creates a fresh tls_client.Session (no persistent pool) to
    avoid fd leaks and connection-state bleed across the long-running daemon
    lifetime.  The sync session runs in an executor thread so the event loop
    is never blocked.
    """

    async def probe(
        self,
        session: AsyncSession,
        subdomain: Subdomain,
    ) -> Optional[Dict[str, Any]]:
        """Perform HTTP probe on subdomain, trying HTTPS then HTTP."""
        logger.debug("HTTP probing: %s", subdomain.name)

        for scheme in ("https", "http"):
            url    = f"{scheme}://{subdomain.name}"
            result = await self._probe_url(url, subdomain)
            if result is not None:
                return result

        return None

    async def _probe_url(
        self,
        url: str,
        subdomain: Subdomain,
    ) -> Optional[Dict[str, Any]]:
        """
        Probe a single URL via tls_client in an executor thread.
        Returns None on connection error or unrecoverable exception.

        PROXY: set HTTP_PROXY=socks5h://127.0.0.1:1080 in .env — the h suffix
        tells tls_client to resolve hostnames through the proxy, not locally.
        """
        proxy = getattr(settings, "HTTP_PROXY", None)

        loop = asyncio.get_running_loop()
        try:
            result = await loop.run_in_executor(
                None,
                lambda: _sync_probe(url, proxy),
            )
        except RuntimeError as e:
            logger.error("HTTP probe runtime error for %s: %s", url, e, exc_info=True)
            return None
        except Exception as e:
            err = str(e)
            # mTLS — server demands a client certificate, not a scanner error
            if "CERTIFICATE_REQUIRED" in err or "tlsv13 alert certificate required" in err.lower():
                logger.debug("HTTP probe: mTLS required for %s — skipping", url)
                return None
            # Self-signed / expired cert — log quietly, fall through to http://
            if "CERTIFICATE_VERIFY_FAILED" in err or "SSL" in err:
                logger.debug("HTTP probe SSL error for %s: %s", url, e)
                return None
            # Brotli decompression quirk — server-side issue, not scanner bug
            if "brotli" in err.lower() or "can_accept_more_data" in err:
                logger.debug("HTTP probe brotli decode error for %s: %s", url, e)
                return None
            # Proxy returned non-HTTP bytes (SOCKS5 refusal etc.)
            if "malformed" in err.lower():
                logger.debug("HTTP probe malformed reply for %s (proxy/unreachable): %s", url, e)
                return None
            logger.error("HTTP probe error for %s: %s", url, e, exc_info=True)
            return None

        if result is None:
            # Clean connection failure — TCP refused, timeout, TLS alert
            return None

        # Persist to subdomain model
        subdomain.http_status         = result["status_code"]
        subdomain.http_title          = self._extract_title(result["body"])
        subdomain.http_body_hash      = result["body_hash"]
        subdomain.http_content_length = result["content_length"]
        subdomain.http_probed_at      = datetime.utcnow()

        logger.debug(
            "HTTP probe: %s → %d (tls_profile=%s)",
            url, result["status_code"], result.get("tls_profile", "?"),
        )
        return result

    def _extract_title(self, html: str) -> Optional[str]:
        """Extract title from HTML."""
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        if match:
            title = match.group(1).strip()
            title = re.sub(r"\s+", " ", title)
            return title[:1000]
        return None