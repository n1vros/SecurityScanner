"""
BugBountyDirectory platform integration.
https://www.bugbountydirectory.com/programs?rewards=Bounty

The listing page (/programs) is fully client-side rendered — no program data
in HTML. Individual program pages (/programs/<slug>) ARE server-side rendered
and contain full scope and bounty information.

Slug discovery:
  Wayback Machine CDX API → enumerate all indexed /programs/<slug> pages.

Per-program scraping (/programs/<slug>):
  - "Bounty" badge must be present
  - Scopes extracted from <ul> under "Scope" heading
  - External URL extracted from any external href on the page
  - If no explicit scopes found, use registered domain of external URL

No-scope fallback:
  Many programs list no explicit scope in HTML, but every program has an
  external link (policy page / main site). We extract the registered domain
  from ANY external href on the page as the fallback scope, bypassing
  extract_domains() so the PLATFORM_DOMAINS blocklist doesn't swallow it.
  We only skip programs where we truly cannot find any external URL.
"""

import asyncio
import re
from datetime import datetime
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, quote, unquote

import httpx
from sqlalchemy import and_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import logger
from app.db.db_models import Program, ProgramPlatform, Scope
from app.programs.base import PlatformBase
from app.programs.domain_utils import extract_domains, registered_domain


_BASE_URL = "https://www.bugbountydirectory.com"
_CDX_URL  = "https://web.archive.org/cdx/search/cdx"

_SLUG_RE = re.compile(
    r"https?://(?:www\.)?bugbountydirectory\.com/programs/([^/?#]+)/?$",
    re.I,
)

# Known managed platform hostnames — programs pointing here are skipped entirely.
_MANAGED_PLATFORM_HOSTS: Dict[str, str] = {
    "hackerone.com":      "hackerone",
    "bugcrowd.com":       "bugcrowd",
    "yeswehack.com":      "yeswehack",
    "intigriti.com":      "intigriti",
    "immunefi.com":       "immunefi",
    "bugbase.ai":         "bugbase",
    "federacy.com":       "federacy",
    "hackenproof.com":    "hackenproof",
    "openbugbounty.org":  "skip",
}

# Domains we never want as scopes even in fallback mode —
# these are third-party services, not the company's own infrastructure.
_FALLBACK_BLOCKLIST: frozenset = frozenset({
    "bugbountydirectory.com",
    "unavatar.io",
    "dicebear.com",
    "getmetadata.abhisheky495.workers.dev",
    "medium.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "youtube.com",
    "facebook.com",
    "instagram.com",
    "github.com",
    "gitlab.com",
    "google.com",
    "apple.com",
    "play.google.com",
    "apps.apple.com",
    "wired.business",
    "twelve.tools",
    "openalternative.co",
})


def _is_managed_platform(url: str) -> bool:
    if not url:
        return False
    try:
        host = urlparse(url).hostname or ""
        host = host.lower().removeprefix("www.")
    except Exception:
        return False
    for domain in _MANAGED_PLATFORM_HOSTS:
        if host == domain or host.endswith(f".{domain}"):
            return True
    return False


def _domain_from_url(url: str) -> str:
    """
    Extract just the registered domain (eTLD+1) from a URL.
    Returns "" if the domain is in the fallback blocklist.
    """
    if not url:
        return ""
    try:
        host = urlparse(url).hostname or ""
        host = host.lower().removeprefix("www.")
    except Exception:
        return ""

    # Check blocklist on raw host first
    for blocked in _FALLBACK_BLOCKLIST:
        if host == blocked or host.endswith(f".{blocked}"):
            return ""

    domain = registered_domain(host)
    if not domain:
        return ""

    # Check blocklist on registered domain too
    for blocked in _FALLBACK_BLOCKLIST:
        if domain == blocked:
            return ""

    return domain


# ---------------------------------------------------------------------------
# HTML parser
# ---------------------------------------------------------------------------

class _ProgramPageParser(HTMLParser):
    """
    Parses a /programs/<slug> SSR page.

    Collects:
      name         — from <title>
      has_bounty   — True if "Bounty" text node found
      scopes       — raw text items from the Scope <ul>
      external_urls — ALL external hrefs on the page (deduped, ordered)
    """

    def __init__(self):
        super().__init__()
        self.name:          str        = ""
        self.has_bounty:    bool       = False
        self.scopes:        List[str]  = []
        self.external_urls: List[str]  = []

        self._in_title         = False
        self._in_scope_section = False
        self._scope_ul_depth   = 0
        self._in_scope_li      = False
        self._scope_li_buf:    List[str] = []
        self._seen_urls:       set = set()

    def handle_starttag(self, tag, attrs):
        attrs_d = dict(attrs)

        if tag == "title":
            self._in_title = True
            return

        if tag == "a":
            href = (attrs_d.get("href") or "").strip()
            if (
                href.startswith("http")
                and "bugbountydirectory.com" not in href
                and href not in self._seen_urls
            ):
                self._seen_urls.add(href)
                self.external_urls.append(href)

        if self._in_scope_section:
            if tag == "ul":
                self._scope_ul_depth += 1
            elif tag == "li" and self._scope_ul_depth > 0:
                self._in_scope_li = True
                self._scope_li_buf = []

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
            return

        if self._in_scope_section:
            if tag == "ul":
                self._scope_ul_depth -= 1
                if self._scope_ul_depth < 0:
                    self._scope_ul_depth = 0
            elif tag == "li" and self._in_scope_li:
                text = "".join(self._scope_li_buf).strip()
                if text:
                    self.scopes.append(text)
                self._in_scope_li = False
                self._scope_li_buf = []
            elif tag in ("section", "div") and self._scope_ul_depth == 0:
                self._in_scope_section = False

    def handle_data(self, data):
        text = data.strip()
        if not text:
            return

        if self._in_title and not self.name:
            self.name = re.sub(r"\s+Bug Bounty Program.*$", "", text, flags=re.I).strip()
            return

        if text == "Bounty":
            self.has_bounty = True

        if text == "Scope":
            self._in_scope_section = True
            self._scope_ul_depth   = 0
            return

        if self._in_scope_section and self._in_scope_li:
            self._scope_li_buf.append(text)


def _parse_program_page(html: str) -> Dict[str, Any]:
    parser = _ProgramPageParser()
    parser.feed(html)
    return {
        "name":          parser.name,
        "has_bounty":    parser.has_bounty,
        "raw_scopes":    parser.scopes,
        "external_urls": parser.external_urls,
    }


# ---------------------------------------------------------------------------
# Platform class
# ---------------------------------------------------------------------------

class BugBountyDirectoryPlatform(PlatformBase):

    platform = ProgramPlatform.SELF_HOSTED

    def __init__(self):
        self.client = httpx.AsyncClient(
            timeout=30.0,
            headers={
                "Accept":          "text/html,application/xhtml+xml,*/*",
                "Accept-Language": "en-US,en;q=0.9",
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
                ),
            },
            follow_redirects=True,
        )
        self._rate_limit_delay  = 0.5
        self._last_request_time = 0.0

    async def authenticate(self, cookie_file: Optional[str] = None) -> Dict[str, Any]:
        try:
            resp = await self.client.get(f"{_BASE_URL}/programs/gifty")
            return {"authenticated": resp.status_code == 200}
        except Exception as e:
            return {"authenticated": False, "error": str(e)}

    async def fetch_programs(
        self,
        session: AsyncSession,
        cookie_file: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        logger.info("BugBountyDirectory: discovering program slugs via Wayback CDX...")
        slugs = await self._get_slugs_via_cdx()

        if not slugs:
            logger.warning("BugBountyDirectory: no slugs discovered — skipping")
            return []

        logger.info("BugBountyDirectory: %d unique slugs to fetch", len(slugs))

        results:          List[Dict[str, Any]] = []
        skipped_no_bounty = 0
        skipped_managed   = 0
        skipped_no_url    = 0

        for slug in slugs:
            await self._rate_limit()
            try:
                data = await self._fetch_program_page(slug)
            except Exception as e:
                logger.error("BugBountyDirectory: error fetching '%s': %s", slug, e)
                continue

            if not data:
                continue

            if not data["has_bounty"]:
                skipped_no_bounty += 1
                continue

            external_urls = data["external_urls"]

            # Skip if the primary (first) external URL is a managed platform
            primary_url = external_urls[0] if external_urls else ""
            if _is_managed_platform(primary_url):
                skipped_managed += 1
                logger.debug(
                    "BugBountyDirectory: skipping '%s' — managed platform", data["name"]
                )
                continue

            # --- Build scope list ---
            scopes: List[str] = []

            # 1. Explicit scope items from the page (run through extract_domains)
            for raw in data["raw_scopes"]:
                for d in extract_domains(raw, data["name"]):
                    if d not in scopes:
                        scopes.append(d)

            # 2. Fallback: derive domain from external URLs on the page.
            #    We bypass extract_domains() here and use registered_domain()
            #    directly so the PLATFORM_DOMAINS blocklist doesn't drop
            #    legitimate company domains.
            if not scopes:
                for url in external_urls:
                    if _is_managed_platform(url):
                        continue
                    domain = _domain_from_url(url)
                    if domain and domain not in scopes:
                        scopes.append(domain)
                        break   # one fallback domain is enough

            if not scopes:
                skipped_no_url += 1
                logger.debug(
                    "BugBountyDirectory: skipping '%s' — no external URL found", data["name"]
                )
                continue

            name = data["name"] or slug
            results.append({
                "name":        name,
                "external_id": slug,
                "url":         primary_url or f"{_BASE_URL}/programs/{quote(slug)}",
                "scopes":      scopes,
                "metadata": {
                    "source":     "bugbountydirectory.com",
                    "slug":       slug,
                    "raw_scopes": data["raw_scopes"],
                },
            })

        logger.info(
            "BugBountyDirectory: %d programs "
            "(skipped: %d no-bounty, %d managed, %d no-url)",
            len(results), skipped_no_bounty, skipped_managed, skipped_no_url,
        )
        return results

    async def _get_slugs_via_cdx(self) -> List[str]:
        params = {
            "url":      "bugbountydirectory.com/programs/*",
            "output":   "json",
            "fl":       "original",
            "collapse": "urlkey",
            "limit":    "5000",
        }
        try:
            resp = await self.client.get(_CDX_URL, params=params, timeout=60.0)
            resp.raise_for_status()
            rows = resp.json()
        except Exception as e:
            logger.error("BugBountyDirectory: CDX API error: %s", e)
            return []

        slugs: List[str] = []
        seen:  set        = set()

        for row in rows:
            if not row:
                continue
            url = row[0] if isinstance(row, list) else str(row)
            if url == "original":
                continue
            m = _SLUG_RE.match(url)
            if m:
                slug = unquote(m.group(1)).lower().strip()
                if slug and slug not in seen:
                    seen.add(slug)
                    slugs.append(slug)

        logger.info("BugBountyDirectory: CDX returned %d unique slugs", len(slugs))
        return slugs

    async def _fetch_program_page(self, slug: str) -> Optional[Dict[str, Any]]:
        url = f"{_BASE_URL}/programs/{quote(slug)}"
        try:
            resp = await self.client.get(url)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return _parse_program_page(resp.text)
        except httpx.HTTPStatusError as e:
            logger.debug("BugBountyDirectory: HTTP %d for '%s'", e.response.status_code, slug)
            return None

    async def _rate_limit(self) -> None:
        import time
        now  = time.monotonic()
        wait = self._rate_limit_delay - (now - self._last_request_time)
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_request_time = time.monotonic()

    async def sync_programs(
        self,
        session: AsyncSession,
        cookie_file: Optional[str] = None,
    ) -> List[Program]:
        logger.info("Syncing programs from BugBountyDirectory")
        programs_data = await self.fetch_programs(session, cookie_file)

        synced:    List[Program] = []
        total_new: int           = 0

        for data in programs_data:
            program = await self._create_or_update_program(session, data)
            if program:
                synced.append(program)
                total_new += await self._sync_scopes_with_deduplication(
                    session, program, data.get("scopes", [])
                )

        logger.info(
            "BugBountyDirectory: synced %d programs with %d new scopes",
            len(synced), total_new,
        )
        return synced

    async def _sync_scopes_with_deduplication(
        self,
        session: AsyncSession,
        program: Program,
        domains: List[str],
    ) -> int:
        if not domains:
            return 0

        result = await session.execute(
            select(Scope).where(
                Scope.program_id == program.id,
                Scope.is_active  == True,
            )
        )
        existing = {s.domain for s in result.scalars().all()}

        new_domains = set(domains) - existing
        for domain in new_domains:
            session.add(Scope(
                program_id=program.id,
                domain=domain,
                added_at=datetime.utcnow(),
            ))
        if new_domains:
            await session.commit()

        removed = existing - set(domains)
        if removed:
            await session.execute(
                update(Scope)
                .where(
                    and_(
                        Scope.program_id == program.id,
                        Scope.domain.in_(list(removed)),
                        Scope.is_active == True,
                    )
                )
                .values(is_active=False)
            )
            await session.commit()

        return len(new_domains)

    async def close(self) -> None:
        await self.client.aclose()