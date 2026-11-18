"""
HackenProof platform integration.
Uses cookie-based auth (cf_clearance + remember_user_token) to collect
bug bounty programs and their web-layer scopes from dashboard.hackenproof.com.

Auth env vars (both required):
  HP_CF_CLEARANCE        -- Cloudflare cf_clearance cookie
  HP_REMEMBER_USER_TOKEN -- HackenProof remember_user_token cookie

Pagination:
  GET /api/internal/user/opportunities?page=N&per_page=10&not_audits=true
  Stop when ``next_page`` is null or batch is empty.

Per-program detail:
  GET /api/internal/user/opportunities/<slug>
  Returns full ``scopes`` array with ``title``, ``target``, ``out_of_scope`` fields.

Scope-type filtering:
  HackenProof programs are heavily crypto-focused. Scopes are tagged by title:
    "Web" / "API"           -> extract domains  <- we want these
    "Smart Contract"        -> on-chain address or GitHub repo, skip
    "Infrastructure"        -> GitHub repo or node/MPC code, skip
    "Blockchain" / "Other"  -> chain-specific targets, skip

  Even within Web scopes the target may be a GitHub URL -- the shared
  ``extract_domains()`` utility already blocks github.com, github.io, etc.
  through its PLATFORM_DOMAINS blocklist, so those pass through safely.
"""

import asyncio
from typing import Any, Dict, List, Optional

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import logger
from app.db.db_models import Program, ProgramPlatform
from app.programs.base import PlatformBase
from app.programs.domain_utils import extract_domains
from app.programs.git_scope_utils import is_git_scope
from app.programs.platforms._git_scope_mixin import extract_git_and_domain_scopes


_BASE_URL      = "https://dashboard.hackenproof.com"
_PROGRAMS_PATH = "/api/internal/user/opportunities"
_PER_PAGE      = 10

# Scope title keywords that indicate a web/API surface worth scanning.
# Comparison is case-insensitive substring match against the ``title`` field.
_WEB_SCOPE_KEYWORDS: frozenset = frozenset({
    "web",
    "api",
    "app",
    "frontend",
    "backend",
    "website",
    "portal",
    "dashboard",
    "mobile",
})

# Scope title keywords that are definitively non-web targets.
# Checked first -- takes priority over _WEB_SCOPE_KEYWORDS.
_NON_WEB_SCOPE_KEYWORDS: frozenset = frozenset({
    "smart contract",
    "infrastructure",
    "blockchain",
    "contract",
    "chain",
    "node",
    "sdk",
    "library",
    "relayer",
    "on-chain",
    "onchain",
    "mpc",
    "bridge contract",
})


def _is_web_scope(title: str) -> bool:
    """
    Return True if this scope title indicates a web/API target.

    Logic:
      1. NON_WEB keyword match -> False  (takes priority)
      2. WEB keyword match     -> True
      3. Unknown title         -> True   (let extract_domains filter further;
                                         PLATFORM_DOMAINS still blocks GitHub etc.)
    """
    t = title.lower().strip()
    for kw in _NON_WEB_SCOPE_KEYWORDS:
        if kw in t:
            return False
    for kw in _WEB_SCOPE_KEYWORDS:
        if kw in t:
            return True
    # Unknown title -- optimistic: pass to extract_domains for final filtering
    return True


class HackenProofPlatform(PlatformBase):
    """HackenProof platform integration using cookie-based authentication."""

    platform = ProgramPlatform.HACKENPROOF

    def __init__(self):
        self._cf_clearance   = settings.HP_CF_CLEARANCE
        self._remember_token = settings.HP_REMEMBER_USER_TOKEN

        if not self._cf_clearance or not self._remember_token:
            logger.warning(
                "HP_CF_CLEARANCE and HP_REMEMBER_USER_TOKEN must both be set "
                "in .env for HackenProof authentication."
            )

        cookies: Dict[str, str] = {}
        if self._cf_clearance:
            cookies["cf_clearance"] = self._cf_clearance
        if self._remember_token:
            cookies["remember_user_token"] = self._remember_token

        self.client = httpx.AsyncClient(
            base_url=_BASE_URL,
            timeout=30.0,
            cookies=cookies,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
                ),
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "en-US,en;q=0.9",
                # Exclude 'br' (Brotli) -- httpx only decompresses it when
                # brotlicffi is installed. gzip is universally safe.
                "Accept-Encoding": "gzip, deflate",
                "DNT": "1",
                "Connection": "keep-alive",
            },
            follow_redirects=True,
        )

        # Conservative -- sits behind Cloudflare
        self._rate_limit_delay  = 1.5
        self._last_request_time = 0.0

    # -- PlatformBase interface ------------------------------------------------

    async def authenticate(self, cookie_file: Optional[str] = None) -> Dict[str, Any]:
        """Verify credentials with a minimal API call."""
        if not self._cf_clearance or not self._remember_token:
            return {
                "authenticated": False,
                "error": "Missing HP_CF_CLEARANCE or HP_REMEMBER_USER_TOKEN in .env",
            }
        try:
            resp = await self._make_request(
                "GET",
                _PROGRAMS_PATH,
                params={"page": 1, "per_page": 1, "not_audits": "true"},
            )
            ok = resp.status_code == 200 and "programs" in resp.json()
            return {"authenticated": ok, "status": resp.status_code}
        except Exception as e:
            return {"authenticated": False, "error": str(e)}

    async def fetch_programs(
        self,
        session: AsyncSession,
        cookie_file: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Fetch all active public bug-bounty programs and their web-layer domains.

        Returns list of dicts with keys:
          name, external_id, url, scopes (List[str]), metadata
        """
        if not self._cf_clearance or not self._remember_token:
            logger.error("HackenProof credentials not set -- skipping fetch.")
            return []

        logger.info("Fetching HackenProof programs...")
        raw_programs = await self._fetch_all_programs()

        results: List[Dict[str, Any]] = []
        total_domains = 0
        total_git_scopes = 0

        for prog in raw_programs:
            try:
                info = await self._process_program(prog)
                if info:
                    results.append(info)
                    total_domains    += len(info["scopes"])
                    total_git_scopes += len(info.get("git_scopes", []))
            except Exception as e:
                logger.error(
                    "HackenProof: error processing program %s: %s",
                    prog.get("slug", "unknown"), e,
                )

        logger.info(
            "Fetched %d HackenProof programs with %d web-layer domains, %d git scopes",
            len(results), total_domains, total_git_scopes,
        )
        return results

    # -- Internal helpers ------------------------------------------------------

    async def _fetch_all_programs(self) -> List[Dict[str, Any]]:
        """
        Page through /api/internal/user/opportunities and return every program.

        Pagination terminates when:
          - ``next_page`` in the response is null, or
          - the returned batch is empty, or
          - collected count >= ``total_items``.
        """
        programs: List[Dict[str, Any]] = []
        page = 1

        while True:
            try:
                resp = await self._make_request(
                    "GET",
                    _PROGRAMS_PATH,
                    params={
                        "page":                     page,
                        "per_page":                 _PER_PAGE,
                        "not_audits":               "true",
                        "order_by[published_date]": "desc",
                    },
                )
                data        = resp.json()
                batch: List = data.get("programs", [])
                total_items = data.get("total_items", 0)

                programs.extend(batch)
                fetched = len(programs)

                logger.debug(
                    "HackenProof page %d: +%d programs (%d/%d total)",
                    page, len(batch), fetched, total_items,
                )

                if not batch or data.get("next_page") is None or fetched >= total_items:
                    break

                page += 1

            except Exception as e:
                logger.error(
                    "HackenProof: error fetching programs page %d: %s", page, e
                )
                break

        logger.info("HackenProof: fetched %d programs total", len(programs))
        return programs

    async def _fetch_program_detail(self, slug: str) -> Optional[Dict[str, Any]]:
        """GET /api/internal/user/opportunities/<slug> -- full program detail."""
        try:
            resp = await self._make_request("GET", f"{_PROGRAMS_PATH}/{slug}")
            return resp.json()
        except Exception as e:
            logger.error(
                "HackenProof: error fetching detail for %s: %s", slug, e
            )
            return None

    async def _process_program(
        self, prog: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Fetch full detail for one listing and extract web-layer domains + git scopes.

        Scope routing (git check is FIRST, before title filter):
          1. is_git_scope(target) → git_scopes, regardless of title label.
             Companies frequently tag GitHub orgs as "Infrastructure" —
             the old title filter was silently dropping them.
          2. _is_web_scope(title) → domain extraction via extract_git_and_domain_scopes
          3. Everything else → skipped (smart contracts, on-chain addresses, etc.)
        """
        slug = prog.get("slug")
        name = prog.get("title", slug)

        if not slug:
            return None

        # Skip programmes not yet live
        status_name: str = (prog.get("status") or {}).get("name", "")
        if status_name.lower() == "upcoming":
            logger.debug("HackenProof: skipping upcoming program: %s", slug)
            return None

        detail = await self._fetch_program_detail(slug)
        if not detail:
            return None

        raw_scopes: List[Dict[str, Any]] = detail.get("scopes", [])
        web_raw_values: List[str] = []
        git_raw_values: List[str] = []
        skipped_non_web = 0

        for sc in raw_scopes:
            if sc.get("out_of_scope"):
                continue

            target: str      = (sc.get("target") or "").strip()
            scope_title: str = (sc.get("title") or "").strip()

            if not target:
                continue

            # Git scope check FIRST — before title-based filtering.
            # "Infrastructure" scopes often contain GitHub org URLs which
            # the old _is_web_scope() check would discard.
            if is_git_scope(target):
                if target not in git_raw_values:
                    git_raw_values.append(target)
                continue

            # Title-based web/non-web filter for remaining targets
            if not _is_web_scope(scope_title):
                logger.debug(
                    "HackenProof [%s]: skipping non-web scope "
                    "(title=%r target=%s)",
                    slug, scope_title, target,
                )
                skipped_non_web += 1
                continue

            web_raw_values.append(target)

        if skipped_non_web:
            logger.debug(
                "HackenProof [%s]: skipped %d non-web/non-git scope(s)",
                slug, skipped_non_web,
            )

        # Run web targets through domain extractor (mixin handles git URL dedup too)
        domains, extra_git = extract_git_and_domain_scopes(web_raw_values, name)
        # Merge any git URLs that slipped through the title filter
        all_git_scopes = git_raw_values + [u for u in extra_git if u not in git_raw_values]

        if all_git_scopes:
            logger.debug(
                "HackenProof [%s]: %d git scope(s): %s",
                slug, len(all_git_scopes), all_git_scopes,
            )

        labels = prog.get("labels", {})
        return {
            "name":        name,
            "external_id": slug,
            "url":         f"https://hackenproof.com/programs/{slug}",
            "scopes":      domains,
            "git_scopes":  all_git_scopes,
            "metadata": {
                "slug":                    slug,
                "max_bounty":              prog.get("max_bounty"),
                "min_bounty":              prog.get("min_bounty"),
                "status":                  status_name,
                "types":                   labels.get("types", []),
                "languages":               labels.get("languages", []),
                "platforms":               labels.get("platforms", []),
                "project_types":           labels.get("project_types", []),
                "kyc_required":            prog.get("kyc_required"),
                "poc_required":            prog.get("poc_required"),
                "total_scopes":            len(raw_scopes),
                "skipped_non_web_scopes":  skipped_non_web,
                "bounty_eligible_domains": len(domains),
                "git_scopes_found":        len(all_git_scopes),
            },
        }

    async def _make_request(
        self, method: str, path: str, **kwargs
    ) -> httpx.Response:
        """
        Rate-limited HTTP request with retry and 429 back-off.

        A 403 logs an actionable hint about refreshing the Cloudflare cookies.
        """
        elapsed = asyncio.get_event_loop().time() - self._last_request_time
        if elapsed < self._rate_limit_delay:
            await asyncio.sleep(self._rate_limit_delay - elapsed)

        max_retries = 3
        for attempt in range(max_retries):
            try:
                self._last_request_time = asyncio.get_event_loop().time()
                resp = await self.client.request(method, path, **kwargs)

                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", 60))
                    logger.warning(
                        "HackenProof: rate limited -- sleeping %ds", retry_after
                    )
                    await asyncio.sleep(retry_after)
                    continue

                if resp.status_code == 403:
                    logger.error(
                        "HackenProof: 403 Forbidden -- "
                        "HP_CF_CLEARANCE or HP_REMEMBER_USER_TOKEN may be expired. "
                        "Refresh them from your browser's DevTools cookies."
                    )
                    resp.raise_for_status()

                resp.raise_for_status()
                return resp

            except httpx.HTTPStatusError:
                raise
            except httpx.HTTPError as e:
                if attempt < max_retries - 1:
                    wait = 2 ** attempt
                    logger.warning(
                        "HackenProof: request failed (attempt %d/%d): %s -- "
                        "retrying in %ds",
                        attempt + 1, max_retries, e, wait,
                    )
                    await asyncio.sleep(wait)
                else:
                    raise

        raise httpx.HTTPError("HackenProof: request failed after all retries")

    async def close(self):
        await self.client.aclose()