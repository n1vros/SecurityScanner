"""
Bugcrowd platform integration using the CrowdControl web API.
Uses cookie-based auth (_bugcrowd_session) — no official public API exists.

Flow
----
  1. GET /engagements.json?category=bug_bounty&rewards_amount=1&...
       → paginated list of engagements, each has "briefUrl" e.g. "/engagements/okta"

  2. GET /engagements/<slug>
       → large HTML page; extract changelog UUID from embedded JSON:
         getBriefVersionDocument&quot;:&quot;/engagements/<slug>/changelog/<uuid>

  3. GET /engagements/<slug>/changelog/<uuid>.json
       → full program brief JSON; extract in-scope domains from targetGroups

  4. Extract wildcard domains via extract_domains() (same util as other platforms)

Auth
----
  BC_SESSION cookie (_bugcrowd_session) is the only required credential.
  Set BC_SESSION in .env — copy the value from your browser DevTools
  (Application → Cookies → bugcrowd.com → _bugcrowd_session).

  _crowdcontrol_session_key is NOT required for public programs.
  If you later need private programs, add it as BC_CROWDCONTROL_SESSION.
"""

import asyncio
import math
import re
from html import unescape
from typing import Any, Dict, List, Optional

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import logger
from app.db.db_models import Program, ProgramPlatform
from app.programs.base import PlatformBase
from app.programs.bounty_utils import (
    as_optional_bool,
    bounty_decision,
    positive_money,
)
from app.programs.domain_utils import extract_domains
from app.programs.platforms._git_scope_mixin import extract_git_and_domain_scopes


# Regex to pull the changelog path out of the HTML blob.
# The page contains JSON-encoded HTML entities, so &quot; instead of "
# Example:
#   getBriefVersionDocument&quot;:&quot;/engagements/okta/changelog/976d2960-...
_CHANGELOG_RE = re.compile(
    r"getBriefVersionDocument&quot;:&quot;(/engagements/[^&]+/changelog/[0-9a-f\-]+)"
)

_BASE_URL = "https://bugcrowd.com"

# Group names that indicate an out-of-scope section.
# Matched case-insensitively against the group's "name" field.
_OOS_GROUP_KEYWORDS = ("out of scope", "out-of-scope", "outofscope", "not in scope")

# CrowdControl target categories. Website/URL/domain targets are host-bearing;
# mobile, API/GraphQL, hardware, binaries, source code and "other" are not.
# Network targets are host-dependent and are kept only when they carry a host.
_DOMAIN_TARGET_CATEGORIES = frozenset({
    "website", "web", "url", "domain", "wildcard",
})
_HOST_REQUIRED_TARGET_CATEGORIES = frozenset({"network"})
_NON_DOMAIN_TARGET_CATEGORIES = frozenset({
    "android", "ios", "mobile", "mobile-application", "mobile_application",
    "hardware", "iot", "other", "api", "graphql", "source-code", "source_code",
    "source code", "repository", "executable", "binary", "smart-contract",
    "smart_contract", "smart contract", "testcase", "test case",
    "ai-model", "ai_model", "ai model",
})


def program_offers_bounty(engagement: Dict[str, Any]) -> bool:
    """Conservative bounty check for a Bugcrowd engagement list item.

    CrowdControl exposes ``rewardSummary`` for paid engagements; VDPs return
    null. A monetary min/max reward is the positive signal. Only when the key
    is absent entirely do we fall back to the engagement's own Bug Bounty
    label, because a present-but-empty summary is explicit evidence of no pay.
    """
    if not isinstance(engagement, dict):
        return False

    explicit = None
    for key in ("bounty", "offers_bounties"):
        if key in engagement:
            explicit = as_optional_bool(engagement.get(key))
            break

    if "rewardSummary" in engagement:
        summary = engagement.get("rewardSummary")
        if isinstance(summary, dict):
            signals = (
                positive_money(summary.get("minReward")),
                positive_money(summary.get("maxReward")),
                positive_money(summary.get("compensationSummary")),
            )
        else:
            signals = ()
    else:
        engagement_type = engagement.get("productEngagementType")
        label = (
            engagement_type.get("label")
            if isinstance(engagement_type, dict)
            else None
        )
        signals = (str(label or "").strip().lower() == "bug bounty",)

    return bounty_decision(
        platform="Bugcrowd",
        program=str(engagement.get("name") or engagement.get("briefUrl") or ""),
        explicit=explicit,
        signals=signals,
    )


def target_category_is_domain(category: object) -> Optional[bool]:
    """Return True/False for known categories, None when host-dependent/unknown."""
    if not isinstance(category, str):
        return None
    normalized = category.strip().lower().replace("_", "-")
    if not normalized:
        return None
    if normalized in _DOMAIN_TARGET_CATEGORIES:
        return True
    if normalized in _HOST_REQUIRED_TARGET_CATEGORIES:
        return None
    if normalized in _NON_DOMAIN_TARGET_CATEGORIES:
        return False
    return None


def _clean_str(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _scope_groups(brief: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """Return the brief's scope-group list.

    None means no recognised group key or an unexpected shape; [] means the
    payload explicitly contained an empty list. The caller uses that distinction
    to treat a schema change as a failed scope fetch rather than as "all scopes
    were removed".
    """
    if not isinstance(brief, dict):
        return None
    nested = brief.get("brief")
    nested = nested if isinstance(nested, dict) else {}

    candidates = (
        brief.get("scope"),
        brief.get("target_groups"),
        brief.get("targetGroups"),
        nested.get("scope"),
        nested.get("target_groups"),
        nested.get("targetGroups"),
    )
    saw_list = False
    for candidate in candidates:
        if candidate is None:
            continue
        if not isinstance(candidate, list):
            return None
        saw_list = True
        if candidate:
            return candidate
    return [] if saw_list else None


def iter_in_scope_targets(brief: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return target dicts from in-scope groups, excluding OOS groups/flags."""
    targets: List[Dict[str, Any]] = []
    for group in _scope_groups(brief) or []:
        if not isinstance(group, dict):
            continue
        group_lower = _clean_str(group.get("name")).lower()
        if any(keyword in group_lower for keyword in _OOS_GROUP_KEYWORDS):
            continue
        group_targets = group.get("targets")
        if not isinstance(group_targets, list):
            continue
        for target in group_targets:
            if not isinstance(target, dict):
                continue
            in_scope = target.get("in_scope", target.get("inScope", True))
            if in_scope is False:
                continue
            targets.append(target)
    return targets


def extract_scopes(
    brief: Dict[str, Any],
    program_name: str,
) -> tuple[List[str], List[str]]:
    """Filter a Bugcrowd brief into domain scopes and git scopes.

    Git scopes are collected from every in-scope target before category
    filtering, so source-code/repository targets reach the git scanner without
    ever becoming subdomain scopes.
    """
    targets = iter_in_scope_targets(brief)

    raw_for_git: List[str] = []
    raw_for_domains: List[str] = []

    for target in targets:
        raw_value = _clean_str(target.get("uri")) or _clean_str(target.get("name"))
        if not raw_value:
            continue

        raw_for_git.append(raw_value)

        category_signal = target_category_is_domain(target.get("category"))
        if category_signal is False:
            logger.debug(
                "Bugcrowd [%s]: skipping non-domain target category %r: %s",
                program_name, target.get("category"), raw_value,
            )
            continue
        if category_signal is None:
            logger.debug(
                "Bugcrowd [%s]: host-dependent/unknown target category %r — "
                "keeping only a host-shaped value: %s",
                program_name, target.get("category"), raw_value,
            )
        raw_for_domains.append(raw_value)

    domains: List[str] = []
    for raw_value in raw_for_domains:
        for domain in extract_domains(raw_value, program_name):
            if domain not in domains:
                domains.append(domain)

    _, git_scope_urls = extract_git_and_domain_scopes(raw_for_git, program_name)
    return domains, git_scope_urls


class BugcrowdPlatform(PlatformBase):
    """Bugcrowd platform integration via cookie-authenticated CrowdControl API."""

    platform = ProgramPlatform.BUGCROWD

    def __init__(self) -> None:
        self._session_cookie = getattr(settings, "BC_SESSION", None)
        self._cc_session      = getattr(settings, "BC_CROWDCONTROL_SESSION", None)

        if not self._session_cookie:
            logger.warning(
                "BC_SESSION not set in .env — Bugcrowd collection will be skipped. "
                "Copy _bugcrowd_session cookie value from your browser."
            )

        cookies: Dict[str, str] = {}
        if self._session_cookie:
            cookies["_bugcrowd_session"] = self._session_cookie
        if self._cc_session:
            cookies["_crowdcontrol_session_key"] = self._cc_session

        self.client = httpx.AsyncClient(
            base_url=_BASE_URL,
            timeout=30.0,
            cookies=cookies,
            headers={
                "Accept":     "application/json, text/html, */*",
                "User-Agent": "Mozilla/5.0 STOscanner/1.0",
                "Referer":    "https://bugcrowd.com/programs",
            },
            follow_redirects=True,
        )

        # Conservative: ~1 req/s
        self._rate_limit_delay  = 1.2
        self._last_request_time = 0.0

    # ── PlatformBase interface ────────────────────────────────────────────────

    async def authenticate(self, cookie_file: Optional[str] = None) -> Dict[str, Any]:
        """Verify the session cookie is still valid."""
        if not self._session_cookie:
            return {"authenticated": False, "error": "BC_SESSION not set in .env"}
        try:
            resp = await self._get(
                "/engagements.json",
                params={
                    "category":         "bug_bounty",
                    "page":             1,
                    "rewards_amount":   1,
                    "rewards_operator": "gte",
                    "rewards_priority": "all",
                    "sort_by":          "promoted",
                    "sort_direction":   "desc",
                },
                accept_json=True,
            )
            ok = resp.status_code == 200
            return {"authenticated": ok, "status": resp.status_code}
        except Exception as exc:
            return {"authenticated": False, "error": str(exc)}

    async def fetch_programs(
        self,
        session: AsyncSession,
        cookie_file: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Full collection pipeline:
          1. Page through engagements list
          2. For each engagement: fetch HTML → extract changelog UUID → fetch JSON
          3. Parse scope items → extract domains
        """
        if not self._session_cookie:
            self.fetch_error = "BC_SESSION not configured"
            logger.error("BC_SESSION not configured — skipping Bugcrowd")
            return []

        logger.info("Fetching Bugcrowd bug bounty programs...")
        engagements = await self._fetch_all_engagements()
        if self.fetch_error:
            return []
        logger.info("Bugcrowd: %d engagements found", len(engagements))

        results: List[Dict[str, Any]] = []
        total_domains = 0
        total_git_scopes = 0

        for eng in engagements:
            try:
                info = await self._process_engagement(eng)
                if info:
                    results.append(info)
                    total_domains    += len(info["scopes"])
                    total_git_scopes += len(info.get("git_scopes", []))
            except Exception as exc:
                logger.error(
                    "Bugcrowd: error processing %s: %s",
                    eng.get("briefUrl", "unknown"), exc,
                )

        logger.info(
            "Bugcrowd: fetched %d programs with %d total wildcard scopes, %d git scopes",
            len(results), total_domains, total_git_scopes,
        )
        return results

    # ── Step 1: list all engagements ─────────────────────────────────────────

    async def _fetch_all_engagements(self) -> List[Dict[str, Any]]:
        """
        Page through GET /engagements.json using paginationMeta for exact page count.
        Returns raw engagement dicts from the API.
        """
        engagements: List[Dict[str, Any]] = []
        page = 1
        total_pages: Optional[int] = None
        limit = 25  # default fallback

        while True:
            try:
                resp = await self._get(
                    "/engagements.json",
                    params={
                        "category":         "bug_bounty",
                        "page":             page,
                        "rewards_amount":   1,
                        "rewards_operator": "gte",
                        "rewards_priority": "all",
                        "sort_by":          "promoted",
                        "sort_direction":   "desc",
                    },
                    accept_json=True,
                )
                data = resp.json()
                batch = data.get("engagements")
                if not isinstance(batch, list):
                    self.fetch_error = "unexpected engagement listing shape"
                    logger.error("Bugcrowd engagement listing returned no array")
                    break

                if not batch:
                    break

                engagements.extend(batch)

                # On first page, calculate total pages from paginationMeta
                if total_pages is None:
                    meta = data.get("paginationMeta")
                    meta = meta if isinstance(meta, dict) else {}
                    try:
                        total_count = int(meta.get("totalCount") or 0)
                        limit = int(meta.get("limit") or len(batch))
                    except (TypeError, ValueError):
                        total_count, limit = 0, 0
                    if total_count and limit:
                        total_pages = math.ceil(total_count / limit)
                        logger.info(
                            "Bugcrowd: %d total engagements across %d pages (limit %d)",
                            total_count, total_pages, limit,
                        )

                logger.debug(
                    "Bugcrowd engagements page %d/%s: %d items",
                    page, total_pages or "?", len(batch),
                )

                if total_pages is not None and page >= total_pages:
                    break

                # Fallback safety: stop on short page if meta was missing
                if total_pages is None and len(batch) < limit:
                    break

                page += 1

            except Exception as exc:
                self.fetch_error = f"program listing page {page} failed: {exc}"
                logger.error("Bugcrowd: error fetching engagements page %d: %s", page, exc)
                break

        return engagements

    # ── Step 2+3: process one engagement ─────────────────────────────────────

    async def _process_engagement(self, eng: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Given an engagement dict from the list API:
          1. Extract briefUrl (e.g. /engagements/okta)
          2. Fetch the HTML page to get the changelog UUID
          3. Fetch the changelog JSON for the full scope
          4. Extract all wildcard domains
        """
        if not isinstance(eng, dict):
            return None
        brief_url = _clean_str(eng.get("briefUrl"))
        name = (
            _clean_str(eng.get("name"))
            or _clean_str(eng.get("tagline"))
            or brief_url.rstrip("/").split("/")[-1]
        )
        slug = brief_url.strip("/").split("/")[-1] if brief_url else ""

        if not brief_url:
            return None
        if not program_offers_bounty(eng):
            logger.debug("Bugcrowd [%s]: not bounty-eligible, skipping", slug)
            return None

        changelog_path = await self._extract_changelog_path(brief_url)
        scope_fetch_failed = not changelog_path
        brief_data = None
        if changelog_path:
            logger.debug("Bugcrowd [%s]: changelog path → %s", slug, changelog_path)
            brief_data = await self._fetch_changelog_json(changelog_path)
            scope_fetch_failed = brief_data is None
        else:
            logger.debug("Bugcrowd: no changelog path found for %s", brief_url)

        if brief_data:
            if _scope_groups(brief_data) is None:
                self.partial_fetch = True
                scope_fetch_failed = True
                logger.error(
                    "Bugcrowd [%s]: brief returned an unexpected scope shape", slug
                )
            domains, git_scope_urls = extract_scopes(brief_data, name)
        else:
            domains, git_scope_urls = [], []

        return {
            "name":               name,
            "external_id":        slug,
            "url":                f"{_BASE_URL}{brief_url}",
            "scopes":             domains,
            "git_scopes":         git_scope_urls,
            "scope_fetch_failed": scope_fetch_failed,
            "metadata": {
                "slug":             slug,
                "brief_url":        brief_url,
                "changelog_path":   changelog_path,
                "total_domains":    len(domains),
                "git_scopes_found": len(git_scope_urls),
            },
        }

    async def _extract_changelog_path(self, brief_url: str) -> Optional[str]:
        """
        GET /engagements/<slug> (HTML) and extract the changelog UUID path.

        The page embeds JSON with HTML-entity-encoded quotes, e.g.:
          getBriefVersionDocument&quot;:&quot;/engagements/okta/changelog/976d2960-...
        """
        try:
            resp = await self._get(brief_url, accept_json=False)
            if resp.status_code != 200:
                self.partial_fetch = True
                logger.debug(
                    "Bugcrowd: brief page %s returned HTTP %d", brief_url, resp.status_code
                )
                return None

            match = _CHANGELOG_RE.search(resp.text)
            if not match:
                self.partial_fetch = True
                logger.debug("Bugcrowd: changelog path not found in %s", brief_url)
                return None

            return unescape(match.group(1))

        except Exception as exc:
            self.partial_fetch = True
            logger.error("Bugcrowd: error fetching brief HTML %s: %s", brief_url, exc)
            return None

    async def _fetch_changelog_json(self, changelog_path: str) -> Optional[Dict[str, Any]]:
        """
        GET /engagements/<slug>/changelog/<uuid>.json

        The response wraps the actual brief inside `presentedChangelog`.
        We unwrap that layer before returning.
        """
        json_path = changelog_path if changelog_path.endswith(".json") else f"{changelog_path}.json"
        try:
            resp = await self._get(json_path, accept_json=True)
            if resp.status_code != 200:
                self.partial_fetch = True
                logger.debug(
                    "Bugcrowd: changelog JSON %s returned HTTP %d",
                    json_path, resp.status_code,
                )
                return None

            outer = resp.json()
            brief = outer.get("data") or outer
            logger.debug(
                "Bugcrowd: unwrapped brief keys: %s",
                list(brief.keys()) if isinstance(brief, dict) else type(brief),
            )
            return brief

        except Exception as exc:
            self.partial_fetch = True
            logger.error("Bugcrowd: error fetching changelog JSON %s: %s", json_path, exc)
            return None

    # ── HTTP helper ───────────────────────────────────────────────────────────

    async def _get(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        accept_json: bool = True,
    ) -> httpx.Response:
        """Rate-limited GET with exponential backoff and 429 handling."""
        elapsed = asyncio.get_event_loop().time() - self._last_request_time
        if elapsed < self._rate_limit_delay:
            await asyncio.sleep(self._rate_limit_delay - elapsed)

        headers = {}
        if accept_json:
            headers["Accept"] = "application/json"

        max_retries = 3
        for attempt in range(max_retries):
            try:
                self._last_request_time = asyncio.get_event_loop().time()
                resp = await self.client.get(path, params=params, headers=headers)

                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", 60))
                    logger.warning(
                        "Bugcrowd rate limited — retrying after %ds", retry_after
                    )
                    await asyncio.sleep(retry_after)
                    continue

                if resp.status_code == 401:
                    logger.error(
                        "Bugcrowd: 401 Unauthorized — BC_SESSION cookie is expired or invalid"
                    )
                    raise httpx.HTTPStatusError(
                        "401 Unauthorized — refresh BC_SESSION",
                        request=resp.request,
                        response=resp,
                    )

                resp.raise_for_status()
                return resp

            except httpx.HTTPStatusError:
                raise
            except httpx.HTTPError as exc:
                if attempt < max_retries - 1:
                    wait = 2 ** attempt
                    logger.warning(
                        "Bugcrowd request failed (attempt %d/%d): %s — retrying in %ds",
                        attempt + 1, max_retries, exc, wait,
                    )
                    await asyncio.sleep(wait)
                else:
                    raise

        raise httpx.HTTPError("Bugcrowd request failed after all retries")

    async def close(self) -> None:
        await self.client.aclose()