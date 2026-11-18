"""
YesWeHack platform integration using the official API.

Only programs that offer bounties are imported. Scope items are filtered by
their scope_type taxonomy so mobile, API/GraphQL, source-code and hardware
assets never become subdomain scopes.
"""

import asyncio
from typing import List, Optional, Dict, Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import logger
from app.core.config import settings
from app.db.db_models import Program, ProgramPlatform
from app.programs.base import PlatformBase
from app.programs.bounty_utils import (
    as_optional_bool,
    bounty_decision,
    positive_money,
)
from app.programs.platforms._git_scope_mixin import extract_git_and_domain_scopes


# YesWeHack /programs/{slug}/scopes returns a scope_type taxonomy. Only
# web/domain types become subdomain scopes; mobile apps, API/GraphQL assets,
# source code, hardware, IP/CIDR and other asset types do not.
_DOMAIN_SCOPE_TYPES = frozenset({
    "web-application", "web application", "website", "url", "domain", "wildcard",
})
_NON_DOMAIN_SCOPE_TYPES = frozenset({
    "mobile-application", "mobile application", "mobile-application-android",
    "mobile-application-ios", "mobile_application_android",
    "mobile_application_ios", "android", "ios", "application", "executable",
    "source-code", "source code", "source_code", "repository", "hardware",
    "iot", "smart-contract", "smart contract", "smart_contract", "ip-address",
    "ip address", "ip_address", "cidr", "network", "api", "graphql",
    "testcase", "test case", "ai-model", "ai model",
})


def program_offers_bounty(item: Dict[str, Any]) -> bool:
    """Conservative bounty check for one YesWeHack program list item.

    YesWeHack exposes ``bounty`` on the program list and a reward range as
    ``bounty_reward_min``/``bounty_reward_max``. Some responses use the older
    ``rewards`` field instead, so it is accepted as an equivalent signal.
    """
    explicit = None
    for key in ("bounty", "offers_bounties"):
        if key in item:
            explicit = as_optional_bool(item.get(key))
            break
    if explicit is None and "rewards" in item:
        explicit = as_optional_bool(item.get("rewards"))

    rewards = item.get("rewards")
    rewards_present = isinstance(rewards, (dict, list)) and bool(rewards)
    signals = (
        positive_money(item.get("bounty_reward_max")),
        positive_money(item.get("bounty_reward_min")),
        positive_money(rewards),
        rewards_present,
    )
    return bounty_decision(
        platform="YesWeHack",
        program=str(item.get("slug") or item.get("title") or ""),
        explicit=explicit,
        signals=signals,
    )


def scope_type_is_domain(scope_type: object) -> Optional[bool]:
    """Return True for domain-bearing types, False for known non-domain ones.

    None means the type is missing or unknown; the caller then keeps the value
    only if domain extraction can find a host in it.
    """
    if not isinstance(scope_type, str):
        return None
    normalized = scope_type.strip().lower()
    if not normalized:
        return None
    if normalized in _DOMAIN_SCOPE_TYPES:
        return True
    if normalized in _NON_DOMAIN_SCOPE_TYPES:
        return False
    return None


def extract_scopes(
    raw_scopes: List[Dict[str, Any]],
    program_name: str,
) -> tuple[List[str], List[str]]:
    """Filter YesWeHack scope items into domain and git scopes."""
    raw_values: List[str] = []

    for item in raw_scopes:
        if not isinstance(item, dict):
            continue

        in_scope = item.get("in_scope", item.get("inScope", True))
        if in_scope is False:
            logger.debug(
                "YWH [%s]: skipping out-of-scope entry: %s",
                program_name, item.get("scope", ""),
            )
            continue
        if item.get("is_oos") is True or item.get("out_of_scope") is True:
            continue

        raw_value = (
            item.get("scope")
            or item.get("endpoint")
            or item.get("target")
            or ""
        )
        if not isinstance(raw_value, str) or not raw_value.strip():
            continue

        type_signal = scope_type_is_domain(
            item.get("scope_type") or item.get("type")
        )
        if type_signal is False:
            logger.debug(
                "YWH [%s]: skipping non-domain scope type %s: %s",
                program_name, item.get("scope_type"), raw_value,
            )
            continue
        if type_signal is None:
            logger.debug(
                "YWH [%s]: unknown scope type %r — keeping only a host-shaped "
                "value: %s",
                program_name, item.get("scope_type"), raw_value,
            )

        raw_values.append(raw_value.strip())

    return extract_git_and_domain_scopes(raw_values, program_name)


class YesWeHackPlatform(PlatformBase):
    """YesWeHack platform integration using official API."""

    platform = ProgramPlatform.YESWEHACK

    def __init__(self):
        self.base_url = "https://api.yeswehack.com"
        self._token   = settings.YWH_TOKEN

        if not self._token:
            logger.warning(
                "YWH_TOKEN must be set in .env for YesWeHack API authentication"
            )

        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=30.0,
            headers={
                "Accept":     "application/json",
                "User-Agent": "STOscanner/1.0",
            },
        )
        if self._token:
            self.client.headers["Authorization"] = f"Bearer {self._token}"

        # ~1 req/s
        self._rate_limit_delay  = 1.1
        self._last_request_time = 0.0

    async def authenticate(self, cookie_file: Optional[str] = None) -> Dict[str, Any]:
        """Verify API token with a minimal request."""
        if not self._token:
            return {"authenticated": False, "error": "Missing YWH_TOKEN in .env"}
        try:
            resp = await self._make_request(
                "GET", "/programs", params={"page": 1, "filter[disabled]": 0}
            )
            return {"authenticated": resp.status_code == 200, "status": resp.status_code}
        except Exception as e:
            return {"authenticated": False, "error": str(e)}

    async def fetch_programs(
        self,
        session: AsyncSession,
        cookie_file: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Page through all public bounty programs and extract wildcard domains.

        Returns list of dicts with keys:
          name, external_id, url, scopes (List[str]), metadata
        """
        if not self._token:
            self.fetch_error = "YWH_TOKEN not configured"
            logger.error("YWH_TOKEN not set — cannot fetch YesWeHack programs")
            return []

        logger.info("Fetching YesWeHack programs...")
        raw_programs = await self._fetch_all_programs()
        if self.fetch_error:
            return []

        results = []
        total_wildcards = 0
        total_git_scopes = 0

        for item in raw_programs:
            try:
                info = await self._process_program(item)
                if info:
                    results.append(info)
                    total_wildcards  += len(info["scopes"])
                    total_git_scopes += len(info.get("git_scopes", []))
            except Exception as e:
                logger.error(
                    "Error processing YWH program %s: %s",
                    item.get("slug", "unknown"), e,
                )

        logger.info(
            "Fetched %d YWH programs with %d wildcard scopes, %d git scopes",
            len(results), total_wildcards, total_git_scopes,
        )
        return results

    async def _fetch_all_programs(self) -> List[Dict[str, Any]]:
        """Page through /programs and return all items."""
        programs    = []
        current     = 1
        total_pages = 1

        while current <= total_pages:
            logger.info("Fetching YWH programs page %d/%d...", current, total_pages)
            try:
                resp = await self._make_request(
                    "GET",
                    "/programs",
                    params={
                        "filter[rewardMin]": 1,
                        "filter[disabled]":  0,
                        "filter[type][]":    "bug-bounty",
                        "page":              current,
                    },
                )
                data = resp.json()
                pagination = data.get("pagination")
                pagination = pagination if isinstance(pagination, dict) else {}
                try:
                    total_pages = int(pagination.get("nb_pages", 1) or 1)
                except (TypeError, ValueError):
                    total_pages = 1
                items = data.get("items")
                if not isinstance(items, list):
                    self.fetch_error = "unexpected program listing shape"
                    logger.error("YWH program listing returned no items array")
                    break
                programs.extend(items)
                current += 1
            except Exception as e:
                self.fetch_error = f"program listing page {current} failed: {e}"
                logger.error("Error fetching YWH page %d: %s", current, e)
                break

        logger.info("Fetched %d programs from YesWeHack API", len(programs))
        return programs

    async def _process_program(self, item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Fetch scopes for one program, extract all wildcard domains."""
        if not isinstance(item, dict):
            return None
        slug = item.get("slug")
        name = item.get("title") or slug

        if not slug:
            return None
        if not program_offers_bounty(item):
            logger.debug("YWH [%s]: not bounty-eligible, skipping", slug)
            return None

        raw_scopes = await self._fetch_program_scopes(slug)
        scope_fetch_failed = raw_scopes is None
        raw_scopes = raw_scopes or []

        domains, git_scope_urls = extract_scopes(raw_scopes, name)

        if git_scope_urls:
            logger.debug(
                "YWH [%s]: %d git scope(s): %s",
                slug, len(git_scope_urls), git_scope_urls,
            )

        return {
            "name":               name,
            "external_id":        slug,
            "url":                f"https://yeswehack.com/programs/{slug}",
            "scopes":             domains,
            "git_scopes":         git_scope_urls,
            "scope_fetch_failed": scope_fetch_failed,
            "metadata": {
                "slug":                    slug,
                "total_scopes":            len(raw_scopes),
                "bounty_eligible_domains": len(domains),
                "git_scopes_found":        len(git_scope_urls),
            },
        }

    async def _fetch_program_scopes(
        self,
        slug: str,
    ) -> Optional[List[Dict[str, Any]]]:
        """GET /programs/{slug}/scopes and return raw scope items.

        None signals a failed request; [] is a program with no scopes.
        """
        try:
            resp = await self._make_request("GET", f"/programs/{slug}/scopes")
            data = resp.json()
            items = data.get("items")
            if not isinstance(items, list):
                self.partial_fetch = True
                logger.error(
                    "YWH scopes for %s returned an unexpected shape", slug
                )
                return None
            return items
        except Exception as e:
            self.partial_fetch = True
            logger.error("Failed to fetch YWH scopes for %s: %s", slug, e)
            return None

    async def _make_request(self, method: str, path: str, **kwargs) -> httpx.Response:
        """Rate-limited request with exponential backoff and 429 handling."""
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
                    logger.warning("YWH rate limited — retrying after %ds", retry_after)
                    await asyncio.sleep(retry_after)
                    continue

                resp.raise_for_status()
                return resp

            except httpx.HTTPError as e:
                if attempt < max_retries - 1:
                    wait = 2 ** attempt
                    logger.warning(
                        "YWH request failed (attempt %d/%d): %s — retrying in %ds",
                        attempt + 1, max_retries, e, wait,
                    )
                    await asyncio.sleep(wait)
                else:
                    raise

        raise httpx.HTTPError("YWH request failed after all retries")

    async def close(self):
        await self.client.aclose()