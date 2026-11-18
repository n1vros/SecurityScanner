"""
Intigriti platform integration using the official Researcher API v1.

Only open Bug Bounty programs that offer a bounty are imported. Domain entries
are filtered by their asset-type value and out-of-scope tier/flag so only
URL/domain/wildcard assets become subdomain scopes.

API base: https://api.intigriti.com/external/researcher
Auth:     Bearer token (INTI_TOKEN in .env)

status.id == 3  -> Open
type.id   == 1  -> Bug Bounty
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


# Confirmed from API: status.id == 3 is "Open", type.id == 1 is "Bug Bounty"
_STATUS_OPEN     = 3
_TYPE_BUG_BOUNTY = 1

# DomainViewModel.type is an EnumerationViewModel; match its human-readable
# value because the numeric IDs are not part of the published OpenAPI schema.
# Only web/domain types become subdomain scopes; mobile apps, API/GraphQL
# assets, hardware, source code, CIDR and other types are excluded.
_DOMAIN_TYPE_VALUES = frozenset({
    "url", "domain", "wildcard", "website", "web-application",
    "web application", "web app",
})
_NON_DOMAIN_TYPE_VALUES = frozenset({
    "android", "ios", "mobile", "mobile-application", "mobile application",
    "hardware", "iot", "other", "source-code", "source code",
    "executable", "binary", "smart-contract", "smart contract", "api",
    "graphql", "testcase", "test case", "ai-model", "ai model",
    "ip-address", "ip address", "cidr", "network",
})
_OOS_TYPE_VALUES = frozenset({
    "exclude", "excluded", "out-of-scope", "out of scope", "oos",
})
# Intigriti tier enumeration: normal tiers are in scope, tier 5 is out of scope.
_OOS_TIER_ID = 5


def _money_field(item: Dict[str, Any], key: str) -> object:
    value = item.get(key)
    if isinstance(value, dict):
        return value.get("value")
    return value


def _dict(value: object) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def program_offers_bounty(item: Dict[str, Any]) -> bool:
    """Conservative bounty check for one Intigriti program record.

    The Researcher API exposes ``minBounty``/``maxBounty`` money objects. Some
    responses also carry ``bounty``/``rewards``; those flags win when present.
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
    money_keys = ("minBounty", "maxBounty")
    has_money_field = any(key in item for key in money_keys)
    type_is_bug_bounty = _dict(item.get("type")).get("id") == _TYPE_BUG_BOUNTY

    signals = (
        positive_money(_money_field(item, "maxBounty")),
        positive_money(_money_field(item, "minBounty")),
        positive_money(rewards),
        rewards_present,
        # If the API omits the money objects entirely, its own Bug Bounty
        # classification is the only remaining positive signal.
        type_is_bug_bounty and not has_money_field,
    )
    return bounty_decision(
        platform="Intigriti",
        program=str(item.get("handle") or item.get("name") or item.get("id") or ""),
        explicit=explicit,
        signals=signals,
    )


def scope_type_is_domain(scope_type: object) -> Optional[bool]:
    """Map an Intigriti asset type value to domain / non-domain / unknown."""
    if not isinstance(scope_type, str):
        return None
    normalized = scope_type.strip().lower().replace("_", "-")
    if not normalized:
        return None
    if normalized in _DOMAIN_TYPE_VALUES:
        return True
    if normalized in _NON_DOMAIN_TYPE_VALUES:
        return False
    return None


def extract_scopes(
    domain_entries: List[Dict[str, Any]],
    program_name: str,
) -> tuple[List[str], List[str]]:
    """Filter Intigriti domains.content[] into domain and git scopes."""
    raw_values: List[str] = []

    for entry in domain_entries:
        if not isinstance(entry, dict):
            continue

        if entry.get("outOfScope") is True:
            logger.debug(
                "Intigriti [%s]: skipping outOfScope=True domain: %s",
                program_name, entry.get("endpoint", ""),
            )
            continue

        type_info = entry.get("type") or {}
        type_value = type_info.get("value") if isinstance(type_info, dict) else None
        type_normalized = (
            type_value.strip().lower().replace("_", "-")
            if isinstance(type_value, str)
            else ""
        )
        if type_normalized in _OOS_TYPE_VALUES:
            logger.debug(
                "Intigriti [%s]: skipping out-of-scope asset type %r: %s",
                program_name, type_value, entry.get("endpoint", ""),
            )
            continue

        tier_info = entry.get("tier") or {}
        tier_value = tier_info.get("value") if isinstance(tier_info, dict) else None
        tier_normalized = (
            tier_value.strip().lower().replace("_", "-")
            if isinstance(tier_value, str)
            else ""
        )
        tier_id = tier_info.get("id") if isinstance(tier_info, dict) else None
        if tier_normalized in _OOS_TYPE_VALUES or (
            not tier_normalized and tier_id == _OOS_TIER_ID
        ):
            logger.debug(
                "Intigriti [%s]: skipping out-of-scope tier: %s",
                program_name, entry.get("endpoint", ""),
            )
            continue

        type_signal = scope_type_is_domain(type_value)
        if type_signal is False:
            logger.debug(
                "Intigriti [%s]: skipping non-domain asset type %r: %s",
                program_name, type_value, entry.get("endpoint", ""),
            )
            continue
        if type_signal is None:
            logger.debug(
                "Intigriti [%s]: unknown asset type %r — keeping only a "
                "host-shaped value: %s",
                program_name, type_value, entry.get("endpoint", ""),
            )

        endpoint = entry.get("endpoint")
        if isinstance(endpoint, str) and endpoint.strip():
            raw_values.append(endpoint.strip())

    return extract_git_and_domain_scopes(raw_values, program_name)


class IntigritiPlatform(PlatformBase):
    """Intigriti platform integration using official Researcher API v1."""

    platform = ProgramPlatform.INTIGRITI

    def __init__(self):
        self.base_url = "https://api.intigriti.com/external/researcher/v1"
        self._token   = settings.INTI_TOKEN

        if not self._token:
            logger.warning(
                "INTI_TOKEN must be set in .env for Intigriti API authentication"
            )

        self.client = httpx.AsyncClient(
            timeout=30.0,
            headers={
                "Accept":     "application/json",
                "User-Agent": "STOscanner/1.0",
            },
        )
        if self._token:
            self.client.headers["Authorization"] = f"Bearer {self._token}"

        # ~1 req/s -- conservative to stay within rate limits
        self._rate_limit_delay  = 1.1
        self._last_request_time = 0.0

    async def authenticate(self, cookie_file: Optional[str] = None) -> Dict[str, Any]:
        """Verify API token with a minimal request."""
        if not self._token:
            return {"authenticated": False, "error": "Missing INTI_TOKEN in .env"}
        try:
            resp = await self._make_request(
                "GET", "/programs", params={"limit": 1, "offset": 0}
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
        Page through all open bug-bounty programs and extract wildcard domains.

        Returns list of dicts with keys:
          name, external_id, url, scopes (List[str]), metadata
        """
        if not self._token:
            self.fetch_error = "INTI_TOKEN not configured"
            logger.error("INTI_TOKEN not set -- cannot fetch Intigriti programs")
            return []

        logger.info("Fetching Intigriti bug bounty programs...")
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
                    "Error processing Intigriti program %s (%s): %s",
                    item.get("name", "unknown"), item.get("id", ""), e,
                )

        logger.info(
            "Fetched %d Intigriti bug bounty programs with %d wildcard scopes, %d git scopes",
            len(results), total_wildcards, total_git_scopes,
        )
        return results

    async def _fetch_all_programs(self) -> List[Dict[str, Any]]:
        """
        Page through GET /v1/programs and return all records.

        Filters server-side to Open (statusId=3) Bug Bounty (typeId=1) programs.
        Pagination via limit/offset; envelope: { maxCount, records[] }.
        """
        programs = []
        limit    = 100
        offset   = 0

        while True:
            logger.info(
                "Fetching Intigriti programs (offset=%d, limit=%d)...", offset, limit
            )
            try:
                resp = await self._make_request(
                    "GET",
                    "/programs",
                    params={
                        "statusId": _STATUS_OPEN,
                        "typeId":   _TYPE_BUG_BOUNTY,
                        "limit":    limit,
                        "offset":   offset,
                    },
                )
                data = resp.json()
                records = data.get("records")
                if not isinstance(records, list):
                    self.fetch_error = "unexpected program listing shape"
                    logger.error("Intigriti program listing returned no records array")
                    break
                try:
                    max_count = int(data.get("maxCount", 0) or 0)
                except (TypeError, ValueError):
                    max_count = 0

                programs.extend(records)
                offset += len(records)

                if offset >= max_count or not records:
                    break

            except Exception as e:
                self.fetch_error = f"program listing offset {offset} failed: {e}"
                logger.error(
                    "Error fetching Intigriti programs at offset %d: %s", offset, e
                )
                break

        logger.info("Fetched %d total program records from Intigriti API", len(programs))
        return programs

    async def _process_program(self, item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Validate bounty eligibility, fetch full program detail, and extract
        all wildcard domains.
        """
        if not isinstance(item, dict):
            return None
        program_id = item.get("id")
        name       = item.get("name") or item.get("handle") or str(program_id)

        if not program_id:
            return None

        # Guard 1: must be Bug Bounty type
        type_id = _dict(item.get("type")).get("id")
        if type_id != _TYPE_BUG_BOUNTY:
            return None

        # Guard 2: must offer a bounty, with a conservative fallback when the
        # money fields are missing from this response shape.
        if not program_offers_bounty(item):
            logger.debug("Intigriti [%s]: not bounty-eligible, skipping", name)
            return None

        max_bounty = _money_field(item, "maxBounty")

        detail = await self._fetch_program_detail(program_id)
        scope_fetch_failed = detail is None
        detail = detail or {}

        # domains.content[] is the in-scope DomainViewModel list. Out-of-scope
        # entries can arrive either with outOfScope=True, an OOS type value, or
        # an out-of-scope tier; all three are rejected by extract_scopes().
        # A missing/non-list content array is treated as a failed scope fetch,
        # not as "the program has no scopes", so a schema change cannot
        # deactivate every stored scope.
        domain_entries = None
        if not scope_fetch_failed:
            domains_obj = detail.get("domains")
            if isinstance(domains_obj, dict):
                domain_entries = domains_obj.get("content")
            if not isinstance(domain_entries, list):
                self.partial_fetch = True
                scope_fetch_failed = True
                domain_entries = []
                logger.error(
                    "Intigriti detail for %s returned an unexpected domains shape",
                    program_id,
                )

        domains, git_scope_urls = extract_scopes(domain_entries, name)

        if git_scope_urls:
            logger.debug(
                "Intigriti [%s]: %d git scope(s): %s",
                name, len(git_scope_urls), git_scope_urls,
            )

        url = (
            _dict(item.get("webLinks")).get("detail")
            or f"https://app.intigriti.com/programs/{item.get('handle')}"
        )

        return {
            "name":               name,
            "external_id":        program_id,
            "url":                url,
            "scopes":             domains,
            "git_scopes":         git_scope_urls,
            "scope_fetch_failed": scope_fetch_failed,
            "metadata": {
                "program_id":              program_id,
                "handle":                  item.get("handle"),
                "max_bounty":              max_bounty,
                "total_domains":           len(domain_entries),
                "bounty_eligible_domains": len(domains),
                "git_scopes_found":        len(git_scope_urls),
            },
        }

    async def _fetch_program_detail(self, program_id: str) -> Optional[Dict[str, Any]]:
        """GET /v1/programs/{programId}; None means the request failed."""
        try:
            resp = await self._make_request("GET", f"/programs/{program_id}")
            data = resp.json()
            return data if isinstance(data, dict) else None
        except Exception as e:
            self.partial_fetch = True
            logger.error(
                "Failed to fetch Intigriti detail for program %s: %s", program_id, e
            )
            return None

    async def _make_request(self, method: str, path: str, **kwargs) -> httpx.Response:
        """Rate-limited request with exponential backoff and 429 handling."""
        url = f"{self.base_url}{path}"

        elapsed = asyncio.get_event_loop().time() - self._last_request_time
        if elapsed < self._rate_limit_delay:
            await asyncio.sleep(self._rate_limit_delay - elapsed)

        max_retries = 3
        for attempt in range(max_retries):
            try:
                self._last_request_time = asyncio.get_event_loop().time()
                resp = await self.client.request(method, url, **kwargs)

                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", 60))
                    logger.warning(
                        "Intigriti rate limited -- retrying after %ds", retry_after
                    )
                    await asyncio.sleep(retry_after)
                    continue

                resp.raise_for_status()
                return resp

            except httpx.HTTPError as e:
                if attempt < max_retries - 1:
                    wait = 2 ** attempt
                    logger.warning(
                        "Intigriti request failed (attempt %d/%d): %s -- retrying in %ds",
                        attempt + 1, max_retries, e, wait,
                    )
                    await asyncio.sleep(wait)
                else:
                    raise

        raise httpx.HTTPError("Intigriti request failed after all retries")

    async def close(self):
        await self.client.aclose()