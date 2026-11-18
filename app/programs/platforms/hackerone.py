"""
HackerOne platform integration using official API v1.

Only programs that offer bounties are imported. URL/DOMAIN/WILDCARD assets
become subdomain scopes; SOURCE_CODE assets feed the git scanner and are never
stored as domains.
"""

import asyncio
import base64
from typing import List, Optional, Dict, Any
from urllib.parse import urljoin

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import logger
from app.core.config import settings
from app.db.db_models import Program, ProgramPlatform, Scope
from app.programs.base import PlatformBase
from app.programs.bounty_utils import as_optional_bool, bounty_decision
from app.programs.git_scope_utils import is_git_scope
from app.programs.platforms._git_scope_mixin import extract_git_and_domain_scopes


# asset_type values that describe a web-addressable host. HackerOne's taxonomy
# (docs: Asset Types) also has CIDR/IP, SOURCE_CODE, mobile store IDs, hardware,
# executables, smart contracts and OTHER; those never become subdomain scopes.
_DOMAIN_ASSET_TYPES = frozenset({"URL", "DOMAIN", "WILDCARD"})
_GIT_ASSET_TYPES = frozenset({"SOURCE_CODE"})


def program_offers_bounty(
    attrs: Dict[str, Any],
    scopes: List[Dict[str, Any]],
) -> bool:
    """Conservative program-level bounty check for HackerOne API v1."""
    explicit = as_optional_bool(attrs.get("offers_bounties"))
    # A structured scope flagged eligible_for_bounty is a second positive
    # signal if the program attribute disappears from the response.
    scope_signal = False
    for scope in scopes:
        if not isinstance(scope, dict):
            continue
        scope_attrs = scope.get("attributes")
        if not isinstance(scope_attrs, dict):
            continue
        if as_optional_bool(scope_attrs.get("eligible_for_bounty")) is True:
            scope_signal = True
            break
    return bounty_decision(
        platform="HackerOne",
        program=str(attrs.get("handle") or attrs.get("name") or ""),
        explicit=explicit,
        signals=(scope_signal,),
    )


def scope_is_bounty_eligible(attrs: Dict[str, Any], program_offers: bool) -> bool:
    """Decide whether one structured scope is bounty-eligible.

    HackerOne normally sends eligible_for_bounty explicitly. When it is absent,
    keep the scope only if the program itself is bounty-eligible and the scope
    is not explicitly excluded from submissions.
    """
    explicit = as_optional_bool(attrs.get("eligible_for_bounty"))
    submission = as_optional_bool(attrs.get("eligible_for_submission"))

    # An asset the company does not accept reports for is never a scan scope,
    # even when it is marked eligible for bounty.
    if explicit is False or submission is False:
        return False
    if explicit is True:
        return True

    logger.debug(
        "H1: eligible_for_bounty missing on asset %s — keeping only with a "
        "bounty-eligible program and submissions not disabled",
        attrs.get("asset_identifier", "<unknown>"),
    )
    return bool(program_offers) and submission is not False


def extract_scopes(
    raw_scopes: List[Dict[str, Any]],
    program_name: str,
    program_offers: bool,
) -> tuple[List[str], List[str]]:
    """Filter HackerOne structured scopes into domains and git scopes.

    Source-code assets stay on the git-scan path and are never added as domain
    scopes. Every non-domain asset type is excluded here, before
    domain_utils.extract_domains() can turn an identifier into a hostname.
    """
    raw_values: List[str] = []

    for scope in raw_scopes:
        if not isinstance(scope, dict):
            continue
        attrs = scope.get("attributes")
        if not isinstance(attrs, dict):
            continue
        if not scope_is_bounty_eligible(attrs, program_offers):
            continue

        asset_type = str(attrs.get("asset_type") or "").strip().upper()
        identifier = str(attrs.get("asset_identifier") or "").strip()
        if not identifier:
            continue

        if asset_type in _GIT_ASSET_TYPES:
            if is_git_scope(identifier):
                raw_values.append(identifier)
            else:
                logger.debug(
                    "H1 [%s]: SOURCE_CODE scope is not a git URL, skipping: %s",
                    program_name, identifier,
                )
            continue

        if asset_type not in _DOMAIN_ASSET_TYPES:
            logger.debug(
                "H1 [%s]: skipping non-domain asset type %s: %s",
                program_name, asset_type or "<missing>", identifier,
            )
            continue

        raw_values.append(identifier)

    domains, git_scope_urls = extract_git_and_domain_scopes(raw_values, program_name)
    return domains, git_scope_urls


class HackerOnePlatform(PlatformBase):
    """HackerOne platform integration using official API v1."""

    platform = ProgramPlatform.HACKERONE

    def __init__(self):
        self.base_url = "https://api.hackerone.com"
        self._username  = settings.H1_USERNAME
        self._api_token = settings.H1_API_TOKEN

        if not self._username or not self._api_token:
            logger.warning(
                "H1_USERNAME and H1_API_TOKEN must be set in .env "
                "for HackerOne API authentication"
            )

        auth_header = None
        if self._username and self._api_token:
            encoded = base64.b64encode(
                f"{self._username}:{self._api_token}".encode()
            ).decode()
            auth_header = f"Basic {encoded}"

        self.client = httpx.AsyncClient(
            timeout=30.0,
            headers={
                "Accept": "application/json",
                "User-Agent": "STOscanner/1.0",
            },
        )
        if auth_header:
            self.client.headers["Authorization"] = auth_header

        # ~1 req/s — well within HackerOne's 60 req/min limit
        self._rate_limit_delay = 1.1
        self._last_request_time = 0.0

    async def authenticate(self, cookie_file: Optional[str] = None) -> Dict[str, Any]:
        """Verify credentials with a minimal API call."""
        if not self._username or not self._api_token:
            return {
                "authenticated": False,
                "error": "Missing H1_USERNAME or H1_API_TOKEN in .env",
            }
        try:
            resp = await self._make_request(
                "GET", "/v1/hackers/programs", params={"page[size]": 1}
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
        Fetch all public bounty programs and extract wildcard domains.

        Returns list of dicts with keys:
          name, external_id, url, scopes (List[str]), metadata
        """
        if not self._username or not self._api_token:
            self.fetch_error = "H1_USERNAME/H1_API_TOKEN not configured"
            logger.error("H1 credentials not set — cannot fetch programs")
            return []

        logger.info("Fetching HackerOne programs...")
        raw_programs = await self._fetch_all_programs()
        if self.fetch_error:
            return []

        results = []
        total_wildcards = 0
        total_git_scopes = 0

        for prog in raw_programs:
            try:
                info = await self._process_program(prog)
                if info:
                    results.append(info)
                    total_wildcards += len(info["scopes"])
                    total_git_scopes += len(info.get("git_scopes", []))
            except Exception as e:
                logger.error(
                    "Error processing H1 program %s: %s",
                    prog.get("attributes", {}).get("handle", "unknown"),
                    e,
                )

        logger.info(
            "Fetched %d H1 programs with %d total wildcard scopes, %d git scopes",
            len(results), total_wildcards, total_git_scopes,
        )
        return results

    async def _fetch_all_programs(self) -> List[Dict[str, Any]]:
        """Page through /v1/hackers/programs and return all items."""
        programs = []
        page = 1

        while True:
            try:
                resp = await self._make_request(
                    "GET",
                    "/v1/hackers/programs",
                    params={
                        "page[size]":              100,
                        "page[number]":            page,
                        "filter[state]":           "public",
                        "filter[offers_bounties]": "true",
                    },
                )
                data = resp.json()
                batch = data.get("data")
                if not isinstance(batch, list):
                    self.fetch_error = "unexpected program listing shape"
                    logger.error("H1 program listing returned no data array")
                    break
                programs.extend(batch)

                if not data.get("links", {}).get("next"):
                    break
                page += 1

            except Exception as e:
                self.fetch_error = f"program listing page {page} failed: {e}"
                logger.error("Error fetching H1 programs page %d: %s", page, e)
                break

        logger.info("Fetched %d programs from HackerOne API", len(programs))
        return programs

    async def _process_program(self, prog: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Fetch scopes for one program, extract domain scopes and git scopes."""
        attrs = prog.get("attributes") if isinstance(prog, dict) else None
        attrs = attrs if isinstance(attrs, dict) else {}
        handle = attrs.get("handle")
        name   = attrs.get("name") or handle

        if not handle:
            return None

        # Skip an explicitly unpaid program before spending a scope request.
        if as_optional_bool(attrs.get("offers_bounties")) is False:
            return None

        raw_scopes = await self._fetch_structured_scopes(handle)
        scope_fetch_failed = raw_scopes is None
        raw_scopes = raw_scopes or []

        if not program_offers_bounty(attrs, raw_scopes):
            logger.debug("H1 [%s]: not bounty-eligible, skipping", handle)
            return None

        domains, git_scope_urls = extract_scopes(
            raw_scopes, name, program_offers=True
        )

        if git_scope_urls:
            logger.debug(
                "H1 [%s]: %d git scope(s) found: %s",
                handle, len(git_scope_urls), git_scope_urls,
            )

        return {
            "name":               name,
            "external_id":        handle,
            "url":                f"https://hackerone.com/{handle}",
            "scopes":             domains,
            "git_scopes":         git_scope_urls,
            "scope_fetch_failed": scope_fetch_failed,
            "metadata": {
                "handle":                  handle,
                "program_id":              prog.get("id"),
                "state":                   attrs.get("state"),
                "offers_bounties":         attrs.get("offers_bounties"),
                "total_scopes":            len(raw_scopes),
                "bounty_eligible_domains": len(domains),
                "git_scopes_found":        len(git_scope_urls),
            },
        }

    async def _fetch_structured_scopes(
        self,
        handle: str,
    ) -> Optional[List[Dict[str, Any]]]:
        """GET all pages of /v1/hackers/programs/{handle}/structured_scopes.

        Returns None when any page fails so the caller can keep the previously
        stored scopes instead of reconciling them as removed.
        """
        items: List[Dict[str, Any]] = []
        page = 1

        while True:
            try:
                resp = await self._make_request(
                    "GET",
                    f"/v1/hackers/programs/{handle}/structured_scopes",
                    params={"page[size]": 100, "page[number]": page},
                )
                data = resp.json()
                batch = data.get("data")
                if not isinstance(batch, list):
                    self.partial_fetch = True
                    logger.error(
                        "H1 structured scopes for %s returned no data array", handle
                    )
                    return None
                items.extend(batch)
                links = data.get("links")
                if not batch or not isinstance(links, dict) or not links.get("next"):
                    break
                page += 1
            except Exception as e:
                self.partial_fetch = True
                logger.error(
                    "Error fetching H1 scopes for %s (page %d): %s",
                    handle, page, e,
                )
                return None

        return items

    async def _make_request(self, method: str, path: str, **kwargs) -> httpx.Response:
        """Rate-limited request with exponential backoff on failure and 429 handling."""
        url = urljoin(self.base_url, path)

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
                    logger.warning("H1 rate limited — retrying after %ds", retry_after)
                    await asyncio.sleep(retry_after)
                    continue

                resp.raise_for_status()
                return resp

            except httpx.HTTPError as e:
                if attempt < max_retries - 1:
                    wait = 2 ** attempt
                    logger.warning(
                        "H1 request failed (attempt %d/%d): %s — retrying in %ds",
                        attempt + 1, max_retries, e, wait,
                    )
                    await asyncio.sleep(wait)
                else:
                    raise

        raise httpx.HTTPError("H1 request failed after all retries")

    async def close(self):
        await self.client.aclose()