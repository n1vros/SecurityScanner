"""
app/takeover/providers/aws_apigateway.py

AWS API Gateway subdomain takeover — detection + POTENTIAL_LONG escalation.

Vulnerable pattern
------------------
  subdomain CNAME → <domain-id>.execute-api.<region>.amazonaws.com

  Typical signals:
    • d-XXXXXXXX.execute-api.<region>.amazonaws.com   — regional custom domain
    • <api-id>.execute-api.<region>.amazonaws.com     — direct REST/HTTP API endpoint

  The CNAME resolves but the endpoint returns HTTP 403
  {"message":"Forbidden"} (content-length: 23) — the canonical API Gateway
  fingerprint for an unclaimed or mapping-deleted custom domain.

Why auto-takeover is NOT possible
----------------------------------
  API Gateway custom domain execute-api hostnames (d-XXXXXXXX) are generated
  deterministically when a custom domain is registered.  They are:

    1. Tied to the AWS account that created the custom domain.
    2. Not reusable across accounts — creating search.dev.priceless.com as a
       custom domain in OUR account produces a DIFFERENT d-YYYYYYYY hostname.
    3. Not listed in a global namespace (unlike S3 bucket names) that another
       party can simply claim by re-registering.

  Therefore, even if the original custom domain is fully deleted from the
  victim's account, we cannot obtain the same execute-api hostname.  The
  victim's CNAME continues to point to the old hostname, not ours.

  → This checker confirms the finding is genuine and transitions the
    subdomain to POTENTIAL_LONG (manual exploitation / report required).

Verification strategy
---------------------
  Step 1 — Probe the execute-api target directly.
    HEAD/GET https://<cname>   →   403 + body == {"message":"Forbidden"}
    Confirms the infrastructure endpoint is still live.  NXDOMAIN on the
    execute-api host itself would mean the endpoint is truly gone.

  Step 2 (optional, requires AWS credentials) — API Gateway SDK check.
    Call apigateway.get_domain_name(domainName=subdomain_name) from our account.
      • NotFoundException   → domain not in our account.  Could be in the
                              victim's account (still owned) OR fully deleted
                              (endpoint infrastructure may lag).  Either way,
                              we cannot claim it. → POTENTIAL_LONG.
      • 200                 → domain already in OUR account (unexpected in a
                              bug-bounty context). → NOT_VULN.
      • Exception / timeout → inconclusive, fall through to POTENTIAL_LONG.

  If no AWS credentials are configured the SDK step is skipped and the
  result is NOT_IMPL; the caller (providers_evaluator._do_aws_apigateway)
  still transitions to POTENTIAL_LONG.

Required .env  (optional — checker degrades gracefully without them)
--------------------------------------------------------------------
  AWS_ACCESS_KEY_ID      — IAM key with apigateway:GET on *
  AWS_SECRET_ACCESS_KEY  — IAM secret
"""

import asyncio
import re
from typing import Optional, Tuple

import aiohttp

from app.core.config import settings
from app.core.logging import logger
from app.takeover.subdomain_hunter.providers.base import TakeoverResult, TakeoverStatus

# Matches both custom-domain regional endpoints (d-XXXX) and plain API IDs.
#   d-3rlc18orf1.execute-api.us-east-1.amazonaws.com
#   abc123def4.execute-api.eu-west-1.amazonaws.com
_APIGW_RE = re.compile(
    r"^([a-z0-9][a-z0-9\-]{0,62}[a-z0-9])"
    r"\.execute-api"
    r"\.([a-z]{2}-[a-z]+-\d+)"
    r"\.amazonaws\.com\.?$",
    re.IGNORECASE,
)

# Canonical API Gateway 403 fingerprint — returned when a custom domain
# exists at the infrastructure level but has no API mapping.
_APIGW_403_BODY     = b'{"message":"Forbidden"}'
_APIGW_403_BODY_LEN = len(_APIGW_403_BODY)   # 23 bytes

_DEFAULT_REGION = "us-east-1"
_HTTP_TIMEOUT   = 10  # seconds for direct endpoint probe


def extract_domain_id_and_region(cname: str) -> Tuple[Optional[str], str]:
    """
    Parse an API Gateway execute-api CNAME.

    Returns (domain_id, region).
    domain_id is None when the CNAME does not match the execute-api pattern.
    """
    cname = cname.lower().strip().rstrip(".")
    m = _APIGW_RE.match(cname)
    if not m:
        return None, _DEFAULT_REGION
    return m.group(1), m.group(2)


async def _probe_execute_api(cname: str) -> Tuple[bool, int, int]:
    """
    Probe the execute-api endpoint directly.

    Returns (is_apigw_403, status_code, content_length).
    is_apigw_403 = True  → 403 {"message":"Forbidden"} confirmed on execute-api host.
    is_apigw_403 = False → endpoint responded differently (or timed out).
    """
    url = f"https://{cname.rstrip('.')}/"
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=_HTTP_TIMEOUT),
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:
            async with session.get(
                url,
                allow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0 (compatible; STOscanner/1.0)"},
            ) as resp:
                body = await resp.read()
                status       = resp.status
                content_len  = len(body)
                is_apigw_403 = (
                    status == 403
                    and content_len == _APIGW_403_BODY_LEN
                    and body.strip() == _APIGW_403_BODY
                )
                return is_apigw_403, status, content_len
    except asyncio.TimeoutError:
        logger.debug("aws_apigateway: probe timeout for %s", cname)
        return False, 0, 0
    except Exception as exc:
        logger.debug("aws_apigateway: probe error for %s: %s", cname, exc)
        return False, 0, 0


class AWSAPIGatewayTakeoverChecker:
    """
    Verify AWS API Gateway subdomain takeover findings.

    Detection only — auto-takeover is architecturally impossible for API
    Gateway custom-domain execute-api hostnames (see module docstring).

    Returns NOT_IMPL in all cases; the caller (providers_evaluator) is
    responsible for transitioning the subdomain to POTENTIAL_LONG.
    """

    PROVIDER = "aws_apigateway"

    def __init__(self) -> None:
        self._key_id: Optional[str] = getattr(settings, "AWS_ACCESS_KEY_ID", None)
        self._secret: Optional[str] = getattr(settings, "AWS_SECRET_ACCESS_KEY", None)
        self._ready = bool(self._key_id and self._secret)
        if not self._ready:
            logger.info(
                "AWSAPIGatewayTakeoverChecker: no AWS credentials — "
                "SDK step will be skipped, HTTP probe still runs"
            )

    async def attempt(self, subdomain_name: str, cname: str) -> TakeoverResult:
        """
        Main entry point.  Always returns NOT_IMPL; populates evidence dict
        with probe results so the Discord embed is informative.
        """
        domain_id, region = extract_domain_id_and_region(cname)
        base_evidence = {
            "apigw_cname":     cname,
            "apigw_domain_id": domain_id,
            "apigw_region":    region,
        }

        logger.info(
            "aws_apigateway: checking %s (domain_id=%s region=%s)",
            subdomain_name, domain_id, region,
        )

        # ── Step 1: direct execute-api probe ──────────────────────────────────
        is_apigw_403, probe_status, probe_len = await _probe_execute_api(cname)
        base_evidence.update({
            "probe_status":       probe_status,
            "probe_content_len":  probe_len,
            "probe_is_apigw_403": is_apigw_403,
        })

        if probe_status == 0:
            # Probe failed — endpoint may be truly gone or network unreachable.
            # We can't confirm the fingerprint, but we also can't rule out a
            # transient failure.  Fall through; SDK check may still clarify.
            logger.info(
                "aws_apigateway: %s — execute-api endpoint unreachable (timeout/error)",
                subdomain_name,
            )
        elif not is_apigw_403:
            # Endpoint responded but NOT with the canonical API GW 403.
            # This may be a redirect, a different service, or a misconfiguration
            # that doesn't match the takeover pattern.
            logger.info(
                "aws_apigateway: %s — execute-api returned %d (expected 403/23), "
                "fingerprint mismatch — continuing to SDK check",
                subdomain_name, probe_status,
            )
        else:
            logger.info(
                "aws_apigateway: %s — 403 Forbidden fingerprint confirmed on execute-api endpoint",
                subdomain_name,
            )

        # ── Step 2: AWS SDK check (optional) ──────────────────────────────────
        sdk_result = await self._sdk_check(subdomain_name, region, base_evidence)
        if sdk_result is not None:
            return sdk_result

        # ── All paths → NOT_IMPL; caller transitions to POTENTIAL_LONG ────────
        return TakeoverResult(
            status=TakeoverStatus.NOT_IMPL,
            provider=self.PROVIDER,
            subdomain=subdomain_name,
            confidence_delta=0,
            evidence=base_evidence,
            error=(
                "API Gateway execute-api hostnames are account-bound and cannot be "
                "reclaimed from an external AWS account. Manual verification required."
            ),
        )

    async def _sdk_check(
        self,
        subdomain_name: str,
        region:         str,
        evidence:       dict,
    ) -> Optional[TakeoverResult]:
        """
        Optional AWS SDK check.

        Calls apigateway.get_domain_name(domainName=subdomain_name) from our account.

        Returns a TakeoverResult only for the NOT_VULN case (domain already in our
        account — should never happen in a real bug-bounty context).
        Returns None for all other outcomes so the caller falls through to NOT_IMPL.
        """
        if not self._ready:
            evidence["sdk_check"] = "skipped_no_credentials"
            return None

        try:
            import aioboto3
        except ImportError:
            evidence["sdk_check"] = "skipped_aioboto3_missing"
            logger.warning("aws_apigateway: aioboto3 not installed — SDK check skipped")
            return None

        try:
            session = aioboto3.Session(
                aws_access_key_id=self._key_id,
                aws_secret_access_key=self._secret,
                region_name=region,
            )
            async with session.client("apigateway") as apigw:
                try:
                    resp = await apigw.get_domain_name(domainName=subdomain_name)
                    # 200 → domain is registered to OUR account.  This is unexpected
                    # in a bug-bounty scenario but means it's not vulnerable from the
                    # outside.
                    owned_hostname = (
                        resp.get("regionalDomainName")
                        or resp.get("distributionDomainName")
                        or "unknown"
                    )
                    evidence.update({
                        "sdk_check":          "domain_owned_by_us",
                        "sdk_regional_domain": owned_hostname,
                    })
                    logger.info(
                        "aws_apigateway: %s — domain already registered in our account "
                        "(regional=%s) — NOT_VULN",
                        subdomain_name, owned_hostname,
                    )
                    return TakeoverResult(
                        status=TakeoverStatus.NOT_VULN,
                        provider=self.PROVIDER,
                        subdomain=subdomain_name,
                        confidence_delta=-30,
                        evidence=evidence,
                        error="Custom domain is registered in our AWS account — not vulnerable",
                    )

                except apigw.exceptions.NotFoundException:
                    # Domain not in our account.  Could be in the victim's account
                    # (still owned, just missing API mapping → the 403 we see) or
                    # fully deleted.  Either way, we cannot claim the same execute-api
                    # hostname from the outside.
                    evidence["sdk_check"] = "domain_not_found_in_our_account"
                    logger.info(
                        "aws_apigateway: %s — NotFoundException from SDK "
                        "(domain not in our account; likely in victim's or fully deleted)",
                        subdomain_name,
                    )
                    # Fall through → NOT_IMPL / POTENTIAL_LONG

                except asyncio.TimeoutError:
                    evidence["sdk_check"] = "timeout"
                    logger.warning(
                        "aws_apigateway: SDK check timed out for %s", subdomain_name
                    )

                except Exception as exc:
                    evidence["sdk_check"] = f"error: {exc}"
                    logger.warning(
                        "aws_apigateway: SDK check error for %s: %s", subdomain_name, exc
                    )

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            evidence["sdk_check"] = f"session_error: {exc}"
            logger.warning(
                "aws_apigateway: failed to create aioboto3 session for %s: %s",
                subdomain_name, exc,
            )

        return None  # Caller falls through to NOT_IMPL