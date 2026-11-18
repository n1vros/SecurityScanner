"""
app/takeover/providers/github.py

GitHub Pages subdomain takeover — detection only.

Vulnerable pattern
------------------
  subdomain CNAME → <username>.github.io
  The GitHub account no longer exists → someone could register it.

Why auto-takeover is NOT possible via API
-----------------------------------------
  Claiming a dangling github.io requires registering the deleted GitHub
  username. GitHub account creation requires browser signup, email
  verification, and CAPTCHA — there is no API endpoint for this.

  This checker therefore:
    - Confirms the account is gone (+confidence) or still exists (-confidence)
    - Always returns NOT_IMPL for the takeover attempt
    - Logs the username so you can try to register it manually at github.com

Manual steps when you get a NOT_IMPL alert
-------------------------------------------
  1. Go to https://github.com/join
  2. Register the username shown in the alert
  3. Create repo: <username>.github.io
  4. Push claim HTML
  5. Add CNAME record / custom domain in repo settings
"""

import re
from typing import Optional

import aiohttp

from app.core.logging import logger
from app.takeover.subdomain_hunter.providers.base import TakeoverResult, TakeoverStatus

_GITHUB_IO_RE = re.compile(r"^([a-z0-9][a-z0-9\-]*[a-z0-9])\.github\.io\.?$", re.IGNORECASE)
_TIMEOUT      = aiohttp.ClientTimeout(total=10)

# Confidence adjustments from account existence check
_DELTA_MISSING = +30   # account gone — strong positive signal
_DELTA_EXISTS  = -40   # account alive — suppress finding


class GitHubTakeoverChecker:
    """
    Verify GitHub account existence for confidence scoring.
    Always returns NOT_IMPL for takeover — manual registration required.
    """

    PROVIDER = "github"

    def extract_username(self, cname: str) -> Optional[str]:
        cname = cname.lower().strip().rstrip(".")
        m = _GITHUB_IO_RE.match(cname)
        return m.group(1) if m else None

    async def attempt(self, subdomain_name: str, cname: str) -> TakeoverResult:
        """
        Check account existence, return NOT_IMPL (or NOT_VULN if account exists).
        Never raises.
        """
        username = self.extract_username(cname)
        if not username:
            return TakeoverResult(
                status=TakeoverStatus.UNAVAILABLE,
                provider=self.PROVIDER,
                subdomain=subdomain_name,
                error=f"Cannot extract username from CNAME: {cname}",
            )

        account_exists = await self._account_exists(username)

        if account_exists:
            logger.debug("github: account %s exists — not vulnerable", username)
            return TakeoverResult(
                status=TakeoverStatus.NOT_VULN,
                provider=self.PROVIDER,
                subdomain=subdomain_name,
                confidence_delta=_DELTA_EXISTS,
                evidence={"github_username": username, "account_exists": True},
            )

        # Account is gone — manually claimable but not via API
        logger.info(
            "github: account '%s' is GONE — %s is vulnerable. "
            "Register https://github.com/join with username '%s' to claim.",
            username, subdomain_name, username,
        )
        return TakeoverResult(
            status=TakeoverStatus.NOT_IMPL,
            provider=self.PROVIDER,
            subdomain=subdomain_name,
            confidence_delta=_DELTA_MISSING,
            evidence={
                "github_username":  username,
                "account_exists":   False,
                "manual_steps":     f"Register github.com/{username} then create {username}.github.io repo",
            },
            error="GitHub account registration requires browser signup — cannot automate",
        )

    async def _account_exists(self, username: str) -> bool:
        try:
            async with aiohttp.ClientSession(timeout=_TIMEOUT) as http:
                async with http.get(
                    "https://github.com/signup_check/username",
                    params={"value": username},
                    headers={
                        "User-Agent": "Mozilla/5.0",
                        "Accept": "*/*",
                        "Connection": "keep-alive",
                    },
                ) as resp:
                    if resp.status == 200:
                        # Username available — account is gone
                        return False
                    if resp.status == 422:
                        # Username taken — account exists
                        return True
                    # Unexpected status — log and fail safe
                    logger.debug(
                        "github: unexpected status %d from signup_check for %s",
                        resp.status, username,
                    )
                    return True
        except Exception as exc:
            logger.debug("github: signup_check request failed for %s: %s", username, exc)
            return True  # fail safe: assume exists to avoid false positive