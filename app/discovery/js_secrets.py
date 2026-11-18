"""
app/discovery/js_secrets.py

JS body secret scanning — runs after each JS file is fetched in js_scrape.py.

Scans the raw JS body for hardcoded credentials, API keys, tokens, and secrets
using compiled regex patterns.  Findings are persisted to DB (JsSecretFinding)
and sent to Discord via DISCORD_WEBHOOK_URL.

External tool recommendation (optional but better coverage):
  pip install trufflehog  → trufflehog filesystem --no-update <file>
    Best for entropy-based detection + 700+ detector rules.
    Install: https://github.com/trufflesecurity/trufflehog
  pip install gitleaks    → gitleaks detect --source <file>
    Best for TOML rule sets.
    Install: https://github.com/gitleaks/gitleaks
  secretfinder            → python SecretFinder.py -i <url> -o cli
    Best for inline JS scanning via URL.
    Install: https://github.com/m4ll0k/SecretFinder

This module uses inline regex patterns as a zero-dependency baseline.
Set JS_SECRET_TRUFFLEHOG=true in .env to also run trufflehog on each file
for deeper coverage (requires trufflehog binary installed).

Config knobs:
  JS_SECRET_SCAN_ENABLED      bool   default True
  JS_SECRET_MIN_MATCH_LEN     int    default 16    — ignore matches shorter than N chars
  JS_SECRET_MAX_BODY_BYTES    int    default 524288 — skip files larger than N bytes
  JS_SECRET_TRUFFLEHOG        bool   default False  — also run trufflehog subprocess
  TRUFFLEHOG_BIN              str    default "trufflehog"  (shared with git scanner)
  JS_SECRET_TRUFFLEHOG_TIMEOUT int   default 30
"""

from __future__ import annotations

import asyncio
import re
import tempfile
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from app.core.config import settings
from app.core.logging import logger


# ---------------------------------------------------------------------------
# Secret patterns — (label, compiled_regex, is_high_entropy_hint)
# ---------------------------------------------------------------------------
# Each entry: (display_name, pattern, redact_group_index_for_log)
# redact_group_index: 1-based group to show truncated in logs/alerts (0 = full match)

_PATTERNS: list[tuple[str, re.Pattern, int]] = [
    # ── Cloud providers ──────────────────────────────────────────────────────
    (
        "AWS Access Key ID",
        re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])", re.ASCII),
        1,
    ),
    (
        "AWS Secret Access Key",
        re.compile(
            r"(?:aws_secret_access_key|aws_secret|secret_access_key)"
            r"[\s\"'`]*[=:]+[\s\"'`]*([A-Za-z0-9+/]{40})",
            re.IGNORECASE,
        ),
        1,
    ),
    (
        "Google API Key",
        re.compile(r"AIza[0-9A-Za-z\-_]{35}", re.ASCII),
        0,
    ),
    (
        "Google OAuth Client Secret",
        re.compile(r"GOCSPX-[0-9A-Za-z\-_]{28}", re.ASCII),
        0,
    ),
    (
        "Azure Storage Connection String",
        re.compile(
            r"DefaultEndpointsProtocol=https;AccountName=[^;]{3,50};"
            r"AccountKey=[A-Za-z0-9+/=]{60,}",
            re.IGNORECASE,
        ),
        0,
    ),
    # ── Auth / identity platforms ────────────────────────────────────────────
    (
        "GitHub Personal Access Token",
        re.compile(r"ghp_[A-Za-z0-9]{36}", re.ASCII),
        0,
    ),
    (
        "GitHub Fine-Grained Token",
        re.compile(r"github_pat_[A-Za-z0-9_]{82}", re.ASCII),
        0,
    ),
    (
        "GitHub App Installation Token",
        re.compile(r"ghs_[A-Za-z0-9]{36}", re.ASCII),
        0,
    ),
    (
        "Slack Bot/User Token",
        re.compile(r"xox[baprs]-[0-9A-Za-z]{10,48}", re.ASCII),
        0,
    ),
    (
        "Slack Webhook URL",
        re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}", re.ASCII),
        0,
    ),
    (
        "Stripe Secret Key",
        re.compile(r"sk_live_[0-9a-zA-Z]{24,}", re.ASCII),
        0,
    ),
    (
        "Stripe Restricted Key",
        re.compile(r"rk_live_[0-9a-zA-Z]{24,}", re.ASCII),
        0,
    ),
    (
        "Twilio Account SID",
        re.compile(r"AC[a-f0-9]{32}", re.ASCII),
        0,
    ),
    (
        "Twilio Auth Token",
        re.compile(
            r"twilio.*?([a-f0-9]{32})",
            re.IGNORECASE | re.DOTALL,
        ),
        1,
    ),
    (
        "SendGrid API Key",
        re.compile(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}", re.ASCII),
        0,
    ),
    (
        "Mailgun API Key",
        re.compile(r"key-[0-9a-zA-Z]{32}", re.ASCII),
        0,
    ),
    (
        "Square Access Token",
        re.compile(r"sq0atp-[0-9A-Za-z\-_]{22}", re.ASCII),
        0,
    ),
    (
        "Square OAuth Secret",
        re.compile(r"sq0csp-[0-9A-Za-z\-_]{43}", re.ASCII),
        0,
    ),
    (
        "PayPal Braintree Access Token",
        re.compile(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}", re.ASCII),
        0,
    ),
    (
        "NPM Auth Token",
        re.compile(r"//registry\.npmjs\.org/:_authToken\s*=\s*([a-zA-Z0-9\-]{36,})", re.IGNORECASE),
        1,
    ),
    # ── Database / connection strings ────────────────────────────────────────
    (
        "Generic DB Connection String (password in URL)",
        re.compile(
            r"(?:mysql|postgres|postgresql|mongodb|redis|amqp)(?:\+[a-z]+)?"
            r"://[^:@\s]{3,50}:([^@\s]{8,})@[a-zA-Z0-9\.\-]+",
            re.IGNORECASE,
        ),
        1,
    ),
    # ── Generic high-entropy patterns ────────────────────────────────────────
    (
        "Generic Secret Assignment",
        re.compile(
            r"(?:secret|api_?key|private_?key|access_?token|auth_?token)"
            r"[\s\"'`]*[=:]+[\s\"'`]*([A-Za-z0-9+/\-_]{32,})",
            re.IGNORECASE,
        ),
        1,
    ),
]

_FP_ALLOWLIST = re.compile(
    r"(?:00000000-0000-|ffffffff-ffff-|example|placeholder|your[_-]?(?:api[_-]?)?key"
    r"|test[_-]?secret|sample|dummy|lorem|XXXX)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

@dataclass
class JsSecretFinding:
    """A single secret match found inside a JS file."""
    url:          str          # JS file URL where the match was found
    secret_type:  str          # display name from _PATTERNS
    match_value:  str          # raw match (potentially truncated for safety)
    line_number:  Optional[int] = None
    scope_domain: str = ""
    program_name: str = ""
    platform:     str = ""
    found_at:     datetime = field(default_factory=datetime.utcnow)

    @property
    def redacted(self) -> str:
        """Safe display value: first 6 chars + *** + last 4 chars."""
        v = self.match_value
        if len(v) <= 12:
            return v[:3] + "***"
        return v[:6] + "***" + v[-4:]


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------

class JsSecretScanner:
    """
    Scan a JS file body for hardcoded secrets using regex patterns.

    Optionally delegates to trufflehog subprocess for entropy-based scanning
    (set JS_SECRET_TRUFFLEHOG=true in .env and install the binary).
    """

    def __init__(self) -> None:
        self._enabled         = getattr(settings, "JS_SECRET_SCAN_ENABLED", True)
        self._min_len         = getattr(settings, "JS_SECRET_MIN_MATCH_LEN", 16)
        self._max_bytes       = getattr(settings, "JS_SECRET_MAX_BODY_BYTES", 524288)
        self._trufflehog      = getattr(settings, "JS_SECRET_TRUFFLEHOG", False)
        # TRUFFLEHOG_BIN is now shared with the git scanner (renamed from JS_SECRET_TRUFFLEHOG_BIN)
        self._truffle_bin     = getattr(settings, "TRUFFLEHOG_BIN", "trufflehog")
        self._truffle_timeout = getattr(settings, "JS_SECRET_TRUFFLEHOG_TIMEOUT", 30)

    def scan_body(
        self,
        body: str,
        url: str,
        scope_domain: str = "",
        program_name: str = "",
        platform: str = "",
    ) -> List[JsSecretFinding]:
        """
        Scan a JS body string for secrets.  Returns a list of findings (may be empty).
        This is synchronous — call from async context via run_in_executor if needed.
        """
        if not self._enabled:
            return []

        if len(body.encode("utf-8", errors="ignore")) > self._max_bytes:
            logger.debug("js_secrets: body too large for %s — skipping regex scan", url)
            return []

        findings: List[JsSecretFinding] = []
        seen_values: set[str] = set()

        for secret_type, pattern, group_idx in _PATTERNS:
            for m in pattern.finditer(body):
                # Extract the right group (or full match for group_idx=0)
                try:
                    value = m.group(group_idx) if group_idx > 0 else m.group(0)
                except IndexError:
                    value = m.group(0)

                if not value or len(value) < self._min_len:
                    continue

                # Allowlist check
                if _FP_ALLOWLIST.search(value):
                    continue

                # Dedup by value to avoid flooding with the same token repeated
                value_key = f"{secret_type}:{value[:32]}"
                if value_key in seen_values:
                    continue
                seen_values.add(value_key)

                # Find line number
                line_no = body[:m.start()].count("\n") + 1

                findings.append(JsSecretFinding(
                    url=url,
                    secret_type=secret_type,
                    match_value=value,
                    line_number=line_no,
                    scope_domain=scope_domain,
                    program_name=program_name,
                    platform=platform,
                ))

                logger.info(
                    "js_secrets: [%s] found in %s at line %d — value=%s",
                    secret_type, url, line_no, value[:6] + "***",
                )

        return findings

    async def scan_body_async(
        self,
        body: str,
        url: str,
        scope_domain: str = "",
        program_name: str = "",
        platform: str = "",
    ) -> List[JsSecretFinding]:
        """Async wrapper — runs regex scan in thread executor to avoid blocking event loop."""
        loop = asyncio.get_event_loop()
        findings = await loop.run_in_executor(
            None,
            lambda: self.scan_body(body, url, scope_domain, program_name, platform),
        )

        # Optional trufflehog pass
        if self._trufflehog and findings is not None:
            truffle_findings = await self._run_trufflehog(body, url, scope_domain, program_name, platform)
            findings = findings + truffle_findings

        return findings

    async def _run_trufflehog(
        self,
        body: str,
        url: str,
        scope_domain: str,
        program_name: str,
        platform: str,
    ) -> List[JsSecretFinding]:
        """
        Write body to a temp file and run trufflehog filesystem against it.

        trufflehog outputs JSON lines, one per finding:
          {"DetectorName": "AWS", "Raw": "AKIA...", "Verified": true, ...}

        Requires:
          pip install trufflehog          # Python wrapper
          OR
          curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh
        """
        import json as _json

        findings: List[JsSecretFinding] = []
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".js",
                delete=False,
                prefix="jssecret_",
            ) as tmp:
                tmp.write(body)
                tmp_path = tmp.name

            cmd = [
                self._truffle_bin,
                "filesystem",
                "--no-update",
                "--json",
                tmp_path,
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=self._truffle_timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                logger.warning("js_secrets: trufflehog timed out for %s", url)
                return []

            for line in stdout.decode(errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = _json.loads(line)
                except _json.JSONDecodeError:
                    continue
                detector  = obj.get("DetectorName", "Unknown")
                raw_value = obj.get("Raw", "") or obj.get("RawV2", "")
                verified  = obj.get("Verified", False)
                label     = f"trufflehog:{detector}" + (" (verified)" if verified else "")
                if raw_value and len(raw_value) >= 8:
                    findings.append(JsSecretFinding(
                        url=url,
                        secret_type=label,
                        match_value=raw_value,
                        scope_domain=scope_domain,
                        program_name=program_name,
                        platform=platform,
                    ))
                    logger.info(
                        "js_secrets: trufflehog [%s] in %s — verified=%s",
                        detector, url, verified,
                    )

        except FileNotFoundError:
            logger.warning(
                "js_secrets: trufflehog binary '%s' not found. "
                "Install: curl -sSfL https://raw.githubusercontent.com/trufflesecurity/"
                "trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin",
                self._truffle_bin,
            )
        except Exception as exc:
            logger.debug("js_secrets: trufflehog error for %s: %s", url, exc)
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass

        return findings


# ---------------------------------------------------------------------------
# Discord notification helper
# ---------------------------------------------------------------------------

async def persist_js_secret_findings(
    findings: List[JsSecretFinding],
    scope_domain: str = "",
    scope_id: Optional[int] = None,
) -> int:
    """
    Persist findings so they stay queryable after the Discord alert.

    Rows are upserted on (scope_id, url, secret_type, redacted) and only the
    last-seen timestamp/line are refreshed on repeat sightings. Returns the
    number of findings passed in (0 when no scope could be resolved).
    """
    if not findings:
        return 0

    from sqlalchemy import select
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from app.db.db_models import JsSecretRecord, Scope
    from app.db.session import get_session

    async with get_session() as session:
        if scope_id is None and scope_domain:
            normalized = scope_domain[2:] if scope_domain.startswith("*.") else scope_domain
            result = await session.execute(
                select(Scope.id).where(Scope.domain == normalized).limit(1)
            )
            scope_id = result.scalar_one_or_none()
        if scope_id is None:
            logger.debug(
                "js_secrets: no scope row for %r — persistence skipped", scope_domain
            )
            return 0

        now = datetime.utcnow()
        for finding in findings:
            stmt = (
                pg_insert(JsSecretRecord)
                .values(
                    scope_id=int(scope_id),
                    url=finding.url[:2048],
                    secret_type=finding.secret_type[:128],
                    redacted=finding.redacted[:512],
                    line_number=finding.line_number,
                    first_seen_at=now,
                    last_seen_at=now,
                )
                .on_conflict_do_update(
                    constraint="uq_js_secret",
                    set_={"last_seen_at": now, "line_number": finding.line_number},
                )
            )
            await session.execute(stmt)
        await session.commit()

    logger.info("js_secrets: persisted %d finding(s) for %s", len(findings), scope_domain)
    return len(findings)


async def notify_js_secrets(
    findings: List[JsSecretFinding],
    webhook_url: Optional[str] = None,
) -> None:
    """
    Send a Discord embed for a batch of JS secret findings from the same URL.
    Groups findings by JS file URL into one embed per file.
    Uses DISCORD_WEBHOOK_URL from settings (or override webhook_url).
    """
    import httpx

    if not findings:
        return

    wh = webhook_url or getattr(settings, "DISCORD_WEBHOOK_URL", None)
    if not wh:
        return

    # Group by URL
    by_url: dict[str, list[JsSecretFinding]] = {}
    for f in findings:
        by_url.setdefault(f.url, []).append(f)

    for url, url_findings in by_url.items():
        first = url_findings[0]
        fields = []
        for f in url_findings[:20]:  # Discord embed field limit
            fields.append({
                "name":   f.secret_type,
                "value":  f"`{f.redacted}`" + (f" (line {f.line_number})" if f.line_number else ""),
                "inline": False,
            })
        if len(url_findings) > 20:
            fields.append({
                "name":  "…and more",
                "value": f"{len(url_findings) - 20} additional findings suppressed",
                "inline": False,
            })

        embed = {
            "title":       f"🔑 JS Secrets Found: {url[:100]}",
            "description": f"**{len(url_findings)} secret(s)** detected in JS file",
            "color":       0xFF0000,
            "fields":      fields,
            "footer":      {"text": f"STOscanner — JS Secret Scanner • {first.program_name} ({first.platform.upper()})"},
            "timestamp":   datetime.utcnow().isoformat(),
        }

        payload = {"embeds": [embed], "username": "STOscanner"}

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(wh, json=payload, timeout=30.0)
                if resp.status_code == 204:
                    logger.info("js_secrets: Discord alert sent for %s (%d findings)", url, len(url_findings))
                elif resp.status_code == 429:
                    data = resp.json()
                    retry_after = min(float(data.get("retry_after", 2.0)), 30.0)
                    await asyncio.sleep(retry_after)
                    await notify_js_secrets(url_findings, webhook_url=wh)
                else:
                    logger.warning("js_secrets: Discord alert failed: %s", resp.status_code)
        except Exception as exc:
            logger.error("js_secrets: Discord notify error for %s: %s", url, exc)