"""
Discord notifications for takeover alerts.
"""

import json
import asyncio
from datetime import datetime
from typing import List, Optional

import aiohttp
import httpx

from app.core.config import settings
from app.core.logging import logger
from app.takeover.subdomain_hunter.providers.base import TakeoverResult, TakeoverStatus
from app.db.db_models import Subdomain

# ---------------------------------------------------------------------------
# Takeover status → Discord display
# ---------------------------------------------------------------------------

_STATUS_BADGE = {
    TakeoverStatus.SUCCESS:     "✅ Auto-takeover: **Success** — claim page deployed",
    TakeoverStatus.FAIL:        "❌ Auto-takeover: **Failed** — attempt errored, may still be claimable",
    TakeoverStatus.NOT_IMPL:    "⚠️ Auto-takeover: **N/A** — manual steps required (see below)",
    TakeoverStatus.NOT_VULN:    "🟢 Auto-takeover: **Not vulnerable** — resource still owned",
    TakeoverStatus.UNAVAILABLE: "⚠️ Auto-takeover: **Unchecked** — API token not configured",
    TakeoverStatus.NEEDS_TXT:   "🔒 Auto-takeover: **Blocked** — domain in another account, TXT transfer required",
}

_STATUS_COLOR = {
    TakeoverStatus.SUCCESS:     0x00C851,   # green  — confirmed claimed
    TakeoverStatus.FAIL:        0xFF8800,   # orange — claimable, attempt failed
    TakeoverStatus.NOT_IMPL:    0xFFCC00,   # yellow — manual action needed
    TakeoverStatus.NOT_VULN:    0x00AAFF,   # blue   — false positive suppressed
    TakeoverStatus.UNAVAILABLE: 0xAAAAAA,   # grey   — unchecked
    TakeoverStatus.NEEDS_TXT:   0x9B59B6,   # purple — ownership-blocked, long recheck
}

# Fallback colors when no takeover_result is available
_CONF_COLOR_HIGH   = 0xFF0000   # red    — confidence ≥ 90
_CONF_COLOR_MEDIUM = 0xFFA500   # orange — confidence < 90


class DiscordNotifier:
    """Send Discord webhook notifications with rate limiting and retry logic."""

    # Discord limits: 6000 chars total across all embed fields
    MAX_EMBED_CHARS = 6000
    # 30 messages per minute = 1 message every 2 seconds
    RATE_LIMIT_DELAY = 2.0
    # Cap on retry_after to guard against millisecond values or
    # unexpectedly large numbers from Discord's API causing indefinite sleeps.
    MAX_RETRY_AFTER = 30.0

    def __init__(self, webhook_url: Optional[str] = None):
        # Allow callers to pass an explicit webhook URL (e.g. NS sweep staging channel).
        # Falls back to DISCORD_WEBHOOK_URL from settings if not provided.
        self.webhook_url = webhook_url or settings.DISCORD_WEBHOOK_URL
        self.enabled     = bool(self.webhook_url)


    async def send_raw(
        self,
        title:       str,
        description: str = "",
        color:       int = 0xAAAAAA,
        fields:      Optional[List[dict]] = None,
        footer_text: Optional[str]        = None,
    ) -> None:
        """
        Send a bare Discord embed with explicit title/description/color.

        Used by NS-lottery takeover workers (Route53, Azure DNS, GCP DNS) to
        send result notifications after the lottery attempt completes.
        """
        if not self.enabled:
            return

        embed: dict = {
            "title":     title,
            "color":     color,
            "timestamp": datetime.utcnow().isoformat(),
        }
        if description:
            embed["description"] = description
        if fields:
            embed["fields"] = fields
        embed["footer"] = {"text": footer_text or "STOscanner"}

        embed = self._truncate_embed(embed)
        payload = {"embeds": [embed], "username": "STOscanner"}

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.webhook_url,
                    json=payload,
                    timeout=30.0,
                )
                if response.status_code == 204:
                    logger.info("Discord send_raw: sent — %s", title[:80])
                elif response.status_code == 429:
                    data        = response.json()
                    retry_after = min(float(data.get("retry_after", self.RATE_LIMIT_DELAY)), self.MAX_RETRY_AFTER)
                    await asyncio.sleep(retry_after)
                    await self.send_raw(title, description, color, fields, footer_text)
                else:
                    logger.warning(
                        "Discord send_raw failed: %s %s",
                        response.status_code, response.text[:200],
                    )
        except Exception as e:
            logger.error("Discord send_raw error: %s", e)

    async def notify_ns_takeover_result(
        self,
        subdomain_name: str,
        provider:       str,
        success:        bool,
        program_name:   str = "unknown",
        platform:       str = "unknown",
        winning_ns:     Optional[List[str]] = None,
        error_detail:   Optional[str]       = None,
        poc_txt:        Optional[str]       = None,
        poc_ip:         Optional[str]       = None,
        zone_detail:    Optional[str]       = None,
    ) -> None:
        """
        Send the RESULT notification after an NS-lottery takeover attempt.

        This is the 2nd notification per NS finding:
          1st -> notify_dns_takeover() fires on discovery
          2nd -> this method fires after the lottery worker completes
        """
        if not self.enabled:
            return

        if success:
            title = f"✅ NS Takeover SUCCESS — {subdomain_name}"
            color = 0x00C853
            ns_str = ", ".join(f"`{ns}`" for ns in (winning_ns or []))
            description = (
                f"**🎉 DNS zone successfully claimed via NS lottery!**\n\n"
                f"**Program**: {program_name}\n"
                f"**Platform**: {platform.upper()}\n"
                f"**Domain**: `{subdomain_name}`\n"
                f"**Provider**: {provider}\n"
                f"**Matched NS**: {ns_str or '—'}\n"
            )
            if poc_txt:
                description += f"**TXT PoC**: `{poc_txt}`\n"
            if poc_ip:
                description += f"**A Record**: `{subdomain_name} → {poc_ip}`\n"
            if zone_detail:
                description += f"**Zone**: {zone_detail}\n"
            description += (
                "\n**Next steps:**\n"
                "1. Screenshot DNS resolution proving domain control\n"
                "2. Screenshot TXT PoC record\n"
                "3. Submit report to BB program\n"
                "4. Delete zone/resource after report is accepted"
            )
        else:
            title = f"⚠️ NS Takeover FAILED — {subdomain_name}"
            color = 0xFF6D00
            description = (
                f"**NS lottery attempt completed — no matching NS set found.**\n\n"
                f"**Program**: {program_name}\n"
                f"**Platform**: {platform.upper()}\n"
                f"**Domain**: `{subdomain_name}`\n"
                f"**Provider**: {provider}\n"
            )
            if error_detail:
                description += f"**Reason**: {error_detail}\n"
            description += (
                f"\n**Manual option:** Create a DNS zone for `{subdomain_name}` in "
                f"the {provider} console and check if the assigned NS matches the stale "
                f"delegation. The vulnerability is still real — the lottery just did not "
                f"win this round."
            )

        await self.send_raw(
            title       = title,
            description = description,
            color       = color,
            footer_text = f"STOscanner — NS Takeover Result (2/2) • {program_name} ({platform.upper()})",
        )

    async def notify(
        self,
        subdomains: List,
        takeover_result: Optional[TakeoverResult] = None,
    ) -> None:
        """Send notification for high-confidence takeover subdomains.

        subdomains — list of (Subdomain, program_name, platform) tuples.
        takeover_result — optional TakeoverResult from the provider checker.
            When present, the embed shows a clear status badge (Success / Fail /
            N/A / Unchecked) so you always know what the auto-takeover attempt did.
            When absent (batch notifications), the embed falls back to confidence-
            based coloring without a takeover status line.

        program_names and platform must be pre-resolved by the caller while the
        DB session is still open, because asyncio.sleep() yields the event loop
        and SQLAlchemy will expire lazy-loaded attributes mid-loop.
        """
        if not self.enabled:
            logger.debug("Discord notifications disabled")
            return

        for i, (subdomain, program_name, platform) in enumerate(subdomains):
            if i > 0:
                await asyncio.sleep(self.RATE_LIMIT_DELAY)
            await self._send_single_notification(
                subdomain, program_name, platform,
                takeover_result=takeover_result,
            )

    async def _send_single_notification(
        self,
        subdomain: "Subdomain",
        program_name: str,
        platform: str,
        retry_count: int = 0,
        takeover_result: Optional[TakeoverResult] = None,
    ) -> None:
        """Send a single Discord notification with recursive retry on 429."""
        if retry_count > 3:
            logger.error("Max retries exceeded for %s", subdomain.name)
            return

        embed   = self._create_embed(subdomain, program_name, platform, takeover_result)
        embed   = self._truncate_embed(embed)
        payload = {
            "embeds":   [embed],
            "username": "STOscanner",
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.webhook_url,
                    json=payload,
                    timeout=30.0,
                )

                if response.status_code == 204:
                    logger.info("Discord notification sent for %s", subdomain.name)

                elif response.status_code == 429:
                    data        = response.json()
                    retry_after = data.get("retry_after", self.RATE_LIMIT_DELAY)
                    retry_after = min(float(retry_after), self.MAX_RETRY_AFTER)
                    logger.warning(
                        "Discord rate limited for %s. Retrying in %.1fs (attempt %d/3)",
                        subdomain.name, retry_after, retry_count + 1,
                    )
                    await asyncio.sleep(retry_after)
                    await self._send_single_notification(
                        subdomain, program_name, platform,
                        retry_count=retry_count + 1,
                        takeover_result=takeover_result,
                    )

                else:
                    logger.warning(
                        "Discord notification failed for %s: %s %s",
                        subdomain.name, response.status_code, response.text,
                    )
        except Exception as e:
            logger.error("Discord notification error for %s: %s", subdomain.name, e)

    def _create_embed(
        self,
        subdomain: "Subdomain",
        program_name: str,
        platform: str,
        takeover_result: Optional[TakeoverResult] = None,
    ) -> dict:
        """
        Build the Discord embed.

        Takeover status badge is the first line of the description so it's
        immediately visible without scrolling, even on long embeds.  Color
        reflects the outcome rather than raw confidence so you can triage at a
        glance:
          green  — auto-claimed successfully
          yellow — manual steps needed (NOT_IMPL) or API unconfigured
          orange — attempt failed, still likely claimable
          red    — high confidence, no provider checker result yet
        """
        # ── Takeover status line (most important — top of embed) ──────────────
        description = ""

        if takeover_result:
            badge = _STATUS_BADGE.get(takeover_result.status, "❓ Unknown status")
            description += f"{badge}\n"

            # For NOT_IMPL: surface the manual steps from the evidence dict
            if takeover_result.status == TakeoverStatus.NOT_IMPL and takeover_result.error:
                description += f"> {takeover_result.error}\n"

            # For SUCCESS: show the claim URL prominently
            if takeover_result.status == TakeoverStatus.SUCCESS and takeover_result.claim_url:
                description += f"**Claim URL**: {takeover_result.claim_url}\n"

            # For FAIL: show what went wrong
            if takeover_result.status == TakeoverStatus.FAIL and takeover_result.error:
                description += f"> Error: `{takeover_result.error}`\n"

            description += "\n"

        # ── Core subdomain details ────────────────────────────────────────────
        description += (
            f"**Confidence**: {subdomain.confidence}%\n"
            f"**Provider**: {subdomain.takeover_provider or 'Unknown'}\n"
            f"**State**: {subdomain.state.value}\n"
        )

        if subdomain.cname_target:
            description += f"**CNAME**: `{subdomain.cname_target}`\n"
        if subdomain.http_status:
            description += f"**HTTP Status**: {subdomain.http_status}\n"

        # ── Evidence block ────────────────────────────────────────────────────
        if subdomain.takeover_evidence:
            try:
                evidence = json.loads(subdomain.takeover_evidence)

                # Prefer takeover_result.evidence for freshest data if available;
                # fall back to what was persisted in the DB.
                evidence_to_show = (
                    takeover_result.evidence
                    if takeover_result and takeover_result.evidence
                    else evidence
                )

                evidence_str = json.dumps(evidence_to_show, indent=2)
                if len(evidence_str) > 400:
                    evidence_str = evidence_str[:400] + "..."
                description += f"\n**Evidence**:\n```json\n{evidence_str}\n```"
            except (json.JSONDecodeError, TypeError):
                pass

        # ── Embed color ───────────────────────────────────────────────────────
        if takeover_result:
            color = _STATUS_COLOR.get(takeover_result.status, _CONF_COLOR_MEDIUM)
        else:
            color = _CONF_COLOR_HIGH if subdomain.confidence >= 90 else _CONF_COLOR_MEDIUM

        # ── Fields ───────────────────────────────────────────────────────────
        fields = [
            {"name": "Program",    "value": program_name,                         "inline": True},
            {"name": "Platform",   "value": platform.upper(),                     "inline": True},
            {"name": "Provider",   "value": subdomain.takeover_provider or "?",   "inline": True},
            {"name": "Confidence", "value": f"{subdomain.confidence}%",           "inline": True},
        ]

        # Add takeover status as a field too — easier to filter in Discord search
        if takeover_result:
            fields.append({
                "name":   "Takeover Status",
                "value":  takeover_result.status.value.upper(),
                "inline": True,
            })

        return {
            "title":       f"🚨 Subdomain Takeover: {subdomain.name}",
            "description": description,
            "color":       color,
            "timestamp":   datetime.utcnow().isoformat(),
            "fields":      fields,
            "footer":      {"text": f"STOscanner • {program_name}"},
        }

    def _truncate_embed(self, embed: dict) -> dict:
        """Truncate embed to stay within Discord's 6000 char total limit."""
        total = (
            len(embed.get("title", ""))
            + len(embed.get("description", ""))
            + sum(
                len(f.get("name", "")) + len(f.get("value", ""))
                for f in embed.get("fields", [])
            )
            + len(embed.get("footer", {}).get("text", ""))
        )

        if total <= self.MAX_EMBED_CHARS:
            return embed

        overflow    = total - self.MAX_EMBED_CHARS
        description = embed.get("description", "")
        if len(description) > overflow + 100:
            cut        = len(description) - overflow - 3
            truncated  = description[:cut]
            last_nl    = truncated.rfind("\n")
            if last_nl > cut * 0.8:
                truncated = truncated[:last_nl]
            embed["description"] = truncated + "..."

        return embed

    async def notify_dns_takeover(
        self,
        finding,
        program_name: str = "unknown",
        platform: str = "unknown",
    ) -> None:
        """
        Send a DNS takeover finding notification.
        Distinct from subdomain takeover — uses purple color and DNS-specific fields.

        Handles three rcode variants:
          Standard rcode         — classic NS takeover (SERVFAIL/REFUSED/NXDOMAIN)
          WILDCARD_CNAME         — *.domain CNAME to claimable provider (all subdomains)
          CNAME_HOP_AVAILABLE    — intermediate CNAME hop domain is available to register
        """
        if not self.enabled:
            return

        rcode = getattr(finding, "rcode", "")

        # ── Title / description / color vary by finding type ──────────────────
        if rcode == "CNAME_HOP_AVAILABLE":
            embed_title = f"🔗 CNAME Hop Domain Available: `{finding.nameserver}`"
            embed_desc  = (
                f"An intermediate domain in a CNAME chain for "
                f"`{finding.subdomain_name}` is **available to register**.\n\n"
                f"Registering `{finding.nameserver}` gives full control over all "
                f"downstream hops in the chain, including the terminal IP — without "
                f"needing to claim the cloud IP at all.\n\n"
                f"{finding.provider_notes}"
            )
            embed_color = 0xFF4500   # orange-red — high severity
        elif rcode == "WILDCARD_CNAME":
            embed_title = f"🌐 Wildcard CNAME Takeover: `{finding.subdomain_name}`"
            embed_desc  = (
                f"The wildcard record `{finding.subdomain_name}` has a CNAME pointing "
                f"to a claimable provider resource.\n\n"
                f"**This gives control over EVERY subdomain** under the scope at once.\n\n"
                f"{finding.provider_notes}"
            )
            embed_color = 0xFF0000   # bright red — critical
        else:
            # use subdomain_name as the vulnerable entity in the title.
            # scope_domain is the scope root (e.g. comcast.com); subdomain_name
            # is the actual vulnerable record (e.g. bopis.comcast.com).
            # Fall back to scope_domain only when subdomain_name is absent
            # (scope-root findings where both fields are identical).
            vulnerable_domain = finding.subdomain_name or finding.scope_domain
            embed_title = f"🌐 DNS Takeover: {vulnerable_domain}"
            embed_desc  = (
                f"The domain's authoritative nameserver belongs to **{finding.provider}** "
                f"but the zone appears to be unclaimed (returned `{finding.rcode}`).\n\n"
                f"**This gives full DNS control** — A, MX, TXT, subdomains, everything."
            )
            embed_color = 0x9B59B6   # purple — distinct from subdomain takeover

        embed = {
            "title":       embed_title,
            "description": embed_desc,
            "color":       embed_color,
            "fields": [
                {"name": "Program",      "value": program_name,                    "inline": True},
                {"name": "Platform",     "value": platform.upper(),                "inline": True},
                # show the actual vulnerable subdomain, not the scope root.
                # Added a separate "Scope" field so operators can still see which
                # program scope the finding belongs to.
                {"name": "Subdomain",    "value": f"`{finding.subdomain_name}`",   "inline": True},
                {"name": "Scope",        "value": f"`{finding.scope_domain}`",     "inline": True},
                {"name": "Nameserver",   "value": f"`{finding.nameserver}`",       "inline": True},
                {"name": "Provider",     "value": finding.provider,                "inline": True},
                {"name": "DNS Response", "value": f"`{finding.rcode}`",            "inline": True},
                {"name": "How to claim", "value": finding.provider_notes,          "inline": False},
            ],
            "footer": {"text": f"STOscanner — DNS Takeover • {program_name} ({platform.upper()})"},
        }

        payload = {"embeds": [embed]}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 429:
                        data = await resp.json()
                        await asyncio.sleep(
                            min(float(data.get("retry_after", 5)), self.MAX_RETRY_AFTER)
                        )
                        await self.notify_dns_takeover(finding, program_name, platform)
                    elif resp.status not in (200, 204):
                        logger.warning("dns_takeover discord notify returned %d", resp.status)
        except Exception as e:
            logger.error("dns_takeover discord notify error: %s", e)

    async def notify_domain_buyable(
        self,
        domain: str,
        expires_at,
        registrar: Optional[str] = None,
        program_name: str = "unknown",
        platform: str = "unknown",
    ) -> None:
        """
        Send a Discord alert when a domain has passed its expiry date and
        is confirmed available to register via DNS check.
        """
        if not self.enabled:
            return

        expiry_str = expires_at.strftime("%Y-%m-%d") if expires_at else "unknown"

        description = (
            f"**Domain**: `{domain}`\n"
            f"**Expired**: {expiry_str}\n"
        )
        if registrar:
            description += f"**Previous registrar**: {registrar}\n"

        description += (
            "\n**Where to buy**:\n"
            "• [Namecheap](https://www.namecheap.com)\n"
            "• [GoDaddy](https://www.godaddy.com)\n"
            "• [Cloudflare Registrar](https://www.cloudflare.com/products/registrar/)\n"
        )

        embed = {
            "title":       f"🟢 Domain Available: {domain}",
            "description": description,
            "color":       0x00C851,
            "timestamp":   datetime.utcnow().isoformat(),
            "fields": [
                {"name": "Program",        "value": program_name,           "inline": True},
                {"name": "Platform",       "value": platform.upper(),       "inline": True},
                {"name": "Domain",         "value": f"`{domain}`",          "inline": True},
                {"name": "Expiry date",    "value": expiry_str,             "inline": True},
                {"name": "Prev registrar", "value": registrar or "unknown", "inline": True},
            ],
            "footer": {"text": f"STOscanner — Domain Buy Scanner • {program_name}"},
        }

        payload = {"embeds": [self._truncate_embed(embed)], "username": "STOscanner"}

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.webhook_url,
                    json=payload,
                    timeout=30.0,
                )
                if response.status_code == 204:
                    logger.info("Domain buy alert sent for %s", domain)
                elif response.status_code == 429:
                    data        = response.json()
                    retry_after = min(float(data.get("retry_after", self.RATE_LIMIT_DELAY)), self.MAX_RETRY_AFTER)
                    await asyncio.sleep(retry_after)
                    await self.notify_domain_buyable(
                        domain, expires_at, registrar,
                        program_name=program_name,
                        platform=platform,
                    )
                else:
                    logger.warning(
                        "Domain buy alert failed for %s: %s %s",
                        domain, response.status_code, response.text,
                    )
        except Exception as e:
            logger.error("Domain buy alert error for %s: %s", domain, e)



    async def notify_ip_hit(
        self,
        ip:              str,
        provider:        str,
        region:          str,
        cidr_block:      str,
        score:           float,
        attempts:        int,
        subdomain_names: list,
        # BB triage fields — optional for back-compat with old call sites
        program_name:    str = "unknown",
        platform:        str = "unknown",
        scope_url:       str = "",
    ) -> None:
        """
        Send a Discord alert when the IP hunter claims a target IP.

        Uses the same retry/rate-limit logic as every other notification.
        Called from hunter.py._notify_hit() — replaces the inline aiohttp call.
        """
        if not self.enabled:
            return

        webhook = self.webhook_url
        if not webhook:
            return

        subdomains_str = (
            "\n".join(f"• https://{n}" for n in subdomain_names[:10])
            or "unknown"
        )
        if len(subdomain_names) > 10:
            subdomains_str += f"\n… and {len(subdomain_names) - 10} more"

        # Provider-specific release command
        _release_cmd = {
            "aws":          f"`aws ec2 release-address --public-ip {ip}`",
            "azure":        "Portal → Public IP addresses → delete the resource",
            "gcp":          f"`gcloud compute addresses delete <n> --region {region}`",
            "digitalocean": f"Portal → Networking → Reserved IPs → delete `{ip}`",
        }.get(provider.lower(), "Release via provider console")

        embed = {
            "title":       f"🎯 IP Takeover Hit: `{ip}`",
            "description": (
                f"An IP matching a known target was allocated during the hunt.\n"
                f"⚠️ **The EIP has NOT been released** — set your PoC records before freeing it."
            ),
            "color":     0xFF4500,
            "timestamp": datetime.utcnow().isoformat(),
            "fields": [
                # ── BB identity — most important for triage ──────────────────
                {"name": "Program",   "value": program_name,                                   "inline": True},
                {"name": "Platform",  "value": platform.upper() if platform != "unknown" else "—", "inline": True},
                {"name": "Scope URL", "value": scope_url or "—",                               "inline": True},
                # ── Technical ────────────────────────────────────────────────
                {"name": "IP",        "value": f"`{ip}`",        "inline": True},
                {"name": "Provider",  "value": provider.upper(), "inline": True},
                {"name": "Region",    "value": region,           "inline": True},
                {"name": "CIDR Block","value": f"`{cidr_block}`","inline": True},
                {"name": "Score",     "value": f"{score:.3f}",   "inline": True},
                {"name": "Attempts",  "value": str(attempts),    "inline": True},
                # ── Affected endpoints ────────────────────────────────────────
                {
                    "name":   f"Subdomains pointing to `{ip}` ({len(subdomain_names)})",
                    "value":  subdomains_str,
                    "inline": False,
                },
                # ── What to do ────────────────────────────────────────────────
                {
                    "name":  "Next steps",
                    "value": (
                        f"1. Confirm: `dig +short {subdomain_names[0] if subdomain_names else '<subdomain>'}` → `{ip}`\n"
                        f"2. Add A / TXT PoC record via **{provider.upper()}** console\n"
                        f"3. Screenshot + submit to **{program_name}** on **{platform.upper()}**\n"
                        f"4. Release: {_release_cmd}"
                    ),
                    "inline": False,
                },
            ],
            "footer": {"text": f"STOscanner — IP Hunter • {program_name} ({platform.upper()})"},
        }

        payload = {"embeds": [self._truncate_embed(embed)], "username": "STOscanner"}

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    webhook,
                    json=payload,
                    timeout=30.0,
                )
                if response.status_code == 204:
                    logger.info("ip_hunter: Discord hit alert sent for %s", ip)
                elif response.status_code == 429:
                    data        = response.json()
                    retry_after = min(float(data.get("retry_after", self.RATE_LIMIT_DELAY)), self.MAX_RETRY_AFTER)
                    logger.warning("ip_hunter: Discord rate limited, retrying in %.1fs", retry_after)
                    await asyncio.sleep(retry_after)
                    await self.notify_ip_hit(
                        ip, provider, region, cidr_block,
                        score, attempts, subdomain_names,
                        program_name=program_name,
                        platform=platform,
                        scope_url=scope_url,
                    )
                else:
                    logger.warning(
                        "ip_hunter: Discord hit alert failed: %s %s",
                        response.status_code, response.text,
                    )
        except Exception as exc:
            logger.error("ip_hunter: Discord hit alert error: %s", exc)

    async def notify_ip_hit_stale(
        self,
        ip:              str,
        provider:        str,
        region:          str,
        subdomain_names: list,
        program_name:    str = "unknown",
        platform:        str = "unknown",
    ) -> None:
        """
        Send a Discord alert when the IP hunter claimed a target IP but a live
        DNS recheck confirmed the subdomains no longer resolve to that IP.

        This means the target DNS record was already cleaned up between the time
        the DB was last scanned and the moment we claimed the address.  The stale
        entry has been removed from the database; no manual action is required
        for the subdomains, but the operator should release the held IP.
        """
        if not self.enabled:
            return

        webhook = self.webhook_url
        if not webhook:
            return

        _release_cmd = {
            "aws":          f"`aws ec2 release-address --public-ip {ip}`",
            "azure":        "Portal → Public IP addresses → delete the resource",
            "gcp":          f"`gcloud compute addresses delete <name> --region {region}`",
            "digitalocean": f"Portal → Networking → Reserved IPs → delete `{ip}`",
        }.get(provider.lower(), "Release via provider console")

        subdomains_str = (
            "\n".join(f"• `{n}`" for n in subdomain_names[:10]) or "unknown"
        )
        if len(subdomain_names) > 10:
            subdomains_str += f"\n… and {len(subdomain_names) - 10} more"

        embed = {
            "title":       f"🔄 IP Claimed — DNS Already Cleared: `{ip}`",
            "description": (
                f"The IP hunter allocated `{ip}` (matching a known target), but a "
                f"live DNS recheck found **no subdomain still resolves to this address**.\n\n"
                f"The stale `ip_addresses` entry has been removed from the database. "
                f"No takeover window is currently open — **please release the IP** using "
                f"the command below."
            ),
            "color":     0x5865F2,   # blurple — informational, not critical
            "timestamp": datetime.utcnow().isoformat(),
            "fields": [
                {"name": "Program",   "value": program_name,                                       "inline": True},
                {"name": "Platform",  "value": platform.upper() if platform != "unknown" else "—", "inline": True},
                {"name": "IP",        "value": f"`{ip}`",                                          "inline": True},
                {"name": "Provider",  "value": provider.upper(),                                   "inline": True},
                {"name": "Region",    "value": region,                                             "inline": True},
                {
                    "name":   f"Checked subdomains ({len(subdomain_names)})",
                    "value":  subdomains_str,
                    "inline": False,
                },
                {
                    "name":  "Action required",
                    "value": f"Release the IP to avoid unnecessary charges:\n{_release_cmd}",
                    "inline": False,
                },
            ],
            "footer": {"text": f"STOscanner — IP Hunter • DNS recheck: stale cleared"},
        }

        payload = {"embeds": [self._truncate_embed(embed)], "username": "STOscanner"}

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(webhook, json=payload, timeout=30.0)
                if response.status_code == 204:
                    logger.info("ip_hunter: stale-cleared Discord alert sent for %s", ip)
                elif response.status_code == 429:
                    data        = response.json()
                    retry_after = min(
                        float(data.get("retry_after", self.RATE_LIMIT_DELAY)),
                        self.MAX_RETRY_AFTER,
                    )
                    await asyncio.sleep(retry_after)
                    await self.notify_ip_hit_stale(
                        ip, provider, region, subdomain_names, program_name, platform
                    )
                else:
                    logger.warning(
                        "ip_hunter: stale-cleared Discord alert failed: %s %s",
                        response.status_code, response.text[:200],
                    )
        except Exception as exc:
            logger.error("ip_hunter: stale-cleared Discord alert error: %s", exc)

    async def notify_exposure(
        self,
        finding,
        subdomain,
        program_name: str = "unknown",
        platform: str = "unknown",
    ) -> None:
        """Exposure finding — 🔴 critical, 🟠 high, 🟡 medium."""
        if not self.enabled:
            return

        color = {"critical": 0xFF0000, "high": 0xFF6600, "medium": 0xFFCC00}.get(
            finding.severity, 0xFFCC00
        )
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(finding.severity, "⚠️")

        embed = {
            "title":       f"{emoji} Exposed File [{finding.severity.upper()}]: {finding.path}",
            "description": finding.description,
            "color":       color,
            "timestamp":   datetime.utcnow().isoformat(),
            "fields": [
                {"name": "Program",   "value": program_name,                    "inline": True},
                {"name": "Platform",  "value": platform.upper(),                "inline": True},
                {"name": "Subdomain", "value": f"`{finding.subdomain}`",        "inline": True},
                {"name": "Severity",  "value": finding.severity.upper(),        "inline": True},
                {"name": "URL",       "value": finding.url,                     "inline": False},
                {"name": "Preview",   "value": f"```{finding.snippet[:280]}```","inline": False},
            ],
            "footer": {"text": f"STOscanner — Exposure Scanner • {program_name}"},
        }

        payload = {"embeds": [self._truncate_embed(embed)], "username": "STOscanner"}

        try:
            async with aiohttp.ClientSession() as http_session:
                async with http_session.post(
                    self.webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 429:
                        data = await resp.json()
                        retry_after = min(float(data.get("retry_after", 5)), self.MAX_RETRY_AFTER)
                        await asyncio.sleep(retry_after)
                        await self.notify_exposure(finding, subdomain, program_name, platform)
                    elif resp.status not in (200, 204):
                        logger.warning("exposure notify returned %d", resp.status)
        except Exception as e:
            logger.error("exposure notify error: %s", e)

    async def notify_spf_dmarc(
        self,
        finding,
        program_name: str = "unknown",
        platform:     str = "unknown",
    ) -> None:
        """
        Send a Discord embed for a SpfDmarcFinding from ip_indicators.check_spf_dmarc().

        Three finding types:
          spf_include_nxdomain  — orange  — SPF include target is NXDOMAIN
          spf_include_takeover  — red     — SPF include NS is claimable → email spoofing
          dmarc_ns_takeover     — red     — _dmarc NS is claimable → policy hijack
        """
        if not self.enabled:
            return

        finding_type = getattr(finding, "finding_type", "spf_include_nxdomain")

        color_map = {
            "spf_include_nxdomain": 0xFFA500,   # orange — broken but not directly exploitable
            "spf_include_takeover": 0xFF0000,   # red — claimable → full email spoofing
            "dmarc_ns_takeover":    0xFF0000,   # red — claimable → policy hijack
        }
        title_map = {
            "spf_include_nxdomain": f"📧 Dangling SPF Include: `{finding.target_domain}`",
            "spf_include_takeover": f"🚨 SPF Include NS Takeover: `{finding.target_domain}`",
            "dmarc_ns_takeover":    f"🚨 DMARC NS Takeover: `{finding.target_domain}`",
        }
        color = color_map.get(finding_type, 0xFFA500)
        title = title_map.get(finding_type, f"📧 SPF/DMARC Issue: `{finding.target_domain}`")

        indicators_text = "\n".join(
            f"• {ind}" for ind in (finding.indicators or [])[:10]
        ) or "none"

        fields = [
            {"name": "Program",       "value": program_name,               "inline": True},
            {"name": "Platform",      "value": platform.upper(),           "inline": True},
            {"name": "Scope Domain",  "value": f"`{finding.scope_domain}`","inline": True},
            {"name": "Target Domain", "value": f"`{finding.target_domain}`","inline": True},
            {"name": "Finding Type",  "value": finding_type,               "inline": True},
            {"name": "Severity",      "value": finding.severity.upper(),   "inline": True},
            {"name": "Detail",        "value": finding.detail[:1000],      "inline": False},
            {"name": "Evidence",      "value": indicators_text,            "inline": False},
        ]

        embed = {
            "title":     title,
            "color":     color,
            "fields":    fields,
            "footer":    {"text": f"STOscanner — SPF/DMARC Scanner • {program_name} ({platform.upper()})"},
            "timestamp": datetime.utcnow().isoformat(),
        }

        webhook = self.webhook_url
        if not webhook:
            return

        payload = {"embeds": [self._truncate_embed(embed)], "username": "STOscanner"}

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(webhook, json=payload, timeout=30.0)
                if response.status_code == 204:
                    logger.info(
                        "spf_dmarc: Discord alert sent for %s (type=%s)",
                        finding.target_domain, finding_type,
                    )
                elif response.status_code == 429:
                    data        = response.json()
                    retry_after = min(float(data.get("retry_after", self.RATE_LIMIT_DELAY)), self.MAX_RETRY_AFTER)
                    await asyncio.sleep(retry_after)
                    await self.notify_spf_dmarc(finding, program_name, platform)
                else:
                    logger.warning(
                        "spf_dmarc: Discord alert failed: %s %s",
                        response.status_code, response.text,
                    )
        except Exception as exc:
            logger.error("spf_dmarc: Discord alert error for %s: %s", finding.target_domain, exc)

    async def notify_dangling_ip(self, finding) -> None:
        """
        Send a Discord embed for a DanglingIPFinding from dns_scanner.

        Three distinct alert types based on finding.finding_type:

          "dangling"       — IP appears unallocated. Cloud provider's pool
                             released it. Includes claim command + confidence.
                             Color: orange (medium) or red (high severity).

          "foreign_cert"   — IP is ALLOCATED, but the TLS cert belongs to a
                             DIFFERENT company. The IP has already been taken.
                             The subdomain's DNS is still pointing there — this
                             is a stale DNS record pointing at someone else's
                             server. Operator must update DNS immediately.
                             Color: purple (distinct — not a claimable finding).

          "cname_dangling" — IP reached via CNAME chain is dangling. Similar
                             to "dangling" but with lower confidence and the
                             CNAME chain shown for context.
                             Color: same as dangling, slightly lower confidence.
        """
        if not self.enabled:
            return

        finding_type = getattr(finding, "finding_type", "dangling")

        # ── Colors and titles per finding type ──────────────────────────────
        _SEV_COLOR = {
            "high":   0xFF4500,
            "medium": 0xFFA500,
            "low":    0xAAAAAA,
        }
        severity  = getattr(finding, "severity", "medium")
        sev_emoji = {"high": "🔴", "medium": "🟠", "low": "🟡"}.get(severity, "⚠️")

        if finding_type == "foreign_cert":
            color = 0x9B59B6   # purple — taken by another company, not claimable
            title = f"🔐 Foreign TLS Cert on Cloud IP: `{finding.ip}`"
            verdict_line = (
                "⚠️ **IP ALREADY TAKEN** — TLS cert on port 443 belongs to a **different company**.\n"
                "The subdomain's DNS is stale and pointing at someone else's server.\n"
                "**Action required**: update DNS to remove the stale A record."
            )
        elif finding_type == "cname_dangling":
            color = _SEV_COLOR.get(severity, 0xFFA500)
            title = f"{sev_emoji} Dangling IP via CNAME Chain: `{finding.ip}`"
            chain_str = " → ".join(finding.cname_chain[:6]) if finding.cname_chain else "?"
            verdict_line = (
                f"✅ **IP APPEARS DANGLING** — reached via CNAME chain\n"
                f"Chain: `{chain_str}`\n"
                f"Confidence: **{finding.confidence}%** (reduced for CNAME-indirect path)"
            )
        elif finding_type == "ipv6_dangling":
            color = _SEV_COLOR.get(severity, 0xFFA500)
            title = f"{sev_emoji} Dangling IPv6 Address [{severity.upper()}]: `{finding.ip}`"
            if finding.cloud_claim_confirmed:
                verdict_line = "✅ **DEFINITIVELY FREE** — direct probe confirmed."
            elif finding.confirmed_free:
                verdict_line = (
                    f"⚠️ **IPv6 ADDRESS APPEARS DANGLING** — no running server detected.\n"
                    f"Confidence: **{finding.confidence}%** (IPv6 port scans are less reliable)"
                )
            else:
                verdict_line = (
                    f"🔍 **IPv6 UNCERTAIN** — inconclusive.\n"
                    f"Confidence: **{finding.confidence}%** — manual verification recommended."
                )
        elif finding_type == "wildcard_a_dangling":
            color = 0xFF0000   # bright red — maximum severity, wildcard scope
            title = f"🚨 WILDCARD A Dangling IP [CRITICAL]: `{finding.ip}`"
            if finding.cloud_claim_confirmed:
                verdict_line = (
                    "✅ **DEFINITIVELY FREE** — direct claim probe **SUCCEEDED**.\n"
                    f"⚡ **WILDCARD IMPACT**: `*.{finding.scope_domain}` A → `{finding.ip}`\n"
                    "Claiming this IP gives control over **EVERY subdomain** simultaneously."
                )
            elif finding.confirmed_free:
                verdict_line = (
                    f"⚠️ **IP APPEARS DANGLING** (confidence={finding.confidence}%)\n"
                    f"⚡ **WILDCARD IMPACT**: `*.{finding.scope_domain}` A → `{finding.ip}`\n"
                    "Claiming this IP gives control over **EVERY subdomain** simultaneously."
                )
            else:
                verdict_line = (
                    f"🔍 **UNCERTAIN** — confidence={finding.confidence}%\n"
                    f"⚡ **WILDCARD SCOPE**: `*.{finding.scope_domain}` A → `{finding.ip}`\n"
                    "Verify manually — wildcard A records warrant special attention."
                )
        else:
            # "dangling" — direct A record
            color = _SEV_COLOR.get(severity, 0xFFA500)
            if finding.cloud_claim_confirmed:
                color = 0x00C851   # green — definitively confirmed
            title = f"{sev_emoji} Dangling Cloud IP [{severity.upper()}]: `{finding.ip}`"
            if finding.cloud_claim_confirmed:
                verdict_line = (
                    "✅ **DEFINITIVELY FREE** — AWS direct claim probe **SUCCEEDED**.\n"
                    "The IP was allocated and immediately released during verification.\n"
                    "This is a confirmed IP takeover opportunity."
                )
            elif finding.confirmed_free:
                verdict_line = (
                    f"⚠️ **IP APPEARS DANGLING** — no running server detected.\n"
                    f"Confidence: **{finding.confidence}%**"
                )
            else:
                verdict_line = (
                    f"🔍 **UNCERTAIN** — inconclusive indicators.\n"
                    f"Confidence: **{finding.confidence}%** — manual verification recommended."
                )

        # ── Build indicator list (capped for embed size) ─────────────────────
        indicators_text = "\n".join(
            f"• {ind}" for ind in finding.indicators[:12]
        )
        if len(finding.indicators) > 12:
            indicators_text += f"\n• … and {len(finding.indicators) - 12} more"
        if not indicators_text:
            indicators_text = "none"

        # ── Claim / action section ────────────────────────────────────────────
        if finding_type == "foreign_cert":
            action_name  = "Required Action"
            action_value = (
                f"1. Verify: `dig +short {finding.subdomain_name}` → `{finding.ip}`\n"
                f"2. Check TLS cert: `openssl s_client -connect {finding.ip}:443 </dev/null 2>/dev/null | openssl x509 -noout -subject`\n"
                f"3. Remove stale DNS A record for `{finding.subdomain_name}`\n"
                f"4. Report stale DNS to the program if in scope"
            )
        else:
            can_claim    = getattr(finding, "claim_possible", False)
            can_specific = getattr(finding, "can_claim_specific", False)
            claim_cmd    = getattr(finding, "claim_cmd", "")
            action_name  = "How to claim / PoC"
            action_value = ""
            if claim_cmd:
                action_value += f"```\n{claim_cmd[:400]}\n```\n"
            if not can_specific:
                action_value += "⚠️ This provider does **not** support requesting a specific IP — race allocation required.\n"
            action_value += (
                f"1. Verify DNS: `dig +short {finding.subdomain_name}` → `{finding.ip}`\n"
                f"2. Use claim command above to allocate the IP\n"
                f"3. Deploy PoC page confirming control of the IP\n"
                f"4. Screenshot DNS + PoC page → submit to BB program\n"
                f"5. Release the IP after report accepted"
            )
            if not can_claim:
                action_value = "⚠️ This provider's IPs are **not directly claimable** via public API — see provider docs."

        # ── TLS cert details (foreign_cert type) ─────────────────────────────
        tls_field = None
        tls_cn    = getattr(finding, "tls_cn", None)
        tls_sans  = getattr(finding, "tls_sans", [])
        if tls_cn or tls_sans:
            tls_val = f"**CN**: `{tls_cn or '?'}`"
            if tls_sans:
                tls_val += "\n**SANs**: " + ", ".join(f"`{s}`" for s in tls_sans[:6])
                if len(tls_sans) > 6:
                    tls_val += f" … +{len(tls_sans) - 6} more"
            tls_field = {"name": "TLS Certificate", "value": tls_val, "inline": False}

        # ── Fields ────────────────────────────────────────────────────────────
        fields = [
            {"name": "Subdomain",   "value": f"`{finding.subdomain_name}`",    "inline": True},
            {"name": "IP",          "value": f"`{finding.ip}`",                "inline": True},
            {"name": "IP Version",  "value": f"IPv{getattr(finding, 'ip_version', 4)}", "inline": True},
            {"name": "Provider",    "value": finding.provider_display,         "inline": True},
            {"name": "Region",      "value": finding.region or "unknown",      "inline": True},
            {"name": "Severity",    "value": severity.upper(),                 "inline": True},
        ]

        # ASN fallback note — shown when CIDR index missed and ASN was used
        if getattr(finding, "asn_lookup_used", False) and getattr(finding, "asn", None):
            fields.append({
                "name":   "⚠️ Provider Detection Method",
                "value":  f"Identified via BGP ASN **{finding.asn}** (Team Cymru lookup) — "
                          f"CIDR index had no entry. Provider match may be less precise.",
                "inline": False,
            })

        # CIDR / ASN range
        cidr_val = getattr(finding, "cidr", "")
        if cidr_val:
            fields.append({"name": "CIDR / Range", "value": f"`{cidr_val}`", "inline": True})

        # PTR record
        ptr = getattr(finding, "ptr_hostname", None)
        if ptr:
            fields.append({"name": "PTR", "value": f"`{ptr}`", "inline": True})

        # HTTP/HTTPS status
        http_s  = getattr(finding, "http_status",  None)
        https_s = getattr(finding, "https_status", None)
        if http_s is not None or https_s is not None:
            fields.append({
                "name":   "HTTP / HTTPS",
                "value":  f"`{http_s or '—'}` / `{https_s or '—'}`",
                "inline": True,
            })

        open_ports = getattr(finding, "open_ports", [])
        if open_ports:
            fields.append({
                "name":   "Open Ports",
                "value":  f"`{', '.join(str(p) for p in open_ports[:20])}`",
                "inline": True,
            })

        # Verdict
        fields.append({"name": "Verdict", "value": verdict_line, "inline": False})

        # Indicators
        fields.append({"name": "Evidence / Indicators", "value": indicators_text, "inline": False})

        # TLS cert (if present)
        if tls_field:
            fields.append(tls_field)

        # Action
        fields.append({"name": action_name, "value": action_value[:1000], "inline": False})

        # Scope / program
        if finding.scope_domain:
            fields.append({
                "name":   "Scope / Program",
                "value":  f"`{finding.scope_domain}` — {finding.program_name} ({finding.platform})",
                "inline": False,
            })

        # CNAME chain (cname_dangling type)
        if finding_type == "cname_dangling" and finding.cname_chain:
            fields.append({
                "name":   "CNAME Chain",
                "value":  " → ".join(f"`{h}`" for h in finding.cname_chain[:8]),
                "inline": False,
            })

        # Wildcard scope annotation (wildcard_a_dangling type)
        if finding_type == "wildcard_a_dangling":
            fields.append({
                "name":   "Wildcard Record",
                "value":  f"`*.{finding.scope_domain}` A → `{finding.ip}`",
                "inline": False,
            })
            fields.append({
                "name":   "Impact",
                "value":  (
                    "⚡ **ALL subdomains** under this scope resolve to this IP.\n"
                    "A single claim gives control over the entire subdomain namespace."
                ),
                "inline": False,
            })

        embed = {
            "title":     title,
            "color":     color,
            "fields":    fields,
            "footer":    {"text": f"STOscanner — DNS Scanner • {finding.provider_key}"},
            "timestamp": datetime.utcnow().isoformat(),
        }

        webhook = self.webhook_url
        payload = {"embeds": [self._truncate_embed(embed)], "username": "STOscanner"}

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(webhook, json=payload, timeout=30.0)
                if response.status_code == 204:
                    logger.info(
                        "dangling_ip: Discord alert sent for %s (type=%s ip=%s)",
                        finding.subdomain_name, finding_type, finding.ip,
                    )
                elif response.status_code == 429:
                    data        = response.json()
                    retry_after = min(
                        float(data.get("retry_after", self.RATE_LIMIT_DELAY)),
                        self.MAX_RETRY_AFTER,
                    )
                    logger.warning(
                        "dangling_ip: Discord rate limited, retrying in %.1fs", retry_after
                    )
                    await asyncio.sleep(retry_after)
                    await self.notify_dangling_ip(finding)
                else:
                    logger.warning(
                        "dangling_ip: Discord alert failed: %s %s",
                        response.status_code, response.text,
                    )
        except Exception as exc:
            logger.error(
                "dangling_ip: Discord alert error for %s: %s", finding.ip, exc
            )