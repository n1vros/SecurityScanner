"""
Scheduled resync of the four main bounty platforms.

The daemon runs :func:`run_platform_syncs` on a short poll and lets each
platform's own interval in DAYS decide whether a real API sync is due. The CLI
uses the same code path with ``force=True`` so there is one implementation of
credential checks, adapter loading and state stamping.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Mapping, Optional, Sequence, Set

from sqlalchemy import select

from app.core.config import settings
from app.core.logging import logger
from app.db.db_models import PlatformSyncState
from app.db.session import get_session
from app.programs.loader import get_loader


@dataclass(frozen=True)
class PlatformSyncSpec:
    """Everything the scheduler needs to know about one platform."""

    name: str
    label: str
    interval_setting: str
    credential_settings: tuple[str, ...]


PLATFORM_SPECS: Dict[str, PlatformSyncSpec] = {
    "hackerone": PlatformSyncSpec(
        name="hackerone",
        label="HackerOne",
        interval_setting="HACKERONE_SYNC_INTERVAL_DAYS",
        credential_settings=("H1_USERNAME", "H1_API_TOKEN"),
    ),
    "yeswehack": PlatformSyncSpec(
        name="yeswehack",
        label="YesWeHack",
        interval_setting="YESWEHACK_SYNC_INTERVAL_DAYS",
        credential_settings=("YWH_TOKEN",),
    ),
    "intigriti": PlatformSyncSpec(
        name="intigriti",
        label="Intigriti",
        interval_setting="INTIGRITI_SYNC_INTERVAL_DAYS",
        credential_settings=("INTI_TOKEN",),
    ),
    "bugcrowd": PlatformSyncSpec(
        name="bugcrowd",
        label="Bugcrowd",
        interval_setting="BUGCROWD_SYNC_INTERVAL_DAYS",
        credential_settings=("BC_SESSION",),
    ),
}


@dataclass(frozen=True)
class PlatformSyncResult:
    """Outcome of one platform sync attempt."""

    platform: str
    status: str
    programs: int = 0
    error: Optional[str] = None
    skipped_reason: Optional[str] = None


def platform_interval_days(platform: str) -> float:
    """Return the configured interval for *platform* in days."""
    spec = PLATFORM_SPECS[platform]
    return float(getattr(settings, spec.interval_setting, 7.0))


def credentials_configured(platform: str) -> bool:
    """True when every credential setting required by *platform* is non-empty."""
    spec = PLATFORM_SPECS[platform]
    return all(
        str(getattr(settings, name, "") or "").strip()
        for name in spec.credential_settings
    )


def is_due(
    now: datetime,
    last_synced_at: Optional[datetime],
    interval_days: float,
) -> bool:
    """True when a platform has never synced or its interval has elapsed."""
    if last_synced_at is None:
        return True
    return now - last_synced_at >= timedelta(days=interval_days)


def select_due_platforms(
    states: Mapping[str, Optional[datetime]],
    now: datetime,
    intervals: Mapping[str, float],
) -> List[str]:
    """Return configured platforms that are due, preserving spec order."""
    return [
        name
        for name in PLATFORM_SPECS
        if name in states
        and is_due(now, states.get(name), intervals.get(name, 7.0))
    ]


async def _load_sync_state_times(
    session,
    platform_names: Sequence[str],
) -> Dict[str, Optional[datetime]]:
    result = await session.execute(
        select(
            PlatformSyncState.platform,
            PlatformSyncState.last_synced_at,
        ).where(PlatformSyncState.platform.in_(platform_names))
    )
    values = {row[0]: row[1] for row in result.all()}
    return {name: values.get(name) for name in platform_names}


async def stamp_sync_state(
    session,
    platform: str,
    *,
    status: str,
    now: datetime,
    error: Optional[str] = None,
) -> None:
    """Insert or update the persistent sync bookkeeping row for *platform*."""
    result = await session.execute(
        select(PlatformSyncState).where(PlatformSyncState.platform == platform)
    )
    state = result.scalar_one_or_none()
    if state is None:
        state = PlatformSyncState(platform=platform)
        session.add(state)

    state.last_synced_at = now
    state.last_status = status
    state.last_error = error
    state.updated_at = now
    await session.commit()


async def sync_platform(
    platform: str,
    *,
    cookie_file: Optional[str] = None,
) -> PlatformSyncResult:
    """Load the adapter for one platform and run a program/scope sync."""
    if platform not in PLATFORM_SPECS:
        return PlatformSyncResult(
            platform=platform,
            status="error",
            error=f"unsupported platform: {platform}",
        )

    if not credentials_configured(platform):
        missing = ", ".join(PLATFORM_SPECS[platform].credential_settings)
        return PlatformSyncResult(
            platform=platform,
            status="skipped",
            skipped_reason=f"credentials not configured ({missing})",
        )

    adapter = get_loader().get_platform(platform)
    if adapter is None:
        return PlatformSyncResult(
            platform=platform,
            status="error",
            error="platform adapter is not registered",
        )

    try:
        async with get_session() as session:
            programs = await adapter.sync_programs(session, cookie_file)
        return PlatformSyncResult(
            platform=platform,
            status="success",
            programs=len(programs),
        )
    except Exception as exc:
        logger.error(
            "platform_sync: %s sync failed: %s", platform, exc, exc_info=True
        )
        return PlatformSyncResult(
            platform=platform,
            status="error",
            error=str(exc),
        )
    finally:
        try:
            await adapter.close()
        except Exception as exc:
            logger.debug("platform_sync: %s adapter close failed: %s", platform, exc)


async def run_platform_syncs(
    platform_names: Optional[Sequence[str]] = None,
    *,
    force: bool = False,
    now: Optional[datetime] = None,
    missing_credentials_warned: Optional[Set[str]] = None,
) -> List[PlatformSyncResult]:
    """Sync due (or all, with *force*) platforms, one isolated attempt each.

    A failure on one platform never prevents the others from running. Missing
    credentials are surfaced once per process unless the caller supplies a
    shared warning set to deduplicate the message across polls.
    """
    now = now or datetime.utcnow()
    warned = missing_credentials_warned if missing_credentials_warned is not None else set()

    candidates = list(platform_names or PLATFORM_SPECS.keys())
    unknown = [name for name in candidates if name not in PLATFORM_SPECS]
    if unknown:
        logger.warning("platform_sync: ignoring unsupported platform(s): %s", ", ".join(unknown))
    candidates = [name for name in candidates if name in PLATFORM_SPECS]

    if force:
        due = candidates
    else:
        async with get_session() as session:
            states = await _load_sync_state_times(session, candidates)
        intervals = {name: platform_interval_days(name) for name in candidates}
        due = select_due_platforms(states, now, intervals)

    if not due:
        logger.debug("platform_sync: no platform is due")
        return []

    results: List[PlatformSyncResult] = []
    for name in due:
        if not credentials_configured(name):
            missing = ", ".join(PLATFORM_SPECS[name].credential_settings)
            if name not in warned:
                logger.warning(
                    "platform_sync: skipping %s — credentials not configured (%s)",
                    PLATFORM_SPECS[name].label, missing,
                )
                warned.add(name)
            results.append(PlatformSyncResult(
                platform=name,
                status="skipped",
                skipped_reason=f"credentials not configured ({missing})",
            ))
            continue

        warned.discard(name)
        logger.info("platform_sync: syncing %s", PLATFORM_SPECS[name].label)
        result = await sync_platform(name)
        results.append(result)

        status = "success" if result.status == "success" else "error"
        error = result.error if result.status == "error" else None
        try:
            async with get_session() as session:
                await stamp_sync_state(
                    session,
                    name,
                    status=status,
                    now=now,
                    error=error,
                )
        except Exception as exc:
            logger.error(
                "platform_sync: could not persist %s state: %s", name, exc
            )

        if result.status == "success":
            logger.info(
                "platform_sync: %s synced %d program(s)",
                PLATFORM_SPECS[name].label, result.programs,
            )
        else:
            logger.error(
                "platform_sync: %s failed — %s",
                PLATFORM_SPECS[name].label, result.error,
            )

    return results
