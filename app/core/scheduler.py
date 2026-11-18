"""
Job scheduler for automatic scanning pipeline.
"""

from datetime import datetime, timedelta
from typing import List, Optional

from sqlalchemy import and_, case, or_, select, true, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.db_models import Program, ProgramPlatform, Scope, Subdomain, SubdomainState


def retry_due_clause(now: Optional[datetime] = None):
    """
    SQL predicate for "no retry schedule recorded, or the schedule is due".

    A NULL ``takeover_retry_at`` means no attempt outcome has been recorded yet
    and must not block selection; a future timestamp defers the finding until
    the outcome policy's retry interval elapses.
    """
    now = now or datetime.utcnow()
    return or_(
        Subdomain.takeover_retry_at.is_(None),
        Subdomain.takeover_retry_at <= now,
    )


class Scheduler:
    """Schedules scanning jobs based on program and subdomain state."""

    @staticmethod
    async def get_programs_needing_scan(
        session: AsyncSession,
        limit: Optional[int] = None,
    ) -> List[Program]:
        """Fetch active programs whose scan interval has elapsed or that have
        never been scanned.

        update_program_scan_time is stamped only after all background probe
        tasks complete, so a program with pending work has not been stamped yet
        and passes the interval filter without an extra subquery.
        """
        scan_cutoff    = datetime.utcnow() - timedelta(hours=settings.SCAN_INTERVAL_HOURS)
        effective_limit = limit if limit is not None else getattr(settings, "PROGRAMS_LIMIT_PER_ITERATION", 50)

        # Never-scanned programs: other platforms first, HackerOne last.
        # Once a program has been scanned at least once, normal last_scan_at
        # ordering takes over and this tiebreaker has no effect.
        platform_priority = case(
            (
                and_(
                    Program.last_scan_at.is_(None),
                    Program.platform == ProgramPlatform.HACKERONE,
                ),
                1,
            ),
            else_=0,
        )

        stmt = (
            select(Program)
            .where(
                and_(
                    Program.is_active == true(),
                    or_(
                        Program.last_scan_at.is_(None),
                        Program.last_scan_at < scan_cutoff,
                    ),
                )
            )
            .order_by(platform_priority.asc(), Program.last_scan_at.asc().nullsfirst())
            .limit(effective_limit)
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())

    @staticmethod
    async def get_scopes_needing_scan(
        session: AsyncSession,
        program_id: Optional[int] = None,
        limit: int = 100,
    ) -> List[Scope]:
        """Fetch active scopes whose discovery cooldown has elapsed or that have
        never been scanned. Prevents re-running subfinder/active on restart.
        Uses SCAN_INTERVAL_HOURS as the cooldown — same rhythm as program re-queuing."""
        discovery_cutoff = datetime.utcnow() - timedelta(
            hours=settings.SCAN_INTERVAL_HOURS
        )

        conditions = [
            Scope.is_active == true(),
            or_(
                Scope.last_scanned_at.is_(None),
                Scope.last_scanned_at < discovery_cutoff,
            ),
        ]
        if program_id is not None:
            conditions.append(Scope.program_id == program_id)

        stmt = (
            select(Scope)
            .where(and_(*conditions))
            .order_by(Scope.last_scanned_at.asc().nullsfirst())
            .limit(limit)
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())

    @staticmethod
    async def get_subdomains_needing_scan(
        session: AsyncSession,
        scope_id: Optional[int] = None,
        state: Optional[SubdomainState] = None,
        limit: Optional[int] = None,
    ) -> List[Subdomain]:
        """Fetch subdomains that have never been scanned or are stale."""
        stale_cutoff    = datetime.utcnow() - timedelta(hours=settings.RESCAN_STALE_HOURS)
        effective_limit = limit if limit is not None else getattr(settings, "SUBDOMAINS_LIMIT_PER_SCOPE", 1000)

        conditions = [true()]
        if scope_id is not None:
            conditions.append(Subdomain.scope_id == scope_id)
        if state is not None:
            conditions.append(Subdomain.state == state)

        stmt = (
            select(Subdomain)
            .where(and_(*conditions))
            .where(
                or_(
                    Subdomain.last_scanned_at.is_(None),
                    Subdomain.last_scanned_at < stale_cutoff,
                )
            )
            .order_by(Subdomain.last_scanned_at.asc().nullsfirst())
            .limit(effective_limit)
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())

    @staticmethod
    async def get_potential_subdomains_needing_recheck(
        session: AsyncSession,
        limit: Optional[int] = None,
    ) -> List[Subdomain]:
        """Fetch POTENTIAL subdomains due for a recheck."""
        recheck_cutoff  = datetime.utcnow() - timedelta(hours=settings.POTENTIAL_RECHECK_HOURS)
        effective_limit = limit if limit is not None else getattr(settings, "POTENTIAL_RECHECK_LIMIT", 50)

        stmt = (
            select(Subdomain)
            .where(Subdomain.state == SubdomainState.POTENTIAL)
            .where(
                or_(
                    Subdomain.last_scanned_at.is_(None),
                    Subdomain.last_scanned_at < recheck_cutoff,
                )
            )
            .where(retry_due_clause())
            .order_by(Subdomain.last_scanned_at.asc().nullsfirst())
            .limit(effective_limit)
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())

    @staticmethod
    async def get_potential_long_subdomains_needing_recheck(
        session: AsyncSession,
        limit: Optional[int] = None,
    ) -> List[Subdomain]:
        """Fetch POTENTIAL_LONG subdomains due for a recheck.

        These are ownership-blocked findings (Vercel NEEDS_TXT, Netlify
        domain_claimed_elsewhere) that should only be retried every
        POTENTIAL_LONG_RECHECK_HOURS to avoid spamming provider APIs.
        """
        recheck_cutoff  = datetime.utcnow() - timedelta(hours=settings.POTENTIAL_LONG_RECHECK_HOURS)
        effective_limit = limit if limit is not None else getattr(settings, "POTENTIAL_RECHECK_LIMIT", 50)

        stmt = (
            select(Subdomain)
            .where(Subdomain.state == SubdomainState.POTENTIAL_LONG)
            .where(
                or_(
                    Subdomain.last_scanned_at.is_(None),
                    Subdomain.last_scanned_at < recheck_cutoff,
                )
            )
            .where(retry_due_clause())
            .order_by(Subdomain.last_scanned_at.asc().nullsfirst())
            .limit(effective_limit)
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())

    @staticmethod
    async def get_dangling_subdomains_needing_retry(
        session: AsyncSession,
        limit: Optional[int] = None,
    ) -> List[Subdomain]:
        """
        DANGLING findings whose automatic-attempt retry timestamp is due.

        Only rows that recorded an attempt outcome are selected: ``retry_at``
        carries both the due time and the fact that a provider was tried. The
        ``last_scanned_at`` guard prevents re-probing a finding that was just
        attempted (a probe stamps that column after evaluation).
        """
        now = datetime.utcnow()
        scan_cutoff = now - timedelta(hours=max(1, int(settings.TAKEOVER_RETRY_HOURS)))
        effective_limit = limit if limit is not None else getattr(settings, "POTENTIAL_RECHECK_LIMIT", 50)

        stmt = (
            select(Subdomain)
            .where(Subdomain.state == SubdomainState.DANGLING)
            .where(Subdomain.takeover_retry_at.is_not(None))
            .where(Subdomain.takeover_retry_at <= now)
            .where(
                or_(
                    Subdomain.last_scanned_at.is_(None),
                    Subdomain.last_scanned_at < scan_cutoff,
                )
            )
            .order_by(Subdomain.takeover_retry_at.asc())
            .limit(effective_limit)
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())

    @staticmethod
    async def update_program_scan_time(
        session: AsyncSession,
        program_id: int,
    ) -> None:
        stmt = (
            update(Program)
            .where(Program.id == program_id)
            .values(last_scan_at=datetime.utcnow())
        )
        await session.execute(stmt)

    @staticmethod
    async def update_scope_scan_time(
        session: AsyncSession,
        scope_id: int,
    ) -> None:
        stmt = (
            update(Scope)
            .where(Scope.id == scope_id)
            .values(last_scanned_at=datetime.utcnow())
        )
        await session.execute(stmt)

    @staticmethod
    async def update_subdomain_scan_time(
        session: AsyncSession,
        subdomain_id: int,
    ) -> None:
        stmt = (
            update(Subdomain)
            .where(Subdomain.id == subdomain_id)
            .values(last_scanned_at=datetime.utcnow())
        )
        await session.execute(stmt)

    @staticmethod
    async def update_scope_js_scrape_time(
        session: AsyncSession,
        scope_id: int,
    ) -> None:
        stmt = (
            update(Scope)
            .where(Scope.id == scope_id)
            .values(last_js_scraped_at=datetime.utcnow())
        )
        await session.execute(stmt)
        await session.commit()