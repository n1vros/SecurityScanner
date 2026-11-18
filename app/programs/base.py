"""
Base class for platform integrations.
"""

import abc
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, List, Optional, Dict, Any, Tuple

from sqlalchemy import func, select, or_, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import logger
from app.db.db_models import Program, ProgramPlatform, Scope, Subdomain, SubdomainState, GitScope
from app.programs.git_scope_utils import parse_git_scope


class PlatformSyncError(RuntimeError):
    """Raised when a platform listing could not be fetched completely."""


@dataclass(frozen=True)
class ScopeState:
    """Snapshot of the DB fields that drive scope reconciliation."""

    domain: str
    is_active: bool
    manually_deactivated: bool


@dataclass(frozen=True)
class ScopeDiff:
    """Pure reconciliation result for one program's scope listing."""

    added: Tuple[str, ...]
    reactivated: Tuple[str, ...]
    deactivated: Tuple[str, ...]
    manually_kept: Tuple[str, ...]


def diff_scope_listing(
    existing: Iterable[ScopeState],
    incoming: Iterable[str],
    *,
    allow_deactivation: bool = True,
) -> ScopeDiff:
    """Compute scope actions without touching the database.

    Rules:
      - unknown domain -> add active;
      - known, inactive, not manual -> reactivate;
      - known, manual -> never touch (operator-excluded);
      - known, active, absent from listing -> deactivate when allowed.
    """
    existing_map = {state.domain: state for state in existing}
    incoming_order: List[str] = []
    incoming_set = set()
    for domain in incoming:
        if domain and domain not in incoming_set:
            incoming_set.add(domain)
            incoming_order.append(domain)

    added: List[str] = []
    reactivated: List[str] = []
    manually_kept: List[str] = []

    for domain in incoming_order:
        state = existing_map.get(domain)
        if state is None:
            added.append(domain)
        elif state.manually_deactivated:
            manually_kept.append(domain)
        elif not state.is_active:
            reactivated.append(domain)

    deactivated = [
        domain
        for domain, state in existing_map.items()
        if allow_deactivation
        and domain not in incoming_set
        and state.is_active
        and not state.manually_deactivated
    ]

    return ScopeDiff(
        added=tuple(added),
        reactivated=tuple(reactivated),
        deactivated=tuple(deactivated),
        manually_kept=tuple(manually_kept),
    )


def missing_program_ids(
    active_program_ids: Iterable[int],
    seen_program_ids: Iterable[int],
) -> Tuple[int, ...]:
    """Return active program ids that were absent from a complete listing."""
    seen = set(seen_program_ids)
    return tuple(pid for pid in active_program_ids if pid not in seen)


class PlatformBase(abc.ABC):
    """Abstract base class for bug bounty platform integrations."""

    platform: ProgramPlatform

    # Set by adapters while fetch_programs() runs. A fatal error aborts the sync
    # before any DB writes; a partial fetch still imports new scopes but skips
    # all removals so one failed page cannot deactivate a program.
    fetch_error: Optional[str] = None
    partial_fetch: bool = False
    listing_complete: bool = True

    @abc.abstractmethod
    async def fetch_programs(
        self,
        session: AsyncSession,
        cookie_file: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Fetch programs from the platform.

        Returns list of program dicts with keys:
          name:               str
          external_id:        Optional[str]
          url:                Optional[str]
          scopes:             List[str] (domains)
          git_scopes:         List[str] (GitHub/GitLab URLs) — optional key
          scope_fetch_failed: bool — set when the scope request failed, so the
                              program is kept but its existing scopes are not
                              reconciled as "removed".
        """
        pass

    @abc.abstractmethod
    async def authenticate(self, cookie_file: Optional[str]) -> Dict[str, Any]:
        """Verify authentication with the platform."""
        pass

    async def sync_programs(
        self,
        session: AsyncSession,
        cookie_file: Optional[str] = None,
    ) -> List[Program]:
        """Sync programs from platform to database.

        Reconciliation is all-or-nothing per platform: a fatal listing error
        aborts before any write, and a partial fetch (one failed page or scope
        request) imports additions but applies no removals. Only a complete,
        non-empty listing may deactivate programs or scopes that disappeared.
        """
        logger.info("Syncing programs from %s", self.platform.value)

        self.fetch_error = None
        self.partial_fetch = False
        self.listing_complete = True

        programs_data = await self.fetch_programs(session, cookie_file)

        if self.fetch_error:
            raise PlatformSyncError(self.fetch_error)

        if any(data.get("scope_fetch_failed") for data in programs_data):
            self.partial_fetch = True

        # Never treat an empty successful response as "every program vanished":
        # an auth/schema quirk would otherwise wipe the whole platform.
        allow_deactivation = (
            not self.partial_fetch
            and self.listing_complete
            and bool(programs_data)
        )
        if not allow_deactivation:
            logger.warning(
                "%s: removals skipped (partial fetch or empty listing)",
                self.platform.value,
            )

        synced = []
        seen_ids = set()
        total_new_domains = 0
        total_new_git_scopes = 0

        for data in programs_data:
            program = await self._create_or_update_program(session, data)
            if not program:
                continue

            synced.append(program)
            seen_ids.add(program.id)

            if data.get("scope_fetch_failed"):
                logger.warning(
                    "%s [%s]: scope fetch failed — existing scopes left untouched",
                    self.platform.value, program.name,
                )
            else:
                total_new_domains += await self._sync_scopes_with_deduplication(
                    session,
                    program,
                    data.get("scopes", []),
                    allow_deactivation=allow_deactivation,
                )

            # Sync git scopes if the platform adapter provided them
            git_scope_urls = data.get("git_scopes", [])
            if git_scope_urls:
                total_new_git_scopes += await self._sync_git_scopes(
                    session, program, git_scope_urls
                )

        removed_programs = 0
        if allow_deactivation:
            removed_programs = await self._deactivate_missing_programs(
                session, seen_ids
            )

        logger.info(
            "Synced %d programs from %s — %d new domain scope(s), %d new git "
            "scope(s), %d deactivated program(s)",
            len(synced), self.platform.value, total_new_domains,
            total_new_git_scopes, removed_programs,
        )
        return synced

    async def _create_or_update_program(
        self,
        session: AsyncSession,
        data: Dict[str, Any],
    ) -> Optional[Program]:
        """
        Create or update a program in the database.

        Lookup is scoped to self.platform so the same external_id (slug)
        on different programs never collides — e.g. 'nextcloud' on both
        HackerOne and YesWeHack are two distinct programs.
        """
        external_id = data.get("external_id")
        name        = data["name"]

        # Build lookup conditions — always filter by platform first
        conditions = [Program.platform == self.platform]
        if external_id:
            # Prefer external_id match; fall back to name within same platform
            conditions.append(
                or_(
                    Program.external_id == external_id,
                    Program.name == name,
                )
            )
        else:
            conditions.append(Program.name == name)

        stmt   = select(Program).where(*conditions)
        result = await session.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing:
            existing.name        = name
            existing.url         = data.get("url")
            existing.external_id = external_id
            existing.updated_at  = datetime.utcnow()

            # A program removed by the platform is re-activated when it
            # reappears, unless the operator excluded every scope via
            # deactivate-program (all scopes carry manually_deactivated=True).
            if not existing.is_active and await self._program_is_operator_excluded(
                session, existing
            ) is False:
                existing.is_active = True
                logger.info(
                    "Reactivated program: %s (%s)", name, self.platform.value
                )

            program = existing
            logger.debug("Updated program: %s (%s)", name, self.platform.value)
        else:
            program = Program(
                name=name,
                platform=self.platform,
                external_id=external_id,
                url=data.get("url"),
            )
            session.add(program)
            logger.debug("Created program: %s (%s)", name, self.platform.value)

        await session.commit()

        return program

    async def _program_is_operator_excluded(
        self,
        session: AsyncSession,
        program: Program,
    ) -> bool:
        """True when every scope was excluded by the operator, not by sync.

        ``deactivate-program`` marks all child scopes manually_deactivated. That
        is the only durable signal distinguishing an operator exclusion from an
        automatic removal, because Program has no manual flag.
        """
        total = await session.scalar(
            select(func.count()).select_from(Scope).where(
                Scope.program_id == program.id
            )
        )
        manual = await session.scalar(
            select(func.count()).select_from(Scope).where(
                Scope.program_id == program.id,
                Scope.manually_deactivated.is_(True),
            )
        )
        return bool(total) and manual == total

    async def _sync_scopes_with_deduplication(
        self,
        session: AsyncSession,
        program: Program,
        domains: List[str],
        *,
        allow_deactivation: bool = True,
    ) -> int:
        """
        Canonical scope sync used by all platforms.

        Rules
        -----
        - Scopes with manually_deactivated=True are NEVER touched by this
          method. They were explicitly excluded by the operator via the CLI
          (out-of-scope, owned infra, etc.) and must not be re-activated even
          if the platform still lists them.
        - Newly discovered scopes that weren't in the platform listing before
          are added as active. Auto-deactivated scopes (a domain that
          temporarily disappeared from a program) are re-activated.
        - Scopes that disappear from the provider listing are set is_active=False
          AND all their child subdomains are set to DEAD so they stop appearing
          as live findings in the UI and the scan queue. This is skipped for
          partial listings because absence is not trustworthy then.

        Returns count of newly added/re-activated scope domains.
        """
        # Fetch ALL scope rows for this program (active, inactive, manually
        # deactivated) so the pure diff sees the complete state.
        result = await session.execute(
            select(Scope).where(Scope.program_id == program.id)
        )
        scopes_by_domain: Dict[str, Scope] = {
            scope.domain: scope for scope in result.scalars().all()
        }

        diff = diff_scope_listing(
            (
                ScopeState(
                    domain=scope.domain,
                    is_active=scope.is_active,
                    manually_deactivated=scope.manually_deactivated,
                )
                for scope in scopes_by_domain.values()
            ),
            domains,
            allow_deactivation=allow_deactivation,
        )

        for domain in diff.added:
            session.add(Scope(
                program_id=program.id,
                domain=domain,
                added_at=datetime.utcnow(),
                is_active=True,
            ))

        reactivated_ids = [
            scopes_by_domain[domain].id for domain in diff.reactivated
        ]
        for domain in diff.reactivated:
            scopes_by_domain[domain].is_active = True

        # DEAD is terminal in StateManager, so a scope that comes back would
        # otherwise stay invisible forever. Reset only the children that the
        # removal path marked DEAD; FALSE_POSITIVE/CLAIMED findings keep their
        # verdict and last_scanned_at is cleared to put them back in the queue.
        if reactivated_ids:
            await session.execute(
                update(Subdomain)
                .where(
                    Subdomain.scope_id.in_(reactivated_ids),
                    Subdomain.state == SubdomainState.DEAD,
                )
                .values(
                    state=SubdomainState.DISCOVERED,
                    last_scanned_at=None,
                )
            )

        deactivated_ids = [
            scopes_by_domain[domain].id for domain in diff.deactivated
        ]
        if deactivated_ids:
            await session.execute(
                update(Subdomain)
                .where(Subdomain.scope_id.in_(deactivated_ids))
                .values(state=SubdomainState.DEAD)
            )
            for domain in diff.deactivated:
                scopes_by_domain[domain].is_active = False

        await session.commit()

        new_count = len(diff.added) + len(diff.reactivated)
        if new_count or deactivated_ids or diff.manually_kept:
            logger.info(
                "Scope sync for %s/%s: %d added, %d reactivated, %d "
                "deactivated, %d manually excluded kept",
                self.platform.value,
                program.name,
                len(diff.added),
                len(diff.reactivated),
                len(diff.deactivated),
                len(diff.manually_kept),
            )

        return new_count

    async def _deactivate_missing_programs(
        self,
        session: AsyncSession,
        seen_program_ids: set,
    ) -> int:
        """Deactivate programs that a complete listing no longer contains.

        Their scopes stop being active and every child subdomain is marked DEAD
        so the program leaves the scan queue and the findings UI. Rows are kept
        for history. manually_deactivated scope rows stay inactive.
        """
        # Only rows previously created by an API sync are reconciled. Manually
        # added programs (external_id IS NULL) may legitimately be absent from
        # the platform's public listing — e.g. private/invited engagements.
        result = await session.execute(
            select(Program.id).where(
                Program.platform == self.platform,
                Program.is_active.is_(True),
                Program.external_id.is_not(None),
            )
        )
        active_ids = [row[0] for row in result.all()]
        missing_ids = missing_program_ids(active_ids, seen_program_ids)
        if not missing_ids:
            return 0

        scope_ids_result = await session.execute(
            select(Scope.id).where(Scope.program_id.in_(missing_ids))
        )
        scope_ids = [row[0] for row in scope_ids_result.all()]

        if scope_ids:
            await session.execute(
                update(Subdomain)
                .where(Subdomain.scope_id.in_(scope_ids))
                .values(state=SubdomainState.DEAD)
            )
            await session.execute(
                update(Scope)
                .where(Scope.program_id.in_(missing_ids))
                .values(is_active=False)
            )

        await session.execute(
            update(Program)
            .where(Program.id.in_(missing_ids))
            .values(is_active=False)
        )
        await session.commit()

        logger.info(
            "%s: deactivated %d program(s) missing from listing (%d scope(s), "
            "all child subdomains -> DEAD)",
            self.platform.value, len(missing_ids), len(scope_ids),
        )
        return len(missing_ids)

    async def _sync_git_scopes(
        self,
        session: AsyncSession,
        program: Program,
        git_scope_urls: List[str],
    ) -> int:
        """
        Upsert git scopes for a program.

        New scope URLs are inserted. Existing ones are left untouched
        (we never deactivate git scopes based on platform sync — they're additive).

        Returns count of newly inserted git scopes.
        """
        if not git_scope_urls:
            return 0

        # Fetch all existing git scopes for this program
        result = await session.execute(
            select(GitScope).where(
                GitScope.program_id == program.id,
                GitScope.is_active.is_(True),
            )
        )
        existing_urls = {gs.repo_url for gs in result.scalars().all()}

        new_count = 0
        for raw_url in git_scope_urls:
            parsed = parse_git_scope(raw_url)
            if not parsed:
                continue

            repo_url = parsed["repo_url"]
            if repo_url in existing_urls:
                continue

            session.add(GitScope(
                program_id=program.id,
                repo_url=repo_url,
                platform=parsed["platform"],
                is_wildcard=parsed["is_wildcard"],
                added_at=datetime.utcnow(),
            ))
            existing_urls.add(repo_url)
            new_count += 1
            logger.debug(
                "git_scope: added %s for program %s (wildcard=%s)",
                repo_url, program.name, parsed["is_wildcard"],
            )

        if new_count:
            await session.commit()
            logger.info(
                "git_scope: %d new git scope(s) for %s", new_count, program.name
            )

        return new_count

    async def close(self):
        pass