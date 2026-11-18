"""
CLI for STOscanner administration.
"""

import asyncio
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table

from app.core.config import settings
from app.core.logging import setup_logging
from app.core.process_control import process_controller
from app.db.session import get_session, create_tables
from app.programs.base import PlatformSyncError
from app.programs.loader import get_loader

app = typer.Typer(help="STOscanner Administration CLI")
console = Console()


@app.command()
def programs_add(
    file: Path = typer.Argument(..., help="Path to JSON file containing programs to import"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Parse and validate without writing to DB"),
):
    """
    Bulk-import programs and scopes from a JSON file.

    JSON format:
      [
        {
          "name": "Example Corp",
          "platform": "manual",
          "url": "https://example.com/security",
          "scopes": ["example.com", "api.example.com", "*.example.com"]
        },
        ...
      ]

    Run with --dry-run to validate the file without touching the database.
    """
    asyncio.run(_programs_add(file, dry_run))


@app.command()
def add_program(
    name: str = typer.Argument(..., help="Program name"),
    platform: str = typer.Option("manual", help="Platform: hackerone, bugcrowd, yeswehack, intigriti, immunefi, bugbase, hackenproof, self_hosted, manual"),
    scopes: str = typer.Option("", help="Comma-separated list of domains"),
):
    asyncio.run(_add_program(name, platform, scopes))


@app.command()
def update_scope(
    program_id: int = typer.Argument(..., help="Program ID"),
    domain: str = typer.Argument(..., help="Domain to add"),
):
    """Add a scope domain to an existing program."""
    asyncio.run(_update_scope(program_id, domain))


@app.command()
def deactivate_scope(
    domains: List[str] = typer.Argument(..., help="One or more scope domains to permanently deactivate"),
):
    """
    Permanently deactivate one or more scope domains and all their subdomains.

    Scopes deactivated this way are marked manually_deactivated=True and will
    NEVER be re-activated by automated platform syncs, even if the platform
    still lists them as in-scope.

    All child subdomains are set to DEAD state so they vanish from the scan
    queue and the web UI.

    Example:
        stoscanner deactivate-scope example.com api.example.com staging.example.com
    """
    asyncio.run(_deactivate_scopes(list(domains)))


@app.command()
def deactivate_program(
    program_name: str = typer.Argument(..., help="Exact program name to permanently deactivate"),
):
    """
    Permanently deactivate a program and ALL its scopes (and their subdomains).

    The program is marked is_active=False.  Every scope belonging to it is set
    manually_deactivated=True so automated platform syncs will NEVER re-enable
    them.  All child subdomains are moved to DEAD state so they vanish from the
    scan queue and the web UI.

    Example:
        stoscanner deactivate-program "Example Corp"
    """
    asyncio.run(_deactivate_program(program_name))


@app.command()
def ingest_platform(
    platform: str = typer.Argument(..., help="Platform: hackerone, bugcrowd, yeswehack, intigriti, hackenproof"),
    cookie_file: Optional[Path] = typer.Option(None, help="Path to cookie file"),
):
    """Ingest programs from a bug bounty platform."""
    asyncio.run(_ingest_platform(platform, cookie_file))


@app.command()
def hackerone(
    cookie_file: Optional[Path] = typer.Option(None, help="Path to cookie file (optional)"),
):
    """Sync programs from HackerOne API using credentials from .env."""
    console.print("[cyan]Syncing HackerOne programs...[/cyan]")
    asyncio.run(_sync_hackerone(cookie_file))


@app.command()
def bugcrowd(
    cookie_file: Optional[Path] = typer.Option(None, help="Path to cookie file (optional)"),
):
    """Sync programs from Bugcrowd using BC_SESSION cookie from .env."""
    console.print("[cyan]Syncing Bugcrowd programs...[/cyan]")
    asyncio.run(_sync_bugcrowd(cookie_file))


@app.command()
def ywh(
    cookie_file: Optional[Path] = typer.Option(None, help="Path to cookie file (optional)"),
):
    """Sync programs from YesWeHack using credentials from .env."""
    console.print("[cyan]Syncing YesWeHack programs...[/cyan]")
    asyncio.run(_sync_ywh(cookie_file))


@app.command()
def intigriti(
    cookie_file: Optional[Path] = typer.Option(None, help="Path to cookie file (optional)"),
):
    """Sync programs from Intigriti using credentials from .env."""
    console.print("[cyan]Syncing Intigriti programs...[/cyan]")
    asyncio.run(_sync_intigriti(cookie_file))


@app.command()
def immunefi():
    """Sync programs from Immunefi (no credentials required)."""
    console.print("[cyan]Syncing Immunefi programs...[/cyan]")
    asyncio.run(_sync_immunefi())


@app.command()
def bugbase():
    """Sync programs from BugBase (no credentials required)."""
    console.print("[cyan]Syncing BugBase programs...[/cyan]")
    asyncio.run(_sync_bugbase())


@app.command()
def hackenproof(
    cookie_file: Optional[Path] = typer.Option(None, help="Path to cookie file (optional)"),
):
    """Sync programs from HackenProof using HP_CF_CLEARANCE and HP_REMEMBER_USER_TOKEN from .env."""
    console.print("[cyan]Syncing HackenProof programs...[/cyan]")
    asyncio.run(_sync_hackenproof(cookie_file))


@app.command()
def disclosio():
    """Sync self-hosted bounty programs from disclose.io (no credentials required)."""
    console.print("[cyan]Syncing disclose.io programs...[/cyan]")
    asyncio.run(_sync_disclosio())


@app.command()
def bugbountydirectory():
    """Sync self-hosted bounty programs from BugBountyDirectory.com (no credentials required)."""
    console.print("[cyan]Syncing BugBountyDirectory programs...[/cyan]")
    asyncio.run(_sync_bugbountydirectory())


@app.command("sync-platforms")
def sync_platforms(
    platform: Optional[str] = typer.Option(
        None,
        "--platform",
        help="Only sync this platform (hackerone, yeswehack, intigriti, bugcrowd)",
    ),
):
    """
    Resync programs and scopes from the configured bounty platforms now.

    Uses the same credential checks, adapter loading, reconciliation and
    PlatformSyncState bookkeeping as the daemon's automatic loop. Platforms
    without credentials are skipped; the per-platform commands remain
    available for one-off imports.
    """
    asyncio.run(_sync_platforms(platform))


@app.command("clear-all-ip")
def clear_all_ip(
    providers: List[str] = typer.Argument(
        ...,
        help="One or more providers to clean: aws  azure  do  gcp",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run",
        help="List IPs that would be released without actually releasing them.",
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y",
        help="Skip the confirmation prompt.",
    ),
    sto_only: bool = typer.Option(
        True, "--sto-only/--all",
        help=(
            "AWS/DO: --sto-only (default) only touches EIPs tagged sto-scanner=true (AWS) "
            "or unassociated IPs in configured regions (DO). "
            "Use --all to widen the filter — prints an extra warning."
        ),
    ),
):
    """
    Release / delete all scanner-created reserved IPs across cloud providers.

    Examples
    --------
      python3 main.py clear-all-ip gcp do
      python3 main.py clear-all-ip aws azure gcp do --dry-run
      python3 main.py clear-all-ip aws --all --yes
    """
    valid = ("aws", "azure", "gcp", "do")
    bad   = [p for p in providers if p.lower() not in valid]
    if bad:
        console.print(
            f"[red]Unknown provider(s): {', '.join(bad)}[/red]\n"
            f"Valid choices: {', '.join(valid)}"
        )
        raise typer.Exit(1)

    mode = "[yellow]DRY RUN[/yellow] — no IPs will be released" if dry_run else "[red]LIVE RUN[/red]"
    console.print(f"\n[bold]Cloud IP Cleaner[/bold]   {mode}")
    console.print(f"Providers : [cyan]{', '.join(p.upper() for p in providers)}[/cyan]")

    if not sto_only:
        console.print(
            "[bold red]WARNING:[/bold red] --all mode for AWS will release "
            "[bold]every[/bold] unassociated EIP in the configured regions, "
            "including any not created by this scanner."
        )

    if not dry_run and not yes:
        typer.confirm(
            "\nThis will permanently release the IPs listed above. Continue?",
            abort=True,
        )

    asyncio.run(_clear_all_ip(providers, dry_run=dry_run, sto_only=sto_only))


@app.command()
def status():
    """Show system status and statistics."""
    asyncio.run(_show_status())


@app.command()
def pause():
    """Pause automatic scanning (creates a lock file)."""
    lock_file = Path("scan.pause")
    lock_file.touch()
    console.print(f"[yellow]Scanning paused. Lock file created: {lock_file}[/yellow]")


@app.command()
def resume():
    """Resume automatic scanning (removes lock file)."""
    lock_file = Path("scan.pause")
    if lock_file.exists():
        lock_file.unlink()
        console.print("[green]Scanning resumed. Lock file removed.[/green]")
    else:
        console.print("[yellow]No lock file found. Scanning is already active.[/yellow]")


@app.command()
def start():
    """Start the scanner daemon in the background."""
    result = process_controller.start()
    if result.get("success"):
        console.print(f"[green]Daemon started[/green] (PID {result['pid']})")
        console.print(f"Log: {result['log_file']}")
        console.print(f"PID file: {result['pid_file']}")
    else:
        console.print(f"[yellow]{result.get('message', 'Failed to start daemon')}[/yellow]")
        raise typer.Exit(code=1)


@app.command()
def stop():
    """Stop the scanner daemon, however it was started."""
    result = process_controller.stop()
    if result.get("success"):
        console.print(f"[green]{result['message']}[/green]")
        return
    console.print(f"[yellow]{result.get('message', 'Daemon is not running')}[/yellow]")
    # A daemon that is simply not running is a normal no-op; a daemon we
    # found but could not stop is a real failure.
    if result.get("pid") is not None:
        raise typer.Exit(code=1)


@app.command("daemon-status")
def daemon_status():
    """Show whether the background daemon is running."""
    status = process_controller.status()
    if status["running"]:
        console.print(f"[green]running[/green] (PID {status['pid']})")
        if status.get("uptime_seconds") is not None:
            console.print(f"Uptime: {_format_uptime(status['uptime_seconds'])}")
        if status.get("started_at"):
            console.print(f"Started: {status['started_at']}")
    else:
        console.print("[yellow]stopped[/yellow]")
    console.print(f"PID file: {status['pid_file']}")
    console.print(f"Log: {status['log_file']}")


def _format_uptime(seconds: int) -> str:
    minutes, seconds = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    parts.append(f"{seconds}s")
    return " ".join(parts)


@app.command()
def daemon(
    max_iterations: Optional[int] = typer.Option(None, help="Maximum iterations before stopping"),
):
    """Start the scanning daemon in the foreground."""
    from app.core.daemon import Daemon

    if max_iterations:
        import os
        os.environ["DAEMON_MAX_ITERATIONS"] = str(max_iterations)

    console.print("[green]Starting STOscanner daemon...[/green]")
    daemon = Daemon()
    asyncio.run(daemon.run())


# ---------------------------------------------------------------------------
# Async helpers
# ---------------------------------------------------------------------------

async def _programs_add(file: Path, dry_run: bool):
    """Delegate to ManualPlatform.parse_file + import_programs."""
    from app.programs.platforms.manual import ManualPlatform

    programs, errors = ManualPlatform.parse_file(file)

    for err in errors:
        console.print(f"[yellow]  ! {err}[/yellow]")

    console.print(f"[cyan]Parsed {len(programs)} valid programs, {len(errors)} skipped[/cyan]")

    if not programs:
        console.print("[red]Nothing to import.[/red]")
        raise typer.Exit(1)

    if dry_run:
        console.print("\n[bold yellow]--- DRY RUN (no DB writes) ---[/bold yellow]")
        for p in programs:
            preview = ", ".join(p["scopes"][:5])
            suffix  = " ..." if len(p["scopes"]) > 5 else ""
            console.print(
                f"  [green]{p['name']}[/green] ({p['platform'].value}) "
                f"— {len(p['scopes'])} domains: {preview}{suffix}"
            )
        return

    async with get_session() as session:
        new_p, new_s = await ManualPlatform.import_programs(session, programs)

    console.print(f"[green]Done — {new_p} new programs, {new_s} new scopes added[/green]")


async def _add_program(name: str, platform: str, scopes: str):
    """Add a program to the database."""
    from app.db.db_models import Program, ProgramPlatform, Scope
    from datetime import datetime

    async with get_session() as session:
        program = Program(
            name=name,
            platform=ProgramPlatform(platform.lower()),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        session.add(program)
        await session.commit()

        scope_list = []
        if scopes:
            scope_list = [s.strip() for s in scopes.split(",") if s.strip()]
            for domain in scope_list:
                session.add(Scope(
                    program_id=program.id,
                    domain=domain,
                    added_at=datetime.utcnow(),
                ))

        await session.commit()

        console.print(f"[green]Added program: {name} (ID: {program.id})[/green]")
        if scope_list:
            console.print(f"[green]Added scopes: {', '.join(scope_list)}[/green]")


async def _update_scope(program_id: int, domain: str):
    """Add a scope to a program."""
    from app.db.db_models import Scope
    from sqlalchemy import select
    from datetime import datetime

    async with get_session() as session:
        stmt = select(Scope).where(
            Scope.program_id == program_id,
            Scope.domain == domain,
        )
        result = await session.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing:
            console.print(f"[yellow]Scope already exists: {domain}[/yellow]")
            return

        session.add(Scope(
            program_id=program_id,
            domain=domain,
            added_at=datetime.utcnow(),
        ))
        await session.commit()
        console.print(f"[green]Added scope: {domain} to program {program_id}[/green]")


async def _deactivate_scopes(domains: List[str]) -> None:
    """
    Permanently deactivate scope domains and all linked subdomains.

    Sets manually_deactivated=True on each scope so automated platform syncs
    will never re-enable them, even if the platform still lists them as in-scope.
    All child subdomains are moved to DEAD state.
    """
    from sqlalchemy import select, update
    from app.db.db_models import Scope, Subdomain, SubdomainState
    from datetime import datetime

    if not domains:
        console.print("[yellow]No domains provided.[/yellow]")
        return

    async with get_session() as session:
        deactivated: List[str] = []
        already_manual: List[str] = []
        not_found: List[str] = []

        for domain in domains:
            result = await session.execute(
                select(Scope).where(Scope.domain == domain)
            )
            scope = result.scalar_one_or_none()

            if not scope:
                not_found.append(domain)
                continue

            if scope.manually_deactivated:
                already_manual.append(domain)
                # Still ensure subdomains are dead (idempotent)
                await session.execute(
                    update(Subdomain)
                    .where(Subdomain.scope_id == scope.id)
                    .values(state=SubdomainState.DEAD)
                )
                continue

            # Mark as permanently manually deactivated
            scope.is_active           = False
            scope.manually_deactivated = True

            # Kill all child subdomains
            await session.execute(
                update(Subdomain)
                .where(Subdomain.scope_id == scope.id)
                .values(state=SubdomainState.DEAD)
            )
            deactivated.append(domain)

        await session.commit()

    if deactivated:
        console.print(
            f"[green]✓ Permanently deactivated {len(deactivated)} scope(s) "
            f"(+ all subdomains → DEAD):[/green]"
        )
        for d in deactivated:
            console.print(f"  [yellow]  {d}[/yellow]")

    if already_manual:
        console.print(f"[yellow]Already manually deactivated ({len(already_manual)}):[/yellow]")
        for d in already_manual:
            console.print(f"  [dim]  {d}[/dim]")

    if not_found:
        console.print(f"[red]✗ Not found in DB ({len(not_found)}):[/red]")
        for d in not_found:
            console.print(f"  [red]  {d}[/red]")


async def _deactivate_program(program_name: str) -> None:
    """
    Permanently deactivate a program by name and all its scopes + subdomains.

    - Program.is_active         → False
    - Scope.is_active           → False  (for every scope of that program)
    - Scope.manually_deactivated → True  (prevents re-activation by platform syncs)
    - Subdomain.state           → DEAD   (for every subdomain of those scopes)
    """
    from sqlalchemy import select, update
    from app.db.db_models import Program, Scope, Subdomain, SubdomainState

    async with get_session() as session:
        # ── 1. Look up the program ────────────────────────────────────────────
        result = await session.execute(
            select(Program).where(Program.name == program_name)
        )
        program = result.scalar_one_or_none()

        if not program:
            console.print(f"[red]✗ Program not found: '{program_name}'[/red]")
            raise typer.Exit(1)

        if not program.is_active:
            console.print(f"[yellow]Program '{program_name}' is already inactive.[/yellow]")
            # Fall through so scopes/subdomains are guaranteed to be dead too.

        # ── 2. Fetch all scopes for this program ──────────────────────────────
        result = await session.execute(
            select(Scope).where(Scope.program_id == program.id)
        )
        scopes = result.scalars().all()
        scope_ids = [s.id for s in scopes]

        # ── 3. Kill all subdomains belonging to those scopes ──────────────────
        if scope_ids:
            await session.execute(
                update(Subdomain)
                .where(Subdomain.scope_id.in_(scope_ids))
                .values(state=SubdomainState.DEAD)
            )

        # ── 4. Mark every scope as permanently deactivated ────────────────────
        if scope_ids:
            await session.execute(
                update(Scope)
                .where(Scope.program_id == program.id)
                .values(is_active=False, manually_deactivated=True)
            )

        # ── 5. Deactivate the program itself ──────────────────────────────────
        program.is_active = False

        await session.commit()

    console.print(
        f"[green]✓ Program '[bold]{program_name}[/bold]' permanently deactivated.[/green]"
    )
    console.print(
        f"[green]  {len(scopes)} scope(s) marked manually_deactivated=True "
        f"(+ all subdomains → DEAD)[/green]"
    )


async def _sync_platforms(platform: Optional[str]):
    """Resync one or all configured platforms through the shared sync path."""
    from app.programs.sync import PLATFORM_SPECS, run_platform_syncs

    if platform and platform.lower() not in PLATFORM_SPECS:
        console.print(
            f"[red]Unknown platform: {platform}. "
            f"Choose from: {', '.join(PLATFORM_SPECS)}[/red]"
        )
        return

    names = [platform.lower()] if platform else list(PLATFORM_SPECS)
    await create_tables()
    results = await run_platform_syncs(names, force=True)

    table = Table(title="Platform sync")
    table.add_column("Platform")
    table.add_column("Status")
    table.add_column("Programs", justify="right")
    table.add_column("Detail")

    for result in results:
        label = PLATFORM_SPECS[result.platform].label
        detail = result.skipped_reason or result.error or ""
        color = {
            "success": "green",
            "error": "red",
            "skipped": "yellow",
        }.get(result.status, "white")
        table.add_row(
            label,
            f"[{color}]{result.status}[/{color}]",
            str(result.programs),
            detail,
        )

    console.print(table)


async def _ingest_platform(platform: str, cookie_file: Optional[Path]):
    """Ingest programs from a platform."""
    loader = get_loader()
    platform_obj = loader.get_platform(platform)
    if not platform_obj:
        console.print(f"[red]Unknown platform: {platform}[/red]")
        return

    cookie_path = str(cookie_file) if cookie_file else None
    async with get_session() as session:
        try:
            programs = await platform_obj.sync_programs(session, cookie_path)
        except PlatformSyncError as exc:
            console.print(f"[red]Sync failed for {platform}: {exc}[/red]")
            return
        console.print(f"[green]Synced {len(programs)} programs from {platform}[/green]")


async def _sync_hackerone(cookie_file: Optional[Path]):
    """Sync HackerOne programs using credentials from .env."""
    loader = get_loader()
    platform_obj = loader.get_platform("hackerone")
    if not platform_obj:
        console.print("[red]HackerOne platform not available[/red]")
        return

    if not settings.H1_USERNAME or not settings.H1_API_TOKEN:
        console.print("[red]H1_USERNAME and H1_API_TOKEN must be set in .env[/red]")
        return

    cookie_path = str(cookie_file) if cookie_file else None

    async with get_session() as session:
        console.print("[cyan]Authenticating with HackerOne API...[/cyan]")
        auth_result = await platform_obj.authenticate(cookie_path)
        if not auth_result.get("authenticated"):
            console.print(f"[red]Authentication failed: {auth_result.get('error', 'Unknown error')}[/red]")
            return

        console.print("[green]Authentication successful[/green]")
        console.print("[cyan]Fetching programs from HackerOne...[/cyan]")

        try:
            programs = await platform_obj.sync_programs(session, cookie_path)
            console.print(f"[green]Synced {len(programs)} programs from HackerOne[/green]")
            await _print_scope_summary(session, programs)
        except Exception as e:
            console.print(f"[red]Error syncing HackerOne programs: {e}[/red]")
            import traceback
            traceback.print_exc()


async def _sync_bugcrowd(cookie_file: Optional[Path]):
    """Sync Bugcrowd programs using BC_SESSION cookie from .env."""
    loader = get_loader()
    platform_obj = loader.get_platform("bugcrowd")
    if not platform_obj:
        console.print("[red]Bugcrowd platform not available[/red]")
        return

    if not getattr(settings, "BC_SESSION", None):
        console.print("[red]BC_SESSION must be set in .env (copy _bugcrowd_session cookie from your browser)[/red]")
        return

    cookie_path = str(cookie_file) if cookie_file else None

    async with get_session() as session:
        console.print("[cyan]Authenticating with Bugcrowd...[/cyan]")
        auth_result = await platform_obj.authenticate(cookie_path)
        if not auth_result.get("authenticated"):
            console.print(f"[red]Authentication failed: {auth_result.get('error', 'Unknown error')}[/red]")
            return

        console.print("[green]Authentication successful[/green]")
        console.print("[cyan]Fetching programs from Bugcrowd...[/cyan]")

        try:
            programs = await platform_obj.sync_programs(session, cookie_path)
            console.print(f"[green]Synced {len(programs)} programs from Bugcrowd[/green]")
            await _print_scope_summary(session, programs)
        except Exception as e:
            console.print(f"[red]Error syncing Bugcrowd programs: {e}[/red]")
            import traceback
            traceback.print_exc()


async def _sync_ywh(cookie_file: Optional[Path]):
    """Sync YesWeHack programs using credentials from .env."""
    loader = get_loader()
    platform_obj = loader.get_platform("yeswehack")
    if not platform_obj:
        console.print("[red]YesWeHack platform not available[/red]")
        return

    if not settings.YWH_TOKEN:
        console.print("[red]YWH_TOKEN must be set in .env[/red]")
        return

    cookie_path = str(cookie_file) if cookie_file else None

    async with get_session() as session:
        console.print("[cyan]Authenticating with YesWeHack API...[/cyan]")
        auth_result = await platform_obj.authenticate(cookie_path)
        if not auth_result.get("authenticated"):
            console.print(f"[red]Authentication failed: {auth_result.get('error', 'Unknown error')}[/red]")
            return

        console.print("[green]Authentication successful[/green]")
        console.print("[cyan]Fetching programs from YesWeHack...[/cyan]")

        try:
            programs = await platform_obj.sync_programs(session, cookie_path)
            console.print(f"[green]Synced {len(programs)} programs from YesWeHack[/green]")
            await _print_scope_summary(session, programs)
        except Exception as e:
            console.print(f"[red]Error syncing YesWeHack programs: {e}[/red]")
            import traceback
            traceback.print_exc()


async def _sync_intigriti(cookie_file: Optional[Path]):
    """Sync Intigriti programs using credentials from .env."""
    loader = get_loader()
    platform_obj = loader.get_platform("intigriti")
    if not platform_obj:
        console.print("[red]Intigriti platform not available[/red]")
        return

    if not settings.INTI_TOKEN:
        console.print("[red]INTI_TOKEN must be set in .env[/red]")
        return

    cookie_path = str(cookie_file) if cookie_file else None

    async with get_session() as session:
        console.print("[cyan]Authenticating with Intigriti API...[/cyan]")
        auth_result = await platform_obj.authenticate(cookie_path)
        if not auth_result.get("authenticated"):
            console.print(f"[red]Authentication failed: {auth_result.get('error', 'Unknown error')}[/red]")
            return

        console.print("[green]Authentication successful[/green]")
        console.print("[cyan]Fetching programs from Intigriti...[/cyan]")

        try:
            programs = await platform_obj.sync_programs(session, cookie_path)
            console.print(f"[green]Synced {len(programs)} programs from Intigriti[/green]")
            await _print_scope_summary(session, programs)
        except Exception as e:
            console.print(f"[red]Error syncing Intigriti programs: {e}[/red]")
            import traceback
            traceback.print_exc()


async def _sync_immunefi():
    """Sync Immunefi programs (no credentials required)."""
    loader = get_loader()
    platform_obj = loader.get_platform("immunefi")
    if not platform_obj:
        console.print("[red]Immunefi platform not available[/red]")
        return

    async with get_session() as session:
        console.print("[cyan]Fetching programs from Immunefi...[/cyan]")
        try:
            programs = await platform_obj.sync_programs(session)
            console.print(f"[green]Synced {len(programs)} programs from Immunefi[/green]")
            await _print_scope_summary(session, programs)
        except Exception as e:
            console.print(f"[red]Error syncing Immunefi programs: {e}[/red]")
            import traceback
            traceback.print_exc()


async def _sync_bugbase():
    """Sync BugBase programs (no credentials required)."""
    loader = get_loader()
    platform_obj = loader.get_platform("bugbase")
    if not platform_obj:
        console.print("[red]BugBase platform not available[/red]")
        return

    async with get_session() as session:
        console.print("[cyan]Fetching programs from BugBase...[/cyan]")
        try:
            programs = await platform_obj.sync_programs(session)
            console.print(f"[green]Synced {len(programs)} programs from BugBase[/green]")
            await _print_scope_summary(session, programs)
        except Exception as e:
            console.print(f"[red]Error syncing BugBase programs: {e}[/red]")
            import traceback
            traceback.print_exc()


async def _sync_hackenproof(cookie_file: Optional[Path]):
    """Sync HackenProof programs using cookie credentials from .env."""
    loader = get_loader()
    platform_obj = loader.get_platform("hackenproof")
    if not platform_obj:
        console.print("[red]HackenProof platform not available[/red]")
        return

    if not getattr(settings, "HP_CF_CLEARANCE", None) or not getattr(settings, "HP_REMEMBER_USER_TOKEN", None):
        console.print("[red]HP_CF_CLEARANCE and HP_REMEMBER_USER_TOKEN must both be set in .env[/red]")
        console.print("[yellow]Copy these cookie values from dashboard.hackenproof.com in your browser DevTools.[/yellow]")
        return

    cookie_path = str(cookie_file) if cookie_file else None

    async with get_session() as session:
        console.print("[cyan]Authenticating with HackenProof...[/cyan]")
        auth_result = await platform_obj.authenticate(cookie_path)
        if not auth_result.get("authenticated"):
            console.print(f"[red]Authentication failed: {auth_result.get('error', 'Unknown error')}[/red]")
            console.print("[yellow]Hint: cookies may be expired — refresh HP_CF_CLEARANCE and HP_REMEMBER_USER_TOKEN.[/yellow]")
            return

        console.print("[green]Authentication successful[/green]")
        console.print("[cyan]Fetching programs from HackenProof...[/cyan]")

        try:
            programs = await platform_obj.sync_programs(session, cookie_path)
            console.print(f"[green]Synced {len(programs)} programs from HackenProof[/green]")
            await _print_scope_summary(session, programs)
        except Exception as e:
            console.print(f"[red]Error syncing HackenProof programs: {e}[/red]")
            import traceback
            traceback.print_exc()


async def _sync_disclosio():
    """Sync disclose.io self-hosted bounty programs (no credentials required)."""
    from app.programs.platforms.disclose import DisclosIOPlatform

    platform_obj = DisclosIOPlatform()

    async with get_session() as session:
        console.print("[cyan]Fetching programs from disclose.io...[/cyan]")
        try:
            programs = await platform_obj.sync_programs(session)
            console.print(f"[green]Synced {len(programs)} self-hosted programs from disclose.io[/green]")
            await _print_scope_summary(session, programs)
        except Exception as e:
            console.print(f"[red]Error syncing disclose.io programs: {e}[/red]")
            import traceback
            traceback.print_exc()
        finally:
            await platform_obj.close()


async def _sync_bugbountydirectory():
    """Sync BugBountyDirectory.com self-hosted bounty programs (no credentials required)."""
    from app.programs.platforms.bugbountydirectory import BugBountyDirectoryPlatform

    platform_obj = BugBountyDirectoryPlatform()

    async with get_session() as session:
        console.print("[cyan]Fetching programs from BugBountyDirectory.com...[/cyan]")
        try:
            programs = await platform_obj.sync_programs(session)
            console.print(f"[green]Synced {len(programs)} self-hosted programs from BugBountyDirectory[/green]")
            await _print_scope_summary(session, programs)
        except Exception as e:
            console.print(f"[red]Error syncing BugBountyDirectory programs: {e}[/red]")
            import traceback
            traceback.print_exc()
        finally:
            await platform_obj.close()


async def _print_scope_summary(session, programs):
    """Print total scope count for a list of programs."""
    from sqlalchemy import select, func
    from app.db.db_models import Scope

    if not programs:
        return

    program_ids = [p.id for p in programs]
    stmt = select(func.count(Scope.id)).where(Scope.program_id.in_(program_ids))
    result = await session.execute(stmt)
    total_scopes = result.scalar()
    console.print(f"[green]Total scopes added/updated: {total_scopes}[/green]")


async def _show_status():
    """Show system status."""
    from sqlalchemy import select, func
    from app.db.db_models import Program, Scope, Subdomain, SubdomainState

    async with get_session() as session:
        stmt = select(func.count(Program.id))
        result = await session.execute(stmt)
        program_count = result.scalar()

        stmt = select(func.count(Scope.id))
        result = await session.execute(stmt)
        scope_count = result.scalar()

        stmt = select(func.count(Scope.id)).where(Scope.manually_deactivated == True)
        result = await session.execute(stmt)
        manual_deactivated_count = result.scalar()

        state_counts = {}
        for state in SubdomainState:
            stmt = select(func.count(Subdomain.id)).where(Subdomain.state == state)
            result = await session.execute(stmt)
            state_counts[state.value] = result.scalar()

        stmt = select(func.count(Subdomain.id)).where(Subdomain.confidence >= 80)
        result = await session.execute(stmt)
        high_confidence = result.scalar()

    table = Table(title="STOscanner Status", show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Programs", str(program_count))
    table.add_row("Scopes (total)", str(scope_count))
    table.add_row("Scopes (manually deactivated)", str(manual_deactivated_count))
    table.add_row("High Confidence Takeovers (≥80)", str(high_confidence))

    for state, count in state_counts.items():
        table.add_row(f"Subdomains ({state})", str(count))

    console.print(table)

    lock_file = Path("scan.pause")
    if lock_file.exists():
        console.print("[yellow]⚠️  Scanning is PAUSED[/yellow]")
        console.print("[yellow]Run 'stoscanner resume' to resume scanning.[/yellow]")
    else:
        console.print("[green]✓ Scanning is ACTIVE[/green]")


async def _clear_all_ip(
    providers: List[str],
    dry_run:   bool = False,
    sto_only:  bool = True,
) -> None:
    """Drive CloudIPCleaner and render a Rich table with the results."""
    from app.takeover.ip_hunter.cleaner import CloudIPCleaner

    cleaner = CloudIPCleaner()
    console.print("\n[dim]Querying providers...[/dim]")

    results = await cleaner.clean(providers, dry_run=dry_run, sto_only=sto_only)

    for provider, result in results.items():
        title_color = "green" if result.ok else "red"
        console.print(f"\n[bold {title_color}]{provider.upper()}[/bold {title_color}]")

        if result.errors:
            for err in result.errors:
                console.print(f"  [red]✗[/red] {err}")

        if not result.found:
            console.print("  [dim]No reserved IPs found.[/dim]")
            continue

        tbl = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        tbl.add_column("IP",      style="cyan",  no_wrap=True)
        tbl.add_column("Region",  style="white", no_wrap=True)
        tbl.add_column("Name / ID")
        tbl.add_column("Status")

        for info in sorted(result.found, key=lambda x: (x.region, x.ip)):
            if info in result.released:
                status_str = "[green]✓ released[/green]" if not dry_run else "[yellow]~ would release[/yellow]"
            elif info in result.skipped:
                status_str = "[dim]— in use (skipped)[/dim]"
            else:
                status_str = "[red]✗ error[/red]"
            tbl.add_row(info.ip, info.region, info.name, status_str)

        console.print(tbl)

    # ── Summary ───────────────────────────────────────────────────────────
    total_found    = sum(len(r.found)    for r in results.values())
    total_released = sum(len(r.released) for r in results.values())
    total_skipped  = sum(len(r.skipped)  for r in results.values())
    total_errors   = sum(len(r.errors)   for r in results.values())

    verb = "would release" if dry_run else "released"

    console.print(
        f"\n[bold]Summary[/bold]  "
        f"found=[cyan]{total_found}[/cyan]  "
        f"{verb}=[green]{total_released}[/green]  "
        f"skipped=[dim]{total_skipped}[/dim]  "
        f"errors=[red]{total_errors}[/red]"
    )

    if total_errors:
        console.print("\n[yellow]Some operations failed — check logs for details.[/yellow]")
        raise typer.Exit(1)


async def init_db():
    """Initialize database tables."""
    await create_tables()
    console.print("[green]Database tables created[/green]")


if __name__ == "__main__":
    app()