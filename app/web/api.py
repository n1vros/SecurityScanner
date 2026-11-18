"""
FastAPI web API for STOscanner.
"""

from typing import List, Optional
from datetime import datetime, timedelta

from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import desc, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from app.db.db_models import (
    Program,
    Scope,
    Subdomain,
    SubdomainState,
    DiscoverySourceEntry,
    StateTransition,
    JsSecretRecord,
    GitSecretRecord,
    GitProject,
    GitScope,
)
from app.db.session import get_session
from app.core.logging import logger
from app.core.daemon_manager import daemon_manager


app = FastAPI(
    title="STOscanner API",
    description="Web interface for Subdomain Takeover Scanner",
    version="0.1.0",
)


@app.on_event("startup")
async def startup_event():
    """Initialize the database and opt-in daemon autostart."""
    from app.db.session import create_tables
    try:
        await create_tables()
        logger.info("Database tables initialized")
    except Exception as e:
        logger.warning("Database tables may already exist: %s", e)

    # Autostart must run after database initialization and only when opted in.
    try:
        await daemon_manager.autostart_if_enabled()
    except Exception as e:
        logger.error("Daemon autostart failed: %s", e)


# get_session() is an asynccontextmanager, not an async iterator.
# Using `async for` bypassed the try/except/rollback guard inside get_session,
# meaning DB exceptions in API handlers would never trigger a rollback.
async def get_db() -> AsyncSession:
    """Dependency for database session."""
    async with get_session() as session:
        yield session


@app.get("/api/programs")
async def get_programs(
    db: AsyncSession = Depends(get_db),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> List[dict]:
    """Get list of programs."""
    result = await db.execute(
        select(Program)
        .options(selectinload(Program.scopes))
        .order_by(desc(Program.created_at))
        .limit(limit)
        .offset(offset)
    )
    programs = result.scalars().all()

    return [
        {
            "id": p.id,
            "name": p.name,
            "platform": p.platform.value,
            "url": p.url,
            "created_at": p.created_at.isoformat() if p.created_at else None,
            "updated_at": p.updated_at.isoformat() if p.updated_at else None,
            "last_scan_at": p.last_scan_at.isoformat() if p.last_scan_at else None,
            "is_active": p.is_active,
            "scope_count": len(p.scopes),
        }
        for p in programs
    ]


@app.get("/api/scopes")
async def get_scopes(
    db: AsyncSession = Depends(get_db),
    program_id: Optional[int] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> List[dict]:
    """Get list of scopes."""
    query = select(Scope).options(selectinload(Scope.subdomains))

    if program_id:
        query = query.where(Scope.program_id == program_id)

    query = query.order_by(desc(Scope.added_at)).limit(limit).offset(offset)

    result = await db.execute(query)
    scopes = result.scalars().all()

    return [
        {
            "id": s.id,
            "program_id": s.program_id,
            "program_name": s.program.name if s.program else None,
            "domain": s.domain,
            "added_at": s.added_at.isoformat() if s.added_at else None,
            "is_active": s.is_active,
            "subdomain_count": len(s.subdomains),
        }
        for s in scopes
    ]


@app.get("/api/subdomains")
async def get_subdomains(
    db: AsyncSession = Depends(get_db),
    scope_id: Optional[int] = None,
    state: Optional[SubdomainState] = None,
    min_confidence: Optional[int] = Query(None, ge=0, le=100),
    max_confidence: Optional[int] = Query(None, ge=0, le=100),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    order_by: str = Query("confidence", pattern="^(confidence|name|last_scanned_at|state)$"),
) -> List[dict]:
    """Get list of subdomains with filters."""
    query = select(Subdomain).options(
        selectinload(Subdomain.scope).selectinload(Scope.program)
    )

    if scope_id:
        query = query.where(Subdomain.scope_id == scope_id)
    if state:
        query = query.where(Subdomain.state == state)
    if min_confidence is not None:
        query = query.where(Subdomain.confidence >= min_confidence)
    if max_confidence is not None:
        query = query.where(Subdomain.confidence <= max_confidence)

    if order_by == "confidence":
        query = query.order_by(desc(Subdomain.confidence))
    elif order_by == "name":
        query = query.order_by(Subdomain.name)
    elif order_by == "last_scanned_at":
        query = query.order_by(desc(Subdomain.last_scanned_at))
    elif order_by == "state":
        query = query.order_by(Subdomain.state)

    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    subdomains = result.scalars().all()

    return [
        {
            "id": s.id,
            "scope_id": s.scope_id,
            "scope_domain": s.scope.domain if s.scope else None,
            "program_name": s.scope.program.name if s.scope and s.scope.program else None,
            "name": s.name,
            "state": s.state.value,
            "confidence": s.confidence,
            "discovered_at": s.discovered_at.isoformat() if s.discovered_at else None,
            "last_scanned_at": s.last_scanned_at.isoformat() if s.last_scanned_at else None,
            "cname_target": s.cname_target,
            "http_status": s.http_status,
            "http_title": s.http_title,
            "takeover_provider": s.takeover_provider,
        }
        for s in subdomains
    ]


@app.get("/api/findings")
async def get_findings(
    db: AsyncSession = Depends(get_db),
    min_confidence: int = Query(70, ge=0, le=100),
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> List[dict]:
    """Get high-confidence takeover findings."""
    cutoff_time = datetime.utcnow() - timedelta(hours=hours)

    result = await db.execute(
        select(Subdomain)
        .options(selectinload(Subdomain.scope).selectinload(Scope.program))
        .where(Subdomain.confidence >= min_confidence)
        .where(Subdomain.last_scanned_at >= cutoff_time)
        .order_by(desc(Subdomain.confidence), desc(Subdomain.last_scanned_at))
        .limit(limit)
        .offset(offset)
    )
    subdomains = result.scalars().all()

    findings = []
    for s in subdomains:
        sources_result = await db.execute(
            select(DiscoverySourceEntry.source)
            .where(DiscoverySourceEntry.subdomain_id == s.id)
        )
        sources = [source[0].value for source in sources_result.all()]

        transitions_result = await db.execute(
            select(StateTransition)
            .where(StateTransition.subdomain_id == s.id)
            .order_by(desc(StateTransition.transitioned_at))
            .limit(5)
        )
        transitions = transitions_result.scalars().all()

        findings.append({
            "id": s.id,
            "name": s.name,
            "scope_domain": s.scope.domain if s.scope else None,
            "program_name": s.scope.program.name if s.scope and s.scope.program else None,
            "state": s.state.value,
            "confidence": s.confidence,
            "discovered_at": s.discovered_at.isoformat() if s.discovered_at else None,
            "last_scanned_at": s.last_scanned_at.isoformat() if s.last_scanned_at else None,
            "cname_target": s.cname_target,
            "http_status": s.http_status,
            "http_title": s.http_title,
            "takeover_provider": s.takeover_provider,
            "takeover_evidence": s.takeover_evidence,
            "discovery_sources": sources,
            "state_transitions": [
                {
                    "from_state": t.from_state.value if t.from_state else None,
                    "to_state": t.to_state.value,
                    "transitioned_at": t.transitioned_at.isoformat() if t.transitioned_at else None,
                    "reason": t.reason,
                }
                for t in transitions
            ],
        })

    return findings


@app.get("/api/latest-findings")
async def get_latest_findings(
    db: AsyncSession = Depends(get_db),
    min_confidence: int = Query(70, ge=0, le=100),
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(10, ge=1, le=100),
) -> dict:
    """Latest high-confidence findings, shaped for the dashboard poller."""
    cutoff_time = datetime.utcnow() - timedelta(hours=hours)

    result = await db.execute(
        select(Subdomain)
        .options(selectinload(Subdomain.scope).selectinload(Scope.program))
        .where(Subdomain.confidence >= min_confidence)
        .where(Subdomain.last_scanned_at >= cutoff_time)
        .order_by(desc(Subdomain.confidence), desc(Subdomain.last_scanned_at))
        .limit(limit)
    )
    subdomains = result.scalars().all()

    return {
        "findings": [
            {
                "id": s.id,
                "name": s.name,
                "scope_domain": s.scope.domain if s.scope else None,
                "program_name": (
                    s.scope.program.name
                    if s.scope and s.scope.program
                    else None
                ),
                "state": s.state.value,
                "confidence": s.confidence,
                "discovered_at": s.discovered_at.isoformat() if s.discovered_at else None,
                "last_scanned_at": s.last_scanned_at.isoformat() if s.last_scanned_at else None,
                "cname_target": s.cname_target,
                "http_status": s.http_status,
                "http_title": s.http_title,
                "takeover_provider": s.takeover_provider,
                "takeover_evidence": s.takeover_evidence,
            }
            for s in subdomains
        ]
    }


@app.get("/api/stats")
async def get_stats(db: AsyncSession = Depends(get_db)) -> dict:
    """Get system statistics."""
    result = await db.execute(select(func.count(Program.id)))
    program_count = result.scalar()

    result = await db.execute(select(func.count(Scope.id)))
    scope_count = result.scalar()

    result = await db.execute(
        select(Subdomain.state, func.count(Subdomain.id))
        .group_by(Subdomain.state)
    )
    subdomain_counts = {state.value: count for state, count in result.all()}

    result = await db.execute(
        select(func.count(Subdomain.id))
        .where(Subdomain.confidence >= 70)
    )
    high_confidence_count = result.scalar()

    result = await db.execute(
        select(func.max(Subdomain.last_scanned_at))
    )
    latest_scan = result.scalar()

    cutoff_time = datetime.utcnow() - timedelta(hours=24)
    result = await db.execute(
        select(func.count(Subdomain.id))
        .where(Subdomain.last_scanned_at >= cutoff_time)
        .where(Subdomain.confidence >= 70)
    )
    recent_findings = result.scalar()

    return {
        "programs": program_count,
        "scopes": scope_count,
        "subdomains_by_state": subdomain_counts,
        "high_confidence_findings": high_confidence_count,
        "recent_findings_24h": recent_findings,
        "latest_scan": latest_scan.isoformat() if latest_scan else None,
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.get("/api/program/{program_id}")
async def get_program(
    program_id: int,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get detailed information about a specific program."""
    result = await db.execute(
        select(Program).where(Program.id == program_id)
    )
    program = result.scalar_one_or_none()

    if not program:
        raise HTTPException(status_code=404, detail="Program not found")

    result = await db.execute(
        select(Subdomain.state, func.count(Subdomain.id))
        .join(Scope)
        .where(Scope.program_id == program_id)
        .group_by(Subdomain.state)
    )
    subdomain_counts = {state.value: count for state, count in result.all()}

    # eagerly load subdomains so len(s.subdomains) doesn't lazy-load
    result = await db.execute(
        select(Scope)
        .options(selectinload(Scope.subdomains))
        .where(Scope.program_id == program_id)
        .order_by(Scope.domain)
    )
    scopes = result.scalars().all()

    return {
        "id": program.id,
        "name": program.name,
        "platform": program.platform.value,
        "url": program.url,
        "created_at": program.created_at.isoformat() if program.created_at else None,
        "updated_at": program.updated_at.isoformat() if program.updated_at else None,
        "last_scan_at": program.last_scan_at.isoformat() if program.last_scan_at else None,
        "is_active": program.is_active,
        "scopes": [
            {
                "id": s.id,
                "domain": s.domain,
                "added_at": s.added_at.isoformat() if s.added_at else None,
                "is_active": s.is_active,
                "subdomain_count": len(s.subdomains),
            }
            for s in scopes
        ],
        "subdomain_counts": subdomain_counts,
        "total_subdomains": sum(subdomain_counts.values()),
    }


@app.get("/api/subdomain/{subdomain_id}")
async def get_subdomain(
    subdomain_id: int,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get detailed information about a specific subdomain."""
    # eagerly load scope → program chain
    result = await db.execute(
        select(Subdomain)
        .options(selectinload(Subdomain.scope).selectinload(Scope.program))
        .where(Subdomain.id == subdomain_id)
    )
    subdomain = result.scalar_one_or_none()

    if not subdomain:
        raise HTTPException(status_code=404, detail="Subdomain not found")

    result = await db.execute(
        select(DiscoverySourceEntry)
        .where(DiscoverySourceEntry.subdomain_id == subdomain_id)
        .order_by(DiscoverySourceEntry.discovered_at)
    )
    sources = result.scalars().all()

    result = await db.execute(
        select(StateTransition)
        .where(StateTransition.subdomain_id == subdomain_id)
        .order_by(desc(StateTransition.transitioned_at))
    )
    transitions = result.scalars().all()

    return {
        "id": subdomain.id,
        "scope_id": subdomain.scope_id,
        "scope_domain": subdomain.scope.domain if subdomain.scope else None,
        "program_name": subdomain.scope.program.name if subdomain.scope and subdomain.scope.program else None,
        "name": subdomain.name,
        "state": subdomain.state.value,
        "confidence": subdomain.confidence,
        "discovered_at": subdomain.discovered_at.isoformat() if subdomain.discovered_at else None,
        "last_scanned_at": subdomain.last_scanned_at.isoformat() if subdomain.last_scanned_at else None,
        "last_state_change_at": subdomain.last_state_change_at.isoformat() if subdomain.last_state_change_at else None,
        "cname_target": subdomain.cname_target,
        "dns_resolver": subdomain.dns_resolver,
        "dns_resolved_at": subdomain.dns_resolved_at.isoformat() if subdomain.dns_resolved_at else None,
        "http_status": subdomain.http_status,
        "http_title": subdomain.http_title,
        "http_body_hash": subdomain.http_body_hash,
        "http_content_length": subdomain.http_content_length,
        "http_probed_at": subdomain.http_probed_at.isoformat() if subdomain.http_probed_at else None,
        "takeover_provider": subdomain.takeover_provider,
        "takeover_evidence": subdomain.takeover_evidence,
        "discovery_sources": [
            {
                "source": s.source.value,
                "discovered_at": s.discovered_at.isoformat() if s.discovered_at else None,
            }
            for s in sources
        ],
        "state_transitions": [
            {
                "id": t.id,
                "from_state": t.from_state.value if t.from_state else None,
                "to_state": t.to_state.value,
                "transitioned_at": t.transitioned_at.isoformat() if t.transitioned_at else None,
                "reason": t.reason,
            }
            for t in transitions
        ],
    }


# Daemon control endpoints
@app.get("/api/daemon/status")
async def get_daemon_status():
    """Get current daemon status."""
    status = await daemon_manager.get_status()
    return status


@app.post("/api/daemon/start")
async def start_daemon():
    """Start the daemon."""
    result = await daemon_manager.start_daemon()
    return result


@app.post("/api/daemon/stop")
async def stop_daemon():
    """Stop the daemon."""
    result = await daemon_manager.stop_daemon()
    return result


@app.post("/api/daemon/restart")
async def restart_daemon():
    """Restart the daemon."""
    result = await daemon_manager.restart_daemon()
    return result


@app.get("/api/js-secrets")
async def get_js_secrets(
    db: AsyncSession = Depends(get_db),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    scope_id: Optional[int] = Query(None),
) -> dict:
    """Persisted JS secret findings, newest first."""
    base = select(JsSecretRecord)
    if scope_id is not None:
        base = base.where(JsSecretRecord.scope_id == scope_id)

    count_result = await db.execute(
        select(func.count()).select_from(base.subquery())
    )
    total_count = count_result.scalar() or 0

    result = await db.execute(
        base.options(selectinload(JsSecretRecord.scope))
        .order_by(desc(JsSecretRecord.last_seen_at))
        .offset(offset)
        .limit(limit)
    )
    records = result.scalars().all()

    return {
        "total_count": total_count,
        "items": [
            {
                "id": record.id,
                "scope_id": record.scope_id,
                "scope_domain": record.scope.domain if record.scope else None,
                "url": record.url,
                "secret_type": record.secret_type,
                "redacted": record.redacted,
                "line_number": record.line_number,
                "first_seen_at": record.first_seen_at.isoformat() if record.first_seen_at else None,
                "last_seen_at": record.last_seen_at.isoformat() if record.last_seen_at else None,
            }
            for record in records
        ],
    }


@app.get("/api/git-secrets")
async def get_git_secrets(
    db: AsyncSession = Depends(get_db),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> dict:
    """Persisted verified git secret findings, newest first."""
    base = select(GitSecretRecord)

    count_result = await db.execute(
        select(func.count()).select_from(base.subquery())
    )
    total_count = count_result.scalar() or 0

    result = await db.execute(
        base.options(
            selectinload(GitSecretRecord.git_project)
            .selectinload(GitProject.git_scope)
            .selectinload(GitScope.program)
        )
        .order_by(desc(GitSecretRecord.last_seen_at))
        .offset(offset)
        .limit(limit)
    )
    records = result.scalars().all()

    items = []
    for record in records:
        project = record.git_project
        program_name = None
        if project and project.git_scope and project.git_scope.program:
            program_name = project.git_scope.program.name
        items.append(
            {
                "id": record.id,
                "repo_url": project.repo_url if project else None,
                "program": program_name,
                "detector": record.detector,
                "redacted": record.redacted,
                "file_path": record.file_path,
                "verified": record.verified,
                "first_seen_at": record.first_seen_at.isoformat() if record.first_seen_at else None,
                "last_seen_at": record.last_seen_at.isoformat() if record.last_seen_at else None,
            }
        )

    return {"total_count": total_count, "items": items}
