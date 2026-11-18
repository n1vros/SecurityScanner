"""
Web interface routes and templates for STOscanner.
"""

from pathlib import Path
from typing import Optional
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from app.db.db_models import Program, Scope, Subdomain, SubdomainState
from app.db.session import get_session
from app.core.config import settings
from app.core.logging import logger


router = APIRouter()
templates = Jinja2Templates(
    directory=str(Path(__file__).resolve().parent / "templates")
)


async def get_db() -> AsyncSession:
    """Dependency for database session."""
    async with get_session() as session:
        yield session


def _render(
    request: Request,
    name: str,
    context: dict,
    status_code: int = 200,
):
    """Render a page with the shared footer timestamp context."""
    now = datetime.utcnow()
    return templates.TemplateResponse(
        request,
        name,
        {
            "request": request,
            "current_year": now.year,
            "current_time": now.strftime("%H:%M:%S"),
            **context,
        },
        status_code=status_code,
    )


@router.get("/", response_class=HTMLResponse)
@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, db: AsyncSession = Depends(get_db)):
    """Dashboard with statistics and latest findings."""
    result = await db.execute(select(func.count(Program.id)))
    program_count = result.scalar()

    result = await db.execute(select(func.count(Scope.id)))
    scope_count = result.scalar()

    result = await db.execute(select(func.count(Subdomain.id)))
    subdomain_count = result.scalar()

    result = await db.execute(
        select(func.count(Subdomain.id))
        .where(Subdomain.confidence >= 70)
    )
    high_confidence_count = result.scalar()

    cutoff_time = datetime.utcnow() - timedelta(hours=24)
    result = await db.execute(
        select(func.count(Subdomain.id))
        .where(Subdomain.last_scanned_at >= cutoff_time)
        .where(Subdomain.confidence >= 70)
    )
    recent_findings = result.scalar()

    result = await db.execute(
        select(func.max(Subdomain.last_scanned_at))
    )
    latest_scan = result.scalar()

    # Eagerly load scope → program so the loop below doesn't lazy-load
    result = await db.execute(
        select(Subdomain)
        .options(selectinload(Subdomain.scope).selectinload(Scope.program))
        .join(Scope)
        .join(Program)
        .where(Subdomain.confidence >= 70)
        .order_by(desc(Subdomain.last_scanned_at))
        .limit(10)
    )
    latest_subdomains = result.scalars().all()

    latest_findings = []
    for s in latest_subdomains:
        latest_findings.append({
            "id": s.id,
            "name": s.name,
            "scope_domain": s.scope.domain if s.scope else None,
            "program_name": s.scope.program.name if s.scope and s.scope.program else None,
            "state": s.state.value,
            "confidence": s.confidence,
            "last_scanned_at": s.last_scanned_at.isoformat() if s.last_scanned_at else None,
            "cname_target": s.cname_target,
            "http_status": s.http_status,
            "takeover_provider": s.takeover_provider,
        })

    # use settings.SCAN_INTERVAL_HOURS instead of hardcoded 24 so this
    # widget stays in sync with what the daemon scheduler actually picks up.
    cutoff_scan = datetime.utcnow() - timedelta(hours=settings.SCAN_INTERVAL_HOURS)
    result = await db.execute(
        select(Program)
        .options(selectinload(Program.scopes))
        .where(
            (Program.last_scan_at < cutoff_scan) |
            (Program.last_scan_at.is_(None))
        )
        .where(Program.is_active == True)
        .order_by(Program.last_scan_at.asc().nulls_first())
        .limit(10)
    )
    programs_needing_scan = result.scalars().all()

    return _render(
        request,
        "dashboard.html",
        {
            "program_count": program_count,
            "scope_count": scope_count,
            "subdomain_count": subdomain_count,
            "high_confidence_count": high_confidence_count,
            "recent_findings": recent_findings,
            "latest_scan": latest_scan.isoformat() if latest_scan else None,
            "latest_findings": latest_findings,
            "programs_needing_scan": [
                {
                    "id": p.id,
                    "name": p.name,
                    "last_scan_at": p.last_scan_at.isoformat() if p.last_scan_at else "Never",
                    "scope_count": len(p.scopes),
                }
                for p in programs_needing_scan
            ],
        },
    )


@router.get("/findings", response_class=HTMLResponse)
async def findings(
    request: Request,
    db: AsyncSession = Depends(get_db),
    min_confidence: Optional[int] = Query(70, ge=0, le=100),
    hours: Optional[int] = Query(24, ge=1, le=168),
    page: Optional[int] = Query(1, ge=1),
    per_page: Optional[int] = Query(50, ge=1, le=200),
):
    """Findings page with takeover alerts."""
    offset = (page - 1) * per_page

    query = select(Subdomain).join(Scope).join(Program)
    query = query.where(Subdomain.confidence >= min_confidence)

    if hours:
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        query = query.where(Subdomain.last_scanned_at >= cutoff_time)

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total_count = count_result.scalar()

    # Eagerly load scope → program
    query = (
        query
        .options(selectinload(Subdomain.scope).selectinload(Scope.program))
        .order_by(desc(Subdomain.confidence), desc(Subdomain.last_scanned_at))
        .limit(per_page)
        .offset(offset)
    )

    result = await db.execute(query)
    subdomains = result.scalars().all()

    findings_list = []
    for s in subdomains:
        findings_list.append({
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
        })

    total_pages = (total_count + per_page - 1) // per_page if total_count > 0 else 1

    return _render(
        request,
        "findings.html",
        {
            "findings": findings_list,
            "total_count": total_count,
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
            "min_confidence": min_confidence,
            "hours": hours,
        },
    )


@router.get("/programs", response_class=HTMLResponse)
async def programs(
    request: Request,
    db: AsyncSession = Depends(get_db),
    page: Optional[int] = Query(1, ge=1),
    per_page: Optional[int] = Query(20, ge=1, le=100),
):
    """Programs listing page."""
    offset = (page - 1) * per_page

    count_result = await db.execute(select(func.count(Program.id)))
    total_count = count_result.scalar()

    result = await db.execute(
        select(Program)
        .options(selectinload(Program.scopes))
        .order_by(desc(Program.created_at))
        .limit(per_page)
        .offset(offset)
    )
    programs_list = result.scalars().all()

    programs_with_counts = []
    for p in programs_list:
        result = await db.execute(
            select(Subdomain.state, func.count(Subdomain.id))
            .join(Scope)
            .where(Scope.program_id == p.id)
            .group_by(Subdomain.state)
        )
        subdomain_counts = {state.value: count for state, count in result.all()}

        programs_with_counts.append({
            "id": p.id,
            "name": p.name,
            "platform": p.platform.value,
            "url": p.url,
            "created_at": p.created_at.isoformat() if p.created_at else None,
            "updated_at": p.updated_at.isoformat() if p.updated_at else None,
            "last_scan_at": p.last_scan_at.isoformat() if p.last_scan_at else None,
            "is_active": p.is_active,
            "scope_count": len(p.scopes),
            "subdomain_counts": subdomain_counts,
            "total_subdomains": sum(subdomain_counts.values()),
        })

    total_pages = (total_count + per_page - 1) // per_page if total_count > 0 else 1

    return _render(
        request,
        "programs.html",
        {
            "programs": programs_with_counts,
            "total_count": total_count,
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
        },
    )


@router.get("/subdomains", response_class=HTMLResponse)
async def subdomains(
    request: Request,
    db: AsyncSession = Depends(get_db),
    state: Optional[SubdomainState] = None,
    min_confidence: Optional[int] = Query(None, ge=0, le=100),
    max_confidence: Optional[int] = Query(None, ge=0, le=100),
    scope_id: Optional[int] = None,
    program_id: Optional[int] = None,
    page: Optional[int] = Query(1, ge=1),
    per_page: Optional[int] = Query(50, ge=1, le=200),
    order_by: Optional[str] = Query("confidence", pattern="^(confidence|name|last_scanned_at|state)$"),
):
    """Subdomains listing page."""
    offset = (page - 1) * per_page

    query = (
        select(Subdomain)
        .options(selectinload(Subdomain.scope).selectinload(Scope.program))
        .join(Scope)
        .join(Program)
    )

    if state:
        query = query.where(Subdomain.state == state)
    if min_confidence is not None:
        query = query.where(Subdomain.confidence >= min_confidence)
    if max_confidence is not None:
        query = query.where(Subdomain.confidence <= max_confidence)
    if scope_id:
        query = query.where(Subdomain.scope_id == scope_id)
    if program_id:
        query = query.where(Scope.program_id == program_id)

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total_count = count_result.scalar()

    if order_by == "confidence":
        query = query.order_by(desc(Subdomain.confidence))
    elif order_by == "name":
        query = query.order_by(Subdomain.name)
    elif order_by == "last_scanned_at":
        query = query.order_by(desc(Subdomain.last_scanned_at))
    elif order_by == "state":
        query = query.order_by(Subdomain.state)

    query = query.limit(per_page).offset(offset)

    result = await db.execute(query)
    subdomains_list = result.scalars().all()

    subdomains_data = []
    for s in subdomains_list:
        subdomains_data.append({
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
        })

    total_pages = (total_count + per_page - 1) // per_page if total_count > 0 else 1

    result = await db.execute(
        select(Program.id, Program.name).order_by(Program.name)
    )
    programs_list = [{"id": p[0], "name": p[1]} for p in result.all()]

    result = await db.execute(
        select(Scope.id, Scope.domain, Program.name)
        .join(Program)
        .order_by(Scope.domain)
    )
    scopes_list = [{"id": s[0], "domain": s[1], "program_name": s[2]} for s in result.all()]

    return _render(
        request,
        "subdomains.html",
        {
            "subdomains": subdomains_data,
            "total_count": total_count,
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
            "state": state.value if state else None,
            "min_confidence": min_confidence,
            "max_confidence": max_confidence,
            "scope_id": scope_id,
            "program_id": program_id,
            "order_by": order_by,
            "states": [s.value for s in SubdomainState],
            "programs": programs_list,
            "scopes": scopes_list,
        },
    )


@router.get("/program/{program_id}", response_class=HTMLResponse)
async def program_detail(
    program_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Program detail page."""
    result = await db.execute(
        select(Program).where(Program.id == program_id)
    )
    program = result.scalar_one_or_none()

    if not program:
        return _render(
            request,
            "404.html",
            {"message": f"Program {program_id} not found"},
            status_code=404,
        )

    # b: eagerly load subdomains so len(s.subdomains) doesn't lazy-load
    result = await db.execute(
        select(Scope)
        .options(selectinload(Scope.subdomains))
        .where(Scope.program_id == program_id)
        .order_by(Scope.domain)
    )
    scopes = result.scalars().all()

    result = await db.execute(
        select(Subdomain.state, func.count(Subdomain.id))
        .join(Scope)
        .where(Scope.program_id == program_id)
        .group_by(Subdomain.state)
    )
    subdomain_counts = {state.value: count for state, count in result.all()}

    # c: eagerly load scope so s.scope.domain doesn't lazy-load
    result = await db.execute(
        select(Subdomain)
        .options(selectinload(Subdomain.scope))
        .join(Scope)
        .where(Scope.program_id == program_id)
        .where(Subdomain.confidence >= 70)
        .order_by(desc(Subdomain.last_scanned_at))
        .limit(20)
    )
    recent_findings = result.scalars().all()

    return _render(
        request,
        "program_detail.html",
        {
            "program": {
                "id": program.id,
                "name": program.name,
                "platform": program.platform.value,
                "url": program.url,
                "created_at": program.created_at.isoformat() if program.created_at else None,
                "updated_at": program.updated_at.isoformat() if program.updated_at else None,
                "last_scan_at": program.last_scan_at.isoformat() if program.last_scan_at else None,
                "is_active": program.is_active,
            },
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
            "recent_findings": [
                {
                    "id": s.id,
                    "name": s.name,
                    "scope_domain": s.scope.domain if s.scope else None,
                    "state": s.state.value,
                    "confidence": s.confidence,
                    "last_scanned_at": s.last_scanned_at.isoformat() if s.last_scanned_at else None,
                    "cname_target": s.cname_target,
                    "takeover_provider": s.takeover_provider,
                }
                for s in recent_findings
            ],
        },
    )


@router.get("/subdomain/{subdomain_id}", response_class=HTMLResponse)
async def subdomain_detail(
    subdomain_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Subdomain detail page."""
    # a: eagerly load scope → program to avoid MissingGreenlet on async session
    result = await db.execute(
        select(Subdomain)
        .options(selectinload(Subdomain.scope).selectinload(Scope.program))
        .where(Subdomain.id == subdomain_id)
    )
    subdomain = result.scalar_one_or_none()

    if not subdomain:
        return _render(
            request,
            "404.html",
            {"message": f"Subdomain {subdomain_id} not found"},
            status_code=404,
        )

    return _render(
        request,
        "subdomain_detail.html",
        {
            "subdomain": {
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
            },
        },
    )


@router.get("/{path:path}", response_class=HTMLResponse)
async def web_not_found(request: Request, path: str):
    """Render the HTML 404 page for unknown /web paths."""
    return _render(
        request,
        "404.html",
        {"message": f"Page /web/{path} not found"},
        status_code=404,
    )
