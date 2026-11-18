"""
SQLAlchemy models for STOscanner.
"""

import enum
from datetime import datetime
from typing import Optional, List

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class ProgramPlatform(enum.Enum):
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    YESWEHACK = "yeswehack"
    INTIGRITI = "intigriti"
    IMMUNEFI = "immunefi"
    BUGBASE = "bugbase"
    FEDERACY = "federacy"
    HACKENPROOF = "hackenproof"
    SELF_HOSTED = "self_hosted"
    MANUAL = "manual"


class SubdomainState(enum.Enum):
    DISCOVERED = "discovered"
    ALIVE = "alive"
    DEAD = "dead"
    DANGLING = "dangling"
    CLAIMED = "claimed"
    FALSE_POSITIVE = "false_positive"
    POTENTIAL = "potential"
    POTENTIAL_LONG = "potential_long"   # ownership-blocked; recheck every POTENTIAL_LONG_RECHECK_HOURS


class Program(Base):
    __tablename__ = "programs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    platform: Mapped[ProgramPlatform] = mapped_column(Enum(ProgramPlatform, values_callable=lambda x: [e.value for e in x]), nullable=False)
    # external_id is unique per platform, not globally.
    # "nextcloud" can exist on both HackerOne and YesWeHack independently.
    external_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_scan_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    scopes: Mapped[List["Scope"]] = relationship(back_populates="program", cascade="all, delete-orphan")
    git_scopes: Mapped[List["GitScope"]] = relationship(back_populates="program", cascade="all, delete-orphan")

    __table_args__ = (
        # Unique per platform — same slug can exist on H1 and YWH simultaneously
        UniqueConstraint("platform", "external_id", name="uq_program_platform_external_id"),
        Index("ix_programs_platform", "platform"),
        Index("ix_programs_last_scan_at", "last_scan_at"),
    )


class PlatformSyncState(Base):
    """Last automatic sync attempt for one bounty platform.

    A row exists only after the first attempt, so ``last_synced_at is NULL``
    means "never attempted" and makes the platform immediately due. The
    timestamp is stamped for failures too: retrying a broken endpoint every
    poll would hammer it, so the platform waits for its normal interval.
    """

    __tablename__ = "platform_sync_state"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    platform: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    last_synced_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    # "success" or "error"; NULL until the first attempt completes.
    last_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_platform_sync_state_last_synced_at", "last_synced_at"),
    )


class Scope(Base):
    __tablename__ = "scopes"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    program_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("programs.id", ondelete="CASCADE"), nullable=False)
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    added_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # When True: this scope was deactivated manually via CLI and must NEVER be
    # re-activated by automated platform syncs, even if the platform still lists
    # it as in-scope (e.g. out-of-scope for this researcher, owned infra, etc.).
    manually_deactivated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    last_scanned_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_js_scraped_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # DNS takeover notification tracking — stamped each time a Discord alert fires.
    # Enforces the DNS_TAKEOVER_RENOTIFY_HOURS cooldown (default 24h).
    dns_takeover_notified_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    program: Mapped["Program"] = relationship(back_populates="scopes")
    subdomains: Mapped[List["Subdomain"]] = relationship(back_populates="scope", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("program_id", "domain", name="uq_program_domain"),
        Index("ix_scopes_domain", "domain"),
        Index("ix_scopes_program_id", "program_id"),
        Index("ix_scopes_is_active", "is_active"),
        Index("ix_scopes_manually_deactivated", "manually_deactivated"),
        Index("ix_scopes_last_scanned_at", "last_scanned_at"),
        Index("ix_scopes_last_js_scraped_at", "last_js_scraped_at"),
        Index("ix_scopes_dns_takeover_notified_at", "dns_takeover_notified_at"),
    )


class Subdomain(Base):
    __tablename__ = "subdomains"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    scope_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("scopes.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    state: Mapped[SubdomainState] = mapped_column(Enum(SubdomainState, values_callable=lambda x: [e.value for e in x]), default=SubdomainState.DISCOVERED)
    confidence: Mapped[int] = mapped_column(Integer, default=0, nullable=False)  # 0-100
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_scanned_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_state_change_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # DNS data
    cname_target: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    dns_resolver: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    dns_resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    # JSON array of IPv4 addresses returned by the last successful A-record query.
    # e.g. '["1.2.3.4", "5.6.7.8"]'  — NULL means no A records were seen yet.
    ip_addresses: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # JSON array of IPv6 addresses returned by the last successful AAAA-record query.
    # e.g. '["2606:4700::6812:1f63"]'  — NULL means no AAAA records were seen yet.
    ipv6_addresses: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # HTTP probe snapshot — written by app/probing/http.py and read by the
    # notification and web layers after a fresh query.
    http_status: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    http_title: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    http_body_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    http_content_length: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    http_probed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Takeover detection
    takeover_provider: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    takeover_evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON

    # Outcome of the last automatic takeover attempt and the next time another
    # attempt is allowed. NULL retry_at means "no schedule recorded" (due now);
    # recheck queries skip rows whose timestamp is still in the future.
    takeover_last_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    takeover_retry_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # NS sweep
    last_ns_sweep_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # NS lottery takeover attempt stamps — set once per subdomain, prevent re-queue
    aws_route53_attempted_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    azure_dns_attempted_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    gcp_dns_attempted_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # IP free check
    ip_free: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    ip_free_checked_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    # JSON object keyed by IPv4 address containing the latest per-IP verdicts.
    # Example:
    #   {
    #     "1.2.3.4": {
    #       "status": "free",
    #       "source": "dangling_ip",
    #       "checked_at": "2026-04-09T12:00:00"
    #     }
    #   }
    ip_verdicts: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    scope: Mapped["Scope"] = relationship(back_populates="subdomains")
    discovery_sources: Mapped[List["DiscoverySourceEntry"]] = relationship(back_populates="subdomain", cascade="all, delete-orphan")
    notifications: Mapped[List["Notification"]] = relationship(back_populates="subdomain", cascade="all, delete-orphan")
    exposure_findings: Mapped[List["ExposureFinding"]] = relationship(back_populates="subdomain", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_subdomains_name", "name"),
        Index("ix_subdomains_state", "state"),
        Index("ix_subdomains_confidence", "confidence"),
        Index("ix_subdomains_last_scanned_at", "last_scanned_at"),
        Index("ix_subdomains_last_ns_sweep_at", "last_ns_sweep_at"),
        Index("ix_subdomains_cname_target", "cname_target"),
        Index("ix_subdomains_ip_free", "ip_free"),
        Index("ix_subdomains_takeover_retry_at", "takeover_retry_at"),
        UniqueConstraint("scope_id", "name", name="uq_scope_subdomain"),
    )


class DiscoverySource(enum.Enum):
    SUBFINDER = "subfinder"
    CRT_SH = "crt_sh"
    GITHUB = "github"
    ORG_WORDLIST = "org_wordlist"
    PUREDNS = "puredns"
    WAYBACK = "wayback"
    CERTSTREAM = "certstream"
    JS_SCRAPE = "js_scrape"


class DiscoverySourceEntry(Base):
    __tablename__ = "discovery_sources"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    subdomain_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("subdomains.id", ondelete="CASCADE"), nullable=False)
    source: Mapped[DiscoverySource] = mapped_column(Enum(DiscoverySource, values_callable=lambda x: [e.value for e in x]), nullable=False)
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    subdomain: Mapped["Subdomain"] = relationship(back_populates="discovery_sources")

    __table_args__ = (
        UniqueConstraint("subdomain_id", "source", name="uq_subdomain_source"),
        Index("ix_discovery_sources_source", "source"),
    )


class NotificationChannel(enum.Enum):
    DISCORD = "discord"


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    subdomain_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("subdomains.id", ondelete="CASCADE"), nullable=False)
    channel: Mapped[NotificationChannel] = mapped_column(Enum(NotificationChannel, values_callable=lambda x: [e.value for e in x]), nullable=False)
    sent_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)  # JSON

    subdomain: Mapped["Subdomain"] = relationship(back_populates="notifications")

    __table_args__ = (
        Index("ix_notifications_subdomain_id", "subdomain_id"),
        Index("ix_notifications_sent_at", "sent_at"),
    )


class StateTransition(Base):
    __tablename__ = "state_transitions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    subdomain_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("subdomains.id", ondelete="CASCADE"), nullable=False)
    from_state: Mapped[Optional[SubdomainState]] = mapped_column(Enum(SubdomainState, values_callable=lambda x: [e.value for e in x]), nullable=True)
    to_state: Mapped[SubdomainState] = mapped_column(Enum(SubdomainState, values_callable=lambda x: [e.value for e in x]), nullable=False)
    transitioned_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    reason: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    subdomain: Mapped["Subdomain"] = relationship()

    __table_args__ = (
        Index("ix_state_transitions_subdomain_id", "subdomain_id"),
        Index("ix_state_transitions_transitioned_at", "transitioned_at"),
    )


class DomainAvailabilityState(enum.Enum):
    REGISTERED = "registered"   # Domain is currently owned — not buyable
    AVAILABLE  = "available"    # Domain is free to register right now
    UNKNOWN    = "unknown"      # WHOIS lookup failed or returned no expiry


class DomainAvailability(Base):
    """
    Tracks scope root domains and their WHOIS expiry dates.

    Lifecycle:
      1. Row is created when a new scope domain is first discovered.
         WHOIS is run once at that point to populate expires_at + registrar.
      2. The buy-scanner runs each daemon iteration and queries only rows
         where expires_at <= now.  For those it performs a lightweight
         availability check (DNS resolution) and notifies via Discord if
         the domain can be registered.
    """
    __tablename__ = "domain_availability"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    # The root domain being watched (e.g. "example.com")
    domain: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)

    # Current availability state
    state: Mapped[DomainAvailabilityState] = mapped_column(
        Enum(DomainAvailabilityState, values_callable=lambda x: [e.value for e in x]),
        default=DomainAvailabilityState.REGISTERED,
        nullable=False,
    )

    # WHOIS expiry date — None means we couldn't determine it (privacy proxy etc.)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Metadata
    registrar: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    whois_raw: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Audit columns
    first_seen_at: Mapped[datetime]   = mapped_column(DateTime, default=datetime.utcnow)
    last_checked_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Notification tracking — avoid re-alerting every cycle
    last_notified_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # WHOIS failure tracking — after WHOIS_RETRY_LIMIT consecutive failures
    # Once True, WHOIS retries stop for this domain.
    # Resets to 0 / False if a successful WHOIS response is ever received.
    whois_retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    whois_give_up: Mapped[bool]    = mapped_column(Boolean, default=False, nullable=False)

    __table_args__ = (
        Index("ix_domain_availability_state",       "state"),
        Index("ix_domain_availability_expires_at",  "expires_at"),
        Index("ix_domain_availability_last_checked", "last_checked_at"),
    )


class ExposureFinding(Base):
    """
    Deduplicated exposure findings per subdomain+path.

    One row per (subdomain, path) pair. On first discovery the row is
    inserted and a Discord notification fires. On subsequent scans the
    row already exists — no notification. The `last_seen_at` column is
    updated every scan so you can tell if a finding is still live.

    url, tags, snippet and last_notified_at are written by
    exposure_scanner._persist(). body_snippet is kept for backwards
    compatibility with existing rows.
    """
    __tablename__ = "exposure_findings"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    subdomain_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("subdomains.id", ondelete="CASCADE"), nullable=False
    )
    path: Mapped[str] = mapped_column(String(1024), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)  # critical/high/medium
    description: Mapped[str] = mapped_column(Text, nullable=False)
    url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tags: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    snippet: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    body_snippet: Mapped[Optional[str]] = mapped_column(Text, nullable=True)    # kept for backwards compat
    status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    content_length: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_notified_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    subdomain: Mapped["Subdomain"] = relationship(back_populates="exposure_findings")

    __table_args__ = (
        UniqueConstraint("subdomain_id", "path", name="uq_exposure_subdomain_path"),
        Index("ix_exposure_findings_subdomain_id", "subdomain_id"),
        Index("ix_exposure_findings_severity", "severity"),
        Index("ix_exposure_findings_last_seen_at", "last_seen_at"),
        Index("ix_exposure_findings_last_notified_at", "last_notified_at"),
    )


# ---------------------------------------------------------------------------
# Git scanning models
# ---------------------------------------------------------------------------

class GitScope(Base):
    """
    A GitHub/GitLab scope entry extracted from a bug bounty program.

    Examples of repo_url values:
      https://github.com/shopify          — bare org → expand via API (wildcard)
      https://github.com/shopify/shopify-api-ruby — single repo → scan directly
      https://gitlab.com/gitlab-org       — bare GitLab group (wildcard)
    """
    __tablename__ = "git_scopes"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    program_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("programs.id", ondelete="CASCADE"), nullable=False
    )

    # Raw URL normalised (no trailing slash, no /* suffix — stored as bare org URL)
    repo_url: Mapped[str] = mapped_column(String(2048), nullable=False)

    # "github" or "gitlab"
    platform: Mapped[str] = mapped_column(String(32), nullable=False)

    # True when the original scope was a wildcard (org-level) → requires API enumeration
    is_wildcard: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    added_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Stamped when wildcard expansion (or direct project add) finishes.
    # Priority queue: NULL first, then oldest.
    last_expanded_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    program: Mapped["Program"] = relationship(back_populates="git_scopes")
    git_projects: Mapped[List["GitProject"]] = relationship(
        back_populates="git_scope", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("program_id", "repo_url", name="uq_git_scope_program_url"),
        Index("ix_git_scopes_program_id", "program_id"),
        Index("ix_git_scopes_platform", "platform"),
        Index("ix_git_scopes_last_expanded_at", "last_expanded_at"),
        Index("ix_git_scopes_is_active", "is_active"),
    )


class GitProject(Base):
    """
    An individual repository resolved from a GitScope.

    One row per concrete repo URL (no wildcards). Created either directly from
    a non-wildcard GitScope, or by expanding a wildcard scope via the GitHub/GitLab API.
    """
    __tablename__ = "git_projects"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    git_scope_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("git_scopes.id", ondelete="CASCADE"), nullable=False
    )

    # Canonical HTTPS URL of the repo (no trailing slash)
    # e.g. https://github.com/shopify/shopify-api-ruby
    repo_url: Mapped[str] = mapped_column(String(2048), nullable=False)

    # Display name (e.g. "shopify/shopify-api-ruby")
    repo_name: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    added_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # NULL = not yet scanned; stamped after trufflehog finishes (even with 0 findings)
    last_scanned_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Count of verified findings from the last scan
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    git_scope: Mapped["GitScope"] = relationship(back_populates="git_projects")

    last_commit_sha: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        UniqueConstraint("git_scope_id", "repo_url", name="uq_git_project_scope_url"),
        Index("ix_git_projects_git_scope_id", "git_scope_id"),
        Index("ix_git_projects_last_scanned_at", "last_scanned_at"),
        Index("ix_git_projects_repo_url", "repo_url"),
    )


class JsSecretRecord(Base):
    """Persisted JS secret finding (one row per file + detector + value)."""

    __tablename__ = "js_secret_findings"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    scope_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("scopes.id", ondelete="CASCADE"), nullable=False
    )
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    secret_type: Mapped[str] = mapped_column(String(128), nullable=False)
    redacted: Mapped[str] = mapped_column(String(512), nullable=False)
    line_number: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    scope: Mapped["Scope"] = relationship()

    __table_args__ = (
        UniqueConstraint("scope_id", "url", "secret_type", "redacted", name="uq_js_secret"),
        Index("ix_js_secret_findings_scope_id", "scope_id"),
        Index("ix_js_secret_findings_last_seen_at", "last_seen_at"),
    )


class GitSecretRecord(Base):
    """Persisted verified git secret finding (one row per project + detector + value)."""

    __tablename__ = "git_secret_findings"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    git_project_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("git_projects.id", ondelete="CASCADE"), nullable=False
    )
    detector: Mapped[str] = mapped_column(String(128), nullable=False)
    redacted: Mapped[str] = mapped_column(String(512), nullable=False)
    file_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    verified: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    git_project: Mapped["GitProject"] = relationship()

    __table_args__ = (
        UniqueConstraint(
            "git_project_id", "detector", "redacted", name="uq_git_secret"
        ),
        Index("ix_git_secret_findings_project_id", "git_project_id"),
        Index("ix_git_secret_findings_last_seen_at", "last_seen_at"),
    )
