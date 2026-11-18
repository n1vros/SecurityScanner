"""
Async database session management.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.core.config import settings
from app.db.db_models import Base

# Ensure DATABASE_URL is set
if settings.DATABASE_URL is None:
    raise ValueError("DATABASE_URL is not configured")

DATABASE_URL = str(settings.DATABASE_URL)

# Engine kwargs
engine_kwargs = {
    "echo": settings.DB_ECHO,
    "pool_pre_ping": True,  # detect stale connections before use
}

# Optional pool configuration
if settings.DB_POOL_DISABLE:
    engine_kwargs["poolclass"] = NullPool
else:
    engine_kwargs.update(
        {
            "pool_size": settings.DB_POOL_SIZE,
            "max_overflow": settings.DB_MAX_OVERFLOW,
            "pool_recycle": settings.DB_POOL_RECYCLE,
            "pool_timeout": 30,
            "connect_args": {
                "server_settings": {
                    "tcp_keepalives_idle": "60",
                    "tcp_keepalives_interval": "10",
                    "tcp_keepalives_count": "5",
                }
            },
        }
    )

# Async engine
engine = create_async_engine(DATABASE_URL, **engine_kwargs)

# Async session maker
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,  # prevent auto flush to avoid "Session is already flushing"
)


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Async DB session context manager.

    - Does NOT auto-commit on exit — business logic owns commit boundaries.
    - Rolls back on unhandled exceptions to release locks immediately.
    - Each caller gets a dedicated session for concurrency safety.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


async def create_tables() -> None:
    """Create all tables (dev/testing only)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def run_enum_migrations() -> None:
    """
    Idempotently add new enum values and columns to the existing PostgreSQL schema.

    SQLAlchemy's create_all() only creates missing *tables* — it never alters
    existing enum types or adds new columns.  When a new value is added to a
    Python Enum (e.g. SubdomainState.POTENTIAL_LONG) the DB type must be updated
    separately.  Likewise new columns must be added via ALTER TABLE.

    IMPORTANT: PostgreSQL requires ALTER TYPE ... ADD VALUE to run outside an
    explicit transaction block (it cannot be rolled back).  Each statement is
    executed via a dedicated AUTOCOMMIT connection so no transaction wraps it.
    IF NOT EXISTS (Postgres 9.3+) makes each run idempotent.
    """
    from sqlalchemy import text
    from sqlalchemy.exc import ProgrammingError

    # ── Enum value migrations ─────────────────────────────────────────────────
    enum_migrations = [
        "ALTER TABLE git_projects ADD COLUMN IF NOT EXISTS last_commit_sha VARCHAR(64)",
    ]

    # ALTER TYPE ADD VALUE must run outside a transaction block in Postgres.
    # Use AUTOCOMMIT isolation so each statement commits immediately.
    async with engine.connect() as conn:
        await conn.execution_options(isolation_level="AUTOCOMMIT")
        for sql in enum_migrations:
            try:
                await conn.execute(text(sql))
            except ProgrammingError as exc:
                err = str(exc).lower()
                # Type doesn't exist yet (fresh DB) — create_all will handle it
                if "does not exist" in err or "undefined object" in err:
                    pass
                else:
                    raise

    # ── Column migrations — idempotent via IF NOT EXISTS ──────────────────────
    # Add new columns to existing tables without touching existing data.
    column_migrations = [
        "ALTER TABLE scopes ADD COLUMN IF NOT EXISTS dns_takeover_notified_at TIMESTAMP",
        "ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS last_ns_sweep_at TIMESTAMP",
        "CREATE INDEX IF NOT EXISTS ix_subdomains_last_ns_sweep_at ON subdomains (last_ns_sweep_at)",
        "ALTER TABLE scopes ADD COLUMN IF NOT EXISTS manually_deactivated BOOLEAN NOT NULL DEFAULT FALSE",
        "CREATE INDEX IF NOT EXISTS ix_scopes_manually_deactivated ON scopes (manually_deactivated)",
        "CREATE INDEX IF NOT EXISTS ix_scopes_is_active ON scopes (is_active)",
        "ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS exposure_checked_paths TEXT",
        "ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS ip_addresses TEXT",
        "ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS ipv6_addresses TEXT",
        # IP takeover qualification — aggregate flag plus per-IP verdict storage
        "ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS ip_free BOOLEAN",
        "ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS ip_free_checked_at TIMESTAMP",
        "ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS ip_verdicts TEXT",
        "CREATE INDEX IF NOT EXISTS ix_subdomains_ip_free ON subdomains (ip_free)",
        # IP hunter attempts table
        "CREATE TABLE IF NOT EXISTS ip_hunt_attempts ("
        "  id BIGSERIAL PRIMARY KEY,"
        "  provider VARCHAR(32) NOT NULL,"
        "  region VARCHAR(64) NOT NULL,"
        "  cidr_block VARCHAR(20) NOT NULL,"
        "  ip_hit VARCHAR(45),"
        "  hit BOOLEAN NOT NULL DEFAULT FALSE,"
        "  attempts INTEGER NOT NULL DEFAULT 0,"
        "  score_at_hunt FLOAT,"
        "  attempted_at TIMESTAMP NOT NULL,"
        "  released_at TIMESTAMP,"
        "  error TEXT"
        ")",
        "CREATE INDEX IF NOT EXISTS ix_ip_hunt_attempts_hit ON ip_hunt_attempts (hit)",
        "CREATE INDEX IF NOT EXISTS ix_ip_hunt_attempts_attempted_at ON ip_hunt_attempts (attempted_at)",
        "CREATE INDEX IF NOT EXISTS ix_ip_hunt_attempts_provider ON ip_hunt_attempts (provider)",
        "CREATE INDEX IF NOT EXISTS ix_ip_hunt_attempts_cidr_block ON ip_hunt_attempts (cidr_block)",
        # Automatic platform sync bookkeeping
        "CREATE TABLE IF NOT EXISTS platform_sync_state ("
        "  id BIGSERIAL PRIMARY KEY,"
        "  platform VARCHAR(64) NOT NULL UNIQUE,"
        "  last_synced_at TIMESTAMP,"
        "  last_status VARCHAR(32),"
        "  last_error TEXT,"
        "  updated_at TIMESTAMP NOT NULL DEFAULT NOW()"
        ")",
        "CREATE INDEX IF NOT EXISTS ix_platform_sync_state_last_synced_at ON platform_sync_state (last_synced_at)",
        # NS lottery takeover attempt stamps
        "ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS aws_route53_attempted_at TIMESTAMP",
        "CREATE INDEX IF NOT EXISTS ix_subdomains_aws_route53_attempted_at ON subdomains (aws_route53_attempted_at)",
        "ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS azure_dns_attempted_at TIMESTAMP",
        "CREATE INDEX IF NOT EXISTS ix_subdomains_azure_dns_attempted_at ON subdomains (azure_dns_attempted_at)",
        "ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS gcp_dns_attempted_at TIMESTAMP",
        "CREATE INDEX IF NOT EXISTS ix_subdomains_gcp_dns_attempted_at ON subdomains (gcp_dns_attempted_at)",
        # Automatic takeover attempt outcome + retry schedule
        "ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS takeover_last_status VARCHAR(32)",
        "ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS takeover_retry_at TIMESTAMP",
        "CREATE INDEX IF NOT EXISTS ix_subdomains_takeover_retry_at ON subdomains (takeover_retry_at)",
        # HTTP probe snapshot — the prober already writes these attributes
        "ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS http_status INTEGER",
        "ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS http_title VARCHAR(1000)",
        "ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS http_body_hash VARCHAR(64)",
        "ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS http_content_length INTEGER",
        "ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS http_probed_at TIMESTAMP",
        # ExposureFinding — four columns were missing; their absence caused a TypeError
        # on every INSERT, silently dropping all exposure scanner Discord alerts.
        "ALTER TABLE exposure_findings ADD COLUMN IF NOT EXISTS url TEXT",
        "ALTER TABLE exposure_findings ADD COLUMN IF NOT EXISTS tags TEXT",
        "ALTER TABLE exposure_findings ADD COLUMN IF NOT EXISTS snippet TEXT",
        "ALTER TABLE exposure_findings ADD COLUMN IF NOT EXISTS last_notified_at TIMESTAMP",
        "CREATE INDEX IF NOT EXISTS ix_exposure_findings_last_notified_at ON exposure_findings (last_notified_at)",
    ]

    async with engine.connect() as conn:
        await conn.execution_options(isolation_level="AUTOCOMMIT")
        for sql in column_migrations:
            try:
                await conn.execute(text(sql))
            except ProgrammingError as exc:
                err = str(exc).lower()
                if "does not exist" in err or "already exists" in err:
                    pass
                else:
                    raise


async def drop_tables() -> None:
    """Drop all tables (testing only)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
