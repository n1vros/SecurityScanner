# AGENTS.md

Guidance for coding agents and humans working in this repository.

## What this project is

**STOscanner** is a continuous subdomain-takeover and attack-surface scanner for
bug bounty programs. It imports program scopes from bounty platforms, discovers
subdomains, probes DNS/HTTP, evaluates dangling-DNS / takeover conditions, and
reports findings through a FastAPI web UI and Discord notifications.

## Tech stack

| Area | Technology |
| --- | --- |
| Language | Python 3.12 (`python3 --version` → 3.12.3) |
| Async runtime | `asyncio` throughout; no sync I/O in hot paths |
| Web | FastAPI + Jinja2 templates (`app/web/`), uvicorn |
| CLI | Typer + Rich (`app/core/cli.py`) |
| Database | PostgreSQL via SQLAlchemy 2 async + `asyncpg` |
| State/cache | In-process rate-limit buckets (Redis is provisioned but unused) |
| HTTP | `httpx` (with SOCKS), `aiohttp`, `tls-client` |
| DNS | `dnspython`, `puredns` + `massdns` subprocesses |
| Cloud SDKs | `aioboto3` (AWS), `azure-*`, `google-*` |
| Config | `pydantic-settings` reading `.env` (`app/core/config.py`) |

Runtime dependencies live in `requirements.txt`; development/CI dependencies in
`requirements-dev.txt`. `pyproject.toml` configures pytest and ruff, and
`.github/workflows/ci.yml` runs both. Tests are network-free and do not need a
database.

## Repository layout

```
main.py                  Entry point: daemon | web | CLI passthrough
app/core/                Config, logging, CLI, daemon + scheduler, rate limiting,
                         daemon process control (PID file shared by web/CLI)
app/db/                  SQLAlchemy models and async session/engine setup
app/discovery/           Passive, active, permutation, certstream, wayback,
                         JS-scrape and git-secret discovery
app/probing/             DNS/HTTP probing, dns_scanner/ (NS sweeps, IP analysis),
                         exposure scanner, IP liveness checks
app/takeover/            Takeover evaluators: subdomain_hunter, ns_hunter,
                         ip_hunter (AWS/Azure/GCP/DigitalOcean IP claims)
app/programs/            Bounty-platform loaders (HackerOne, Bugcrowd,
                         YesWeHack, Intigriti, Immunefi, Bugbase, HackenProof,
                         Disclose, BugBountyDirectory, manual) plus scheduled
                         resync (sync.py) and scope reconciliation (base.py)
app/notify/              Discord webhook notifications
app/web/                 FastAPI app + routes + Jinja2 templates
tests/                   pytest suite (state, confidence, platforms, takeover, web)
.github/workflows/       CI: ruff + pytest
init.sql                 PostgreSQL bootstrap mounted by Compose
files/                   YAML wordlists/signatures/provider lists, sample JSON
manual_platforms/        Manually curated program scope JSON
scripts/                 One-off ops/cloud scripts (not imported by the app)
config/                  Runtime config directory (currently empty)
.agents/skills/          Agent skills (see `commit/` for the commit workflow)
vault/                   Markdown knowledge vault (design notes, decisions)
PLAN.md                  As-built logic, gap audit and phased plan
SPEC.md                  Specification (intentionally empty for now)
Dockerfile               App image with every recon binary installed
docker-compose.yml       PostgreSQL 15 + Redis 7 + the web app
install-tools.sh         Host installer for the Go/Rust recon binaries
```

## Running it

```bash
# 1. Dependencies
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Local infrastructure (PostgreSQL + Redis)
docker compose up -d

# 3. Configuration
cp .env.example .env   # then set DB_PASSWORD, REDIS_PASSWORD and any API tokens
#    DB_HOST/DB_PORT/DB_NAME and REDIS_URL default to localhost

# 4. Run
python main.py web            # http://127.0.0.1:8000/web/dashboard , /docs
python main.py start          # detached scanner daemon (PID file shared with web)
python main.py daemon-status
python main.py stop
python main.py daemon         # foreground debug variant
python main.py status         # database statistics
pytest -q                     # unit tests (no DB/network)
```

Useful CLI commands (see `app/core/cli.py`): `add-program`, `programs-add`,
`update-scope`, `deactivate-scope`, `deactivate-program`, `ingest-platform`,
`sync-platforms`, per-platform imports (`hackerone`, `bugcrowd`, `ywh`,
`intigriti`, `immunefi`, `bugbase`, `hackenproof`, `disclosio`,
`bugbountydirectory`), `status`, `pause`, `resume`, `start`, `stop`,
`daemon-status`, `daemon`, `clear-all-ip`.

External binaries used at runtime: `subfinder`, `httpx`, `puredns`, `massdns`,
`alterx`, `gau`, `waybackurls`, `katana`, `trufflehog` (`nuclei` is no
longer part of the pipeline). Missing tools
should degrade gracefully (feature flags in settings), not crash the daemon.

## Configuration & secrets

- All settings are declared in `app/core/config.py` as `pydantic-settings`
  fields with `env=` names; read them via `from app.core.config import settings`.
- Secrets live in `.env` (gitignored) and `gcp.json` (gitignored). Never hardcode
  tokens, API keys, or credentials in source.
- `docker-compose.yml` reads all credentials from `.env` and refuses to start
  without `DB_PASSWORD` / `REDIS_PASSWORD`; never commit real values.
- Cloud takeover providers need their own credentials (AWS keys, `AZURE_CLIENT_*`,
  `GCP_SERVICE_ACCOUNT_*`, `DO_API_TOKEN`, `VERCEL_TOKEN`, `HEROKU_API_KEY`,
  `NETLIFY_TOKEN`). Every provider can be disabled via its `*_ENABLED` flag.

## Data flow (high level)

1. `app/programs/loader.py` syncs programs/scopes into the DB; the daemon
   resyncs each platform on its own interval (`PLATFORM_SYNC_ENABLED`,
   `*_SYNC_INTERVAL_DAYS`) and reconciles removed scopes/subdomains.
2. Discovery modules add `Subdomain` rows (passive sources, brute force,
   permutations, CT logs, Wayback, JS scraping, git secrets).
3. `app/core/daemon.py` orchestrates: DNS probe → HTTP probe → NS sweep →
   takeover evaluation → exposure scan → notifications, on a scheduler.
4. Findings are persisted and surfaced in the web UI, Discord, and reports.

## Conventions

- **Async first.** DB access goes through `app/db/session.get_session()` (an
  `asynccontextmanager`; use `async with`, not `async for`). Never share an
  `AsyncSession` across tasks.
- **Logging** via `app.core.logging.logger`; do not add `print()` in library code.
- **Rate limits** are centralized in `app/core/ratelimit.py` and the per-CDN
  settings in `config.py`. Respect them; add new external calls to the limiter.
- **Feature flags** (`*_ENABLED` settings) guard every optional/expensive module.
  New scanners should default to `False` unless they are core.
- Match existing style: 4-space indent, `snake_case`, type hints on public
  functions, docstrings on modules/classes, module-level imports.
- Subprocess tool paths are settings (`*_BINARY` / `*_PATH`), never bare strings.
- Findings should stay deduplicated and re-notify-aware (see `*_RENOTIFY_*`
  settings) to avoid alert spam.
- **Comments describe durable behaviour** — intent, invariants, thresholds and
  external quirks. Never use them as a changelog: no `FIX`/`BUG-FIX` labels,
  ticket numbers, dates, "previously/was" narratives, or restatements of the
  next line. See the `comments` skill before cleaning or adding comments.

## Known gotchas

- `docker-compose.yml` has no default credentials: it refuses to start without
  `DB_PASSWORD` and `REDIS_PASSWORD` in `.env`. `init.sql` is committed and
  mounted by Compose.
- **Daemon control is opt-in.** `DAEMON_AUTOSTART` defaults to false. The web UI
  and CLI share `/tmp/stoscanner-daemon.pid` (override `STOSCANNER_PID_FILE`),
  so either side sees and stops the same process. The daemon runs in a new
  session and survives a web restart, but a container/process-group stop kills
  it.
- **Automatic claims** require `TAKEOVER_AUTO_ENABLED`, DANGLING confidence,
  provider credentials, and a non-parent host. A claimed host must serve
  `TAKEOVER_CLAIM_MARKER` before it is reported as claimed; failures retry per
  `retry_policy.py`.
- `files/*.yaml` are loaded once at startup: editing a signature/provider file
  requires a daemon restart, and there is no automatic refresh.
- `config/` is empty and `manual_platforms/` holds hand-maintained JSON.
- Windows/macOS is not supported for tool installation; `install-tools.sh`
  targets Debian/Ubuntu with root privileges and Go installed.
- The daemon writes temporary files under `/tmp/gitscan` and
  `files/resolvers_cache.txt`; keep those paths configurable.
- Git history is on `master`; the project is actively evolving (see `TODO.txt`).

## Working agreements for agents

- Read the relevant module before editing; prefer minimal, targeted diffs.
- Do not commit `.env`, `gcp.json`, caches, or scan output.
- When adding a dependency, update `requirements.txt` and note why.
- When adding a setting, add it to `app/core/config.py` with an `env=` alias and
  document it next to related options.
- If you add behavior, update this file, `README.md`, and the relevant note in
  `vault/`.
- **Plan** — `PLAN.md` is the single plan of record: read the current phase
  before starting work and update it when a phase ships.
- **Commits** — use the `commit` skill (`.agents/skills/commit/SKILL.md`). It
  stages all working files (not just the ones you touched), screens them with
  `scripts/preflight.sh`, and writes a single plain message with no attribution.
  Never add co-author trailers, "generated by" lines, or tool/model references.
- Run `pytest -q` and `ruff check app tests main.py` before committing. Add a
  regression test to `tests/` for every bug fix; state, confidence, verdicts,
  platform filters/reconciliation, takeover policy and web routes are covered.
- Keep platform sync and takeover retry behavior testable through pure helpers
  (`programs/base.py`, `programs/bounty_utils.py`, `takeover/.../retry_policy.py`)
  rather than hiding decisions in I/O code.
