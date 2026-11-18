# STOscanner — As-Built Logic, Gap Audit and AI Work Plan

> **Snapshot:** 2026-11-17, commit `a2093cc` (`master`); updated after the
> first fix round (§1.4) and the second implementation round (§1.5). Last
> functional change before the audit:
> `a3eb8d8` on 2026-04-09 — roughly 7 months before this audit (the request
> estimated nine; git history measures seven).
> **Method:** static reading of all 90 Python modules (~32.8k lines), the YAML
> data files, `requirements.txt`, Docker Compose and the web templates.
> **Caveat:** the scanner has been exercised against PostgreSQL and a real web
> process, and the Docker stack was built and started. No target, bounty
> platform account or cloud provider was scanned; provider API behavior remains
> mocked. Anything uncertain is marked **[unverified]**. See §11.
>
> **Audience:** the project owner (what exists, what is broken, what to decide)
> and the AI agent (what to do, in which order, with which invariants).

---

## 0. How to use this file

- **Owner:** read §1 (summary), §8 (gaps and risks) and §12 (decisions). Everything else
  is reference.
- **AI agent:** read §8 before touching anything, follow §9 phases in order, and
  respect §10 invariants. Do not start a later phase while a P0 blocker
  (P0-1/P0-2) remains.
- **Living document:** when a phase ships, tick its acceptance boxes and update
  the affected sections here together with `AGENTS.md` and `README.md`.
- **Line references** are from the snapshot above; treat them as search hints,
  not permanent addresses.

---

## 1. Executive summary

### 1.1 What the project is

STOscanner is a continuous, bug-bounty-oriented attack-surface scanner. It
ingests program scopes from bounty platforms, discovers subdomains, probes DNS
and HTTP, evaluates takeover conditions (subdomain, DNS/NS and cloud-IP),
detects leaked secrets and exposed files, attempts automated takeover where it
is safe and legal to do so, and reports findings to Discord and a web dashboard.

### 1.2 The pipeline in one paragraph

Programs and scopes are synced into PostgreSQL from ten platform adapters or a
manual JSON file. A daemon iteration picks programs whose scan interval elapsed,
runs discovery for each scope (subfinder, crt.sh, puredns brute force, alterx
permutations, gau/waybackurls, katana + JS scraping, certificate transparency,
git-secret scanning), then probes every queued subdomain (raw-UDP DNS, TCP
liveness, TLS-fingerprinted HTTP behind per-domain and per-CDN token buckets).
The takeover evaluator combines DNS and HTTP signatures from `signatures.yaml`,
runs provider-specific verification and, for a subset of providers, actually
claims the resource and deploys a PoC. Independent background loops run a weekly
NS/DNS sweep (dangling delegation, dangling cloud IPs, CNAME chains, SPF/DMARC),
a continuous exposure scanner, an optional cloud-IP hunter, an optional git
secret scanner, certstream monitoring and a domain-availability scanner.
Findings are deduplicated, persisted, and pushed to Discord as report-ready
embeds; the FastAPI + Jinja UI exposes the same data.

### 1.3 Your six-point idea vs. what is implemented

| # | Intended behaviour | Status | Notes |
| --- | --- | --- | --- |
| 1 | Gather programs from HackerOne, YesWeHack, Bugcrowd, Intigriti | **Done** (+6 more platforms and manual JSON) | Automatic per-platform resync, bounty-only and subdomain-only; cookie/HTML adapters remain brittle |
| 2 | Scan subdomains and main domains | **Mostly** | Subdomains are discovered and probed continuously; scope roots are covered by the weekly NS/DNS sweep and NS lottery, but are not run through the HTTP/takeover evaluator unless they appear as a discovered subdomain |
| 3 | Check many vulnerability classes | **Done** | Subdomain takeover, DNS/NS takeover, cloud-IP takeover, leaked credentials (JS + git), exposed files, dangling SPF/DMARC, wildcard CNAME/A, foreign TLS cert, available CNAME-hop domains, expiring/available domains |
| 4 | Automatically take over and validate | **Done** | Vercel, Heroku, Netlify, S3 and some Azure services are auto-claimed and validated against the live host; NS lotteries and cloud-IP hunts; retry/no-retry policy. Remaining: claim cleanup tooling and dry-run mode |
| 5 | Discord notification with a report-ready summary | **Done** | Rich embeds with program, platform, provider, evidence, claim status. Missing: report export, channel separation, queueing |
| 6 | UI to organise findings | **Partially** | Dashboard/API/findings/program/subdomain pages with working daemon Start/Stop/Restart; no auth, triage workflow or report export |

### 1.4 Fix status (first fix round)

| Item | Status | What changed |
| --- | --- | --- |
| P0-1 missing modules | **Fixed** | `discovery/state.py`, `discovery/resolvers.py`, `probing/confidence.py`, `probing/ip_verdicts.py` implemented; full import graph passes |
| P0-2 environment | **Fixed** | `.env.example` (230 settings), env-driven Compose with no default secrets, committed `init.sql`, `boto3` + `sqlalchemy[asyncio]` added |
| P0-3 undefined settings | **Fixed** | all 29 `getattr` knobs declared in `Settings`; regression test asserts it |
| P0-4 migrations | **Open** | Alembic not adopted yet; new tables use `create_all()` |
| P1-1 secret persistence | **Fixed** | `js_secret_findings` / `git_secret_findings` tables, upserts, `/api/js-secrets`, `/api/git-secrets` |
| P1-2 Route 53 parent bug | **Fixed** | scope roots enqueue with `is_parent=True`; regression test pending |
| P1-3 exposure tag mapping | **Fixed** | `credentials` → `creds` directory |
| P1-4 daemon stub | **Fixed** | real subprocess supervisor (start/stop/restart/status) with limitations documented |
| P1-5 adapter resilience | **Open** | retries/backoff and cookie-expiry reporting still missing |
| P2 data freshness | **Open** | no refresh/versioning for `files/*.yaml` |
| P2 packaging/docs drift | **Partly fixed** | Docker docs consolidated into README.md, CI added, path defaults corrected |
| Tests / CI | **Fixed** | 36 pytest tests (state ladder, confidence, verdicts, resolvers, config, domain utils), ruff, GitHub Actions |

Additional bugs found and fixed during the round:

- `TAKEOVER_SIGNATURES_PATH` and `EXPOSURE_WORDLIST_PATH` pointed at files that
  do not exist (`app/takeover/signatures.yaml`, `exposure_paths.yaml`), so the
  evaluator loaded **zero** signatures and the exposure scanner zero paths.
- `ip_verdicts` also needed `filter_current_ip_verdicts` / `load_ip_verdicts`
  for the IP hunter; both are implemented and tested.
- Signature/wordlist paths are now resolved against the project root instead of
  the current working directory.
- Requirements were missing `greenlet`/`sqlalchemy[asyncio]`, so no async DB
  code could import on a clean install.

An end-to-end smoke test was run: a temporary PostgreSQL 17 container, one
daemon iteration (`DAEMON_MAX_ITERATIONS=1`, background loops disabled), all 13
tables created, clean shutdown. No target was scanned and no platform/cloud
credentials were exercised.

Known follow-ups after this round: Alembic adoption, adapter backoff, YAML data
refresh/versioning, and UI pages for the persisted secrets (the API exists).

### 1.5 Second implementation round (Docker, sync, control, takeover)

| Area | Result |
| --- | --- |
| Docker | Multi-stage `Dockerfile` installs all nine recon binaries at pinned versions; `docker compose up` starts PostgreSQL, Redis and the app. Image built (≈344 MB compressed, 1.36 GB on disk) and smoke-tested: healthy, 13 tables, `/api/stats` and `/docs` 200, one daemon iteration exits 0. |
| Platform resync | Per-platform intervals (`*_SYNC_INTERVAL_DAYS`, default 7), `platform_sync_state` table, daemon poll loop, `sync-platforms` CLI. Bounty-only and subdomain-only filters for HackerOne/YesWeHack/Intigriti/Bugcrowd; removed scopes/programs deactivate their subdomains unless operator-excluded; partial/empty listings never delete data. |
| Daemon control | Autostart is opt-in (`DAEMON_AUTOSTART=false`). A shared PID-file controller gives identical `start`/`stop`/`daemon-status` behavior from CLI and the web UI, including cross-control and stale-PID handling. |
| Takeover | Audited end-to-end; 22 issues fixed. Provider successes are validated against the live host (`TAKEOVER_CLAIM_MARKER`) before `CLAIMED`; outcomes drive retry (`TAKEOVER_RETRY_HOURS`/`_DAYS`) or terminal states. Automatic attempts are gated by DANGLING confidence, `TAKEOVER_AUTO_ENABLED`, credentials and a parent-domain guard. |
| Web UI | Fixed the Starlette 1.10 `TemplateResponse` calls and the invalid Jinja `{% now %}` tags; added `/web/dashboard`, the missing subdomain-detail template, a 404 page and `/api/latest-findings`. |
| Verification | 192 tests, ruff clean, live web+PostgreSQL smoke (all pages 200), CLI/web cross-control, container build and stack smoke. |

### 1.6 Health snapshot

| Dimension | State | Evidence |
| --- | --- | --- |
| Importability | **Fixed** | Full import graph, daemon and web app start; 192 tests pass |
| Runtime deps | **Installed** | `.venv` created from `requirements.txt`/`requirements-dev.txt` |
| Database | **Verified** | 13 tables created via daemon and web startup; idempotent column/table migrations run at boot |
| Tests / CI / lint | **Present** | `tests/` (192 tests), `pytest`, `ruff`, GitHub Actions |
| Migrations | Ad-hoc SQL | `app/db/session.py` runs `ALTER TABLE … IF NOT EXISTS` strings |
| Configuration | **Consolidated** | 243 `Settings` fields, no undeclared `getattr` knobs, `.env.example` complete (regression-tested) |
| Data files | Present but stale | 177 signatures, 23 NS providers, 137 exposure paths, 17 IP providers load correctly, but there is still no refresh process |
| Documentation | **Current** | `AGENTS.md`, `README.md` (setup, Docker, pipeline and audit), `PLAN.md` describe the implemented state |
| Platform adapters | Brittle by design | Cookie scraping (Bugcrowd, HackenProof), HTML scraping (BugBountyDirectory), unofficial APIs (Bugbase) |

### 1.7 Top issues, ordered

Priority codes: **P0** = must fix before any production scan. P0-1/P0-2 and
P0-3 are resolved; P0-4 (Alembic) remains open. Most P1/P2 items are resolved —
see §1.4 and §1.5 for the current status.

| # | Severity | Area | Issue | Phase |
| --- | --- | --- | --- | --- |
| P0-1 | Blocker | Imports | `app/discovery/state.py`, `app/discovery/resolvers.py`, `app/probing/confidence.py`, `app/probing/ip_verdicts.py` do not exist, yet the daemon, discovery, probing and takeover modules import them | 0 |
| P0-2 | Blocker | Env | No `.env`/`.env.example`; Compose ships hard-coded dev credentials and mounts a missing `init.sql` | 0 |
| P0-3 | High | Settings | 29 settings used via `getattr` are absent from `Settings`, so `.env` values are silently ignored (`NS_SWEEP_BATCH_SIZE`, `DANGLING_IP_*`, `IP_HUNTER_MODE`, `SCOPE_CONCURRENCY`, …) | 2 |
| P0-4 | High | DB | No migration tool; schema evolution is hand-written SQL that runs at daemon startup | 2 |
| P1-1 | High | Correctness | JS secret findings claim DB persistence but no model/table exists; git findings store only a count | 5 |
| P1-2 | High | Correctness | Route 53 scope-root enqueue passes `is_parent=False` despite a comment promising `True` (§4.6.6) | 5 |
| P1-3 | Medium | Exposure | 70 of 137 wordlist entries are tagged `credentials`, which `_TAG_TO_SUBDIR` does not map — most credential findings are alerted but not saved to disk | 5 |
| P1-4 | Medium | UI | Web daemon controls were a stub — resolved in the second round with a shared PID-file controller | 7 |
| P1-5 | Medium | Resilience | Platform adapters have no retry/backoff and fail silently on cookie expiry; `CERTSTREAM_TAKEOVER_CHECK_ENABLED` is read via `getattr` and cannot be configured | 3 |
| P2-1 | Medium | Freshness | Signature/provider/wordlist data has no provenance, versioning or refresh path | 3 |
| P2-2 | Medium | Legal/safety | Auto-takeover runs by default when credentials exist; no authorization allowlist, dry-run mode or global kill switch | 5 |
| P2-3 | Medium | Packaging | `boto3` used by AWS EIP hunting/cleanup but absent from `requirements.txt`; Nuclei settings remain after Nuclei was removed | 0 |
| P2-4 | Low | Docs | Docker docs consolidated into `README.md`; `.env.example` exists; `.dockerignore` still mentions `app/nuclei/templates` | 8 |

---

## 2. Repository & environment snapshot

```
main.py                      CLI entry: daemon | web | pass-through to Typer
app/core/                    config, logging, CLI, daemon, scheduler, rate limits, PID-file daemon control
app/db/                      models + async engine/session + hand-rolled migrations
app/discovery/               passive, active, permutation, certstream, wayback, js_scrape, js_secrets, git_scanner
app/probing/                 dns, http, ip_check, exposure_scanner, domain_buy_scanner, dns_scanner/*
app/takeover/                subdomain_hunter, ns_hunter, ip_hunter
app/programs/                platform adapters + loader + scope/domain utilities
app/notify/                  Discord notifier
app/web/                     FastAPI app + routes + 7 Jinja templates
files/                       signatures, NS providers, IP providers, exposure wordlist, 2k subdomain wordlist, examples
manual_platforms/            hand-maintained JSON (e.g. federacy.json)
scripts/                     one-off ops scripts (not imported by the app)
vault/                       knowledge base (index + conventions)
AGENTS.md / README.md / PLAN.md
docker-compose.yml           PostgreSQL 15 + Redis 7 (Redis is not actually used)
```

- **Python:** 3.12; `requirements.txt` only (no lockfile, no `pyproject.toml`).
- **Process model:** a single asyncio process. `python main.py daemon` runs the
  whole pipeline; `python main.py web` runs FastAPI/uvicorn. They are separate
  processes that only share PostgreSQL — the web UI cannot start a daemon
  (§4.13).
- **Database:** PostgreSQL via SQLAlchemy 2 async + `asyncpg`. Redis is
  configured (`REDIS_URL`) and provisioned by Compose but **not used** by code:
  rate limiting is in-process only (§6.3).
- **Missing local files:** `.env`, `.env.example`, `init.sql`, and the four
  Python modules from P0-1. `.gitignore` covers `.env`, `gcp.json`, caches,
  databases and logs.

---

## 3. Architecture

```
┌───────────────────────────── CLI / Web ─────────────────────────────┐
│ main.py  ─┬─ daemon ── Daemon.run() ── Daemon._iteration()         │
│           ├─ web    ── FastAPI (api.py) + Jinja router (web.py)    │
│           └─ <cmd>  ── Typer CLI (programs, ingest, status, pause) │
└─────────────────────────────────────────────────────────────────────┘
                     │ SQLAlchemy async (asyncpg)
                     ▼
                PostgreSQL 15
                     ▲
   ┌─────────────────┴──────────────────────────────────────────────┐
   │                         Daemon                                 │
   │  main loop (DAEMON_SLEEP_SECONDS, default 60s)                 │
   │   ├─ Scheduler.get_programs_needing_scan → per-program scopes  │
   │   ├─ Discovery per scope (gated by first scan / cooldowns)     │
   │   ├─ Probe each subdomain (semaphore GLOBAL_CONCURRENCY_LIMIT) │
   │   ├─ Recheck POTENTIAL / POTENTIAL_LONG                        │
   │   ├─ Process queued notifications                              │
   │   └─ Domain-buy scan (fire and forget)                         │
   │  background tasks started once at boot:                        │
   │   ├─ certstream monitor          ├─ NS sweep loop (weekly)     │
   │   ├─ SPF/DMARC sweep loop        ├─ exposure loop (continuous) │
   │   ├─ IP hunter loop (optional)   ├─ git scanner loop (optional)│
   │   ├─ Route53 / GCP DNS lottery workers (module singletons)     │
   │   └─ CIDR index refresh loop                                   │
   └────────────────────────────────────────────────────────────────┘
                     │
        ┌────────────┼─────────────┬──────────────┬─────────────┐
        ▼            ▼             ▼              ▼             ▼
   Discovery     DNS/HTTP      Takeover       Exposure      Notifier
   (tools +      probers       evaluators     scanner       (Discord)
    APIs)        + rate limits + providers
```

**Design characteristics worth preserving**

- Every expensive subsystem is behind a `*_ENABLED` flag.
- External calls are rate-limited (per root domain, per CDN, per provider API,
  per confirmation resolver).
- Long work runs in background tasks with strong references; scans never block
  the main loop.
- Findings are deduplicated in the DB and re-notified on cooldowns.
- Scanners degrade gracefully when an optional tool or credential is missing.

**Design characteristics that hurt**

- Four missing modules break the import graph.
- Health of the system is only visible through logs; no metrics/health endpoint.
- Session handling is repeated ad hoc (`get_session()` everywhere), with several
  documented "double commit/expire" bugs fixed in comments.
- Business rules live in comments as much as in code (see the long docstrings in
  `evaluator.py`, `ip_indicators.py`, `providers_evaluator.py`).

---

## 4. Mechanics inventory (as built)

### 4.1 Program ingestion

Adapters live in `app/programs/platforms/` and are registered in
`app/programs/loader.py`. `PlatformBase.sync_programs()` creates/updates
`Program` rows, deduplicates scopes per program, and records git scopes.

| Platform | Auth / credential | Source | Notes |
| --- | --- | --- | --- |
| HackerOne | `H1_USERNAME`, `H1_API_TOKEN` (API v1) | `api.hackerone.com` | `asset_type=SOURCE_CODE` routed to git scopes |
| YesWeHack | `YWH_TOKEN` (Bearer) | `api.yeswehack.com` | Programs + scopes |
| Intigriti | `INTI_TOKEN` (Bearer) | `api.intigriti.com/external/researcher` | `status.id == 3` open, `type.id == 1` bounty, `type.id == 4` excluded |
| Bugcrowd | `BC_SESSION` cookie (`_bugcrowd_session`), optional crowdcontrol cookie | `bugcrowd.com` | No public API — HTML/JSON scraping |
| HackenProof | `HP_CF_CLEARANCE` + `HP_REMEMBER_USER_TOKEN` cookies | `hackenproof.com/api/internal/...` | Cloudflare-protected |
| BugBase | None (CSRF cookie set on first request) | `bugbase.ai/api/hacktivity` | Only `web`/`api` asset types |
| Immunefi | None | GitHub raw JSON (`infosec-us-team`) | Public dataset |
| Disclose.io | None | GitHub raw `diodb/program-list.json` | Detects platform from program URL |
| BugBountyDirectory | None | `bugbountydirectory.com` HTML | Per-program page scraping |
| Manual | Local JSON file | `programs-add <file>` CLI | Accepts domains, wildcards, URLs; also used for `manual_platforms/*.json` |

- **Scope parsing:** `app/programs/domain_utils.py` — wildcard expansion, URL →
  hostname, registrable-domain and platform-domain filtering, alternation
  expansion, dedup.
- **Git scopes:** `app/programs/git_scope_utils.py` parses GitHub/GitLab URLs /
  org wildcards into `GitScope` rows for the git secret scanner.
- **Manual deactivation:** `deactivate-scope`/`deactivate-program` set
  `manually_deactivated=True` and DEAD state so automated platform syncs never
  revive them.
- **Scheduled resync:** `app/programs/sync.py` polls every
  `PLATFORM_SYNC_POLL_SECONDS` (60 s) and syncs each of the four main platforms
  when its `*_SYNC_INTERVAL_DAYS` (default 7) has elapsed. `PLATFORM_SYNC_ENABLED`
  is the master switch; platforms without credentials are skipped with one
  warning. `sync-platforms [--platform]` runs the same path immediately.
- **Bounty-only and subdomain-only:** adapters keep only programs that pay
  bounties and only domain/wildcard/URL-host scopes. Source-code assets remain
  git scopes; mobile, API-only, hardware and other asset types are skipped (see
  `bounty_utils.py` and the per-adapter predicates).
- **Reconciliation:** a scope that disappears is deactivated and its subdomains
  are set DEAD; a reappearing scope is reactivated and its DEAD children are
  re-queued. `manually_deactivated` scopes and programs added outside the
  platform API are never touched. Removals run only for complete, non-empty
  listings.
- **Federacy** exists in the `ProgramPlatform` enum and in
  `manual_platforms/federacy.json`, but there is **no adapter**; it is imported
  as platform `federacy` via the manual JSON path.

### 4.2 Scheduling and cadences

All timestamps are UTC. `app/core/scheduler.py` is the single source of truth.

| What | Setting | Default | Notes |
| --- | --- | --- | --- |
| Daemon iteration sleep | `DAEMON_SLEEP_SECONDS` | 60 s | Main loop |
| Re-scan program | `SCAN_INTERVAL_HOURS` | 24 h | `Program.last_scan_at` |
| Re-scan scope discovery | `SCAN_INTERVAL_HOURS` | 24 h | `Scope.last_scanned_at` |
| Stale subdomain probe | `RESCAN_STALE_HOURS` | 168 h (7 d) | `Subdomain.last_scanned_at` |
| POTENTIAL recheck | `POTENTIAL_RECHECK_HOURS` | 24 h | Up to `POTENTIAL_RECHECK_LIMIT` (50)/iteration; deferred while `takeover_retry_at` is in the future |
| POTENTIAL_LONG recheck | `POTENTIAL_LONG_RECHECK_HOURS` | 72 h | Ownership-blocked findings |
| NS sweep | `NS_SWEEP_INTERVAL_HOURS` | 168 h | Scope roots first, then batches |
| NS sweep batch | `NS_SWEEP_BATCH_SIZE` | 1000 | Cursor pagination on `last_ns_sweep_at` |
| SPF/DMARC sweep | shares NS sweep interval | 168 h | One check per scope root |
| JS scrape | `JSSCRAPE_RESCAN_HOURS` | 336 h (14 d) | `Scope.last_js_scraped_at` |
| Exposure loop | continuous, ~5 s between cycles | — | Batch size `EXPOSURE_BATCH_SIZE` (100) |
| Git scanner | `GIT_SCANNER_INTERVAL_HOURS` | 24 h | Optional loop |
| IP hunter | `IP_HUNTER_INTERVAL_HOURS` | 6 h (per provider) | Optional; `IP_HUNTER_MODE` (`off`/`takeover`) |
| Certstream | continuous WebSocket | — | Scope cache refreshed every 300 s |
| CIDR index | `CIDR_INDEX_MAX_AGE_HOURS` | 24 h | Plus a refresh loop |
| Domain buy | every iteration | — | Fire-and-forget |
| Platform resync | `*_SYNC_INTERVAL_DAYS` | 7 d per platform | Poll every `PLATFORM_SYNC_POLL_SECONDS` (60 s) |
| Discord | ≥2 s between messages | — | 30 msg/min target |
| Takeover retry | `TAKEOVER_RETRY_HOURS` / `TAKEOVER_RETRY_DAYS` | 24 h / 7 d | Transient failures vs ownership-blocked/manual |

**Ordering detail:** `Scheduler.get_programs_needing_scan()` prioritises
never-scanned programs, and puts HackerOne last among them (large/noisy source),
then orders by `last_scan_at`. Program `last_scan_at` is stamped only after all
background probes finish, so pending work is never skipped.

### 4.3 Discovery

Runs per scope inside `Daemon._scan_scope()`. Each source writes `Subdomain`
rows (unique per `(scope_id, name)`) plus `DiscoverySourceEntry` provenance.

| Source | Implementation | Gate | Notes |
| --- | --- | --- | --- |
| Passive | `subfinder` + `crt.sh` HTTP JSON | every scope scan | `SUBFINDER_MAX_CONCURRENT`, timeout 120 s |
| Active brute force | `puredns bruteforce files/subdomains_2k.txt` with resolver file | **first scan only** | wildcard filtering inside puredns; shared semaphore |
| Permutations | `alterx` → `puredns resolve` | only for "interesting" seeds (dev/test/staging/…), or all seeds on an empty first scan | `ALTERX_ENRICH_ALL` overrides the seed filter; ALTERX + puredns concurrency caps |
| Wayback | `gau` + `waybackurls` | **first scan only** | Extracts hostnames from historical URLs |
| JS scrape | `gau` + `waybackurls` + `katana` + in-process fetch | every `JSSCRAPE_RESCAN_HOURS` | Fetch capped by size/time/concurrency; regex extraction of subdomains; proxied via `HTTP_PROXY`; per-domain/CDN rate limits |
| JS secrets | Regexes over fetched JS (+ optional TruffleHog) | same run as JS scrape | Findings are **Discord-only** — no DB table/model despite docstring |
| Git secrets | TruffleHog filesystem scan of cloned repos/archives | `GIT_SCANNER_ENABLED` | SHA-based skip, clone queue, archive depth 1, `--only-verified`; stores `findings_count` only |
| Certstream | CT log WebSocket (`certstream.calidog.io`) | `CERTSTREAM_ENABLED` | SAN match → upsert → expedited probe callback (§4.11) |

- `DiscoverySource` enum: `subfinder`, `crt_sh`, `github`, `org_wordlist`,
  `puredns`, `wayback`, `certstream`, `js_scrape`.
- Deduplication: `DiscoverySourceEntry` has `uq_subdomain_source`
  `(subdomain_id, source)`. Passive discovery inserts with
  `ON CONFLICT DO NOTHING`; active discovery does a select-then-insert, which is
  racy under concurrency (DB constraint prevents duplicates but may raise).
- Active/wayback intentionally run once: they are expensive and historical data
  does not change weekly.

### 4.4 Probing

Per subdomain, inside `Daemon._probe_subdomain()`:

1. **DNS** (`app/probing/dns.py`): raw UDP queries, a fresh random resolver per
   query from the pool, A/AAAA/CNAME, NXDOMAIN flag, timeout `DNS_PROBE_TIMEOUT`
   **[undefined setting]**. Updates `cname_target`, `ip_addresses`,
   `ipv6_addresses`, `dns_resolved_at`.
2. **IP liveness** (`app/probing/ip_check.py`): TCP connect to
   `IP_CHECK_PORTS` (default 22,80,443,3389,8080,8443), timeout 5 s, 20
   concurrent. Produces per-IP verdicts stored as `ip_verdicts` JSON +
   aggregate `ip_free`. Conservative: only "all probes silent" scores free.
3. **CDN detection & throttling** (`app/core/ratelimit.py`): CNAME → CDN key
   (`akamai`, `cloudflare`, `fastly`, `cloudfront`, `incapsula`, `sucuri`).
   Per-CDN token bucket shared across all subdomains behind that CDN;
   `*_RATE_LIMIT=0` skips HTTP entirely for that CDN this cycle.
4. **HTTP** (`app/probing/http.py`): `tls_client` with rotated browser TLS
   profiles (`chrome_124`, `firefox_120`, `safari_16_0`, …), browser-like
   headers, optional `HTTP_PROXY`. Returns status, headers, body (truncated),
   content length, final URL.

### 4.5 Subdomain takeover evaluation

Entry point: `TakeoverEvaluator.evaluate()` in
`app/takeover/subdomain_hunter/evaluator.py`; provider verification in
`providers_evaluator.py`.

**Decision tree (documented in the module and implemented accordingly):**

1. No DNS and no HTTP data → confidence 0, no state change.
2. Probe looks empty (no CNAME, no NXDOMAIN, no IPs, no HTTP) while already
   POTENTIAL/DANGLING → treat as transient timeout, preserve state.
3. Internal CNAME (same registrable domain) → ALIVE, confidence 0.
4. Alive 2xx + CNAME to a **claimable** provider and no provider error page in
   the body → **POTENTIAL** (confidence capped at 59).
5. NXDOMAIN + no CNAME → ALIVE (record does not exist; not a takeover).
6. NXDOMAIN + CNAME + recognised provider → score (DNS + HTTP) → state.
7. NXDOMAIN + CNAME + unrecognised provider → ALIVE (no way to confirm the
   resource is claimable; suppresses a known false-positive class).
8. CNAME + provider matched + claimable → score; a live HTTP fingerprint for a
   **different** provider gates the finding to 0; timeouts do not.
9. Non-claimable providers (e.g. CloudFront) → suppressed.

**Confidence ladder** (implemented in the missing `app/discovery/state.py`;
thresholds are referenced across the code):

| Confidence | State | Effect |
| --- | --- | --- |
| 0 | ALIVE | No alert |
| 30–59 | POTENTIAL | Monitored; rechecked daily; never alerts |
| ≥ 60 | DANGLING | Discord alert; queued for report |
| 60–72 | DANGLING (NOT_IMPL) | Alert labelled "auto-takeover N/A" |
| ≥ 82 | DANGLING (verified/claimed) | Distinct, higher-severity embed |
| — | POTENTIAL_LONG | Ownership-blocked; rechecked every 72 h |
| — | CLAIMED | Enum value exists; **[unverified]** whether any code path sets it today |

Thresholds referenced by name: `DANGLING_THRESHOLD` (60),
`POTENTIAL_LONG_THRESHOLD` (30). `ConfidenceScorer` (missing) computes DNS and
HTTP scores from signature weights; `StateManager` (missing) persists state
transitions.

**Provider verification and auto-takeover matrix**
(`app/takeover/subdomain_hunter/providers/`):

| Provider | Verification | Auto-takeover | Failure semantics |
| --- | --- | --- | --- |
| Vercel | API project/domain lookup | Create project + domain + deploy | `TAKEN` → NOT_VULN; `NEEDS_TXT` → POTENTIAL_LONG |
| Heroku | App existence pre-check | Create app + add domain + deploy | `name_reserved` → POTENTIAL_LONG |
| Netlify | Site existence pre-check | Create site + deploy zip | `domain_claimed_elsewhere` → POTENTIAL_LONG |
| AWS S3 | Bucket/website inspection | Create bucket, website config, upload HTML | `AccessDenied`/`NoSuchWebsiteConfiguration` → NOT_VULN |
| Azure | Resource existence via ARM REST | CDN / Front Door / Websites where supported | Other services → NOT_IMPL |
| GitHub Pages | Repo/account existence check | **Not implemented** (manual signup) | NOT_IMPL |
| AWS API Gateway | 403 `{"message":"Forbidden"}` fingerprint + optional SDK check | Impossible by design (account-bound hostname) | POTENTIAL_LONG |
| Not-implemented set | Stub | — | `fastly`, `ghost_io`, `surge_sh`, `readme_io`, `helpscout`, `zendesk`, `bitbucket`, `wordpress`, `smugmug`, `strikingly`, `ucraft`, `cargo`, `tilda`, `webflow`, `wix` |

- Provider API calls are throttled to 1 req/s globally
  (`TAKEOVER_CHECK_RATE_LIMIT`) and verified at most once per
  `TAKEOVER_PROVIDER_VERIFY_COOLDOWN_HOURS` (24 h) per provider/subdomain.
- `TakeoverStatus`: `SUCCESS`, `FAIL`, `NOT_VULN`, `NOT_IMPL`, `UNAVAILABLE`,
  `NEEDS_TXT`. Every NOT_VULN/TAKEN path must return confidence 0 (a documented
  fix; keep this invariant).
- A provider `SUCCESS` is provisional until `claim_validator.ClaimValidator`
  fetches the host (https, then http, bounded retries) and finds
  `TAKEOVER_CLAIM_MARKER`. Validated claims transition to `CLAIMED` with
  confidence ≥90 and persist `takeover_evidence` including validation details;
  an unvalidated success is recorded as `validation_failed` and retried.
- Outcomes are stored as `takeover_last_status` + `takeover_retry_at`: validated
  success and NOT_VULN/TAKEN are terminal, transient failures retry after
  `TAKEOVER_RETRY_HOURS`, ownership-blocked/NOT_IMPL cases after
  `TAKEOVER_RETRY_DAYS`. Attempts are single-flight per `(subdomain, provider)`
  and gated by `TAKEOVER_AUTO_ENABLED`, DANGLING confidence, credentials and a
  parent-domain guard. The PoC page is `CLAIM_HTML`; claimed resources are not
  cleaned up automatically except `clear-all-ip` for cloud IPs.

### 4.6 DNS/NS takeover and dangling infrastructure

Core: `app/probing/dns_scanner/` (`ns_checker.py` ~1.8k lines, `sweeper.py`
~1.2k, `ip_indicators.py` ~1.25k).

#### 4.6.1 NS delegation checks

- Parent-zone NS query with recursion disabled, no CNAME chasing.
- Detection modes:
  1. **AWS Route 53 NS-set mismatch** — custom path; a claimed zone still
     returns NOERROR, so the signal is that the recursive NS set differs from
     what Route 53 authoritatively serves.
  2. **Standard rcode** — `SERVFAIL` / `REFUSED` / `NXDOMAIN` for other
     providers in `files/dns_takeover_providers.yaml`.
  3. **Unresolvable NS hostnames** — dead nameservers.
- **Cross-confirmation:** findings from the random resolver pool are re-queried
  against a trusted pool (16 well-known resolvers, serialised to ≤10 q/s); at
  least `NS_CONFIRMATION_MIN_AGREE` (2) must agree before alerting.
- **Wildcard CNAME** (`*.domain → claimable provider`) and **CNAME hop domain
  available** are separate finding types with their own Discord copy.

#### 4.6.2 Per-subdomain sweep

For each subdomain in a batch: A + AAAA resolution, CNAME chain following
(max 5 hops, terminal IPv4/IPv6), NS check, dangling-IP analysis for direct A,
CNAME terminal IPs, MX targets, NXDOMAIN CNAME targets (authoritative probe),
and CNAME intermediate-hop availability. Results are persisted in bulk with
timing instrumentation and callbacks into the daemon.

#### 4.6.3 Dangling cloud IP analysis

`DanglingIPAnalyzer` + per-provider heuristics from
`files/vulnerable_ip_providers.yaml` (17 providers). Signals:

- PTR records vs provider allocation/release patterns (including universal
  cloud PTR shapes and "no PTR" policy per provider);
- HTTP response headers vs provider indicators;
- TLS certificate CN/SANs belonging to a different company → **foreign cert**
  (IP already taken by someone else; DNS should be fixed);
- ASN lookup via Team Cymru DNS TXT, mapped to provider;
- CIDR index membership (AWS/Azure/GCP/DigitalOcean/Oracle/BGP sources);
- direct claim probes for AWS/Azure specific IPs;
- port scan liveness.

`score_finding()` aggregates to 0–100; **`confirmed_free` at ≥60**. Finding
types: `dangling`, `cname_dangling` (−15 confidence for the extra hop),
`foreign_cert`. Alertability requires `confirmed_free` or `foreign_tls_cert` or
`cloud_claim_confirmed`.

#### 4.6.4 SPF / DMARC

Per scope root: resolve SPF `include:` targets and `_dmarc` NS delegation;
detect `spf_include_nxdomain`, `spf_include_takeover`, `dmarc_ns_takeover`;
alert with a distinct embed. Can be disabled with `DANGLING_SPF_DMARC_CHECK`.

#### 4.6.5 Dangling IP → claim path

The IP hunter (§4.7) uses the per-IP verdicts to decide which cloud regions and
CIDR blocks to allocate in. Dangling findings themselves are alerts (with
suggested claim commands) rather than automatic claims.

#### 4.6.6 Automatic NS takeover ("NS lottery")

Cloud DNS providers assign nameservers randomly; the scanner tries to win a
matching delegation:

- **Route 53:** create hosted zone → compare its four NS against the stale
  delegation → delete on mismatch; on match add TXT PoC, keep zone, alert.
  One attempt per subdomain lifetime (`aws_route53_attempted_at`), max 1 global
  worker, `ROUTE53_MAX_ATTEMPTS`, `ROUTE53_SLEEP_BETWEEN`.
- **Azure DNS** and **GCP Cloud DNS:** same lottery pattern with their own
  queues/stamps and PoC records.
- Scope-root (parent) domains must **never** be taken over, only alerted.
  ⚠️ The parent path in `daemon._handle_dns_takeover_finding` calls
  `Route53TakeoverQueue.enqueue(..., is_parent=False)` although the comment says
  `is_parent=True` — verify and fix (§8 P1-2).
- Enqueues also happen from `sweeper.py` for eligible subdomains; the daemon
  suppresses the discovery alert when auto-confirmation logic exists.

### 4.7 IP hunter (optional, `IP_HUNTER_ENABLED` / `IP_HUNTER_MODE`)

Purpose: claim released cloud IPs that a scoped subdomain still resolves to.
Mode is `off` or `takeover`; `IP_HUNTER_MODE` is not a `Settings` field, so
only the default (`off`) applies unless the code is changed. The config
comments also reference an `INFORM` mode that this hunter does not implement.

- **CIDR index** (`cidr_index.py`): AWS `ip-ranges.json`, Azure service tags,
  GCP `cloud.json`, DigitalOcean and Oracle via RIPE/Geoff, generic BGP ASNs;
  cached under `files/cidr_cache`, refreshed every 24 h; maps IP → provider +
  region + service.
- **Providers** (`ip_hunter/providers/`): AWS EIP (allocate/compare/release,
  `AWS_EIP_DUP_HOLD` pool diversification), Azure public IP (`sto-hunt-*`),
  GCP static IP, DigitalOcean reserved IP; each has its own loop and kill switch.
- **Verifier loop** re-checks claimed IPs and clears stale ones (DNS
  re-resolution, rewrite `ip_addresses`, clear verdicts).
- **Cleanup** (`cleaner.py`): `clear-all-ip` CLI releases unassociated EIPs,
  `sto-hunt-*` Azure/GCP resources, unassigned DO reserved IPs. AWS cannot tag
  EIPs at allocation, so the cleaner may touch **all** unassociated EIPs in
  configured regions — document this risk loudly.
- Notifications: `notify_ip_hit`, `notify_ip_hit_stale`.

### 4.8 Exposure scanner (optional, `EXPOSURE_SCAN_ENABLED`)

- Wordlist: `files/exposure_paths.yaml` — 137 paths, fields `path`, `severity`,
  `description`, `signatures` (required substrings), `tags`, `prio` (1–10).
  79 critical, 56 high, 2 medium; most-tagged: credentials (70), env (31),
  cloud (20), database (15), backup (14).
- Selection: each cycle picks `EXPOSURE_BATCH_SIZE` random subdomains across all
  scopes; for each, the highest-priority unchecked path is probed; progress is
  tracked per subdomain (`exposure_checked*`).
- False-positive layers: (1) SPA/catch-all canary paths, (2) expected
  content-type family, (3) HTML body rejection, (4) signature verification,
  (5) minimum body length.
- Findings persist to `exposure_findings`; raw bodies are saved to
  `EXPOSURE_FINDINGS_PATH/<category>/<subdomain_with_underscores>` for
  git/env/cert/db/bak categories (dots become underscores, e.g.
  `api_example_com`).
  ⚠️ `_TAG_TO_SUBDIR` maps `git, env, keys, database, backup`; the wordlist uses
  `credentials` (70 entries) instead of `keys`, so most credential files are
  alerted but never saved.
- Notifications use `EXPOSURE_RENOTIFY_DAYS` (30) dedup and
  `EXPOSURE_SCAN_TIMEOUT` / `EXPOSURE_SCAN_CONCURRENCY`.

### 4.9 Secret scanning

- **JS secrets** (`discovery/js_secrets.py`): 22 detector rules covering AWS
  keys, Google/Azure/GitHub/Slack/Stripe/Twilio credentials, DB/REDIS URIs, JWTs
  and generic high-entropy assignments; placeholder filtering; match-length
  threshold; optional TruffleHog subprocess. Findings are redacted and sent to
  Discord grouped per file. No DB table exists (docstring is wrong).
- **Git secrets** (`discovery/git_scanner.py`): expands orgs via GitHub/GitLab
  API, clones one at a time, runs TruffleHog with archive unpacking, skips
  unchanged HEAD SHAs, deletes clones, persists `findings_count` and alerts to
  `DISCORD_WEBHOOK_URL_TEST` when set. Token: `GITHUB_TOKEN` / `GITLAB_TOKEN`.
  No findings table; results are not queryable later.

### 4.10 Domain availability / buy scanner

`app/probing/domain_buy_scanner.py` — two-phase design:

1. On first discovery of a scope domain: one WHOIS lookup
   (`python-whois`), store expiry/registrar in `domain_availability`.
2. Each iteration: for expired rows, a DNS-based availability check; if free →
   Discord (`notify_domain_buyable`); if still resolving → re-WHOIS to refresh
   expiry. Retries/backoff per TLD; `DOMAIN_BUY_RENOTIFY_HOURS` (48 h) dedup.

### 4.11 Certstream (continuous)

`wss://certstream.calidog.io` (configurable) → SAN extraction → scope match
(refresh every `CERTSTREAM_SCOPE_REFRESH_SECS`) → upsert subdomain → expedited
probe callback (`_certstream_probe_callback`). Intended to act within the
minutes-long window after certificate issuance: CNAME race, shadow DNS/dangling
IP, SaaS verification race. `CERTSTREAM_TAKEOVER_CHECK_ENABLED` is read via
`getattr` but is **not** a `Settings` field. No proxy for the WebSocket by
design.

### 4.12 Notifications

`app/notify/discord.py` — one notifier, many event shapes. All are opt-in via
`DISCORD_WEBHOOK_URL` (git scanner prefers `DISCORD_WEBHOOK_URL_TEST`).

| Event | Method | Content highlights |
| --- | --- | --- |
| Subdomain takeover (batch) | `notify()` | Provider, confidence, evidence, status badge, claim URL, program/platform |
| DNS/NS takeover | `notify_dns_takeover()` | Purple embed; subdomain, scope, nameserver, provider, rcode, "how to claim" |
| Dangling IP | `notify_dangling_ip()` | IP, provider/region, finding type, confidence, claim command |
| SPF/DMARC | `notify_spf_dmarc()` | Vector, records, impact |
| Exposure finding | `notify_exposure()` | Path, severity, URL, snippet |
| Cloud IP hit | `notify_ip_hit()` / `notify_ip_hit_stale()` | Provider, region, IP, affected subdomain |
| Domain buyable | `notify_domain_buyable()` | Domain, expiry, availability, renotify window |
| NS lottery result | `notify_ns_takeover_result()` / `send_raw()` | Success/failure, matched NS, claim URL |
| JS secrets | `notify_js_secrets()` | Grouped per file, redacted |
| Git secrets | inline in `git_scanner.py` | Repo, detector, verified flag |

Dedup and throttling:

- `notifications` table records `(subdomain, channel, confidence, payload)`; a
  new notification is skipped if one with `confidence >= current` exists.
- DNS/dangling findings reuse `Scope.dns_takeover_notified_at` with
  `DNS_TAKEOVER_RENOTIFY_HOURS` (24 h) and per-scope asyncio locks to avoid
  cross-handler races.
- Discord limits enforced: 2 s between messages, 6000 embed chars, truncated
  fields, `retry_after` capped at 30 s.

### 4.13 Web UI and API

`python main.py web` serves FastAPI (`/api/*`, `/docs`) and a Jinja router
mounted at `/web/*`. Bootstrap is loaded from a CDN; no authentication.

| Page | Route | Contents |
| --- | --- | --- |
| Dashboard | `/web/` and `/web/dashboard` | Counts, recent findings, program list, daemon Start/Stop/Restart controls |
| Findings | `/web/findings` | Confidence/time filters, pagination, links to subdomain detail |
| Programs | `/web/programs` | Program list + stats |
| Subdomains | `/web/subdomains` | Filters: state, confidence range, program, scope, order, page size |
| Program detail | `/web/program/{id}` | Scopes + subdomains + findings |
| Subdomain detail | `/web/subdomain/{id}` | Evidence, transitions, discovery sources, exposure findings |
| API | `/api/programs`, `/api/scopes`, `/api/subdomains`, `/api/findings`, `/api/latest-findings`, `/api/stats`, `/api/program/{id}`, `/api/subdomain/{id}`, `/api/js-secrets`, `/api/git-secrets`, `/api/daemon/{status,start,stop,restart}` | JSON |

The daemon controls are real: `app/core/process_control.py` owns
`/tmp/stoscanner-daemon.pid`, and both the UI and
`python main.py start|stop|daemon-status` drive the same process.
`DAEMON_AUTOSTART` (default false) controls whether web startup starts it. The
UI is still unauthenticated; keep it bound to loopback or behind an
authenticating proxy.

### 4.14 Data model (PostgreSQL)

| Table | Purpose | Key columns |
| --- | --- | --- |
| `programs` | Bounty programs | `platform`, `external_id`, `last_scan_at`, `is_active`; unique `(platform, external_id)` |
| `scopes` | In-scope domains | `domain`, `is_active`, `manually_deactivated`, `last_scanned_at`, `last_js_scraped_at`, `dns_takeover_notified_at` |
| `subdomains` | Discovered hosts | `state`, `confidence`, `cname_target`, `ip_addresses`, `ipv6_addresses`, `ip_free`, `ip_verdicts`, `takeover_provider`, `takeover_evidence`, `aws/azure/gcp_dns_attempted_at`, `last_ns_sweep_at`; unique `(scope_id, name)` |
| `discovery_sources` | Provenance per subdomain | `source` enum |
| `notifications` | Dedup log | `channel`, `confidence`, `payload` |
| `state_transitions` | Audit trail | `from_state`, `to_state`, `reason` |
| `domain_availability` | WHOIS/expiry state | `expires_at`, `registrar`, `whois_retry_count`, `whois_give_up`, `last_notified_at` |
| `exposure_findings` | Exposed files | `path`, `severity`, `url`, `tags`, `snippet`, `last_notified_at` |
| `git_scopes` / `git_projects` | Git orgs/repos | `is_wildcard`, `last_expanded_at`, `last_commit_sha`, `findings_count` |
| `ip_hunt_attempts` | Raw-SQL table, no ORM model | provider, region, cidr, ip, hit, attempts, score |

State enums: `SubdomainState` (`discovered`, `alive`, `dead`, `dangling`,
`claimed`, `false_positive`, `potential`, `potential_long`), `ProgramPlatform`,
`DiscoverySource`, `NotificationChannel`, `DomainAvailabilityState`.

Schema changes are applied by `run_enum_migrations()` /
`create_tables()` at daemon startup (`app/db/session.py`) — Alembic is in
`requirements.txt` but unused.

---

## 5. Confidence, state and scheduling invariants

These rules are load-bearing and are documented inside the code
(`evaluator.py`, `potential.py`, `providers_evaluator.py`, `ip_indicators.py`).
Preserve them when refactoring:

1. Only provider verification may lift a finding to DANGLING (≥60). A live 2xx
   subdomain is POTENTIAL, capped at 59.
2. Any path that proves a resource is NOT vulnerable must return confidence 0
   (otherwise the evaluator overwrites the 0 and false alerts fire).
3. NXDOMAIN without a CNAME is never a takeover.
4. An unmatched CNAME provider is never a takeover (no claimability evidence).
5. Probe timeouts must not downgrade POTENTIAL/DANGLING.
6. NOT_IMPL findings stay in 60–72: alert-worthy but visibly lower-confidence.
7. POTENTIAL_LONG transitions are explicit and only for the four ownership-blocked
   cases; `update_confidence` must not silently overwrite them.
8. Parent/scope-root domains are never auto-claimed.
9. DNS confirmations need `NS_CONFIRMATION_MIN_AGREE` independent resolvers.
10. Provider checks, confirmations and HTTP probes must obey their token buckets.

---

## 6. Configuration, data files and environment audit

### 6.1 Settings (`app/core/config.py`)

- 243 declared fields, all referenced via `settings` or documented `getattr`;
  no undeclared runtime knobs remain (the earlier ~29 were promoted and are
  regression-tested).
- `.env.example` documents every field, with secrets commented out; a test
  asserts coverage.
- Platform sync (`PLATFORM_SYNC_*`, four `*_SYNC_INTERVAL_DAYS`), daemon control
  (`DAEMON_AUTOSTART`), and takeover policy (`TAKEOVER_AUTO_ENABLED`,
  `TAKEOVER_RETRY_HOURS`, `TAKEOVER_RETRY_DAYS`, validation timeout/attempts/
  marker) are settings rather than constants.
- Validators cover DNS resolvers, wordlist paths and empty
  `DAEMON_MAX_ITERATIONS`; Compose takes all credentials from `.env` and refuses
  to start without them.

### 6.2 Data files

| File | Size | Schema | Freshness risk |
| --- | --- | --- | --- |
| `files/signatures.yaml` | 177 providers | `provider`, `severity`, `claimable`, `cname_patterns`, `http_patterns`, `header_patterns`, `nxdomain_required` | Weights and provider text pages drift; sourced from can-i-take-over-xyz; no version/date field |
| `files/dns_takeover_providers.yaml` | 23 providers | `name`, `pattern`, `notes`, `fp_risk`, `custom_detection` | Based on can-i-take-over-dns; several entries say "Needs Testing"/"Edge case"; no verification date |
| `files/exposure_paths.yaml` | 137 paths | `path`, `severity`, `description`, `signatures`, `tags`, `prio` | New framework paths missing; tags inconsistent with save categories |
| `files/vulnerable_ip_providers.yaml` | 17 providers | per-provider PTR/header/CIDR heuristics | Cloud PTR policies change; no provenance |
| `files/subdomains_2k.txt` | 2,431 labels | one label per line | Small wordlist; no refresh |
| `files/programs_add_example.json` | example | program import format | Fine |
| `manual_platforms/federacy.json` | manual imports | program JSON | Static, no loader |
| `config/` | empty | — | Placeholder |

None of these files is validated at startup beyond per-entry try/except; a
typo silently drops a provider (logged at warning/debug).

### 6.3 Environment / Docker

- `.env` and `.env.example` are absent; `docker-compose.yml` hard-codes
  development PostgreSQL and Redis credentials (values redacted) and mounts
  `./init.sql`, which does not exist.
  Volumes are declared `external: true` and must be created manually.
- `Dockerfile` builds the app with all recon binaries; Compose runs app +
  Postgres + Redis. `init.sql` is mounted read-only and required secrets come
  from `.env`.
- Redis is provisioned but unused (in-process token buckets); keep it or drop it
  deliberately.
- `.dockerignore` still mentions `app/nuclei/templates` and excludes
  `install-tools.sh`.

### 6.4 Toolchain drift

- External binaries: `subfinder`, `httpx`, `puredns`, `massdns`, `alterx`,
  `gau`, `waybackurls`, `katana`, `trufflehog`, `nuclei` (nuclei unused),
  `whois` binary (domain buy fallback).
- `requirements.txt` pins only lower bounds; no lockfile. `boto3` is imported
  lazily but missing; `aioboto3`, `tls-client`, Google/Azure SDKs are present.
- No `pyproject.toml`, lint/type config, tests, CI, or pre-commit hooks.
- Python 3.12 features are used (`X | None` annotations).

---

## 7. Security and operational risks

| Risk | Why it matters | Mitigation direction |
| --- | --- | --- |
| Auto-takeover is on by default when credentials are present | Claiming resources can violate program rules or law if scopes are wrong | Explicit allowlist per program, dry-run default, signed authorization note, per-provider kill switches (see Phase 5) |
| Scope data can be wrong (platform sync, wildcard expansion) | Scanning out-of-scope hosts is the top real-world risk | Validate scopes against program policy text, operator confirmation, blocklists |
| Hard-coded dev credentials in Compose | Copy-paste into production | `.env`-driven Compose, `.env.example`, README warning |
| No UI authentication | Findings and controls exposed if bound publicly — `HOST` defaults to `127.0.0.1`, which mitigates | Keep loopback default; add auth before any remote exposure |
| Claimed resources never cleaned up | Reputation/legal exposure, cloud cost | Cleanup command per provider, TTL metadata, runbook |
| Evidence may contain secrets (JS secrets, exposure bodies) | Discord and disk are sensitive | Retention policy, redaction (partly present), access control |
| Single process, no supervision | A crash silently stops scanning | systemd/Docker restart policy, healthcheck endpoint |
| Raw scan output under `/findings` and `/tmp/gitscan` | Disk exhaustion | Quotas, retention job |

---

## 8. Gap analysis (evidence-based)

### P0 — must fix before anything else (**fixed in the first round**)

**P0-1. Four missing modules break the import graph.** ✅ restored; see §1.4.
`app/discovery/state.py`, `app/discovery/resolvers.py`,
`app/probing/confidence.py` and `app/probing/ip_verdicts.py` do not exist in
the tree or in git history, yet they are imported by 13 files:

| Module | Imported by | Required surface (from call sites) |
| --- | --- | --- |
| `discovery/state.py` | `daemon.py`, `evaluator.py`, `potential.py`, `providers_evaluator.py` | `StateManager.update_confidence(session, subdomain, confidence, takeover_provider=None, takeover_evidence=None)`, `StateManager.transition(session, subdomain, state, reason=None)`, constants `DANGLING_THRESHOLD=60`, `POTENTIAL_LONG_THRESHOLD=30`; writes `StateTransition`, updates `last_state_change_at` |
| `discovery/resolvers.py` | `daemon.py`, `active.py`, `permutation.py`, `dns.py`, `dns_scanner/resolvers.py`, `ns_checker.py` | `get_resolver_list()`, `get_resolvers_file()`, `ensure_resolver_pool()`; refresh from `DNS_RESOLVER_URLS`/`DNS_RESOLVER_FILES` into `DNS_RESOLVER_CACHE`, health-sample with `DNS_HEALTH_*` |
| `probing/confidence.py` | `evaluator.py`, `ns_checker.py` | `ConfidenceScorer.score_dns(cname, nxdomain, subdomain_name) -> (score, provider)`, `.score_http(status_code, body, headers) -> (score, provider)`, `.compute_overall(dns_score, http_score, nxdomain, subdomain_name) -> int`, `._sig() -> SignatureData` |
| `probing/ip_verdicts.py` | `ip_check.py`, `ns_checker.py`, `sweeper.py`, `models.py`, `hunter.py` | `IPVerdict` (ip, status, source, checked_at, reason…), `IPVerdictStatus` (`FREE`, `TAKEN`, `INCONCLUSIVE`, …), `verdict_from_finding(finding)`, `serialize_ip_verdicts(iterable) -> str`, `aggregate_subdomain_ip_free(iterable) -> Optional[bool]` |

First action: search stashes, other branches, backups and the author's machines.
If unrecoverable, reimplement from this contract, add unit tests for the state
ladder and the confidence math, and keep the documented thresholds.

**P0-2. No runnable environment.** ✅ `.env.example`, Compose, `init.sql`, dependency fixes shipped. Add `.env.example` covering every setting,
fix `docker-compose.yml` (credentials via env, create volumes, provide or remove
`init.sql`), document setup, and add `boto3` to `requirements.txt`.

### P1 — correctness and safety (mostly fixed; see §1.4)

- **JS secrets are not persisted** despite the docstring; add a table or correct
  the docs (and make findings queryable in the UI).
- **Git findings are not persisted** beyond `findings_count`; add a findings
  table if the UI/report should expose them.
- **Route 53 parent enqueue mismatch** (`is_parent=False`): confirm intent and
  fix, with a regression test that parent domains never enter the lottery.
- **Exposure tag mapping** (`credentials` vs `keys`) causes most credential
  hits to be unsaved.
- **`CLAIMED` state** is defined but never set; either wire it to SUCCESS or
  remove it.
- **`DANGLING_IP_CONCURRENCY`, `DNS_TAKEOVER_SWEEP_CONCURRENCY`, etc.** are
  invisible knobs; consolidate into `Settings` (P0-3).
- **No way to pause auto-takeover** short of removing credentials; add a global
  kill switch and dry-run mode.

### P2 — robustness and freshness

- Provider signature/NS/IP data has no refresh path, provenance or CI
  validation; add a "data version" and periodic review checklist, validate YAML
  on load, and fail closed with a visible warning.
- Platform adapters rely on cookies and HTML; add contract tests with saved
  fixtures, timeouts/backoff, and clear failure reporting.
- No metrics or health endpoint; a stuck loop is invisible.
- Hand-rolled migrations are hard to review; adopt Alembic (already a
  dependency) and freeze the ad-hoc SQL.

### P3 — UI and docs

- Findings/secret UI is read-only; no triage workflow or report export.
- Claimed resources have no automated cleanup command.
- Docker docs now live in `README.md`; `.dockerignore` still mentions Nuclei.
- `AGENTS.md` claims "no test suite" — still true, and this plan should change it.

---

## 9. Plan for the AI

Work strictly in order. Each phase ends with a green check, a commit using the
`commit` skill, and an update to this file. Never skip Phase 0.

### Phase 0 — Make the repository runnable (P0)

**Objective:** imports succeed, a local DB can be created, and the daemon starts
for one iteration.

Tasks:

1. Search history/backups for the four missing modules (P0-1). If absent,
   implement them against the contracts in §8, preserving thresholds and the
   state ladder.
2. Add `.env.example` with every `Settings` field, grouped and commented
   (DB, rate limits, discovery, takeover, notifications, optional providers).
3. Fix `docker-compose.yml`: env-driven credentials, remove or add `init.sql`,
   create named volumes (not external), keep healthchecks.
4. Add `boto3` to `requirements.txt`; remove or clearly mark unused Nuclei
   settings; note `tls-client`/`aioboto3`/cloud SDKs as optional extras.
5. Add a minimal `Makefile` or documented commands for `venv`, install, DB up,
   import smoke, and `DAEMON_MAX_ITERATIONS=1 python main.py daemon`.
6. Document the restore in `AGENTS.md` and `vault/` (brief note).

**Done when:**

```bash
python -m compileall -q app main.py
python -c "import app.core.daemon, app.discovery.active, app.probing.dns_scanner.ns_checker, app.takeover.subdomain_hunter.evaluator, app.takeover.ip_hunter.hunter"
python main.py --help
```

all pass with dependencies installed, and `docker compose up -d` yields a
reachable Postgres.

**Risk:** reimplementing `state.py`/`confidence.py` incorrectly silently changes
every finding's severity. Add unit tests first (Phase 1 overlaps here for these
four modules).

### Phase 1 — Safety net: tests, lint, CI

**Objective:** every pure rule is testable without network/DB.

Tasks:

1. Add `pytest`, `pytest-asyncio`, `ruff` (and optionally `mypy`) with a
   `pyproject.toml`.
2. Tests for: `domain_utils`, `git_scope_utils`, `takeover_loader` (YAML →
   compiled signatures), `ConfidenceScorer` math, `StateManager` ladder (POTENTIAL
   cap 59, DANGLING ≥60, POTENTIAL_LONG preservation, NOT_VULN → 0),
   `ip_verdicts` aggregation, exposure false-positive layers (with canned HTTP
   responses), CNAME chain parsing, `Scheduler` query logic (SQLite or a mocked
   session where feasible).
3. Fixture-based tests for platform parsers using saved JSON/HTML (no network).
4. GitHub Actions: lint + tests on push/PR.
5. Add a "golden" test that imports every module (`test_imports.py`) to catch
   future missing-module regressions.

**Done when:** `pytest -q` passes, CI is green, and coverage of utility/takeover
logic exists (target ≥60% on non-I/O modules).

### Phase 2 — Configuration truth and schema management

**Objective:** what `.env` says is what runs; schema changes are reviewable.

Tasks:

1. Move every `getattr(settings, "...", default)` knob into `Settings` with an
   `env=` alias and documentation; remove silent defaults where a setting is
   required. Keep backwards-compatible defaults.
2. Add startup validation: required credentials per enabled feature, wordlist
   paths, YAML files exist and parse, thresholds sane. Fail fast with actionable
   messages (not "daemon silently does nothing").
3. Introduce Alembic: baseline the current schema, move `run_enum_migrations()`
   SQL into revisions, keep `create_all()` only for tests.
4. Add a `/api/health` (DB + resolver pool + queue depth) and structured
   startup summary (enabled features, tool availability, versions).
5. Remove or implement dead settings (`REDIS_URL`, `NUCLEI_*`, `ROUTE53_*` if
   unused, `DNS_HEALTH_*` if the resolver pool does not use them).

**Done when:** a settings inventory test asserts every knob is declared, `.env`
changes take effect, and a fresh DB migrates from zero.

### Phase 3 — Platform ingestion hardening

**Objective:** trustworthy scope data, refreshed on a schedule.

Tasks:

1. Add `sync-platforms` command (or daemon loop) that runs all configured
   adapters daily with per-platform backoff and a summary report.
2. Add error reporting: per-platform auth failure, schema change, empty result;
   surface in `/api/health` and Discord ops channel.
3. Harden adapters: request timeouts, retry with jitter, pagination limits,
   HTML-parser tests for Bugcrowd/HackenProof/BugBountyDirectory, cookie
   expiry detection, and validation of fetched scopes through `domain_utils`.
4. Implement Federacy (or document that it is manual-only) and remove the enum/
   adapter mismatch.
5. Add scope change audit: log added/removed scopes per sync; never silently
   drop deactivated scopes.
6. Add an out-of-scope blocklist and a "require confirmation for wildcards"
   option.

**Done when:** a full sync from fixtures produces deterministic DB rows; failure
modes are visible; no adapter can crash the daemon.

### Phase 4 — Discovery and probing quality

**Objective:** fewer false positives, predictable load, observable progress.

Tasks:

1. Audit upserts: keep the `uq_subdomain_source` constraint and replace
   select-then-insert races in active discovery with `ON CONFLICT DO NOTHING`
   (or catch `IntegrityError`).
2. Verify resolver pool behaviour (refresh, health, fallback) and expose stats.
3. Make rate limiting observable: `/api/stats` or logs for per-domain/CDN
   buckets, skip decisions.
4. Add body-size limits and truncation metadata to HTTP probing; ensure
   `tls_client` profile rotation is testable and documented.
5. Confirm first-scan gating for active/wayback/permutation and make it explicit
   in settings.
6. Add per-scope timing metrics (the NS sweeper already logs them) and a simple
   scan report endpoint.

**Done when:** a single-scope smoke run produces subdomains with provenance and
no duplicate source rows; load is bounded by configured limits.

### Phase 5 — Takeover correctness and automation guardrails

**Objective:** every claim is justified, reversible and rules-compliant.

Tasks:

1. Fix the Route 53 parent-domain bug and add the regression test.
2. Persist secret findings (JS and git) or explicitly document Discord-only
   behaviour; add `js_secret_findings` / `git_secret_findings` tables if the UI
   should show them.
3. Fix the exposure tag mapping (`credentials` → `cert` or a dedicated folder)
   and add a loader test that every tag has a mapping.
4. Add takeover policy: global `TAKEOVER_DRY_RUN` (default true), per-provider
   enable flags that default off, scope allowlist, and a machine-readable
   authorization record (program URL + policy snapshot date).
5. Add claim cleanup: `release-claims` command per provider, TTL metadata, and
   a runbook for disputes.
6. Make provider results idempotent: one attempt per subdomain/provider/lifetime,
   clear state on operator reset, audit every claim in `state_transitions` or a
   dedicated table.
7. Re-verify the confidence ladder with fixtures: POTENTIAL never alerts,
   NOT_IMPL stays 60–72, NOT_VULN returns 0.

**Done when:** dry-run mode performs zero claims; every real claim is gated by
policy; the Route 53 parent case is tested.

### Phase 6 — Notifications and report-ready output

**Objective:** an alert is enough to write a report without leaving Discord.

Tasks:

1. Standardise the finding payload: program, platform, scope, asset, provider,
   finding type, confidence, evidence (DNS/HTTP/TLS), reproduction steps,
   claim status, first/last seen, dedup key.
2. Add a Markdown/JSON report generator (`report <subdomain|program>`) and an
   API endpoint; include evidence and a suggested writeup skeleton.
3. Fix dedup semantics: notify when a finding materially changes (state,
   confidence bucket, provider) and respect per-type cooldowns; never notify
   POTENTIAL.
4. Add delivery reliability: queue with retry/backoff, persist pending
   notifications, handle webhook failure without losing the finding.
5. Separate channels: findings, ops, secrets (avoid mixing high-volume secret
   alerts with takeover alerts).

**Done when:** each alert variant has a documented payload; a report can be
generated from the DB alone; notification duplicates are tested.

### Phase 7 — UI and API

**Objective:** operate and triage without reading logs.

Tasks:

1. Daemon control is real (shared PID file). Add authentication before exposing
   the UI beyond loopback; keep systemd/Docker supervision for production.
2. Findings triage: status changes (acknowledged/false positive/claimed),
   assignment, notes, and a report view.
3. Add secret and exposure views; add evidence viewer for `takeover_evidence`
   JSON and saved exposure bodies.
4. Add filters/export (CSV/JSON/Markdown) and pagination consistency.
5. Add minimal auth (basic auth or reverse-proxy header trust) and CSRF
   protection for any write endpoint; keep loopback default.
6. Add accessibility/regression tests for templates (snapshot or smoke render).

**Done when:** an operator can pause the daemon, triage a finding and export a
report from the UI; no stub remains.

### Phase 8 — Operations and documentation

**Objective:** a system someone can run for months.

Tasks:

1. Containerisation is done (Dockerfile + Compose app service, non-root user,
   pinned tool versions, healthcheck). Extend the image with supply-chain
   scanning and reproducible-digest pinning.
2. Add observability: structured logs with correlation IDs, Prometheus metrics
   (scan duration, queue depth, findings by type, provider error rate), and
   alerts.
3. Add backup/retention: Postgres dumps, `/findings` retention, git clone temp
   cleanup, notification pruning.
4. Update `README.md`, `AGENTS.md`, `vault/` and this plan; record decisions in
   `vault/decisions/`.
5. Add runbooks: rotate platform cookies/tokens, refresh signature data, release
   claims, respond to a disputed finding.

**Done when:** `docker compose up` runs app + DB + Redis; dashboards/alerts
exist; docs match reality.

### Sequencing notes

- Phase 0 and the four missing-module tests in Phase 1 are the only true
  blockers.
- Phases 3–4 can proceed in parallel with 5 once Phase 2 lands.
- Do not start Phase 7 before Phase 5's policy work: exposing claim controls in
  a UI without guardrails is a liability.
- Effort: P0 ≈ 1–3 days; Phases 1–2 ≈ 1 week; 3–6 ≈ 2–4 weeks; 7–8 ≈ 1–2 weeks,
  depending on how much of the missing logic must be reimplemented.

---

## 10. Invariants and conventions for the AI

From `AGENTS.md` (authoritative for style) plus load-bearing rules from §5:

- **Async first.** Use `async with get_session()`; never share an `AsyncSession`
  across tasks; never touch ORM attributes after an `await` on a different
  session.
- **Feature flags.** Every optional/expensive subsystem stays behind a
  `*_ENABLED` setting and degrades gracefully when its tool/credential is
  missing.
- **Rate limits are mandatory.** Route new outbound calls through
  `app/core/ratelimit.py` or an equivalent per-provider bucket.
- **Never add secrets** to source or docs; `.env`/`gcp.json` stay untracked.
- **Keep the confidence ladder** (§5). Any change to thresholds or NOT_VULN
  handling needs fixtures.
- **No silent failures.** Log at warning+ with the scope/subdomain and the
  fix hint; the codebase has a history of swallowed exceptions.
- **Data files are code.** Validate YAML at load, fail loudly on malformed
  entries, and keep provider data versioned.
- **Comments are documentation, not a changelog.** Record durable intent,
  invariants and trade-offs; no fix/bug labels, ticket IDs, dates or
  "previously/was" narratives (see the `comments` skill).
- **Commits:** use the `commit` skill (`bash .agents/skills/commit/scripts/commit.sh`),
  which screens for secrets and rejects attribution lines.
- **Update the trio:** when behaviour changes, update `AGENTS.md`, `README.md`
  and this plan.

---

## 11. Verification playbook

Once dependencies are installed (Phase 0):

```bash
# 1. Static sanity (no imports needed)
python -m compileall -q app main.py

# 2. Import graph (catches missing modules and broken packaging)
python -c "import main; import app.core.daemon; import app.web.api; \
import app.discovery.active; import app.probing.dns_scanner.ns_checker; \
import app.takeover.subdomain_hunter.evaluator; import app.takeover.ip_hunter.hunter"

# 3. Unit tests + lint
pytest -q
ruff check app tests main.py

# 4. Infrastructure
docker compose up -d
psql "postgresql://$DB_USERNAME:$DB_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME" -c '\dt'

# 5. Full stack (app + DB + Redis + all recon tools)
cp .env.example .env   # set DB_PASSWORD / REDIS_PASSWORD
docker compose up -d --build
curl -sf localhost:8000/web/ >/dev/null && echo "web ok"

# 6. Daemon control (shared by UI and CLI)
python main.py start && python main.py daemon-status
python main.py stop

# 7. One bounded daemon iteration
DAEMON_MAX_ITERATIONS=1 DAEMON_SLEEP_SECONDS=1 python main.py daemon

# 8. CLI smoke
python main.py --help
python main.py status
python main.py sync-platforms --help

# 9. Web smoke (separate process)
python main.py web   # then: curl -s localhost:8000/api/stats
```

A healthy first iteration logs: database tables/migrations applied, resolver
pool ready, platform-sync loop started, NS sweep loop started, certstream
connected (or a clear warning), programs selected, scopes scanned, probes
dispatched, and a clean shutdown.

Already verified: 192 unit tests pass, `ruff` is clean, every module imports,
the Compose file validates with the required env vars, `files/signatures.yaml`
and `files/exposure_paths.yaml` load 177 providers and 137 paths, a temporary
PostgreSQL run created all 13 tables, the Docker image built and the stack
became healthy, every `/web/*` page returned 200, and CLI/web daemon
cross-control worked. Provider APIs, bounty platforms and scan targets were not
contacted.

---

## 12. Decisions needed from the owner

1. **Missing modules:** resolved by reimplementation (see §1.4). Please compare
   the new state ladder/confidence maths with your original expectations before
   relying on production alerts — thresholds are preserved (30/60) but the
   implementation is new.
2. **Auto-takeover policy:** should it default to dry-run? Which providers are
   pre-authorized? Who signs off that a scope is claimable? What is the cleanup
   and disclosure workflow?
3. **Scope authority:** which sources are trusted, and is there a blocklist of
   subsidiaries/third parties that must never be touched?
4. **Platform priority:** which adapters must keep working first (HackerOne,
   YesWeHack, Bugcrowd, Intigriti were named)? Are private/cookie-based
   platforms still needed?
5. **Data retention:** how long to keep raw exposure bodies, JS secrets, git
   clones and notifications? Where may they live?
6. **Reporting target:** Markdown files, a hosted report, or platform-specific
   submission drafts (HackerOne/Bugcrowd formats)?
7. **UI exposure:** loopback only, or authenticated remote access? Single user?
8. **Testing budget:** is a fixture-based test suite acceptable, or do you want
   live integration tests (slower, needs targets/credentials)?
9. **Infrastructure:** keep Redis (unused) or remove it; systemd vs Docker
   deployment.

---

## Appendix A — Module index

| Path | Responsibility |
| --- | --- |
| `main.py` | Entry point: `daemon`, `web`, otherwise Typer CLI |
| `app/core/config.py` | 200 `pydantic-settings` fields |
| `app/core/daemon.py` | Orchestrator: loops, scan pipeline, finding handlers |
| `app/core/scheduler.py` | SQL selection of programs/scopes/subdomains due for work |
| `app/core/ratelimit.py` | Per-domain and per-CDN token buckets |
| `app/core/cli.py` | Programs/scopes admin, platform sync, status, pause/resume |
| `app/core/process_control.py` | PID-file daemon lifecycle shared by web UI and CLI |
| `app/db/db_models.py` | ORM models and enums |
| `app/db/session.py` | Async engine, session factory, ad-hoc migrations |
| `app/discovery/passive.py` | subfinder + crt.sh |
| `app/discovery/active.py` | puredns brute force + shared upsert helper |
| `app/discovery/permutation.py` | alterx + puredns resolve |
| `app/discovery/wayback.py` | gau + waybackurls |
| `app/discovery/js_scrape.py` | JS URL collection, fetch, subdomain extraction |
| `app/discovery/js_secrets.py` | Regex secret detection + Discord |
| `app/discovery/git_scanner.py` | GitHub/GitLab enumeration + TruffleHog |
| `app/discovery/certstream.py` | CT log monitoring |
| `app/probing/dns.py` | Raw UDP DNS probing |
| `app/probing/http.py` | `tls_client` HTTP probing |
| `app/probing/ip_check.py` | TCP liveness verdicts |
| `app/probing/exposure_scanner.py` | Exposed-path scanner |
| `app/probing/domain_buy_scanner.py` | Expiry/availability monitoring |
| `app/probing/dns_scanner/` | NS scan, sweeper, dangling IP analysis, confirmations, resolvers, models |
| `app/takeover/subdomain_hunter/` | Evaluator, potential detector, provider checkers/claims |
| `app/takeover/ns_hunter/` | API Gateway checker, Azure/GCP DNS lotteries |
| `app/takeover/ip_hunter/` | CIDR index, hunters, verifier, cleaner |
| `app/programs/` | Platform adapters, loader, domain/git utilities |
| `app/notify/discord.py` | Discord embeds and delivery |
| `app/web/api.py`, `app/web/web.py`, templates | JSON API + dashboard |

## Appendix B — Glossary

- **Dangling CNAME** — DNS points at a provider resource that no longer exists
  and can be claimed.
- **NS takeover** — the delegated nameservers for a zone belong to a provider
  where the zone is unclaimed (or the delegation is stale).
- **NS lottery** — repeatedly creating zones at a cloud provider hoping to be
  assigned the stale nameservers.
- **Dangling IP** — a scoped hostname resolves to an IP that appears released
  and can be re-allocated.
- **POTENTIAL** — live host structurally at risk; not actionable yet.
- **POTENTIAL_LONG** — ownership-blocked (needs TXT transfer, provider release,
  or is architecturally impossible); slow recheck.
- **Exposure** — sensitive file/path publicly reachable (`.git`, `.env`, dumps).
- **CIDR index** — IP-range → cloud provider/region mapping.

## Appendix C — Quick commands

```bash
# Setup
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
docker compose up -d

# Programs
python main.py programs-add files/programs_add_example.json --dry-run
python main.py programs-add programs.json
python main.py add-program "Acme" --platform hackerone --scopes "acme.com,*.acme.com"
python main.py ingest-platform hackerone
python main.py status

# Run
python main.py daemon
DAEMON_MAX_ITERATIONS=1 python main.py daemon
python main.py web            # http://127.0.0.1:8000/web/dashboard , /docs

# Maintenance
python main.py pause / resume
python main.py clear-all-ip aws azure --dry-run
```
