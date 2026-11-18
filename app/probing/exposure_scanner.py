"""
app/probing/exposure_scanner.py

Exposed sensitive file/path scanner.

SCAN LOOP (separate from main subdomain scan):
  Each daemon iteration calls ExposureScanner.run_exposure_loop() which:
    1. Picks EXPOSURE_BATCH_SIZE (default 100) random subdomains from DB,
       drawn uniformly across ALL scopes so no single area is hammered together.
    2. For each subdomain, finds the highest-priority (lowest `prio`) path from
       the wordlist that has NOT yet been recorded in exposure_checked.
    3. Probes that one path per subdomain, records the result in exposure_checked,
       and persists any finding to exposure_findings.
  This ensures the scan spreads evenly across all subdomains and always works
  through the most impactful paths first.

FALSE POSITIVE PREVENTION (five layers):
  1. SPA/catch-all detection — before scanning, probe two random canary paths.
     If either returns 200, the server serves its SPA for all unknown routes.
     Skip the entire subdomain — nothing here will be a real finding.
  2. Content-type enforcement — each path has an expected content-type family
     inferred from its extension.
  3. HTML body rejection — even if content-type is text/plain, if the body
     starts with <!doctype html or <html, it's a catch-all in disguise.
  4. Signature verification — body must contain at least one expected string.
  5. Minimum body length — completely empty responses are never reported.

FILE SAVING:
  When a finding is confirmed the raw response body is saved to disk under
  EXPOSURE_FINDINGS_PATH/<category>/<subdomain_as_path> where the subdomain
  dots are replaced with path separators so files stay organised.

  Categories (mapped from tags):
    git   → EXPOSURE_FINDINGS_PATH/git/<subdomain>
    env   → EXPOSURE_FINDINGS_PATH/env/<subdomain>
    keys  → EXPOSURE_FINDINGS_PATH/cert/<subdomain>
    database → EXPOSURE_FINDINGS_PATH/db/<subdomain>
    backup   → EXPOSURE_FINDINGS_PATH/bak/<subdomain>

Config:
  EXPOSURE_SCAN_ENABLED          bool  default False
  EXPOSURE_SCAN_TIMEOUT          int   default 5
  EXPOSURE_SCAN_CONCURRENCY      int   default 3
  EXPOSURE_WORDLIST_PATH         str   default "exposure_paths.yaml"
  EXPOSURE_BATCH_SIZE            int   default 100
  EXPOSURE_RENOTIFY_DAYS         int   default 30
  EXPOSURE_FINDINGS_PATH         str   default "/findings"
"""

import asyncio
import hashlib
import os
import random
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set

import requests
import yaml
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import logger
from app.db.db_models import Subdomain, SubdomainState


# ---------------------------------------------------------------------------
# Human-like browser session (using requests, run in executor thread)
# ---------------------------------------------------------------------------

_TLS_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) "
    "Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
]

def _make_headers() -> Dict[str, str]:
    ua = random.choice(_TLS_USER_AGENTS)
    return {
        "User-Agent": ua,
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,*/*;q=0.8"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "DNT": "1",
        "Cache-Control": "no-cache",
    }


def _sync_get(url: str, timeout: int, proxy: Optional[str]) -> Optional[requests.Response]:
    """
    Synchronous GET with human-like headers.  Run via run_in_executor.
    Returns the Response on success, None on any connection/protocol failure.
    """
    proxies = {"https": proxy, "http": proxy} if proxy else None
    try:
        resp = requests.get(
            url,
            headers=_make_headers(),
            timeout=timeout,
            allow_redirects=True,
            verify=False,
            proxies=proxies,
            stream=False,
        )
        return resp
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Content-type families
# ---------------------------------------------------------------------------

class CType:
    TEXT          = "text"
    JSON          = "json"
    BINARY        = "binary"
    ANY           = "any"
    HTML_OK       = "html_ok"
    ACTUATOR_JSON = "actuator_json"
    BINARY_TEXT   = "binary_text"
    JS            = "js"


def _is_html(content_type: str) -> bool:
    ct = content_type.split(";")[0].strip().lower()
    return ct in ("text/html", "application/xhtml+xml")


def _content_type_ok(content_type: str, expected: str) -> bool:
    ct = content_type.split(";")[0].strip().lower()

    if expected == CType.HTML_OK:
        return True
    if expected == CType.ANY:
        return not _is_html(content_type)
    if expected == CType.ACTUATOR_JSON:
        return ct == "application/json" or ct.startswith("application/vnd.spring-boot.actuator")
    if expected == CType.BINARY:
        return ct in (
            "application/octet-stream", "application/zip",
            "application/x-tar", "application/java-archive",
            "application/x-java-keystore",
        ) or ct.startswith("application/")
    if expected == CType.BINARY_TEXT:
        return ct in ("application/octet-stream", "text/plain") or ct.startswith("text/")
    if expected == CType.JSON:
        if _is_html(content_type):
            return False
        return ct == "application/json" or ct.endswith("+json")
    if expected == CType.JS:
        if _is_html(content_type):
            return False
        return ct in ("text/javascript", "application/javascript", "application/x-javascript") or ct.startswith("text/")
    if expected == CType.TEXT:
        if _is_html(content_type):
            return False
        return ct.startswith("text/") or ct in (
            "application/x-yaml", "application/yaml",
            "application/x-sh", "application/x-ruby",
            "application/x-python", "application/toml",
        )
    return True


def _body_looks_like_html(body: str) -> bool:
    s = body.lstrip()[:300].lower()
    return (
        s.startswith("<!doctype html")
        or s.startswith("<html")
        or ("<head>" in s and "<title>" in s)
        or "<meta charset" in s
    )


# ---------------------------------------------------------------------------
# Path definition
# ---------------------------------------------------------------------------

@dataclass
class ExposurePath:
    path:           str
    severity:       str
    description:    str
    signatures:     List[str] = field(default_factory=list)
    tags:           List[str] = field(default_factory=list)
    content_type:   str       = CType.TEXT
    min_body_bytes: int       = 1
    prio:           int       = 5   # 1=highest priority, 10=lowest


@dataclass
class ExposureFindingResult:
    subdomain:   str
    url:         str
    path:        str
    severity:    str
    description: str
    status_code: int
    snippet:     str
    tags:        List[str] = field(default_factory=list)
    body_bytes:  bytes     = field(default_factory=bytes)  # raw body for file saving


# ---------------------------------------------------------------------------
# Content-type inference
# ---------------------------------------------------------------------------

_MIN_BODY_OVERRIDES: dict = {
    "/config/credentials.yml.enc": 32,
    "/config/master.key":           16,
    "/vault_pass.txt":               4,
    "/.vault_pass":                  4,
}


def _infer_content_type(path: str) -> str:
    p = path.lower()

    if any(p.endswith(ext) for ext in (
        ".zip", ".tar", ".tar.gz", ".tgz", ".7z",
        ".tar.bz2", ".p12", ".pfx", ".jks", ".jar",
    )):
        return CType.BINARY

    if p.endswith("/.git/index") or p == "/.git/index":
        return CType.BINARY

    if p.endswith("/heapdump") or p == "/actuator/heapdump":
        return CType.BINARY

    if any(p == e or p.endswith(e) for e in (
        "/phpinfo.php", "/info.php",
        "/console",
        "/telescope", "/telescope/api/requests",
        "/horizon",
        "/_profiler", "/_profiler/phpinfo",
        "/__debug__",
    )):
        return CType.HTML_OK

    if any(p == e for e in (
        "/actuator/env", "/actuator/beans", "/actuator/mappings",
        "/actuator/httptrace", "/actuator/loggers", "/actuator/scheduledtasks",
    )):
        return CType.ACTUATOR_JSON

    if p.endswith(".json"):
        return CType.JSON

    if p.endswith(".js"):
        return CType.JS

    if any(p.endswith(ext) for ext in (
        ".yml", ".yaml", ".properties", ".conf", ".cfg", ".ini",
        ".toml", ".env",
        ".pem", ".key", ".crt", ".cer",
        ".sql", ".log", ".py", ".rb", ".php", ".sh", ".xml",
        ".txt", ".bak", ".old", ".save", ".orig", ".swp", ".enc", ".~",
        ".config",
    )):
        return CType.BINARY_TEXT

    if any(p == e or p.endswith(e) for e in (
        "/.git/head", "/.git/config", "/.git/packed-refs",
        "/.git/logs/head",
        "/id_rsa", "/id_dsa", "/id_ecdsa", "/id_ed25519",
        "/.ssh/id_rsa",
        "/.aws/credentials", "/.aws/config",
        "/credentials", "/kubeconfig", "/.kube/config",
        "/.vault_pass", "/.npmrc", "/.htpasswd",
        "/terraform.tfstate", "/terraform.tfstate.backup",
        "/.terraform/terraform.tfstate", "/terraform.tfvars",
        "/error_log", "/php.ini",
        "/wp-config.php~",
    )):
        return CType.BINARY_TEXT

    filename = p.split("/")[-1]
    if filename.startswith(".env"):
        return CType.BINARY_TEXT

    return CType.TEXT


# ---------------------------------------------------------------------------
# Wordlist loader
# ---------------------------------------------------------------------------

def load_exposure_paths(yaml_path: Optional[str] = None) -> List[ExposurePath]:
    if yaml_path is None:
        yaml_path = getattr(
            settings,
            "EXPOSURE_WORDLIST_PATH",
            str(Path(__file__).parent / "exposure_paths.yaml"),
        )

    p = Path(yaml_path)
    if not p.is_absolute():
        p = Path(__file__).resolve().parents[2] / p
    if not p.exists():
        logger.warning("exposure: wordlist not found at %s", yaml_path)
        return []

    try:
        with open(p) as f:
            raw = yaml.safe_load(f)

        if not isinstance(raw, list):
            logger.error("exposure: wordlist must be a YAML list")
            return []

        paths = []
        for entry in raw:
            if not isinstance(entry, dict) or "path" not in entry:
                continue
            ep_path = entry["path"]
            paths.append(ExposurePath(
                path           = ep_path,
                severity       = entry.get("severity", "high"),
                description    = entry.get("description", ep_path),
                signatures     = entry.get("signatures", []),
                tags           = entry.get("tags", []),
                content_type   = _infer_content_type(ep_path),
                min_body_bytes = _MIN_BODY_OVERRIDES.get(
                    ep_path,
                    entry.get("min_body_bytes", 1),
                ),
                prio           = int(entry.get("prio", 5)),
            ))

        # Pre-sort by prio ascending so iteration order is priority-correct
        paths.sort(key=lambda ep: ep.prio)
        logger.info("exposure: loaded %d paths from %s", len(paths), yaml_path)
        return paths

    except Exception as e:
        logger.error("exposure: failed to load wordlist: %s", e)
        return []


# ---------------------------------------------------------------------------
# File saving helpers
# ---------------------------------------------------------------------------

_TAG_TO_SUBDIR: Dict[str, str] = {
    "git":         "git",
    "env":         "env",
    "keys":        "cert",
    "credentials": "creds",
    "database":    "db",
    "backup":      "bak",
}


def _resolve_save_subdir(tags: List[str]) -> Optional[str]:
    """Map finding tags to a save subdirectory. First match wins."""
    for tag in tags:
        subdir = _TAG_TO_SUBDIR.get(tag)
        if subdir:
            return subdir
    return None


def _subdomain_to_path(subdomain_name: str) -> str:
    """
    Convert a subdomain name to a filesystem-safe path component.
    'api.example.com' → 'api_example_com'
    """
    return re.sub(r"[^a-zA-Z0-9_\-]", "_", subdomain_name)


def _save_finding_to_disk(
    subdomain_name: str,
    path: str,
    tags: List[str],
    body_bytes: bytes,
) -> Optional[str]:
    """
    Save raw body to EXPOSURE_FINDINGS_PATH/<subdir>/<subdomain_as_path>.
    Returns the saved file path, or None if saving was skipped/failed.
    """
    if not body_bytes:
        return None

    subdir = _resolve_save_subdir(tags)
    if not subdir:
        return None

    base_dir = Path(getattr(settings, "EXPOSURE_FINDINGS_PATH", "/findings"))
    save_dir = base_dir / subdir
    try:
        save_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        logger.warning("exposure: cannot create findings dir %s: %s", save_dir, e)
        return None

    # Filename: <subdomain_as_path>__<path_hash_short>
    # The path component is hashed to avoid filename collisions when multiple
    # paths match the same subdomain (e.g. /.env and /.env.local).
    sd_part   = _subdomain_to_path(subdomain_name)
    path_slug = re.sub(r"[^a-zA-Z0-9_\-]", "_", path.strip("/"))[:60]
    filename  = f"{sd_part}__{path_slug}"
    save_path = save_dir / filename

    try:
        with open(save_path, "wb") as fh:
            fh.write(body_bytes)
        logger.info("exposure: saved finding body → %s", save_path)
        return str(save_path)
    except Exception as e:
        logger.warning("exposure: failed to save finding to %s: %s", save_path, e)
        return None


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class ExposureScanner:
    """
    Priority-ordered exposure scanner with per-subdomain progress tracking.

    Main entry point: run_exposure_loop(session)
      - Called once per daemon iteration.
      - Selects EXPOSURE_BATCH_SIZE random alive subdomains.
      - For each: probes the next unchecked highest-priority path.
      - Uses EXPOSURE_SCAN_CONCURRENCY semaphore (default 3).
    """

    def __init__(self) -> None:
        self._timeout     = getattr(settings, "EXPOSURE_SCAN_TIMEOUT",     5)
        self._concurrency = getattr(settings, "EXPOSURE_SCAN_CONCURRENCY", 3)
        self._batch_size  = getattr(settings, "EXPOSURE_BATCH_SIZE",       100)
        self._paths       = load_exposure_paths()
        self._proxy       = getattr(settings, "HTTP_PROXY", None)
        # Build a sorted list of path strings for quick checked-set comparison
        self._path_list: List[ExposurePath] = sorted(self._paths, key=lambda ep: ep.prio)

    def reload_paths(self) -> None:
        self._paths     = load_exposure_paths()
        self._path_list = sorted(self._paths, key=lambda ep: ep.prio)
        logger.info("exposure: reloaded %d paths", len(self._paths))

    # ------------------------------------------------------------------
    # Main loop entry point (called from daemon iteration)
    # ------------------------------------------------------------------

    async def run_exposure_loop(
        self,
        notify_callback=None,
    ) -> None:
        """
        Single exposure loop iteration:
          1. Pick EXPOSURE_BATCH_SIZE random alive subdomains (across all scopes).
          2. For each, find the next unchecked path (by prio).
          3. Probe it concurrently under EXPOSURE_SCAN_CONCURRENCY.
        """
        if not getattr(settings, "EXPOSURE_SCAN_ENABLED", False):
            return

        if not self._path_list:
            logger.warning("exposure: no paths loaded — skipping loop")
            return

        from app.db.session import get_session

        # ── Step 1: Pick random subdomains ────────────────────────────────────
        subdomains = await self._pick_random_subdomains()
        if not subdomains:
            logger.debug("exposure: no eligible subdomains for this iteration")
            return

        logger.info(
            "exposure: loop starting — %d subdomains, concurrency=%d",
            len(subdomains), self._concurrency,
        )

        sem = asyncio.Semaphore(self._concurrency)
        # Rate limit: max 10 requests/sec — one token every 100ms.
        # _throttle() serialises dispatch so no more than 10 coroutines
        # are launched per second regardless of concurrency setting.
        _rate_lock = asyncio.Lock()
        _last_time: list = [0.0]

        async def _throttle():
            async with _rate_lock:
                now  = asyncio.get_event_loop().time()
                wait = 0.1 - (now - _last_time[0])
                if wait > 0:
                    await asyncio.sleep(wait)
                _last_time[0] = asyncio.get_event_loop().time()

        async def _handle_one(sd_id: int, sd_name: str):
            await _throttle()
            async with sem:
                await self._probe_one_subdomain(sd_id, sd_name, notify_callback)

        await asyncio.gather(
            *[_handle_one(sd.id, sd.name) for sd in subdomains],
            return_exceptions=True,
        )

        logger.info("exposure: loop complete for %d subdomains", len(subdomains))

    # ------------------------------------------------------------------
    # Per-subdomain: pick next path and probe it
    # ------------------------------------------------------------------

    async def _probe_one_subdomain(
        self,
        sd_id: int,
        sd_name: str,
        notify_callback=None,
    ) -> None:
        """
        Open a fresh session, read exposure_checked_paths JSON from the subdomain
        row, find the next unchecked highest-priority path, probe it, update the
        JSON column.  One row touched per probe — no join table.
        """
        import json as _json
        from app.db.session import get_session

        async with get_session() as session:
            sd_result = await session.execute(
                select(Subdomain).where(Subdomain.id == sd_id)
            )
            subdomain = sd_result.scalar_one_or_none()
            if subdomain is None:
                return
            if subdomain.state == SubdomainState.DEAD:
                return

            # Deserialise checked-paths set from JSON column
            checked_paths: Set[str] = set()
            if subdomain.exposure_checked_paths:
                try:
                    checked_paths = set(_json.loads(subdomain.exposure_checked_paths))
                except Exception:
                    checked_paths = set()

            # Find next unchecked path (list is pre-sorted by prio)
            next_ep: Optional[ExposurePath] = None
            for ep in self._path_list:
                if ep.path not in checked_paths:
                    next_ep = ep
                    break

            if next_ep is None:
                logger.debug(
                    "exposure: %s — all %d paths already checked",
                    sd_name, len(self._path_list),
                )
                return

            base_url = f"https://{sd_name}"

            # ── SPA catch-all check — only on first ever probe for this subdomain ──
            if not checked_paths:
                if await self._is_catchall(base_url):
                    logger.debug("exposure: %s is catch-all — marking all paths as checked", sd_name)
                    all_paths = [ep.path for ep in self._path_list]
                    subdomain.exposure_checked_paths = _json.dumps(all_paths)
                    await session.commit()
                    return

            # ── Probe ─────────────────────────────────────────────────────────
            finding = await self._check_path(base_url, next_ep, sd_name)

            # ── Update JSON column ────────────────────────────────────────────
            checked_paths.add(next_ep.path)
            subdomain.exposure_checked_paths = _json.dumps(sorted(checked_paths))

            if finding is not None:
                logger.info(
                    "exposure: [%s] %s%s",
                    finding.severity.upper(), sd_name, finding.path,
                )
                _save_finding_to_disk(
                    subdomain_name = sd_name,
                    path           = finding.path,
                    tags           = finding.tags,
                    body_bytes     = finding.body_bytes,
                )
                should_notify = await self._persist(session, subdomain, finding)
                if should_notify and notify_callback:
                    try:
                        await notify_callback(finding, subdomain)
                    except Exception as e:
                        logger.debug("exposure: notify error: %s", e)

            await session.commit()

    # ------------------------------------------------------------------
    # Random subdomain selection
    # ------------------------------------------------------------------

    async def _pick_random_subdomains(self) -> List[Subdomain]:
        """
        Select up to EXPOSURE_BATCH_SIZE subdomains at random from all alive
        subdomains across all scopes.  Uses DB-level random ordering so the
        selection is truly random and not biased toward any particular scope.
        """
        from app.db.session import get_session
        from app.db.db_models import Scope

        dead_states = [SubdomainState.DEAD, SubdomainState.FALSE_POSITIVE]

        async with get_session() as session:
            result = await session.execute(
                select(Subdomain)
                .join(Subdomain.scope)
                .where(
                    Scope.is_active.is_(True),
                    Subdomain.state.notin_(dead_states),
                )
                .order_by(func.random())
                .limit(self._batch_size)
            )
            subdomains = result.scalars().all()
            session.expunge_all()

        return list(subdomains)

    # ------------------------------------------------------------------
    # SPA / catch-all detection
    # ------------------------------------------------------------------

    async def _is_catchall(self, base_url: str) -> bool:
        canaries = [
            f"/stoscanner-{uuid.uuid4().hex[:10]}",
            f"/{uuid.uuid4().hex[:8]}.env",
        ]
        loop = asyncio.get_running_loop()
        for canary in canaries:
            url  = f"{base_url}{canary}"
            resp = await loop.run_in_executor(
                None,
                lambda u=url: _sync_get(u, self._timeout, self._proxy),
            )
            if resp is not None and resp.status_code == 200:
                return True
        return False

    # ------------------------------------------------------------------
    # Path checker
    # ------------------------------------------------------------------

    async def _check_path(
        self,
        base_url:   str,
        ep:         ExposurePath,
        sd_name:    str,
    ) -> Optional[ExposureFindingResult]:

        url  = f"{base_url}{ep.path}"
        loop = asyncio.get_running_loop()

        try:
            resp = await loop.run_in_executor(
                None,
                lambda: _sync_get(url, self._timeout, self._proxy),
            )
        except Exception:
            return None

        if resp is None:
            return None

        try:
            if resp.status_code == 403:
                return None
            if resp.status_code != 200:
                return None

            # ── Layer 0: JSON error / rate-limit body on 200 ─────────────────
            _raw_ct = resp.headers.get("content-type", "").lower()
            if "json" in _raw_ct or resp.content[:1] == b"{":
                try:
                    import json as _json
                    _j = _json.loads(resp.content)
                    _code = str(_j.get("code", "")).strip()
                    if _code in ("429", "404", "403", "401", "500", "503", "400", "405"):
                        return None
                except Exception:
                    pass

            content_type = resp.headers.get("content-type", "")
            body_bytes   = resp.content
            try:
                body = resp.text
            except Exception:
                body = body_bytes.decode("utf-8", errors="replace")

            # ── Layer 2: Content-type ─────────────────────────────────────────
            if not _content_type_ok(content_type, ep.content_type):
                return None

            # ── Layer 3: HTML body rejection ──────────────────────────────────
            if ep.content_type != CType.HTML_OK and _body_looks_like_html(body):
                return None

            # ── Layer 4: Signature verification ──────────────────────────────
            if ep.signatures:
                if ep.content_type == CType.BINARY:
                    matched = any(sig.encode("latin-1") in body_bytes for sig in ep.signatures)
                else:
                    matched = any(sig in body for sig in ep.signatures)
                if not matched:
                    return None

            # ── Layer 5: Minimum body length ──────────────────────────────────
            effective_bytes = len(body.strip()) if ep.content_type != CType.BINARY else len(body_bytes)
            if effective_bytes < ep.min_body_bytes:
                return None

            # Snippet
            if ep.content_type == CType.BINARY:
                snippet = body_bytes[:48].hex(" ")
            else:
                snippet = re.sub(r"\s+", " ", body[:400].strip())

            return ExposureFindingResult(
                subdomain   = sd_name,
                url         = url,
                path        = ep.path,
                severity    = ep.severity,
                description = ep.description,
                status_code = resp.status_code,
                snippet     = snippet,
                tags        = ep.tags,
                body_bytes  = body_bytes,
            )

        except Exception:
            return None

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    async def _persist(
        self,
        session:   AsyncSession,
        subdomain: Subdomain,
        finding:   ExposureFindingResult,
    ) -> bool:
        """
        Upsert into exposure_findings.
        Returns True if a Discord notification should fire.
        """
        import json as _json
        from app.db.db_models import ExposureFinding as ExposureFindingModel

        renotify_days   = getattr(settings, "EXPOSURE_RENOTIFY_DAYS", 30)
        renotify_cutoff = datetime.utcnow() - timedelta(days=renotify_days)
        tags_str        = _json.dumps(finding.tags) if finding.tags else None

        stmt   = select(ExposureFindingModel).where(
            ExposureFindingModel.subdomain_id == subdomain.id,
            ExposureFindingModel.path         == finding.path,
        )
        result   = await session.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing is None:
            row = ExposureFindingModel(
                subdomain_id     = subdomain.id,
                path             = finding.path,
                severity         = finding.severity,
                description      = finding.description,
                url              = finding.url,
                tags             = tags_str,
                snippet          = finding.snippet[:200] if finding.snippet else None,
                first_seen_at    = datetime.utcnow(),
                last_seen_at     = datetime.utcnow(),
                last_notified_at = datetime.utcnow(),
            )
            session.add(row)
            logger.info(
                "exposure: NEW finding — %s%s [%s]",
                subdomain.name, finding.path, finding.severity,
            )
            return True

        existing.last_seen_at = datetime.utcnow()
        existing.snippet      = finding.snippet[:200] if finding.snippet else existing.snippet

        should_renotify = (
            existing.last_notified_at is None
            or existing.last_notified_at < renotify_cutoff
        )
        if should_renotify:
            existing.last_notified_at = datetime.utcnow()
            logger.info(
                "exposure: still live after %dd — re-notifying %s%s [%s]",
                renotify_days, subdomain.name, finding.path, finding.severity,
            )
            return True

        logger.debug(
            "exposure: known finding suppressed (notified %s) — %s%s",
            existing.last_notified_at.strftime("%Y-%m-%d"),
            subdomain.name, finding.path,
        )
        return False