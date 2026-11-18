"""
app/discovery/git_scanner.py

Git repository secret scanner using TruffleHog (filesystem mode with archive unpacking).

Flow per iteration:
  1. Pick oldest-not-yet-expanded GitScope (NULL last_expanded_at first)
  2. If is_wildcard → call GitHub/GitLab API to enumerate all repos in the org,
     insert them as GitProject rows (deduped by repo_url).
  3. If not is_wildcard → insert a single GitProject for the scope URL.
  4. Stamp git_scope.last_expanded_at.
  5. Pick ALL GitProjects (both never-scanned and previously-scanned).
  6. For each project fetch the current HEAD SHA cheaply via API (no clone).
     Skip repos whose SHA matches last_commit_sha — nothing changed.
  7. Pipeline (producer/consumer) for repos that need scanning:
       Producer — clones repos into GIT_CLONE_TMP_DIR one at a time, no proxy,
                  waits GIT_CLONE_DELAY seconds between clones to avoid hammering
                  GitHub, pushes (project, clone_path, head_sha) onto a bounded
                  asyncio.Queue.
       Consumers — GIT_SCANNER_CONCURRENCY workers pull from the queue, run
                   trufflehog filesystem (with archive unpacking at depth 1), then
                   delete the clone directory and update the DB.
       At most GIT_SCANNER_CONCURRENCY + 1 repos are on disk simultaneously.
  8. On findings → send Discord notification to DISCORD_WEBHOOK_URL_TEST.
  9. On startup → wipe any leftover gitscan_* directories in GIT_CLONE_TMP_DIR
     from a previous crashed run.

SHA-based re-scan logic:
  Before cloning, HEAD SHA is fetched from the GitHub/GitLab API (one cheap HTTP
  call).  If it matches GitProject.last_commit_sha the repo is skipped entirely —
  no clone, no scan.  When a new commit is pushed (or a new archive is added) the
  SHA changes and the repo is re-scanned automatically.  This means previously-
  scanned repos are also checked every iteration, not just new ones.

Archive unpacking:
  trufflehog filesystem with --archive-max-depth=1 unpacks archives (.zip, .jar,
  .war, .tar.gz, etc.) committed directly in the repo (one layer deep).  Depth > 1
  is not a realistic accidental-leak pattern and raises zip-bomb risk since the
  size limit applies per layer.

No proxy for git clone:
  git clone is one-at-a-time and connects only to the target host.  Proxy env vars
  are stripped from the subprocess environment so git connects directly.  All
  GitHub/GitLab API calls still go through the configured HTTP_PROXY.

Config keys (.env):
  GIT_SCANNER_ENABLED           bool   default False
  GIT_SCANNER_INTERVAL_HOURS    float  default 24.0  — full loop cooldown
  GIT_SCANNER_CONCURRENCY       int    default 2     — parallel trufflehog workers
  GIT_CLONE_TMP_DIR             str    default /tmp/gitscan
  GIT_CLONE_TIMEOUT             int    default 120   — seconds per git clone
  GIT_CLONE_DELAY               float  default 3.0   — seconds to sleep between clones
  TRUFFLEHOG_BIN                str    default "trufflehog"
  TRUFFLEHOG_TIMEOUT            int    default 300   — seconds per trufflehog scan
  TRUFFLEHOG_ARCHIVE_MAX_SIZE   int    default 104857600 (100 MB)
  TRUFFLEHOG_ARCHIVE_MAX_DEPTH  int    default 1
  GITHUB_TOKEN                  str    optional
  GITLAB_TOKEN                  str    optional
  DISCORD_WEBHOOK_URL_TEST      str    optional

DB requirement:
  GitProject must have a nullable String column `last_commit_sha`.
  Migration: ALTER TABLE git_projects ADD COLUMN last_commit_sha VARCHAR(64);
"""

from __future__ import annotations

import asyncio
import json as _json
import os
import shutil
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, quote

import httpx
from sqlalchemy import select

from app.core.config import settings
from app.core.logging import logger
from app.db.db_models import GitProject, GitScope
from app.db.session import get_session


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

@dataclass
class GitSecretFinding:
    """A single verified secret found by trufflehog in a git repo."""
    repo_url:   str
    repo_name:  str
    detector:   str
    raw_value:  str
    verified:   bool
    file_path:  str = ""
    found_at:   datetime = field(default_factory=datetime.utcnow)

    @property
    def redacted(self) -> str:
        v = self.raw_value
        if len(v) <= 12:
            return v[:3] + "***"
        return v[:6] + "***" + v[-4:]


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------

class GitScanner:
    """
    Independent background loop that scans git repositories for secrets.

    Producer/consumer pipeline:
      - Producer fetches HEAD SHA per repo via API, skips unchanged repos,
        clones new/changed repos one at a time (with a polite delay), pushes
        (project, clone_path, head_sha) onto a bounded queue.
      - GIT_SCANNER_CONCURRENCY consumer workers scan cloned repos with
        trufflehog filesystem, clean up, update DB with new SHA.
    """

    def __init__(self) -> None:
        self._enabled           = settings.GIT_SCANNER_ENABLED
        self._interval_hours    = float(getattr(settings, "GIT_SCANNER_INTERVAL_HOURS", 24.0))
        self._concurrency       = settings.GIT_SCANNER_CONCURRENCY
        self._tmp_base          = Path(settings.GIT_CLONE_TMP_DIR)
        self._clone_timeout     = settings.GIT_CLONE_TIMEOUT
        self._clone_delay       = settings.GIT_CLONE_DELAY
        self._truffle_bin       = settings.TRUFFLEHOG_BIN
        self._truffle_timeout   = settings.TRUFFLEHOG_TIMEOUT
        self._archive_max_size  = settings.TRUFFLEHOG_ARCHIVE_MAX_SIZE
        self._archive_max_depth = settings.TRUFFLEHOG_ARCHIVE_MAX_DEPTH
        self._gh_token          = settings.GITHUB_TOKEN
        self._gl_token          = settings.GITLAB_TOKEN
        self._webhook           = (
            getattr(settings, "DISCORD_WEBHOOK_URL_TEST", None)
            or settings.DISCORD_WEBHOOK_URL  # fall back to the main webhook
        )

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    async def run_loop(self) -> None:
        """Entry point called by daemon.py."""
        await self.run_forever()

    async def run_forever(self) -> None:
        if not self._enabled:
            logger.info("git_scanner: disabled (GIT_SCANNER_ENABLED=false)")
            return

        logger.info(
            "git_scanner: starting — interval=%.1fh concurrency=%d clone_delay=%.1fs tmp=%s",
            self._interval_hours, self._concurrency, self._clone_delay, self._tmp_base,
        )

        self._cleanup_tmp_dir(startup=True)

        while True:
            try:
                await self._expand_scopes()
                await self._scan_pending_projects()
            except Exception as exc:
                logger.error("git_scanner: loop crashed: %s", exc, exc_info=True)
            logger.info(
                "git_scanner: sleeping %.1fh before next cycle",
                self._interval_hours,
            )
            await asyncio.sleep(self._interval_hours * 3600)

    # ------------------------------------------------------------------
    # Startup / ongoing cleanup
    # ------------------------------------------------------------------

    def _cleanup_tmp_dir(self, startup: bool = False) -> None:
        """Remove all gitscan_* subdirectories from GIT_CLONE_TMP_DIR."""
        if not self._tmp_base.exists():
            try:
                self._tmp_base.mkdir(parents=True, exist_ok=True)
                logger.info("git_scanner: created tmp dir %s", self._tmp_base)
            except Exception as exc:
                logger.error("git_scanner: cannot create tmp dir %s: %s",
                             self._tmp_base, exc)
            return

        removed = 0
        for entry in self._tmp_base.iterdir():
            if entry.is_dir() and entry.name.startswith("gitscan_"):
                try:
                    shutil.rmtree(entry, ignore_errors=True)
                    removed += 1
                except Exception as exc:
                    logger.warning("git_scanner: cleanup failed for %s: %s", entry, exc)

        if removed:
            if startup:
                logger.warning(
                    "git_scanner: startup cleanup removed %d leftover dir(s) in %s",
                    removed, self._tmp_base,
                )
            else:
                logger.debug("git_scanner: removed %d leftover dir(s)", removed)

    # ------------------------------------------------------------------
    # Scope expansion
    # ------------------------------------------------------------------

    async def _expand_scopes(self) -> None:
        async with get_session() as session:
            result = await session.execute(
                select(GitScope)
                .where(GitScope.last_expanded_at.is_(None))
                .order_by(GitScope.added_at.asc())
                .limit(5)
            )
            scopes = result.scalars().all()
            session.expunge_all()

        for scope in scopes:
            try:
                if scope.is_wildcard:
                    await self._expand_wildcard_scope(scope)
                else:
                    await self._expand_single_scope(scope)
                # only stamp on success
                async with get_session() as session:
                    result = await session.execute(
                        select(GitScope).where(GitScope.id == scope.id)
                    )
                    s = result.scalar_one_or_none()
                    if s:
                        s.last_expanded_at = datetime.utcnow()
                        await session.commit()
            except Exception as exc:
                logger.error("git_scanner: scope expansion failed for %s: %s",
                             scope.scope_url, exc)

    async def _expand_single_scope(self, scope: GitScope) -> None:
        async with get_session() as session:
            existing = await session.execute(
                select(GitProject).where(GitProject.repo_url == scope.scope_url)
            )
            if existing.scalar_one_or_none():
                return
            session.add(GitProject(
                repo_url=scope.scope_url,
                repo_name=_repo_name(scope.scope_url),
                scope_id=scope.id,
            ))
            await session.commit()

    async def _expand_wildcard_scope(self, scope: GitScope) -> None:
        parsed = urlparse(scope.scope_url)
        host   = parsed.netloc.lower()
        path   = parsed.path.strip("/")

        if "github.com" in host:
            repos = await self._list_github_repos(path)
        elif "gitlab.com" in host:
            repos = await self._list_gitlab_repos(path)
        else:
            logger.warning("git_scanner: unknown wildcard host %s", host)
            return

        async with get_session() as session:
            for repo_url, repo_name in repos:
                existing = await session.execute(
                    select(GitProject).where(GitProject.repo_url == repo_url)
                )
                if existing.scalar_one_or_none():
                    continue
                session.add(GitProject(
                    repo_url=repo_url,
                    repo_name=repo_name,
                    scope_id=scope.id,
                ))
            await session.commit()

        logger.info("git_scanner: expanded %s → %d repo(s)", scope.scope_url, len(repos))

    async def _list_github_repos(self, org: str) -> List[Tuple[str, str]]:
        headers = {"Accept": "application/vnd.github+json"}
        if self._gh_token:
            headers["Authorization"] = f"Bearer {self._gh_token}"

        # use type=all when token present (private repos)
        repo_type = "all" if self._gh_token else "public"

        repos: List[Tuple[str, str]] = []
        page = 1
        async with httpx.AsyncClient(headers=headers, timeout=30) as client:
            while True:
                resp = await client.get(
                    f"https://api.github.com/orgs/{org}/repos",
                    params={"type": repo_type, "per_page": 100, "page": page},
                )
                if resp.status_code != 200:
                    logger.warning("git_scanner: GitHub API %s for org %s",
                                   resp.status_code, org)
                    break
                data = resp.json()
                if not data:
                    break
                for r in data:
                    repos.append((r["clone_url"], r["full_name"]))
                page += 1
        return repos

    async def _list_gitlab_repos(self, group_path: str) -> List[Tuple[str, str]]:
        # Strip a .git suffix before encoding.
        if group_path.endswith(".git"):
            group_path = group_path[:-4]
        encoded = quote(group_path, safe="")  # encode nested group path

        headers = {}
        if self._gl_token:
            headers["PRIVATE-TOKEN"] = self._gl_token

        repos: List[Tuple[str, str]] = []
        page = 1
        async with httpx.AsyncClient(headers=headers, timeout=30) as client:
            while True:
                resp = await client.get(
                    f"https://gitlab.com/api/v4/groups/{encoded}/projects",
                    params={"per_page": 100, "page": page, "include_subgroups": "true"},
                )
                if resp.status_code != 200:
                    logger.warning("git_scanner: GitLab API %s for group %s",
                                   resp.status_code, group_path)
                    break
                data = resp.json()
                if not data:
                    break
                for r in data:
                    repos.append((r["http_url_to_repo"], r["path_with_namespace"]))
                page += 1
        return repos

    # ------------------------------------------------------------------
    # HEAD SHA fetching  (cheap — no clone, just one API call per repo)
    # ------------------------------------------------------------------

    async def _fetch_head_sha(
        self, client: httpx.AsyncClient, repo_url: str
    ) -> Optional[str]:
        """
        Return the current HEAD commit SHA for a repo via API.
        Returns None on error — callers treat None as "proceed with scan" (fail open).
        """
        parsed = urlparse(repo_url)
        host   = parsed.netloc.lower()
        path   = parsed.path.strip("/")
        if path.endswith(".git"):
            path = path[:-4]

        try:
            if "github.com" in host:
                headers = {"Accept": "application/vnd.github+json"}
                if self._gh_token:
                    headers["Authorization"] = f"Bearer {self._gh_token}"
                resp = await client.get(
                    f"https://api.github.com/repos/{path}/commits/HEAD",
                    headers=headers,
                    timeout=10,
                )
                if resp.status_code == 200:
                    return resp.json().get("sha")

            elif "gitlab.com" in host:
                encoded = quote(path, safe="")
                headers = {}
                if self._gl_token:
                    headers["PRIVATE-TOKEN"] = self._gl_token
                resp = await client.get(
                    f"https://gitlab.com/api/v4/projects/{encoded}/repository/commits/HEAD",
                    headers=headers,
                    timeout=10,
                )
                if resp.status_code == 200:
                    return resp.json().get("id")

        except Exception as exc:
            logger.debug("git_scanner: HEAD SHA fetch failed for %s: %s", repo_url, exc)

        return None

    # ------------------------------------------------------------------
    # Producer / consumer pipeline
    # ------------------------------------------------------------------

    async def _scan_pending_projects(self) -> None:
        """
        Check projects for new commits in batches, scanning those that changed.
        """
        # Create queue and consumers
        queue: asyncio.Queue[
            Optional[Tuple[GitProject, Optional[Path], Optional[str]]]
        ] = asyncio.Queue(maxsize=self._concurrency + 1)

        consumers = [
            asyncio.create_task(self._scan_worker(queue))
            for _ in range(self._concurrency)
        ]

        # Settings for batching and concurrency
        BATCH_SIZE = 50
        MAX_PROJECTS = 200
        SHA_CONCURRENCY = 10

        processed = 0
        offset = 0
        first_clone = True  # to manage clone delay

        # We'll use a session for each batch to avoid holding a transaction too long
        while processed < MAX_PROJECTS:
            async with get_session() as session:
                # Fetch next batch, ordered by last_scanned_at (NULLs first = oldest first)
                stmt = (
                    select(GitProject)
                    .order_by(GitProject.last_scanned_at.asc().nullsfirst())
                    .offset(offset)
                    .limit(BATCH_SIZE)
                )
                result = await session.execute(stmt)
                batch = result.scalars().all()
                if not batch:
                    break

                # Detach objects from session to use outside
                session.expunge_all()

            # Fetch HEAD SHAs for this batch concurrently with a semaphore
            sem = asyncio.Semaphore(SHA_CONCURRENCY)
            async with httpx.AsyncClient() as client:
                async def fetch_with_limit(project: GitProject) -> Optional[str]:
                    async with sem:
                        return await self._fetch_head_sha(client, project.repo_url)

                head_shas: List[Optional[str]] = await asyncio.gather(
                    *[fetch_with_limit(p) for p in batch],
                    return_exceptions=False,
                )

            # Process each project in the batch
            for project, head_sha in zip(batch, head_shas):
                processed += 1
                stored_sha = getattr(project, "last_commit_sha", None)
                # Decide if we need to scan: head_sha is None (fetch failed) or stored_sha is None or head_sha != stored_sha
                if head_sha is not None and stored_sha is not None and head_sha == stored_sha:
                    logger.debug(
                        "git_scanner: skip %s — SHA unchanged (%s)",
                        project.repo_url, head_sha[:8],
                    )
                    continue

                logger.info(
                    "git_scanner: will scan %s (old SHA: %s, new SHA: %s)",
                    project.repo_url,
                    stored_sha[:8] if stored_sha else "None",
                    head_sha[:8] if head_sha else "unknown",
                )

                # Apply clone delay except for the first clone overall
                if not first_clone and self._clone_delay > 0:
                    await asyncio.sleep(self._clone_delay)
                first_clone = False

                # Clone the repo (may return None on failure)
                clone_path = await self._clone_repo(project)
                # Push to queue (even if clone failed, so worker can update DB)
                await queue.put((project, clone_path, head_sha))

                # If we've reached MAX_PROJECTS, break out early
                if processed >= MAX_PROJECTS:
                    break

            # After finishing the batch, increase offset for next batch
            offset += len(batch)

            # If we broke early due to MAX_PROJECTS, break outer loop
            if processed >= MAX_PROJECTS:
                break

            # Small sleep between batches to avoid hammering API even when no clones happen
            await asyncio.sleep(0.5)

        # Signal consumers to stop
        for _ in range(self._concurrency):
            await queue.put(None)

        await asyncio.gather(*consumers, return_exceptions=True)

    async def _scan_worker(
        self,
        queue: asyncio.Queue[
            Optional[Tuple[GitProject, Optional[Path], Optional[str]]]
        ],
    ) -> None:
        """Consumer: scan a cloned repo, save new SHA to DB, delete clone."""
        while True:
            item = await queue.get()
            if item is None:
                queue.task_done()
                return

            project, clone_path, head_sha = item
            try:
                if clone_path is not None and clone_path.exists():
                    findings = await self._run_trufflehog_fs(project, clone_path)
                else:
                    findings = []

                await self._update_project(project, len(findings), head_sha)
                await self._persist_findings(project, findings)

                if findings:
                    logger.info("git_scanner: %d verified finding(s) in %s",
                                len(findings), project.repo_url)
                    await self._notify_discord(findings)
                else:
                    logger.debug("git_scanner: no findings in %s", project.repo_url)

            except Exception as exc:
                logger.error("git_scanner: worker error for %s: %s",
                             project.repo_url, exc)
            finally:
                if clone_path is not None:
                    _rm_clone(clone_path)
                queue.task_done()

    # ------------------------------------------------------------------
    # Git clone  (no proxy — direct connection)
    # ------------------------------------------------------------------

    async def _clone_repo(self, project: GitProject) -> Optional[Path]:
        """
        Shallow-clone the repo into GIT_CLONE_TMP_DIR.

        Proxy env vars are stripped so git connects directly regardless of the
        system proxy configuration.  Credentials are embedded in the URL.
        """
        self._tmp_base.mkdir(parents=True, exist_ok=True)
        clone_dir = self._tmp_base / f"gitscan_{uuid.uuid4().hex}"
        repo_url  = self._inject_token(project.repo_url)

        env = {
            k: v for k, v in os.environ.items()
            if k.upper() not in {
                "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                "http_proxy", "https_proxy", "all_proxy",
            }
        }

        cmd = [
            "git", "clone",
            "--depth=1",
            "--single-branch",
            "--quiet",
            repo_url,
            str(clone_dir),
        ]

        logger.info("git_scanner: cloning %s → %s", project.repo_url, clone_dir.name)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            try:
                _, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self._clone_timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                logger.warning("git_scanner: clone timed out after %ds for %s",
                               self._clone_timeout, project.repo_url)
                _rm_clone(clone_dir)
                return None

            if proc.returncode != 0:
                err_msg = stderr.decode(errors="ignore").strip()[:200]
                logger.error("git_scanner: clone failed for %s: %s",
                             project.repo_url, err_msg)
                _rm_clone(clone_dir)
                return None

            logger.info("git_scanner: clone complete %s", clone_dir.name)
            return clone_dir

        except FileNotFoundError:
            logger.error("git_scanner: 'git' binary not found on PATH")
            return None
        except Exception as exc:
            logger.error("git_scanner: clone error for %s: %s", project.repo_url, exc)
            _rm_clone(clone_dir)
            return None

    # ------------------------------------------------------------------
    # TruffleHog filesystem scan  (archive unpacking depth=1)
    # ------------------------------------------------------------------

    async def _run_trufflehog_fs(
        self, project: GitProject, clone_path: Path
    ) -> List[GitSecretFinding]:
        """
        Run trufflehog filesystem on the cloned directory.

        --archive-max-depth=1  unpacks archives committed directly in the repo
        (.zip, .jar, .war, .tar.gz, etc.) — one level deep, no zip-bomb risk.
        """
        cmd = [
            self._truffle_bin,
            "filesystem",
            str(clone_path),
            "--only-verified",
            "--json",
            "--no-update",
            f"--archive-max-size={self._archive_max_size}",
            f"--archive-max-depth={self._archive_max_depth}",
        ]

        findings: List[GitSecretFinding] = []

        logger.info("git_scanner: scanning %s", project.repo_url)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=self._truffle_timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                logger.warning("git_scanner: trufflehog timed out after %ds for %s",
                               self._truffle_timeout, project.repo_url)
                return []

            for line in stdout.decode(errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = _json.loads(line)
                except _json.JSONDecodeError:
                    continue

                detector  = obj.get("DetectorName", "Unknown")
                raw_value = obj.get("Raw", "") or obj.get("RawV2", "")
                verified  = obj.get("Verified", False)

                if not verified or not raw_value:
                    continue

                source_meta = obj.get("SourceMetadata", {}).get("Data", {})
                fs_meta     = source_meta.get("Filesystem", {})
                file_path   = fs_meta.get("file", "")

                # Strip tmp clone prefix for cleaner output
                if file_path.startswith(str(clone_path)):
                    file_path = file_path[len(str(clone_path)):].lstrip("/")

                findings.append(GitSecretFinding(
                    repo_url=project.repo_url,
                    repo_name=project.repo_name or _repo_name(project.repo_url),
                    detector=detector,
                    raw_value=raw_value,
                    verified=True,
                    file_path=file_path,
                ))

                logger.info("git_scanner: [%s] verified in %s — file=%s",
                            detector, project.repo_url, file_path)

        except FileNotFoundError:
            logger.error(
                "git_scanner: trufflehog binary '%s' not found. "
                "Install: curl -sSfL https://raw.githubusercontent.com/trufflesecurity/"
                "trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin",
                self._truffle_bin,
            )

        return findings

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------

    def _inject_token(self, repo_url: str) -> str:
        parsed = urlparse(repo_url)
        if self._gh_token and "github.com" in parsed.netloc:
            return repo_url.replace(
                "https://github.com/",
                f"https://{self._gh_token}@github.com/",
                1,
            )
        if self._gl_token and "gitlab.com" in parsed.netloc:
            return repo_url.replace(
                "https://gitlab.com/",
                f"https://oauth2:{self._gl_token}@gitlab.com/",
                1,
            )
        return repo_url

    async def _update_project(
        self,
        project: GitProject,
        findings_count: int,
        head_sha: Optional[str],
    ) -> None:
        async with get_session() as session:
            result = await session.execute(
                select(GitProject).where(GitProject.id == project.id)
            )
            proj = result.scalar_one_or_none()
            if proj:
                proj.last_scanned_at = datetime.utcnow()
                proj.findings_count  = findings_count
                if head_sha:
                    proj.last_commit_sha = head_sha
                await session.commit()

    async def _persist_findings(
        self,
        project: GitProject,
        findings: List[GitSecretFinding],
    ) -> None:
        """Upsert verified findings so they survive the Discord alert."""
        if not findings:
            return

        from sqlalchemy.dialects.postgresql import insert as pg_insert

        from app.db.db_models import GitSecretRecord

        now = datetime.utcnow()
        try:
            async with get_session() as session:
                for finding in findings:
                    stmt = (
                        pg_insert(GitSecretRecord)
                        .values(
                            git_project_id=int(project.id),
                            detector=finding.detector[:128],
                            redacted=finding.redacted[:512],
                            file_path=(finding.file_path or None),
                            verified=bool(finding.verified),
                            first_seen_at=now,
                            last_seen_at=now,
                        )
                        .on_conflict_do_update(
                            constraint="uq_git_secret",
                            set_={"last_seen_at": now, "file_path": finding.file_path or None},
                        )
                    )
                    await session.execute(stmt)
                await session.commit()
            logger.info(
                "git_scanner: persisted %d finding(s) for %s",
                len(findings), project.repo_url,
            )
        except Exception as exc:
            logger.warning(
                "git_scanner: could not persist findings for %s: %s",
                project.repo_url, exc,
            )

    # ------------------------------------------------------------------
    # Discord notification
    # ------------------------------------------------------------------

    async def _notify_discord(self, findings: List[GitSecretFinding]) -> None:
        if not findings:
            return
        if not self._webhook:
            logger.warning("git_scanner: no Discord webhook configured (set DISCORD_WEBHOOK_URL or DISCORD_WEBHOOK_URL_TEST) — skipping")
            return

        by_repo: Dict[str, List[GitSecretFinding]] = {}
        for f in findings:
            by_repo.setdefault(f.repo_url, []).append(f)

        for repo_url, repo_findings in by_repo.items():
            first  = repo_findings[0]
            fields = []

            for f in repo_findings[:20]:
                detail = f"`{f.file_path}`" if f.file_path else "—"
                fields.append({
                    "name":   f"🔑 {f.detector}",
                    "value":  f"`{f.redacted}`\n{detail}",
                    "inline": False,
                })

            if len(repo_findings) > 20:
                fields.append({
                    "name":  "…and more",
                    "value": f"{len(repo_findings) - 20} additional finding(s) suppressed",
                    "inline": False,
                })

            embed = {
                "title": f"🚨 Git Secrets: {first.repo_name or repo_url}",
                "description": (
                    f"**{len(repo_findings)} verified secret(s)** found by TruffleHog\n"
                    f"[{repo_url}]({repo_url})"
                ),
                "color":  0xFF0000,
                "fields": fields,
                "footer": {"text": "STOscanner — Git Secret Scanner (filesystem + archives)"},
                "timestamp": datetime.utcnow().isoformat(),
            }

            payload = {"embeds": [embed], "username": "STOscanner"}

            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.post(self._webhook, json=payload, timeout=30.0)
                    if resp.status_code == 204:
                        logger.info("git_scanner: Discord alert sent for %s (%d findings)",
                                    repo_url, len(repo_findings))
                    elif resp.status_code == 429:
                        retry_after = min(float(resp.json().get("retry_after", 2.0)), 30.0)
                        await asyncio.sleep(retry_after)
                        await self._notify_discord(repo_findings)
                    else:
                        logger.warning("git_scanner: Discord alert failed HTTP %s for %s",
                                       resp.status_code, repo_url)
            except Exception as exc:
                logger.error("git_scanner: Discord notify error for %s: %s",
                             repo_url, exc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _repo_name(url: str) -> str:
    parts = url.rstrip("/").split("/")
    if len(parts) >= 2:
        return "/".join(parts[-2:])
    return url


def _rm_clone(path: Optional[Path]) -> None:
    if path is None:
        return
    try:
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)
            logger.debug("git_scanner: removed clone dir %s", path.name)
    except Exception as exc:
        logger.warning("git_scanner: failed to remove %s: %s", path, exc)
