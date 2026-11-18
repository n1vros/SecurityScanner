"""
app/discovery/permutation.py

Permutation-based subdomain discovery.

For each newly discovered subdomain (e.g. dev.example.com) this module:
  1. Runs `alterx` to generate a wordlist of permutations:
       dev2.example.com, dev-old.example.com, dev-staging.example.com, …
  2. Pipes that wordlist into `puredns resolve` to filter to live hosts.
  3. Upserts any resolving permutations into the Subdomain table, exactly
     like ActiveDiscovery does, so they enter the normal probe pipeline.

Permutation scanning is intentionally scoped to seeds that look "interesting"
(test/dev/staging/old/etc.) to avoid exploding the candidate set on production
subdomains that are unlikely to have dangling siblings.

Config knobs (all optional, all in settings):
  ALTERX_ENABLED               bool  default True
  ALTERX_BINARY                str   default "alterx"
  ALTERX_MAX_CONCURRENT        int   default 3   (parallel alterx+puredns runs)
  ALTERX_TIMEOUT_SECS          int   default 120
  ALTERX_ENRICH_ALL            bool  default False
                                     True  → permute every subdomain found
                                     False → only permute "interesting" names
"""

import asyncio
import os
import re
import tempfile
from pathlib import Path
from typing import List

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import logger
from app.discovery.resolvers import get_resolvers_file, get_resolver_list
from app.discovery.active import ActiveDiscovery, _get_puredns_semaphore  # reuse upsert helper + shared puredns semaphore

# Matches subdomains whose labels look like candidates worth permuting.
# We intentionally keep this broad rather than tight so we catch things like
# api-test, gateway-staging, auth-dev-eu, etc.
_INTERESTING = re.compile(
    r"(^|[-.])(dev|test|staging|stage|beta|demo|uat|qa|sandbox|preview|"
    r"old|legacy|temp|tmp|backup|bak|alpha|rc|pre|canary|internal|"
    r"int|stg|preprod|admin|mgmt|manage|portal|cdn|api|app|web|"
    r"static|assets|media|images|img|files|upload|uploads|cdn\d*|"
    r"v\d+|v\d+\.\d+)($|[-.])",
    re.IGNORECASE,
)


class PermutationDiscovery:
    """
    Runs alterx + puredns on each seed subdomain to find live permutations.
    """

    def __init__(self) -> None:
        self._sem = asyncio.Semaphore(
            getattr(settings, "ALTERX_MAX_CONCURRENT", 3)
        )

    # ── Public API ─────────────────────────────────────────────────────────────

    async def enrich(
        self,
        session: AsyncSession,
        scope_domain: str,
        seeds: List[str],
    ) -> List[str]:
        """
        Generate and resolve permutations for each seed in `seeds`.

        Pipeline:
          1. Run alterx concurrently on all interesting seeds (bounded by _sem).
          2. Merge and deduplicate all generated candidates across seeds.
          3. Single puredns resolve run on the merged list — avoids redundant
             DNS queries that would occur if each seed had its own puredns run.
          4. Scope-filter resolved results and upsert to DB.

        Args:
            session:      AsyncSession — used for DB upserts.
            scope_domain: The parent scope (e.g. "example.com") — used to
                          filter out-of-scope results from puredns output.
            seeds:        List of subdomains discovered this iteration to
                          use as permutation seeds.

        Returns:
            List of newly upserted subdomain names (may be empty).
        """
        if not getattr(settings, "ALTERX_ENABLED", True):
            return []

        if not seeds:
            return []

        enrich_all: bool = getattr(settings, "ALTERX_ENRICH_ALL", False)
        interesting = [s for s in seeds if enrich_all or _INTERESTING.search(s)]

        if not interesting:
            logger.debug(
                "permutation: no interesting seeds in %d candidates for %s",
                len(seeds),
                scope_domain,
            )
            return []

        logger.info(
            "permutation: running alterx on %d/%d seeds for %s",
            len(interesting),
            len(seeds),
            scope_domain,
        )

        # Step 1: run all alterx jobs concurrently (semaphore-bounded)
        alterx_tasks = [self._run_alterx_for_seed(seed) for seed in interesting]
        alterx_results = await asyncio.gather(*alterx_tasks, return_exceptions=True)

        # Step 2: merge + deduplicate candidates across all seeds
        all_candidates: set = set()
        for seed, result in zip(interesting, alterx_results):
            if isinstance(result, Exception):
                logger.warning("permutation: alterx error on seed %s: %s", seed, result)
            else:
                all_candidates.update(result)

        if not all_candidates:
            return []

        logger.debug(
            "permutation: %d unique candidates from %d seeds for %s",
            len(all_candidates),
            len(interesting),
            scope_domain,
        )

        # Step 3: single puredns run on merged candidate list
        resolved = await self._run_puredns(sorted(all_candidates))
        if not resolved:
            return []

        # Step 4: scope-filter + upsert
        in_scope = [
            h for h in resolved
            if h == scope_domain or h.endswith(f".{scope_domain}")
        ]
        if not in_scope:
            return []

        logger.debug(
            "permutation: resolved=%d in_scope=%d for %s",
            len(resolved),
            len(in_scope),
            scope_domain,
        )

        upserted = await self._upsert_subdomains(session, scope_domain, in_scope)
        if upserted:
            logger.info(
                "permutation: found %d new subdomains for %s",
                len(upserted),
                scope_domain,
            )
        return upserted

    # ── Core pipeline ──────────────────────────────────────────────────────────

    async def _run_alterx_for_seed(self, seed: str) -> List[str]:
        """
        Run alterx on a single seed (semaphore-bounded) and return candidates.
        Scope filtering and puredns resolution are handled by enrich() on the
        merged candidate set — not here — to avoid redundant DNS queries.
        """
        async with self._sem:
            return await self._run_alterx(seed)

    # ── alterx ────────────────────────────────────────────────────────────────

    async def _run_alterx(self, seed: str) -> List[str]:
        """
        Run alterx on a single seed and return the generated permutations.

        alterx takes the seed on stdin (or via -list) and writes one candidate
        per line to stdout.  We pass it via stdin to avoid temp-file churn.
        """
        binary: str = getattr(settings, "ALTERX_BINARY", "alterx")
        timeout: int = getattr(settings, "ALTERX_TIMEOUT_SECS", 120)

        # -enrich  — use alterx's built-in enrichment patterns
        # -silent  — suppress banner/progress to keep stdout clean
        cmd = [binary, "-enrich", "-silent"]

        logger.debug("permutation: alterx cmd=%s seed=%s", cmd, seed)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=(seed + "\n").encode()),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            logger.warning("permutation: alterx timed out for seed=%s", seed)
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
            return []
        except FileNotFoundError:
            logger.error(
                "permutation: alterx binary not found at '%s'. "
                "Install with: go install github.com/projectdiscovery/alterx/cmd/alterx@latest",
                binary,
            )
            return []
        except Exception as exc:
            logger.warning("permutation: alterx error for seed=%s: %s", seed, exc)
            return []

        if proc.returncode not in (0, None) and stderr:
            logger.debug(
                "permutation: alterx stderr for seed=%s: %s",
                seed,
                stderr.decode(errors="replace").strip(),
            )

        lines = stdout.decode(errors="replace").splitlines()
        candidates = [ln.strip().lower() for ln in lines if ln.strip()]
        logger.debug(
            "permutation: alterx generated %d candidates for seed=%s",
            len(candidates),
            seed,
        )
        return candidates

    # ── puredns ───────────────────────────────────────────────────────────────

    async def _run_puredns(self, candidates: List[str]) -> List[str]:
        """
        Resolve a list of candidate hostnames via puredns.

        Writes candidates to a temp file, runs puredns resolve, returns the
        resolved hostnames.  Uses the same puredns settings as ActiveDiscovery.
        """
        if not candidates:
            return []

        binary: str = getattr(settings, "PUREDNS_BINARY", "puredns")
        rate_limit: int = getattr(settings, "PUREDNS_RATE_LIMIT", 500)
        timeout: int = getattr(settings, "PUREDNS_TIMEOUT_SECS", 300)

        # Use the full DNS_RESOLVERS pool (15k+ IPs) via shared temp file
        resolvers_path: str = get_resolvers_file()
        resolver_count = len(get_resolver_list())

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, prefix="alterx_candidates_"
        ) as tmp:
            tmp.write("\n".join(candidates))
            tmp_path = tmp.name

        cmd = [
            binary, "resolve", tmp_path,
            "--rate-limit", str(rate_limit),
            "--write-wildcard-answers", "/dev/null",
            "-q",   # quiet — only resolved hostnames to stdout
        ]
        if resolvers_path and Path(resolvers_path).exists():
            cmd += ["-r", resolvers_path]
        else:
            logger.warning(
                "permutation: resolver file missing — puredns will use system resolver"
            )

        logger.debug(
            "permutation: puredns resolving %d candidates using %d resolvers @ %d QPS",
            len(candidates), resolver_count, rate_limit,
        )

        resolved: List[str] = []
        puredns_sem = _get_puredns_semaphore()
        try:
            async with puredns_sem:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout,
                )
            lines = stdout.decode(errors="replace").splitlines()
            resolved = [ln.strip().lower() for ln in lines if ln.strip()]
        except asyncio.TimeoutError:
            logger.warning(
                "permutation: puredns timed out on %d candidates", len(candidates)
            )
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
        except FileNotFoundError:
            logger.error(
                "permutation: puredns binary not found at '%s'. "
                "Install: go install github.com/d3mondev/puredns/v2@latest",
                binary,
            )
        except Exception as exc:
            logger.warning("permutation: puredns error: %s", exc)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

        logger.debug(
            "permutation: puredns resolved %d/%d", len(resolved), len(candidates)
        )
        return resolved

    # ── DB upsert ─────────────────────────────────────────────────────────────

    async def _upsert_subdomains(
        self,
        session: AsyncSession,
        scope_domain: str,
        hostnames: List[str],
    ) -> List[str]:
        """
        Upsert resolved permutations into the Subdomain table.

        Delegates to ActiveDiscovery._upsert_subdomains which already handles
        the scope lookup, deduplication, and source tagging correctly.
        Permutations are tagged with source="permutation" to distinguish them
        from passive/active discoveries in queries and reporting.
        """
        if not hostnames:
            return []

        # ActiveDiscovery.upsert_subdomains is a classmethod that takes
        # (session, scope_domain, hostnames, source).  We call it directly
        # to avoid duplicating the scope-lookup + insert logic.
        try:
            return await ActiveDiscovery.upsert_subdomains(
                session,
                scope_domain,
                hostnames,
                source="permutation",
            )
        except Exception as exc:
            logger.warning(
                "permutation: upsert failed for %s: %s", scope_domain, exc
            )
            return []