"""
app/takeover/ip_hunter/providers/gcp_eip.py

GCP Static External IP takeover provider.

Reserves a batch of static external IP addresses (no VM required), checks if
any assigned IP matches a target, then releases all non-hits immediately.

Single-batch-per-region design
───────────────────────────────
hunt() allocates exactly GCP_EIP_BATCH_SIZE addresses in parallel, checks
every assigned IP against the target pool, releases all non-hits concurrently,
and returns. There is NO outer attempts loop and NO duplicate-IP tracking —
the looping is handled externally by hunter.py's per-provider loop (which
sleeps IP_HUNTER_INTERVAL_HOURS between calls). This keeps the GCP quota
usage predictable and eliminates the noise from duplicate IPs recycling.

Thread-safety note
──────────────────
googleapiclient uses httplib2 internally. httplib2.Http is NOT thread-safe.
_get_addresses_client() is called INSIDE each blocking closure so every
executor thread owns its own service object and HTTP connection pool. Never
store and share a client across concurrent calls.

Config keys (.env):
  GCP_PROJECT_ID           str   required
  GCP_SERVICE_ACCOUNT_JSON str   required  (path to SA JSON file)
                                           OR set GCP_SERVICE_ACCOUNT_KEY
  GCP_SERVICE_ACCOUNT_KEY  str   SA JSON content directly
  GCP_EIP_REGIONS          str   default "us-central1,us-east1,europe-west1,asia-southeast1"
  GCP_EIP_BATCH_SIZE       int   default 3   IPs allocated per region per cycle
  GCP_EIP_SLEEP_MS         int   default 1000  ms between batch and next region
"""

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Set
import uuid

from app.core.config import settings
from app.core.logging import logger
from app.takeover.ip_hunter.cidr_index import CIDRIndex


# SSL errors from the GCP API are transient (packet corruption, TLS session
# expiry, connection reuse after a long idle). Retry up to this many times
# with a short backoff before giving up on a single allocation slot.
_SSL_RETRY_ATTEMPTS = 3
_SSL_RETRY_SLEEP    = 2.0   # seconds between retries


def _is_location_forbidden(exc_str: str) -> bool:
    """
    Return True when GCP says this region/location is inaccessible —
    either not enabled for the project or missing IAM permissions.

    Error shapes seen in the wild:
      HTTP 403 "Permission denied on 'locations/me-central2' (or it may not exist)."
      HTTP 403 "Forbidden" with reason "forbidden" on a locations/ URL
    """
    return (
        "Permission denied on 'locations/" in exc_str
        or (
            "403" in exc_str
            and "locations/" in exc_str
            and "forbidden" in exc_str.lower()
        )
    )


@dataclass
class GCPHuntResult:
    region:        str
    ip_allocated:  str
    address_name:  str
    hit:           bool
    attempted_at:  datetime
    released_at:   Optional[datetime] = None
    error:         Optional[str]      = None


class GCPStaticIPHunter:
    """
    Hunts dangling GCP IPs by reserving static external addresses
    and checking if any assigned IP matches known targets.
    """

    def __init__(
        self,
        target_ips: Set[str],
        cidr_index: Optional[CIDRIndex] = None,
    ) -> None:
        self._targets      = target_ips
        self._cidr_index   = cidr_index
        self._project      = getattr(settings, "GCP_PROJECT_ID",           None)
        self._sa_json_path = getattr(settings, "GCP_SERVICE_ACCOUNT_JSON", None)
        self._sa_key       = getattr(settings, "GCP_SERVICE_ACCOUNT_KEY",  None)
        self._sleep_ms     = int(getattr(settings, "GCP_EIP_SLEEP_MS", 1000))

        if not self._project:
            raise RuntimeError(
                "GCPStaticIPHunter: GCP_PROJECT_ID must be set in .env"
            )
        if not self._sa_json_path and not self._sa_key:
            raise RuntimeError(
                "GCPStaticIPHunter: either GCP_SERVICE_ACCOUNT_JSON (path) or "
                "GCP_SERVICE_ACCOUNT_KEY (JSON content) must be set in .env"
            )

    # ── Region helpers ───────────────────────────────────────────────────────

    @staticmethod
    def default_regions() -> List[str]:
        raw = getattr(
            settings, "GCP_EIP_REGIONS",
            "us-central1,us-east1,europe-west1,asia-southeast1",
        )
        return [r.strip() for r in raw.split(",") if r.strip()]

    def target_regions(self) -> List[str]:
        """
        Return GCP regions that contain target IPs per CIDR index.
        Skips 'global' scope entries — those are anycast, not regional EIPs.
        """
        if not self._cidr_index or not self._targets:
            return self.default_regions()

        matched: Set[str] = set()
        for ip in self._targets:
            match = self._cidr_index.lookup(ip)
            if match and match.provider == "gcp":
                region = match.region.strip().lower()
                if region and region != "global":
                    matched.add(region)

        if not matched:
            logger.info("gcp_eip: no CIDR matches for targets — using default regions")
            return self.default_regions()

        logger.info("gcp_eip: target regions from CIDR index: %s", sorted(matched))
        return sorted(matched)

    # ── GCP client factory ───────────────────────────────────────────────────

    def _get_addresses_client(self):
        """
        Build a fresh Compute API client.

        CRITICAL — thread safety:
        googleapiclient uses httplib2 internally. httplib2.Http is NOT
        thread-safe. Never reuse a single client across concurrent
        run_in_executor calls — each blocking closure must call this
        function itself so every OS thread gets its own HTTP connection pool.
        Sharing a client across threads causes heap corruption → SIGABRT.
        """
        import json
        from google.oauth2 import service_account
        from googleapiclient import discovery

        if self._sa_key:
            info = json.loads(self._sa_key)
            creds = service_account.Credentials.from_service_account_info(
                info,
                scopes=["https://www.googleapis.com/auth/compute"],
            )
        else:
            creds = service_account.Credentials.from_service_account_file(
                self._sa_json_path,
                scopes=["https://www.googleapis.com/auth/compute"],
            )

        # cache_discovery=False avoids a shared file-system cache that can
        # also be read/written concurrently from multiple threads.
        return discovery.build("compute", "v1", credentials=creds, cache_discovery=False)

    # ── Stranded resource cleanup ─────────────────────────────────────────────

    async def _purge_stranded(self, loop, region: str) -> None:
        """
        Delete any static addresses in this region whose IP is NOT in the
        target pool. Only touches addresses whose name starts with 'sto-hunt-'.

        Checks ALL statuses (RESERVED, IN_USE, or transient) rather than only
        RESERVED, so addresses left mid-provisioning by a previous crash are
        also cleaned up. A new client is created inside the executor closure
        for thread safety.
        """
        def _do_purge():
            compute = self._get_addresses_client()
            try:
                result = compute.addresses().list(
                    project=self._project,
                    region=region,
                ).execute()
            except Exception as exc:
                logger.warning("gcp_eip: _purge_stranded list failed in %s: %s", region, exc)
                return []

            return [
                addr for addr in result.get("items", [])
                if addr.get("name", "").startswith("sto-hunt-")
                and addr.get("address") not in self._targets
            ]

        try:
            stranded = await loop.run_in_executor(None, _do_purge)
        except Exception as exc:
            logger.warning("gcp_eip: _purge_stranded failed in %s: %s", region, exc)
            return

        if not stranded:
            logger.debug("gcp_eip: no stranded addresses found in %s", region)
            return

        logger.warning(
            "gcp_eip: purging %d stranded address(es) in %s: %s",
            len(stranded), region,
            [f"{a.get('name')}={a.get('address')}({a.get('status')})" for a in stranded],
        )
        for addr in stranded:
            await self._delete_address(loop, region, addr["name"])
            logger.info(
                "gcp_eip: purged stranded address %s (%s, status=%s)",
                addr.get("address"), addr["name"], addr.get("status"),
            )

    # ── Core hunt — single batch per region ───────────────────────────────────

    async def hunt(
        self,
        region:     str,
        batch_size: Optional[int] = None,
    ) -> List[GCPHuntResult]:
        """
        Allocate ONE batch of GCP_EIP_BATCH_SIZE static addresses in parallel,
        check each against the target pool, release all non-hits, and return.

        No outer attempts loop — no duplicate-IP tracking. The looping and
        sleeping between cycles is handled by hunter.py's _provider_loop().

        Thread safety: every blocking GCP API call creates its own client
        instance inside the executor closure — never shared across threads.

        Error handling:
          409 alreadyExists  — orphan from a crashed run; delete and retry slot.
          SSL/timeout errors — transient; retry up to _SSL_RETRY_ATTEMPTS times.
          403 location forbidden — region not enabled; abort region immediately.
          LocationNotAvailableForResourceType — same early-abort.
        """
        _batch_size = batch_size if batch_size is not None else int(
            getattr(settings, "GCP_EIP_BATCH_SIZE", 3)
        )
        loop = asyncio.get_running_loop()

        # Shared flag: set by _alloc_one when the region is forbidden.
        # Checked after gather() to abort early and clean up.
        region_forbidden = False

        await self._purge_stranded(loop, region)

        logger.info(
            "gcp_eip: hunting in %s — batch=%d, %d targets",
            region, _batch_size, len(self._targets),
        )

        # ── Inner allocation coroutine ────────────────────────────────────────

        async def _alloc_one(address_name: str) -> tuple:
            """
            Allocate one static address. Returns (name, ip) or (name, None).

            Each blocking call builds its own compute client so no client
            object crosses a thread boundary (httplib2 thread-safety fix).
            """
            nonlocal region_forbidden

            for attempt in range(1, _SSL_RETRY_ATTEMPTS + 1):
                def _create(addr_name=address_name):
                    compute = self._get_addresses_client()
                    op = compute.addresses().insert(
                        project=self._project,
                        region=region,
                        body={
                            "name":        addr_name,
                            "addressType": "EXTERNAL",
                            "networkTier": "PREMIUM",
                        },
                    ).execute()
                    return compute, op

                try:
                    compute, op = await loop.run_in_executor(None, _create)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    exc_str = str(exc)

                    if _is_location_forbidden(exc_str):
                        logger.warning(
                            "gcp_eip: region %s is forbidden or not enabled for "
                            "this project — aborting region. "
                            "Remove it from GCP_EIP_REGIONS to suppress this warning. (%s)",
                            region, exc_str[:120],
                        )
                        region_forbidden = True
                        return address_name, None

                    if "LocationNotAvailableForResourceType" in exc_str:
                        logger.warning(
                            "gcp_eip: skipping %s — region does not support "
                            "compute static addresses "
                            "(LocationNotAvailableForResourceType). "
                            "Remove it from GCP_EIP_REGIONS to suppress this warning.",
                            region,
                        )
                        region_forbidden = True
                        return address_name, None

                    if "alreadyExists" in exc_str or "already exists" in exc_str:
                        logger.info(
                            "gcp_eip: address %s already exists (orphan) — "
                            "deleting and retrying",
                            address_name,
                        )
                        await self._delete_address(loop, region, address_name)
                        continue   # retry this slot

                    is_ssl_or_timeout = any(kw in exc_str for kw in (
                        "SSL", "ssl", "DECRYPTION_FAILED", "BAD_RECORD_MAC",
                        "CERTIFICATE_VERIFY_FAILED", "EOF occurred in violation",
                        "Connection reset", "BrokenPipeError",
                        "timed out", "TimeoutError", "read operation",
                    ))
                    if is_ssl_or_timeout and attempt < _SSL_RETRY_ATTEMPTS:
                        logger.debug(
                            "gcp_eip: transient error for %s (attempt %d/%d), "
                            "retrying in %.1fs: %s",
                            address_name, attempt, _SSL_RETRY_ATTEMPTS,
                            _SSL_RETRY_SLEEP, exc,
                        )
                        await asyncio.sleep(_SSL_RETRY_SLEEP)
                        continue

                    logger.warning("gcp_eip: alloc error for %s: %s", address_name, exc)
                    return address_name, None

                # Wait for the insert operation to complete
                op_name = op.get("name", "")
                try:
                    def _wait_op(c=compute, on=op_name):
                        import time as _t
                        for _ in range(30):
                            _t.sleep(1)
                            status = c.regionOperations().get(
                                project=self._project,
                                region=region,
                                operation=on,
                            ).execute()
                            if status.get("status") == "DONE":
                                return status
                        return None

                    await loop.run_in_executor(None, _wait_op)
                except Exception as exc:
                    logger.warning("gcp_eip: wait_op error for %s: %s", address_name, exc)
                    return address_name, None

                # Fetch the assigned IP address
                try:
                    def _get_addr(addr_name=address_name):
                        c = self._get_addresses_client()
                        return c.addresses().get(
                            project=self._project,
                            region=region,
                            address=addr_name,
                        ).execute()

                    addr_obj = await loop.run_in_executor(None, _get_addr)
                    return address_name, addr_obj.get("address")
                except Exception as exc:
                    logger.warning("gcp_eip: get_addr error for %s: %s", address_name, exc)
                    return address_name, None

            return address_name, None

        # ── Allocate the batch in parallel ────────────────────────────────────

        attempted_at = datetime.utcnow()
        names = [f"sto-hunt-{uuid.uuid4().hex[:12]}" for _ in range(_batch_size)]

        try:
            alloc_results = await asyncio.gather(*[_alloc_one(n) for n in names])
        except asyncio.CancelledError:
            logger.info(
                "gcp_eip: cancelled during batch in %s — "
                "_purge_stranded will clean up on next run",
                region,
            )
            raise

        # ── Region forbidden: clean up anything that was allocated ─────────────

        if region_forbidden:
            for name, ip in alloc_results:
                if ip:
                    await self._delete_address(loop, region, name)
            return []

        allocated = [(n, ip) for n, ip in alloc_results if ip]
        if not allocated:
            logger.info("gcp_eip: %s — no IPs allocated in batch", region)
            return []

        ips = [ip for _, ip in allocated]
        logger.info("gcp_eip: %s batch allocated %d IPs: %s", region, len(ips), ips)

        # ── Check for hits ────────────────────────────────────────────────────

        hit_ip   = next((ip for ip in ips if ip in self._targets), None)
        hit_name = next((n for n, ip in allocated if ip == hit_ip), None)

        # Release all non-hits concurrently (each call gets its own client)
        to_release = [(n, ip) for n, ip in allocated if ip != hit_ip]
        if to_release:
            await asyncio.gather(*[
                self._delete_address(loop, region, n)
                for n, _ in to_release
            ])
        released_at = datetime.utcnow()

        results: List[GCPHuntResult] = []
        for name, ip in allocated:
            is_hit = (ip == hit_ip)
            results.append(GCPHuntResult(
                region=region,
                ip_allocated=ip,
                address_name=name,
                hit=is_hit,
                attempted_at=attempted_at,
                released_at=None if is_hit else released_at,
            ))

        if hit_ip:
            logger.info(
                "gcp_eip: HIT! %s in %s — NOT releasing address %s. Verify manually.",
                hit_ip, region, hit_name,
            )
        else:
            logger.info(
                "gcp_eip: %s — no hit this batch (%d released)",
                region, len(to_release),
            )

        return results

    # ── Address deletion helper ───────────────────────────────────────────────

    async def _delete_address(self, loop, region: str, name: str) -> None:
        """Delete a static address. Creates its own client for thread safety."""
        def _do_delete(addr_name=name):
            compute = self._get_addresses_client()
            compute.addresses().delete(
                project=self._project,
                region=region,
                address=addr_name,
            ).execute()

        try:
            await loop.run_in_executor(None, _do_delete)
        except Exception as exc:
            # 404 is fine — already deleted or never fully created
            if "notFound" not in str(exc) and "404" not in str(exc):
                logger.warning("gcp_eip: failed to delete address %s: %s", name, exc)

    async def release_leaked(self, address_names: List[str], region: str) -> None:
        """Delete any static addresses that leaked due to a crash."""
        if not address_names:
            return
        loop = asyncio.get_running_loop()
        for name in address_names:
            await self._delete_address(loop, region, name)
            logger.info("gcp_eip: released leaked address %s in %s", name, region)