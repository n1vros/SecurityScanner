"""
app/takeover/ip_hunter/providers/azure_pip.py

Azure Public IP takeover provider.

Creates a standalone Public IP resource (no VM required), checks if the
assigned IP matches any target, then deletes it immediately if no match.

Sequential gather-and-release strategy:
  Allocate PIPs one at a time, accumulating each in `held`.
  Nothing is released until all `attempts` are complete (or a hit is found,
  or a quota/region error occurs).  Releasing all non-hits at once drains the
  pool together — preventing the same IP from recycling back immediately.

Config keys (.env):
  AZURE_TENANT_ID         str     required
  AZURE_CLIENT_ID         str     required
  AZURE_CLIENT_SECRET     str     required
  AZURE_SUBSCRIPTION_ID   str     required
  AZURE_RESOURCE_GROUP    str     required  (pre-existing RG for IP resources)
  AZURE_PIP_REGIONS       str     default "eastus,westus2,westeurope,southeastasia"
  AZURE_PIP_ATTEMPTS      int     default 20
  AZURE_PIP_SLEEP_MS      int     default 1000
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Set, Tuple
import uuid

from app.core.config import settings
from app.core.logging import logger
from app.takeover.ip_hunter.cidr_index import CIDRIndex

# Suppress Azure SDK's verbose HTTP request/response logging
logging.getLogger("azure").setLevel(logging.WARNING)


@dataclass
class AzurePIPHuntResult:
    region:        str
    ip_allocated:  str
    resource_name: str
    hit:           bool
    attempted_at:  datetime
    released_at:   Optional[datetime] = None
    error:         Optional[str]      = None


class AzurePublicIPHunter:
    """
    Hunts dangling Azure IPs by creating standalone Public IP resources
    and checking if the assigned IP matches known targets.
    """

    def __init__(
        self,
        target_ips: Set[str],
        cidr_index: Optional[CIDRIndex] = None,
    ) -> None:
        self._targets       = target_ips
        self._cidr_index    = cidr_index
        self._tenant_id     = getattr(settings, "AZURE_TENANT_ID",       None)
        self._client_id     = getattr(settings, "AZURE_CLIENT_ID",       None)
        self._client_secret = getattr(settings, "AZURE_CLIENT_SECRET",   None)
        self._subscription  = getattr(settings, "AZURE_SUBSCRIPTION_ID", None)
        self._rg            = getattr(settings, "AZURE_RESOURCE_GROUP",  None)
        self._sleep_ms      = int(getattr(settings, "AZURE_PIP_SLEEP_MS", 1000))

        if not all([self._tenant_id, self._client_id,
                    self._client_secret, self._subscription, self._rg]):
            raise RuntimeError(
                "AzurePublicIPHunter: AZURE_TENANT_ID, AZURE_CLIENT_ID, "
                "AZURE_CLIENT_SECRET, AZURE_SUBSCRIPTION_ID, and "
                "AZURE_RESOURCE_GROUP must all be set in .env"
            )

    # ── region helpers ───────────────────────────────────────────────────────

    @staticmethod
    def default_regions() -> List[str]:
        raw = getattr(
            settings, "AZURE_PIP_REGIONS",
            "eastus,westus2,westeurope,southeastasia",
        )
        return [r.strip() for r in raw.split(",") if r.strip()]

    def target_regions(self) -> List[str]:
        """
        Return Azure regions that contain target IPs per CIDR index.
        Skips empty/global region strings from ServiceTags.
        """
        if not self._cidr_index or not self._targets:
            return self.default_regions()

        matched: Set[str] = set()
        for ip in self._targets:
            match = self._cidr_index.lookup(ip)
            if match and match.provider == "azure":
                region = match.region.strip().lower()
                if region and region != "global" and "." not in region:
                    matched.add(region)

        if not matched:
            logger.info("azure_pip: no CIDR matches for targets — using default regions")
            return self.default_regions()

        logger.info("azure_pip: target regions from CIDR index: %s", sorted(matched))
        return sorted(matched)

    # ── Azure client ─────────────────────────────────────────────────────────

    def _get_network_client(self):
        from azure.identity import ClientSecretCredential
        from azure.mgmt.network import NetworkManagementClient

        credential = ClientSecretCredential(
            tenant_id=self._tenant_id,
            client_id=self._client_id,
            client_secret=self._client_secret,
        )
        return NetworkManagementClient(credential, self._subscription)

    # ── Stranded resource cleanup ─────────────────────────────────────────────

    async def _purge_stranded(self, client, loop, region: str) -> None:
        """
        Delete any unassociated Public IP resources in this resource group
        whose assigned IP is NOT in the target pool.  Runs at the start of
        each hunt() to clean up addresses left by crashes or previous runs.
        Only touches resources whose name starts with 'sto-hunt-'.
        """
        try:
            pips = await loop.run_in_executor(
                None,
                lambda: list(client.public_ip_addresses.list(self._rg)),
            )
        except Exception as exc:
            logger.warning("azure_pip: _purge_stranded list failed in %s: %s", region, exc)
            return

        stranded = [
            pip for pip in pips
            if pip.location.lower().replace(" ", "") == region.lower().replace(" ", "")
            and pip.name.startswith("sto-hunt-")
            and (pip.ip_configuration is None)
            and (pip.ip_address not in self._targets if pip.ip_address else True)
        ]

        if not stranded:
            logger.debug("azure_pip: no stranded PIPs found in %s", region)
            return

        logger.warning(
            "azure_pip: purging %d stranded PIP(s) in %s: %s",
            len(stranded), region,
            [p.ip_address or p.name for p in stranded],
        )
        for pip in stranded:
            try:
                await loop.run_in_executor(
                    None,
                    lambda n=pip.name: client.public_ip_addresses
                        .begin_delete(self._rg, n).result(),
                )
                logger.info("azure_pip: purged stranded PIP %s (%s)", pip.ip_address, pip.name)
            except Exception as exc:
                logger.warning("azure_pip: failed to purge %s: %s", pip.name, exc)

    # ── Sequential gather-and-release hunt ────────────────────────────────────

    async def hunt(
        self,
        region:   str,
        attempts: int = 20,
    ) -> List[AzurePIPHuntResult]:
        """
        Allocate PIPs one at a time up to `attempts`, check each against the
        target list, keep any hit, release all non-hits at the end.
        """
        loop   = asyncio.get_running_loop()
        client = await loop.run_in_executor(None, self._get_network_client)

        results: List[AzurePIPHuntResult]              = []
        held:    List[Tuple[str, str, AzurePIPHuntResult]] = []  # (resource_name, ip, result)

        await self._purge_stranded(client, loop, region)

        logger.info(
            "azure_pip: starting hunt in %s — %d attempts, %d targets",
            region, attempts, len(self._targets),
        )

        async def _delete_pip(name: str) -> None:
            try:
                await loop.run_in_executor(
                    None,
                    lambda n=name: client.public_ip_addresses
                        .begin_delete(self._rg, n).result(),
                )
            except Exception as exc:
                logger.warning("azure_pip: failed to delete PIP %s: %s", name, exc)

        async def _release_no_hits() -> None:
            """Delete all non-hit PIPs from held list concurrently."""
            to_release = [(n, ip, res) for n, ip, res in held if not res.hit]
            if not to_release:
                return
            await asyncio.gather(
                *[_delete_pip(n) for n, _, _ in to_release],
                return_exceptions=True,
            )
            released_at = datetime.utcnow()
            for _, _, res in to_release:
                res.released_at = released_at
            held[:] = [(n, ip, res) for n, ip, res in held if res.hit]
            logger.info(
                "azure_pip: released %d non-hit PIP(s) in %s: %s",
                len(to_release), region, [ip for _, ip, _ in to_release],
            )

        # Track the in-flight PIP so CancelledError can delete it.
        current_resource: Optional[str] = None
        current_is_hit:   bool          = False

        try:
            for i in range(attempts):
                current_resource = None
                current_is_hit   = False
                attempted_at     = datetime.utcnow()
                resource_name    = f"sto-hunt-{uuid.uuid4().hex[:12]}"
                allocated_ip:    Optional[str] = None

                try:
                    poller = await loop.run_in_executor(
                        None,
                        lambda n=resource_name: client.public_ip_addresses.begin_create_or_update(
                            self._rg,
                            n,
                            {
                                "location": region,
                                "sku": {"name": "Standard"},
                                "public_ip_allocation_method": "Static",
                                "public_ip_address_version": "IPv4",
                            },
                        ),
                    )
                    pip = await loop.run_in_executor(None, poller.result)
                    allocated_ip = pip.ip_address

                    # PIP is now live — track it for CancelledError cleanup
                    current_resource = resource_name

                    if not allocated_ip:
                        logger.warning(
                            "azure_pip: [%d/%d] no IP assigned in %s", i + 1, attempts, region
                        )
                        await loop.run_in_executor(
                            None,
                            lambda n=resource_name: client.public_ip_addresses
                                .begin_delete(self._rg, n).result(),
                        )
                        current_resource = None
                        continue

                    logger.info(
                        "azure_pip: [%d/%d] %s got %s",
                        i + 1, attempts, region, allocated_ip,
                    )

                    hit = allocated_ip in self._targets
                    result = AzurePIPHuntResult(
                        region=region,
                        ip_allocated=allocated_ip,
                        resource_name=resource_name,
                        hit=hit,
                        attempted_at=attempted_at,
                    )

                    held.append((resource_name, allocated_ip, result))
                    results.append(result)

                    if hit:
                        logger.info(
                            "azure_pip: HIT! %s in %s — NOT deleting resource %s. "
                            "Verify manually.",
                            allocated_ip, region, resource_name,
                        )
                        current_is_hit   = True
                        current_resource = None  # intentionally kept — do not clean up
                        await _release_no_hits()
                        return results

                except asyncio.CancelledError:
                    raise

                except Exception as exc:
                    exc_str = str(exc)
                    if "LocationNotAvailableForResourceType" in exc_str:
                        logger.warning(
                            "azure_pip: skipping %s — region does not support "
                            "Microsoft.Network/publicIPAddresses "
                            "(LocationNotAvailableForResourceType). "
                            "Remove it from AZURE_PIP_REGIONS to suppress this warning.",
                            region,
                        )
                        await _release_no_hits()
                        return results

                    logger.warning(
                        "azure_pip: [%d/%d] error in %s: %s",
                        i + 1, attempts, region, exc,
                    )
                    if current_resource and not current_is_hit:
                        try:
                            await loop.run_in_executor(
                                None,
                                lambda n=current_resource: client.public_ip_addresses
                                    .begin_delete(self._rg, n).result(),
                            )
                        except Exception:
                            pass
                        current_resource = None

                if self._sleep_ms > 0:
                    await asyncio.sleep(self._sleep_ms / 1000)

        except asyncio.CancelledError:
            if current_resource and not current_is_hit:
                logger.info(
                    "azure_pip: hunt cancelled in %s — cleaning up in-flight PIP %s",
                    region, current_resource,
                )
                try:
                    await loop.run_in_executor(
                        None,
                        lambda n=current_resource: client.public_ip_addresses
                            .begin_delete(self._rg, n).result(),
                    )
                    logger.info(
                        "azure_pip: cancelled — cleaned up in-flight PIP %s in %s",
                        current_resource, region,
                    )
                except Exception as cleanup_exc:
                    logger.warning(
                        "azure_pip: cleanup of in-flight PIP %s on cancel failed: %s "
                        "— _purge_stranded will handle it on next run",
                        current_resource, cleanup_exc,
                    )
            await _release_no_hits()
            raise

        # Normal exit — release all remaining non-hits together
        await _release_no_hits()

        hits = sum(1 for r in results if r.hit)
        logger.info(
            "azure_pip: finished hunt in %s — %d/%d attempts, %d hits",
            region, len(results), attempts, hits,
        )
        return results

    # ── Leaked resource cleanup (crash recovery) ──────────────────────────────

    async def release_leaked(self, resource_names: List[str]) -> None:
        """Delete any Public IP resources that leaked due to a crash."""
        if not resource_names:
            return
        loop = asyncio.get_running_loop()
        try:
            client = await loop.run_in_executor(None, self._get_network_client)
        except Exception as exc:
            logger.warning("azure_pip: cannot create client for cleanup: %s", exc)
            return

        for name in resource_names:
            try:
                await loop.run_in_executor(
                    None,
                    lambda n=name: client.public_ip_addresses
                        .begin_delete(self._rg, n).result(),
                )
                logger.info("azure_pip: released leaked resource %s", name)
            except Exception as exc:
                logger.warning(
                    "azure_pip: failed to release leaked resource %s: %s", name, exc
                )