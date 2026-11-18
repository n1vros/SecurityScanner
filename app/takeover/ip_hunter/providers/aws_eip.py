"""
app/takeover/ip_hunter/providers/aws_eip.py

AWS Elastic IP takeover provider.

Allocates an EIP (no EC2 instance required), checks if the assigned public IP
matches any target from the database, then immediately releases it if no match.

Why EIP:
  AllocateAddress + ReleaseAddress — no VM, no compute cost.
  AWS charges ~$0.005/hr for unassociated EIPs but we release in <2s so the
  actual cost is negligible.  Default quota is 5 EIPs per region (soft limit).

Region detection:
  We group target IPs by AWS region using the CIDR index and only allocate in
  regions where we have matching targets.  No point hunting us-west-2 when all
  your targets resolved to us-east-1 IPs.

Config keys (.env):
  AWS_ACCESS_KEY_ID       str     required
  AWS_SECRET_ACCESS_KEY   str     required
  AWS_EIP_REGIONS         str     default "us-east-1,us-west-2,eu-west-1,ap-southeast-1"
                                  comma-separated list of regions to hunt
  AWS_EIP_SLEEP_MS        int     default 200  ms between allocations in same region
  AWS_EIP_DUP_HOLD        int     default 4    IPs gathered per cycle before releasing non-hits
"""

import asyncio
import re
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Set, Tuple

from app.core.config import settings
from app.core.logging import logger
from app.takeover.ip_hunter.cidr_index import CIDRIndex


@dataclass
class EIPHuntResult:
    region:               str
    ip_allocated:         str
    allocation_id:        str
    hit:                  bool
    matched_subdomain_ips: List[str]
    attempted_at:         datetime
    released_at:          Optional[datetime] = None
    error:                Optional[str]      = None


class AWSEIPHunter:
    """
    Hunts dangling AWS Elastic IPs by allocating EIPs in targeted regions
    and checking if the assigned IP matches known targets.

    Gather-and-release strategy:
      Allocate AWS_EIP_DUP_HOLD IPs one by one, then release all non-hits in a
      single pass.  Holding them simultaneously drains the pool before releasing,
      reducing the chance the same IP recycles back immediately.
    """

    def __init__(
        self,
        target_ips: Set[str],
        cidr_index: Optional[CIDRIndex] = None,
    ) -> None:
        self._targets    = target_ips
        self._cidr_index = cidr_index
        self._access_key = getattr(settings, "AWS_ACCESS_KEY_ID",     None)
        self._secret_key = getattr(settings, "AWS_SECRET_ACCESS_KEY", None)
        self._sleep_ms   = int(getattr(settings, "AWS_EIP_SLEEP_MS", 200))

        if not self._access_key or not self._secret_key:
            raise RuntimeError(
                "AWSEIPHunter: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY "
                "must be set in .env"
            )

    # ── region helpers ───────────────────────────────────────────────────────

    @staticmethod
    def default_regions() -> List[str]:
        raw = getattr(settings, "AWS_EIP_REGIONS",
                      "us-east-1,us-west-2,eu-west-1,ap-southeast-1")
        return [r.strip() for r in raw.split(",") if r.strip()]

    _AWS_REGION_PATTERN = re.compile(r'^[a-z]{2,}-[a-z]+-[0-9]+$')

    def target_regions(self) -> List[str]:
        """
        Return only regions that actually contain target IPs according to the
        CIDR index.  Falls back to default_regions() if index not available.
        Only returns strings that match a real AWS region format — filters out
        GLOBAL, global, or other non-region strings from GCP/Azure entries.
        """
        if not self._cidr_index or not self._targets:
            return self.default_regions()

        matched: Set[str] = set()
        for ip in self._targets:
            match = self._cidr_index.lookup(ip)
            if match and match.provider == "aws":
                region = match.region
                if self._AWS_REGION_PATTERN.match(region):
                    matched.add(region)
                else:
                    logger.debug(
                        "aws_eip: skipping non-standard region %r for IP %s",
                        region, ip,
                    )

        if not matched:
            logger.info(
                "aws_eip: no valid AWS regions found in CIDR index for targets "
                "— using default regions"
            )
            return self.default_regions()

        logger.info("aws_eip: target regions from CIDR index: %s", sorted(matched))
        return sorted(matched)

    # ── EC2 client ────────────────────────────────────────────────────────────

    def _make_ec2_client(self, region: str):
        import boto3
        return boto3.client(
            "ec2",
            region_name=region,
            aws_access_key_id=self._access_key,
            aws_secret_access_key=self._secret_key,
        )

    # ── Stranded EIP cleanup ──────────────────────────────────────────────────

    async def _purge_stranded(self, ec2, region: str) -> None:
        """
        Release any unassociated EIPs in this region that are NOT in the
        target pool.  Runs once at the start of each hunt() call to clean
        up addresses left behind by crashes or previous runs.
        """
        import botocore.exceptions

        loop = asyncio.get_running_loop()
        try:
            resp = await loop.run_in_executor(
                None, lambda: ec2.describe_addresses(
                    Filters=[{"Name": "domain", "Values": ["vpc"]}]
                )
            )
        except botocore.exceptions.ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AuthFailure", "UnauthorizedOperation"):
                logger.debug(
                    "aws_eip: _purge_stranded skipping %s — region not enabled "
                    "or permission denied (%s)",
                    region, code,
                )
            else:
                logger.warning(
                    "aws_eip: _purge_stranded describe failed in %s: %s", region, exc
                )
            return
        except Exception as exc:
            logger.warning("aws_eip: _purge_stranded describe failed in %s: %s", region, exc)
            return

        stranded = [
            addr for addr in resp.get("Addresses", [])
            if "AssociationId" not in addr
            and addr.get("PublicIp") not in self._targets
        ]

        if not stranded:
            logger.debug("aws_eip: no stranded EIPs found in %s", region)
            return

        logger.warning(
            "aws_eip: purging %d stranded EIP(s) in %s: %s",
            len(stranded), region,
            [a["PublicIp"] for a in stranded],
        )
        for addr in stranded:
            try:
                await loop.run_in_executor(
                    None,
                    lambda aid=addr["AllocationId"]: ec2.release_address(AllocationId=aid),
                )
                logger.info(
                    "aws_eip: purged stranded EIP %s (%s)",
                    addr["PublicIp"], addr["AllocationId"],
                )
            except botocore.exceptions.ClientError as exc:
                logger.warning("aws_eip: failed to purge %s: %s", addr["PublicIp"], exc)

    # ── Core hunt ─────────────────────────────────────────────────────────────

    async def hunt(
        self,
        region: str,
    ) -> List[EIPHuntResult]:
        """
        Hunt IPs in the given region in a single pass.

        Allocates up to AWS_EIP_DUP_HOLD IPs one by one, then releases all
        non-hits.  Holding them simultaneously drains the pool before releasing,
        reducing immediate IP recycling.  Call once per region.

        Early exits:
          - HIT found            → keep hit EIP, release non-hits, return immediately
          - AddressLimitExceeded → quota hit, release non-hits and stop
          - AuthFailure          → region not enabled, stop immediately
        """
        import botocore.exceptions

        BATCH_SIZE: int = int(getattr(settings, "AWS_EIP_DUP_HOLD", 20))

        results: List[EIPHuntResult]                  = []
        held:    List[Tuple[str, str, EIPHuntResult]] = []  # (allocation_id, ip, result)

        loop = asyncio.get_running_loop()
        ec2  = self._make_ec2_client(region)

        await self._purge_stranded(ec2, region)

        logger.info(
            "aws_eip: starting hunt in %s — batch=%d %d targets",
            region, BATCH_SIZE, len(self._targets),
        )

        async def _release_one(aid: str) -> None:
            try:
                await loop.run_in_executor(
                    None, lambda a=aid: ec2.release_address(AllocationId=a)
                )
            except Exception as exc:
                logger.warning("aws_eip: failed to release %s: %s", aid, exc)

        async def _release_no_hits() -> None:
            """Release all non-hit EIPs from held list."""
            to_release = [(aid, ip, res) for aid, ip, res in held if not res.hit]
            for aid, ip, res in to_release:
                await _release_one(aid)
                res.released_at = datetime.utcnow()
            held[:] = [(aid, ip, res) for aid, ip, res in held if res.hit]
            if to_release:
                logger.info(
                    "aws_eip: released %d non-hit EIP(s) in %s: %s",
                    len(to_release), region, [ip for _, ip, _ in to_release],
                )

        try:
            for i in range(BATCH_SIZE):
                allocation_id: Optional[str] = None
                attempted_at = datetime.utcnow()

                try:
                    response = await loop.run_in_executor(
                        None,
                        lambda: ec2.allocate_address(Domain="vpc"),
                    )

                    allocated_ip  = response["PublicIp"]
                    allocation_id = response["AllocationId"]

                    logger.info(
                        "aws_eip: [%d/%d] %s got %s",
                        i + 1, BATCH_SIZE, region, allocated_ip,
                    )

                    hit     = allocated_ip in self._targets
                    matched = [allocated_ip] if hit else []

                    result = EIPHuntResult(
                        region=region,
                        ip_allocated=allocated_ip,
                        allocation_id=allocation_id,
                        hit=hit,
                        matched_subdomain_ips=matched,
                        attempted_at=attempted_at,
                    )

                    held.append((allocation_id, allocated_ip, result))
                    results.append(result)

                    if hit:
                        logger.info(
                            "aws_eip: HIT! %s in %s — keeping (allocation_id=%s). "
                            "Verify manually.",
                            allocated_ip, region, allocation_id,
                        )
                        await _release_no_hits()
                        return results

                except botocore.exceptions.ClientError as exc:
                    code = exc.response["Error"]["Code"]

                    if code == "AddressLimitExceeded":
                        logger.info(
                            "aws_eip: quota reached in %s (%d/%d allocated) — "
                            "releasing non-hits and finishing region",
                            region, i, BATCH_SIZE,
                        )
                        await _release_no_hits()
                        break

                    if code == "AuthFailure":
                        logger.warning(
                            "aws_eip: skipping %s — region not enabled on this account "
                            "(AuthFailure). Enable it in the AWS console or remove it "
                            "from AWS_EIP_REGIONS to suppress this warning.",
                            region,
                        )
                        await _release_no_hits()
                        return results

                    if code == "UnauthorizedOperation":
                        logger.warning(
                            "aws_eip: skipping %s — UnauthorizedOperation. "
                            "IAM policy is missing ec2:AllocateAddress permission.",
                            region,
                        )
                        await _release_no_hits()
                        return results

                    logger.warning("aws_eip: error in %s: %s", region, exc)

                except Exception as exc:
                    logger.warning("aws_eip: unexpected error in %s: %s", region, exc)
                    if allocation_id:
                        await _release_one(allocation_id)

                if self._sleep_ms > 0:
                    await asyncio.sleep(self._sleep_ms / 1000)

        except asyncio.CancelledError:
            logger.info(
                "aws_eip: cancelled in %s — releasing %d held EIP(s) before exit",
                region, len(held),
            )
            await _release_no_hits()
            raise

        # Normal exit — release any remaining non-hits
        await _release_no_hits()

        hits = sum(1 for r in results if r.hit)
        logger.info(
            "aws_eip: finished %s — %d allocated, %d hits",
            region, len(results), hits,
        )
        return results

    # ── Leaked EIP cleanup (crash recovery) ──────────────────────────────────

    async def release_leaked(self, allocation_ids: List[str], region: str) -> None:
        """Release any EIPs that were allocated but never released (e.g. crash)."""
        import botocore.exceptions

        ec2  = self._make_ec2_client(region)
        loop = asyncio.get_running_loop()

        for aid in allocation_ids:
            try:
                await loop.run_in_executor(
                    None,
                    lambda a=aid: ec2.release_address(AllocationId=a),
                )
                logger.info("aws_eip: released leaked EIP %s in %s", aid, region)
            except botocore.exceptions.ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "InvalidAllocationID.NotFound":
                    logger.debug(
                        "aws_eip: leaked EIP %s not found (already released?)", aid
                    )
                else:
                    logger.warning(
                        "aws_eip: failed to release leaked EIP %s: %s", aid, exc
                    )
            except Exception as exc:
                logger.warning(
                    "aws_eip: unexpected error releasing %s: %s", aid, exc
                )