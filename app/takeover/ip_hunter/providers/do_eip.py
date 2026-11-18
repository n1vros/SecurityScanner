"""
app/takeover/ip_hunter/providers/do_eip.py

DigitalOcean Reserved IP takeover provider.

Single-batch-per-region design (mirrors GCP hunter):
  hunt() allocates exactly DO_EIP_BATCH_SIZE IPs in parallel, checks every
  assigned IP against the target pool, releases all non-hits concurrently,
  and returns. The looping and sleeping between cycles is handled externally
  by hunter.py's per-provider loop.

Config keys (.env):
  DO_API_TOKEN          str     required
  DO_EIP_REGIONS        str     default "nyc1,nyc3,sfo3,ams3,sgp1,lon1,fra1,blr1,tor1,syd1"
  DO_EIP_BATCH_SIZE     int     default 3    IPs allocated per region per cycle
  DO_EIP_SLEEP_MS       int     default 500  delay between individual allocations in a batch
"""

import asyncio
import re
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Set, Tuple

import aiohttp

from app.core.config import settings
from app.core.logging import logger
from app.takeover.ip_hunter.cidr_index import CIDRIndex


_DO_API = "https://api.digitalocean.com/v2"

# DigitalOcean datacenter slugs: 2-5 lowercase letters + exactly 1-2 digits
_DO_SLUG_RE = re.compile(r'^[a-z]{2,5}\d{1,2}$')


@dataclass
class DOHuntResult:
    region:         str
    ip_allocated:   str
    reserved_ip_id: str
    hit:            bool
    attempted_at:   datetime
    released_at:    Optional[datetime] = None
    error:          Optional[str]      = None


class DOReservedIPHunter:
    """
    Hunts dangling DigitalOcean IPs by allocating Reserved IPs and checking
    if the assigned IP matches known targets.
    """

    def __init__(
        self,
        target_ips: Set[str],
        cidr_index: Optional[CIDRIndex] = None,
    ) -> None:
        self._targets    = target_ips
        self._cidr_index = cidr_index
        self._token      = getattr(settings, "DO_API_TOKEN", None)
        self._sleep_ms   = int(getattr(settings, "DO_EIP_SLEEP_MS", 500))

        if not self._token:
            raise RuntimeError(
                "DOReservedIPHunter: DO_API_TOKEN must be set in .env"
            )

    # ── region helpers ───────────────────────────────────────────────────────

    @staticmethod
    def default_regions() -> List[str]:
        raw = getattr(
            settings, "DO_EIP_REGIONS",
            "nyc1,nyc3,sfo3,ams3,sgp1,lon1,fra1,blr1,tor1,syd1",
        )
        return [r.strip() for r in raw.split(",") if r.strip()]

    def target_regions(self) -> List[str]:
        """
        Return DO datacenter slugs that contain target IPs per CIDR index.
        Falls back to default_regions() if no valid slug matches are found.
        """
        if not self._cidr_index or not self._targets:
            return self.default_regions()

        matched: Set[str] = set()
        for ip in self._targets:
            match = self._cidr_index.lookup(ip)
            if match and match.provider == "digitalocean" and match.region:
                region = match.region.lower().strip()
                if _DO_SLUG_RE.match(region):
                    matched.add(region)

        if not matched:
            logger.info("do_eip: no DC-slug CIDR matches for targets — using default regions")
            return self.default_regions()

        logger.info("do_eip: target regions from CIDR index: %s", sorted(matched))
        return sorted(matched)

    # ── stranded cleanup ─────────────────────────────────────────────────────

    async def _purge_stranded(self, session: aiohttp.ClientSession, region: str) -> None:
        """
        Delete any unassigned Reserved IPs in this region whose IP is NOT
        in the target pool. Runs at the start of each hunt() call.
        """
        stranded = []
        page = 1
        while True:
            try:
                async with session.get(
                    f"{_DO_API}/reserved_ips",
                    params={"per_page": 100, "page": page},
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status != 200:
                        logger.warning("do_eip: _purge_stranded list failed: %s", resp.status)
                        return
                    data = await resp.json()
            except Exception as exc:
                logger.warning("do_eip: _purge_stranded list error: %s", exc)
                return

            for rip in data.get("reserved_ips", []):
                rip_region = (rip.get("region") or {}).get("slug", "")
                ip         = rip.get("ip")
                assigned   = rip.get("droplet") is not None
                if rip_region == region and not assigned and ip not in self._targets:
                    stranded.append(ip)

            links = data.get("links", {})
            if not links.get("pages", {}).get("next"):
                break
            page += 1

        if not stranded:
            logger.debug("do_eip: no stranded Reserved IPs found in %s", region)
            return

        logger.warning(
            "do_eip: purging %d stranded Reserved IP(s) in %s: %s",
            len(stranded), region, stranded,
        )
        for ip in stranded:
            try:
                async with session.delete(
                    f"{_DO_API}/reserved_ips/{ip}",
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status in (204, 404):
                        logger.info("do_eip: purged stranded Reserved IP %s", ip)
                    else:
                        logger.warning("do_eip: failed to purge %s: %s", ip, resp.status)
            except Exception as exc:
                logger.warning("do_eip: error purging %s: %s", ip, exc)

    # ── core hunt ────────────────────────────────────────────────────────────

    async def hunt(self, region: str) -> List[DOHuntResult]:
        """
        Allocate one batch of DO_EIP_BATCH_SIZE IPs sequentially, check each
        against the target pool, release all non-hits, and return.
        No outer attempts loop, no dup tracking.
        """
        batch_size = int(getattr(settings, "DO_EIP_BATCH_SIZE", 3))

        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type":  "application/json",
        }

        async with aiohttp.ClientSession(headers=headers) as session:
            await self._purge_stranded(session, region)

            logger.info(
                "do_eip: starting hunt in %s — batch=%d, %d targets",
                region, batch_size, len(self._targets),
            )

            allocated: List[Tuple[str, DOHuntResult]] = []  # (ip, result)
            attempted_at = datetime.utcnow()

            # ── allocate batch sequentially ───────────────────────────────────
            for i in range(batch_size):
                try:
                    async with session.post(
                        f"{_DO_API}/reserved_ips",
                        json={"region": region},
                        timeout=aiohttp.ClientTimeout(total=15),
                    ) as resp:
                        if resp.status == 429:
                            retry = int(resp.headers.get("Retry-After", 10))
                            logger.warning(
                                "do_eip: rate limited in %s — sleeping %ds",
                                region, retry,
                            )
                            await asyncio.sleep(retry)
                            continue

                        if resp.status not in (200, 201, 202):
                            logger.warning(
                                "do_eip: allocate failed in %s: %s %s",
                                region, resp.status, (await resp.text())[:120],
                            )
                            continue

                        data = await resp.json()
                        ip   = data.get("reserved_ip", {}).get("ip")

                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.warning("do_eip: alloc error in %s: %s", region, exc)
                    continue

                if not ip:
                    continue

                logger.info("do_eip: [%d/%d] %s got %s", i + 1, batch_size, region, ip)

                result = DOHuntResult(
                    region=region,
                    ip_allocated=ip,
                    reserved_ip_id=ip,
                    hit=ip in self._targets,
                    attempted_at=attempted_at,
                )
                allocated.append((ip, result))

                if self._sleep_ms > 0 and i < batch_size - 1:
                    await asyncio.sleep(self._sleep_ms / 1000)

            if not allocated:
                logger.info("do_eip: %s — no IPs allocated in batch", region)
                return []

            # ── check for hit ─────────────────────────────────────────────────
            hit_pair = next(((ip, r) for ip, r in allocated if r.hit), None)

            # ── release all non-hits concurrently ─────────────────────────────
            to_release = [(ip, r) for ip, r in allocated if not r.hit]
            if to_release:
                async def _release(ip: str) -> None:
                    try:
                        async with session.delete(
                            f"{_DO_API}/reserved_ips/{ip}",
                            timeout=aiohttp.ClientTimeout(total=10),
                        ) as resp:
                            if resp.status not in (204, 404):
                                logger.warning(
                                    "do_eip: failed to release %s: %s", ip, resp.status
                                )
                    except Exception as exc:
                        logger.warning("do_eip: release error for %s: %s", ip, exc)

                await asyncio.gather(*[_release(ip) for ip, _ in to_release])
                released_at = datetime.utcnow()
                for _, r in to_release:
                    r.released_at = released_at
                logger.info(
                    "do_eip: released %d non-hit IP(s) in %s: %s",
                    len(to_release), region, [ip for ip, _ in to_release],
                )

            if hit_pair:
                hit_ip, _ = hit_pair
                logger.info(
                    "do_eip: HIT! %s in %s — NOT releasing. Verify manually.",
                    hit_ip, region,
                )
            else:
                logger.info(
                    "do_eip: %s — no hit this batch (%d released)",
                    region, len(to_release),
                )

            results = [r for _, r in allocated]
            hits    = sum(1 for r in results if r.hit)
            logger.info(
                "do_eip: finished hunt in %s — %d allocated, %d hits",
                region, len(results), hits,
            )
            return results

    async def release_leaked(self, ips: List[str]) -> None:
        """Release any Reserved IPs that leaked due to a crash."""
        if not ips:
            return
        headers = {"Authorization": f"Bearer {self._token}"}
        async with aiohttp.ClientSession(headers=headers) as session:
            for ip in ips:
                try:
                    async with session.delete(
                        f"{_DO_API}/reserved_ips/{ip}",
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as resp:
                        if resp.status in (204, 404):
                            logger.info("do_eip: released leaked IP %s", ip)
                        else:
                            logger.warning(
                                "do_eip: failed to release leaked IP %s: %s", ip, resp.status
                            )
                except Exception as exc:
                    logger.warning("do_eip: error releasing leaked IP %s: %s", ip, exc)