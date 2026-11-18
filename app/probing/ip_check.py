"""
app/probing/ip_check.py

Cloud IP liveness check via pure-Python async TCP connects.
No external binaries required -- uses asyncio.open_connection() only.

Ports checked (all concurrently, single timeout)
-------------------------------------------------
  22    SSH       -- Linux/Unix servers
  80    HTTP      -- Any web server
  443   HTTPS     -- Any TLS service
  3389  RDP       -- Windows instances
  8080  HTTP-alt  -- App servers, proxies
  8443  HTTPS-alt -- Alt TLS, Tomcat, etc.

Decision rule
-------------
  ANY port OPEN      -> verdict = TAKEN         (server is running)
  ANY port CLOSED    -> verdict = TAKEN         (host actively refused)
  only FILTERED      -> verdict = INCONCLUSIVE  (silent network path)
  only ERROR         -> verdict = INCONCLUSIVE  (probe failed)
  FILTERED + ERROR   -> verdict = INCONCLUSIVE  (still ambiguous)

TCP connect outcomes
--------------------
  SYN-ACK received  -> "open"     (something is listening)
  RST received      -> "closed"   (port actively refused -- OS is up, port not listening)
  No response       -> "filtered" (firewall drop or IP unallocated)
  OS error          -> "error"    (routing failure, ICMP unreachable, etc.)

Why FILTERED is not treated as free
-----------------------------------
An RST on any port means an operating system responded. An unallocated cloud
IP never sends RST -- the provider's network either drops the packet (filtered)
or returns ICMP unreachable (mapped to error here).
If we see RST on every checked port, there IS a machine there -- it's just
not listening on those specific ports. Still allocated.

Pure TCP silence is too ambiguous for hunting. It could be an unallocated cloud
IP, but it could also be a live host behind strict filtering. Generic port
probes only promote "taken" when a host clearly responds; stronger provider-
aware "free" decisions come from the dangling-IP analyzer or direct claim probes.

Config keys (.env)
------------------
  IP_CHECK_ENABLED      bool    default True
  IP_CHECK_PORTS        str     default "22,80,443,3389,8080,8443"
  IP_CHECK_TIMEOUT      float   default 5.0   (per-port connect timeout, seconds)
  IP_CHECK_CONCURRENCY  int     default 20    (max parallel IPs in backfill script)
"""

import asyncio
from datetime import datetime
from typing import Optional

from app.core.config import settings
from app.core.logging import logger
from app.probing.ip_verdicts import IPVerdict, IPVerdictStatus, aggregate_subdomain_ip_free


# ---- Config helpers ----------------------------------------------------------

_DEFAULT_PORTS = [22, 80, 443, 3389, 8080, 8443]


def _get_ports() -> list[int]:
    raw = getattr(settings, "IP_CHECK_PORTS", "")
    if raw:
        try:
            return [int(p.strip()) for p in str(raw).split(",") if p.strip()]
        except ValueError:
            pass
    return _DEFAULT_PORTS


def _get_timeout() -> float:
    return float(getattr(settings, "IP_CHECK_TIMEOUT", 5.0))


# ---- Single port probe -------------------------------------------------------

async def _tcp_probe(ip: str, port: int, timeout: float) -> str:
    """
    Attempt a TCP connect to ip:port.

    Returns one of:
      "open"     -- SYN-ACK received (something is listening)
      "closed"   -- RST received (OS responded, port not listening)
      "filtered" -- timeout (no response -- firewall drop or IP unallocated)
      "error"    -- OS-level error (ICMP unreachable, no route, etc.)
    """
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return "open"

    except asyncio.TimeoutError:
        return "filtered"

    except ConnectionRefusedError:
        return "closed"

    except OSError:
        # ICMP unreachable, no route -- treat as filtered
        return "filtered"

    except Exception as exc:
        logger.debug("ip_check: probe %s:%d unexpected error: %s", ip, port, exc)
        return "error"


# ---- Per-IP check ------------------------------------------------------------

async def check_ip(ip: str) -> Optional[bool]:
    verdict = await check_ip_verdict(ip)
    return verdict.ip_free


async def check_ip_verdict(ip: str) -> IPVerdict:
    """
    Check all configured ports on a single IP concurrently and return a shared
    per-IP verdict.
    """
    if not getattr(settings, "IP_CHECK_ENABLED", True):
        return IPVerdict(
            ip=ip,
            status=IPVerdictStatus.INCONCLUSIVE,
            source="ip_check",
            checked_at=datetime.utcnow(),
        )

    ports   = _get_ports()
    timeout = _get_timeout()

    results = await asyncio.gather(
        *[_tcp_probe(ip, port, timeout) for port in ports]
    )

    port_results = dict(zip(ports, results))
    logger.debug("ip_check: %s -> %s", ip, port_results)

    if "open" in results:
        open_ports = [p for p, r in port_results.items() if r == "open"]
        logger.debug(
            "ip_check: %s -> TAKEN (open ports: %s)",
            ip, ", ".join(str(p) for p in open_ports),
        )
        return IPVerdict(
            ip=ip,
            status=IPVerdictStatus.TAKEN,
            source="ip_check",
            checked_at=datetime.utcnow(),
            open_ports=open_ports,
        )

    if "closed" in results:
        closed_ports = [p for p, r in port_results.items() if r == "closed"]
        logger.debug(
            "ip_check: %s -> TAKEN (closed ports: %s)",
            ip, ", ".join(str(p) for p in closed_ports),
        )
        return IPVerdict(
            ip=ip,
            status=IPVerdictStatus.TAKEN,
            source="ip_check",
            checked_at=datetime.utcnow(),
        )

    if all(r == "error" for r in results):
        logger.debug("ip_check: %s -> inconclusive (all probes errored)", ip)
        return IPVerdict(
            ip=ip,
            status=IPVerdictStatus.INCONCLUSIVE,
            source="ip_check",
            checked_at=datetime.utcnow(),
        )

    logger.debug(
        "ip_check: %s -> inconclusive (no host response -- filtered=%d error=%d)",
        ip,
        sum(1 for r in results if r == "filtered"),
        sum(1 for r in results if r == "error"),
    )
    return IPVerdict(
        ip=ip,
        status=IPVerdictStatus.INCONCLUSIVE,
        source="ip_check",
        checked_at=datetime.utcnow(),
    )


# ---- Per-subdomain aggregation -----------------------------------------------

async def check_ips_for_subdomain(ips: list[str]) -> Optional[bool]:
    verdicts = await check_ips_for_subdomain_verdicts(ips)
    return aggregate_subdomain_ip_free(verdicts)


async def check_ips_for_subdomain_verdicts(ips: list[str]) -> list[IPVerdict]:
    """
    Run shared per-IP verdict checks across all IPv4s on a subdomain.
    """
    if not ips:
        return []
    return await asyncio.gather(*[check_ip_verdict(ip) for ip in ips])
