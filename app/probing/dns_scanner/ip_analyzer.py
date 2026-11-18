"""
app/probing/dns_scanner/ip_analyzer.py

DanglingIPAnalyzer — full dangling IP detection pipeline.

Supports both IPv4 and IPv6. IPv6 analysis uses the same stages but with
adjustments:
  - TCP port scan targets IPv6 address
  - PTR lookup via reverse IPv6 (ip6.arpa)
  - HTTP/HTTPS probe via http://[::1]/ bracket notation
  - TLS cert check works identically (ssl.create_default_context supports IPv6)
  - AWS/Azure direct claim probes only for IPv4
  - No IPv6 score penalty (removed — IPv6 findings fire at the same threshold)

ASN fallback:
  When the CIDR index has no match for an IP (can happen for newer cloud
  prefixes not yet in the cached range files), the analyzer falls back to a
  Team Cymru DNS TXT ASN lookup. If the ASN maps to a known cloud provider,
  analysis proceeds with a synthetic provider config.

  The ASN -15 confidence penalty has been removed. asn_lookup_used=True is
  still passed to score_finding() for call-site compatibility but has no
  effect on scoring. ASN-identified providers score identically to
  CIDR-identified ones.

Finding types produced:
  "dangling"       — IPv4: no running server, appears released to cloud pool
  "ipv6_dangling"  — IPv6: same logic, different family
  "foreign_cert"   — Port 443 open, TLS cert belongs to a DIFFERENT company
  "cname_dangling" — IP reached via CNAME chain is dangling (set by caller)
  "mx_dangling"    — IP reached via MX record is dangling (set by caller)
"""

import asyncio
import ipaddress
from typing import Dict, List, Optional, Tuple

import httpx

from app.core.config import settings
from app.core.logging import logger
from app.probing.dns_scanner.models import DanglingIPFinding
from app.probing.dns_scanner.ip_providers import get_provider_cfg, VULNERABLE_IP_PROVIDERS
from app.probing.dns_scanner.ip_indicators import (
    analyze_ptr,
    analyze_headers,
    get_tls_cert_info,
    is_foreign_cert,
    aws_direct_claim_probe,
    azure_direct_claim_probe,
    resolve_asn_cymru,
    get_provider_from_asn,
    score_finding,
)

try:
    from app.takeover.ip_hunter.cidr_index import CIDRIndex, CIDRMatch
except ImportError:
    CIDRIndex = None
    CIDRMatch = None


# ─────────────────────────────────────────────────────────────────────────────
# Providers claimable via public API (used when CIDR gives no config)
# ─────────────────────────────────────────────────────────────────────────────

_CLAIMABLE_PROVIDERS = frozenset([
    "aws", "azure", "digitalocean", "gcp", "linode", "vultr", "hetzner",
    "scaleway", "oracle", "fly", "equinix_metal", "upcloud",
])


# ─────────────────────────────────────────────────────────────────────────────
# TCP port scan (IPv4 + IPv6)
# ─────────────────────────────────────────────────────────────────────────────

async def _tcp_probe_ports(
    ip:          str,
    ports:       List[int],
    timeout:     float,
    concurrency: int,
) -> List[int]:
    """Async TCP connect scan for IPv4 or IPv6. Returns list of open ports."""
    sem        = asyncio.Semaphore(concurrency)
    open_ports: List[int] = []
    lock       = asyncio.Lock()

    async def _check(port: int) -> None:
        async with sem:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=timeout
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                async with lock:
                    open_ports.append(port)
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                pass
            except Exception:
                pass

    await asyncio.gather(*[_check(p) for p in ports])
    return sorted(open_ports)


# ─────────────────────────────────────────────────────────────────────────────
# HTTP probe (IPv4 + IPv6)
# ─────────────────────────────────────────────────────────────────────────────

def _http_url(ip: str, scheme: str) -> str:
    """Build a URL for an IP, using bracket notation for IPv6."""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 6:
            return f"{scheme}://[{ip}]/"
    except ValueError:
        pass
    return f"{scheme}://{ip}/"


async def _http_probe(
    ip:      str,
    timeout: float,
) -> Tuple[Optional[int], Optional[int], Dict[str, str]]:
    """HEAD request to http and https. IPv6-aware URL construction."""
    merged: Dict[str, str] = {}

    async def _probe(url: str) -> Tuple[Optional[int], Dict[str, str]]:
        try:
            async with httpx.AsyncClient(
                verify=False, follow_redirects=False, timeout=timeout
            ) as c:
                resp = await c.head(url)
                return resp.status_code, dict(resp.headers)
        except Exception:
            return None, {}

    http_s,  http_h  = await _probe(_http_url(ip, "http"))
    https_s, https_h = await _probe(_http_url(ip, "https"))
    merged.update(http_h)
    merged.update(https_h)
    return http_s, https_s, merged


# ─────────────────────────────────────────────────────────────────────────────
# PTR lookup (IPv4 + IPv6)
# ─────────────────────────────────────────────────────────────────────────────

async def _ptr_lookup(ip: str) -> Optional[str]:
    """Reverse-DNS PTR lookup. Works for both IPv4 and IPv6."""
    import socket
    try:
        loop = asyncio.get_running_loop()
        hostname, *_ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        return hostname
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# DanglingIPAnalyzer
# ─────────────────────────────────────────────────────────────────────────────

class DanglingIPAnalyzer:
    """
    Full dangling IP analysis pipeline for a single IP address (IPv4 or IPv6).

    Called by DNSScanner.scan_subdomain():
      - For each direct A record IP (non-CNAME)  → finding_type="dangling"
      - For each direct AAAA record IP           → finding_type="ipv6_dangling"
      - For CNAME terminal IPs                   → finding_type="cname_dangling"
      - For MX target IPs                        → finding_type="mx_dangling"

    When the CIDR index has no entry for an IP, falls back to Team Cymru ASN
    lookup (requires IP_HUNTER_ASN_LOOKUP=True in .env).
    """

    def __init__(self, cidr_index=None) -> None:
        self._cidr_index  = cidr_index
        self._ports       = self._parse_ports()
        self._timeout     = float(getattr(settings, "DANGLING_IP_TIMEOUT", 5.0))
        self._http_probe  = bool(getattr(settings, "DANGLING_IP_HTTP_PROBE", True))
        self._ptr_check   = bool(getattr(settings, "DANGLING_IP_PTR_CHECK", True))
        self._tls_check   = bool(getattr(settings, "DANGLING_IP_TLS_CHECK", True))
        self._cloud_claim = bool(getattr(settings, "DANGLING_IP_CLOUD_CLAIM_CHECK", False))
        self._concurrency = int(getattr(settings, "DANGLING_IP_CONCURRENCY", 30))

    def _parse_ports(self) -> List[int]:
        raw = getattr(settings, "DANGLING_IP_PORTS", "22,80,443,3389,8080,8443")
        try:
            return [int(p.strip()) for p in str(raw).split(",") if p.strip()]
        except ValueError:
            return [22, 80, 443, 3389, 8080, 8443]

    def set_cidr_index(self, cidr_index) -> None:
        self._cidr_index = cidr_index

    async def analyze(
        self,
        ip:             str,
        subdomain_name: str,
        scope_domain:   str = "",
        program_name:   str = "",
        platform:       str = "",
        finding_type:   str = "dangling",
        cname_chain:    Optional[List[str]] = None,
        cname_terminal: Optional[str]       = None,
    ) -> Optional[DanglingIPFinding]:
        """
        Full dangling IP analysis for a single IP (IPv4 or IPv6).

        Returns DanglingIPFinding if the IP belongs to a claimable cloud provider
        (via CIDR index or ASN fallback), None otherwise.

        For IPv6:
          - finding_type is overridden to "ipv6_dangling" if caller passes "dangling"
          - AWS and Azure direct claim probes are skipped (PIPs/EIPs are IPv4-only)
          - No score penalty (IPv6 fires at the same threshold as IPv4)

        ASN fallback:
          - asn_lookup_used=True is passed to score_finding() for compat; no penalty
          - Provider identity is correct; scores identically to CIDR-identified IPs
        """
        if not getattr(settings, "DANGLING_IP_CHECK_ENABLED", True):
            return None

        # Determine IP version
        try:
            addr    = ipaddress.ip_address(ip)
            version = addr.version
        except ValueError:
            logger.debug("dangling_ip: invalid IP address %r — skipping", ip)
            return None

        # For IPv6, override finding_type if caller passed "dangling"
        if version == 6 and finding_type == "dangling":
            finding_type = "ipv6_dangling"

        # ── Stage A: CIDR index lookup → ASN fallback ───────────────────────
        cidr_match   = self._cidr_index.lookup(ip) if self._cidr_index else None
        asn          = None
        asn_lookup_used = False

        if cidr_match is None:
            # Fallback: Team Cymru ASN lookup
            asn = await resolve_asn_cymru(ip)
            provider_key_from_asn = get_provider_from_asn(asn)
            if provider_key_from_asn is None:
                logger.debug(
                    "dangling_ip: %s — CIDR miss, ASN=%s, no provider match — skipping",
                    ip, asn,
                )
                return None
            # Build a synthetic CIDRMatch-like namespace for the rest of the pipeline
            provider_key    = provider_key_from_asn
            asn_lookup_used = True
            logger.info(
                "dangling_ip: %s — CIDR miss, matched via ASN %s → provider=%s",
                ip, asn, provider_key,
            )
            region = f"asn:{asn}"
            cidr   = f"ASN{asn}"
        else:
            provider_key = cidr_match.provider
            region       = cidr_match.region
            cidr         = cidr_match.cidr

        provider_cfg     = get_provider_cfg(provider_key)
        provider_display = provider_cfg.get("name", provider_key.upper())
        severity         = provider_cfg.get("severity", "medium")
        claim_cmd_tmpl   = provider_cfg.get("claim_cmd", "")
        can_claim_specific = bool(provider_cfg.get("can_claim_specific_ip", False))
        claim_possible   = provider_key in _CLAIMABLE_PROVIDERS
        anchor_ip        = bool(provider_cfg.get("indicators", {}).get("anchor_ip_behavior", False))

        indicators: List[str] = []
        open_ports: List[int] = []

        # Note ASN fallback in indicators
        if asn_lookup_used:
            indicators.append(
                f"Provider identified via ASN {asn} (Team Cymru lookup) — "
                f"CIDR index had no entry for this IP"
            )

        # ── Stage B: TCP port scan ──────────────────────────────────────────
        open_ports = await _tcp_probe_ports(ip, self._ports, self._timeout, self._concurrency)

        if open_ports:
            indicators.append(
                f"Open ports: {', '.join(str(p) for p in open_ports)} "
                f"— server is running, IP is ALLOCATED"
            )
            logger.debug("dangling_ip: %s has open ports %s", ip, open_ports)

            # Even with open ports, check for foreign TLS cert
            if self._tls_check and 443 in open_ports:
                tls_cn, tls_sans = await get_tls_cert_info(ip, self._timeout)
                if (tls_cn or tls_sans) and is_foreign_cert(tls_cn, tls_sans, scope_domain):
                    indicators.append(
                        f"⚠️ TLS cert belongs to a FOREIGN domain: "
                        f"CN={tls_cn}, SANs={tls_sans[:5]}"
                    )
                    logger.info(
                        "dangling_ip: %s port 443 open with FOREIGN TLS cert "
                        "(CN=%s) — IP taken by another company",
                        ip, tls_cn,
                    )
                    return self._build(
                        ip=ip, version=version, subdomain_name=subdomain_name,
                        provider_key=provider_key, provider_display=provider_display,
                        region=region, cidr=cidr, severity=severity,
                        claim_possible=False, can_claim_specific=False,
                        claim_cmd_tmpl="", finding_type="foreign_cert",
                        confirmed_free=False, confidence=0,
                        indicators=indicators, open_ports=open_ports,
                        tls_cn=tls_cn, tls_sans=tls_sans, foreign_tls_cert=True,
                        asn=asn, asn_lookup_used=asn_lookup_used,
                        scope_domain=scope_domain, program_name=program_name, platform=platform,
                        cname_chain=cname_chain, cname_terminal=cname_terminal,
                    )

            # Open ports, no foreign cert — allocated to unknown owner
            return self._build(
                ip=ip, version=version, subdomain_name=subdomain_name,
                provider_key=provider_key, provider_display=provider_display,
                region=region, cidr=cidr, severity=severity,
                claim_possible=False, can_claim_specific=False,
                claim_cmd_tmpl=claim_cmd_tmpl, finding_type=finding_type,
                confirmed_free=False, confidence=0,
                indicators=indicators, open_ports=open_ports,
                asn=asn, asn_lookup_used=asn_lookup_used,
                scope_domain=scope_domain, program_name=program_name, platform=platform,
                cname_chain=cname_chain, cname_terminal=cname_terminal,
            )

        # No open ports — full indicator analysis
        indicators.append(
            f"No open ports on {self._ports} — candidate for dangling analysis"
        )

        ptr_hostname:  Optional[str]  = None
        http_status:   Optional[int]  = None
        https_status:  Optional[int]  = None
        resp_headers:  Dict[str, str] = {}
        tls_cn:        Optional[str]  = None
        tls_sans:      List[str]      = []
        cloud_claim_confirmed         = False

        # ── Stage C: Provider-specific indicators ───────────────────────────

        if anchor_ip:
            indicators.append(
                f"{provider_display}: anchor IP behavior — "
                f"ICMP/filtered ports do NOT confirm IP is unallocated"
            )

        if self._ptr_check:
            ptr_hostname = await _ptr_lookup(ip)
            ptr_ev = analyze_ptr(ip, ptr_hostname, provider_cfg)
            indicators.extend(ptr_ev["indicators"])

        if self._http_probe:
            http_status, https_status, resp_headers = await _http_probe(ip, self._timeout)
            if http_status  is not None: indicators.append(f"HTTP  response: {http_status}")
            if https_status is not None: indicators.append(f"HTTPS response: {https_status}")
            if resp_headers:
                hdr_ev = analyze_headers(resp_headers, provider_cfg)
                indicators.extend(hdr_ev["indicators"])

        if self._tls_check:
            tls_cn, tls_sans = await get_tls_cert_info(ip, self._timeout)
            if tls_cn:
                if is_foreign_cert(tls_cn, tls_sans, scope_domain):
                    indicators.append(
                        f"TLS cert belongs to FOREIGN domain: CN={tls_cn}, SANs={tls_sans[:5]}"
                    )
                    return self._build(
                        ip=ip, version=version, subdomain_name=subdomain_name,
                        provider_key=provider_key, provider_display=provider_display,
                        region=region, cidr=cidr, severity=severity,
                        claim_possible=False, can_claim_specific=False,
                        claim_cmd_tmpl="", finding_type="foreign_cert",
                        confirmed_free=False, confidence=0,
                        indicators=indicators, open_ports=open_ports,
                        ptr_hostname=ptr_hostname,
                        http_status=http_status, https_status=https_status,
                        resp_headers=resp_headers,
                        tls_cn=tls_cn, tls_sans=tls_sans, foreign_tls_cert=True,
                        asn=asn, asn_lookup_used=asn_lookup_used,
                        scope_domain=scope_domain, program_name=program_name, platform=platform,
                        cname_chain=cname_chain, cname_terminal=cname_terminal,
                    )
                else:
                    indicators.append(f"TLS cert CN={tls_cn} (matches scope or unrelated)")

        # Direct claim probes — IPv4 only (EIPs and PIPs are IPv4-only)
        # AWS:   --address flag requests a specific previously-released EIP.
        # Azure: ip_address field in PIP create body requests a specific IP.
        # Both confirm definitively that the IP is free if the call succeeds.
        if self._cloud_claim and version == 4 and can_claim_specific and region and not asn_lookup_used:
            if provider_key == "aws":
                cloud_claim_confirmed = await aws_direct_claim_probe(ip, region)
                if cloud_claim_confirmed:
                    indicators.append(
                        f"✅ AWS direct claim probe SUCCEEDED: "
                        f"--address {ip} --region {region} — IP DEFINITIVELY FREE"
                    )
            elif provider_key == "azure":
                cloud_claim_confirmed = await azure_direct_claim_probe(ip, region)
                if cloud_claim_confirmed:
                    indicators.append(
                        f"✅ Azure direct claim probe SUCCEEDED: "
                        f"ip_address={ip} region={region} — IP DEFINITIVELY FREE"
                    )

        # ── Stage D: Confidence scoring + verdict ───────────────────────────
        if cloud_claim_confirmed:
            confidence     = 100
            confirmed_free = True
        else:
            confidence, confirmed_free = score_finding(
                indicators=indicators,
                open_ports=open_ports,
                anchor_ip_behavior=anchor_ip,
                http_status=http_status,
                https_status=https_status,
                is_ipv6=(version == 6),
                asn_lookup_used=asn_lookup_used,
            )

        verdict = (
            f"VERDICT: IP appears DANGLING (confidence={confidence}%) — no running server"
            if confirmed_free else
            f"VERDICT: IP status UNCERTAIN (confidence={confidence}%) — manual check recommended"
        )
        indicators.append(verdict)

        if confirmed_free:
            logger.info(
                "dangling_ip: %s appears DANGLING — provider=%s region=%s "
                "v%d confidence=%d asn_fallback=%s",
                ip, provider_key, region, version, confidence, asn_lookup_used,
            )

        return self._build(
            ip=ip, version=version, subdomain_name=subdomain_name,
            provider_key=provider_key, provider_display=provider_display,
            region=region, cidr=cidr, severity=severity,
            claim_possible=claim_possible, can_claim_specific=can_claim_specific,
            claim_cmd_tmpl=claim_cmd_tmpl, finding_type=finding_type,
            confirmed_free=confirmed_free, confidence=confidence,
            indicators=indicators, open_ports=open_ports,
            ptr_hostname=ptr_hostname,
            http_status=http_status, https_status=https_status,
            resp_headers=resp_headers,
            tls_cn=tls_cn, tls_sans=tls_sans,
            foreign_tls_cert=is_foreign_cert(tls_cn, tls_sans, scope_domain),
            cloud_claim_confirmed=cloud_claim_confirmed,
            asn=asn, asn_lookup_used=asn_lookup_used,
            scope_domain=scope_domain, program_name=program_name, platform=platform,
            cname_chain=cname_chain, cname_terminal=cname_terminal,
        )

    @staticmethod
    def _build(
        ip: str, version: int, subdomain_name: str,
        provider_key: str, provider_display: str,
        region: str, cidr: str, severity: str,
        claim_possible: bool, can_claim_specific: bool,
        claim_cmd_tmpl: str, finding_type: str,
        confirmed_free: bool, confidence: int,
        indicators: List[str], open_ports: List[int],
        ptr_hostname: Optional[str]  = None,
        http_status:  Optional[int]  = None,
        https_status: Optional[int]  = None,
        resp_headers: dict            = None,
        tls_cn:       Optional[str]   = None,
        tls_sans:     List[str]       = None,
        foreign_tls_cert: bool        = False,
        cloud_claim_confirmed: bool   = False,
        asn:          Optional[int]   = None,
        asn_lookup_used: bool         = False,
        scope_domain: str = "", program_name: str = "", platform: str = "",
        cname_chain:  Optional[List[str]] = None,
        cname_terminal: Optional[str]     = None,
    ) -> DanglingIPFinding:
        claim_cmd = claim_cmd_tmpl.replace("{ip}", ip).replace("{region}", region or "")
        return DanglingIPFinding(
            ip=ip, subdomain_name=subdomain_name,
            provider_key=provider_key, provider_display=provider_display,
            region=region, cidr=cidr, severity=severity,
            finding_type=finding_type, ip_version=version,
            confirmed_free=confirmed_free, confidence=confidence,
            claim_possible=claim_possible, can_claim_specific=can_claim_specific,
            claim_cmd=claim_cmd,
            indicators=indicators, open_ports=open_ports,
            ptr_hostname=ptr_hostname,
            http_status=http_status, https_status=https_status,
            resp_headers=resp_headers or {},
            tls_cn=tls_cn, tls_sans=tls_sans or [],
            foreign_tls_cert=foreign_tls_cert,
            cloud_claim_confirmed=cloud_claim_confirmed,
            asn=asn, asn_lookup_used=asn_lookup_used,
            cname_chain=cname_chain or [], cname_terminal=cname_terminal,
            scope_domain=scope_domain, program_name=program_name, platform=platform,
        )