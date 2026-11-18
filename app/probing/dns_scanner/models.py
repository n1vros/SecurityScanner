"""
app/probing/dns_scanner/db_models.py

All dataclasses and result types for the DNS scanner package.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from app.probing.ip_verdicts import IPVerdict


@dataclass
class NSFinding:
    """A confirmed NS takeover vulnerability on a subdomain or scope root."""
    subdomain_name:  str
    nameserver:      str
    provider:        str
    provider_notes:  str
    rcode:           str           # SERVFAIL / REFUSED / NXDOMAIN / NS_MISMATCH
    fp_risk:         bool
    scope_domain:    str
    program_name:    str
    platform:        str
    all_nameservers: List[str] = field(default_factory=list)

    @property
    def scope_domain_compat(self) -> str:
        return self.scope_domain or self.subdomain_name


@dataclass
class DanglingIPFinding:
    """
    A dangling cloud IP detected during the DNS sweep.

    finding_type:
      "dangling"       — IPv4: no running server, IP appears released to pool
      "ipv6_dangling"  — IPv6: same logic, different address family
      "foreign_cert"   — Port 443 open, TLS cert belongs to a DIFFERENT company
                         (IP taken by someone else — stale DNS, not claimable)
      "cname_dangling" — IP reached via CNAME chain is dangling

    ip_version:  4 or 6
    """
    ip:               str
    subdomain_name:   str
    provider_key:     str
    provider_display: str
    region:           str
    cidr:             str
    severity:         str           # high / medium / low
    finding_type:     str           # "dangling" | "ipv6_dangling" | "foreign_cert" | "cname_dangling"
    ip_version:       int           # 4 or 6

    confirmed_free:   bool
    confidence:       int           # 0-100

    claim_possible:   bool
    can_claim_specific: bool
    claim_cmd:        str

    indicators:       List[str]     = field(default_factory=list)
    open_ports:       List[int]     = field(default_factory=list)

    ptr_hostname:     Optional[str] = None
    http_status:      Optional[int] = None
    https_status:     Optional[int] = None
    resp_headers:     dict          = field(default_factory=dict)

    tls_cn:           Optional[str] = None
    tls_sans:         List[str]     = field(default_factory=list)
    foreign_tls_cert: bool          = False

    cloud_claim_confirmed: bool     = False

    # ASN fallback context
    asn:              Optional[int] = None
    asn_lookup_used:  bool          = False   # True = found via ASN, not CIDR index

    # CNAME chain context
    cname_chain:      List[str]     = field(default_factory=list)
    cname_terminal:   Optional[str] = None

    scope_domain:     str           = ""
    program_name:     str           = ""
    platform:         str           = ""


@dataclass
class ScanResult:
    """Combined result from scanning one subdomain (one pass, all checks)."""
    subdomain_name: str
    ips:            List[str]               = field(default_factory=list)
    ipv6s:          List[str]               = field(default_factory=list)
    ip_verdicts:    Dict[str, IPVerdict]    = field(default_factory=dict)
    ip_free:        Optional[bool]          = None
    has_cname:      bool                    = False
    cname_chain:    List[str]               = field(default_factory=list)
    ns_finding:     Optional[NSFinding]     = None
    dangling_ip_findings: List[DanglingIPFinding] = field(default_factory=list)
