"""
app/probing/dns_scanner/ip_indicators.py

Per-provider signal analysis helpers for dangling IP detection.

Pure analysis functions — accept data, return structured evidence dicts.
All network I/O (port scan, HTTP, TLS) is in ip_analyzer.py.

Covers:
  analyze_ptr()              — PTR record vs provider allocation/release patterns
  analyze_headers()          — HTTP response headers vs provider indicators
  is_foreign_cert()          — TLS cert CN/SANs belong to a different company
  get_tls_cert_info()        — async TLS cert CN + SANs extraction
  aws_direct_claim_probe()   — async AWS-specific specific-IP allocation probe
  azure_direct_claim_probe() — async Azure-specific specific-IP allocation probe
  resolve_asn_cymru()        — async BGP ASN lookup via Team Cymru DNS TXT
  get_provider_from_asn()    — map ASN → vulnerable provider key
  score_finding()            — aggregate signals into confidence score + verdict
  check_spf_dmarc()          — async SPF include + DMARC delegation dangling check

Scoring rules
─────────────
  IPv4 and IPv6 addresses use the same threshold (confidence ≥ 60); there is
  no address-family penalty. ASN-fallback addresses score the same as
  CIDR-identified ones.

  analyze_ptr() covers every detectable PTR case:
    • Absent PTR — provider-specific interpretation via no_ptr_means config
    • Bare in-addr.arpa reverse — no PTR was configured
    • Provider YAML patterns — ptr_patterns, ptr_release_patterns, dns_label_patterns
    • Universal cloud-provider allocated PTRs (Azure cloudapp, GCP googleusercontent,
      AWS EC2, Linode, Vultr, Hetzner, OVH, Oracle, Scaleway, Fly.io, UpCloud…)
    • Universal pool/release PTRs (DO Quadranet reset, OVH poneytelecom, bare reverses)
    • Service-name PTR prefixes (mail, mx, smtp, ns, vpn, api, www, etc.) — strong
      allocated signals regardless of provider, as these are customer-configured
    • IP-embedded auto-generated PTR heuristic — pattern like ip-1-2-3-4.something
      with no other labels is a weak release signal (generic assignment, not
      customer-configured)
    • Unrecognised PTR present but unclassified — neutral

  score_finding() counts signals by substring, so indicator wording is
  load-bearing:
    Free signals      → contain "released", "unallocated", or "free"
    Allocated signals → contain "allocated", "reserved", "infrastructure",
                        "running", or "behind"
    Inconclusive      → contain none of those words

  SPF/DMARC: check_spf_dmarc() function resolves TXT records for the scope
  domain, extracts SPF include targets and DMARC delegation, and checks whether
  those targets are dangling. Called from ns_checker.py during the NS sweep.
"""

import asyncio
import re
import socket
import ssl
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from app.core.logging import logger


# ─────────────────────────────────────────────────────────────────────────────
# Universal PTR pattern tables
# ─────────────────────────────────────────────────────────────────────────────
#
# These are checked AFTER the provider-specific YAML patterns as a cross-
# provider safety net.  Each entry is (regex, human_reason).
#
# Ordering matters: more-specific patterns first so the first match wins and
# the reason is accurate.

# Patterns that mean the IP is ALLOCATED / RESERVED
# ──────────────────────────────────────────────────
# Indicator strings for these MUST contain at least one of:
#   "allocated", "reserved", "infrastructure", "running", "behind"
_UNIVERSAL_ALLOCATED_PTR: List[Tuple[str, str]] = [
    # ── Known cloud provider "still bound to a named resource" PTRs ──────────
    # Azure: any cloudapp FQDN means the Public IP resource is still assigned
    (r'.*\.cloudapp\.azure\.com$',
     "Azure cloudapp FQDN in PTR — IP still bound to an Azure Public IP resource (RESERVED)"),
    (r'.*\.cloudapp\.net$',
     "Azure legacy cloudapp.net PTR — IP still reserved in Azure"),
    # GCP: bc.googleusercontent.com PTR means instance still allocated
    (r'.*\.bc\.googleusercontent\.com$',
     "GCP googleusercontent PTR — IP still allocated to a GCE instance"),
    # AWS: ec2 compute PTR means EIP still attached to an instance
    (r'^ec2-[\d-]+\.(compute-1|[\w-]+\.compute)\.amazonaws\.com$',
     "AWS EC2 compute PTR — IP still attached to an EC2 instance or EIP (RESERVED)"),
    (r'^ip-[\d-]+\.ec2\.internal$',
     "AWS EC2 internal PTR — IP still assigned to an EC2 instance (RESERVED)"),
    # Linode/Akamai
    (r'.*\.members\.linode\.com$',
     "Linode members PTR — IP allocated to a Linode instance (RESERVED)"),
    (r'.*\.ip\.linodeusercontent\.com$',
     "Linode Akamai PTR — IP allocated to a Linode/Akamai instance (RESERVED)"),
    # Vultr
    (r'.*\.vultr\.com$',
     "Vultr PTR — IP allocated to a Vultr instance (RESERVED)"),
    # Hetzner: clients.your-server.de PTR is set for ALL allocated Hetzner IPs
    (r'.*\.clients\.your-server\.de$',
     "Hetzner PTR — IP allocated to a Hetzner server (RESERVED)"),
    # OVH / OVHcloud allocated instances
    (r'.*\.vps\.ovh\.(net|ca|us)$',
     "OVH VPS PTR — IP allocated to an OVH VPS instance (RESERVED)"),
    (r'.*\.dedibox\.fr$',
     "OVH/Dedibox dedicated server PTR — IP allocated (RESERVED)"),
    (r'.*\.dedi\.ovh\.net$',
     "OVH dedicated server PTR — IP allocated (RESERVED)"),
    (r'.*\.ovh\.net$',
     "OVH PTR — IP allocated to an OVH resource (RESERVED)"),
    # Scaleway
    (r'.*\.scaleway\.com$',
     "Scaleway PTR — IP allocated to a Scaleway instance (RESERVED)"),
    # Oracle Cloud
    (r'.*\.oraclevcn\.com$',
     "Oracle Cloud VCN PTR — IP allocated to an OCI instance (RESERVED)"),
    (r'.*\.oraclecloud\.com$',
     "Oracle Cloud PTR — IP allocated to an OCI resource (RESERVED)"),
    # UpCloud
    (r'.*\.ext\.upcloud\.host$',
     "UpCloud PTR — IP allocated to an UpCloud server (RESERVED)"),
    # Fly.io
    (r'.*\.fly\.dev$',
     "Fly.io PTR — IP allocated to a Fly.io application (RESERVED)"),
    # Equinix Metal / Packet
    (r'.*\.packet\.net$',
     "Equinix Metal/Packet PTR — IP allocated to a bare-metal instance (RESERVED)"),
    # Contabo: vmiXXXX pattern = customer VPS — always allocated
    (r'^vmi\d+\.contaboserver\.net$',
     "Contabo VPS PTR — IP allocated to a Contabo customer instance (RESERVED)"),
    # Generic cloud internal hostnames
    (r'.*\.compute\.internal$',
     "Cloud compute-internal PTR — IP allocated to an internal cloud instance (RESERVED)"),
    (r'.*\.internal$',
     "Cloud internal PTR suffix — IP allocated to an internal cloud resource (RESERVED)"),

    # ── Service-name prefixes — strong signal of customer-configured allocation ──
    # Matches first label of PTR (e.g. mail.example.com → label is "mail")
    # These are explicitly set by customers and mean the IP is actively in use.
    (r'^mail\d*\.',
     "Mail server hostname in PTR (mail.) — IP actively used for email (ALLOCATED)"),
    (r'^mx\d*\.',
     "MX record hostname in PTR (mx.) — IP actively used for mail exchange (ALLOCATED)"),
    (r'^smtp\d*\.',
     "SMTP hostname in PTR — IP allocated to a mail submission server (ALLOCATED)"),
    (r'^imap\d*\.',
     "IMAP hostname in PTR — IP allocated to a mail retrieval server (ALLOCATED)"),
    (r'^pop3?\d*\.',
     "POP3 hostname in PTR — IP allocated to a mail server (ALLOCATED)"),
    (r'^ns\d+\.',
     "Nameserver hostname in PTR (ns.) — IP allocated as a DNS nameserver (ALLOCATED)"),
    (r'^dns\d*\.',
     "DNS hostname in PTR — IP allocated as a DNS server (ALLOCATED)"),
    (r'^vpn\d*\.',
     "VPN gateway hostname in PTR — IP allocated to network infrastructure (ALLOCATED)"),
    (r'^fw\d*\.',
     "Firewall hostname in PTR — IP allocated to network infrastructure (ALLOCATED)"),
    (r'^gw\d*\.',
     "Gateway hostname in PTR — IP allocated to network infrastructure (ALLOCATED)"),
    (r'^(www|web|http|nginx|apache)\d*\.',
     "Web server hostname in PTR — IP allocated to a web server (ALLOCATED)"),
    (r'^(api|app|service|svc)\d*\.',
     "Application hostname in PTR — IP allocated to an application service (ALLOCATED)"),
    (r'^(db|mysql|postgres|pgsql|redis|mongo|elastic)\d*\.',
     "Database hostname in PTR — IP allocated to a database server (ALLOCATED)"),
    (r'^(cdn|edge|cache|proxy|lb|loadbalancer)\d*\.',
     "CDN/cache/proxy hostname in PTR — IP allocated behind content infrastructure (ALLOCATED)"),
    (r'^git(lab|hub)?\d*\.',
     "Git/SCM hostname in PTR — IP allocated to a repository service (ALLOCATED)"),
    (r'^(ci|jenkins|build|deploy|bamboo|drone)\d*\.',
     "CI/CD hostname in PTR — IP allocated to a build/deploy service (ALLOCATED)"),
    (r'^(k8s|kube|rancher|docker|harbor)\d*\.',
     "Container-infra hostname in PTR — IP allocated to a container cluster (ALLOCATED)"),
    (r'^(monitor|grafana|prometheus|kibana|splunk)\d*\.',
     "Monitoring hostname in PTR — IP allocated to a monitoring service (ALLOCATED)"),
    (r'^(ssh|bastion|jump)\d*\.',
     "SSH/bastion hostname in PTR — IP allocated to a jump-host (ALLOCATED)"),
    (r'^(ftp|sftp)\d*\.',
     "FTP hostname in PTR — IP allocated to a file transfer server (ALLOCATED)"),
    (r'^(prod|production|staging|stage|dev|development|test|uat)\d*\.',
     "Environment-name hostname in PTR — IP allocated to a running environment (ALLOCATED)"),
]

# Patterns that mean the IP is RELEASED / UNALLOCATED / back in the pool
# ──────────────────────────────────────────────────────────────────────
# Indicator strings for these MUST contain at least one of:
#   "released", "unallocated", "free"
_UNIVERSAL_RELEASED_PTR: List[Tuple[str, str]] = [
    # Bare in-addr.arpa reverse — the zone name itself, no real hostname
    (r'^\d+\.\d+\.\d+\.\d+\.in-addr\.arpa\.?$',
     "Bare in-addr.arpa reverse PTR — no hostname configured, IP is unallocated/free"),
    # Bare IPv6 reverse
    (r'^[0-9a-f.]+\.ip6\.arpa\.?$',
     "Bare ip6.arpa reverse PTR — no hostname configured, IPv6 IP is unallocated/free"),
    # DigitalOcean Quadranet reset — DO resets PTR to this on release
    (r'.*\.static\.quadranet\.com$',
     "DO-style Quadranet PTR reset — IP returned to pool and is now unallocated/free"),
    # OVH/Scaleway generic reverse (auto-assigned when no customer PTR)
    (r'^\d+\.\d+\.\d+\.\d+\.rev\.poneytelecom\.eu$',
     "OVH/Scaleway generic poneytelecom reverse PTR — IP is unallocated/free in provider pool"),
    # OVH generic IP-based PTR (not a customer reverse — auto-generated by OVH)
    (r'^ip\d+-\d+-\d+-\d+\.eu\.org$',
     "OVH generic IP-format eu.org PTR — IP is unallocated/free in provider pool"),
    # Hetzner un-configured static PTR (auto-generated, not customer-set)
    # Format: static.X.X.X.X.clients.your-server.de is ALLOCATED (handled above)
    # but ip-X-X-X-X.your-server.de (without 'static') is the un-configured default
    (r'^ip-\d+-\d+-\d+-\d+\.your-server\.de$',
     "Hetzner unconfigured IP-format PTR — IP likely unallocated/free (no customer PTR set)"),
    # Leaseweb generic reverse
    (r'^ptr\.\d+\.\d+\.\d+\.\d+\.in-addr\.arpa$',
     "Leaseweb generic PTR — IP unallocated/free in provider pool"),
    # Pure IP literal PTR (some providers return this for pool IPs)
    (r'^\d+\.\d+\.\d+\.\d+$',
     "IP-literal PTR value — no hostname configured, IP appears unallocated/free"),
]

# Generic auto-generated PTR pattern — IP embedded in dashes at start
# e.g.  1-2-3-4.some-isp.net  or  host-1-2-3-4.datacenter.net
# This is a WEAK free signal — many allocated IPs also have this style of PTR
# (it's the provider's auto-assignment), but custom labels are usually words.
_IP_EMBEDDED_PTR_PATTERN = re.compile(
    r'^(?:ip-|host-|server-|static-)?(\d{1,3}[-.]){3}\d{1,3}[.-]',
    re.IGNORECASE,
)

# Service-name pattern (compiled once for performance)
_SERVICE_NAME_PATTERN = re.compile(
    r'^(mail|mx|smtp|imap|pop3?|ns|dns|vpn|fw|firewall|gw|gateway|'
    r'www|web|http|nginx|apache|api|app|service|svc|db|mysql|postgres|'
    r'pgsql|redis|mongo|elastic|cdn|edge|cache|proxy|lb|git|ci|jenkins|'
    r'build|deploy|k8s|kube|monitor|grafana|bastion|jump|ssh|ftp|sftp|'
    r'prod|staging|stage|dev|test|uat)\d*\.',
    re.IGNORECASE,
)


# ─────────────────────────────────────────────────────────────────────────────
# PTR analysis
# ─────────────────────────────────────────────────────────────────────────────

def analyze_ptr(
    ip: str,
    ptr_hostname: Optional[str],
    provider_cfg: dict,
) -> Dict:
    """
    Comprehensive PTR record analysis for dangling IP detection.

    Evaluation order (first match wins per category, both categories are
    independent so you can get allocated + released signals from different
    layers — allocated signals always win when present):

    1. Absent PTR   — provider no_ptr_means config → free or inconclusive
    2. Bare reverse — in-addr.arpa / ip6.arpa literal → free signal
    3. Provider YAML patterns
         ptr_patterns         → allocated
         ptr_release_patterns → released
         dns_label_patterns   → allocated
    4. Universal hardcoded allocated PTR patterns  (cloud provider + service names)
    5. Universal hardcoded released/pool PTR patterns
    6. IP-embedded auto-generated PTR heuristic   → weak free signal
    7. Unrecognised PTR present                   → neutral (no keyword leak)

    Indicator string contract (score_finding() keyword matching):
      - Free signals:      strings contain "released", "unallocated", or "free"
      - Allocated signals: strings contain "allocated", "reserved",
                           "infrastructure", "running", or "behind"
      - Inconclusive:      strings contain NONE of the above

    Returns {"allocated": bool, "released": bool, "indicators": [str]}.
    """
    indicators:    List[str] = []
    allocated      = False
    released       = False
    ind_cfg        = provider_cfg.get("indicators", {})
    provider_name  = provider_cfg.get("name", "?")

    # ── 1. Absent PTR ────────────────────────────────────────────────────────
    if ptr_hostname is None:
        no_ptr_means = ind_cfg.get("no_ptr_means", "unknown")
        if no_ptr_means == "released":
            released = True
            indicators.append(
                f"PTR absent — for {provider_name} this typically means the IP "
                f"has been released back to the pool (unallocated)"
            )
        else:
            # IMPORTANT: do NOT include "no ptr record" here — score_finding()
            # keyword-matches on that phrase and would count it as a free signal
            # even when the status is genuinely inconclusive.
            indicators.append(
                f"PTR absent — allocation status inconclusive for {provider_name} "
                f"(this provider does not use PTR as a release signal)"
            )
        return {"allocated": allocated, "released": released, "indicators": indicators}

    indicators.append(f"PTR resolves to: {ptr_hostname}")
    ptr_lower = ptr_hostname.lower()

    # ── 2. Bare in-addr.arpa / ip6.arpa reverse ──────────────────────────────
    # This is the raw zone label — no actual hostname was configured.
    for pattern_str, reason in _UNIVERSAL_RELEASED_PTR[:2]:  # first two are bare reverses
        try:
            if re.match(pattern_str, ptr_hostname, re.IGNORECASE):
                released = True
                indicators.append(f"{reason} [PTR={ptr_hostname}]")
                return {"allocated": allocated, "released": released, "indicators": indicators}
        except re.error:
            pass

    # ── 3. Provider-specific YAML patterns ───────────────────────────────────
    for pattern_str in ind_cfg.get("ptr_patterns", []):
        try:
            if re.match(pattern_str, ptr_hostname, re.IGNORECASE):
                allocated = True
                indicators.append(
                    f"PTR matches provider allocation pattern `{pattern_str}` — "
                    f"IP appears still RESERVED by {provider_name}"
                )
                break
        except re.error:
            pass

    for pattern_str in ind_cfg.get("ptr_release_patterns", []):
        try:
            if re.match(pattern_str, ptr_hostname, re.IGNORECASE):
                released  = True
                allocated = False
                indicators.append(
                    f"PTR matches provider release pattern `{pattern_str}` — "
                    f"IP appears RELEASED from {provider_name} pool (unallocated)"
                )
                break
        except re.error:
            pass

    for pattern_str in ind_cfg.get("dns_label_patterns", []):
        try:
            if re.match(pattern_str, ptr_hostname, re.IGNORECASE):
                allocated = True
                indicators.append(
                    f"PTR matches provider DNS-label pattern `{pattern_str}` — "
                    f"IP is still bound to a named resource (RESERVED by {provider_name})"
                )
                break
        except re.error:
            pass

    # If provider YAML already gave us a definitive answer, stop here
    if allocated or released:
        return {"allocated": allocated, "released": released, "indicators": indicators}

    # ── 4. Universal hardcoded ALLOCATED patterns ─────────────────────────────
    for pattern_str, reason in _UNIVERSAL_ALLOCATED_PTR:
        try:
            if re.match(pattern_str, ptr_hostname, re.IGNORECASE):
                allocated = True
                indicators.append(f"{reason} [PTR={ptr_hostname}]")
                return {"allocated": allocated, "released": released, "indicators": indicators}
        except re.error:
            pass

    # ── 5. Universal hardcoded RELEASED/pool patterns ─────────────────────────
    # (skip index 0–1 which were already checked in step 2)
    for pattern_str, reason in _UNIVERSAL_RELEASED_PTR[2:]:
        try:
            if re.match(pattern_str, ptr_hostname, re.IGNORECASE):
                released = True
                indicators.append(f"{reason} [PTR={ptr_hostname}]")
                return {"allocated": allocated, "released": released, "indicators": indicators}
        except re.error:
            pass

    # ── 6. IP-embedded auto-generated PTR heuristic ───────────────────────────
    # PTRs like "1-2-3-4.datacenter.net" or "host-1-2-3-4.isp.net" are often
    # auto-assigned by providers for IPs in their general pool with no customer
    # PTR set.  This is a WEAK release signal — add it but note the uncertainty.
    # We only fire this if the PTR has ≤3 labels (e.g. "1-2-3-4.isp.net") to
    # avoid false-positives on "ip-1-2-3-4.prod.company.com" (customer-set).
    labels = ptr_lower.split(".")
    if _IP_EMBEDDED_PTR_PATTERN.match(ptr_hostname) and len(labels) <= 3:
        indicators.append(
            f"PTR appears to be an auto-generated IP-embedded hostname "
            f"(no customer PTR configured) — IP possibly free/unallocated [PTR={ptr_hostname}]"
        )
        released = True
        return {"allocated": allocated, "released": released, "indicators": indicators}

    # ── 7. Unrecognised PTR present ───────────────────────────────────────────
    # PTR exists but matched none of our patterns.  This is likely a customer-
    # configured hostname pointing to a service we don't recognise.  Treat as a
    # weak allocated signal (having ANY custom PTR means someone cares about this
    # IP), but do NOT add keywords that would falsely score it as free.
    #
    # Check if first label looks like a word (not numeric / IP-derived).
    first_label = labels[0] if labels else ""
    if first_label and not re.match(r'^[\d\-]+$', first_label):
        # Has a meaningful word label — likely customer-configured
        indicators.append(
            f"PTR has an unrecognised but non-generic hostname — "
            f"possibly customer-configured, IP may be allocated [PTR={ptr_hostname}]"
        )
        # This is ambiguous so we don't set allocated=True, but we don't set
        # released either.  The indicator string doesn't contain scoring keywords
        # so it contributes 0 to free_signals and 0 to allocated_signals.
    else:
        # First label is all digits/dashes — looks auto-generated but didn't
        # match our known pool patterns.  Treat as inconclusive.
        indicators.append(
            f"PTR has a numeric/dash first label but no matching pool pattern — "
            f"status inconclusive [PTR={ptr_hostname}]"
        )

    return {"allocated": allocated, "released": released, "indicators": indicators}


# ─────────────────────────────────────────────────────────────────────────────
# HTTP response header analysis
# ─────────────────────────────────────────────────────────────────────────────

def analyze_headers(headers: Dict[str, str], provider_cfg: dict) -> Dict:
    """
    Check response headers against provider-specific allocation indicators.

    Returns {"allocated": bool, "indicators": [str]}.
    """
    if not headers:
        return {"allocated": False, "indicators": []}

    indicators:   List[str] = []
    allocated     = False
    ind_cfg       = provider_cfg.get("indicators", {})
    provider_name = provider_cfg.get("name", "?")
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

    for header_pattern in ind_cfg.get("response_headers", []):
        if ":" in header_pattern:
            hk, hv = header_pattern.split(":", 1)
            hk = hk.strip().lower()
            hv = hv.strip().lower()
            if hk in headers_lower and hv in headers_lower[hk]:
                allocated = True
                indicators.append(
                    f"Response header `{header_pattern}` detected — "
                    f"IP is behind {provider_name} infrastructure (ALLOCATED)"
                )
        else:
            pat_lower = header_pattern.lower()
            for hk, hv in headers_lower.items():
                if hk.startswith(pat_lower) or pat_lower in hv:
                    allocated = True
                    indicators.append(
                        f"Response header matching `{header_pattern}` "
                        f"(`{hk}: {hv[:80]}`) — IP behind {provider_name} (ALLOCATED)"
                    )
                    break

    return {"allocated": allocated, "indicators": indicators}


# ─────────────────────────────────────────────────────────────────────────────
# TLS certificate extraction
# ─────────────────────────────────────────────────────────────────────────────

async def get_tls_cert_info(ip: str, timeout: float) -> Tuple[Optional[str], List[str]]:
    """
    Grab TLS certificate CN and SANs from port 443 without verifying chain.
    Works for both IPv4 and IPv6 addresses.
    Returns (cn, [san, ...]).
    """
    try:
        loop = asyncio.get_running_loop()

        def _get_cert():
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((ip, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock) as ssock:
                    return ssock.getpeercert()

        cert = await asyncio.wait_for(
            loop.run_in_executor(None, _get_cert),
            timeout=timeout + 2,
        )
        if not cert:
            return None, []

        cn: Optional[str] = None
        for field_pair in cert.get("subject", []):
            for key, val in field_pair:
                if key == "commonName":
                    cn = val

        sans: List[str] = [
            san_val
            for san_type, san_val in cert.get("subjectAltName", [])
            if san_type == "DNS"
        ]
        return cn, sans
    except Exception:
        return None, []


# ─────────────────────────────────────────────────────────────────────────────
# Foreign cert check
# ─────────────────────────────────────────────────────────────────────────────

def is_foreign_cert(
    tls_cn:       Optional[str],
    tls_sans:     List[str],
    scope_domain: str,
) -> bool:
    """
    Returns True if the TLS cert's CN or any SAN belongs to a domain that is
    NOT part of scope_domain.

    Meaning: another company is running a TLS service on this IP. The original
    subdomain's DNS is stale and pointing at someone else's server.

    Ignores wildcards, localhost, and single-label names.
    """
    if not tls_cn and not tls_sans:
        return False
    if not scope_domain:
        return False

    scope_root = scope_domain.lstrip("*").lstrip(".").lower()
    all_names  = ([tls_cn] if tls_cn else []) + tls_sans

    for name in all_names:
        name_clean = name.lstrip("*").lstrip(".").lower()
        if not name_clean:
            continue
        if name_clean in ("localhost", "example.com") or "." not in name_clean:
            continue
        if not (name_clean == scope_root or name_clean.endswith("." + scope_root)):
            return True

    return False


# ─────────────────────────────────────────────────────────────────────────────
# AWS direct IP claim probe
# ─────────────────────────────────────────────────────────────────────────────

async def aws_direct_claim_probe(ip: str, region: str) -> bool:
    """
    Attempt: aws ec2 allocate-address --domain vpc --address <ip> --region <region>

    AWS supports requesting a SPECIFIC previously-released Elastic IP via --address.
    A successful allocation definitively confirms the IP is free. Released immediately.

    Returns True if successfully allocated (IP is confirmed free).
    Requires AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY in settings.
    """
    try:
        import boto3
        from app.core.config import settings as _s

        aws_key    = getattr(_s, "AWS_ACCESS_KEY_ID", None)
        aws_secret = getattr(_s, "AWS_SECRET_ACCESS_KEY", None)
        if not aws_key or not aws_secret:
            return False

        loop   = asyncio.get_running_loop()
        client = boto3.client(
            "ec2",
            region_name=region,
            aws_access_key_id=aws_key,
            aws_secret_access_key=aws_secret,
        )

        def _allocate():
            try:
                resp = client.allocate_address(Domain="vpc", Address=ip)
                alloc_id = resp.get("AllocationId")
                if alloc_id:
                    client.release_address(AllocationId=alloc_id)
                    return True
                return False
            except Exception:
                return False

        return await asyncio.wait_for(
            loop.run_in_executor(None, _allocate),
            timeout=15.0,
        )
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Azure direct IP claim probe
# ─────────────────────────────────────────────────────────────────────────────

async def azure_direct_claim_probe(ip: str, region: str) -> bool:
    """
    Attempt to claim a specific previously-released Azure Public IP directly:

      PublicIPAddresses.begin_create_or_update(
          resource_group, name,
          {"location": region, "sku": {"name": "Standard"},
           "public_ip_allocation_method": "Static",
           "ip_address": <ip>}
      )

    Azure Static Standard PIPs support an ip_address field in the create body.
    If the IP is in the regional pool (released), it is assigned immediately —
    confirming the IP is definitively free.  The resource is released immediately
    after the confirmation.

    If still in use the API raises a Conflict/InUse exception → returns False.

    Returns True if the IP was successfully claimed (IP is confirmed free).
    Requires AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET,
    AZURE_SUBSCRIPTION_ID, AZURE_RESOURCE_GROUP in settings.
    Only runs when DANGLING_IP_CLOUD_CLAIM_CHECK=True.
    """
    try:
        from app.core.config import settings as _s

        tenant_id     = getattr(_s, "AZURE_TENANT_ID",       None)
        client_id     = getattr(_s, "AZURE_CLIENT_ID",       None)
        client_secret = getattr(_s, "AZURE_CLIENT_SECRET",   None)
        subscription  = getattr(_s, "AZURE_SUBSCRIPTION_ID", None)
        rg            = getattr(_s, "AZURE_RESOURCE_GROUP",  None)

        if not all([tenant_id, client_id, client_secret, subscription, rg]):
            return False

        import uuid
        from azure.identity import ClientSecretCredential
        from azure.mgmt.network import NetworkManagementClient

        loop = asyncio.get_running_loop()

        def _claim():
            credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
            )
            client = NetworkManagementClient(credential, subscription)
            resource_name = f"sto-probe-{uuid.uuid4().hex[:12]}"
            try:
                poller = client.public_ip_addresses.begin_create_or_update(
                    rg,
                    resource_name,
                    {
                        "location":                    region,
                        "sku":                         {"name": "Standard"},
                        "public_ip_allocation_method": "Static",
                        "public_ip_address_version":   "IPv4",
                        "ip_address":                  ip,
                    },
                )
                pip    = poller.result()
                got_ip = pip.ip_address
                # Always release immediately — we only needed the confirmation
                client.public_ip_addresses.begin_delete(rg, resource_name).result()
                return got_ip == ip
            except Exception:
                # Expected on InUse / Conflict — IP still allocated
                # Clean up any partially created resource
                try:
                    client.public_ip_addresses.begin_delete(rg, resource_name).result()
                except Exception:
                    pass
                return False

        return await asyncio.wait_for(
            loop.run_in_executor(None, _claim),
            timeout=30.0,
        )
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# ASN lookup via Team Cymru
# ─────────────────────────────────────────────────────────────────────────────

# Known ASN → vulnerable provider key mappings
_ASN_TO_PROVIDER: Dict[int, str] = {
    16509: "aws",    14618: "aws",
    8075:  "azure",
    15169: "gcp",    396982: "gcp",
    14061: "digitalocean",
    63949: "linode",
    20473: "vultr",
    24940: "hetzner",
    31898: "oracle",
    16276: "ovh",
    12876: "scaleway",
    396507: "fly",
    202053: "upcloud",
}


async def resolve_asn_cymru(ip: str) -> Optional[int]:
    """
    Async BGP ASN lookup for ip via Team Cymru DNS TXT service.
    Returns the ASN integer, or None on failure.
    """
    from app.core.config import settings as _s
    if not getattr(_s, "IP_HUNTER_ASN_LOOKUP", False):
        return None

    try:
        import dns.asyncresolver
        import ipaddress as _ipa

        addr = _ipa.ip_address(ip)
        if isinstance(addr, _ipa.IPv4Address):
            reversed_ip = ".".join(reversed(ip.split(".")))
            query_name  = f"{reversed_ip}.origin.asn.cymru.com"
        else:
            expanded    = addr.exploded.replace(":", "")
            reversed_ip = ".".join(reversed(expanded))
            query_name  = f"{reversed_ip}.origin6.asn.cymru.com"

        answer = await dns.asyncresolver.resolve(query_name, "TXT")
        for rdata in answer:
            txt = str(rdata).strip('"').strip()
            first_field = txt.split("|")[0].strip()
            asn_str = first_field.split()[0]
            return int(asn_str)
    except Exception:
        return None


def get_provider_from_asn(asn: Optional[int]) -> Optional[str]:
    """
    Map an ASN integer to a vulnerable provider key.
    Returns None if the ASN is not in our map.
    """
    if asn is None:
        return None
    return _ASN_TO_PROVIDER.get(asn)


# ─────────────────────────────────────────────────────────────────────────────
# Confidence scoring
# ─────────────────────────────────────────────────────────────────────────────

def score_finding(
    indicators:         List[str],
    open_ports:         List[int],
    anchor_ip_behavior: bool,
    http_status:        Optional[int],
    https_status:       Optional[int],
    is_ipv6:            bool = False,  # unused; kept for call-site compatibility
    asn_lookup_used:    bool = False,  # unused; kept for call-site compatibility
) -> Tuple[int, bool]:
    """
    Aggregate all collected signals into a (confidence, confirmed_free) tuple.

    confidence:    0–100 estimate that the IP is truly unallocated
    confirmed_free: True when confidence ≥ 60

    Scoring logic
    ─────────────
    Base:  50

    Bonuses (free_signals × +15):
      Indicator strings containing "released", "unallocated", or "free"
      e.g. absent PTR for a provider where no_ptr_means=released → +15
           PTR matches known release pattern                       → +15
           IP-embedded PTR heuristic fired                        → +15
           Cloud-specific release PTR (Quadranet, poneytelecom…)  → +15

    Penalties (allocated_signals × -20):
      Indicator strings containing "allocated", "reserved", "infrastructure",
      "running", or "behind"
      e.g. provider PTR pattern matched                           → -20
           service-name prefix (mail., vpn., api.…)              → -20
           known cloud-allocated PTR (cloudapp, bc.googleusercontent) → -20

    Modifier penalties:
      anchor_ip_behavior  → -15 (DO anchor IPs respond to ICMP even when free)

    NOTE — IPv6 penalty: the -10 IPv6 penalty has been REMOVED. IPv6 findings
      fire at the same threshold as IPv4 (confidence ≥ 60). is_ipv6 is accepted
      for backwards call-site compatibility but is not used.

    NOTE — ASN penalty: the -15 asn_lookup_used penalty has been REMOVED after
      testing showed it suppressed too many genuine findings.  ASN-identified
      providers now score identically to CIDR-identified ones.  asn_lookup_used
      is accepted for backwards call-site compatibility but is not used.

    Minimum reachable score:
      open_ports=[]  http/https=None  0 free signals, 0 alloc signals
      CIDR match, IPv4:              50 → does NOT fire (need 1 free signal)
      CIDR match, IPv4, no PTR:      65 → fires ✅
      CIDR match, IPv6, no PTR:      65 → fires ✅
      ASN fallback, IPv4, no PTR:    65 → fires ✅ (no penalty)
      ASN fallback + release PTR:    80 → fires ✅
    """
    if open_ports:
        return 0, False

    if http_status is not None and 200 <= http_status < 400:
        return 5, False

    if https_status is not None and 200 <= https_status < 400:
        return 5, False

    free_signals = sum(
        1 for s in indicators
        if any(kw in s.lower() for kw in ("released", "unallocated", "free"))
    )
    allocated_signals = sum(
        1 for s in indicators
        if any(kw in s.lower() for kw in ("allocated", "running", "reserved", "behind", "infrastructure"))
    )

    base  = 50
    base += free_signals      * 15
    base -= allocated_signals * 20

    if anchor_ip_behavior:
        base -= 15   # DO anchor routing keeps ICMP alive even without a droplet

    confidence     = max(0, min(100, base))
    confirmed_free = confidence >= 60

    return confidence, confirmed_free


# ─────────────────────────────────────────────────────────────────────────────
# SPF / DMARC dangling check
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SpfDmarcFinding:
    """
    A dangling SPF include target or DMARC delegation found during the NS sweep.

    finding_type:
      "spf_include_nxdomain"   — SPF include: target domain is NXDOMAIN.
                                  Email authentication for scope_domain is broken
                                  and can be bypassed if the domain is re-registered.
      "spf_include_takeover"   — SPF include: target domain has a vulnerable NS
                                  delegation. The SPF policy can be overwritten by
                                  claiming the NS zone, allowing arbitrary IPs to
                                  pass SPF for scope_domain.
      "dmarc_ns_takeover"      — _dmarc.scope_domain or its NS zone is claimable.
                                  Attacker can serve p=none to disable enforcement
                                  or redirect rua= reports to exfiltrate infra data.

    severity: "high" for SPF takeover / DMARC takeover, "medium" for NXDOMAIN only.
    """
    finding_type:  str           # see above
    scope_domain:  str           # the scope domain whose email auth is affected
    target_domain: str           # the dangling include target or _dmarc subdomain
    detail:        str           # human-readable explanation
    severity:      str = "high"
    program_name:  str = ""
    platform:      str = ""
    indicators:    List[str] = field(default_factory=list)


# SPF include: regex to extract domains from `include:` and `redirect=` modifiers.
# Stops at whitespace and SPF mechanism terminators (~all, -all, +all, ?all, etc.)
# so malformed records like `spf.protection.outlook.com-all` don't get parsed as
# a single domain.  The character class [a-zA-Z0-9._\-] excludes the common
# error of concatenated tokens.
_SPF_INCLUDE_RE = re.compile(
    r'(?:include:|redirect=)([a-zA-Z0-9._\-]+)',
    re.IGNORECASE,
)

# Valid FQDN: must have at least one dot AND a TLD of 2+ alpha chars.
# Rejects: single-label names, truncated tokens like "spf.prote", numeric-only
# TLDs, and concatenated garbage like "outlook.com-all".
_FQDN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'  # one or more labels
    r'+[a-zA-Z]{2,}$'                                            # TLD 2+ alpha only
)

# ─────────────────────────────────────────────────────────────────────────────
# TLD registrability filter
# ─────────────────────────────────────────────────────────────────────────────
#
# TLDs where domain registration is impossible for a generic attacker — either
# restricted to government/military/edu entities, reserved by IANA, or
# infrastructure-only.  A dangling SPF include pointing into one of these is
# either a misconfiguration in the SPF record itself or a false positive from
# macro expansion — either way it's not actionable, so we skip it.

_NON_REGISTRABLE_TLDS = frozenset({
    # US Government / Military / Education — restricted registration
    "gov", "mil", "edu",
    # IANA reserved / infrastructure
    "arpa", "int",
    # RFC 2606 / RFC 6761 reserved for testing / local use
    "test", "example", "invalid", "localhost", "local",
    # New IANA reserved
    "internal",
})


def _get_tld(domain: str) -> str:
    """Return the rightmost label (TLD) of a domain, lowercased."""
    return domain.rstrip(".").rsplit(".", 1)[-1].lower()


def _extract_registrable_root(domain: str) -> str:
    """
    Return the registrable root domain (the part you actually buy).

    Uses a two-part-TLD heuristic (.co.uk, .com.br, .org.au etc.):
      sub.example.co.uk  →  example.co.uk
      sub.example.com    →  example.com
      example.com        →  example.com
    """
    domain = domain.lstrip("*").lstrip(".").lower().rstrip(".")
    parts  = domain.split(".")
    if len(parts) >= 3 and len(parts[-2]) <= 3 and parts[-2].isalpha():
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def _is_registrable_domain(domain: str) -> bool:
    """
    Return True if `domain` is a registrable root domain (i.e. the domain you
    can buy via a registrar), not a subdomain deeper than the registrable root.

    Examples:
      example.com           → True   (root domain)
      foo.example.com       → False  (subdomain — cannot be registered)
      example.co.uk         → True   (root with 2-part TLD)
      foo.example.co.uk     → False  (subdomain)
      sendgrid.net          → True
      em1234.sendgrid.net   → False
    """
    domain = domain.lower().rstrip(".")
    root   = _extract_registrable_root(domain)
    # If domain == root, it's a registrable root; otherwise it's a subdomain
    return domain == root


# Known large shared SPF providers — no takeover value, skip to avoid noise.
# Checked with endswith() so subdomains (e.g. _spf1.mailgun.org) also match.
_SPF_SKIP_SUFFIXES = (
    "spf.protection.outlook.com",
    "mail.protection.outlook.com",
    "protection.outlook.com",
    "_spf.google.com",
    "spf.sendgrid.net",
    "sendgrid.net",
    "amazonses.com",
    "mailgun.org",
    "_spf.mandrillapp.com",
    "spf.mandrillapp.com",
    "spf.messagelabs.com",
    "mimecast.com",
    "spf.smtp2go.com",
    "servers.mcsv.net",       # Mailchimp
    "spf.mtasv.net",          # Postmark
    "pphosted.com",           # Proofpoint — shared infra, subdomain churn is normal
    "spf-protect.agari.com",  # Agari/HelpSystems
    "spf-protect.agari-dns.net",
    "hubspotemail.net",
    "sparkpostmail.com",
    "mailjet.com",
    "sendinblue.com",
    "brevo.com",
)


def _is_valid_spf_domain(domain: str, scope_domain: str = "") -> bool:
    """
    Return True if domain looks like a real FQDN worth checking for takeover.

    Rejects:
      - Strings without a dot (single-label)
      - SPF macro expressions containing %{ (e.g. %{ir}.%{v}.%{d}.spf.host.com)
      - TLDs that are not pure alpha (catches "-all" suffixes like "outlook.com-all")
      - Strings shorter than 4 chars or longer than 253 chars
      - Known high-volume shared provider suffixes (no takeover value)
      - Non-registrable TLDs (.gov, .mil, .edu, .arpa, .int, .test …)
      - Subdomains of scope_domain or scope_domain itself (mother-domain filter)
    """
    if not domain or len(domain) < 4 or len(domain) > 253:
        return False
    # Reject SPF macro expressions immediately
    if "%{" in domain or "%}" in domain:
        return False
    if not _FQDN_RE.match(domain):
        return False
    domain_lower = domain.lower().rstrip(".")

    # reject non-registrable TLDs
    if _get_tld(domain_lower) in _NON_REGISTRABLE_TLDS:
        return False

    # reject if domain is the scope domain itself or a subdomain of it
    if scope_domain:
        scope_root = scope_domain.lstrip("*").lstrip(".").lower().rstrip(".")
        if domain_lower == scope_root or domain_lower.endswith("." + scope_root):
            return False

    for suffix in _SPF_SKIP_SUFFIXES:
        if domain_lower == suffix or domain_lower.endswith("." + suffix):
            return False
    return True


async def check_spf_dmarc(
    scope_domain:  str,
    program_name:  str = "",
    platform:      str = "",
    timeout:       float = 3.0,
) -> List[SpfDmarcFinding]:
    """
    Check SPF include targets and DMARC delegation for the scope domain.

    Attack vectors:
      1. SPF include target is NXDOMAIN — email authentication broken,
         re-registering the domain bypasses SPF for scope_domain entirely.
      2. SPF include target has vulnerable NS — claiming the NS zone lets
         an attacker publish v=spf1 +all, passing all IPs as scope_domain.
      3. DMARC record's NS zone is vulnerable — attacker can serve p=none
         (disabling enforcement) or redirect rua= reports.

    Uses standard DNS TXT queries via dnspython async resolver.
    Non-fatal: any resolver error returns an empty list rather than raising.

    Config key: DANGLING_SPF_DMARC_CHECK (bool, default True)
    """
    from app.core.config import settings as _s
    if not getattr(_s, "DANGLING_SPF_DMARC_CHECK", True):
        return []

    findings: List[SpfDmarcFinding] = []

    try:
        import dns.asyncresolver
        import dns.rdatatype
        import dns.rcode
        import dns.exception

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = timeout

        # ── 1. Fetch SPF TXT record for scope_domain ──────────────────────
        spf_includes: List[str] = []
        try:
            answer = await resolver.resolve(scope_domain, "TXT")
            for rdata in answer:
                # Correctly join multi-string TXT records (DNS TXT records are
                # sequences of <255-byte strings). str(rdata) wraps each chunk
                # in quotes which corrupts domain parsing — join raw bytes instead.
                txt = "".join(
                    s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                    for s in rdata.strings
                )
                if not txt.lower().startswith("v=spf1"):
                    continue
                for match in _SPF_INCLUDE_RE.finditer(txt):
                    include_domain = match.group(1).lower().rstrip(".")
                    # Pass scope_domain so mother-domain and non-registrable TLD
                    # filters are applied at extraction time
                    if _is_valid_spf_domain(include_domain, scope_domain=scope_domain):
                        spf_includes.append(include_domain)
        except (dns.exception.DNSException, Exception):
            pass   # no SPF record or lookup failed — not an error

        # ── 2. Check each SPF include target ─────────────────────────────
        for include_domain in spf_includes:
            is_nxdomain = False
            try:
                await resolver.resolve(include_domain, "A")
            except dns.resolver.NXDOMAIN:
                is_nxdomain = True
            except Exception:
                pass   # SERVFAIL, timeout — inconclusive

            if is_nxdomain:
                # only alert if this is a registrable root domain.
                # A subdomain like em1234.sendgrid.net being NXDOMAIN doesn't
                # mean an attacker can register it — only the root can be bought.
                if not _is_registrable_domain(include_domain):
                    logger.debug(
                        "spf_dmarc: skipping nxdomain finding for %s — "
                        "not a registrable root domain (subdomain of %s)",
                        include_domain, _extract_registrable_root(include_domain),
                    )
                    continue

                findings.append(SpfDmarcFinding(
                    finding_type="spf_include_nxdomain",
                    scope_domain=scope_domain,
                    target_domain=include_domain,
                    severity="medium",
                    detail=(
                        f"SPF include target `{include_domain}` is NXDOMAIN. "
                        f"Email authentication for `{scope_domain}` is broken — "
                        f"SPF evaluation returns PermError, many mail servers treat "
                        f"this as neutral/pass. Re-registering `{include_domain}` "
                        f"allows publishing `v=spf1 +all` to pass SPF as any `@{scope_domain}` sender."
                    ),
                    program_name=program_name,
                    platform=platform,
                    indicators=[
                        f"SPF record for {scope_domain} contains: include:{include_domain}",
                        f"{include_domain} → NXDOMAIN (registrable root domain — can be bought)",
                    ],
                ))
                logger.info(
                    "spf_dmarc: SPF include NXDOMAIN for %s — include:%s",
                    scope_domain, include_domain,
                )
                continue

            # Check if the include domain's NS is vulnerable
            # confirm via trusted resolvers before alerting
            ns_vuln = await _check_domain_ns_vulnerable(include_domain, resolver, timeout)
            if ns_vuln:
                findings.append(SpfDmarcFinding(
                    finding_type="spf_include_takeover",
                    scope_domain=scope_domain,
                    target_domain=include_domain,
                    severity="high",
                    detail=(
                        f"SPF include target `{include_domain}` has a vulnerable NS delegation "
                        f"({ns_vuln}). Claiming the NS zone allows publishing "
                        f"`v=spf1 +all ~all` to make any IP pass SPF for `@{scope_domain}` — "
                        f"enables sending phishing email that passes authentication."
                    ),
                    program_name=program_name,
                    platform=platform,
                    indicators=[
                        f"SPF record for {scope_domain} contains: include:{include_domain}",
                        f"{include_domain} NS → {ns_vuln} (confirmed vulnerable via trusted resolvers)",
                    ],
                ))
                logger.info(
                    "spf_dmarc: SPF include NS takeover for %s — include:%s ns=%s",
                    scope_domain, include_domain, ns_vuln,
                )

        # ── 3. Check DMARC record and its NS delegation ───────────────────
        dmarc_domain = f"_dmarc.{scope_domain}"
        try:
            await resolver.resolve(dmarc_domain, "TXT")
            ns_vuln = await _check_domain_ns_vulnerable(dmarc_domain, resolver, timeout)
            if ns_vuln:
                findings.append(SpfDmarcFinding(
                    finding_type="dmarc_ns_takeover",
                    scope_domain=scope_domain,
                    target_domain=dmarc_domain,
                    severity="high",
                    detail=(
                        f"DMARC record `{dmarc_domain}` has a vulnerable NS delegation "
                        f"({ns_vuln}). Claiming the NS zone allows serving a forged DMARC "
                        f"policy — e.g. `p=none` to disable enforcement entirely, or "
                        f"`rua=mailto:attacker@evil.com` to intercept aggregate reports "
                        f"revealing the email infrastructure of `{scope_domain}`."
                    ),
                    program_name=program_name,
                    platform=platform,
                    indicators=[
                        f"_dmarc.{scope_domain} TXT record exists",
                        f"Authoritative NS zone for {dmarc_domain} → {ns_vuln} (vulnerable)",
                    ],
                ))
                logger.info(
                    "spf_dmarc: DMARC NS takeover for %s — ns=%s",
                    scope_domain, ns_vuln,
                )
        except dns.resolver.NXDOMAIN:
            pass
        except Exception:
            pass

    except Exception as exc:
        logger.debug("spf_dmarc: check failed for %s: %s", scope_domain, exc)

    return findings


async def _check_domain_ns_vulnerable(
    domain:   str,
    resolver,
    timeout:  float,
) -> Optional[str]:
    """
    Check whether the domain's authoritative NS delegation is vulnerable.

    Returns the vulnerable NS hostname if confirmed, None otherwise.

    Two-stage check:
      Stage A — resolve NS records for the domain via the bulk resolver.
                Any NS host that fails A-record resolution is a candidate.
      Stage B — confirm the candidate via confirm_ns_rcode() using the
                trusted confirmation resolver pool (same mechanism as the
                main NS takeover checker).  Only returns a result if
                trusted resolvers also see SERVFAIL/REFUSED/NXDOMAIN.
    """
    try:
        import dns.exception

        answer = await resolver.resolve(domain, "NS")
        candidates: List[str] = []
        for rdata in answer:
            ns_host = str(rdata.target).rstrip(".").lower()
            try:
                await resolver.resolve(ns_host, "A")
            except Exception:
                # NS host doesn't resolve on bulk resolver — candidate
                candidates.append(ns_host)

        if not candidates:
            return None

        # confirm each candidate via trusted resolvers
        from app.probing.dns_scanner.ns_confirmation import confirm_ns_rcode
        for ns_host in candidates:
            confirmed = await confirm_ns_rcode(
                domain=domain,
                ns=ns_host,
                expected_rcodes=("SERVFAIL", "REFUSED", "NXDOMAIN"),
            )
            if confirmed:
                logger.debug(
                    "spf_dmarc: NS vulnerability confirmed by trusted resolvers "
                    "for %s — ns=%s", domain, ns_host,
                )
                return ns_host
            else:
                logger.debug(
                    "spf_dmarc: NS candidate %s for %s NOT confirmed by trusted "
                    "resolvers — suppressing as likely false positive", ns_host, domain,
                )

    except Exception:
        pass
    return None