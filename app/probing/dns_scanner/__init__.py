"""
app/probing/dns_scanner/

Unified DNS security scanner package.

Structure
---------
  __init__.py          — public re-exports (drop-in for old dns_takeover imports)
  db_models.py            — all dataclasses / result types
  resolvers.py         — UDP query helpers, resolver pool management
  ns_confirmation.py   — trusted-resolver confirmation for NS takeover findings
  ns_providers.py      — VulnerableNSProvider loader from YAML
  ns_checker.py        — DNSScanner: NS takeover detection logic
  ip_providers.py      — vulnerable IP provider YAML loader
  ip_indicators.py     — PTR / header / TLS / direct-claim analysis helpers
  ip_analyzer.py       — DanglingIPAnalyzer: full IP dangling analysis pipeline
  cname_follower.py    — CNAME chain follower for dangling IP via CNAME
  sweeper.py           — SubdomainNSSweeper: batch orchestrator + DB persistence

Config keys (.env) — all with defaults, no new required keys:
  DNS_TAKEOVER_ENABLED          bool    default True
  DNS_TAKEOVER_TIMEOUT          float   default 3.0
  DNS_TAKEOVER_PROVIDERS_PATH   str     default "files/dns_takeover_providers.yaml"
  NS_CONFIRMATION_ENABLED       bool    default True
  NS_CONFIRMATION_TIMEOUT       float   default 5.0
  NS_CONFIRMATION_MIN_AGREE     int     default 2
  NS_CONFIRMATION_RESOLVERS     str     comma-separated trusted resolvers
  NS_SWEEP_INTERVAL_HOURS       int     default 168
  NS_SWEEP_CONCURRENCY          int     default 10
  DANGLING_IP_CHECK_ENABLED     bool    default True
  DANGLING_IP_PORTS             str     default "22,80,443,3389,8080,8443"
  DANGLING_IP_TIMEOUT           float   default 5.0
  DANGLING_IP_HTTP_PROBE        bool    default True
  DANGLING_IP_PTR_CHECK         bool    default True
  DANGLING_IP_TLS_CHECK         bool    default True
  DANGLING_IP_CLOUD_CLAIM_CHECK bool    default False  (requires cloud creds)
  DANGLING_IP_CONCURRENCY       int     default 30
  DANGLING_IP_CNAME_FOLLOW      bool    default True
  VULNERABLE_IP_PROVIDERS_PATH  str     default "files/vulnerable_ip_providers.yaml"
"""

from app.probing.dns_scanner.models import (
    NSFinding,
    DanglingIPFinding,
    ScanResult,
)
from app.probing.dns_scanner.ns_checker import DNSScanner
from app.probing.dns_scanner.sweeper import SubdomainNSSweeper

# Backward-compatibility aliases so daemon.py import still works unchanged
DNSTakeoverProber  = DNSScanner
DNSTakeoverFinding = NSFinding
SubdomainNSFinding = NSFinding

__all__ = [
    "DNSScanner",
    "SubdomainNSSweeper",
    "NSFinding",
    "DanglingIPFinding",
    "ScanResult",
    # compat
    "DNSTakeoverProber",
    "DNSTakeoverFinding",
    "SubdomainNSFinding",
]