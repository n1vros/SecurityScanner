"""
Configuration management for STOscanner.
"""

import os
from pathlib import Path
from typing import Optional

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    HOST: str = Field(default="127.0.0.1", env="HOST")
    PORT: int = Field(default=8000, env="PORT")

    # Database
    DB_USERNAME: str = Field(default="postgres", env="DB_USERNAME")
    DB_PASSWORD: str = Field(default="postgres", env="DB_PASSWORD")
    DB_HOST: str = Field(default="localhost", env="DB_HOST")
    DB_PORT: int = Field(default=5432, env="DB_PORT")
    DB_NAME: str = Field(default="stoscanner", env="DB_NAME")
    DB_ECHO: bool = Field(default=False, env="DB_ECHO")
    DB_POOL_DISABLE: bool = Field(default=False, env="DB_POOL_DISABLE")
    DB_POOL_SIZE: int = Field(default=20, env="DB_POOL_SIZE")
    DB_MAX_OVERFLOW: int = Field(default=10, env="DB_MAX_OVERFLOW")
    DB_POOL_RECYCLE: int = Field(default=3600, env="DB_POOL_RECYCLE")

    @property
    def DATABASE_URL(self) -> str:
        return f"postgresql+asyncpg://{self.DB_USERNAME}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"

    # Rate limiting -- per domain
    RATE_LIMIT_PER_DOMAIN: float = Field(default=1.0, env="RATE_LIMIT_PER_DOMAIN")
    GLOBAL_CONCURRENCY_LIMIT: int = Field(default=100, env="GLOBAL_CONCURRENCY_LIMIT")
    RATE_LIMIT_BUCKET_SIZE: int = Field(default=5, env="RATE_LIMIT_BUCKET_SIZE")

    # ---------------------------------------------------------------------------
    # CDN-aware rate limiting
    # ---------------------------------------------------------------------------
    #
    # Each CDN gets a single shared token bucket across ALL subdomains sitting
    # behind it, regardless of how many different root domains are involved.
    # This prevents the scanner from hammering a CDN edge network just because
    # the subdomains happen to have different root domains.
    #
    # Values:
    #   > 0   -- max requests per second across all subdomains behind this CDN
    #   = 0   -- SKIP subdomains behind this CDN entirely this iteration
    #           (they will be retried on the next scan cycle automatically)
    #  empty / not set -- no CDN-level throttle (per-domain bucket still applies)
    #
    # Recommended conservative defaults during testing (set in your .env):
    #
    #   AKAMAI_RATE_LIMIT=0.5      Akamai is the most aggressive WAF -- 1 req/2s
    #   CLOUDFLARE_RATE_LIMIT=2.0  CF is more lenient but still rate-limits
    #   FASTLY_RATE_LIMIT=1.0      Fastly WAF triggers around 5+ req/s sustained
    #   CLOUDFRONT_RATE_LIMIT=2.0  CloudFront not takeable, but still rate-limits
    #   INCAPSULA_RATE_LIMIT=0.5   Imperva/Incapsula blocks scanners aggressively
    #   SUCURI_RATE_LIMIT=1.0      Sucuri is moderately strict
    #
    # Set AKAMAI_RATE_LIMIT=0 if you keep getting blocked and want to skip
    # Akamai-proxied targets entirely until you have a residential proxy setup.

    AKAMAI_RATE_LIMIT:     Optional[float] = Field(default=0.5,  env="AKAMAI_RATE_LIMIT")
    CLOUDFLARE_RATE_LIMIT: Optional[float] = Field(default=2.0,  env="CLOUDFLARE_RATE_LIMIT")
    FASTLY_RATE_LIMIT:     Optional[float] = Field(default=1.0,  env="FASTLY_RATE_LIMIT")
    CLOUDFRONT_RATE_LIMIT: Optional[float] = Field(default=2.0,  env="CLOUDFRONT_RATE_LIMIT")
    INCAPSULA_RATE_LIMIT:  Optional[float] = Field(default=0.5,  env="INCAPSULA_RATE_LIMIT")
    SUCURI_RATE_LIMIT:     Optional[float] = Field(default=1.0,  env="SUCURI_RATE_LIMIT")

    # Scanning
    SCAN_INTERVAL_HOURS: int = Field(default=24, env="SCAN_INTERVAL_HOURS")
    RESCAN_STALE_HOURS: int = Field(default=168, env="RESCAN_STALE_HOURS")
    PASSIVE_DISCOVERY_ENABLED: bool = Field(default=True, env="PASSIVE_DISCOVERY_ENABLED")
    ACTIVE_DISCOVERY_ENABLED: bool = Field(default=False, env="ACTIVE_DISCOVERY_ENABLED")
    ACTIVE_WORDLIST_PATH: Optional[str] = Field(default=None, env="ACTIVE_WORDLIST_PATH")
    ACTIVE_DISCOVERY_CONCURRENCY: int = Field(default=200, env="ACTIVE_DISCOVERY_CONCURRENCY")
    # Comma-separated resolver IPs. Supports 15k+ entries — written to a
    # process-scoped temp file at startup for puredns/massdns consumption.
    # Per-query UDP timeout used by the subdomain DNS prober.
    DNS_PROBE_TIMEOUT: int = Field(default=5, env="DNS_PROBE_TIMEOUT")
    DNS_RESOLVERS: str = Field(default="1.1.1.1,8.8.8.8", env="DNS_RESOLVERS")

    # ---------------------------------------------------------------------------
    # Resolver pool — auto-refresh from remote + local sources every 48h
    # ---------------------------------------------------------------------------
    # DNS_RESOLVER_URLS  — comma-separated URLs to download resolver lists from
    # DNS_RESOLVER_FILES — comma-separated paths to local resolver list files
    # DNS_RESOLVER_CACHE — path to write the merged+validated cache
    # DNS_RESOLVER_REFRESH_HOURS — how often to re-download and re-validate
    #
    # Example .env:
    #   DNS_RESOLVER_URLS=https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt,https://public-dns.info/nameservers.txt
    #   DNS_RESOLVER_FILES=files/my_resolvers.txt
    #   DNS_RESOLVER_CACHE=files/resolvers_cache.txt
    #   DNS_RESOLVER_REFRESH_HOURS=48
    # ---------------------------------------------------------------------------
    DNS_RESOLVER_URLS:           str   = Field(default="", env="DNS_RESOLVER_URLS")
    DNS_RESOLVER_FILES:          str   = Field(default="", env="DNS_RESOLVER_FILES")
    DNS_RESOLVER_CACHE:          str   = Field(default="files/resolvers_cache.txt", env="DNS_RESOLVER_CACHE")
    DNS_RESOLVER_REFRESH_HOURS:  float = Field(default=48.0, env="DNS_RESOLVER_REFRESH_HOURS")

    # Health-check tuning (applied during refresh and warm_pool sweeps)
    DNS_HEALTH_SAMPLE_SIZE:  int   = Field(default=200,  env="DNS_HEALTH_SAMPLE_SIZE")
    DNS_HEALTH_MAX_PROBES:   int   = Field(default=3,    env="DNS_HEALTH_MAX_PROBES")
    DNS_HEALTH_TIMEOUT:      float = Field(default=1.0,  env="DNS_HEALTH_TIMEOUT")
    DNS_HEALTH_CONCURRENCY:  int   = Field(default=2000, env="DNS_HEALTH_CONCURRENCY")
    DNS_HEALTH_MIN_LIVE:     int   = Field(default=50,   env="DNS_HEALTH_MIN_LIVE")
    PROGRAMS_LIMIT_PER_ITERATION: int = Field(default=10, env="PROGRAMS_LIMIT_PER_ITERATION")

    # Takeover detection
    POTENTIAL_RECHECK_LIMIT: int = Field(default=50, env="POTENTIAL_RECHECK_LIMIT")
    POTENTIAL_RECHECK_HOURS: int = Field(default=24, env="POTENTIAL_RECHECK_HOURS")
    POTENTIAL_LONG_RECHECK_HOURS: int = Field(default=72, env="POTENTIAL_LONG_RECHECK_HOURS")
    TAKEOVER_PROVIDER_VERIFY_COOLDOWN_HOURS: int = Field(
        default=24, env="TAKEOVER_PROVIDER_VERIFY_COOLDOWN_HOURS"
    )
    TAKEOVER_CHECK_RATE_LIMIT: float = Field(default=1.0, env="TAKEOVER_CHECK_RATE_LIMIT")

    # ---------------------------------------------------------------------------
    # Automatic takeover policy
    # ---------------------------------------------------------------------------
    # TAKEOVER_AUTO_ENABLED gates every provider *attempt* (resource creation /
    # claim). Detection, verification-only checks and alerting keep running when
    # it is false; per-provider credentials still gate each provider on top.
    TAKEOVER_AUTO_ENABLED: bool = Field(default=True, env="TAKEOVER_AUTO_ENABLED")
    # Transient outcomes (FAIL, UNAVAILABLE, failed claim validation) retry in
    # hours; ownership/manual outcomes (NEEDS_TXT, NOT_IMPL, provider-owned
    # elsewhere) retry in days. NOT_VULN and validated claims never retry.
    TAKEOVER_RETRY_HOURS: int = Field(default=24, env="TAKEOVER_RETRY_HOURS")
    TAKEOVER_RETRY_DAYS: int = Field(default=7, env="TAKEOVER_RETRY_DAYS")
    # A provider SUCCESS is only accepted when the claimed hostname serves this
    # marker (deployed by every auto-takeover provider via CLAIM_HTML).
    TAKEOVER_CLAIM_MARKER: str = Field(default="STO by Rizin", env="TAKEOVER_CLAIM_MARKER")
    TAKEOVER_CLAIM_VALIDATE_TIMEOUT: float = Field(
        default=15.0, env="TAKEOVER_CLAIM_VALIDATE_TIMEOUT"
    )
    TAKEOVER_CLAIM_VALIDATE_ATTEMPTS: int = Field(
        default=3, env="TAKEOVER_CLAIM_VALIDATE_ATTEMPTS"
    )

    TAKEOVER_SIGNATURES_PATH: str = Field(default="files/signatures.yaml", env="TAKEOVER_SIGNATURES_PATH")
    DNS_TAKEOVER_PROVIDERS_PATH: str = Field(default="files/dns_takeover_providers.yaml", env="DNS_TAKEOVER_PROVIDERS_PATH")
    NUCLEI_TEMPLATES_PATH: str = Field(default="app/nuclei/templates", env="NUCLEI_TEMPLATES_PATH")
    NUCLEI_BINARY: str = Field(default="nuclei", env="NUCLEI_BINARY")

    NS_CONFIRMATION_ENABLED: bool = Field(default=True, env="NS_CONFIRMATION_ENABLED")
    NS_CONFIRMATION_RESOLVERS: str = Field(
        default=(
            "1.1.1.1,1.0.0.1,"
            "8.8.8.8,8.8.4.4,"
            "9.9.9.9,149.112.112.112,"
            "208.67.222.222,208.67.220.220,"
            "64.6.64.6,64.6.65.6,"
            "185.228.168.9,185.228.169.9,"
            "94.140.14.14,94.140.15.15,"
            "76.76.19.19,76.223.122.150"
        ),
        env="NS_CONFIRMATION_RESOLVERS",
    )

    NS_CONFIRMATION_MIN_AGREE: int = Field(default=2, env="NS_CONFIRMATION_MIN_AGREE")
    NS_CONFIRMATION_TIMEOUT: float = Field(default=5.0, env="NS_CONFIRMATION_TIMEOUT")

    # Notifications
    DISCORD_WEBHOOK_URL: Optional[str] = Field(default=None, env="DISCORD_WEBHOOK_URL")
    DISCORD_WEBHOOK_URL_TEST: Optional[str] = Field(default=None, env="DISCORD_WEBHOOK_URL_TEST")

    NS_SWEEP_BATCH_SIZE: int = Field(default=1000, env="NS_SWEEP_BATCH_SIZE")
    NS_SWEEP_WARM_POOL_ENABLED: bool = Field(default=True, env="NS_SWEEP_WARM_POOL_ENABLED")
    NS_SWEEP_WARM_POOL_SAMPLE: int = Field(default=200, env="NS_SWEEP_WARM_POOL_SAMPLE")
    NS_SWEEP_WARM_POOL_MIN: int = Field(default=8, env="NS_SWEEP_WARM_POOL_MIN")
    NS_SWEEP_WARM_POOL_TIMEOUT: float = Field(default=1.0, env="NS_SWEEP_WARM_POOL_TIMEOUT")
    NS_SWEEP_WARM_POOL_CONCURRENCY: int = Field(default=200, env="NS_SWEEP_WARM_POOL_CONCURRENCY")
    NS_SWEEP_WARM_POOL_ATTEMPTS: int = Field(default=2, env="NS_SWEEP_WARM_POOL_ATTEMPTS")
    DNS_TAKEOVER_SWEEP_CONCURRENCY: int = Field(default=10, env="DNS_TAKEOVER_SWEEP_CONCURRENCY")
    NS_SWEEP_ENABLED: bool = Field(default=False, env="NS_SWEEP_ENABLED")
    NS_SWEEP_CONCURRENCY: int = Field(default=10, env="NS_SWEEP_CONCURRENCY")
    NS_SWEEP_INTERVAL_HOURS: int = Field(default=168, env="NS_SWEEP_INTERVAL_HOURS")

    # ---------------------------------------------------------------------------
    # SPF / DMARC dangling check
    # ---------------------------------------------------------------------------
    # Checks each scope domain's SPF include: targets and _dmarc NS delegation
    # for dangling conditions that allow email authentication bypass or DMARC
    # policy hijacking.  Runs once per NS sweep cycle alongside subdomain checks.
    #
    # Attack vectors detected:
    #   spf_include_nxdomain  — SPF include target is NXDOMAIN; re-registering the
    #                           domain allows publishing v=spf1 +all to bypass SPF.
    #   spf_include_takeover  — SPF include target's NS zone is claimable; attacker
    #                           can overwrite the SPF policy for scope_domain.
    #   dmarc_ns_takeover     — _dmarc.<scope> NS zone is claimable; attacker can
    #                           serve p=none or redirect rua= aggregate reports.
    #
    # ---------------------------------------------------------------------------
    # ---------------------------------------------------------------------------
    # Dangling cloud IP analysis (runs inside the NS sweep)
    # ---------------------------------------------------------------------------
    DANGLING_IP_CHECK_ENABLED:     bool  = Field(default=True,  env="DANGLING_IP_CHECK_ENABLED")
    DANGLING_IP_CLOUD_CLAIM_CHECK: bool  = Field(default=False, env="DANGLING_IP_CLOUD_CLAIM_CHECK")
    DANGLING_IP_CNAME_FOLLOW:      bool  = Field(default=True,  env="DANGLING_IP_CNAME_FOLLOW")
    DANGLING_IP_MX_CHECK:          bool  = Field(default=True,  env="DANGLING_IP_MX_CHECK")
    DANGLING_IP_HTTP_PROBE:        bool  = Field(default=True,  env="DANGLING_IP_HTTP_PROBE")
    DANGLING_IP_TLS_CHECK:         bool  = Field(default=True,  env="DANGLING_IP_TLS_CHECK")
    DANGLING_IP_PTR_CHECK:         bool  = Field(default=True,  env="DANGLING_IP_PTR_CHECK")
    DANGLING_IP_CONCURRENCY:       int   = Field(default=30,    env="DANGLING_IP_CONCURRENCY")
    DANGLING_IP_TIMEOUT:           float = Field(default=5.0,   env="DANGLING_IP_TIMEOUT")
    DANGLING_IP_PORTS:             str   = Field(default="22,80,443,3389,8080,8443", env="DANGLING_IP_PORTS")

    DANGLING_SPF_DMARC_CHECK: bool = Field(default=True, env="DANGLING_SPF_DMARC_CHECK")

    # Redis
    REDIS_URL: Optional[str] = Field(default=None, env="REDIS_URL")

    # External tools
    SUBFINDER_BINARY: str = Field(default="subfinder", env="SUBFINDER_BINARY")
    HTTPX_BINARY: str = Field(default="httpx", env="HTTPX_BINARY")

    # HackerOne
    H1_USERNAME: Optional[str] = Field(default=None, env="H1_USERNAME")
    H1_API_TOKEN: Optional[str] = Field(default=None, env="H1_API_TOKEN")

    # YesWeHack
    YWH_TOKEN: Optional[str] = Field(default=None, env="YWH_TOKEN")

    # Bugcrowd
    BC_SESSION:              Optional[str] = Field(default=None, env="BC_SESSION")
    BC_CROWDCONTROL_SESSION: Optional[str] = Field(default=None, env="BC_CROWDCONTROL_SESSION")

    # Intigrity
    INTI_TOKEN: Optional[str] = Field(default=None, env="INTI_TOKEN")

    # ---------------------------------------------------------------------------
    # Automatic platform sync
    # ---------------------------------------------------------------------------
    # The daemon resyncs each bounty platform independently. A platform is due
    # when now - last_synced_at >= its own interval in DAYS. Missing credentials
    # are skipped, never retried as an anonymous sync.
    PLATFORM_SYNC_ENABLED: bool = Field(default=True, env="PLATFORM_SYNC_ENABLED")
    PLATFORM_SYNC_POLL_SECONDS: int = Field(default=60, env="PLATFORM_SYNC_POLL_SECONDS")
    HACKERONE_SYNC_INTERVAL_DAYS: float = Field(default=7.0, env="HACKERONE_SYNC_INTERVAL_DAYS")
    YESWEHACK_SYNC_INTERVAL_DAYS: float = Field(default=7.0, env="YESWEHACK_SYNC_INTERVAL_DAYS")
    INTIGRITI_SYNC_INTERVAL_DAYS: float = Field(default=7.0, env="INTIGRITI_SYNC_INTERVAL_DAYS")
    BUGCROWD_SYNC_INTERVAL_DAYS: float = Field(default=7.0, env="BUGCROWD_SYNC_INTERVAL_DAYS")

    # HackenProof (cookie-based auth, both required)
    HP_CF_CLEARANCE:        Optional[str] = Field(default=None, env="HP_CF_CLEARANCE")
    HP_REMEMBER_USER_TOKEN: Optional[str] = Field(default=None, env="HP_REMEMBER_USER_TOKEN")

    # PUREDNS — resolvers come from DNS_RESOLVERS, not a separate path
    # With 15k+ resolvers the rate limit can be pushed much higher.
    # PUREDNS_RATE_LIMIT is per-resolver QPS fed to massdns under the hood,
    # so 500 QPS × 15k resolvers = ~7.5M queries/s theoretical ceiling.
    # Start at 500 and tune down if you see dropped packets.
    PUREDNS_BINARY: str = Field(default="puredns", env="PUREDNS_BINARY")
    PUREDNS_RATE_LIMIT: int = Field(default=500, env="PUREDNS_RATE_LIMIT")
    PUREDNS_TIMEOUT_SECS: int = Field(default=300, env="PUREDNS_TIMEOUT_SECS")
    PUREDNS_MAX_CONCURRENT: int = Field(default=4, env="PUREDNS_MAX_CONCURRENT")

    # Permutation scanning (alterx + puredns)
    ALTERX_ENABLED: bool = Field(default=True, env="ALTERX_ENABLED")
    ALTERX_BINARY: str = Field(default="alterx", env="ALTERX_BINARY")
    ALTERX_MAX_CONCURRENT: int = Field(default=3, env="ALTERX_MAX_CONCURRENT")
    ALTERX_TIMEOUT_SECS: int = Field(default=120, env="ALTERX_TIMEOUT_SECS")
    ALTERX_ENRICH_ALL: bool = Field(default=False, env="ALTERX_ENRICH_ALL")

    SUBFINDER_MAX_CONCURRENT: int = Field(default=3, env="SUBFINDER_MAX_CONCURRENT")
    SUBFINDER_TIMEOUT: int = Field(default=120, env="SUBFINDER_TIMEOUT")

    # JS scraping discovery
    JSSCRAPE_ENABLED:           bool          = Field(default=False,    env="JSSCRAPE_ENABLED")
    JSSCRAPE_RESCAN_HOURS:      int           = Field(default=336,     env="JSSCRAPE_RESCAN_HOURS")
    JSSCRAPE_GAU_BINARY:        str           = Field(default="gau",          env="JSSCRAPE_GAU_BINARY")
    JSSCRAPE_WAYBACKURLS_BIN:   str           = Field(default="waybackurls",  env="JSSCRAPE_WAYBACKURLS_BIN")
    JSSCRAPE_KATANA_BINARY:     str           = Field(default="katana",       env="JSSCRAPE_KATANA_BINARY")
    JSSCRAPE_KATANA_DEPTH:      int           = Field(default=2,       env="JSSCRAPE_KATANA_DEPTH")
    JSSCRAPE_KATANA_PAGES:      int           = Field(default=50,      env="JSSCRAPE_KATANA_PAGES")
    JSSCRAPE_FETCH_JITTER_MS:   int           = Field(default=300,     env="JSSCRAPE_FETCH_JITTER_MS")
    JSSCRAPE_FETCH_STAGGER_MS:  int           = Field(default=200,     env="JSSCRAPE_FETCH_STAGGER_MS")
    JSSCRAPE_FETCH_CONCURRENCY: int           = Field(default=10,      env="JSSCRAPE_FETCH_CONCURRENCY")
    JSSCRAPE_FETCH_TIMEOUT:     int           = Field(default=15,      env="JSSCRAPE_FETCH_TIMEOUT")
    JSSCRAPE_TOOL_TIMEOUT:      int           = Field(default=60,      env="JSSCRAPE_TOOL_TIMEOUT")
    JSSCRAPE_MAX_JS_SIZE:       int           = Field(default=524288,  env="JSSCRAPE_MAX_JS_SIZE")
    JSSCRAPE_MAX_URLS:          int           = Field(default=500,     env="JSSCRAPE_MAX_URLS")

    JS_SECRET_SCAN_ENABLED: bool = Field(default=False, env="JS_SECRET_SCAN_ENABLED")
    JS_SECRET_MAX_BODY_BYTES: int = Field(default=524288, env="JS_SECRET_MAX_BODY_BYTES")
    JS_SECRET_MIN_MATCH_LEN: int = Field(default=16, env="JS_SECRET_MIN_MATCH_LEN")
    JS_SECRET_TRUFFLEHOG: bool = Field(default=False, env="JS_SECRET_TRUFFLEHOG")
    JS_SECRET_TRUFFLEHOG_BIN: str = Field(default="trufflehog", env="JS_SECRET_TRUFFLEHOG_BIN")
    JS_SECRET_TRUFFLEHOG_TIMEOUT: int = Field(default=30, env="JS_SECRET_TRUFFLEHOG_TIMEOUT")

    # Git secret scanner (TruffleHog)
    GIT_SCANNER_ENABLED: bool = Field(default=False, env="GIT_SCANNER_ENABLED")
    GIT_SCANNER_INTERVAL_HOURS: float = Field(default=24.0, env="GIT_SCANNER_INTERVAL_HOURS")
    GIT_SCANNER_CONCURRENCY: int = Field(default=1, env="GIT_SCANNER_CONCURRENCY")
    GIT_CLONE_TMP_DIR: str = Field(default="/tmp/gitscan", env="GIT_CLONE_TMP_DIR")
    GIT_CLONE_TIMEOUT: int = Field(default=120, env="GIT_CLONE_TIMEOUT")
    GIT_CLONE_DELAY: float = Field(default=3.0, env="GIT_CLONE_DELAY")
    TRUFFLEHOG_BIN: str = Field(default="trufflehog", env="TRUFFLEHOG_BIN")
    TRUFFLEHOG_TIMEOUT: int = Field(default=300, env="TRUFFLEHOG_TIMEOUT")
    TRUFFLEHOG_ARCHIVE_MAX_SIZE: int = Field(default=104857600, env="TRUFFLEHOG_ARCHIVE_MAX_SIZE")
    TRUFFLEHOG_ARCHIVE_MAX_DEPTH: int = Field(default=1, env="TRUFFLEHOG_ARCHIVE_MAX_DEPTH")
    GITHUB_TOKEN: Optional[str] = Field(default=None, env="GITHUB_TOKEN")
    GITLAB_TOKEN: Optional[str] = Field(default=None, env="GITLAB_TOKEN")

    # Exposure scanner
    EXPOSURE_SCAN_ENABLED:     bool = Field(default=False, env="EXPOSURE_SCAN_ENABLED")
    EXPOSURE_SCAN_TIMEOUT:     int  = Field(default=5,    env="EXPOSURE_SCAN_TIMEOUT")
    EXPOSURE_SCAN_CONCURRENCY: int  = Field(default=3,    env="EXPOSURE_SCAN_CONCURRENCY")
    EXPOSURE_WORDLIST_PATH:    str  = Field(default="files/exposure_paths.yaml", env="EXPOSURE_WORDLIST_PATH")
    EXPOSURE_RENOTIFY_DAYS:    int  = Field(default=30,   env="EXPOSURE_RENOTIFY_DAYS")
    # Number of random subdomains selected per exposure loop iteration
    EXPOSURE_BATCH_SIZE:       int  = Field(default=100,  env="EXPOSURE_BATCH_SIZE")
    # Directory where raw file contents of findings are saved
    # Subdirectories: git/ env/ cert/ db/ bak/
    EXPOSURE_FINDINGS_PATH:    str  = Field(default="/findings", env="EXPOSURE_FINDINGS_PATH")

    # Domain buy / availability scanner
    DOMAIN_BUY_SCANNER_ENABLED:  bool = Field(default=True, env="DOMAIN_BUY_SCANNER_ENABLED")
    # Re-notify interval for already-alerted available domains (hours)
    DOMAIN_BUY_RENOTIFY_HOURS:   int  = Field(default=48,   env="DOMAIN_BUY_RENOTIFY_HOURS")
    DOMAIN_BUY_WHOIS_MIN_INTERVAL_SECONDS: float = Field(default=2.0, env="DOMAIN_BUY_WHOIS_MIN_INTERVAL_SECONDS")
    DOMAIN_BUY_WHOIS_RATE_LIMIT_BACKOFF_SECONDS: float = Field(default=15.0, env="DOMAIN_BUY_WHOIS_RATE_LIMIT_BACKOFF_SECONDS")
    # Max consecutive WHOIS failures before giving up on a domain entirely
    DOMAIN_BUY_WHOIS_RETRY_LIMIT: int = Field(default=5,    env="DOMAIN_BUY_WHOIS_RETRY_LIMIT")

    HTTP_PROXY: Optional[str] = Field(default=None, env="HTTP_PROXY")

    # Logging
    LOG_LEVEL: str = Field(default="INFO", env="LOG_LEVEL")
    LOG_FORMAT: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        env="LOG_FORMAT",
    )
    LOG_FILE: Optional[str] = Field(default=None, env="LOG_FILE")

    # Daemon
    ACTIVE_TASKS_TIMEOUT_SECONDS: int = Field(default=300, env="ACTIVE_TASKS_TIMEOUT_SECONDS")
    SCOPE_CONCURRENCY: int = Field(default=5, env="SCOPE_CONCURRENCY")
    SUBDOMAINS_LIMIT_PER_SCOPE: int = Field(default=1000, env="SUBDOMAINS_LIMIT_PER_SCOPE")
    # Opt-in: start the scanner daemon when the web app starts. Off by default;
    # the UI and `python main.py start` control it explicitly.
    DAEMON_AUTOSTART: bool = Field(default=False, env="DAEMON_AUTOSTART")
    DAEMON_SLEEP_SECONDS: int = Field(default=60, env="DAEMON_SLEEP_SECONDS")
    DAEMON_MAX_ITERATIONS: Optional[int] = Field(default=None, env="DAEMON_MAX_ITERATIONS")

    # Takeover providers
    VERCEL_TOKEN:      Optional[str] = Field(default=None, env="VERCEL_TOKEN")
    VERCEL_PROJECT_ID: Optional[str] = Field(default=None, env="VERCEL_PROJECT_ID")
    HEROKU_API_KEY:    Optional[str] = Field(default=None, env="HEROKU_API_KEY")
    NETLIFY_TOKEN:     Optional[str] = Field(default=None, env="NETLIFY_TOKEN")
    AWS_ACCESS_KEY_ID:     Optional[str] = Field(default=None, env="AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY: Optional[str] = Field(default=None, env="AWS_SECRET_ACCESS_KEY")

    # Azure takeover provider
    AZURE_TENANT_ID:       Optional[str] = Field(default=None, env="AZURE_TENANT_ID")
    AZURE_CLIENT_ID:       Optional[str] = Field(default=None, env="AZURE_CLIENT_ID")
    AZURE_CLIENT_SECRET:   Optional[str] = Field(default=None, env="AZURE_CLIENT_SECRET")
    AZURE_SUBSCRIPTION_ID: Optional[str] = Field(default=None, env="AZURE_SUBSCRIPTION_ID")
    AZURE_RESOURCE_GROUP:  Optional[str] = Field(default=None, env="AZURE_RESOURCE_GROUP")
    AZURE_LOCATION:        str           = Field(default="eastus", env="AZURE_LOCATION")

    POC_IP: Optional[str] = Field(default=None, env="POC_IP")
    POC_TXT: str = Field(default="Bugbounty - DNS takeover POC by Rizin", env="POC_TXT")
    POC_TTL: int = Field(default=60, env="ROUTE53_POC_TTL")

    ROUTE53_TAKEOVER_ENABLED: bool = Field(default=True, env="ROUTE53_TAKEOVER_ENABLED")
    ROUTE53_MAX_ATTEMPTS: int = Field(default=200, env="ROUTE53_MAX_ATTEMPTS")
    ROUTE53_SLEEP_BETWEEN: float = Field(default=1.0, env="ROUTE53_SLEEP_BETWEEN")

    AZURE_DNS_TAKEOVER_ENABLED: bool = Field(default=True, env="AZURE_DNS_TAKEOVER_ENABLED")
    AZURE_DNS_NUM_GROUPS: int = Field(default=20, env="AZURE_DNS_NUM_GROUPS")
    AZURE_DNS_LOCATION: str = Field(default="eastus", env="AZURE_DNS_LOCATION")


    # ---------------------------------------------------------------------------
    # DNS takeover — runtime settings
    # ---------------------------------------------------------------------------
    DNS_TAKEOVER_ENABLED:       bool  = Field(default=True,  env="DNS_TAKEOVER_ENABLED")
    DNS_TAKEOVER_TIMEOUT:       int   = Field(default=3,     env="DNS_TAKEOVER_TIMEOUT")
    DNS_TAKEOVER_RENOTIFY_HOURS: int  = Field(default=24,    env="DNS_TAKEOVER_RENOTIFY_HOURS")

    # ---------------------------------------------------------------------------
    # Certstream CT log monitoring
    # ---------------------------------------------------------------------------
    CERTSTREAM_TAKEOVER_CHECK_ENABLED: bool = Field(default=True, env="CERTSTREAM_TAKEOVER_CHECK_ENABLED")
    CERTSTREAM_ENABLED:            bool  = Field(default=True,                        env="CERTSTREAM_ENABLED")
    CERTSTREAM_URL:                str   = Field(default="wss://certstream.calidog.io", env="CERTSTREAM_URL")
    CERTSTREAM_SCOPE_REFRESH_SECS: int   = Field(default=300,                         env="CERTSTREAM_SCOPE_REFRESH_SECS")
    CERTSTREAM_RECONNECT_SECS:     int   = Field(default=5,                           env="CERTSTREAM_RECONNECT_SECS")
    CERTSTREAM_SKIP_WILDCARDS:     bool  = Field(default=True,                        env="CERTSTREAM_SKIP_WILDCARDS")

    # ---------------------------------------------------------------------------
    # Wayback discovery
    # ---------------------------------------------------------------------------
    WAYBACK_GAU_BINARY:   str  = Field(default="gau",         env="WAYBACK_GAU_BINARY")
    WAYBACK_WAYBACKURLS_BIN: str = Field(default="waybackurls", env="WAYBACK_WAYBACKURLS_BIN")
    WAYBACK_ENABLED:      bool = Field(default=True,  env="WAYBACK_ENABLED")
    WAYBACK_TOOL_TIMEOUT: int  = Field(default=90,    env="WAYBACK_TOOL_TIMEOUT")
    WAYBACK_MAX_URLS:     int  = Field(default=50000, env="WAYBACK_MAX_URLS")

    # ---------------------------------------------------------------------------
    # Exposure scanner — additional
    # ---------------------------------------------------------------------------
    EXPOSURE_RATE_LIMIT: int = Field(default=10, env="EXPOSURE_RATE_LIMIT")

    # ---------------------------------------------------------------------------
    # IP hunter
    # ---------------------------------------------------------------------------
    IP_HUNTER_MODE:               str           = Field(default="off",   env="IP_HUNTER_MODE")
    IP_HUNTER_ENABLED:            bool          = Field(default=False, env="IP_HUNTER_ENABLED")
    IP_HUNTER_INTERVAL_HOURS:     float           = Field(default=6,     env="IP_HUNTER_INTERVAL_HOURS")
    IP_HUNTER_ATTEMPTS_PER_BLOCK: int           = Field(default=50,    env="IP_HUNTER_ATTEMPTS_PER_BLOCK")
    IP_HUNTER_TOP_BLOCKS:         int           = Field(default=20,    env="IP_HUNTER_TOP_BLOCKS")
    IP_HUNTER_MIN_FREE_RATIO:     float         = Field(default=0.3,   env="IP_HUNTER_MIN_FREE_RATIO")
    IP_HUNTER_MIN_DENSITY:        int           = Field(default=2,     env="IP_HUNTER_MIN_DENSITY")

    # ---------------------------------------------------------------------------
    # CIDR index (used by IP hunter)
    # ---------------------------------------------------------------------------
    CIDR_INDEX_CACHE_PATH:    str = Field(default="files/cidr_cache", env="CIDR_INDEX_CACHE_PATH")
    CIDR_INDEX_MAX_AGE_HOURS: int = Field(default=24,                 env="CIDR_INDEX_MAX_AGE_HOURS")

    # ---------------------------------------------------------------------------
    # AWS EIP hunter
    # ---------------------------------------------------------------------------
    AWS_EIP_REGIONS:  str = Field(default="us-east-1,us-west-2,eu-west-1,ap-southeast-1", env="AWS_EIP_REGIONS")
    AWS_EIP_SLEEP_MS: int = Field(default=200, env="AWS_EIP_SLEEP_MS")

    # Max duplicate EIPs to hold simultaneously to force AWS pool diversification.
    # Set to (quota - 1 - expected_findings). Default assumes quota=5.
    # If you raised your quota to 20, set AWS_EIP_DUP_HOLD=14 (20 - 1 - 5 findings).
    AWS_EIP_DUP_HOLD: int = Field(default=4, env="AWS_EIP_DUP_HOLD")

    # ---------------------------------------------------------------------------
    # DigitalOcean Reserved IP hunter
    # ---------------------------------------------------------------------------
    DO_API_TOKEN:    Optional[str] = Field(default=None, env="DO_API_TOKEN")
    DO_EIP_REGIONS:    str = Field(default="nyc1,nyc3,sfo3,ams3,sgp1,lon1,fra1,blr1,tor1,syd1", env="DO_EIP_REGIONS")
    DO_EIP_ATTEMPTS:   int = Field(default=50,  env="DO_EIP_ATTEMPTS")
    DO_EIP_SLEEP_MS:   int = Field(default=500, env="DO_EIP_SLEEP_MS")
    DO_EIP_BATCH_SIZE: int = Field(default=5,   env="DO_EIP_BATCH_SIZE")   # max 25 (DO reserved IP quota)

    # ---------------------------------------------------------------------------
    # GCP Static External IP hunter
    # ---------------------------------------------------------------------------
    GCP_PROJECT_ID:           Optional[str] = Field(default=None, env="GCP_PROJECT_ID")
    GCP_SERVICE_ACCOUNT_JSON: Optional[str] = Field(default=None, env="GCP_SERVICE_ACCOUNT_JSON")
    GCP_SERVICE_ACCOUNT_KEY:  Optional[str] = Field(default=None, env="GCP_SERVICE_ACCOUNT_KEY")
    GCP_EIP_REGIONS:          str = Field(default="us-central1,us-east1,europe-west1,asia-southeast1", env="GCP_EIP_REGIONS")
    GCP_EIP_ATTEMPTS:         int = Field(default=20,   env="GCP_EIP_ATTEMPTS")
    GCP_EIP_SLEEP_MS:         int = Field(default=1000, env="GCP_EIP_SLEEP_MS")
    GCP_EIP_BATCH_SIZE:       int = Field(default=3,    env="GCP_EIP_BATCH_SIZE")  # max 8 (GCP static IP quota per region)

    # ---------------------------------------------------------------------------
    # Azure Public IP hunter
    # ---------------------------------------------------------------------------
    AZURE_PIP_REGIONS:  str = Field(default="eastus,westus2,westeurope,southeastasia", env="AZURE_PIP_REGIONS")
    AZURE_PIP_ATTEMPTS: int = Field(default=20, env="AZURE_PIP_ATTEMPTS")
    AZURE_PIP_SLEEP_MS: int = Field(default=1000, env="AZURE_PIP_SLEEP_MS")

    # ---------------------------------------------------------------------------
    # IP check (liveness port scan)
    # ---------------------------------------------------------------------------
    IP_CHECK_ENABLED:     bool  = Field(default=True,                    env="IP_CHECK_ENABLED")
    IP_CHECK_PORTS:       str   = Field(default="22,80,443,3389,8080,8443", env="IP_CHECK_PORTS")
    IP_CHECK_TIMEOUT:     float = Field(default=5.0,                     env="IP_CHECK_TIMEOUT")
    IP_CHECK_CONCURRENCY: int   = Field(default=20,                      env="IP_CHECK_CONCURRENCY")

    #
    # IP_HUNTER_CONFIRM_TIMEOUT — per-port TCP connect timeout in seconds.
    #   Lower = faster scan but more missed open ports on slow hosts.
    #   Recommended: 1.5–3.0s.
    #
    # IP_HUNTER_CONFIRM_CONCURRENCY — max simultaneous TCP connect attempts.
    #   Higher = faster scan; keep below OS ulimit (default is safe at 50).
    #
    # IP_HUNTER_CONFIRM_HTTP — also probe http://<ip>/ and https://<ip>/.
    #   A 2xx/3xx response flags the IP as "uncertain" (not confirmed free).
    #
    # IP_HUNTER_CONFIRM_PTR — do a reverse-DNS PTR lookup.
    #   Result shown in Discord alert for operator context.
    #
    # IP_HUNTER_INFORM_CONCURRENCY — max IPs checked in parallel in INFORM mode.
    #   Each check runs a full port scan, so keep this modest.
    #
    # IP_HUNTER_ASN_LOOKUP — enable Team Cymru DNS TXT ASN lookups for the
    #   extended provider list (Linode, Vultr, Hetzner, etc.).
    #   Requires:  pip install dnspython
    #   Without dnspython only CIDRIndex providers (AWS/Azure/GCP/DO) are detected.
    # ---------------------------------------------------------------------------

    IP_HUNTER_CONFIRM_PORTS: str = Field(default="", env="IP_HUNTER_CONFIRM_PORTS")
    IP_HUNTER_CONFIRM_TIMEOUT: float = Field(default=2.0, env="IP_HUNTER_CONFIRM_TIMEOUT")
    IP_HUNTER_CONFIRM_CONCURRENCY: int = Field(default=50, env="IP_HUNTER_CONFIRM_CONCURRENCY")
    IP_HUNTER_CONFIRM_HTTP: bool = Field(default=True, env="IP_HUNTER_CONFIRM_HTTP")
    IP_HUNTER_CONFIRM_PTR: bool = Field(default=True, env="IP_HUNTER_CONFIRM_PTR")
    IP_HUNTER_INFORM_CONCURRENCY: int = Field(default=20, env="IP_HUNTER_INFORM_CONCURRENCY")
    IP_HUNTER_ASN_LOOKUP: bool = Field(default=False, env="IP_HUNTER_ASN_LOOKUP")
    # Per-provider on/off switches
    AWS_EIP_ENABLED: bool = Field(default=True, env="AWS_EIP_ENABLED")
    GCP_EIP_ENABLED: bool = Field(default=True, env="GCP_EIP_ENABLED")
    AZURE_PIP_ENABLED: bool = Field(default=True, env="AZURE_PIP_ENABLED")
    DO_EIP_ENABLED: bool = Field(default=True, env="DO_EIP_ENABLED")
    
    VULNERABLE_IP_PROVIDERS_PATH: str = Field(
        default="files/vulnerable_ip_providers.yaml",
        env="VULNERABLE_IP_PROVIDERS_PATH"
    )

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"

    @field_validator("DNS_RESOLVERS")
    @classmethod
    def validate_dns_resolvers(cls, v):
        if not v:
            return "1.1.1.1,8.8.8.8"
        return v

    @field_validator("ACTIVE_WORDLIST_PATH")
    @classmethod
    def validate_wordlist_path(cls, v):
        if not v:
            return v
        path = Path(v)
        if not path.is_absolute():
            project_root = Path(__file__).parent.parent.parent
            path = project_root / path
        if not path.exists():
            raise ValueError(f"Wordlist path does not exist: {path}")
        return str(path)

    @field_validator("DAEMON_MAX_ITERATIONS", mode="before")
    @classmethod
    def validate_daemon_max_iterations(cls, v):
        if v == "":
            return None
        return v

    @model_validator(mode="before")
    @classmethod
    def assemble_db_url_from_components(cls, values):
        if values.get("DATABASE_URL"):
            return values
        username = values.get("DB_USERNAME", "postgres")
        password = values.get("DB_PASSWORD", "postgres")
        host     = values.get("DB_HOST", "localhost")
        port     = values.get("DB_PORT", 5432)
        db_name  = values.get("DB_NAME", "stoscanner")
        values["DATABASE_URL"] = (
            f"postgresql+asyncpg://{username}:{password}@{host}:{port}/{db_name}"
        )
        return values


settings = Settings()
