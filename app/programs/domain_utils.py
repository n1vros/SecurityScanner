"""
app/programs/domain_utils.py

Shared domain extraction utilities for platform integrations.

All regex, TLD lists, platform blocklists, and extraction logic live here.
Platform files (hackerone.py, yeswehack.py, intigriti.py) import from this
module — nothing domain-related should be defined in those files directly.
"""

import re
from typing import List

# ---------------------------------------------------------------------------
# PSL-based registered domain extraction
# ---------------------------------------------------------------------------
# tldextract uses the Mozilla Public Suffix List — it correctly handles
# gouv.fr, gov.br, edu.cn, gc.ca and every other public suffix automatically.
# Install with: pip install tldextract
#
# If not installed, falls back to a minimal hand-rolled set. The fallback
# will mis-classify some public suffixes (gouv.fr etc.) so install tldextract.

try:
    import tldextract as _tldextract

    _extractor = _tldextract.TLDExtract(include_psl_private_domains=False)

    def _registered_domain_psl(hostname: str) -> str:
        r = _extractor(hostname)
        if not r.domain or not r.suffix:
            return ""
        return f"{r.domain}.{r.suffix}"

    _USE_TLDEXTRACT = True

except ImportError:
    _USE_TLDEXTRACT = False

    # Minimal fallback — extend if you're not installing tldextract
    _FALLBACK_TWO_PART_TLDS: frozenset = frozenset({
        "co.uk", "co.jp", "co.nz", "co.za", "co.in", "co.kr",
        "com.au", "com.br", "com.cn", "com.mx", "com.ar",
        "net.au", "org.au", "gov.au", "edu.au",
        "ac.uk", "gov.uk", "org.uk", "me.uk",
        "ne.jp", "or.jp", "ac.jp",
        # Common public suffixes missed by minimal lists
        "gouv.fr", "asso.fr", "nom.fr",
        "gov.br", "mil.br", "edu.br", "org.br", "net.br",
        "gov.in", "mil.in", "edu.in",
        "gov.cn", "edu.cn", "mil.cn", "net.cn", "org.cn",
        "gov.sg", "edu.sg",
        "gov.za", "edu.za", "mil.za", "net.za", "org.za",
        "gov.pl", "edu.pl",
        "gov.ru", "edu.ru",
        "gob.es", "com.es", "org.es", "edu.es",
        "gc.ca",
    })


# ---------------------------------------------------------------------------
# Platform infrastructure blocklist
# ---------------------------------------------------------------------------
# Domains that are hosting/platform infrastructure, not company-owned scope.
# Scopes pointing here are almost always mislabelled user-pages or source
# links, not real subdomain takeover targets.
#
# Exception: if the program name contains an owner token (see PLATFORM_OWNERS),
# the domain is kept — e.g. the "GitHub" program legitimately lists github.com.

PLATFORM_DOMAINS: frozenset = frozenset({
    # GitHub
    "github.com", "github.io", "githubusercontent.com", "githubassets.com",
    # GitLab
    "gitlab.com", "gitlab.io",
    # Bitbucket
    "bitbucket.org", "bitbucket.io",
    # Hosting platforms
    "heroku.com", "herokuapp.com",
    "netlify.com", "netlify.app",
    "vercel.com", "vercel.app",
    "pages.dev",                        # Cloudflare Pages
    "web.app", "firebaseapp.com",       # Firebase Hosting
    "azurewebsites.net",
    "cloudfront.net",
    "amazonaws.com",
    "azure.com", "azurefd.net",
    "trafficmanager.net",
    # Tech giants — appear as CDN/OAuth/login endpoints in unrelated scopes
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "apple.com", "icloud.com",
    # SaaS tools — not scan targets
    "atlassian.com", "atlassian.net", "jira.com", "confluence.com",
    "slack.com", "salesforce.com",
    # Social / package registries — appear as oauth/dependency references
    "twitter.com", "x.com",
    "wordpress.org", "wordpress.com",
    "npmjs.com",
    # Third-party anti-bot / API gateway services
    "captcha-delivery.com", "datadome.co",
    "apigee.net", "apigee.com",
    # Platform sandboxes
    "intigriti.rocks",                  # Intigriti's own sandbox
})

PLATFORM_OWNERS: dict = {
    "github.com":            {"github"},
    "github.io":             {"github"},
    "githubusercontent.com": {"github"},
    "githubassets.com":      {"github"},
    "gitlab.com":            {"gitlab"},
    "gitlab.io":             {"gitlab"},
    "bitbucket.org":         {"bitbucket", "atlassian"},
    "bitbucket.io":          {"bitbucket", "atlassian"},
    "heroku.com":            {"heroku", "salesforce"},
    "herokuapp.com":         {"heroku", "salesforce"},
    "netlify.com":           {"netlify"},
    "netlify.app":           {"netlify"},
    "vercel.com":            {"vercel"},
    "vercel.app":            {"vercel"},
    "pages.dev":             {"cloudflare"},
    "web.app":               {"google", "firebase"},
    "firebaseapp.com":       {"google", "firebase"},
    "azurewebsites.net":     {"microsoft"},
    "cloudfront.net":        {"amazon", "aws"},
    "amazonaws.com":         {"amazon", "aws"},
    "azure.com":             {"microsoft"},
    "azurefd.net":           {"microsoft"},
    "trafficmanager.net":    {"microsoft"},
    # Tech giants
    "google.com":            {"google"},
    "googleapis.com":        {"google"},
    "gstatic.com":           {"google"},
    "googleusercontent.com": {"google"},
    "apple.com":             {"apple"},
    "icloud.com":            {"apple"},
    # SaaS tools
    "atlassian.com":         {"atlassian"},
    "atlassian.net":         {"atlassian"},
    "jira.com":              {"atlassian"},
    "confluence.com":        {"atlassian"},
    "slack.com":             {"slack"},
    "salesforce.com":        {"salesforce"},
    # Social / registries
    "twitter.com":           {"twitter"},
    "x.com":                 {"twitter", "x"},
    "wordpress.org":         {"wordpress", "automattic"},
    "wordpress.com":         {"wordpress", "automattic"},
    "npmjs.com":             {"npm", "npmjs"},
    # Anti-bot / API gateway
    "captcha-delivery.com":  {"datadome"},
    "datadome.co":           {"datadome"},
    "apigee.net":            {"apigee", "google"},
    "apigee.com":            {"apigee", "google"},
    # Platform sandboxes
    "intigriti.rocks":       {"intigriti"},
}


# ---------------------------------------------------------------------------
# Compiled regexes
# ---------------------------------------------------------------------------

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# *.example.com  *.sub.example.co.uk  https://*.example.com/path
WILDCARD_RE = re.compile(
    r"(?:^|[\s/])\*\.([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+)",
    re.IGNORECASE,
)

# Plain FQDNs including inside URLs
FQDN_RE = re.compile(
    r"(?:^|[\s/])([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+)"
    r"(?:$|[\s/:])",
    re.IGNORECASE,
)

# Detects alternation groups like (com|co.uk|ca) anywhere in a scope string.
# Matches the full group including surrounding parens.
_ALTERNATION_RE = re.compile(r"\(([^)]+)\)")


# ---------------------------------------------------------------------------
# Alternation expansion
# ---------------------------------------------------------------------------

def expand_alternations(value: str) -> List[str]:
    """
    Expand alternation groups in scope strings, handling multiple groups and
    nested repetition until no groups remain.

    Examples:
        "*.vfsglobal.(com|co.uk|ca)"
            -> ["*.vfsglobal.com", "*.vfsglobal.co.uk", "*.vfsglobal.ca"]

        "*.example.(com|net) (api|pay).example.org"
            -> ["*.example.com (api|pay).example.org",
                "*.example.net (api|pay).example.org",
                ... all 4 combos ...]

        "*.example.com"  (no alternation)
            -> ["*.example.com"]
    """
    results = [value]

    # Keep expanding until no alternation groups remain in any candidate.
    # Bounded by a safety cap to guard against pathological inputs.
    max_passes = 10
    for _ in range(max_passes):
        next_results: List[str] = []
        changed = False
        for candidate in results:
            m = _ALTERNATION_RE.search(candidate)
            if not m:
                next_results.append(candidate)
                continue
            changed = True
            options = m.group(1).split("|")
            for opt in options:
                next_results.append(
                    candidate[: m.start()] + opt.strip() + candidate[m.end() :]
                )
        results = next_results
        if not changed:
            break

    return results


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

# Rejects mobile bundle IDs like quora.android, app.mobile, com.example.ios
_VALID_TLDS: frozenset = frozenset({
    "com", "net", "org", "io", "co", "ai", "app", "dev", "cloud", "digital",
    "tech", "online", "site", "web", "info", "biz", "pro", "inc", "ltd",
    "llc", "group", "team", "agency", "studio", "media", "services", "solutions",
    "systems", "software", "platform", "api", "mail", "email",
    "uk", "de", "fr", "nl", "be", "ch", "at", "se", "no", "dk", "fi",
    "es", "it", "pt", "pl", "cz", "hu", "ro", "bg", "hr", "sk", "si",
    "us", "ca", "au", "nz", "jp", "cn", "kr", "sg", "hk", "tw", "in",
    "br", "mx", "ar", "cl", "za", "ng", "ke", "eg", "il", "ae", "sa",
    "tr", "ru", "ua", "by", "kz", "id", "my", "th", "vn", "ph",
    "gov", "edu", "mil", "int", "eu", "tv", "fm", "am", "me", "ly",
    "gg", "sh", "ac", "cc", "ws", "gl", "vc", "is", "to", "rocks",
    "xyz", "live", "shop", "store", "money", "finance", "bank", "fund",
    "health", "care", "legal", "law", "network", "zone", "space",
    "works", "tools", "blog", "news", "press", "today", "company",
    "business", "ventures", "partners", "global", "world",
    "international", "holdings", "capital",
})


def is_valid_domain(d: str) -> bool:
    """Return True if d looks like a real domain (not an IP, not a bare label,
    and not a mobile bundle ID like quora.android or app.mobile)."""
    if not d or "." not in d:
        return False
    if IP_RE.match(d):
        return False
    parts = d.split(".")
    if len(parts) < 2 or not all(len(p) > 0 for p in parts):
        return False
    return parts[-1].lower() in _VALID_TLDS


def registered_domain(hostname: str) -> str:
    """
    Return the eTLD+1 of *hostname*, stripping scheme, path, port, and
    leading wildcard. Returns empty string for IPs and bare labels.

    Uses tldextract (Mozilla PSL) when installed, falls back to hand-rolled
    two-part TLD list otherwise.
    """
    hostname = re.sub(r"(?i)^https?://", "", hostname)
    hostname = hostname.split("/")[0].split(":")[0]
    hostname = re.sub(r"^\*\.", "", hostname).strip().lower()

    if not hostname or IP_RE.match(hostname):
        return ""

    if _USE_TLDEXTRACT:
        result = _registered_domain_psl(hostname)
        return result if is_valid_domain(result) else ""

    # Fallback: hand-rolled two-part TLD check
    parts = hostname.split(".")
    if len(parts) < 2:
        return ""
    if len(parts) >= 3 and ".".join(parts[-2:]) in _FALLBACK_TWO_PART_TLDS:
        result = ".".join(parts[-3:])
    else:
        result = ".".join(parts[-2:])
    return result if is_valid_domain(result) else ""


def wildcard_parent(hostname: str) -> str:
    """
    Return the meaningful parent scope for a wildcard target.

    For *.api.example.com the wildcarded host is api.example.com — that's
    one level above eTLD+1, meaning the program explicitly scopes api.example.com
    as a subdomain namespace worth scanning independently. We return it so the
    caller can save both api.example.com AND example.com as scopes.

    Returns "" when the wildcard host IS the registered domain (*.example.com),
    since there is no intermediate parent to save.

    Examples:
        api.example.com       -> "api.example.com"   (one level above eTLD+1)
        sub.api.example.com   -> "api.example.com"   (collapse deep wildcards to one above eTLD+1)
        example.com           -> ""                  (already eTLD+1, no parent)
        example.co.uk         -> ""                  (already eTLD+1 for two-part TLD)
    """
    reg = registered_domain(hostname)
    if not reg or hostname == reg:
        return ""

    # Strip the registered domain suffix to get remaining labels
    remaining = hostname[: len(hostname) - len(reg) - 1]   # e.g. "sub.api" from "sub.api.example.com"
    remaining_parts = remaining.split(".")

    # Take only the last remaining label — the one directly above eTLD+1
    immediate_parent = remaining_parts[-1]
    return f"{immediate_parent}.{reg}"


def is_platform_domain(domain: str, program_name: str) -> bool:
    """
    Return True if *domain* is hosting infrastructure unrelated to this program.
    Returns False (keep it) when the program name matches the platform owner.
    """
    if domain not in PLATFORM_DOMAINS:
        return False
    owners = PLATFORM_OWNERS.get(domain, set())
    if not owners:
        return True
    return not any(owner in program_name.lower() for owner in owners)


# ---------------------------------------------------------------------------
# Main extraction entry point
# ---------------------------------------------------------------------------

def extract_domains(value: str, program_name: str = "") -> List[str]:
    """
    Extract scope domains from a raw endpoint/scope string.

    Rules:
      - Alternation groups are expanded before any regex matching so that
        patterns like *.vfsglobal.(com|co.uk|ca) are correctly resolved into
        all their variants. Multiple groups and nested repetition are handled.

      - Every hostname is reduced to its registered domain (eTLD+1).
        www.example.com -> example.com
        api.pay.example.com -> example.com

      - Wildcard with an intermediate subdomain saves BOTH the immediate
        parent above eTLD+1 AND the registered domain:
        *.api.example.com -> [api.example.com, example.com]
        *.sub.api.example.com -> [api.example.com, example.com]
        *.example.com -> [example.com]

      - Platform infrastructure domains (github.io, netlify.app, etc.) are
        blocked unless the program name matches the known owner.

    Returns a deduplicated list preserving insertion order.
    """
    seen:   set       = set()
    result: List[str] = []

    def _add(domain: str) -> None:
        if not domain or domain in seen:
            return
        if not is_valid_domain(domain):
            return
        if is_platform_domain(domain, program_name):
            return
        seen.add(domain)
        result.append(domain)

    def _process(v: str) -> None:
        for m in WILDCARD_RE.finditer(v):
            host   = m.group(1).lower()
            reg    = registered_domain(host)
            parent = wildcard_parent(host)  # non-empty only when host != reg
            if parent:
                _add(parent)   # e.g. api.example.com
            _add(reg)          # always add example.com

        for m in FQDN_RE.finditer(v):
            fqdn = m.group(1).lower()
            if not IP_RE.match(fqdn):
                _add(registered_domain(fqdn))

    # Expand alternation groups first, then run regex extraction on each
    # expanded variant. Deduplication in _add() ensures no duplicates even
    # when multiple variants resolve to the same registered domain.
    for expanded in expand_alternations(value):
        _process(expanded)

    return result