"""
app/programs/git_scope_utils.py

Utility functions for detecting and parsing GitHub/GitLab scope URLs.

Used by platform adapters to intercept repo URLs before extract_domains()
discards them via the PLATFORM_DOMAINS blocklist.
"""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

# Matches:
#   https://github.com/org/repo
#   https://github.com/org/*
#   https://gitlab.com/group/subgroup/repo
#   https://gitlab.com/group/*
#   http://github.com/org/repo  (http also accepted)
_GIT_URL_RE = re.compile(
    r"^https?://(github\.com|gitlab\.com)/([^/\s]+)(/[^\s]*)?$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_git_scope(value: str) -> bool:
    """
    Return True if *value* looks like a GitHub or GitLab repository/org URL.

    Intentionally broad — we want to catch both:
      https://github.com/shopify/shopify-api-ruby   (single repo)
      https://github.com/shopify/*                  (wildcard org)
      https://github.com/shopify                    (bare org — treat as wildcard)
    """
    v = value.strip()
    if not v:
        return False
    return bool(_GIT_URL_RE.match(v))


def parse_git_scope(value: str) -> Optional[dict]:
    """
    Parse a git scope string and return a dict with:
      platform    str   "github" or "gitlab"
      repo_url    str   normalised URL (trailing slash stripped)
      is_wildcard bool  True when the URL ends with /* or has no path (bare org)

    Returns None if the value is not a recognisable git scope.
    """
    v = value.strip().rstrip("/")
    m = _GIT_URL_RE.match(v)
    if not m:
        return None

    host    = m.group(1).lower()          # "github.com" or "gitlab.com"
    org     = m.group(2)                  # first path segment (org/user/group)
    rest    = (m.group(3) or "").strip("/")  # everything after org

    platform = "github" if "github" in host else "gitlab"

    # Wildcard cases:
    #   https://github.com/shopify/*   → rest == "*"
    #   https://github.com/shopify     → rest == "" (bare org)
    is_wildcard = (rest == "*" or rest == "")

    if is_wildcard:
        # Normalise to bare org URL (no wildcard suffix stored)
        repo_url = f"https://{host}/{org}"
    else:
        repo_url = f"https://{host}/{org}/{rest}"

    return {
        "platform":    platform,
        "repo_url":    repo_url,
        "is_wildcard": is_wildcard,
    }