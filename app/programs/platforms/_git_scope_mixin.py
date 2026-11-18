"""
app/programs/platforms/_git_scope_mixin.py

Mixin/helper for extracting git scopes from raw scope strings in platform adapters.

Used in fetch_programs() implementations BEFORE calling extract_domains() —
so GitHub/GitLab URLs are captured instead of being silently dropped by the
PLATFORM_DOMAINS blocklist.

Usage in a platform's _process_program() or fetch_programs():

    from app.programs.platforms._git_scope_mixin import extract_git_and_domain_scopes

    domains, git_scope_urls = extract_git_and_domain_scopes(raw_scope_list, program_name)

    return {
        "name": name,
        "scopes": domains,
        "git_scopes": git_scope_urls,   # ← new key
        ...
    }

The base class sync_programs() will call _sync_git_scopes() automatically when
the "git_scopes" key is present in the program data dict.
"""

from __future__ import annotations

from typing import List, Tuple

from app.programs.domain_utils import extract_domains
from app.programs.git_scope_utils import is_git_scope


def extract_git_and_domain_scopes(
    raw_values: List[str],
    program_name: str = "",
) -> Tuple[List[str], List[str]]:
    """
    Split a list of raw scope strings into:
      - domains:         web-layer domains (passed through extract_domains as normal)
      - git_scope_urls:  GitHub/GitLab URLs captured before the blocklist applies

    Parameters
    ----------
    raw_values   : raw scope strings from the platform API
    program_name : used by extract_domains() for platform-owner exception logic

    Returns
    -------
    (domains, git_scope_urls)
    """
    domains:         List[str] = []
    git_scope_urls:  List[str] = []

    for raw in raw_values:
        raw = raw.strip()
        if not raw:
            continue

        if is_git_scope(raw):
            # Intercept git scope — do NOT pass to extract_domains()
            if raw not in git_scope_urls:
                git_scope_urls.append(raw)
        else:
            # Normal domain scope — run through existing extractor
            for domain in extract_domains(raw, program_name):
                if domain not in domains:
                    domains.append(domain)

    return domains, git_scope_urls