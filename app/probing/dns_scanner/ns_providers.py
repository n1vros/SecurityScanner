"""
app/probing/dns_scanner/ns_providers.py

Loads the vulnerable DNS provider registry from YAML and exposes it as a
module-level list of VulnerableNSProvider objects.

Loaded once at import time. Restart the process to pick up YAML edits.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List

from app.core.config import settings
from app.core.logging import logger


@dataclass
class VulnerableNSProvider:
    name:             str
    pattern:          re.Pattern
    notes:            str
    fp_risk:          bool = False
    # True = AWS Route 53 NS-mismatch path — custom detection, not rcode-based
    custom_detection: bool = False


def load_ns_providers() -> List[VulnerableNSProvider]:
    import yaml

    path_str = getattr(settings, "DNS_TAKEOVER_PROVIDERS_PATH", "files/dns_takeover_providers.yaml")
    path = Path(path_str)
    if not path.is_absolute():
        path = Path(__file__).parent.parent.parent.parent / path

    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except FileNotFoundError:
        logger.error(
            "dns_scanner: NS providers file not found at %s — NS takeover detection disabled", path
        )
        return []
    except Exception as exc:
        logger.error("dns_scanner: failed to load NS providers from %s: %s", path, exc)
        return []

    providers = []
    for entry in data.get("providers", []):
        try:
            providers.append(VulnerableNSProvider(
                name             = entry["name"],
                pattern          = re.compile(entry["pattern"], re.IGNORECASE),
                notes            = entry.get("notes", ""),
                fp_risk          = bool(entry.get("fp_risk", False)),
                custom_detection = bool(entry.get("custom_detection", False)),
            ))
        except Exception as exc:
            logger.warning(
                "dns_scanner: skipping malformed NS provider %r: %s",
                entry.get("name", "<unnamed>"), exc,
            )

    logger.debug("dns_scanner: loaded %d NS providers from %s", len(providers), path)
    return providers


# Module-level singleton — loaded once at import time
VULNERABLE_NS_PROVIDERS: List[VulnerableNSProvider] = load_ns_providers()