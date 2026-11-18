"""
app/probing/dns_scanner/ip_providers.py

Loads the vulnerable cloud IP provider registry from vulnerable_ip_providers.yaml.
Used by ip_indicators.py and ip_analyzer.py to drive per-provider heuristics.

Loaded once at import time. Restart to pick up YAML edits.
"""

from pathlib import Path
from typing import Dict

from app.core.config import settings
from app.core.logging import logger


def load_ip_providers() -> Dict[str, dict]:
    import yaml

    path_str = getattr(settings, "VULNERABLE_IP_PROVIDERS_PATH", "files/vulnerable_ip_providers.yaml")
    path = Path(path_str)
    if not path.is_absolute():
        path = Path(__file__).parent.parent.parent.parent / path

    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except FileNotFoundError:
        logger.warning(
            "dns_scanner: IP providers file not found at %s — using empty map. "
            "Dangling IP analysis will still run but without per-provider indicators.",
            path,
        )
        return {}
    except Exception as exc:
        logger.error("dns_scanner: failed to load IP providers from %s: %s", path, exc)
        return {}

    result = data.get("providers", {})
    logger.debug("dns_scanner: loaded %d IP provider entries from %s", len(result), path)
    return result


# Module-level singleton
VULNERABLE_IP_PROVIDERS: Dict[str, dict] = load_ip_providers()


def get_provider_cfg(provider_key: str) -> dict:
    """Return provider config dict or empty dict if unknown."""
    return VULNERABLE_IP_PROVIDERS.get(provider_key, {})