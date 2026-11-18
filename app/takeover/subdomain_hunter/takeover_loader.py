"""
app/takeover/takeover_loader.py

Loads provider signatures from signatures.yaml exactly once.
Single source of truth shared by ConfidenceScorer and PotentialTakeoverDetector.

Usage
-----
    from app.takeover.takeover_loader import SignatureLoader

    sig = SignatureLoader.instance()
    sig.cname_patterns       # {provider: [(regex, weight), ...]}
    sig.http_fingerprints    # {provider: [(pattern, weight), ...]}
    sig.header_fingerprints  # [(header, pattern, provider, weight)]
    sig.claimable            # {provider: bool}   True = account-claimable
    sig.severity             # {provider: str}
    sig.all_providers        # [str, ...]
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml

from app.core.config import settings
from app.core.logging import logger


@dataclass
class SignatureData:
    cname_patterns:      Dict[str, List[Tuple[re.Pattern, int]]] = field(default_factory=dict)
    # Store compiled patterns so score_http doesn't re-compile on every call.
    # Typed as Tuple[re.Pattern, int] to match cname_patterns convention.
    http_fingerprints:   Dict[str, List[Tuple[re.Pattern, int]]] = field(default_factory=dict)
    header_fingerprints: List[Tuple[str, re.Pattern, str, int]]  = field(default_factory=list)
    # claimable is Dict[str, bool] — make the type annotation explicit
    # and consistent. True means the provider account can be claimed by an attacker.
    claimable:           Dict[str, bool]                         = field(default_factory=dict)
    severity:            Dict[str, str]                          = field(default_factory=dict)
    # Providers where the CNAME target itself must be NXDOMAIN to be vulnerable.
    # Source: EdOverflow/can-i-take-over-xyz — fingerprint column = "NXDOMAIN".
    nxdomain_required:   Dict[str, bool]                         = field(default_factory=dict)

    @property
    def all_providers(self) -> List[str]:
        return sorted(self.cname_patterns.keys())


class SignatureLoader:
    """Thread-safe singleton — reads signatures.yaml once at startup."""

    _instance: Optional[SignatureLoader] = None
    _lock = threading.Lock()

    def __init__(self, path: Optional[str] = None) -> None:
        self._path = path or settings.TAKEOVER_SIGNATURES_PATH
        self._data: Optional[SignatureData] = None

    @classmethod
    def instance(cls) -> SignatureLoader:
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
                    cls._instance._load()
        return cls._instance

    @property
    def data(self) -> SignatureData:
        if self._data is None:
            self._load()
        return self._data  # type: ignore[return-value]

    @property
    def cname_patterns(self) -> Dict[str, List[Tuple[re.Pattern, int]]]:
        return self.data.cname_patterns

    @property
    def http_fingerprints(self) -> Dict[str, List[Tuple[re.Pattern, int]]]:
        return self.data.http_fingerprints

    @property
    def header_fingerprints(self) -> List[Tuple[str, re.Pattern, str, int]]:
        return self.data.header_fingerprints

    @property
    def claimable(self) -> Dict[str, bool]:
        return self.data.claimable

    @property
    def severity(self) -> Dict[str, str]:
        return self.data.severity

    @property
    def nxdomain_required(self) -> Dict[str, bool]:
        return self.data.nxdomain_required

    @property
    def all_providers(self) -> List[str]:
        return self.data.all_providers

    def _load(self) -> None:
        path = Path(self._path)
        if not path.is_absolute():
            path = Path(__file__).resolve().parents[3] / path
        if not path.exists():
            logger.error("SignatureLoader: file not found: %s", path)
            self._data = SignatureData()
            return

        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.error("SignatureLoader: failed to parse %s: %s", path, exc)
            self._data = SignatureData()
            return

        data = SignatureData()

        for sig in raw.get("signatures", []):
            provider  = sig.get("provider")
            claimable = bool(sig.get("claimable", True))
            severity  = sig.get("severity", "medium").lower()

            if not provider:
                logger.warning("SignatureLoader: entry missing provider field, skipping")
                continue

            data.claimable[provider] = claimable
            data.severity[provider]  = severity
            if sig.get("nxdomain_required"):
                data.nxdomain_required[provider] = True

            # Non-claimable CDN/proxy providers get lower CNAME weight
            cname_weight   = 35 if not claimable else 40
            cname_compiled = []
            for pat in sig.get("cname_patterns", []):
                if _valid(pat, provider, "cname"):
                    try:
                        regex = re.compile(pat, re.IGNORECASE)
                        cname_compiled.append((regex, cname_weight))
                    except re.error as exc:
                        logger.warning(
                            "SignatureLoader: invalid cname regex for %s: %r — %s",
                            provider, pat, exc,
                        )
            if cname_compiled:
                data.cname_patterns[provider] = cname_compiled

            # Pre-compile HTTP fingerprint patterns at load time,
            # not on every score_http() call. ConfidenceScorer.score_http
            # is updated to call pattern.search() directly.
            http_compiled = []
            for entry in sig.get("http_patterns", []):
                pat, weight = entry["pattern"], entry["weight"]
                if _valid(pat, provider, "http"):
                    try:
                        http_compiled.append((re.compile(pat, re.IGNORECASE), weight))
                    except re.error as exc:
                        logger.warning(
                            "SignatureLoader: invalid http regex for %s: %r — %s",
                            provider, pat, exc,
                        )
            if http_compiled:
                data.http_fingerprints[provider] = http_compiled

            # Pre-compile header patterns too.
            for entry in sig.get("header_patterns", []):
                hname  = entry["header"]
                hpat   = entry["pattern"]
                weight = entry["weight"]
                if _valid(hpat, provider, "header"):
                    try:
                        data.header_fingerprints.append(
                            (hname, re.compile(hpat, re.IGNORECASE), provider, weight)
                        )
                    except re.error as exc:
                        logger.warning(
                            "SignatureLoader: invalid header regex for %s: %r — %s",
                            provider, hpat, exc,
                        )

        self._data = data
        logger.debug(
            "SignatureLoader: %d providers | %d http patterns | %d header patterns from %s",
            len(data.cname_patterns),
            sum(len(v) for v in data.http_fingerprints.values()),
            len(data.header_fingerprints),
            path,
        )


def _valid(pattern: str, provider: str, kind: str) -> bool:
    """Return True if pattern compiles as regex, log and return False otherwise."""
    try:
        re.compile(pattern, re.IGNORECASE)
        return True
    except re.error as exc:
        logger.warning(
            "SignatureLoader: invalid %s regex for %s — %r: %s",
            kind, provider, pattern, exc,
        )
        return False