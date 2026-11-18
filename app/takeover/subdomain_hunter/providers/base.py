"""
app/takeover/providers/base.py

Shared constants and base class for all auto-takeover providers.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


# ---------------------------------------------------------------------------
# Claim page — silent PoC, only visible in source
# ---------------------------------------------------------------------------

CLAIM_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title></title>
</head>
<body>
<!-- STO by Rizin - reported to BB program -->
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Unified result across all providers
# ---------------------------------------------------------------------------

class TakeoverStatus(str, Enum):
    SUCCESS      = "success"       # claimed and PoC deployed
    FAIL         = "fail"          # claimable but attempt failed (API error, quota, etc.)
    NOT_VULN     = "not_vuln"      # provider confirmed it's not vulnerable
    NOT_IMPL     = "not_impl"      # provider detected but auto-takeover not implemented
    UNAVAILABLE  = "unavailable"   # token missing / API unreachable
    NEEDS_TXT    = "needs_txt"     # domain owned by another account; TXT transfer required


@dataclass
class TakeoverResult:
    status:           TakeoverStatus
    provider:         str
    subdomain:        str
    confidence_delta: int                    = 0
    evidence:         Dict[str, Any]         = field(default_factory=dict)
    claim_url:        Optional[str]          = None
    error:            Optional[str]          = None
    # Set by ProvidersEvaluator once the claimed hostname serves our marker.
    # An unvalidated SUCCESS is treated as a failed attempt, never as claimed.
    claim_validated:  Optional[bool]         = None

    @property
    def is_success(self) -> bool:
        return self.status == TakeoverStatus.SUCCESS

    @property
    def discord_label(self) -> str:
        return {
            TakeoverStatus.SUCCESS:     "✅ Takeover: Success",
            TakeoverStatus.FAIL:        "❌ Takeover: Fail",
            TakeoverStatus.NOT_VULN:    "🟢 Not vulnerable",
            TakeoverStatus.NOT_IMPL:    "⚠️ Takeover: N/A",
            TakeoverStatus.UNAVAILABLE: "⚠️ Takeover: N/A",
            TakeoverStatus.NEEDS_TXT:   "🔒 Takeover: Needs TXT transfer",
        }[self.status]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status":           self.status.value,
            "provider":         self.provider,
            "confidence_delta": self.confidence_delta,
            "evidence":         self.evidence,
            "claim_url":        self.claim_url,
            "error":            self.error,
            "claim_validated":  self.claim_validated,
        }
