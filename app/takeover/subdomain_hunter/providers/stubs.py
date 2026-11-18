"""
app/takeover/providers/stubs.py

NOT_IMPL stubs for providers where takeover IS possible but requires
manual steps (account signup, portal interaction, etc.) that cannot be
fully automated via a public API with just a token.

Each provider here returns NOT_IMPL so Discord shows "Takeover: N/A" with
full evidence — you know to go claim it manually.

Providers covered
-----------------
  azure_blob     — <storage>.blob.core.windows.net  (requires Azure portal)
  azure_websites — <app>.azurewebsites.net          (requires Azure portal)
  github_actions — served via GH Actions cdn        (NOT_IMPL — edge case)
  fastly         — <whatever>.global.ssl.fastly.net (requires Fastly console)
  ghost_io       — <blog>.ghost.io                  (requires Ghost signup)
  surge_sh       — <name>.surge.sh                  (surge CLI, not API)
  readme_io      — <name>.readme.io                 (requires Readme account)
  helpscout      — <name>.helpscoutdocs.com         (requires HelpScout)
  zendesk        — <name>.zendesk.com               (requires Zendesk signup)
  bitbucket      — <name>.bitbucket.io              (repo creation needed)
  wordpress      — <name>.wordpress.com             (requires WP signup)
  smugmug        — <name>.smugmug.com               (requires account)
  strikingly     — <name>.strikingly.com            (requires account)
  ucraft         — <name>.ucraft.me                 (requires account)
  cargo          — <name>.cargo.site                (requires account)
  tilda          — <name>.tilda.ws                  (requires account)
  webflow        — <name>.webflow.io                (requires Webflow API key)
"""

from app.takeover.subdomain_hunter.providers.base import TakeoverResult, TakeoverStatus


# Map of provider name → human-readable reason why it's N/A
_NOT_IMPL_REASONS: dict = {
    "azure_blob":     "Azure Blob requires portal or azure-cli with subscription",
    "azure_websites": "Azure Web Apps require portal or az CLI with subscription",
    "fastly":         "Fastly requires console — no public create-service API",
    "ghost_io":       "Ghost.io requires manual account registration",
    "surge_sh":       "Surge.sh requires CLI login — no token-based create API",
    "readme_io":      "Readme.io requires account — no public project create API",
    "helpscout":      "HelpScout requires account and portal interaction",
    "zendesk":        "Zendesk signup required — not API automatable",
    "bitbucket":      "Bitbucket Pages requires repo creation via Bitbucket API (add BITBUCKET_TOKEN to enable)",
    "wordpress":      "WordPress.com requires account signup",
    "smugmug":        "SmugMug requires account signup",
    "strikingly":     "Strikingly requires account signup",
    "ucraft":         "uCraft requires account signup",
    "cargo":          "Cargo requires account signup",
    "tilda":          "Tilda requires account signup",
    "webflow":        "Webflow requires Workspace API token — add WEBFLOW_TOKEN to enable",
}


def not_impl_result(provider: str, subdomain: str, cname: str) -> TakeoverResult:
    """Return a NOT_IMPL TakeoverResult for the given provider."""
    reason = _NOT_IMPL_REASONS.get(provider, "Manual takeover required")
    return TakeoverResult(
        status=TakeoverStatus.NOT_IMPL,
        provider=provider,
        subdomain=subdomain,
        confidence_delta=0,
        evidence={"cname": cname, "reason": reason},
        error=reason,
    )