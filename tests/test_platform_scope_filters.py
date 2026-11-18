"""Domain-only scope filtering for the four main platform adapters."""

from app.programs.platforms.bugcrowd import extract_scopes as bugcrowd_scopes
from app.programs.platforms.hackerone import extract_scopes as hackerone_scopes
from app.programs.platforms.intigriti import extract_scopes as intigriti_scopes
from app.programs.platforms.yeswehack import extract_scopes as yeswehack_scopes


def _h1_scope(asset_type, identifier, *, bounty=True, submission=True):
    return {
        "attributes": {
            "asset_type": asset_type,
            "asset_identifier": identifier,
            "eligible_for_bounty": bounty,
            "eligible_for_submission": submission,
        }
    }


def test_hackerone_keeps_domain_types_and_routes_source_code_to_git():
    raw = [
        _h1_scope("URL", "https://www.example.com/app"),
        _h1_scope("WILDCARD", "*.api.example.com"),
        _h1_scope("DOMAIN", "example.org"),
        _h1_scope("CIDR", "10.0.0.0/8"),
        _h1_scope("OTHER_APK", "com.example.app"),
        _h1_scope("HARDWARE", "model-123"),
        _h1_scope("SOURCE_CODE", "https://github.com/example/repo"),
        _h1_scope("SOURCE_CODE", "not-a-git-url"),
        _h1_scope("URL", "https://excluded.example.net", bounty=False),
    ]

    domains, git_scopes = hackerone_scopes(raw, "Example", True)

    assert "example.com" in domains
    assert "api.example.com" in domains
    assert "example.org" in domains
    assert "excluded.example.net" not in domains
    assert "example.net" not in domains
    # Source code never becomes a domain scope.
    assert not any("github" in domain for domain in domains)
    assert git_scopes == ["https://github.com/example/repo"]


def test_hackerone_unknown_or_missing_asset_type_is_not_a_domain():
    raw = [
        {"attributes": {"asset_identifier": "unknown.example.com"}},
        _h1_scope("FUTURE_TYPE", "future.example.net"),
    ]
    domains, git_scopes = hackerone_scopes(raw, "Example", True)
    assert domains == []
    assert git_scopes == []


def test_yeswehack_keeps_web_and_excludes_mobile_api_source_and_hardware():
    raw = [
        {"scope": "https://www.example.com/login", "scope_type": "web-application"},
        {"scope": "*.api.example.com", "scope_type": "wildcard"},
        {"scope": "api.other.net", "scope_type": "api"},
        {"scope": "graphql.other.net", "scope_type": "graphql"},
        {"scope": "com.example.app", "scope_type": "mobile-application-android"},
        {"scope": "https://github.com/example/repo", "scope_type": "source-code"},
        {"scope": "example.org", "scope_type": "hardware"},
        {"scope": "out.example.net", "scope_type": "web-application", "in_scope": False},
    ]

    domains, git_scopes = yeswehack_scopes(raw, "Example")

    assert "example.com" in domains
    assert "api.example.com" in domains
    assert "example.org" not in domains
    assert "other.net" not in domains
    assert "out.example.net" not in domains
    assert git_scopes == []


def test_intigriti_keeps_url_and_wildcard_and_excludes_non_domain_types():
    raw = [
        {
            "endpoint": "https://www.example.com/app",
            "type": {"id": 1, "value": "URL"},
            "tier": {"id": 2, "value": "Tier 2"},
        },
        {
            "endpoint": "*.api.example.com",
            "type": {"id": 7, "value": "Wildcard"},
            "tier": {"id": 2, "value": "Tier 2"},
        },
        {
            "endpoint": "api.other.net",
            "type": {"id": 1, "value": "API"},
            "tier": {"id": 2, "value": "Tier 2"},
        },
        {
            "endpoint": "com.example.app",
            "type": {"id": 2, "value": "Android"},
            "tier": {"id": 2, "value": "Tier 2"},
        },
        {
            "endpoint": "example.org",
            "type": {"id": 5, "value": "Hardware"},
            "tier": {"id": 2, "value": "Tier 2"},
        },
        {
            "endpoint": "https://github.com/example/repo",
            "type": {"id": 6, "value": "Other"},
            "tier": {"id": 2, "value": "Tier 2"},
        },
        {
            "endpoint": "out.example.net",
            "type": {"id": 1, "value": "URL"},
            "tier": {"id": 5, "value": "Out of scope"},
        },
        {
            "endpoint": "oos.example.io",
            "type": {"id": 1, "value": "URL"},
            "tier": {"id": 2, "value": "Tier 2"},
            "outOfScope": True,
        },
    ]

    domains, git_scopes = intigriti_scopes(raw, "Example")

    assert "example.com" in domains
    assert "api.example.com" in domains
    assert "example.org" not in domains
    assert "other.net" not in domains
    assert "out.example.net" not in domains
    assert "oos.example.io" not in domains
    assert git_scopes == []


def _bugcrowd_brief():
    return {
        "scope": [
            {
                "name": "Web",
                "targets": [
                    {
                        "uri": "https://www.example.com/app",
                        "name": "",
                        "category": "website",
                    },
                    {
                        "uri": "",
                        "name": "*.api.example.com",
                        "category": "website",
                    },
                    {
                        "uri": "https://api.other.net",
                        "name": "api.other.net",
                        "category": "api",
                    },
                    {
                        "uri": "https://play.google.com/store/apps/details?id=x",
                        "name": "Android",
                        "category": "android",
                    },
                    {
                        "uri": "https://example.org/firmware",
                        "name": "Firmware",
                        "category": "hardware",
                    },
                    {
                        "uri": "https://github.com/example/repo",
                        "name": "repo",
                        "category": "website",
                    },
                ],
            },
            {
                "name": "Out of Scope",
                "targets": [
                    {
                        "uri": "https://out.example.net",
                        "name": "out",
                        "category": "website",
                    }
                ],
            },
        ]
    }


def test_bugcrowd_keeps_website_and_excludes_non_domain_categories():
    domains, git_scopes = bugcrowd_scopes(_bugcrowd_brief(), "Example")

    assert "example.com" in domains
    assert "api.example.com" in domains
    assert "example.org" not in domains
    assert "other.net" not in domains
    assert "out.example.net" not in domains
    assert git_scopes == ["https://github.com/example/repo"]


def test_scope_filters_tolerate_unexpected_payload_shapes():
    assert hackerone_scopes([None, "bad"], "Example", True) == ([], [])
    assert yeswehack_scopes([None, 42], "Example") == ([], [])
    assert intigriti_scopes([None, "bad"], "Example") == ([], [])
    assert bugcrowd_scopes({"scope": "not-a-list"}, "Example") == ([], [])
    assert bugcrowd_scopes(
        {"scope": [{"name": "Web", "targets": [None, 42]}]},
        "Example",
    ) == ([], [])


def test_bugcrowd_target_level_in_scope_false_is_excluded():
    brief = {
        "scope": [
            {
                "name": "Web",
                "targets": [
                    {
                        "uri": "https://kept.example.com",
                        "category": "website",
                        "in_scope": True,
                    },
                    {
                        "uri": "https://removed.example.com",
                        "category": "website",
                        "in_scope": False,
                    },
                ],
            }
        ]
    }
    domains, _ = bugcrowd_scopes(brief, "Example")
    assert "example.com" in domains
    assert "removed.example.com" not in domains
