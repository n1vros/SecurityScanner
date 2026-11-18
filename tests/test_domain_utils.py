"""Scope/domain parsing used by every platform adapter."""

from app.programs.domain_utils import (
    expand_alternations,
    extract_domains,
    is_valid_domain,
    registered_domain,
)


def test_expand_alternations():
    assert expand_alternations("*.example.(com|net)") == [
        "*.example.com",
        "*.example.net",
    ]
    assert expand_alternations("example.com") == ["example.com"]


def test_registered_domain():
    assert registered_domain("api.eu.example.co.uk") == "example.co.uk"
    assert registered_domain("a.b.example.com") == "example.com"


def test_extract_domains_handles_urls_and_wildcards():
    domains = extract_domains("*.example.com, https://app.example.org/path api.test.net")
    assert domains == ["example.com", "example.org", "test.net"]


def test_is_valid_domain():
    assert is_valid_domain("example.com")
    assert not is_valid_domain("not a domain")


def test_platform_domains_are_filtered():
    assert extract_domains("https://acme.github.io/app", program_name="acme") == []
    assert extract_domains("https://pages.github.io/app", program_name="github") == ["github.io"]
