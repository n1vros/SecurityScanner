"""Resolver pool loading, caching and pruning."""

from pathlib import Path

import pytest

from app.core.config import settings
from app.discovery import resolvers


def test_parse_drops_invalid_entries():
    parsed = resolvers._parse_resolvers("1.1.1.1, 8.8.8.8\nnot-an-ip\n9.9.9.9,1.1.1.1")
    assert parsed == ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


@pytest.mark.asyncio
async def test_refresh_uses_configured_sources_and_writes_cache(monkeypatch, tmp_path):
    cache = tmp_path / "resolvers.txt"
    monkeypatch.setattr(settings, "DNS_RESOLVER_CACHE", str(cache))
    monkeypatch.setattr(settings, "DNS_RESOLVER_URLS", "")
    monkeypatch.setattr(settings, "DNS_RESOLVER_FILES", "")
    monkeypatch.setattr(settings, "DNS_RESOLVERS", "1.1.1.1,4.4.4.4")

    pool = await resolvers.ensure_resolver_pool(force=True)

    assert pool == ["1.1.1.1", "4.4.4.4"]
    assert cache.read_text().split() == ["1.1.1.1", "4.4.4.4"]

    resolvers.reload_resolver_pool()
    assert resolvers.get_resolver_list() == ["1.1.1.1", "4.4.4.4"]


@pytest.mark.asyncio
async def test_refresh_falls_back_when_sources_empty(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "DNS_RESOLVER_CACHE", str(tmp_path / "none.txt"))
    monkeypatch.setattr(settings, "DNS_RESOLVER_URLS", "")
    monkeypatch.setattr(settings, "DNS_RESOLVER_FILES", "")
    monkeypatch.setattr(settings, "DNS_RESOLVERS", "")

    pool = await resolvers.ensure_resolver_pool(force=True)

    assert pool  # defaults are used rather than an empty pool


def test_resolvers_file_is_stable(tmp_path, monkeypatch):
    monkeypatch.setattr(resolvers, "_resolvers_file", None)
    resolvers.set_resolver_list(["1.1.1.1", "8.8.8.8"])

    first = resolvers.get_resolvers_file()
    second = resolvers.get_resolvers_file()

    assert first == second
    assert "1.1.1.1" in Path(first).read_text(encoding="utf-8")
