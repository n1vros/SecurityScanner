"""Regression tests for configuration defaults and file paths."""

from pathlib import Path

from app.core.config import Settings, settings
from app.probing.exposure_scanner import load_exposure_paths

# These were read with getattr() but missing from Settings, so .env values were
# silently ignored. Guard against that regressing.
EXPECTED_SETTINGS = [
    "ACTIVE_TASKS_TIMEOUT_SECONDS",
    "CERTSTREAM_TAKEOVER_CHECK_ENABLED",
    "DANGLING_IP_CHECK_ENABLED",
    "DANGLING_IP_CONCURRENCY",
    "DANGLING_IP_TIMEOUT",
    "DNS_PROBE_TIMEOUT",
    "DNS_TAKEOVER_SWEEP_CONCURRENCY",
    "IP_HUNTER_MODE",
    "JSSCRAPE_FETCH_JITTER_MS",
    "JSSCRAPE_FETCH_STAGGER_MS",
    "JS_SECRET_MAX_BODY_BYTES",
    "NS_SWEEP_BATCH_SIZE",
    "NS_SWEEP_WARM_POOL_ENABLED",
    "POTENTIAL_RECHECK_LIMIT",
    "SCOPE_CONCURRENCY",
    "SUBDOMAINS_LIMIT_PER_SCOPE",
    "WAYBACK_GAU_BINARY",
    "WAYBACK_WAYBACKURLS_BIN",
]


def test_all_runtime_knobs_are_declared():
    fields = Settings.model_fields
    missing = [name for name in EXPECTED_SETTINGS if name not in fields]
    assert missing == []


def test_signature_and_wordlist_paths_exist():
    assert Path(settings.TAKEOVER_SIGNATURES_PATH).is_file()
    assert Path(settings.DNS_TAKEOVER_PROVIDERS_PATH).is_file()
    assert Path(settings.VULNERABLE_IP_PROVIDERS_PATH).is_file()
    assert load_exposure_paths(settings.EXPOSURE_WORDLIST_PATH)


def test_env_file_example_covers_settings():
    example = Path(".env.example")
    assert example.is_file()
    text = example.read_text(encoding="utf-8")
    missing = [
        name
        for name in Settings.model_fields
        if name not in text
    ]
    assert missing == []
