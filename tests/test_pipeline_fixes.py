"""Regressions for issues fixed in the first repair round."""

import yaml

from app.db.db_models import GitSecretRecord, JsSecretRecord
from app.probing.exposure_scanner import _TAG_TO_SUBDIR, load_exposure_paths
from app.web.api import app


def test_credential_findings_have_a_save_directory():
    # The wordlist is dominated by the "credentials" tag; it must map to a
    # directory or most secret findings are never written to disk.
    assert _TAG_TO_SUBDIR["credentials"] == "creds"
    for tag in ("git", "env", "keys", "database", "backup"):
        assert tag in _TAG_TO_SUBDIR


def test_exposure_wordlist_tags_are_documented():
    paths = load_exposure_paths()
    tags = {tag for entry in paths for tag in entry.tags}
    unmapped = sorted(tag for tag in tags if tag not in _TAG_TO_SUBDIR)
    # Most tags are grouping/filtering only; every credential tag must map.
    assert "credentials" in tags
    assert set(unmapped) <= {
        "aws", "azure", "cloud", "debug", "docker", "dotnet", "gcloud", "java",
        "kubernetes", "laravel", "logs", "node", "php", "python", "rails",
        "spring", "symfony", "terraform", "wordpress", "cicd", "actuator", "ide",
        "django",
    }


def test_secret_finding_tables_exist():
    assert JsSecretRecord.__tablename__ == "js_secret_findings"
    assert GitSecretRecord.__tablename__ == "git_secret_findings"


def test_secret_api_routes_are_registered():
    paths = {route.path for route in app.routes}
    assert "/api/js-secrets" in paths
    assert "/api/git-secrets" in paths


def test_wordlist_is_valid_yaml_list():
    raw = yaml.safe_load(open("files/exposure_paths.yaml"))
    assert isinstance(raw, list) and raw
    assert all("path" in entry for entry in raw)
