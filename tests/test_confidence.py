"""Confidence scoring against the real signatures.yaml data."""

from app.probing.confidence import ConfidenceScorer

DANGLING_THRESHOLD = 60


def test_real_signature_file_loads():
    # The loader must find files/signatures.yaml (the config default was wrong).
    providers = ConfidenceScorer._sig().cname_patterns
    assert len(providers) > 100
    assert "github" in providers


def test_nxdomain_cname_scores_above_dangling_threshold():
    score, provider = ConfidenceScorer.score_dns("foo.github.io", nxdomain=True)

    assert score >= DANGLING_THRESHOLD
    # The provider is intentionally hidden on the NXDOMAIN path.
    assert provider is None


def test_matching_cname_returns_provider_when_not_nxdomain():
    score, provider = ConfidenceScorer.score_dns("foo.github.io", nxdomain=False)

    assert provider == "github"
    assert score == 40


def test_unmatched_cname_scores_zero():
    assert ConfidenceScorer.score_dns("internal.example.com", nxdomain=True) == (0, None)
    assert ConfidenceScorer.score_dns(None, nxdomain=True) == (0, None)


def test_http_body_fingerprint():
    score, provider = ConfidenceScorer.score_http(
        404, "The specified bucket does not exist", {}
    )
    assert provider == "aws_s3"
    assert score > 0


def test_negative_http_fingerprint_suppresses():
    score, provider = ConfidenceScorer.score_http(403, "AccessDenied", {})

    assert provider == "aws_s3"
    assert score < 0
    assert ConfidenceScorer.compute_overall(65, score, nxdomain=True) == 0


def test_overall_combination():
    assert ConfidenceScorer.compute_overall(65, 0, nxdomain=True) == 65
    assert ConfidenceScorer.compute_overall(65, 60, nxdomain=True) == 95
    assert ConfidenceScorer.compute_overall(0, 0, nxdomain=False) == 0
    assert ConfidenceScorer.compute_overall(0, -100, nxdomain=False) == 0
    assert ConfidenceScorer.compute_overall(40, 0, nxdomain=False) == 40
