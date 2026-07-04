from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

from app.models.models import ResearchFinding, Severity
from app.services.zero_day import (
    check_cve_exists, lookup_cve, days_until_disclosure_deadline,
    submit_to_hackerone, submit_to_bugcrowd, publish_github_security_advisory, generate_disclosure_advisory,
)


def _make_finding(**overrides):
    defaults = dict(
        id="f1", target_id="t1", title="Heap overflow in libfoo parser",
        cve_id="CVE-2026-0001", cvss_score=9.1, severity=Severity.critical,
        vuln_class="Heap Buffer Overflow", description="Malformed input triggers OOB write.",
    )
    defaults.update(overrides)
    return ResearchFinding(**defaults)


def test_check_cve_exists_true_on_200():
    resp = MagicMock(status_code=200)
    with patch("app.services.zero_day.httpx.get", return_value=resp):
        assert check_cve_exists("CVE-2021-44228") is True


def test_check_cve_exists_false_on_404():
    resp = MagicMock(status_code=404)
    with patch("app.services.zero_day.httpx.get", return_value=resp):
        assert check_cve_exists("CVE-9999-9999") is False


def test_check_cve_exists_false_on_network_error():
    import httpx as httpx_module
    with patch("app.services.zero_day.httpx.get", side_effect=httpx_module.ConnectError("down")):
        assert check_cve_exists("CVE-2021-44228") is False


def test_lookup_cve_parses_nvd_response():
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2021-44228",
                "descriptions": [{"lang": "en", "value": "Log4Shell RCE"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "vectorString": "CVSS:3.1/AV:N"}}]},
                "published": "2021-12-10T00:00:00", "lastModified": "2021-12-15T00:00:00",
            }
        }]
    }
    with patch("app.services.zero_day.httpx.get", return_value=resp):
        result = lookup_cve("CVE-2021-44228")
    assert result["cvss_score"] == 10.0
    assert result["description"] == "Log4Shell RCE"


def test_lookup_cve_returns_none_when_no_results():
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {"vulnerabilities": []}
    with patch("app.services.zero_day.httpx.get", return_value=resp):
        assert lookup_cve("CVE-0000-0000") is None


def test_lookup_cve_returns_none_on_network_failure():
    import httpx as httpx_module
    with patch("app.services.zero_day.httpx.get", side_effect=httpx_module.ConnectError("down")):
        assert lookup_cve("CVE-2021-44228") is None


def test_days_until_disclosure_deadline_none_when_not_notified():
    assert days_until_disclosure_deadline(None) is None


def test_days_until_disclosure_deadline_counts_down_from_90():
    notified = datetime.utcnow() - timedelta(days=10)
    days_left = days_until_disclosure_deadline(notified)
    assert 79 <= days_left <= 80


def test_submit_to_hackerone_skips_without_token():
    finding = _make_finding()
    with patch("app.services.zero_day.settings.HACKERONE_API_TOKEN", ""):
        assert submit_to_hackerone(finding, "acme", "api-id") is None


def test_submit_to_hackerone_posts_when_token_present():
    finding = _make_finding()
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {"data": {"id": "12345", "type": "report"}}
    with patch("app.services.zero_day.settings.HACKERONE_API_TOKEN", "tok"), \
         patch("app.services.zero_day.httpx.post", return_value=resp) as mock_post:
        result = submit_to_hackerone(finding, "acme", "api-id")
    assert result["data"]["id"] == "12345"
    mock_post.assert_called_once()


def test_submit_to_bugcrowd_skips_without_key():
    finding = _make_finding()
    with patch("app.services.zero_day.settings.BUGCROWD_API_KEY", ""):
        assert submit_to_bugcrowd(finding, "acme-program") is None


def test_submit_to_bugcrowd_posts_when_key_present():
    finding = _make_finding()
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {"submission": {"id": "abc123"}}
    with patch("app.services.zero_day.settings.BUGCROWD_API_KEY", "key"), \
         patch("app.services.zero_day.httpx.post", return_value=resp) as mock_post:
        result = submit_to_bugcrowd(finding, "acme-program")
    assert result["submission"]["id"] == "abc123"
    mock_post.assert_called_once()


def test_publish_github_security_advisory_reuses_devsecops_client():
    finding = _make_finding()
    fake_advisory = MagicMock(ghsa_id="GHSA-xxxx", html_url="https://github.com/acme/repo/security/advisories/GHSA-xxxx", state="published")
    fake_repo = MagicMock()
    fake_repo.create_repository_advisory.return_value = fake_advisory
    fake_gh = MagicMock()
    fake_gh.get_repo.return_value = fake_repo
    with patch("app.services.zero_day._github_client", return_value=fake_gh) as mock_client:
        result = publish_github_security_advisory("acme/repo", finding, token="tok")
    mock_client.assert_called_once_with("tok")
    fake_repo.create_repository_advisory.assert_called_once()
    assert result["id"] == "GHSA-xxxx"


def test_generate_disclosure_advisory_grounded_in_finding():
    finding = _make_finding()
    fake_response = MagicMock()
    fake_response.content = [MagicMock(type="text", text="Advisory body.")]
    with patch("app.services.zero_day._claude_client") as mock_client_factory:
        mock_client_factory.return_value.messages.create.return_value = fake_response
        advisory = generate_disclosure_advisory(finding)
    assert advisory == "Advisory body."
    prompt = mock_client_factory.return_value.messages.create.call_args.kwargs["messages"][0]["content"]
    assert "Heap overflow in libfoo parser" in prompt
    assert "CVE-2026-0001" in prompt
