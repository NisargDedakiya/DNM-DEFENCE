import uuid
from unittest.mock import MagicMock, patch

from app.core.database import SessionLocal
from app.models.models import Client, Finding
from app.services import triage


def _make_client(db):
    c = Client(id=str(uuid.uuid4()), name="Triage Co", root_domain="triage.example.com",
               contact_email="a@triage.example.com")
    db.add(c)
    db.commit()
    return c


SAMPLE_SARIF = {
    "runs": [{
        "tool": {"driver": {"name": "Semgrep"}},
        "results": [{
            "ruleId": "python.lang.security.audit.eval-detected",
            "level": "error",
            "message": {"text": "Detected use of eval()"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/main.py"}, "region": {"startLine": 42}}}],
        }],
    }]
}

SAMPLE_TRIVY = {
    "Results": [{
        "Target": "requirements.txt",
        "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2024-1111", "PkgName": "requests", "InstalledVersion": "2.20.0",
            "Severity": "HIGH", "Title": "Requests SSRF vulnerability",
        }],
    }]
}

SAMPLE_OWASP_DC_XML = """<?xml version="1.0"?>
<analysis xmlns="https://jeremylong.github.io/DependencyCheck/dependency-check.1.8.xsd">
  <dependencies>
    <dependency>
      <fileName>log4j-core-2.14.1.jar</fileName>
      <vulnerabilities>
        <vulnerability>
          <name>CVE-2021-44228</name>
          <severity>Critical</severity>
        </vulnerability>
      </vulnerabilities>
    </dependency>
  </dependencies>
</analysis>"""


def test_parse_sarif_extracts_findings():
    findings = triage.parse_sarif(SAMPLE_SARIF)
    assert len(findings) == 1
    assert findings[0]["tool"] == "Semgrep"
    assert findings[0]["severity"] == "high"
    assert findings[0]["line"] == 42


def test_parse_trivy_json_extracts_findings():
    findings = triage.parse_trivy_json(SAMPLE_TRIVY)
    assert len(findings) == 1
    assert findings[0]["check_id"] == "CVE-2024-1111"
    assert findings[0]["severity"] == "high"


def test_parse_owasp_dependency_check_xml_extracts_findings():
    findings = triage.parse_owasp_dependency_check_xml(SAMPLE_OWASP_DC_XML)
    assert len(findings) == 1
    assert findings[0]["check_id"] == "CVE-2021-44228"
    assert findings[0]["severity"] == "critical"
    assert "log4j-core" in findings[0]["file"]


def test_parse_owasp_dependency_check_xml_handles_malformed_xml():
    assert triage.parse_owasp_dependency_check_xml("not xml at all <<<") == []


def _text_block(text):
    block = MagicMock()
    block.type = "text"
    block.text = text
    return block


def test_triage_findings_annotates_verdict_severity_and_fix():
    findings = [{"tool": "semgrep", "check_id": "eval-detected", "severity": "high", "message": "eval() used", "source_format": "sarif", "file": "app.py", "line": 1}]
    fake_ai = MagicMock()
    resp = MagicMock()
    resp.content = [_text_block("0: REAL | SEVERITY:critical | FIX: Replace eval() with ast.literal_eval().")]
    fake_ai.messages.create.return_value = resp

    with patch.object(triage, "_claude_client", return_value=fake_ai):
        result = triage.triage_findings(findings)

    assert result[0]["ai_verdict"] == "REAL"
    assert result[0]["recalibrated_severity"] == "critical"
    assert "ast.literal_eval" in result[0]["fix_suggestion"]


def test_create_jira_ticket_skips_without_config():
    with patch("app.services.triage.settings") as mock_settings:
        mock_settings.JIRA_BASE_URL = ""
        mock_settings.JIRA_API_TOKEN = ""
        mock_settings.JIRA_EMAIL = ""
        with patch("app.services.triage.httpx.post") as mock_post:
            result = triage.create_jira_ticket({"severity": "high", "tool": "trivy", "message": "m"})
    mock_post.assert_not_called()
    assert result is None


def test_create_jira_ticket_success():
    resp = MagicMock()
    resp.status_code = 201
    resp.json.return_value = {"key": "SEC-1"}
    with patch("app.services.triage.settings") as mock_settings:
        mock_settings.JIRA_BASE_URL = "https://acme.atlassian.net"
        mock_settings.JIRA_API_TOKEN = "tok"
        mock_settings.JIRA_EMAIL = "bot@acme.com"
        with patch("app.services.triage.httpx.post", return_value=resp):
            result = triage.create_jira_ticket({"severity": "high", "tool": "trivy", "message": "m"})
    assert result == {"key": "SEC-1"}


def test_sync_triage_findings_to_db_skips_false_positives(client):
    db = SessionLocal()
    c = _make_client(db)
    findings = [
        {"tool": "semgrep", "check_id": "a", "severity": "high", "recalibrated_severity": "high", "message": "real one", "ai_verdict": "REAL", "source_format": "sarif", "file": "a.py", "line": 1, "fix_suggestion": ""},
        {"tool": "semgrep", "check_id": "b", "severity": "medium", "recalibrated_severity": "medium", "message": "fp", "ai_verdict": "FALSE_POSITIVE", "source_format": "sarif", "file": "b.py", "line": 2, "fix_suggestion": ""},
    ]
    count = triage.sync_triage_findings_to_db(db, c, findings)
    assert count == 1
    findings_in_db = db.query(Finding).filter_by(client_id=c.id).all()
    assert len(findings_in_db) == 1
    assert findings_in_db[0].title.startswith("[CI Scan]")


def test_generate_weekly_triage_digest_honest_when_quiet():
    fake_ai = MagicMock()
    resp = MagicMock()
    resp.content = [_text_block("Quiet week.")]
    fake_ai.messages.create.return_value = resp
    with patch.object(triage, "_claude_client", return_value=fake_ai):
        triage.generate_weekly_triage_digest("Acme Co", [])
    prompt = fake_ai.messages.create.call_args.kwargs["messages"][0]["content"]
    assert "genuinely quiet" in prompt
