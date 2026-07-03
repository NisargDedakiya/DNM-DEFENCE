import json
import uuid
from unittest.mock import MagicMock, patch

from app.core.database import SessionLocal
from app.models.models import Client, Finding
from app.services import iac_scan


def _make_client(db):
    c = Client(id=str(uuid.uuid4()), name="IaC Co", root_domain="iac.example.com", contact_email="a@iac.example.com")
    db.add(c)
    db.commit()
    return c


SAMPLE_CHECKOV_OUTPUT = {
    "results": {
        "failed_checks": [{
            "check_id": "CKV_AWS_20", "check_name": "S3 Bucket has an ACL defined which allows public access",
            "severity": "HIGH", "resource": "aws_s3_bucket.data", "file_path": "/main.tf", "file_line_range": [10, 15],
        }]
    }
}


def test_run_checkov_skips_gracefully_when_binary_missing():
    with patch("app.services.iac_scan.subprocess.run", side_effect=FileNotFoundError()):
        assert iac_scan.run_checkov("/tmp/some-dir") == []


def test_run_checkov_parses_single_report_json():
    fake_proc = MagicMock()
    fake_proc.stdout = json.dumps(SAMPLE_CHECKOV_OUTPUT)
    with patch("app.services.iac_scan.subprocess.run", return_value=fake_proc):
        findings = iac_scan.run_checkov("/tmp/some-dir")
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert findings[0]["check_id"] == "CKV_AWS_20"
    assert findings[0]["line"] == 10


def test_run_checkov_parses_multi_framework_list_json():
    fake_proc = MagicMock()
    fake_proc.stdout = json.dumps([SAMPLE_CHECKOV_OUTPUT, SAMPLE_CHECKOV_OUTPUT])
    with patch("app.services.iac_scan.subprocess.run", return_value=fake_proc):
        findings = iac_scan.run_checkov("/tmp/some-dir")
    assert len(findings) == 2


def test_run_checkov_handles_malformed_json():
    fake_proc = MagicMock()
    fake_proc.stdout = "not json"
    with patch("app.services.iac_scan.subprocess.run", return_value=fake_proc):
        assert iac_scan.run_checkov("/tmp/some-dir") == []


def test_run_optional_enrichment_degrades_gracefully_when_tool_missing():
    assert iac_scan.run_optional_enrichment("definitely-not-a-real-binary", []) is None


def test_sync_iac_findings_to_db(client):
    db = SessionLocal()
    c = _make_client(db)
    findings = [{"tool": "checkov", "check_id": "CKV_AWS_20", "severity": "high", "resource": "aws_s3_bucket.data",
                 "description": "S3 bucket public access", "file": "/main.tf", "line": 10, "fix_suggestion": ""}]
    count = iac_scan.sync_iac_findings_to_db(db, c, findings)
    assert count == 1
    saved = db.query(Finding).filter_by(client_id=c.id).all()
    assert saved[0].title.startswith("[IaC]")


def test_sync_iac_findings_to_db_dedupes_on_rerun(client):
    db = SessionLocal()
    c = _make_client(db)
    findings = [{"tool": "checkov", "check_id": "CKV_AWS_20", "severity": "high", "resource": "aws_s3_bucket.data",
                 "description": "S3 bucket public access", "file": "/main.tf", "line": 10, "fix_suggestion": ""}]
    iac_scan.sync_iac_findings_to_db(db, c, findings)
    second = iac_scan.sync_iac_findings_to_db(db, c, findings)
    assert second == 0


def test_post_pr_comment_no_findings():
    fake_pr = MagicMock()
    fake_comment = MagicMock(id=1, html_url="https://github.com/acme/backend/pull/1#comment-1")
    fake_pr.create_issue_comment.return_value = fake_comment
    fake_repo = MagicMock()
    fake_repo.get_pull.return_value = fake_pr
    fake_gh = MagicMock()
    fake_gh.get_repo.return_value = fake_repo

    with patch("app.services.devsecops._github_client", return_value=fake_gh):
        result = iac_scan.post_pr_comment("acme/backend", 1, [], token="fake-token")

    assert result["comment_id"] == 1
    fake_pr.create_issue_comment.assert_called_once()
    body = fake_pr.create_issue_comment.call_args.args[0]
    assert "no findings" in body.lower()


def test_post_pr_comment_with_findings():
    fake_pr = MagicMock()
    fake_comment = MagicMock(id=2, html_url="https://github.com/acme/backend/pull/1#comment-2")
    fake_pr.create_issue_comment.return_value = fake_comment
    fake_repo = MagicMock()
    fake_repo.get_pull.return_value = fake_pr
    fake_gh = MagicMock()
    fake_gh.get_repo.return_value = fake_repo

    findings = [{"severity": "high", "check_id": "CKV_AWS_20", "file": "/main.tf", "description": "public bucket"}]
    with patch("app.services.devsecops._github_client", return_value=fake_gh):
        iac_scan.post_pr_comment("acme/backend", 1, findings, token="fake-token")

    body = fake_pr.create_issue_comment.call_args.args[0]
    assert "CKV_AWS_20" in body
