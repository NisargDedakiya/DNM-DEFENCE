import io
import json
import uuid
from unittest.mock import patch

from app.core.database import SessionLocal
from app.models.models import Client


def _seed_client():
    db = SessionLocal()
    c = Client(id=str(uuid.uuid4()), name="DevSecOps API Co", root_domain="devsecops-api.example.com",
               contact_email="a@devsecops-api.example.com")
    db.add(c)
    db.commit()
    cid = c.id
    db.close()
    return cid


def test_register_pipeline_rejects_unknown_template(admin_user, client):
    client_id = _seed_client()
    r = client.post(f"/api/clients/{client_id}/devsecops/pipelines", headers=admin_user["headers"],
                     json={"repo_full_name": "acme/backend", "template": "not_a_real_template"})
    assert r.status_code == 422


def test_register_and_list_pipeline(admin_user, client):
    client_id = _seed_client()
    r = client.post(f"/api/clients/{client_id}/devsecops/pipelines", headers=admin_user["headers"],
                     json={"repo_full_name": "acme/backend", "template": "python_fastapi", "block_on_severity": "high"})
    assert r.status_code == 201
    pipeline_id = r.json()["id"]

    r = client.get(f"/api/clients/{client_id}/devsecops/pipelines", headers=admin_user["headers"])
    assert len(r.json()) == 1
    assert r.json()[0]["id"] == pipeline_id


def test_deploy_gate_calls_service(admin_user, client):
    client_id = _seed_client()
    pipeline_id = client.post(f"/api/clients/{client_id}/devsecops/pipelines", headers=admin_user["headers"],
                               json={"repo_full_name": "acme/backend", "template": "python_fastapi"}).json()["id"]

    with patch("app.api.devsecops.deploy_gate_workflow", return_value={"action": "created", "path": ".github/workflows/track1-security-gate.yml"}) as mock_deploy:
        r = client.post(f"/api/clients/{client_id}/devsecops/pipelines/{pipeline_id}/deploy-gate", headers=admin_user["headers"])
    assert r.status_code == 200
    assert r.json()["action"] == "created"
    mock_deploy.assert_called_once()


def test_poll_pipeline_syncs_findings(admin_user, client):
    client_id = _seed_client()
    pipeline_id = client.post(f"/api/clients/{client_id}/devsecops/pipelines", headers=admin_user["headers"],
                               json={"repo_full_name": "acme/backend", "template": "python_fastapi"}).json()["id"]

    fake_runs = [{"run_id": 1, "conclusion": "failure", "html_url": "u", "head_branch": "main", "head_sha": "abc"}]
    with patch("app.api.devsecops.poll_pipeline_runs", return_value=fake_runs):
        r = client.post(f"/api/clients/{client_id}/devsecops/pipelines/{pipeline_id}/poll", headers=admin_user["headers"])
    assert r.status_code == 200
    assert r.json()["new_findings"] == 1


def test_triage_sarif_upload(admin_user, client):
    client_id = _seed_client()
    sarif = {"runs": [{"tool": {"driver": {"name": "Semgrep"}}, "results": [
        {"ruleId": "r1", "level": "error", "message": {"text": "bad"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 1}}}]},
    ]}]}
    with patch("app.api.devsecops.triage_findings", side_effect=lambda f: f):
        r = client.post(f"/api/clients/{client_id}/devsecops/triage/sarif", headers=admin_user["headers"],
                         files={"file": ("results.sarif", io.BytesIO(json.dumps(sarif).encode()), "application/json")})
    assert r.status_code == 200
    assert r.json()["parsed"] == 1
    assert r.json()["new_findings"] == 1


def test_triage_sarif_rejects_invalid_json(admin_user, client):
    client_id = _seed_client()
    r = client.post(f"/api/clients/{client_id}/devsecops/triage/sarif", headers=admin_user["headers"],
                     files={"file": ("bad.sarif", io.BytesIO(b"not json"), "application/json")})
    assert r.status_code == 422


def test_scorecard_endpoints(admin_user, client):
    client_id = _seed_client()
    r = client.get(f"/api/clients/{client_id}/devsecops/scorecard", headers=admin_user["headers"])
    assert r.status_code == 200
    assert r.json()["total_pipeline_findings"] == 0

    r = client.post(f"/api/clients/{client_id}/devsecops/scorecard/snapshot", headers=admin_user["headers"])
    assert r.status_code == 200

    r = client.get(f"/api/clients/{client_id}/devsecops/scorecard/trend", headers=admin_user["headers"])
    assert len(r.json()) == 1


def test_scorecard_export_pdf(admin_user, client):
    client_id = _seed_client()
    with patch("app.api.devsecops.generate_scorecard_narrative", return_value="All good."):
        r = client.get(f"/api/clients/{client_id}/devsecops/scorecard/export/pdf", headers=admin_user["headers"])
    assert r.status_code == 200
    assert r.content[:4] == b"%PDF"


def test_iac_scan_endpoint(admin_user, client):
    client_id = _seed_client()
    fake_findings = [{"tool": "checkov", "check_id": "CKV_1", "severity": "high", "resource": "aws_s3_bucket.x",
                       "description": "public bucket", "file": "main.tf", "line": 1}]
    with patch("app.api.devsecops.run_checkov", return_value=fake_findings):
        r = client.post(f"/api/clients/{client_id}/devsecops/iac-scan", headers=admin_user["headers"],
                         files={"file": ("main.tf", io.BytesIO(b"resource \"aws_s3_bucket\" \"x\" {}"), "text/plain")})
    assert r.status_code == 200
    assert r.json()["new_findings"] == 1
