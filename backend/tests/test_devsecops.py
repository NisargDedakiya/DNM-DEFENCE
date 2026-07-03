import uuid
from unittest.mock import MagicMock, patch

from app.core.database import SessionLocal
from app.models.models import Client, Finding
from app.services import devsecops


def _make_client(db):
    c = Client(id=str(uuid.uuid4()), name="DevSecOps Co", root_domain="devsecops.example.com",
               contact_email="a@devsecops.example.com")
    db.add(c)
    db.commit()
    return c


def test_render_gate_workflow_rejects_unknown_template():
    try:
        devsecops.render_gate_workflow("unknown_stack")
        assert False, "expected ValueError"
    except ValueError as e:
        assert "Unknown gate template" in str(e)


def test_render_gate_workflow_preserves_github_actions_syntax():
    out = devsecops.render_gate_workflow("python_fastapi", "high")
    assert "${{ secrets.GITHUB_TOKEN }}" in out
    assert "HIGH" in out  # block_on_severity | upper


def test_github_client_requires_token():
    with patch("app.services.devsecops.settings") as mock_settings:
        mock_settings.GITHUB_TOKEN = ""
        try:
            devsecops._github_client(token=None)
            assert False, "expected RuntimeError"
        except RuntimeError as e:
            assert "No GitHub token" in str(e)


def test_deploy_gate_workflow_creates_new_file_when_not_present():
    fake_repo = MagicMock()
    fake_repo.get_contents.side_effect = Exception("404 not found")
    fake_gh = MagicMock()
    fake_gh.get_repo.return_value = fake_repo

    with patch.object(devsecops, "_github_client", return_value=fake_gh):
        result = devsecops.deploy_gate_workflow("acme/backend", "python_fastapi", "high", token="fake-token")

    assert result["action"] == "created"
    fake_repo.create_file.assert_called_once()


def test_deploy_gate_workflow_updates_existing_file():
    fake_existing = MagicMock()
    fake_existing.sha = "abc123"
    fake_repo = MagicMock()
    fake_repo.get_contents.return_value = fake_existing
    fake_gh = MagicMock()
    fake_gh.get_repo.return_value = fake_repo

    with patch.object(devsecops, "_github_client", return_value=fake_gh):
        result = devsecops.deploy_gate_workflow("acme/backend", "python_fastapi", "high", token="fake-token")

    assert result["action"] == "updated"
    fake_repo.update_file.assert_called_once()


def _fake_run(run_id, conclusion, path="/.github/workflows/track1-security-gate.yml"):
    run = MagicMock()
    run.id = run_id
    run.conclusion = conclusion
    run.status = "completed"
    run.html_url = f"https://github.com/acme/backend/actions/runs/{run_id}"
    run.created_at = None
    run.head_branch = "main"
    run.head_sha = "deadbeef1234"
    run.path = path
    return run


def test_poll_pipeline_runs_filters_to_gate_workflow():
    fake_repo = MagicMock()
    fake_repo.get_workflow_runs.return_value = [
        _fake_run(1, "success"),
        _fake_run(2, "failure", path="/.github/workflows/other.yml"),
    ]
    fake_gh = MagicMock()
    fake_gh.get_repo.return_value = fake_repo

    with patch.object(devsecops, "_github_client", return_value=fake_gh):
        runs = devsecops.poll_pipeline_runs("acme/backend")

    assert len(runs) == 1
    assert runs[0]["run_id"] == 1


def test_sync_pipeline_findings_to_db_only_syncs_failures(client):
    db = SessionLocal()
    c = _make_client(db)
    runs = [
        {"run_id": 1, "conclusion": "success", "html_url": "u1", "head_branch": "main", "head_sha": "abc"},
        {"run_id": 2, "conclusion": "failure", "html_url": "u2", "head_branch": "main", "head_sha": "def"},
    ]
    count = devsecops.sync_pipeline_findings_to_db(db, c, "acme/backend", runs)
    assert count == 1
    findings = db.query(Finding).filter_by(client_id=c.id).all()
    assert len(findings) == 1
    assert findings[0].title.startswith("[Pipeline]")


def test_sync_pipeline_findings_to_db_dedupes_on_rerun(client):
    db = SessionLocal()
    c = _make_client(db)
    runs = [{"run_id": 5, "conclusion": "failure", "html_url": "u", "head_branch": "main", "head_sha": "abc"}]
    devsecops.sync_pipeline_findings_to_db(db, c, "acme/backend", runs)
    second = devsecops.sync_pipeline_findings_to_db(db, c, "acme/backend", runs)
    assert second == 0
