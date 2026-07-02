import uuid
from unittest.mock import patch, MagicMock

from app.core.database import SessionLocal
from app.models.models import Client, Finding
from app.services import threat_intel


def _make_client(db):
    c = Client(id=str(uuid.uuid4()), name="Intel Test Co", root_domain="intel-test.example.com",
               contact_email="a@intel-test.example.com")
    db.add(c)
    db.commit()
    return c


def test_check_paste_sites_returns_hits_from_index():
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"data": [{"id": "abc123", "time": "2026-01-01"}]}
    with patch("app.services.threat_intel.httpx.get", return_value=resp):
        hits = threat_intel.check_paste_sites("intel-test.example.com")
    assert len(hits) == 1
    assert hits[0]["paste_id"] == "abc123"
    assert "pastebin.com/abc123" in hits[0]["url"]


def test_check_paste_sites_degrades_gracefully_on_non_200():
    resp = MagicMock()
    resp.status_code = 500
    with patch("app.services.threat_intel.httpx.get", return_value=resp):
        hits = threat_intel.check_paste_sites("intel-test.example.com")
    assert hits == []


def test_check_paste_sites_degrades_gracefully_on_network_error():
    import httpx as httpx_module
    with patch("app.services.threat_intel.httpx.get", side_effect=httpx_module.ConnectError("down")):
        hits = threat_intel.check_paste_sites("intel-test.example.com")
    assert hits == []


def test_check_dehashed_skips_without_api_key():
    with patch("app.services.threat_intel.settings") as mock_settings:
        mock_settings.DEHASHED_API_KEY = ""
        with patch("app.services.threat_intel.httpx.get") as mock_get:
            hits = threat_intel.check_dehashed("intel-test.example.com")
    mock_get.assert_not_called()
    assert hits == []


def test_check_dehashed_returns_hits_with_key_set():
    resp = MagicMock()
    resp.json.return_value = {"entries": [{"email": "a@intel-test.example.com", "database_name": "BreachXYZ", "id": "1"}]}
    with patch("app.services.threat_intel.settings") as mock_settings:
        mock_settings.DEHASHED_API_KEY = "fake-key"
        with patch("app.services.threat_intel.httpx.get", return_value=resp):
            hits = threat_intel.check_dehashed("intel-test.example.com")
    assert len(hits) == 1
    assert hits[0]["database_name"] == "BreachXYZ"


def test_check_emerging_threats_flags_ip_on_blocklist():
    resp = MagicMock()
    resp.text = "1.2.3.4\n5.6.7.8\n# comment\n9.9.9.9\n"
    resp.raise_for_status = MagicMock()
    with patch("app.services.threat_intel.httpx.get", return_value=resp):
        hits = threat_intel.check_emerging_threats(["1.2.3.4", "10.0.0.1"])
    assert len(hits) == 1
    assert hits[0]["ip"] == "1.2.3.4"


def test_check_emerging_threats_empty_ip_list_skips_fetch():
    with patch("app.services.threat_intel.httpx.get") as mock_get:
        hits = threat_intel.check_emerging_threats([])
    mock_get.assert_not_called()
    assert hits == []


def test_check_emerging_threats_degrades_gracefully_on_fetch_failure():
    import httpx as httpx_module
    with patch("app.services.threat_intel.httpx.get", side_effect=httpx_module.ConnectError("down")):
        hits = threat_intel.check_emerging_threats(["1.2.3.4"])
    assert hits == []


def test_sync_intel_findings_to_db_handles_new_sources(client):
    db = SessionLocal()
    c = _make_client(db)
    paste_hits = [{"paste_id": "p1", "date": "2026-01-01", "url": "https://pastebin.com/p1", "note": "n"}]
    dehashed_hits = [{"email": "a@intel-test.example.com", "database_name": "BreachXYZ", "id": "d1", "note": "n"}]
    et_hits = [{"ip": "1.2.3.4", "note": "n"}]
    count = threat_intel.sync_intel_findings_to_db(
        db, c, breaches=[], github_hits=[], blocklist_hits=[],
        paste_hits=paste_hits, dehashed_hits=dehashed_hits, et_hits=et_hits,
    )
    assert count == 3
    findings = db.query(Finding).filter_by(client_id=c.id).all()
    severities = {f.severity.value for f in findings}
    assert "medium" in severities  # paste
    assert "high" in severities  # dehashed
    assert "critical" in severities  # emerging threats


def test_sync_intel_findings_to_db_dedupes_paste_hits_on_rerun(client):
    db = SessionLocal()
    c = _make_client(db)
    paste_hits = [{"paste_id": "p1", "date": "2026-01-01", "url": "https://pastebin.com/p1", "note": "n"}]
    threat_intel.sync_intel_findings_to_db(db, c, breaches=[], github_hits=[], blocklist_hits=[], paste_hits=paste_hits)
    second_count = threat_intel.sync_intel_findings_to_db(db, c, breaches=[], github_hits=[], blocklist_hits=[], paste_hits=paste_hits)
    assert second_count == 0
