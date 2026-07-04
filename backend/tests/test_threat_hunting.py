import json
import uuid
from unittest.mock import MagicMock, patch

from app.core.database import SessionLocal
from app.models.models import HuntHypothesis, HuntOperation, HuntFinding, Severity, SiemConnection, SiemProvider
from app.services.threat_hunting import (
    seed_hypothesis_library, generate_hypothesis, query_elastic, query_splunk, query_crowdstrike,
    enrich_ioc, generate_hunt_report, compute_attck_coverage, STARTER_HYPOTHESES,
)


def _fake_connection(provider):
    return SiemConnection(id=str(uuid.uuid4()), client_id=str(uuid.uuid4()), provider=provider,
                           base_url="https://siem.example.com", encrypted_credentials="unused-for-this-test")


def test_seed_hypothesis_library_creates_starter_set(client):
    db = SessionLocal()
    created = seed_hypothesis_library(db)
    assert created == len(STARTER_HYPOTHESES)
    assert db.query(HuntHypothesis).count() == len(STARTER_HYPOTHESES)
    db.close()


def test_seed_hypothesis_library_is_idempotent(client):
    db = SessionLocal()
    seed_hypothesis_library(db)
    second_run = seed_hypothesis_library(db)
    assert second_run == 0
    assert db.query(HuntHypothesis).count() == len(STARTER_HYPOTHESES)
    db.close()


def test_generate_hypothesis_parses_json_response():
    fake_response = MagicMock()
    fake_response.content = [MagicMock(type="text", text=json.dumps({
        "title": "Anomalous VPN logins", "description": "Hunt for VPN logins from new ASNs.",
        "attack_technique": "T1133", "data_sources": ["VPN logs"],
    }))]
    with patch("app.services.threat_hunting._claude_client") as mock_client_factory:
        mock_client_factory.return_value.messages.create.return_value = fake_response
        result = generate_hypothesis("fintech", ["new VPN exploit trending"])
    assert result["title"] == "Anomalous VPN logins"
    assert result["attack_technique"] == "T1133"
    prompt = mock_client_factory.return_value.messages.create.call_args.kwargs["messages"][0]["content"]
    assert "fintech" in prompt
    assert "new VPN exploit trending" in prompt


def test_generate_hypothesis_wraps_non_json_response():
    fake_response = MagicMock()
    fake_response.content = [MagicMock(type="text", text="not valid json at all")]
    with patch("app.services.threat_hunting._claude_client") as mock_client_factory:
        mock_client_factory.return_value.messages.create.return_value = fake_response
        result = generate_hypothesis("technology")
    assert result["description"] == "not valid json at all"
    assert result["attack_technique"] is None


def test_query_elastic_returns_empty_without_connection():
    assert query_elastic(None, "some query") == []


def test_query_elastic_returns_empty_without_api_key():
    conn = _fake_connection(SiemProvider.elastic)
    with patch("app.services.threat_hunting.decrypt_credentials", return_value={}):
        assert query_elastic(conn, "some query") == []


def test_query_elastic_parses_hits():
    conn = _fake_connection(SiemProvider.elastic)
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {"hits": {"hits": [{"_source": {"user": "alice"}}]}}
    with patch("app.services.threat_hunting.decrypt_credentials", return_value={"api_key": "abc123"}), \
         patch("app.services.threat_hunting.httpx.post", return_value=resp) as mock_post:
        results = query_elastic(conn, "user:alice")
    assert results == [{"user": "alice"}]
    mock_post.assert_called_once()


def test_query_elastic_degrades_on_network_failure():
    import httpx as httpx_module
    conn = _fake_connection(SiemProvider.elastic)
    with patch("app.services.threat_hunting.decrypt_credentials", return_value={"api_key": "abc123"}), \
         patch("app.services.threat_hunting.httpx.post", side_effect=httpx_module.ConnectError("down")):
        assert query_elastic(conn, "user:alice") == []


def test_query_elastic_degrades_on_decrypt_failure():
    conn = _fake_connection(SiemProvider.elastic)
    with patch("app.services.threat_hunting.decrypt_credentials", side_effect=ValueError("bad key")):
        assert query_elastic(conn, "user:alice") == []


def test_query_splunk_parses_ndjson_results():
    conn = _fake_connection(SiemProvider.splunk)
    resp = MagicMock()
    resp.text = '{"result": {"host": "fs01"}}\n{"result": {"host": "ws02"}}\n'
    with patch("app.services.threat_hunting.decrypt_credentials", return_value={"username": "admin", "password": "pw"}), \
         patch("app.services.threat_hunting.httpx.post", return_value=resp) as mock_post:
        results = query_splunk(conn, "index=main host=fs01")
    assert len(results) == 2
    mock_post.assert_called_once()


def test_query_splunk_returns_empty_without_credentials():
    conn = _fake_connection(SiemProvider.splunk)
    with patch("app.services.threat_hunting.decrypt_credentials", return_value={}):
        assert query_splunk(conn, "search") == []


def test_query_crowdstrike_exchanges_token_then_queries():
    conn = _fake_connection(SiemProvider.crowdstrike)
    token_resp = MagicMock()
    token_resp.raise_for_status = MagicMock()
    token_resp.json.return_value = {"access_token": "tok123"}
    detects_resp = MagicMock()
    detects_resp.raise_for_status = MagicMock()
    detects_resp.json.return_value = {"resources": ["ldt:abc:123"]}
    with patch("app.services.threat_hunting.decrypt_credentials", return_value={"client_id": "id", "client_secret": "secret"}), \
         patch("app.services.threat_hunting.httpx.post", return_value=token_resp), \
         patch("app.services.threat_hunting.httpx.get", return_value=detects_resp):
        results = query_crowdstrike(conn, "status:'new'")
    assert results == ["ldt:abc:123"]


def test_query_crowdstrike_returns_empty_without_credentials():
    conn = _fake_connection(SiemProvider.crowdstrike)
    with patch("app.services.threat_hunting.decrypt_credentials", return_value={}):
        assert query_crowdstrike(conn, "status:'new'") == []


def test_enrich_ioc_ip_calls_all_three_checks():
    with patch("app.services.threat_hunting.check_shodan", return_value=[{"ip": "1.2.3.4"}]) as mock_shodan, \
         patch("app.services.threat_hunting.check_censys", return_value=[]) as mock_censys, \
         patch("app.services.threat_hunting.check_threat_intel_blocklists", return_value=[]) as mock_blocklists:
        result = enrich_ioc("1.2.3.4", "ip")
    assert result["enriched"] is True
    assert result["flagged"] is True
    mock_shodan.assert_called_once_with(["1.2.3.4"])
    mock_censys.assert_called_once_with(["1.2.3.4"])
    mock_blocklists.assert_called_once_with(["1.2.3.4"])


def test_enrich_ioc_non_ip_returns_not_enriched():
    result = enrich_ioc("evil.example.com", "domain")
    assert result["enriched"] is False


def test_generate_hunt_report_grounded_in_findings():
    hypothesis = HuntHypothesis(id="h1", title="Kerberoasting attempts")
    hunt = HuntOperation(id="hunt1", client_id="c1", hypothesis_id="h1", hours_spent=4, outcome="threat_found")
    hunt.hypothesis = hypothesis
    findings = [HuntFinding(id="f1", hunt_id="hunt1", severity=Severity.high, title="Abnormal TGS request volume",
                             description="Service account requested 200 tickets in 5 minutes", confirmed=True, escalated_to_ir=True)]
    fake_response = MagicMock()
    fake_response.content = [MagicMock(type="text", text="Hunt report body.")]
    with patch("app.services.threat_hunting._claude_client") as mock_client_factory:
        mock_client_factory.return_value.messages.create.return_value = fake_response
        report = generate_hunt_report(hunt, findings)
    assert report == "Hunt report body."
    prompt = mock_client_factory.return_value.messages.create.call_args.kwargs["messages"][0]["content"]
    assert "Kerberoasting attempts" in prompt
    assert "Abnormal TGS request volume" in prompt


def test_compute_attck_coverage_counts_techniques():
    hyp1 = HuntHypothesis(id="h1", title="a", attack_technique="T1558.003")
    hyp2 = HuntHypothesis(id="h2", title="b", attack_technique="T1558.003")
    hunt1 = HuntOperation(id="o1", client_id="c1", hypothesis_id="h1")
    hunt1.hypothesis = hyp1
    hunt2 = HuntOperation(id="o2", client_id="c1", hypothesis_id="h2")
    hunt2.hypothesis = hyp2
    layer = compute_attck_coverage([hunt1, hunt2])
    scores = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    assert scores["T1558.003"] == 2


def test_compute_attck_coverage_handles_empty_list():
    layer = compute_attck_coverage([])
    assert layer["techniques"] == []
