import uuid
from unittest.mock import patch

from app.core.database import SessionLocal
from app.models.models import Client


def _seed_client():
    db = SessionLocal()
    c = Client(id=str(uuid.uuid4()), name="Web3 Co", root_domain="web3.example.com", contact_email="a@web3.example.com")
    db.add(c)
    db.commit()
    cid = c.id
    db.close()
    return cid


FAKE_SCAN_RESULT = {
    "solc_version_hint": "^0.8.19",
    "findings": [{"tool": "slither", "check": "reentrancy-eth", "severity": "critical", "description": "Reentrancy found.", "elements": [{"line": 42}]}],
}


def test_create_contract_audit_runs_scan_and_stores_findings(admin_user, client):
    client_id = _seed_client()
    with patch("app.api.web3_security.run_contract_scan", return_value=FAKE_SCAN_RESULT):
        r = client.post(f"/api/clients/{client_id}/web3/contract-audits", headers=admin_user["headers"],
                         json={"contract_name": "Vault", "contract_source": "pragma solidity ^0.8.19;\ncontract Vault {}", "network": "ethereum"})
    assert r.status_code == 201
    body = r.json()
    assert body["status"] == "completed"
    assert body["solc_version_hint"] == "^0.8.19"
    assert len(body["findings"]) == 1


def test_create_contract_audit_marks_failed_on_exception(admin_user, client):
    client_id = _seed_client()
    with patch("app.api.web3_security.run_contract_scan", side_effect=RuntimeError("solc parse error")):
        r = client.post(f"/api/clients/{client_id}/web3/contract-audits", headers=admin_user["headers"],
                         json={"contract_name": "Vault", "contract_source": "garbage", "network": "ethereum"})
    assert r.status_code == 201
    body = r.json()
    assert body["status"] == "failed"
    assert "solc parse error" in body["error_message"]


def test_export_audit_pdf_and_markdown(admin_user, client):
    client_id = _seed_client()
    with patch("app.api.web3_security.run_contract_scan", return_value=FAKE_SCAN_RESULT):
        audit_id = client.post(f"/api/clients/{client_id}/web3/contract-audits", headers=admin_user["headers"],
                                json={"contract_name": "Vault", "contract_source": "pragma solidity ^0.8.19;", "network": "ethereum"}).json()["id"]

    r = client.get(f"/api/clients/{client_id}/web3/contract-audits/{audit_id}/export/pdf", headers=admin_user["headers"])
    assert r.status_code == 200
    assert r.content[:4] == b"%PDF"

    r = client.get(f"/api/clients/{client_id}/web3/contract-audits/{audit_id}/export/markdown", headers=admin_user["headers"])
    assert r.status_code == 200
    assert "Vault" in r.text


def test_create_and_toggle_onchain_monitor(admin_user, client):
    client_id = _seed_client()
    r = client.post(f"/api/clients/{client_id}/web3/onchain-monitors", headers=admin_user["headers"],
                     json={"contract_address": "0xabc123", "network": "ethereum"})
    assert r.status_code == 201
    monitor_id = r.json()["id"]
    assert r.json()["is_active"] is True

    r = client.patch(f"/api/clients/{client_id}/web3/onchain-monitors/{monitor_id}", headers=admin_user["headers"],
                      params={"is_active": False})
    assert r.status_code == 200
    assert r.json()["is_active"] is False

    r = client.get(f"/api/clients/{client_id}/web3/onchain-monitors", headers=admin_user["headers"])
    assert len(r.json()) == 1
