from unittest.mock import MagicMock, patch

from app.services import attack_framework


def test_bundled_tactics_cover_all_14_enterprise_tactics():
    assert len(attack_framework.ATTACK_TACTICS) == 14
    assert "initial_access" in attack_framework.ATTACK_TACTICS
    assert "impact" in attack_framework.ATTACK_TACTICS


def test_bundled_techniques_reference_valid_tactics():
    for technique_id, (tactic, name) in attack_framework.ATTACK_TECHNIQUES.items():
        assert tactic in attack_framework.ATTACK_TACTICS, f"{technique_id} references unknown tactic {tactic}"
        assert name


def test_fetch_technique_name_uses_bundled_list_without_network_call():
    with patch("app.services.attack_framework.httpx.get") as mock_get:
        name = attack_framework.fetch_technique_name("T1566.001")
    mock_get.assert_not_called()
    assert name == "Phishing: Spearphishing Attachment"


def test_fetch_technique_name_falls_back_to_id_on_network_failure():
    import httpx as httpx_module
    with patch("app.services.attack_framework.httpx.get", side_effect=httpx_module.ConnectError("down")):
        name = attack_framework.fetch_technique_name("T9999.999")
    assert name == "T9999.999"


def test_fetch_technique_name_resolves_unknown_id_via_live_lookup_and_caches():
    resp = MagicMock()
    resp.json.return_value = {
        "objects": [{
            "type": "attack-pattern", "name": "Some Novel Technique",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T9111"}],
        }]
    }
    resp.raise_for_status = MagicMock()
    with patch("app.services.attack_framework.httpx.get", return_value=resp) as mock_get:
        name1 = attack_framework.fetch_technique_name("T9111")
        name2 = attack_framework.fetch_technique_name("T9111")  # should hit the cache, not fetch again
    assert name1 == "Some Novel Technique"
    assert name2 == "Some Novel Technique"
    mock_get.assert_called_once()


def test_generate_navigator_layer_produces_valid_layer_shape():
    layer = attack_framework.generate_navigator_layer({"T1566.001": 3, "T1078": 1}, name="Test Op")
    assert layer["name"] == "Test Op"
    assert layer["domain"] == "enterprise-attack"
    assert len(layer["techniques"]) == 2
    scores = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    assert scores["T1566.001"] == 3
    assert layer["gradient"]["maxValue"] == 3


def test_generate_navigator_layer_handles_empty_input():
    layer = attack_framework.generate_navigator_layer({})
    assert layer["techniques"] == []
