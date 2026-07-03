import sys
import types
from unittest.mock import MagicMock, patch

import pytest

from app.services import web3_scan


def test_detect_solc_version_parses_pragma_line():
    source = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.19;\ncontract Foo {}"
    assert web3_scan.detect_solc_version(source) == "^0.8.19"


def test_detect_solc_version_none_when_absent():
    assert web3_scan.detect_solc_version("contract Foo {}") is None


def test_run_slither_skips_gracefully_when_not_installed(monkeypatch):
    monkeypatch.delitem(sys.modules, "slither", raising=False)
    with patch.dict(sys.modules, {"slither": None}):
        assert web3_scan.run_slither("/tmp/fake.sol") == []


@pytest.fixture
def fake_slither_module():
    fake_slither_pkg = types.ModuleType("slither")

    class FakeSlither:
        def __init__(self, path):
            self.path = path

        def run_detectors(self):
            return [[{
                "check": "reentrancy-eth", "impact": "High",
                "description": "Reentrancy vulnerability found.",
                "elements": [{"source_mapping": {"lines": [42]}}],
            }]]

    fake_slither_pkg.Slither = FakeSlither
    sys.modules["slither"] = fake_slither_pkg
    yield fake_slither_pkg
    del sys.modules["slither"]


def test_run_slither_maps_impact_to_severity(fake_slither_module):
    findings = web3_scan.run_slither("/tmp/fake.sol")
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"
    assert findings[0]["tool"] == "slither"
    assert findings[0]["elements"][0]["line"] == 42


def test_run_semgrep_skips_gracefully_when_binary_missing():
    with patch("app.services.web3_scan.subprocess.run", side_effect=FileNotFoundError()):
        assert web3_scan.run_semgrep("/tmp/fake.sol") == []


def test_run_semgrep_parses_json_output():
    fake_proc = MagicMock()
    fake_proc.stdout = (
        '{"results": [{"check_id": "tx-origin-auth", '
        '"extra": {"severity": "ERROR", "message": "tx.origin used"}, '
        '"start": {"line": 10}}]}'
    )
    with patch("app.services.web3_scan.subprocess.run", return_value=fake_proc):
        findings = web3_scan.run_semgrep("/tmp/fake.sol")
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert findings[0]["elements"][0]["line"] == 10


def test_run_mythril_skips_gracefully_when_binary_missing():
    with patch("app.services.web3_scan.subprocess.run", side_effect=FileNotFoundError()):
        assert web3_scan.run_mythril("/tmp/fake.sol") == []


def test_dedup_findings_collapses_same_line_and_rule_family():
    findings = [
        {"tool": "slither", "check": "reentrancy-eth", "severity": "critical", "description": "a", "elements": [{"line": 10}]},
        {"tool": "semgrep", "check": "reentrancy-external-call", "severity": "medium", "description": "b", "elements": [{"line": 10}]},
        {"tool": "semgrep", "check": "tx-origin-auth", "severity": "high", "description": "c", "elements": [{"line": 20}]},
    ]
    deduped = web3_scan.dedup_findings(findings)
    assert len(deduped) == 2


def _text_block(text):
    block = MagicMock()
    block.type = "text"
    block.text = text
    return block


def test_filter_false_positives_annotates_without_deleting():
    findings = [
        {"tool": "semgrep", "check": "block-timestamp-dependence", "severity": "low", "description": "timestamp used", "elements": []},
    ]
    fake_ai = MagicMock()
    resp = MagicMock()
    resp.content = [_text_block("0: LIKELY_FALSE_POSITIVE - not used for randomness here")]
    fake_ai.messages.create.return_value = resp

    with patch.object(web3_scan, "_claude_client", return_value=fake_ai):
        result = web3_scan.filter_false_positives("contract Foo {}", findings)

    assert len(result) == 1
    assert result[0]["ai_verdict"] == "LIKELY_FALSE_POSITIVE"
    assert "not used for randomness" in result[0]["ai_reason"]


def test_run_contract_scan_end_to_end_with_no_tools_installed():
    with patch("app.services.web3_scan.subprocess.run", side_effect=FileNotFoundError()), \
         patch("app.services.web3_scan.settings") as mock_settings:
        mock_settings.ANTHROPIC_API_KEY = ""
        result = web3_scan.run_contract_scan("pragma solidity ^0.8.0;\ncontract Foo {}")
    assert result["solc_version_hint"] == "^0.8.0"
    assert result["findings"] == []
