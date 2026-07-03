import sys
import types
from unittest.mock import MagicMock, patch

import pytest

from app.services import onchain_monitor


@pytest.fixture
def fake_web3_module():
    fake_web3_pkg = types.ModuleType("web3")

    class FakeWeb3:
        def __init__(self, provider):
            self.provider = provider
            self.eth = MagicMock()
            self.eth.block_number = 1000

        @staticmethod
        def HTTPProvider(url):
            return url

    fake_web3_pkg.Web3 = FakeWeb3
    sys.modules["web3"] = fake_web3_pkg
    yield fake_web3_pkg
    del sys.modules["web3"]


def test_get_web3_client_uses_fake_module(fake_web3_module):
    client = onchain_monitor.get_web3_client("ethereum")
    assert onchain_monitor.get_latest_block(client) == 1000


def test_fetch_transactions_since_skips_without_api_key():
    with patch("app.services.onchain_monitor.settings") as mock_settings:
        mock_settings.ETHERSCAN_API_KEY = ""
        with patch("app.services.onchain_monitor.httpx.get") as mock_get:
            result = onchain_monitor.fetch_transactions_since("0xabc", 1, 100)
    mock_get.assert_not_called()
    assert result == []


def test_fetch_transactions_since_returns_results_with_key_set():
    resp = MagicMock()
    resp.json.return_value = {"status": "1", "result": [{"hash": "0x1", "value": "0"}]}
    resp.raise_for_status = MagicMock()
    with patch("app.services.onchain_monitor.settings") as mock_settings:
        mock_settings.ETHERSCAN_API_KEY = "fake-key"
        with patch("app.services.onchain_monitor.httpx.get", return_value=resp):
            result = onchain_monitor.fetch_transactions_since("0xabc", 1, 100)
    assert len(result) == 1


def test_fetch_transactions_since_empty_on_non_ok_status():
    resp = MagicMock()
    resp.json.return_value = {"status": "0", "message": "No transactions found"}
    resp.raise_for_status = MagicMock()
    with patch("app.services.onchain_monitor.settings") as mock_settings:
        mock_settings.ETHERSCAN_API_KEY = "fake-key"
        with patch("app.services.onchain_monitor.httpx.get", return_value=resp):
            result = onchain_monitor.fetch_transactions_since("0xabc", 1, 100)
    assert result == []


def test_detect_anomalies_flags_large_transfer():
    transactions = [{"hash": "0x1", "value": str(20 * 10 ** 18), "from": "0xa", "to": "0xb", "blockNumber": "100", "input": "0x"}]
    alerts = onchain_monitor.detect_anomalies(transactions, {"large_transfer_native_wei": 10 * 10 ** 18})
    types_found = {a["type"] for a in alerts}
    assert "large_transfer" in types_found


def test_detect_anomalies_flags_admin_function_call():
    transactions = [{"hash": "0x2", "value": "0", "from": "0xa", "blockNumber": "101", "input": "0x8456cb59"}]
    alerts = onchain_monitor.detect_anomalies(transactions, {})
    admin_alerts = [a for a in alerts if a["type"] == "admin_function_call"]
    assert len(admin_alerts) == 1
    assert admin_alerts[0]["function"] == "pause()"


def test_detect_anomalies_flags_possible_flash_loan_pattern():
    big = 4 * 10 ** 18
    transactions = [
        {"hash": f"0x{i}", "value": str(big), "from": "0xa", "to": "0xb", "blockNumber": "200", "input": "0x"}
        for i in range(3)
    ]
    alerts = onchain_monitor.detect_anomalies(transactions, {"large_transfer_native_wei": 10 * 10 ** 18})
    flash_alerts = [a for a in alerts if a["type"] == "possible_flash_loan_pattern"]
    assert len(flash_alerts) == 1
    assert len(flash_alerts[0]["tx_hashes"]) == 3


def test_detect_anomalies_no_alerts_for_quiet_transactions():
    transactions = [{"hash": "0x1", "value": "1000", "from": "0xa", "to": "0xb", "blockNumber": "1", "input": "0x"}]
    alerts = onchain_monitor.detect_anomalies(transactions, {"large_transfer_native_wei": 10 * 10 ** 18})
    assert alerts == []


def test_poll_monitor_advances_checkpoint_and_returns_alerts(fake_web3_module):
    with patch("app.services.onchain_monitor.fetch_transactions_since", return_value=[
        {"hash": "0x1", "value": str(20 * 10 ** 18), "from": "0xa", "to": "0xb", "blockNumber": "999", "input": "0x"},
    ]):
        result = onchain_monitor.poll_monitor("0xabc", "ethereum", 990, {"large_transfer_native_wei": 10 * 10 ** 18})
    assert result["new_last_checked_block"] == 1000
    assert len(result["alerts"]) == 1


def test_poll_monitor_handles_rpc_failure_gracefully():
    with patch("app.services.onchain_monitor.get_web3_client", side_effect=ConnectionError("rpc down")):
        result = onchain_monitor.poll_monitor("0xabc", "ethereum", 990, {})
    assert result["alerts"] == []
    assert result["new_last_checked_block"] == 990


def test_poll_monitor_no_new_blocks_returns_no_alerts(fake_web3_module):
    result = onchain_monitor.poll_monitor("0xabc", "ethereum", 1000, {})
    assert result["alerts"] == []
    assert result["new_last_checked_block"] == 1000
