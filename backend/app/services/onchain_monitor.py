"""
WEB3-3 — On-Chain Transaction Monitor.

Polls each registered contract on an interval (default every few
minutes, see settings.ONCHAIN_POLL_INTERVAL_MINUTES) rather than
block-by-block -- polling every ~12 seconds across multiple clients in a
shared Celery beat schedule isn't practical, and the goal (catch large/
anomalous transfers quickly) doesn't need block-level latency.

web3.py's import is lazy (inside get_web3_client) so this module can be
imported without the package installed -- same lazy-heavy-dependency
pattern as ai_reports.py's weasyprint import.
"""
import logging

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

_ETHERSCAN_BASE = "https://api.etherscan.io/api"

_RPC_ENDPOINTS = {
    "ethereum": "https://cloudflare-eth.com",
    "polygon": "https://polygon-rpc.com",
}

# Common admin-style function 4-byte selectors -- calls to these on a
# monitored contract are worth an analyst's attention even without a
# full ABI (pause/mint/ownership changes are the highest-risk category
# of "someone with privileged access just did something").
ADMIN_FUNCTION_SELECTORS = {
    "0x8456cb59": "pause()",
    "0x3f4ba83a": "unpause()",
    "0xf2fde38b": "transferOwnership(address)",
    "0x715018a6": "renounceOwnership()",
    "0x40c10f19": "mint(address,uint256)",
}


def get_web3_client(network: str = "ethereum"):
    from web3 import Web3
    rpc_url = _RPC_ENDPOINTS.get(network, _RPC_ENDPOINTS["ethereum"])
    return Web3(Web3.HTTPProvider(rpc_url))


def get_latest_block(w3) -> int:
    return w3.eth.block_number


def fetch_transactions_since(contract_address: str, from_block: int, to_block: int, network: str = "ethereum", timeout: int = 15) -> list[dict]:
    """Etherscan API transaction history for a contract address between two blocks. Key-gated -- degrades gracefully without ETHERSCAN_API_KEY, same idiom as every other optional integration in this codebase."""
    if not settings.ETHERSCAN_API_KEY:
        logger.info("ETHERSCAN_API_KEY not set — skipping on-chain transaction fetch")
        return []

    try:
        resp = httpx.get(_ETHERSCAN_BASE, params={
            "module": "account", "action": "txlist", "address": contract_address,
            "startblock": from_block, "endblock": to_block, "sort": "asc",
            "apikey": settings.ETHERSCAN_API_KEY,
        }, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError) as e:
        logger.error(f"Etherscan tx fetch failed for {contract_address}: {e}")
        return []

    if data.get("status") != "1":
        return []
    return data.get("result", [])


def detect_anomalies(transactions: list[dict], alert_thresholds: dict) -> list[dict]:
    """
    Flags: (1) large native-token transfers over a client-configured
    threshold, (2) calls to known admin-style function selectors,
    (3) a naive flash-loan-pattern heuristic: 3+ transactions in the same
    block moving a combined value over the threshold. This is
    deliberately a simple heuristic, not real flash-loan detection (which
    needs full trace/log analysis) -- flag for manual review, not a
    confirmed verdict.
    """
    large_threshold_wei = int(alert_thresholds.get("large_transfer_native_wei", 10 * 10 ** 18))
    alerts = []
    by_block: dict = {}

    for tx in transactions:
        value = int(tx.get("value", 0) or 0)
        if value >= large_threshold_wei:
            alerts.append({
                "type": "large_transfer", "hash": tx.get("hash"), "value_wei": value,
                "from": tx.get("from"), "to": tx.get("to"), "block": tx.get("blockNumber"),
                "note": f"Transfer of {value / 10 ** 18:.4f} native tokens exceeds the configured alert threshold.",
            })

        selector = (tx.get("input") or "")[:10]
        if selector in ADMIN_FUNCTION_SELECTORS:
            alerts.append({
                "type": "admin_function_call", "hash": tx.get("hash"), "function": ADMIN_FUNCTION_SELECTORS[selector],
                "from": tx.get("from"), "block": tx.get("blockNumber"),
                "note": f"Admin-style function {ADMIN_FUNCTION_SELECTORS[selector]} was called.",
            })

        by_block.setdefault(tx.get("blockNumber"), []).append(tx)

    for block, txs in by_block.items():
        if len(txs) >= 3 and sum(int(t.get("value", 0) or 0) for t in txs) >= large_threshold_wei:
            alerts.append({
                "type": "possible_flash_loan_pattern", "block": block,
                "tx_hashes": [t.get("hash") for t in txs],
                "note": f"{len(txs)} transactions in the same block moved a combined value above the alert threshold — naive heuristic, verify manually.",
            })

    return alerts


def poll_monitor(contract_address: str, network: str, last_checked_block: int | None, alert_thresholds: dict) -> dict:
    """One polling cycle: fetch new transactions since the last checkpoint, detect anomalies, return the new checkpoint."""
    try:
        w3 = get_web3_client(network)
        latest_block = get_latest_block(w3)
    except Exception as e:
        logger.error(f"Could not reach {network} RPC endpoint: {e}")
        return {"alerts": [], "new_last_checked_block": last_checked_block}

    from_block = (last_checked_block if last_checked_block is not None else latest_block - 1) + 1
    if from_block > latest_block:
        return {"alerts": [], "new_last_checked_block": last_checked_block}

    transactions = fetch_transactions_since(contract_address, from_block, latest_block, network)
    alerts = detect_anomalies(transactions, alert_thresholds)
    return {"alerts": alerts, "new_last_checked_block": latest_block}
