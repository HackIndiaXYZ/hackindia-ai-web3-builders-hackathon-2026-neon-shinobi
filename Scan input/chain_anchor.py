"""
CHAIN ANCHOR — tamper-evident audit log
========================================
Idea simple hai: har baar jab tum "anchor" karte ho, current
alerts_history + policies_history (db_store se) ka ek SHA-256 hash
nikalta hai, aur wahi hash — data nahi, sirf uska fingerprint — ek
chhote smart contract (AuditAnchor.vy) par on-chain store ho jaata hai.

Baad mein koi bhi verify kar sakta hai: apna local DB se wahi hash
recompute karo, aur check karo ki wo hash on-chain anchored hai ya
nahi. Agar kisi ne baad mein history table mein chhed-chhaad ki, hash
match nahi karega — proof of tampering.

DO MODES:

1. LOCAL DEV (default, zero setup):
   Koi env var set nahi kiya to ye ek in-process, ephemeral Ethereum
   test-chain (eth-tester) use karta hai — bilkul real transactions,
   real gas, real blocks, bas sirf isi process ke andar rehta hai aur
   restart pe reset ho jaata hai. Isse "mechanism kaam karta hai" prove
   hota hai bina kisi wallet/RPC/faucet ki zaroorat ke.

2. REAL TESTNET (public, persistent, verifiable by anyone):
   Environment variables set karo:
     WEB3_RPC_URL         - e.g. a free Alchemy/Infura/public RPC URL
                             for Sepolia or Polygon Amoy
     WEB3_PRIVATE_KEY     - a testnet wallet's private key (get free
                             testnet funds from a faucet — never use a
                             real-funds wallet here)
     AUDIT_CONTRACT_ADDRESS (optional) - reuse an already-deployed
                             contract instead of deploying a new one
                             every restart (deploying costs gas).

   Same code, same contract, real chain — anchors are now genuinely
   public and verifiable by anyone with the tx hash, forever.
"""

import os
import json
import time
import hashlib

from web3 import Web3

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ARTIFACT_PATH = os.path.join(SCRIPT_DIR, "contracts", "AuditAnchor.json")

_w3 = None
_contract = None
_account_address = None
_is_local_dev = True
_network_label = "local dev chain (ephemeral)"


def _load_artifact():
    with open(ARTIFACT_PATH, "r") as f:
        return json.load(f)


def _get_web3():
    global _w3, _account_address, _is_local_dev, _network_label
    if _w3 is not None:
        return _w3

    rpc_url = os.environ.get("WEB3_RPC_URL")
    if rpc_url:
        _w3 = Web3(Web3.HTTPProvider(rpc_url))
        if not _w3.is_connected():
            raise RuntimeError(f"Could not connect to WEB3_RPC_URL ({rpc_url}).")
        priv_key = os.environ.get("WEB3_PRIVATE_KEY")
        if not priv_key:
            raise RuntimeError(
                "WEB3_RPC_URL is set but WEB3_PRIVATE_KEY is missing — a real "
                "chain needs a funded testnet account to sign transactions."
            )
        from eth_account import Account
        acct = Account.from_key(priv_key)
        _account_address = acct.address
        _is_local_dev = False
        _network_label = f"chain_id {_w3.eth.chain_id} via {rpc_url}"
    else:
        from web3 import EthereumTesterProvider
        _w3 = Web3(EthereumTesterProvider())
        _account_address = _w3.eth.accounts[0]
        _is_local_dev = True
        _network_label = "local dev chain (ephemeral — resets on backend restart)"

    return _w3


def _send_transaction(func):
    """Builds, signs (if on a real chain) and sends a contract call,
    then waits for the receipt. Works identically whether func is a
    regular contract function or a constructor call."""
    w3 = _get_web3()
    private_key = os.environ.get("WEB3_PRIVATE_KEY")

    if private_key:
        nonce = w3.eth.get_transaction_count(_account_address)
        tx = func.build_transaction({
            "from": _account_address,
            "nonce": nonce,
            "gas": 500000,  # contract is tiny; a generous fixed cap avoids estimate_gas flakiness
            "gasPrice": w3.eth.gas_price,
        })
        signed = w3.eth.account.sign_transaction(tx, private_key=private_key)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    else:
        # local eth-tester accounts are pre-unlocked — no manual signing needed
        tx_hash = func.transact({"from": _account_address})

    return w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)


def _get_contract():
    global _contract
    if _contract is not None:
        return _contract

    w3 = _get_web3()
    artifact = _load_artifact()

    existing_address = os.environ.get("AUDIT_CONTRACT_ADDRESS")
    if existing_address and not _is_local_dev:
        _contract = w3.eth.contract(address=Web3.to_checksum_address(existing_address), abi=artifact["abi"])
        return _contract

    deployer = w3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"])
    receipt = _send_transaction(deployer.constructor())
    address = receipt.contractAddress
    print(f"[*] AuditAnchor contract deployed at {address} ({_network_label})")
    if not _is_local_dev:
        print(f"[*] Save this to skip re-deploying next run: "
              f"export AUDIT_CONTRACT_ADDRESS={address}")

    _contract = w3.eth.contract(address=address, abi=artifact["abi"])
    return _contract


def compute_history_hash():
    """SHA-256 of the current alerts_history + policies_history, as a
    canonical (sorted-keys) JSON blob — this is the 'fingerprint' that
    gets anchored, never the raw data itself."""
    import db_store
    alerts = db_store.get_alerts_history(limit=100000)
    policies = db_store.get_policies_history(limit=100000)
    canonical = json.dumps({"alerts": alerts, "policies": policies}, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).digest()


def anchor_current_state(label=None):
    """Hashes the current history and writes that hash on-chain. Returns
    a record describing the anchor (also saved locally via db_store so
    the dashboard can list past anchors without re-querying the chain)."""
    import db_store

    w3 = _get_web3()
    contract = _get_contract()
    content_hash = compute_history_hash()
    label = (label or f"audit-{int(time.time())}")[:128]

    receipt = _send_transaction(contract.functions.anchor(content_hash, label))

    record = {
        "content_hash": content_hash.hex(),
        "tx_hash": receipt.transactionHash.hex(),
        "block_number": receipt.blockNumber,
        "chain_id": w3.eth.chain_id,
        "contract_address": contract.address,
        "network_label": _network_label,
        "label": label,
    }
    db_store.record_anchor(**record)
    return record


def verify_hash(hex_hash):
    """Checks whether a given hash (hex string, with or without '0x')
    was ever anchored on-chain. Returns the on-chain record if found,
    else None — this is the actual proof-of-integrity check."""
    contract = _get_contract()
    content_hash = bytes.fromhex(hex_hash.replace("0x", ""))
    anchor_id = contract.functions.verify(content_hash).call()
    if anchor_id == 0:
        return None
    record = contract.functions.get_anchor(anchor_id).call()
    return {
        "anchor_id": anchor_id,
        "content_hash": record[0].hex(),
        "label": record[1],
        "timestamp": record[2],
        "sender": record[3],
    }


def verify_current_state():
    """Convenience check: does the CURRENT local history hash match
    something already anchored on-chain? True means nothing has
    changed in alerts/policies history since that anchor was made."""
    content_hash = compute_history_hash()
    return verify_hash(content_hash.hex())


def get_status():
    w3 = _get_web3()
    contract = _get_contract()
    return {
        "network_label": _network_label,
        "is_local_dev": _is_local_dev,
        "chain_id": w3.eth.chain_id,
        "contract_address": contract.address,
        "account_address": _account_address,
    }
