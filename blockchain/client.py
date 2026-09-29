import hashlib
import json
import re
import sqlite3
from pathlib import Path


def commitment(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def digest(value: str) -> str:
    if not re.fullmatch(r"[a-fA-F0-9]{64}", value) or int(value, 16) == 0:
        raise ValueError("Expected a nonzero SHA-256 hex digest")
    return value.lower()


class MockBlockchainClient:
    """Persistent local simulation, NOT independent or tamper-proof attestation."""
    mode = "mock"

    def __init__(self, path=":memory:"):
        self.db = sqlite3.connect(path, check_same_thread=False)
        from threading import RLock
        self.lock = RLock()
        self.db.execute("CREATE TABLE IF NOT EXISTS registry (id TEXT PRIMARY KEY, data TEXT NOT NULL)")

    def get_evidence(self, evidence_id):
        with self.lock:
            row = self.db.execute("SELECT data FROM registry WHERE id=?", (commitment(evidence_id),)).fetchone()
            if not row:
                raise ValueError("Evidence not registered")
            return json.loads(row[0])

    def register_evidence(self, evidence_id, sha256, custodian):
        with self.lock:
            key, sha256, owner = commitment(evidence_id), digest(sha256), commitment(custodian)
            tx = "mock:" + commitment(key + sha256 + owner)
            record = {"sha256": sha256, "custodian": owner, "history": [{"from_entity": None, "to_entity": owner, "tx_id": tx}]}
            try:
                with self.db:
                    self.db.execute("INSERT INTO registry VALUES (?, ?)", (key, json.dumps(record)))
            except sqlite3.IntegrityError as exc:
                raise ValueError("Evidence already registered") from exc
            return tx

    def verify_evidence(self, evidence_id, sha256):
        return self.get_evidence(evidence_id)["sha256"] == digest(sha256)

    def transfer_custody(self, evidence_id, from_entity, to_entity):
        with self.lock:
            record = self.get_evidence(evidence_id)
            old, new = commitment(from_entity), commitment(to_entity)
            if record["custodian"] != old or old == new:
                raise ValueError("Stale custodian or invalid recipient")
            tx = "mock:" + commitment(commitment(evidence_id) + new + str(len(record["history"])))
            record["custodian"] = new
            record["history"].append({"from_entity": old, "to_entity": new, "tx_id": tx})
            with self.db:
                self.db.execute("UPDATE registry SET data=? WHERE id=?", (json.dumps(record), commitment(evidence_id)))
            return tx

    def get_custody_history(self, evidence_id):
        return self.get_evidence(evidence_id)["history"]


class BlockchainClient:
    mode = "evm"

    def __init__(self, rpc_url, contract_address, abi_path, account=None, private_key=None):
        from web3 import Web3
        self.web3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 15}))
        artifact = json.loads(Path(abi_path).read_text())
        self.contract = self.web3.eth.contract(address=Web3.to_checksum_address(contract_address), abi=artifact["abi"])
        self.private_key = private_key
        if private_key:
            derived = self.web3.eth.account.from_key(private_key).address
            if account and Web3.to_checksum_address(account) != Web3.to_checksum_address(derived):
                raise ValueError("BLOCKCHAIN_ACCOUNT does not match BLOCKCHAIN_PRIVATE_KEY")
            self.account = Web3.to_checksum_address(derived)
        elif account:
            self.account = Web3.to_checksum_address(account)
        else:
            raise ValueError("Configure BLOCKCHAIN_PRIVATE_KEY or an unlocked BLOCKCHAIN_ACCOUNT")
        if not self.web3.is_connected():
            raise ValueError("Cannot connect to configured EVM RPC")
        expected_chain_id = os.getenv("BLOCKCHAIN_CHAIN_ID")
        if expected_chain_id and self.web3.eth.chain_id != int(expected_chain_id):
            raise ValueError("Connected EVM chain ID does not match BLOCKCHAIN_CHAIN_ID")
        from threading import RLock
        self.send_lock = RLock()

    def _send(self, function):
        with self.send_lock:
            if self.private_key:
                transaction = function.build_transaction({
                    "from": self.account,
                    "nonce": self.web3.eth.get_transaction_count(self.account, "pending"),
                    "chainId": self.web3.eth.chain_id,
                })
                signed = self.web3.eth.account.sign_transaction(transaction, self.private_key)
                tx_hash = self.web3.eth.send_raw_transaction(signed.raw_transaction)
            else:
                tx_hash = function.transact({"from": self.account})
            receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
        if receipt.status != 1:
            raise ValueError("Registry transaction reverted")
        return self.web3.to_hex(receipt.transactionHash)

    def register_evidence(self, evidence_id, sha256, custodian):
        return self._send(self.contract.functions.registerEvidence(bytes.fromhex(commitment(evidence_id)), bytes.fromhex(digest(sha256)), bytes.fromhex(commitment(custodian))))

    def get_evidence(self, evidence_id):
        item = self.contract.functions.getEvidence(bytes.fromhex(commitment(evidence_id))).call()
        return {"sha256": bytes(item[0]).hex(), "custodian": bytes(item[1]).hex(), "registered_at": item[2]}

    def verify_evidence(self, evidence_id, sha256):
        return self.contract.functions.verifyEvidence(bytes.fromhex(commitment(evidence_id)), bytes.fromhex(digest(sha256))).call()

    def transfer_custody(self, evidence_id, from_entity, to_entity):
        return self._send(self.contract.functions.transferCustody(bytes.fromhex(commitment(evidence_id)), bytes.fromhex(commitment(from_entity)), bytes.fromhex(commitment(to_entity))))

    def get_custody_history(self, evidence_id):
        return self.contract.functions.getCustodyHistory(bytes.fromhex(commitment(evidence_id))).call()
