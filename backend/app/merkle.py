"""Versioned Merkle commitments: sorted manifest, domain-separated SHA-256 nodes."""
import hashlib
import json

ALGORITHM = "jocky-merkle-sha256-v1"

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()

def leaf(item):
    return hashlib.sha256(b"\x00" + canonical(item)).hexdigest()

def parent(left, right):
    return hashlib.sha256(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()

def tree(manifest):
    if not manifest:
        raise ValueError("Empty evidence set")
    levels = [[leaf(item) for item in manifest]]
    while len(levels[-1]) > 1:
        level = levels[-1]
        levels.append([parent(level[i], level[i+1] if i+1 < len(level) else level[i]) for i in range(0, len(level), 2)])
    proofs = []
    for index in range(len(manifest)):
        proof = []
        for level in levels[:-1]:
            sibling = index ^ 1
            proof.append({"side": "left" if index % 2 else "right", "hash": level[sibling] if sibling < len(level) else level[index]})
            index //= 2
        proofs.append(proof)
    return levels[-1][0], proofs

def verify(item, proof, root):
    try:
        value = leaf(item)
        for step in proof:
            if step["side"] not in {"left", "right"}:
                return False
            value = parent(step["hash"], value) if step["side"] == "left" else parent(value, step["hash"])
        return value == root
    except (ValueError, KeyError, TypeError):
        return False
