"""Offline verifier for an exported JOCKY Merkle manifest."""
import argparse
import hashlib
import json
from pathlib import Path


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def leaf(value):
    return hashlib.sha256(b"\x00" + canonical(value)).hexdigest()


def parent(left, right):
    return hashlib.sha256(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def verify(value, proof, root):
    if not isinstance(value, dict) or not isinstance(proof, list):
        return False
    digest = leaf(value)
    for step in proof:
        if not isinstance(step, dict) or not isinstance(step.get("hash"), str):
            return False
        if step.get("side") == "left":
            digest = parent(step["hash"], digest)
        elif step.get("side") == "right":
            digest = parent(digest, step["hash"])
        else:
            return False
    return digest == root.lower()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--root", required=True, help="Merkle root copied from the registry record")
    parser.add_argument("--evidence-id", help="Check one item and its inclusion proof")
    parser.add_argument("--file", type=Path, help="Optional evidence bytes to compare with its SHA-256")
    args = parser.parse_args()
    if args.file and not args.evidence_id:
        parser.error("--file requires --evidence-id")
    try:
        data = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Cannot read manifest: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit("Manifest must be a JSON object")
    if data.get("algorithm") != "jocky-merkle-sha256-v1":
        raise SystemExit("Unsupported or missing Merkle algorithm")
    if data.get("root", "").lower() != args.root.lower():
        raise SystemExit("Manifest root does not match the supplied registry root")
    entries = data.get("evidence", [])
    if not isinstance(entries, list):
        raise SystemExit("Manifest evidence field must be a list")
    chosen = [item for item in entries if not args.evidence_id or item["evidence_id"] == args.evidence_id]
    if not chosen:
        raise SystemExit("Requested evidence ID is not in this manifest")
    for item in chosen:
        try:
            core = {key: value for key, value in item.items() if key != "proof"}
            valid = verify(core, item["proof"], args.root)
            evidence_id, expected = item["evidence_id"], item["sha256"]
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise SystemExit("Malformed evidence entry or proof") from exc
        if not valid:
            raise SystemExit(f"Invalid inclusion proof for {evidence_id}")
        if args.file:
            try:
                current = hashlib.sha256(args.file.read_bytes()).hexdigest()
            except OSError as exc:
                raise SystemExit(f"Cannot read evidence file: {exc}") from exc
            if current != expected:
                raise SystemExit(f"Evidence bytes do not match the manifest for {evidence_id}")
        print(f"VALID {evidence_id} sha256={expected}")
    print(f"All selected inclusion proofs match registry root {args.root}")


if __name__ == "__main__":
    main()
