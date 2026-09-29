"""Run the tiny deterministic rule contract set; this is not real-world accuracy testing."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from app.detection import analyze  # noqa: E402


CASES = [
    ("synthetic_miner_positive", True, "process.list", [{"name": "synthetic_miner.exe", "pid": 41}]),
    ("synthetic_unusual_port_positive", True, "network.connections", [{"remote_address": "198.51.100.40", "remote_port": 3333}]),
    ("baseline_process_negative", False, "process.list", [{"name": "systemd", "pid": 1, "path": "/usr/lib/systemd/systemd"}]),
    ("baseline_network_negative", False, "network.connections", [{"remote_address": "198.51.100.40", "remote_port": 443}]),
]


def main():
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    results = []
    for name, expected_alert, capability, payload in CASES:
        actual_alert = bool(analyze(capability, payload))
        key = ("t" if actual_alert == expected_alert else "f") + ("p" if expected_alert else "n")
        counts[key] += 1
        results.append({"fixture": name, "expected_alert": expected_alert, "actual_alert": actual_alert,
                        "pass": actual_alert == expected_alert})
    total_alerts = counts["tp"] + counts["fp"]
    total_positive = counts["tp"] + counts["fn"]
    print(json.dumps({"label": "SYNTHETIC RULE CONTRACT CHECK — NOT DETECTION ACCURACY",
                      "counts": counts, "fixture_precision": counts["tp"] / total_alerts if total_alerts else None,
                      "fixture_recall": counts["tp"] / total_positive if total_positive else None,
                      "all_pass": all(row["pass"] for row in results), "fixtures": results,
                      "caveat": "Four hand-written fixtures only; do not present these rates as field performance."}, indent=2))
    raise SystemExit(0 if all(row["pass"] for row in results) else 1)


if __name__ == "__main__":
    main()
