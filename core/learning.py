import os
import json
from typing import List, Dict, Any
from datetime import datetime

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".data")
LEARNING_FILE = os.path.join(DATA_DIR, "learning.jsonl")


def record_case(case_id: str, findings: List[Dict], missed: List[str], false_positives: List[str]):
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)

    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "case": case_id,
        "findings_count": len(findings),
        "missed": missed,
        "false_positives": false_positives
    }

    with open(LEARNING_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")


def get_learning_history() -> List[Dict[str, Any]]:
    if not os.path.exists(LEARNING_FILE):
        return []

    history = []
    with open(LEARNING_FILE, "r") as f:
        for line in f:
            if line.strip():
                history.append(json.loads(line))
    return history


def get_common_misses() -> Dict[str, int]:
    history = get_learning_history()
    miss_count = {}
    for entry in history:
        for missed in entry.get("missed", []):
            miss_count[missed] = miss_count.get(missed, 0) + 1
    return dict(sorted(miss_count.items(), key=lambda x: x[1], reverse=True))


def get_common_false_positives() -> Dict[str, int]:
    history = get_learning_history()
    fp_count = {}
    for entry in history:
        for fp in entry.get("false_positives", []):
            fp_count[fp] = fp_count.get(fp, 0) + 1
    return dict(sorted(fp_count.items(), key=lambda x: x[1], reverse=True))


def get_improvement_suggestions() -> List[str]:
    suggestions = []
    common_misses = get_common_misses()
    common_fps = get_common_false_positives()

    for missed, count in common_misses.items():
        if count >= 2:
            suggestions.append(f"Frequently missed: '{missed}' ({count} times). Consider adding a dedicated detection rule.")

    for fp, count in common_fps.items():
        if count >= 2:
            suggestions.append(f"Frequent false positive: '{fp}' ({count} times). Consider raising the confidence threshold.")

    return suggestions
