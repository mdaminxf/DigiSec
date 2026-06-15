import os
import json
from typing import List, Dict, Any
from core.models import Finding

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".data")


class BenchmarkResult:
    def __init__(self):
        self.true_positives: List[str] = []
        self.false_positives: List[str] = []
        self.false_negatives: List[str] = []
        self.hallucinations: List[str] = []

    def precision(self) -> float:
        tp = len(self.true_positives)
        fp = len(self.false_positives)
        return tp / (tp + fp) if (tp + fp) > 0 else 0.0

    def recall(self) -> float:
        tp = len(self.true_positives)
        fn = len(self.false_negatives)
        return tp / (tp + fn) if (tp + fn) > 0 else 0.0

    def f1_score(self) -> float:
        p = self.precision()
        r = self.recall()
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "hallucinations": self.hallucinations,
            "precision": round(self.precision(), 3),
            "recall": round(self.recall(), 3),
            "f1_score": round(self.f1_score(), 3)
        }


def benchmark_case(
    case_name: str,
    findings: List[Finding],
    ground_truth: List[str]
) -> BenchmarkResult:

    result = BenchmarkResult()
    finding_titles = [f.title.lower() for f in findings]
    truth_lower = [t.lower() for t in ground_truth]

    for truth in truth_lower:
        matched = any(truth in title for title in finding_titles)
        if matched:
            result.true_positives.append(truth)
        else:
            result.false_negatives.append(truth)

    for title in finding_titles:
        matched = any(truth in title for truth in truth_lower)
        if not matched:
            result.false_positives.append(title)

    save_benchmark_result(case_name, result)
    return result


def save_benchmark_result(case_name: str, result: BenchmarkResult):
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)

    filepath = os.path.join(DATA_DIR, "benchmarks.jsonl")
    entry = {
        "case": case_name,
        "results": result.to_dict()
    }

    with open(filepath, "a") as f:
        f.write(json.dumps(entry) + "\n")


def load_benchmark_history() -> List[Dict[str, Any]]:
    filepath = os.path.join(DATA_DIR, "benchmarks.jsonl")
    if not os.path.exists(filepath):
        return []

    results = []
    with open(filepath, "r") as f:
        for line in f:
            if line.strip():
                results.append(json.loads(line))
    return results
