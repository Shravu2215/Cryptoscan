"""
CryptoScan Accuracy Benchmarking Pipeline (Precision / Recall / F1).

Runs the full scanner pipeline against hand-verified fixtures in ground_truth.json
or any custom ground-truth answer key.
Evaluates True Positives (TP), False Positives (FP), and False Negatives (FN)
both overall and per detection layer (AST, Regex/Entropy, SCA, Config/Infra).
Appends results to benchmark_results.jsonl to track scanner accuracy over time.

Usage:
  python scanner/tests/benchmark.py
  python scanner/tests/benchmark.py --ground-truth /path/to/answers.json --base-dir /path/to/repo
"""
import argparse
import datetime
import json
import os
import subprocess
import sys
from typing import Dict, Any, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from scanner.cli import scan


TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_GROUND_TRUTH_PATH = os.path.join(TESTS_DIR, "ground_truth.json")
GROUND_TRUTH_PATH = DEFAULT_GROUND_TRUTH_PATH
RESULTS_LOG_PATH = os.path.join(TESTS_DIR, "benchmark_results.jsonl")


def _get_git_commit() -> str:
    """Retrieve current git commit hash if in a git repository."""
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=TESTS_DIR,
            stderr=subprocess.DEVNULL
        ).decode("utf-8").strip()
        return out
    except Exception:
        return ""


def _classify_fixture_layer(rel_path: str) -> str:
    """Classify fixture path into detection layer."""
    norm = rel_path.replace("\\", "/").lower()
    if "fixtures/sca" in norm:
        return "SCA (Manifest)"
    if "fixtures/infra" in norm:
        return "Config / Infra"
    if "fixtures/config" in norm:
        return "Regex / Config"
    return "AST (Python/JS)"


def run_benchmark(ground_truth_path: Optional[str] = None, base_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    Executes accuracy benchmarking across ground-truth fixtures.
    Returns dictionary with precision, recall, f1, counts, per-layer breakdowns, and timestamp.
    """
    gt_path = ground_truth_path or DEFAULT_GROUND_TRUTH_PATH
    b_dir = base_dir or TESTS_DIR

    with open(gt_path, "r", encoding="utf-8") as f:
        ground_truth: Dict[str, Dict[str, Any]] = json.load(f)

    total_tp = 0
    total_fp = 0
    total_fn = 0
    fixture_details = []

    layer_stats: Dict[str, Dict[str, int]] = {
        "AST (Python/JS)": {"tp": 0, "fp": 0, "fn": 0, "fixtures": 0},
        "Regex / Config": {"tp": 0, "fp": 0, "fn": 0, "fixtures": 0},
        "SCA (Manifest)": {"tp": 0, "fp": 0, "fn": 0, "fixtures": 0},
        "Config / Infra": {"tp": 0, "fp": 0, "fn": 0, "fixtures": 0},
    }

    for rel_path, spec in ground_truth.items():
        abs_path = os.path.join(b_dir, rel_path.replace("/", os.sep))
        if not os.path.isfile(abs_path) and not os.path.isdir(abs_path):
            continue

        layer_name = _classify_fixture_layer(rel_path)
        expected_rules = set(spec.get("expected_rule_ids", []))
        findings = scan(abs_path)
        actual_rules = {f.rule_id for f in findings}

        # True Positives: rules expected and detected
        tp_rules = expected_rules.intersection(actual_rules)
        # False Positives: rules detected but not expected
        fp_rules = actual_rules.difference(expected_rules)
        # False Negatives: rules expected but missed
        fn_rules = expected_rules.difference(actual_rules)

        tp = len(tp_rules)
        fp = len(fp_rules)
        fn = len(fn_rules)

        total_tp += tp
        total_fp += fp
        total_fn += fn

        if layer_name in layer_stats:
            layer_stats[layer_name]["tp"] += tp
            layer_stats[layer_name]["fp"] += fp
            layer_stats[layer_name]["fn"] += fn
            layer_stats[layer_name]["fixtures"] += 1

        fixture_details.append({
            "fixture": rel_path,
            "layer": layer_name,
            "expected": list(expected_rules),
            "actual": list(actual_rules),
            "tp": tp,
            "fp": fp,
            "fn": fn,
        })

    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 1.0
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 1.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    layers_summary = {}
    for l_name, s in layer_stats.items():
        l_prec = s["tp"] / (s["tp"] + s["fp"]) if (s["tp"] + s["fp"]) > 0 else 1.0
        l_rec = s["tp"] / (s["tp"] + s["fn"]) if (s["tp"] + s["fn"]) > 0 else 1.0
        l_f1 = (2 * l_prec * l_rec) / (l_prec + l_rec) if (l_prec + l_rec) > 0 else 1.0
        layers_summary[l_name] = {
            "fixtures": s["fixtures"],
            "tp": s["tp"],
            "fp": s["fp"],
            "fn": s["fn"],
            "precision": round(l_prec, 4),
            "recall": round(l_rec, 4),
            "f1": round(l_f1, 4),
        }

    result = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "git_commit": _get_git_commit() or None,
        "total_fixtures": len(fixture_details),
        "tp": total_tp,
        "fp": total_fp,
        "fn": total_fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "layers": layers_summary,
        "details": fixture_details,
    }

    # Append to benchmark_results.jsonl
    log_entry = {
        "timestamp": result["timestamp"],
        "git_commit": result["git_commit"],
        "tp": total_tp,
        "fp": total_fp,
        "fn": total_fn,
        "precision": result["precision"],
        "recall": result["recall"],
        "f1": result["f1"],
    }
    with open(RESULTS_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry) + "\n")

    return result


def print_summary(result: Dict[str, Any]):
    print("=" * 70)
    print(" CRYPTOSCAN ACCURACY BENCHMARK SUMMARY (OVERALL & PER-LAYER)")
    print("=" * 70)
    print(f" Timestamp:      {result['timestamp']}")
    if result.get('git_commit'):
        print(f" Git Commit:     {result['git_commit'][:8]}")
    print(f" Total Fixtures: {result['total_fixtures']}")
    print("-" * 70)
    print(f" True Positives (TP):   {result['tp']:<5}  (Correctly detected vulnerabilities)")
    print(f" False Positives (FP):  {result['fp']:<5}  (False alarms on clean/unrelated code)")
    print(f" False Negatives (FN):  {result['fn']:<5}  (Missed known vulnerabilities)")
    print("-" * 70)
    print(f" Overall Precision:     {result['precision'] * 100:.2f}%")
    print(f" Overall Recall:        {result['recall'] * 100:.2f}%")
    print(f" Overall F1 Score:      {result['f1'] * 100:.2f}%")
    print("=" * 70)
    print(f" {'LAYER':<22} | {'TP':<4} | {'FP':<4} | {'FN':<4} | {'PRECISION':<9} | {'RECALL':<8} | {'F1':<8}")
    print("-" * 70)
    for layer_name, s in result.get("layers", {}).items():
        print(f" {layer_name:<22} | {s['tp']:<4} | {s['fp']:<4} | {s['fn']:<4} | {s['precision']*100:>8.2f}% | {s['recall']*100:>7.2f}% | {s['f1']*100:>7.2f}%")
    print("=" * 70)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CryptoScan Accuracy Benchmark Runner")
    parser.add_argument("--ground-truth", dest="ground_truth", default=None, help="Path to custom ground_truth.json")
    parser.add_argument("--base-dir", dest="base_dir", default=None, help="Base directory for fixture paths")
    args = parser.parse_args()

    res = run_benchmark(ground_truth_path=args.ground_truth, base_dir=args.base_dir)
    print_summary(res)
