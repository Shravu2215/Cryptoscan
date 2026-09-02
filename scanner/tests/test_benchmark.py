"""
Tests for Accuracy Benchmarking and Regression Guard.
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from scanner.tests.benchmark import run_benchmark, GROUND_TRUTH_PATH


def test_ground_truth_file_exists_and_valid():
    assert os.path.isfile(GROUND_TRUTH_PATH)


def test_benchmark_runs_end_to_end():
    result = run_benchmark()
    assert "precision" in result
    assert "recall" in result
    assert "f1" in result
    assert 0.0 <= result["precision"] <= 1.0
    assert 0.0 <= result["recall"] <= 1.0
    assert 0.0 <= result["f1"] <= 1.0
    assert result["tp"] > 0


def test_benchmark_does_not_regress():
    """Ensures scanner accuracy maintains high precision/recall (> 90% F1)."""
    result = run_benchmark()
    assert result["f1"] >= 0.90, f"Benchmark F1 score {result['f1']} regressed below 0.90 baseline"
    assert result["precision"] >= 0.85, f"Benchmark Precision {result['precision']} regressed below 0.85 baseline"
    assert result["recall"] >= 0.90, f"Benchmark Recall {result['recall']} regressed below 0.90 baseline"
