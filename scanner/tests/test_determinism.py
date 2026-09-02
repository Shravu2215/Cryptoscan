"""
Test Reproducibility & Determinism (Part B, Item 8).

Scanning the exact same repository/files twice must produce the exact same finding set,
same fields, same confidence, and same severity every single time.
"""
import os
import sys
import pytest

from scanner.cli import scan

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
FIXTURES_DIR = os.path.join(TESTS_DIR, "fixtures")


def _finding_to_tuple(f):
    return (
        f.file,
        f.line,
        f.column,
        f.rule_id,
        f.severity.value,
        f.quantum_risk.value,
        f.confidence.value,
        f.algorithm,
        f.suppressed,
    )


def test_scan_twice_produces_identical_findings():
    """Verify that multiple scan runs on the same fixtures produce identical results."""
    for root_dir in [
        os.path.join(FIXTURES_DIR, "python"),
        os.path.join(FIXTURES_DIR, "javascript"),
        os.path.join(FIXTURES_DIR, "config"),
        os.path.join(FIXTURES_DIR, "sca"),
        os.path.join(FIXTURES_DIR, "infra"),
    ]:
        if not os.path.isdir(root_dir):
            continue

        run1 = scan(root_dir)
        run2 = scan(root_dir)

        assert len(run1) == len(run2), f"Scan length differed between runs on {root_dir}"

        tuples1 = sorted([_finding_to_tuple(f) for f in run1])
        tuples2 = sorted([_finding_to_tuple(f) for f in run2])

        assert tuples1 == tuples2, f"Findings differed between runs on {root_dir}"
