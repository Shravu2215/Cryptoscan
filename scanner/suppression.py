"""
Allow-list and Finding Suppression Layer (.cryptoscan-ignore).

Supports suppressing known or accepted findings either file-wide or on a specific line.
Format in .cryptoscan-ignore at repo root:
  # Comments start with #
  rule_id|relative/path/to/file.py
  rule_id|relative/path/to/file.py|line_number

First-class pipeline stage:
  - Matching findings are marked with `suppressed: True` and `suppression_reason`.
  - Suppressed findings remain visible in reports and exports with their suppression status.
  - Active (unsuppressed) findings are separated for CI/CD gate evaluation.
"""
import os
from typing import List, Set, Tuple, Any

from .models import Finding


def _normalize_rel_path(path: str, repo_path: str = "") -> str:
    """Normalize file path to forward-slash relative path."""
    clean = path.replace("\\", "/")
    if repo_path:
        repo_clean = repo_path.replace("\\", "/").rstrip("/")
        if clean.startswith(repo_clean + "/"):
            clean = clean[len(repo_clean) + 1:]
    return clean.lstrip("/")


def load_suppressions(repo_path: str) -> Set[Tuple[Any, ...]]:
    """
    Loads suppression rules from .cryptoscan-ignore in the target repo root.
    Returns a set containing (rule_id, rel_path) and/or (rule_id, rel_path, line_no).
    """
    suppressions: Set[Tuple[Any, ...]] = set()
    ignore_file = os.path.join(repo_path, ".cryptoscan-ignore")

    if not os.path.isfile(ignore_file):
        return suppressions

    try:
        with open(ignore_file, "r", encoding="utf-8", errors="ignore") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = [p.strip() for p in line.split("|")]
                if len(parts) == 2:
                    rule_id, rel_path = parts[0], _normalize_rel_path(parts[1])
                    suppressions.add((rule_id, rel_path))
                elif len(parts) >= 3:
                    rule_id, rel_path = parts[0], _normalize_rel_path(parts[1])
                    try:
                        line_no = int(parts[2])
                        suppressions.add((rule_id, rel_path, line_no))
                    except ValueError:
                        suppressions.add((rule_id, rel_path))
    except Exception:
        pass

    return suppressions


def apply_suppressions(
    findings: List[Finding],
    suppressions: Set[Tuple[Any, ...]],
    repo_path: str = "",
) -> Tuple[List[Finding], int]:
    """
    Marks matching findings as suppressed with reason and returns (active_kept_findings, suppressed_count).
    Also sets `f.suppressed = True` and `f.suppression_reason` in-place on suppressed finding objects.
    """
    if not suppressions:
        return findings, 0

    suppressed_count = 0
    kept: List[Finding] = []

    for f in findings:
        rel_path = _normalize_rel_path(f.file, repo_path)
        base_name = os.path.basename(f.file)

        is_suppressed = False
        reason = ""

        if (f.rule_id, rel_path, f.line) in suppressions:
            is_suppressed = True
            reason = f"Suppressed by rule '{f.rule_id}' on {rel_path}:{f.line}"
        elif (f.rule_id, rel_path) in suppressions:
            is_suppressed = True
            reason = f"Suppressed by file-wide rule '{f.rule_id}' on {rel_path}"
        elif (f.rule_id, base_name, f.line) in suppressions:
            is_suppressed = True
            reason = f"Suppressed by rule '{f.rule_id}' on {base_name}:{f.line}"
        elif (f.rule_id, base_name) in suppressions:
            is_suppressed = True
            reason = f"Suppressed by rule '{f.rule_id}' on {base_name}"

        if is_suppressed:
            f.suppressed = True
            f.suppression_reason = reason
            suppressed_count += 1
        else:
            kept.append(f)

    return kept, suppressed_count
