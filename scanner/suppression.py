"""
Allow-list and Finding Suppression Layer (.cryptoscan-ignore).

Supports suppressing known or accepted findings using stable identifiers:
  1. rule_id|relative/path/to/file.ext
  2. rule_id|relative/path/to/file.ext|line_number
  3. rule_id|relative/path/to/file.ext|fingerprint
  4. rule_id|relative/path/to/file.ext|algorithm_or_token
  5. fingerprint

Suppressed findings:
  - Are marked `suppressed = True` with a descriptive reason.
  - Remain preserved in history and audit reports.
  - Are excluded from active risk tallies (Critical/High/Medium/Low) and CI/CD fail exits.
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
                if len(parts) == 1:
                    # Single fingerprint or token
                    suppressions.add(("FINGERPRINT", parts[0]))
                elif len(parts) == 2:
                    rule_id, rel_path = parts[0], _normalize_rel_path(parts[1])
                    suppressions.add((rule_id, rel_path))
                elif len(parts) >= 3:
                    rule_id, rel_path = parts[0], _normalize_rel_path(parts[1])
                    sub = parts[2]
                    try:
                        line_no = int(sub)
                        suppressions.add((rule_id, rel_path, line_no))
                    except ValueError:
                        suppressions.add((rule_id, rel_path, sub))
    except Exception:
        pass

    return suppressions


def apply_suppressions(
    findings: List[Finding],
    suppressions: Set[Tuple[Any, ...]],
    repo_path: str = "",
) -> Tuple[List[Finding], int]:
    """
    Marks matching findings as suppressed with reason and returns (all_findings, suppressed_count).
    Suppressed findings are marked `f.suppressed = True` with `f.suppression_reason` set,
    so they remain accessible for audit while excluded from active risk counts.
    """
    if not suppressions:
        return findings, 0

    suppressed_count = 0

    for f in findings:
        rel_path = _normalize_rel_path(f.file, repo_path)
        base_name = os.path.basename(f.file)
        fp = getattr(f, "fingerprint", "")
        algo = getattr(f, "algorithm", "").lower()

        is_suppressed = False
        reason = ""

        # Check line-specific match
        if (f.rule_id, rel_path, f.line) in suppressions:
            is_suppressed = True
            reason = f"Suppressed by rule '{f.rule_id}' on {rel_path}:{f.line}"
        # Check fingerprint match
        elif ("FINGERPRINT", fp) in suppressions or (f.rule_id, rel_path, fp) in suppressions:
            is_suppressed = True
            reason = f"Suppressed by fingerprint '{fp}' for rule '{f.rule_id}'"
        # Check algorithm sub-match
        elif (f.rule_id, rel_path, algo) in suppressions:
            is_suppressed = True
            reason = f"Suppressed by algorithm token '{algo}' on {rel_path}"
        # Check file-wide match
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

    kept = [f for f in findings if not f.suppressed]
    return kept, suppressed_count
