"""
Allow-list and Finding Suppression Layer (.cryptoscan-ignore).

Supports suppressing known or accepted findings using stable identifiers:
  1. rule_id|relative/path/to/file.ext
  2. rule_id|relative/path/to/file.ext|line_number
  3. rule_id|relative/path/to/file.ext|fingerprint
  4. rule_id|relative/path/to/file.ext|algorithm_or_token
  5. path:line_number or path
  6. rule_id
  7. fingerprint

Suppressed findings:
  - Are marked `suppressed = True` with a descriptive reason.
  - Remain preserved in history and audit reports.
  - Are excluded from active risk tallies (Critical/High/Medium/Low) and CI/CD fail exits.
"""
import os
from typing import List, Set, Tuple, Any

from .models import Finding


def _normalize_rel_path(path: str, repo_path: str = "") -> str:
    """Normalize file path to forward-slash relative path agnostic of OS and casing."""
    if not path:
        return ""
    clean = path.strip().replace("\\", "/")
    
    if repo_path:
        repo_clean = repo_path.strip().replace("\\", "/").rstrip("/")
        # Try os.path.realpath and os.path.relpath first
        try:
            abs_p = os.path.realpath(os.path.abspath(path))
            abs_r = os.path.realpath(os.path.abspath(repo_path))
            rel = os.path.relpath(abs_p, abs_r).replace("\\", "/")
            if not rel.startswith("../") and not rel.startswith(".."):
                return rel.lstrip("./")
        except Exception:
            pass

        # Case-insensitive prefix stripping fallback
        if clean.lower().startswith(repo_clean.lower() + "/"):
            clean = clean[len(repo_clean) + 1:]
        elif clean.lower().startswith(repo_clean.lower()):
            clean = clean[len(repo_clean):]

    # Clean leading ./ or /
    while clean.startswith("./"):
        clean = clean[2:]
    return clean.lstrip("/")


def load_suppressions(repo_path: str) -> Set[Tuple[Any, ...]]:
    """
    Loads suppression rules from .cryptoscan-ignore in the target repo root or extracted root.
    """
    suppressions: Set[Tuple[Any, ...]] = set()
    if not repo_path:
        return suppressions

    ignore_file = os.path.join(repo_path, ".cryptoscan-ignore")

    # If not found directly, check subdirectories (e.g. if extracted archive has top folder)
    if not os.path.isfile(ignore_file):
        for root, dirs, files in os.walk(repo_path):
            if ".cryptoscan-ignore" in files:
                ignore_file = os.path.join(root, ".cryptoscan-ignore")
                break

    if not os.path.isfile(ignore_file):
        return suppressions

    try:
        with open(ignore_file, "r", encoding="utf-8", errors="ignore") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue

                # Strip inline comments if any
                if " #" in line:
                    line = line.split(" #")[0].strip()

                if "|" in line:
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) == 1:
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
                elif ":" in line:
                    parts = [p.strip() for p in line.split(":")]
                    if len(parts) == 2 and parts[1].isdigit():
                        rel_path = _normalize_rel_path(parts[0])
                        suppressions.add(("*", rel_path, int(parts[1])))
                    else:
                        suppressions.add(("FINGERPRINT", line))
                else:
                    # Single item: could be path or rule_id or fingerprint
                    if "/" in line or "\\" in line or "." in line:
                        suppressions.add(("*", _normalize_rel_path(line)))
                    else:
                        suppressions.add((line,))
                        suppressions.add(("FINGERPRINT", line))
    except Exception:
        pass

    return suppressions


def _path_matches(rule_path: str, finding_paths: Set[str]) -> bool:
    """Check if a rule path matches any candidate finding path."""
    rule_norm = _normalize_rel_path(rule_path).lower()
    rule_base = os.path.basename(rule_norm)
    for p in finding_paths:
        p_lower = p.lower()
        if p_lower == rule_norm or p_lower == rule_base or p_lower.endswith("/" + rule_norm):
            return True
        if rule_norm.endswith("/" + p_lower) or rule_base == os.path.basename(p_lower):
            return True
    return False


def apply_suppressions(
    findings: List[Finding],
    suppressions: Set[Tuple[Any, ...]],
    repo_path: str = "",
) -> Tuple[List[Finding], int]:
    """
    Marks matching findings as suppressed with reason and returns (unsuppressed_findings, suppressed_count).
    Suppressed findings are marked `f.suppressed = True` with `f.suppression_reason` set,
    so they remain accessible for audit while excluded from active risk counts.
    """
    if not suppressions:
        return [f for f in findings if not f.suppressed], sum(1 for f in findings if f.suppressed)

    suppressed_count = 0

    for f in findings:
        rel_path = _normalize_rel_path(f.file, repo_path)
        base_name = os.path.basename(f.file)
        fp = getattr(f, "fingerprint", "")
        algo = getattr(f, "algorithm", "").lower()
        rule_id = getattr(f, "rule_id", "")
        line_no = getattr(f, "line", 0)

        # Candidate path representations (normalized, lower, base)
        candidate_paths = {
            rel_path,
            rel_path.lower(),
            base_name,
            base_name.lower(),
        }

        # Candidate rule IDs (rule_id, algo, wildcard)
        candidate_rules = {
            rule_id,
            rule_id.lower(),
            getattr(f, "algorithm", ""),
            algo,
            "*",
        }

        is_suppressed = False
        reason = ""

        # Check rules in suppressions set
        for rule in suppressions:
            if len(rule) == 3:
                r_id, r_path, r_line_or_sub = rule
                if r_id in candidate_rules or r_id.lower() in candidate_rules or r_id == "*":
                    if _path_matches(r_path, candidate_paths):
                        if isinstance(r_line_or_sub, int) and r_line_or_sub == line_no:
                            is_suppressed = True
                            reason = f"Suppressed by rule '{rule_id}' on {rel_path}:{line_no}"
                            break
                        elif str(r_line_or_sub) == str(line_no):
                            is_suppressed = True
                            reason = f"Suppressed by rule '{rule_id}' on {rel_path}:{line_no}"
                            break
                        elif r_line_or_sub == fp or r_line_or_sub == algo:
                            is_suppressed = True
                            reason = f"Suppressed by rule '{rule_id}' ({r_line_or_sub}) on {rel_path}"
                            break
            elif len(rule) == 2:
                r_first, r_second = rule
                if r_first == "FINGERPRINT":
                    if r_second == fp:
                        is_suppressed = True
                        reason = f"Suppressed by fingerprint '{fp}'"
                        break
                elif r_first == "*":
                    if _path_matches(r_second, candidate_paths):
                        is_suppressed = True
                        reason = f"Suppressed by path rule '{r_second}'"
                        break
                else:
                    if r_first in candidate_rules or r_first.lower() in candidate_rules:
                        if _path_matches(r_second, candidate_paths):
                            is_suppressed = True
                            reason = f"Suppressed by rule '{rule_id}' on {rel_path}"
                            break
            elif len(rule) == 1:
                r_item = rule[0]
                if r_item in candidate_rules or r_item.lower() in candidate_rules:
                    is_suppressed = True
                    reason = f"Suppressed by rule ID '{rule_id}'"
                    break
                elif r_item == fp:
                    is_suppressed = True
                    reason = f"Suppressed by fingerprint '{fp}'"
                    break
                elif _path_matches(r_item, candidate_paths):
                    is_suppressed = True
                    reason = f"Suppressed by path rule '{r_item}'"
                    break

        if is_suppressed:
            f.suppressed = True
            f.suppression_reason = reason
            suppressed_count += 1

    kept = [f for f in findings if not f.suppressed]
    return kept, suppressed_count
