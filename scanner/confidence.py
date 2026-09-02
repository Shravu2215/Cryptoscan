"""
Confidence promotion + cross-layer merge layer.

Two responsibilities:

1. MERGE cross-layer duplicates:
   When 2+ findings from *different* detection layers (AST vs regex/entropy)
   describe the same underlying secret on the same (file, line), they are merged
   into a single Finding with:
     - Confidence.CONFIRMED
     - The highest severity among the merged group
     - The most specific rule_id (entropy-secret-high-confidence > regex > AST
       hardcoded-key hits)

   This fixes the bug where the same secret produced N separate rows in the
   Findings page (one per detection layer), inflating the total count and
   making the Findings-page and CBOM-page counts diverge.

2. DO NOT merge findings that represent *distinct* issues on the same line:
   e.g. an AES-ECB finding and a hardcoded-key finding on the same call site
   are independently actionable — keep both. Only merge when the category is
   the same broad bucket ("hardcoded-secret") AND the layers differ.

Usage in pipeline.py / cli.py:
    findings = dedup(findings)
    findings = promote_confirmed(findings)
"""
from typing import List, Dict, Tuple, Set

from .models import Finding, Confidence, Severity


# ---------------------------------------------------------------------------
# Layer classification helper
# ---------------------------------------------------------------------------

def _layer_token(f: Finding) -> str:
    """
    Returns a short string identifying which detection layer produced a finding.

    AST layer:     language in {"python","javascript"} AND rule_id doesn't start with "entropy-"
    Entropy layer: rule_id starts with "entropy-"
    Config/Regex:  language == "config"
    """
    if f.language in {"python", "javascript"} and not f.rule_id.startswith("entropy-"):
        return "ast"
    if f.rule_id.startswith("entropy-"):
        return "entropy"
    return "config"


# ---------------------------------------------------------------------------
# Rule-quality ranking — higher is more specific/preferred as the base finding
# ---------------------------------------------------------------------------

_RULE_QUALITY: Dict[str, int] = {
    "entropy-secret-high-confidence": 100,
    "entropy-secret-high-entropy-only": 80,
    "entropy-secret-name-hint-only": 60,
    "dockerfile-hardcoded-secret": 50,
    "config-plaintext-secret": 40,
}

def _rule_quality(rule_id: str) -> int:
    return _RULE_QUALITY.get(rule_id, 30)


# ---------------------------------------------------------------------------
# Severity ranking (highest value = most severe)
# ---------------------------------------------------------------------------

def _sev_rank(f: Finding) -> int:
    return f.severity.rank


# ---------------------------------------------------------------------------
# Main public function
# ---------------------------------------------------------------------------

def promote_confirmed(findings: List[Finding]) -> List[Finding]:
    """
    After dedup():
      1. Group findings by (file, line).
      2. When 2+ findings from different layers agree on the same secret issue
         (category in {"hardcoded-secret", "secret"}), merge them into one
         Finding with Confidence.CONFIRMED, highest severity, and best rule_id.
      3. For other multi-layer agreement cases (e.g. non-secret findings at
         same line), promote confidence to Confidence.CONFIRMED without dropping.

    Returns the merged/promoted list.
    """
    site_groups: Dict[Tuple[str, int], List[int]] = {}
    for idx, f in enumerate(findings):
        key = (f.file, f.line)
        site_groups.setdefault(key, []).append(idx)

    dropped: Set[int] = set()

    for (file, line), indices in site_groups.items():
        if len(indices) < 2:
            continue

        group = [findings[i] for i in indices]
        layers = {_layer_token(f) for f in group}

        if len(layers) >= 2:
            # Check for hardcoded-secret category overlap to merge
            secret_indices = [i for i in indices if findings[i].category in {"hardcoded-secret", "secret"}]
            if len(secret_indices) >= 2:
                secret_layers = {_layer_token(findings[i]) for i in secret_indices}
                if len(secret_layers) >= 2:
                    # Merge secret findings into the best one
                    secret_group = [findings[i] for i in secret_indices]
                    best_idx = max(secret_indices, key=lambda i: (_rule_quality(findings[i].rule_id), _sev_rank(findings[i])))
                    best = findings[best_idx]
                    best.confidence = Confidence.CONFIRMED
                    best.severity = max(secret_group, key=_sev_rank).severity

                    # Mark other secret findings as dropped
                    for i in secret_indices:
                        if i != best_idx:
                            dropped.add(i)

            # For all surviving findings at this multi-layer corroborated site, promote to CONFIRMED
            for i in indices:
                if i not in dropped:
                    findings[i].confidence = Confidence.CONFIRMED

    out = [findings[i] for i in range(len(findings)) if i not in dropped]
    out.sort(key=lambda f: (f.file, f.line, -f.severity.rank))
    return out
