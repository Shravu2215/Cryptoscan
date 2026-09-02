"""
Dedup engine.

Two distinct bugs this exists to fix:

1. Exact duplicates: the same (file, line, rule_id) emitted twice (e.g. a
   generic catch-all rule re-firing on a call site a specific rule already
   covered, or any accidental double-emission in an analyzer). Collapsed to one.

2. Generic-vs-specific overlap: a specific rule ("aes-hardcoded-key",
   "md5-weak-password-hash", "insecure-rng", ...) and a generic catch-all rule
   ("aes-encryption", "md5-hashing") both fire on the same call site. The
   generic one is suppressed - most-specific-rule-wins, one finding per
   (file, line, call-site) unless the findings represent genuinely distinct
   vulnerability classes on the same line (e.g. hardcoded-key AND
   missing-aead on one call - both are kept, since both are real, different,
   independently-fixable issues; only the *generic* AES-encryption note is
   redundant once either fires).
"""
from typing import List
from models import Finding


def dedup(findings: List[Finding]) -> List[Finding]:
    # Pass 1: collapse exact duplicates (same file + line + rule_id).
    seen = {}
    for f in findings:
        key = (f.file, f.line, f.rule_id)
        if key not in seen:
            seen[key] = f
    deduped = list(seen.values())

    # Pass 2: group by (file, line); drop generic findings if a specific one
    # exists for the same call site / line.
    by_site = {}
    for f in deduped:
        by_site.setdefault((f.file, f.line), []).append(f)

    out: List[Finding] = []
    for site, group in by_site.items():
        has_specific = any(not g.generic for g in group)
        for g in group:
            if g.generic and has_specific:
                continue
            out.append(g)

    out.sort(key=lambda f: (f.file, f.line, -f.severity.rank))
    return out
