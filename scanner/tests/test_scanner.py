"""
Regression tests. Run with: python3 -m pytest tests/ -v  (or plain: python3 tests/test_scanner.py)

These lock in the specific bugs that were reported against the old scanner:
  1. no exact (file, line, rule_id) duplicates
  2. no generic catch-all finding surviving next to a specific one on the same call
  3. a fixed file never scores >= its vulnerable counterpart
  4. timing-unsafe-compare rule exists and fires
  5. RSA is a single merged finding, quantum_risk is never "Safe"
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cli import scan  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
VULN = os.path.join(FIXTURES, "vulnerable")
FIXED = os.path.join(FIXTURES, "fixed")


def test_no_exact_duplicates():
    findings = scan(VULN)
    seen = set()
    for f in findings:
        key = (f.file, f.line, f.rule_id)
        assert key not in seen, f"exact duplicate finding: {key}"
        seen.add(key)


def test_no_generic_alongside_specific():
    findings = scan(VULN)
    by_site = {}
    for f in findings:
        by_site.setdefault(f.call_site, []).append(f)
    for site, group in by_site.items():
        if any(not g.generic for g in group):
            assert not any(g.generic for g in group), f"generic catch-all survived dedup at {site}"


def test_fixed_never_scores_worse_or_equal_critical_vs_vulnerable():
    vuln = {f.file.split("/")[-1]: [] for f in scan(VULN)}
    for f in scan(VULN):
        vuln.setdefault(os.path.basename(f.file), []).append(f)
    fixed = {}
    for f in scan(FIXED):
        fixed.setdefault(os.path.basename(f.file), []).append(f)

    for name in ("02-ecb-mode.js", "03-hardcoded-key.js", "05-static-iv-reuse.js", "06-no-integrity-check.js"):
        vuln_max = max((f.severity.rank for f in vuln.get(name, [])), default=0)
        fixed_max = max((f.severity.rank for f in fixed.get(name, [])), default=0)
        assert fixed_max < vuln_max or fixed_max == 0, (
            f"{name}: fixed severity {fixed_max} not lower than vulnerable {vuln_max}"
        )
        # none of the fixed files should read as Critical (rank 4)
        assert fixed_max < 4, f"{name}: fixed version still shows a Critical finding"


def test_timing_unsafe_compare_rule_fires_only_on_vulnerable():
    vuln_hits = [f for f in scan(VULN) if "08-timing-unsafe-compare" in f.file]
    fixed_hits = [f for f in scan(FIXED) if "08-timing-unsafe-compare" in f.file]
    assert len(vuln_hits) >= 1
    assert all(f.rule_id != "timing-unsafe-compare" for f in fixed_hits)


def test_rsa_is_single_merged_finding_and_never_safe():
    for path, expect_high in ((VULN, True), (FIXED, False)):
        hits = [f for f in scan(path) if "rsa-key-size" in f.file]
        rsa_findings = [f for f in hits if f.rule_id == "rsa-key-generation"]
        assert len(rsa_findings) == 1, f"expected exactly one merged RSA finding, got {len(rsa_findings)}"
        assert rsa_findings[0].quantum_risk.value == "Quantum-Broken"
        if expect_high:
            assert rsa_findings[0].severity.rank >= 3  # High or Critical
        else:
            assert rsa_findings[0].severity.rank <= 2  # Medium at most


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
