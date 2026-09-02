import json
from collections import Counter
from typing import List
from .models import Finding


def summarize(findings: List[Finding]) -> dict:
    active = [f for f in findings if not f.suppressed]
    suppressed = [f for f in findings if f.suppressed]
    return {
        "total_findings": len(findings),
        "active_findings": len(active),
        "suppressed_findings": len(suppressed),
        "by_severity": dict(Counter(f.severity.value for f in active)),
        "by_quantum_risk": dict(Counter(f.quantum_risk.value for f in active)),
        "by_language": dict(Counter(f.language for f in active)),
        "files_with_findings": sorted({f.file for f in active}),
    }


def to_json(findings: List[Finding]) -> str:
    payload = {
        "summary": summarize(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)


SEV_COLOR = {
    "Critical": "\033[91m", "High": "\033[93m", "Medium": "\033[33m",
    "Low": "\033[36m", "Informational": "\033[90m",
}
RESET = "\033[0m"


def print_console(findings: List[Finding], use_color: bool = True) -> None:
    s = summarize(findings)
    print(f"\nCrypto scan: {s['total_findings']} finding(s) ({s['active_findings']} active, {s['suppressed_findings']} suppressed) across {len(s['files_with_findings'])} active file(s)")
    print("Active Severity:  " + ("  ".join(f"{k}={v}" for k, v in s["by_severity"].items()) if s["by_severity"] else "None"))
    print("Active Quantum:   " + ("  ".join(f"{k}={v}" for k, v in s["by_quantum_risk"].items()) if s["by_quantum_risk"] else "None"))
    print("-" * 100)
    for f in findings:
        color = SEV_COLOR.get(f.severity.value, "") if use_color else ""
        reset = RESET if use_color else ""
        status_tag = f" [SUPPRESSED: {f.suppression_reason}]" if f.suppressed else ""
        print(f"{color}[{f.severity.value:>13}]{reset} {f.file}:{f.line}  {f.rule_name}{status_tag}"
              f"  (algo={f.algorithm}, quantum_risk={f.quantum_risk.value}, confidence={f.confidence.value})")
        if f.code_snippet:
            print(f"    {f.code_snippet}")
        print(f"    -> {f.recommendation}")
    print("-" * 100)
