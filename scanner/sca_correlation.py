"""
Cross-Layer SCA & Source Code Corroboration.

Correlates dependency manifest findings (SCA) with source code findings (AST / Regex / Entropy).
When a declared library algorithm (e.g. "DES", "RSA", "MD5", "ECDSA", "RC4") in dependencies
matches an algorithm detected in source code, both the manifest finding and the source finding
are promoted to Confidence.CONFIRMED (as 2 independent layers corroborated the finding).
"""
from typing import List, Set
from .models import Finding, Confidence
from .sca_analyzer import KNOWN_CRYPTO_LIBRARIES


def correlate_sca_with_source(findings: List[Finding]) -> List[Finding]:
    """
    Correlates manifest SCA findings with source-level findings across the scanned repository.
    Promotes matched pairs to Confidence.CONFIRMED.
    """
    if not findings:
        return findings

    # 1. Collect all algorithms detected in source code (AST, Regex, Entropy)
    source_algorithms: Set[str] = set()
    for f in findings:
        if f.language != "manifest" and f.algorithm:
            alg_norm = f.algorithm.strip().upper()
            source_algorithms.add(alg_norm)
            # Add sub-components (e.g. "AES-256-ECB" -> "AES", "ECB"; "3DES/DES" -> "3DES", "DES")
            for part in alg_norm.replace("/", " ").replace("-", " ").replace(",", " ").split():
                if len(part) >= 2 and part not in {"MODE", "KEY", "WEAK", "STATIC", "RAW"}:
                    source_algorithms.add(part)

    # 2. Extract algorithms provided by declared manifest dependencies
    matched_manifest_indices: Set[int] = set()
    corroborated_algorithms: Set[str] = set()

    for idx, f in enumerate(findings):
        if f.language == "manifest":
            # Extract ecosystem and lib name from rule_id: sca-{ecosystem}-{lib_name}
            parts = f.rule_id.split("-")
            ecosystem = parts[1] if len(parts) >= 3 else ""
            lib_name = "-".join(parts[2:]) if len(parts) >= 3 else f.algorithm.lower()

            declared_algos = []
            if ecosystem in KNOWN_CRYPTO_LIBRARIES and lib_name in KNOWN_CRYPTO_LIBRARIES[ecosystem]:
                declared_algos = KNOWN_CRYPTO_LIBRARIES[ecosystem][lib_name].get("algorithms", [])
            elif f.algorithm:
                declared_algos = [f.algorithm]

            matched = False
            for da in declared_algos:
                da_upper = da.upper()
                if da_upper in {"GENERAL CRYPTO", "LEGACY CRYPTO", "SSH/CRYPTO", "BOUNCYCASTLE"}:
                    continue
                if da_upper in source_algorithms or any(da_upper in sa.split() for sa in source_algorithms):
                    matched = True
                    corroborated_algorithms.add(da_upper)
                    for sa in source_algorithms:
                        if da_upper in sa:
                            corroborated_algorithms.add(sa)

            if matched:
                matched_manifest_indices.add(idx)

    # 3. Promote findings that have multi-layer corroboration
    for idx, f in enumerate(findings):
        if idx in matched_manifest_indices:
            f.confidence = Confidence.CONFIRMED
        elif f.language != "manifest" and f.algorithm:
            f_alg = f.algorithm.strip().upper()
            alg_parts = set(f_alg.replace("/", " ").replace("-", " ").split())
            if f_alg in corroborated_algorithms or bool(alg_parts & corroborated_algorithms):
                f.confidence = Confidence.CONFIRMED

    return findings
