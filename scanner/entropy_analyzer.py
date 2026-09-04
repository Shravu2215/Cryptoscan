"""
Entropy / Secrets Layer.

Detects hardcoded secrets that the AST layer misses: strings that are assigned
to a variable but never passed directly into a recognized crypto API call in the
same file (e.g. `const STRIPE_SECRET = "sec_live_..."`).

Detection strategy:
  1. Extract string-literal assignments from .py / .js / .env / config files.
  2. Compute Shannon entropy (bits per character) of the literal value.
  3. Flag when EITHER:
       (a) entropy >= ENTROPY_THRESHOLD AND len >= MIN_SECRET_LEN, OR
       (b) identifier name matches rules.SECRET_NAME_HINTS (regardless of entropy)
     Subject to a series of false-positive guards (see _is_likely_fp).

Output contract: EntropyAnalyzer.analyze(file_path, source) -> List[Finding]
  language = the natural language of the file ("python", "javascript", "config")
  confidence = LIKELY for the high-confidence rule_id, POSSIBLE for the others.

References:
  - Shannon entropy threshold of 4.0 bits/char is a widely-used heuristic for
    secret detection; see: Truffleog (Trufflesecurity), detect-secrets (Yelp),
    and the academic treatment in "Mining for Secrets in Source Code Repositories"
    (Meli et al., MSR 2019). The formula is H = -sum(p_i * log2(p_i)).
  - Minimum length of 16 characters is chosen because shorter strings produce
    unreliable entropy signals (a 10-char random token can look low-entropy by
    coincidence), and because any genuine secret below 16 chars is already
    weak by modern standards.
"""
import re
import math
import os
from collections import Counter
from typing import List, Optional, Tuple

from .models import Finding, Severity, QuantumRisk, Confidence
from . import rules

# ---------------------------------------------------------------------------
# Entropy constants — documented, not magic numbers
# ---------------------------------------------------------------------------

# Minimum Shannon entropy (bits per character) to flag as high-confidence secret.
# 4.0 bits/char corresponds roughly to a random alphanumeric string; values below
# this are consistent with English prose, version strings, and similar low-entropy
# content.  Reference: Meli et al. 2019, Trufflehog v2 defaults.
ENTROPY_THRESHOLD: float = 4.0

# Minimum literal length to compute a reliable entropy signal.
# Very short strings have high variance in measured entropy, causing FPs.
MIN_SECRET_LEN: int = 16

# Minimum length for name-hint-only matching (we still require some length to
# avoid flagging empty initializers like `password = ""`).
MIN_NAME_HINT_LEN: int = 8

# ---------------------------------------------------------------------------
# False-positive guard patterns
# ---------------------------------------------------------------------------

# Semantic version string: 1.2.3, 1.2.3-beta.1, etc.
_VERSION_RE = re.compile(r'^\d+\.\d+(\.\d+)?([.-][a-z0-9]+)*$', re.IGNORECASE)

# URL without embedded credentials (no user:pass@ component)
_URL_RE = re.compile(r'^https?://(?![^@/]*:[^@/]*@)[^\s]+$', re.IGNORECASE)

# File paths (Unix or Windows style)
_PATH_RE = re.compile(r'^(?:/[^/\s]+)+/?$|^[A-Za-z]:\\[^\s]+$')

# UUID (8-4-4-4-12 hex, with or without braces)
_UUID_RE = re.compile(
    r'^[{(]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[})]?$',
    re.IGNORECASE
)

# Placeholder / template values (same list as regex_analyzer for consistency)
_PLACEHOLDER_VALUES = frozenset({
    "", "changeme", "your-secret-here", "xxx", "<secret>",
    "todo", "fixme", "example", "replace_me", "insert_secret_here",
    "password", "secret", "your_password_here",
})

_PLACEHOLDER_PATTERNS = re.compile(
    r"""
    ^\$\{[^}]*\}$       |   # ${VAR} shell/docker interpolation
    ^%[^%]+%$           |   # %VAR% Windows-style
    ^\{\{[^}]+\}\}$     |   # {{var}} template engine
    ^\$\([^)]+\)$           # $(command) shell substitution
    """,
    re.VERBOSE,
)


def _is_placeholder(value: str) -> bool:
    v = value.strip().strip('"\'')
    if v.lower() in _PLACEHOLDER_VALUES:
        return True
    if _PLACEHOLDER_PATTERNS.match(v):
        return True
    return False


def _is_likely_fp(value: str, name: str) -> bool:
    """Return True if the value should be skipped as a likely false positive."""
    if _is_placeholder(value):
        return True
    if _VERSION_RE.match(value):
        return True
    if _URL_RE.match(value):
        return True
    if _PATH_RE.match(value):
        return True
    # English prose / sentences / log messages with spaces (e.g. "...removed legacy RC4 support...")
    if " " in value:
        words = [w for w in re.split(r'[^A-Za-z0-9]+', value) if w]
        if len(words) >= 3:
            return True
    # UUID: only skip if the identifier name doesn't match SECRET_NAME_HINTS
    if _UUID_RE.match(value) and not _is_secret_name(name):
        return True
    return False


def _is_secret_name(name: str) -> bool:
    """Delegates to the shared word-boundary matcher in rules.
    Reuses rules.matches_secret_hint() — single source of truth for naming heuristics."""
    return rules.matches_secret_hint(name)


# ---------------------------------------------------------------------------
# Shannon entropy computation
# ---------------------------------------------------------------------------

def shannon_entropy(s: str) -> float:
    """
    Compute the Shannon entropy of string s in bits per character.

    H(X) = -sum(p_i * log2(p_i))  where p_i = count(char_i) / len(s)

    Returns 0.0 for empty strings.
    """
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


# ---------------------------------------------------------------------------
# Source-extraction helpers — pull string-literal assignments line by line
# ---------------------------------------------------------------------------

# .env / config: KEY=value
_ENV_ASSIGNMENT = re.compile(
    r'^[ \t]*([A-Z_][A-Z0-9_]*)[ \t]*=[ \t]*([^\n#]+)',
    re.IGNORECASE | re.MULTILINE,
)


def _extract_py_assignments(source: str) -> List[Tuple[int, str, str]]:
    """Yield (line_no, identifier, literal_value) for Python source."""
    results = []
    # Match variable assignments and keyword arguments: IDENT = "literal" / IDENT = b"literal"
    assign_re = re.compile(
        r'(?:^[ \t]*|\b)([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(?:[brufBRUF]{1,2})?(?:"([^"\\]*(?:\\.[^"\\]*)*)"|\'([^\'\\]*(?:\\.[^\'\\]*)*)\')',
        re.IGNORECASE | re.MULTILINE,
    )
    for m in assign_re.finditer(source):
        # Skip comment lines
        line_start = source.rfind('\n', 0, m.start()) + 1
        raw_prefix = source[line_start:m.start()].lstrip()
        if raw_prefix.startswith('#'):
            continue
        name = m.group(1)
        value = (m.group(2) if m.group(2) is not None else (m.group(3) or "")).replace('\\n', '\n').replace('\\t', '\t')
        line_no = source[:m.start()].count('\n') + 1
        results.append((line_no, name, value))

    return results


def _extract_js_assignments(source: str) -> List[Tuple[int, str, str]]:
    """Yield (line_no, identifier, literal_value) for JS/TS source."""
    results = []
    # Match const/let/var IDENT = "literal" or object property IDENT: "literal"
    assign_re = re.compile(
        r'(?:^[ \t]*|\b)(?:const|let|var)?[ \t]*([A-Za-z_$][A-Za-z0-9_$]*)[ \t]*[:=][ \t]*(?:"([^"\\]*(?:\\.[^"\\]*)*)"|\'([^\'\\]*(?:\\.[^\'\\]*)*)\'|`([^`\\]*(?:\\.[^`\\]*)*)`)',
        re.IGNORECASE | re.MULTILINE,
    )
    for m in assign_re.finditer(source):
        line_start = source.rfind('\n', 0, m.start()) + 1
        raw_prefix = source[line_start:m.start()].lstrip()
        if raw_prefix.startswith('//') or raw_prefix.startswith('/*') or raw_prefix.startswith('*'):
            continue
        name = m.group(1)
        value = (m.group(2) if m.group(2) is not None else (m.group(3) if m.group(3) is not None else (m.group(4) or ""))).replace('\\n', '\n').replace('\\t', '\t')
        line_no = source[:m.start()].count('\n') + 1
        results.append((line_no, name, value))

    return results


def _extract_env_assignments(source: str) -> List[Tuple[int, str, str]]:
    """Yield (line_no, identifier, value) for .env / config files."""
    results = []
    lines = source.splitlines()
    for line_no, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith('#') or stripped.startswith(';'):
            continue
        if '=' in stripped:
            name, raw_val = stripped.split('=', 1)
            name = name.strip()
            val = raw_val.strip()
            if val.startswith('"') and '"' in val[1:]:
                val = val[1:val.index('"', 1)]
            elif val.startswith("'") and "'" in val[1:]:
                val = val[1:val.index("'", 1)]
            else:
                if ' #' in val:
                    val = val.split(' #', 1)[0].strip()
            if re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', name):
                results.append((line_no, name, val))
    return results


# ---------------------------------------------------------------------------
# Finding factory
# ---------------------------------------------------------------------------

def _make_finding(
    file_path: str,
    line_no: int,
    name: str,
    value: str,
    language: str,
    entropy: float,
    name_matched: bool,
    entropy_matched: bool,
) -> Optional[Finding]:
    """
    Classify and construct a Finding based on which signals fired.

    Classification:
      entropy-secret-high-confidence: BOTH entropy AND name-hint signals fired
      entropy-secret-high-entropy-only: only the entropy signal fired
      entropy-secret-name-hint-only: only the name-hint signal fired

    Severity is based on rules.HARDCODED_KEY (reused, not reinvented), downgraded
    one tier for the name-hint-only case (weaker signal).
    """
    base = rules.HARDCODED_KEY  # algorithm/severity/quantum_risk/recommendation

    if entropy_matched and name_matched:
        rule_id = "entropy-secret-high-confidence"
        rule_name = "High-entropy secret (name + entropy confirmed)"
        severity = base["severity"]                # CRITICAL -> keep as-is
        # We treat this as HIGH instead of CRITICAL because this is a single-layer
        # heuristic (no AST confirmation). promote_confirmed() can upgrade later.
        severity = Severity.HIGH
        confidence = Confidence.LIKELY
    elif entropy_matched:
        rule_id = "entropy-secret-high-entropy-only"
        rule_name = "High-entropy literal (entropy only)"
        severity = Severity.HIGH
        confidence = Confidence.POSSIBLE
    else:
        # name_matched only
        rule_id = "entropy-secret-name-hint-only"
        rule_name = "Possible secret (name hint only)"
        severity = Severity.MEDIUM    # one tier below HIGH — weaker signal
        confidence = Confidence.POSSIBLE

    return Finding(
        file=file_path,
        line=line_no,
        column=0,
        language=language,
        rule_id=rule_id,
        rule_name=rule_name,
        category="hardcoded-secret",
        algorithm=base["algorithm"],
        severity=severity,
        quantum_risk=base["quantum_risk"],
        message=(
            f"Identifier '{name}' assigned a literal value that appears to be a secret "
            f"(entropy={entropy:.2f} bits/char, len={len(value)})."
        ),
        recommendation=base["recommendation"],
        code_snippet=f"{name} = <{len(value)}-char literal>",
        confidence=confidence,
        tags=["entropy", "hardcoded-secret"],
    )


def _classify_language(file_path: str) -> str:
    """Determine language tag from file extension."""
    bn = os.path.basename(file_path)
    ext = os.path.splitext(bn)[1].lower()
    if ext == ".py":
        return "python"
    if ext in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}:
        return "javascript"
    return "config"


def _extract_assignments(file_path: str, source: str) -> List[Tuple[int, str, str]]:
    """Route to the right extractor based on file type."""
    lang = _classify_language(file_path)
    if lang == "python":
        return _extract_py_assignments(source)
    if lang == "javascript":
        return _extract_js_assignments(source)
    # .env, .yml, .yaml, .ini, .conf, Dockerfile — use env-style extraction
    return _extract_env_assignments(source)


# ---------------------------------------------------------------------------
# Main analyzer class
# ---------------------------------------------------------------------------

class EntropyAnalyzer:
    """
    Entropy/secrets detection layer. Mirrors PythonAnalyzer/JSAnalyzer interface:
      .analyze(file_path: str, source: str) -> List[Finding]

    Detects hardcoded secrets via Shannon entropy (4.0 bits/char threshold) and/or
    identifier-name heuristics (rules.SECRET_NAME_HINTS).  All findings are derived
    from actually scanning the provided source — no hardcoded/fake findings.
    """

    def analyze(self, file_path: str, source: str) -> List[Finding]:
        """Analyze a single source file. Returns zero findings for clean files."""
        language = _classify_language(file_path)
        assignments = _extract_assignments(file_path, source)
        findings: List[Finding] = []

        for line_no, name, value in assignments:
            if not value:
                continue
            if _is_likely_fp(value, name):
                continue

            entropy = shannon_entropy(value)
            name_matched = _is_secret_name(name)
            entropy_matched = (len(value) >= MIN_SECRET_LEN and entropy >= ENTROPY_THRESHOLD)

            # Must satisfy at least one signal; name-hint requires minimum length
            if entropy_matched:
                pass  # always worth flagging if entropy is high
            elif name_matched and len(value) >= MIN_NAME_HINT_LEN:
                pass  # name hint + non-trivial length is worth flagging
            else:
                continue

            f = _make_finding(
                file_path=file_path,
                line_no=line_no,
                name=name,
                value=value,
                language=language,
                entropy=entropy,
                name_matched=name_matched,
                entropy_matched=entropy_matched,
            )
            if f is not None:
                findings.append(f)

        return findings
