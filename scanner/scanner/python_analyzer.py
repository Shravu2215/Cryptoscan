"""
AST-based analyzer for Python source. Uses the stdlib `ast` module (real parse
tree, not regex) to find hashlib/pycryptodome/`cryptography`/random/hmac usage
and flag crypto weaknesses.

Supports: hashlib (md5/sha1/...), pycryptodome (Crypto.Cipher.AES/DES/DES3,
Crypto.PublicKey.RSA), the `cryptography` package (rsa.generate_private_key,
ec.generate_private_key), `random` used for security-sensitive values, and
`==`/`!=` secret comparisons that should use hmac.compare_digest.
"""
import ast
from typing import List, Optional

from .models import Finding, Severity, QuantumRisk
from . import rules


def _name_of(node) -> str:
    """Best-effort dotted name for a Call's func, e.g. 'Crypto.Cipher.AES.new'."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


class _Imports(ast.NodeVisitor):
    """Collect import aliases so aliased imports still resolve to their real
    name for rule matching, e.g.:
        import hashlib as _hashlib         -> {"_hashlib": "hashlib"}
        from Crypto.Cipher import ARC4 as RC4Cipher -> {"RC4Cipher": "ARC4"}
    A naive regex/name-based scanner is easily defeated by renaming an
    import; this makes the AST scanner resolve back to the canonical name
    before any rule check runs.
    """

    def __init__(self):
        self.aliases = {}  # local (in-file) name -> canonical name

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            self.aliases[local] = alias.name.split(".")[0]
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        for alias in node.names:
            local = alias.asname or alias.name
            self.aliases[local] = alias.name
        self.generic_visit(node)


def _resolve_alias(fname: str, aliases: dict) -> str:
    """Rewrite the leading component of a dotted call name through the
    import-alias table, e.g. 'RC4Cipher.new' -> 'ARC4.new'."""
    if not fname:
        return fname
    parts = fname.split(".")
    if parts[0] in aliases:
        parts[0] = aliases[parts[0]]
    return ".".join(parts)


def _annotate_parents(tree):
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child._csparent = node


def _enclosing_func_name(node):
    """Walk up parent pointers (set by _annotate_parents) to the nearest
    enclosing function definition's name, or None if at module scope."""
    n = getattr(node, "_csparent", None)
    while n is not None:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return n.name
        n = getattr(n, "_csparent", None)
    return None


def _literal_bytes_len(node) -> Optional[int]:
    if isinstance(node, ast.Constant) and isinstance(node.value, (bytes, str)):
        return len(node.value)
    return None


def _is_secret_name(name: str) -> bool:
    n = (name or "").lower()
    return any(hint in n for hint in rules.SECRET_NAME_HINTS)


def _line_src(source_lines, lineno):
    try:
        return source_lines[lineno - 1].strip()
    except IndexError:
        return ""


class _Assigns(ast.NodeVisitor):
    """One-pass, whole-file, last-write-wins variable table. Heuristic by
    design - good enough for flagging obvious hardcoded/static values in a
    single-file static scan, same tradeoff every lightweight SAST tool makes."""

    def __init__(self):
        self.table = {}  # name -> ast node (the assigned value)

    def visit_Assign(self, node):
        for t in node.targets:
            if isinstance(t, ast.Name):
                self.table[t.id] = node.value
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if isinstance(node.target, ast.Name) and node.value is not None:
            self.table[node.target.id] = node.value
        self.generic_visit(node)


def _resolve(node, table, depth=0):
    """Follow simple Name -> Assign chains to reach a literal or a Call."""
    if depth > 5 or node is None:
        return node
    if isinstance(node, ast.Name) and node.id in table:
        return _resolve(table[node.id], table, depth + 1)
    return node


def _is_dynamic_random_source(node) -> bool:
    """True if `node` is a call that produces cryptographically random bytes."""
    if isinstance(node, ast.Call):
        n = _name_of(node.func)
        return n in ("os.urandom", "urandom", "secrets.token_bytes", "secrets.token_hex",
                     "get_random_bytes", "Random.get_random_bytes")
    return False


def _is_confirmed_static(node) -> bool:
    """True only when the IV/nonce provably resolves to a fixed literal. An
    *unresolved* Name (e.g. a function parameter we can't trace back through
    this file) is unknown, not static - flagging it would be a false
    positive, not a genuine finding."""
    return isinstance(node, ast.Constant) and isinstance(node.value, (bytes, str))


class PythonAnalyzer:
    rule_source = "python-ast"

    def analyze(self, file_path: str, source: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            tree = ast.parse(source, filename=file_path)
        except SyntaxError:
            return findings

        assigns = _Assigns()
        assigns.visit(tree)
        table = assigns.table
        source_lines = source.splitlines()

        imports = _Imports()
        imports.visit(tree)
        aliases = imports.aliases

        _annotate_parents(tree)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                findings.extend(self._check_call(node, file_path, table, source_lines, aliases))
            elif isinstance(node, ast.Compare):
                f = self._check_compare(node, file_path, source_lines)
                if f:
                    findings.append(f)

        return findings

    # -- Call-expression checks --------------------------------------------------
    def _check_call(self, node: ast.Call, file_path, table, source_lines, aliases) -> List[Finding]:
        out: List[Finding] = []
        fname = _resolve_alias(_name_of(node.func), aliases)
        line = node.lineno
        col = node.col_offset
        snippet = _line_src(source_lines, line)

        # -- hashlib.md5 / hashlib.sha1 / hashlib.new("md5") --------------------
        hash_algo = None
        if fname in ("hashlib.md5", "md5", "hashlib.sha1", "sha1", "hashlib.sha256", "sha256", "hashlib.sha3_256", "sha3_256", "hashlib.sha512", "sha512"):
            hash_algo = fname.split(".")[-1].replace("sha3_256", "sha3")
        elif fname == "hashlib.new" and node.args:
            lit = _resolve(node.args[0], table)
            if isinstance(lit, ast.Constant) and isinstance(lit.value, str):
                hash_algo = lit.value.lower()

        if hash_algo and hash_algo in rules.HASH_ALGOS:
            profile = dict(rules.HASH_ALGOS[hash_algo])
            is_password_ctx = _is_secret_name(snippet) and ("password" in snippet.lower() or "pwd" in snippet.lower() or "passwd" in snippet.lower())
            rule_id = f"{hash_algo}-weak-password-hash" if is_password_ctx else f"{hash_algo}-hashing"
            out.append(Finding(
                file=file_path, line=line, column=col, language="python",
                rule_id=rule_id, rule_name=f"{profile['algorithm']} {'weak-password-hash' if is_password_ctx else 'hashing'}",
                category="hash", algorithm=profile["algorithm"], severity=profile["severity"],
                quantum_risk=profile["quantum_risk"],
                message=f"{profile['algorithm']} used{' for password hashing' if is_password_ctx else ''} at line {line}.",
                recommendation=profile["recommendation"], code_snippet=snippet,
                specificity=3 if is_password_ctx else 2, generic=False,
            ))
            return out  # a hashlib call can't also be a cipher/rng call

        # -- Crypto.Cipher.<ALGO>.new(...) (pycryptodome) ------------------------
        # Gate includes every algo name the classical-break branch of
        # _check_cipher_new recognizes, not just AES/DES/DES3 - otherwise an
        # aliased or directly-imported RC4/ARC4/Blowfish/RC2/3DES class name
        # never even reaches the check below.
        if fname.endswith(".new") and fname.split(".")[0] in (
            "AES", "DES", "DES3", "TDES", "RC2", "RC4", "ARC4", "Blowfish",
            "Crypto", "Cryptodome",
        ):
            out.extend(self._check_cipher_new(node, fname, file_path, table, source_lines))

        # -- cryptography lib hazmat: Cipher(algorithms.X(key), modes.Y()) -------
        if fname == "Cipher":
            out.extend(self._check_hazmat_cipher(node, file_path, table, source_lines))

        # -- cryptography lib: Fernet(key) - flag the construction site only,
        # not the paired Fernet.generate_key() call, so a common one-liner
        # like `Fernet(Fernet.generate_key())` doesn't double-report. -------
        if fname == "Fernet":
            out.append(self._mk_finding(file_path, line, col, "python", "fernet-aes128-cbc-hmac",
                                          "Fernet symmetric encryption", "symmetric-cipher",
                                          rules.FERNET_PROFILE, snippet, specificity=2))

        # -- hmac.new(key, msg, hashlib.<weak>) - weak digest used as a MAC ------
        if fname == "hmac.new":
            out.extend(self._check_hmac_digest(node, file_path, table, source_lines, aliases))

        # -- RSA.generate(bits) (pycryptodome) ------------------------------------
        if fname in ("RSA.generate",):
            bits = None
            if node.args:
                lit = _resolve(node.args[0], table)
                if isinstance(lit, ast.Constant) and isinstance(lit.value, int):
                    bits = lit.value
            profile = rules.rsa_profile(bits)
            out.append(self._mk_finding(file_path, line, col, "python", "rsa-key-generation",
                                          "RSA key_generation", "asymmetric", profile, snippet,
                                          specificity=2, tags=profile.get("tags", [])))

        # -- cryptography lib: rsa.generate_private_key(key_size=X) --------------
        if fname in ("rsa.generate_private_key", "generate_private_key") and "RSA" not in fname:
            bits = None
            for kw in node.keywords:
                if kw.arg == "key_size":
                    lit = _resolve(kw.value, table)
                    if isinstance(lit, ast.Constant) and isinstance(lit.value, int):
                        bits = lit.value
            if bits or "rsa" in fname:
                profile = rules.rsa_profile(bits)
                out.append(self._mk_finding(file_path, line, col, "python", "rsa-key-generation",
                                              "RSA key_generation", "asymmetric", profile, snippet,
                                              specificity=2, tags=profile.get("tags", [])))

        # -- cryptography lib: ec.generate_private_key(ec.SECP256R1()) -----------
        if fname in ("ec.generate_private_key",):
            curve = "unknown-curve"
            if node.args and isinstance(node.args[0], ast.Call):
                curve = _name_of(node.args[0].func).split(".")[-1]
            profile = rules.ecc_profile(curve, purpose="signature")
            out.append(self._mk_finding(file_path, line, col, "python", "ecdsa-key-generation",
                                          f"ECDSA key_generation ({curve})", "asymmetric", profile, snippet,
                                          specificity=2))

        # -- insecure RNG feeding a security-sensitive value ----------------------
        if fname in ("random.random", "random.randint", "random.choice", "random.getrandbits",
                       "random.randrange", "random.sample", "random.seed"):
            out.extend(self._check_rng_context(node, file_path, source_lines))

        return out

    def _check_hazmat_cipher(self, node, file_path, table, source_lines) -> List[Finding]:
        """cryptography lib: Cipher(algorithms.AES(key), modes.ECB()) etc.
        A structurally different call shape from pycryptodome's `AES.new(...)`
        - this is a separate composed-object API, so it needs its own check
        rather than reusing _check_cipher_new."""
        out = []
        line, col = node.lineno, node.col_offset
        snippet = _line_src(source_lines, line)
        if len(node.args) < 1:
            return out

        algo_call = node.args[0]
        mode_call = node.args[1] if len(node.args) >= 2 else None
        for kw in node.keywords:
            if kw.arg == "mode":
                mode_call = kw.value

        if not (isinstance(algo_call, ast.Call)):
            return out
        algo = _name_of(algo_call.func).split(".")[-1]  # e.g. "AES", "TripleDES"
        mode = None
        if isinstance(mode_call, ast.Call):
            mode = _name_of(mode_call.func).split(".")[-1].upper()  # e.g. "ECB", "GCM"

        key_bits = None
        if algo_call.args:
            key_val = _resolve(algo_call.args[0], table)
            blen = _literal_bytes_len(key_val)
            if blen:
                key_bits = blen * 8

        if algo.upper() not in ("AES",):
            # Non-AES hazmat ciphers (TripleDES etc.) - flag via the same
            # classical-break table used for pycryptodome's DES3/RC4/Blowfish.
            if algo.upper() in ("TRIPLEDES", "3DES", "DES", "BLOWFISH", "ARC4", "RC4"):
                profile = rules.symmetric_profile(algo, mode or "")
                out.append(self._mk_finding(file_path, line, col, "python", f"{algo.lower()}-deprecated-cipher",
                                              f"{algo} deprecated-cipher", "symmetric-cipher", profile, snippet,
                                              specificity=3))
            return out

        profile = rules.symmetric_profile("AES", mode or "", key_bits)
        if mode == "ECB":
            out.append(self._mk_finding(file_path, line, col, "python", "aes-ecb-mode",
                                          f"AES-{key_bits or '?'}-ECB", "symmetric-cipher", profile, snippet,
                                          specificity=3))
        elif mode in ("CBC", "CTR", "CFB", "OFB"):
            out.append(self._mk_finding(file_path, line, col, "python", "aes-missing-aead",
                                          f"AES-{key_bits or '?'}-{mode} missing-aead", "symmetric-cipher",
                                          profile, snippet, specificity=2, generic=True))
        elif mode in ("GCM", "CCM"):
            out.append(self._mk_finding(file_path, line, col, "python", "aes-aead-mode",
                                          f"AES-{key_bits or '?'}-{mode}", "symmetric-cipher", profile, snippet,
                                          specificity=1, generic=True))
        return out

    def _check_hmac_digest(self, node, file_path, table, source_lines, aliases) -> List[Finding]:
        """hmac.new(key, msg, hashlib.sha1) / digestmod=hashlib.md5 - the weak
        hash is passed as a *reference*, not called, so the hashlib.md5/sha1
        call check above never sees it. Needs its own check."""
        out = []
        line, col = node.lineno, node.col_offset
        snippet = _line_src(source_lines, line)

        digest_node = node.args[2] if len(node.args) >= 3 else None
        for kw in node.keywords:
            if kw.arg == "digestmod":
                digest_node = kw.value
        resolved = _resolve(digest_node, table)

        digest_name = None
        if isinstance(resolved, ast.Attribute):
            digest_name = _resolve_alias(_name_of(resolved), aliases)
        elif isinstance(resolved, ast.Constant) and isinstance(resolved.value, str):
            digest_name = f"hashlib.{resolved.value.lower()}"

        if not digest_name or not digest_name.startswith("hashlib."):
            return out
        algo_key = digest_name.split(".")[-1]
        if algo_key in ("md5", "sha1"):
            profile = dict(rules.HASH_ALGOS[algo_key])
            out.append(self._mk_finding(file_path, line, col, "python", f"{algo_key}-hmac-weak-digest",
                                          f"HMAC-{profile['algorithm']} weak-digest", "hash", profile, snippet,
                                          specificity=3))
        return out

    def _check_cipher_new(self, node, fname, file_path, table, source_lines) -> List[Finding]:
        out = []
        line, col = node.lineno, node.col_offset
        snippet = _line_src(source_lines, line)
        algo = fname.split(".")[0]
        if algo in ("Crypto", "Cryptodome"):
            # e.g. Crypto.Cipher.AES.new -> pull the real algo name out of the dotted path
            dotted = fname.split(".")
            algo = dotted[-2] if len(dotted) >= 2 else "AES"

        if algo in ("DES", "DES3", "TDES", "RC2", "RC4", "ARC4", "Blowfish"):
            # Extract the mode too (if given) purely for a more precise label
            # (e.g. "DES3-ECB" vs bare "DES3") - severity is CRITICAL either
            # way since the algorithm itself is broken/deprecated regardless
            # of mode.
            mode = None
            mode_node = node.args[1] if len(node.args) >= 2 else None
            for kw in node.keywords:
                if kw.arg == "mode":
                    mode_node = kw.value
            if isinstance(mode_node, ast.Attribute) and mode_node.attr.startswith("MODE_"):
                mode = mode_node.attr.replace("MODE_", "")
            profile = rules.symmetric_profile(algo, mode or "")
            out.append(self._mk_finding(file_path, line, col, "python", f"{algo.lower()}-deprecated-cipher",
                                          f"{algo} deprecated-cipher", "symmetric-cipher", profile, snippet,
                                          specificity=3))
            return out

        if algo != "AES":
            return out

        # Determine mode: 2nd positional arg or mode= kwarg, expected form AES.MODE_XXX
        mode = None
        mode_node = None
        if len(node.args) >= 2:
            mode_node = node.args[1]
        for kw in node.keywords:
            if kw.arg == "mode":
                mode_node = kw.value
        if isinstance(mode_node, ast.Attribute) and mode_node.attr.startswith("MODE_"):
            mode = mode_node.attr.replace("MODE_", "")

        # Key: 1st positional arg
        key_bits = None
        key_hardcoded = False
        if node.args:
            key_val = _resolve(node.args[0], table)
            blen = _literal_bytes_len(key_val)
            if blen:
                key_bits = blen * 8
                key_hardcoded = True

        # IV: 3rd positional or iv=/nonce= kwarg
        iv_node = node.args[2] if len(node.args) >= 3 else None
        for kw in node.keywords:
            if kw.arg in ("iv", "nonce"):
                iv_node = kw.value
        iv_static = False
        resolved_iv = None
        if iv_node is not None:
            resolved_iv = _resolve(iv_node, table)
            iv_static = _is_confirmed_static(resolved_iv)

        profile = rules.symmetric_profile("AES", mode or "", key_bits)
        red_flags = []
        if key_hardcoded:
            red_flags.append("hardcoded-key")
        if iv_node is not None and iv_static:
            red_flags.append("static-iv")

        # Hardcoded key -> its own critical, specific finding (independent of mode)
        if key_hardcoded:
            hp = dict(rules.HARDCODED_KEY)
            out.append(self._mk_finding(file_path, line, col, "python", "aes-hardcoded-key",
                                          f"AES-{key_bits}-{mode or '?'} hardcoded-key", "symmetric-cipher",
                                          hp, snippet, specificity=4))

        if iv_node is not None and iv_static and mode in ("CBC", "CTR", "CFB", "OFB", "GCM"):
            ivp = dict(rules.STATIC_IV)
            out.append(self._mk_finding(file_path, line, col, "python", "aes-static-iv-reuse",
                                          f"AES-{key_bits}-{mode} static-iv-reuse", "symmetric-cipher",
                                          ivp, snippet, specificity=4))

        if mode == "ECB":
            out.append(self._mk_finding(file_path, line, col, "python", "aes-ecb-mode",
                                          f"AES-{key_bits}-ECB", "symmetric-cipher", profile, snippet,
                                          specificity=3))
        elif mode in ("CBC", "CTR", "CFB", "OFB"):
            # Escalate "missing AEAD" only when paired with another concrete red flag.
            # A correctly-fixed file (fresh IV, no hardcoded key) gets Low/Informational,
            # not the same Critical rating as a genuinely broken one.
            missing_aead = dict(profile)
            if red_flags:
                missing_aead["severity"] = Severity.CRITICAL
                missing_aead["recommendation"] = (
                    f"Combined with {', '.join(red_flags)}, lack of authenticated encryption makes "
                    "this call exploitable. " + profile["recommendation"]
                )
            out.append(self._mk_finding(file_path, line, col, "python", "aes-missing-aead",
                                          f"AES-{key_bits}-{mode} missing-aead", "symmetric-cipher",
                                          missing_aead, snippet, specificity=2, generic=(not red_flags)))
        elif mode in ("GCM", "CCM"):
            out.append(self._mk_finding(file_path, line, col, "python", "aes-aead-mode",
                                          f"AES-{key_bits}-{mode}", "symmetric-cipher", profile, snippet,
                                          specificity=1, generic=True))
        else:
            # unknown/unspecified mode - generic catch-all, lowest specificity so any
            # more specific finding above on the same call site suppresses this one.
            out.append(self._mk_finding(file_path, line, col, "python", "aes-encryption",
                                          f"AES encryption", "symmetric-cipher", profile, snippet,
                                          specificity=1, generic=True))
        return out

    def _check_rng_context(self, node, file_path, source_lines) -> List[Finding]:
        line, col = node.lineno, node.col_offset
        snippet = _line_src(source_lines, line)
        parent_target = None
        # Approximate using the source line's assignment target name if this
        # call is the RHS of a simple `name = random...(...)`.
        if "=" in snippet and not snippet.strip().startswith("if"):
            target = snippet.split("=", 1)[0].strip()
            if target.isidentifier():
                parent_target = target

        is_secret_context = bool(parent_target and _is_secret_name(parent_target))

        # Fall back to the enclosing function's name: catches calls that
        # aren't a simple `var = random.x(...)` assignment - e.g. used
        # directly in a `return`, or nested inside a comprehension/another
        # call like `"".join(random.choice(c) for _ in range(n))` or
        # `bytes(random.getrandbits(8) for _ in range(32))`. A function named
        # like `generate_otp(...)` or `..._token(...)` is itself the
        # security-sensitive-name signal when no local variable name exists.
        if not is_secret_context:
            func_name = _enclosing_func_name(node)
            if func_name and _is_secret_name(func_name):
                is_secret_context = True

        if is_secret_context:
            profile = dict(rules.INSECURE_RNG)
            return [self._mk_finding(file_path, line, col, "python", "insecure-rng",
                                       "random module insecure-rng", "rng", profile, snippet, specificity=3)]
        return []

    def _check_compare(self, node: ast.Compare, file_path, source_lines) -> Optional[Finding]:
        if len(node.ops) != 1 or not isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
            return None
        left, right = node.left, node.comparators[0]

        def name_of(n):
            if isinstance(n, ast.Name):
                return n.id
            if isinstance(n, ast.Attribute):
                return n.attr
            return ""

        def is_trivial(n):
            return isinstance(n, ast.Constant) and n.value in ("", None, 0)

        NON_SECRET_PROPS = {"length", "len", "size", "count", "index"}
        if name_of(left).lower() in NON_SECRET_PROPS or name_of(right).lower() in NON_SECRET_PROPS:
            return None

        candidate = None
        for side in (left, right):
            nm = name_of(side)
            if nm and _is_secret_name(nm):
                candidate = nm
                break
        if not candidate:
            return None
        if is_trivial(left) or is_trivial(right):
            return None

        line, col = node.lineno, node.col_offset
        snippet = _line_src(source_lines, line)
        profile = dict(rules.TIMING_UNSAFE_COMPARE)
        return self._mk_finding(file_path, line, col, "python", "timing-unsafe-compare",
                                  "Non-constant-time secret comparison", "comparison", profile, snippet,
                                  specificity=3)

    @staticmethod
    def _mk_finding(file_path, line, col, language, rule_id, rule_name, category, profile,
                     snippet, specificity=1, generic=False, tags=None) -> Finding:
        return Finding(
            file=file_path, line=line, column=col, language=language, rule_id=rule_id,
            rule_name=rule_name, category=category, algorithm=profile["algorithm"],
            severity=profile["severity"], quantum_risk=profile["quantum_risk"],
            message=f"{rule_name} at line {line}.", recommendation=profile["recommendation"],
            code_snippet=snippet, specificity=specificity, generic=generic, tags=tags or [],
        )
