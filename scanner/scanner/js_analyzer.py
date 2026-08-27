"""
AST-based analyzer for JavaScript/Node source. Uses `esprima` (a real ECMAScript
parser, not regex) to build a tree, then walks it looking for Node's `crypto`
module usage plus Math.random() and === secret comparisons.

Shares the exact same rule table (scanner.rules) as the Python analyzer so risk
tagging can't drift between the two language paths.
"""
from typing import List, Optional, Dict, Any

from .models import Finding, Severity, QuantumRisk
from . import rules

try:
    import esprima
except ImportError:  # pragma: no cover
    esprima = None


def _walk(node, kind=None):
    """Recursively yield every dict node in the tree (optionally filtered by
    node['type'] == kind). esprima's .toDict() output is plain dict/list, so a
    generic structural walk is enough - no esprima-specific visitor needed."""
    if isinstance(node, dict):
        if kind is None or node.get("type") == kind:
            yield node
        for v in node.values():
            yield from _walk(v, kind)
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item, kind)


def _callee_name(callee: dict) -> str:
    """Dotted name for a MemberExpression/Identifier callee, e.g. 'crypto.createHash'."""
    parts = []
    node = callee
    while isinstance(node, dict) and node.get("type") == "MemberExpression":
        prop = node.get("property", {})
        parts.append(prop.get("name") or prop.get("value") or "?")
        node = node.get("object")
    if isinstance(node, dict) and node.get("type") == "Identifier":
        parts.append(node["name"])
    return ".".join(str(p) for p in reversed(parts))


def _arg_literal(node) -> Optional[Any]:
    if isinstance(node, dict) and node.get("type") == "Literal":
        return node.get("value")
    return None


def _loc(node):
    loc = node.get("loc", {}).get("start", {})
    return loc.get("line", 0), loc.get("column", 0)


def _is_secret_name(name: str) -> bool:
    n = (name or "").lower()
    return any(hint in n for hint in rules.SECRET_NAME_HINTS)


def _annotate_func_scope(tree) -> Dict[int, Optional[str]]:
    """Map id(node) -> nearest enclosing function's name (or None at module
    scope). Used as a fallback context signal when a security-sensitive call
    isn't a simple `varName = Math.random()...` assignment - e.g. it's used
    directly in a `return` statement, like `return Math.random().toString(36)`
    inside `function generateResetToken() {...}`, or a comparison whose
    parameter names carry no signal but the function itself is named
    `verifyApiKey(provided, expected)`."""
    scope_map: Dict[int, Optional[str]] = {}

    def rec(node, stack, name_hint=None):
        if isinstance(node, dict):
            t = node.get("type")
            name = name_hint
            if t in ("FunctionDeclaration", "FunctionExpression"):
                ident = node.get("id")
                if isinstance(ident, dict) and ident.get("name"):
                    name = ident["name"]
            is_func = t in ("FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression")
            scope_map[id(node)] = stack[-1] if stack else None
            new_stack = stack + [name] if is_func else stack

            next_hint = None
            if t == "VariableDeclarator":
                ident = node.get("id")
                if isinstance(ident, dict) and ident.get("name"):
                    next_hint = ident["name"]

            for k, v in node.items():
                rec(v, new_stack, next_hint if k == "init" else None)
        elif isinstance(node, list):
            for item in node:
                rec(item, stack, name_hint)

    rec(tree, [])
    return scope_map


class _Assigns:
    """Whole-file, last-write-wins variable table: name -> init node. Same
    lightweight heuristic as the Python analyzer's resolver."""

    def __init__(self, tree):
        self.table: Dict[str, dict] = {}
        for decl in _walk(tree, "VariableDeclarator"):
            ident = decl.get("id", {})
            if ident.get("type") == "Identifier" and decl.get("init") is not None:
                self.table[ident["name"]] = decl["init"]
        for assign in _walk(tree, "AssignmentExpression"):
            left = assign.get("left", {})
            if left.get("type") == "Identifier":
                self.table[left["name"]] = assign.get("right")

    def resolve(self, node, depth=0):
        if depth > 5 or node is None:
            return node
        if isinstance(node, dict) and node.get("type") == "Identifier" and node["name"] in self.table:
            return self.resolve(self.table[node["name"]], depth + 1)
        return node


def _is_dynamic_random_source(node) -> bool:
    if isinstance(node, dict) and node.get("type") == "CallExpression":
        name = _callee_name(node.get("callee", {}))
        return name in ("crypto.randomBytes", "randomBytes", "crypto.randomFillSync", "randomFillSync")
    return False


def _is_confirmed_static(node) -> bool:
    """True only when the IV/nonce provably resolves to a fixed literal - a
    Buffer.from(<string literal>) or a bare string/number Literal. An
    *unresolved* Identifier (e.g. a function parameter we can't trace back
    through this file, like `iv` in `function encrypt(data, key, iv)`) is
    unknown, not static - flagging it would be a false positive, not a
    genuine finding."""
    if not isinstance(node, dict):
        return False
    if node.get("type") == "Literal":
        return True
    if node.get("type") == "CallExpression" and _callee_name(node.get("callee", {})) == "Buffer.from":
        first = node.get("arguments", [{}])[0]
        return isinstance(first, dict) and first.get("type") == "Literal"
    return False


_MODE_FROM_ALGO = {
    # crypto.createCipheriv('aes-256-cbc', ...) -> algo 'aes', bits 256, mode 'cbc'
}


def _parse_openssl_algo(algo_str: str):
    """'aes-256-cbc' -> ('AES', 256, 'CBC'); 'aes-128-gcm' -> ('AES', 128, 'GCM')."""
    if not algo_str:
        return None, None, None
    parts = algo_str.split("-")
    if parts[0].lower() != "aes" or len(parts) < 3:
        return parts[0].upper(), None, (parts[-1].upper() if len(parts) > 1 else None)
    try:
        bits = int(parts[1])
    except ValueError:
        bits = None
    mode = parts[2].upper()
    return "AES", bits, mode


class JSAnalyzer:
    rule_source = "js-esprima-ast"

    def analyze(self, file_path: str, source: str) -> List[Finding]:
        if esprima is None:
            raise RuntimeError("The 'esprima' package is required for JS analysis. pip install esprima")
        findings: List[Finding] = []
        try:
            tree = esprima.parseScript(source, options={"loc": True, "range": True, "tolerant": True}).toDict()
        except Exception:
            try:
                tree = esprima.parseModule(source, options={"loc": True, "range": True, "tolerant": True}).toDict()
            except Exception:
                return findings

        assigns = _Assigns(tree)
        scope_map = _annotate_func_scope(tree)
        source_lines = source.splitlines()

        for call in _walk(tree, "CallExpression"):
            findings.extend(self._check_call(call, file_path, assigns, source_lines, scope_map))

        for binexpr in _walk(tree, "BinaryExpression"):
            f = self._check_binary(binexpr, file_path, source_lines, scope_map)
            if f:
                findings.append(f)

        return findings

    # -- Call-expression checks --------------------------------------------------
    def _check_call(self, node, file_path, assigns, source_lines, scope_map) -> List[Finding]:
        out: List[Finding] = []
        fname = _callee_name(node.get("callee", {}))
        args = node.get("arguments", [])
        line, col = _loc(node)
        snippet = _line_src(source_lines, line)

        # -- crypto.createHash('md5'|'sha1'|...) ---------------------------------
        if fname in ("crypto.createHash",):
            algo = _arg_literal(args[0]) if args else None
            algo = (algo or "").lower()
            if algo in rules.HASH_ALGOS:
                profile = dict(rules.HASH_ALGOS[algo])
                is_password_ctx = "password" in snippet.lower() or "pwd" in snippet.lower() or "passwd" in snippet.lower()
                rule_id = f"{algo}-weak-password-hash" if is_password_ctx else f"{algo}-hashing"
                out.append(self._mk(file_path, line, col, rule_id,
                                      f"{profile['algorithm']} {'weak-password-hash' if is_password_ctx else 'hashing'}",
                                      "hash", profile, snippet, specificity=3 if is_password_ctx else 2))
            return out

        # -- crypto.createCipheriv(algo, key, iv) / createDecipheriv -------------
        if fname in ("crypto.createCipheriv", "crypto.createDecipheriv"):
            direction = "encryption" if fname.endswith("Cipheriv") else "decryption"
            out.extend(self._check_cipheriv(node, args, assigns, file_path, line, col, snippet, direction))
            return out

        # -- crypto.generateKeyPairSync('rsa', {modulusLength: X}) ----------------
        if fname in ("crypto.generateKeyPairSync", "crypto.generateKeyPair"):
            kind = _arg_literal(args[0]) if args else None
            if kind == "rsa":
                bits = None
                if len(args) >= 2:
                    opts = assigns.resolve(args[1])
                    if isinstance(opts, dict) and opts.get("type") == "ObjectExpression":
                        for prop in opts.get("properties", []):
                            key = prop.get("key", {})
                            if key.get("name") == "modulusLength" or key.get("value") == "modulusLength":
                                bits = _arg_literal(prop.get("value"))
                profile = rules.rsa_profile(bits)
                out.append(self._mk(file_path, line, col, "rsa-key-generation", "RSA key_generation",
                                      "asymmetric", profile, snippet, specificity=2, tags=profile.get("tags", [])))
            elif kind in ("ec",):
                curve = None
                if len(args) >= 2:
                    opts = assigns.resolve(args[1])
                    if isinstance(opts, dict) and opts.get("type") == "ObjectExpression":
                        for prop in opts.get("properties", []):
                            key = prop.get("key", {})
                            if key.get("name") == "namedCurve":
                                curve = _arg_literal(prop.get("value"))
                profile = rules.ecc_profile(curve or "unknown-curve", purpose="signature")
                out.append(self._mk(file_path, line, col, "ecdsa-key-generation",
                                      f"ECDSA key_generation ({curve or 'unknown-curve'})", "asymmetric",
                                      profile, snippet, specificity=2))
            return out

        # -- Math.random() feeding a security-sensitive value ---------------------
        if fname == "Math.random":
            func_name = scope_map.get(id(node))
            out.extend(self._check_rng_context(node, file_path, line, col, snippet, func_name))
            return out

        return out

    def _check_cipheriv(self, node, args, assigns, file_path, line, col, snippet, direction) -> List[Finding]:
        out = []
        algo_str = _arg_literal(args[0]) if args else None
        algo, bits, mode = _parse_openssl_algo(algo_str or "")

        key_node = assigns.resolve(args[1]) if len(args) >= 2 else None
        iv_node = assigns.resolve(args[2]) if len(args) >= 3 else None

        key_hardcoded = False
        if isinstance(key_node, dict):
            if key_node.get("type") == "Literal" and isinstance(key_node.get("value"), str):
                key_hardcoded = True
            elif key_node.get("type") == "CallExpression" and _callee_name(key_node.get("callee", {})) in (
                "Buffer.from",
            ):
                first = key_node.get("arguments", [{}])[0]
                if isinstance(first, dict) and first.get("type") == "Literal":
                    key_hardcoded = True

        iv_static = iv_node is not None and _is_confirmed_static(iv_node)

        if algo != "AES":
            # Non-AES ciphers via OpenSSL name string, e.g. 'des-ede3-cbc'
            if algo in ("DES", "DES-EDE3", "DES3", "RC4", "ARC4", "3DES", "RC2", "BF", "BLOWFISH"):
                profile = rules.symmetric_profile(algo, "")
                out.append(self._mk(file_path, line, col, f"{algo.lower()}-deprecated-cipher",
                                      f"{algo} deprecated-cipher", "symmetric-cipher", profile, snippet,
                                      specificity=3))
            return out

        profile = rules.symmetric_profile("AES", mode or "", bits)
        red_flags = []
        if key_hardcoded:
            red_flags.append("hardcoded-key")
        if iv_node is not None and iv_static:
            red_flags.append("static-iv")

        if key_hardcoded:
            hp = dict(rules.HARDCODED_KEY)
            out.append(self._mk(file_path, line, col, "aes-hardcoded-key",
                                  f"AES-{bits}-{mode or '?'} hardcoded-key", "symmetric-cipher", hp, snippet,
                                  specificity=4))

        if iv_node is not None and iv_static and mode in ("CBC", "CTR", "CFB", "OFB", "GCM"):
            ivp = dict(rules.STATIC_IV)
            out.append(self._mk(file_path, line, col, "aes-static-iv-reuse",
                                  f"AES-{bits}-{mode} static-iv-reuse", "symmetric-cipher", ivp, snippet,
                                  specificity=4))

        if mode == "ECB":
            out.append(self._mk(file_path, line, col, "aes-ecb-mode", f"AES-{bits}-ECB", "symmetric-cipher",
                                  profile, snippet, specificity=3))
        elif mode in ("CBC", "CTR", "CFB", "OFB"):
            missing_aead = dict(profile)
            if red_flags:
                missing_aead["severity"] = Severity.CRITICAL
                missing_aead["recommendation"] = (
                    f"Combined with {', '.join(red_flags)}, lack of authenticated encryption makes "
                    "this call exploitable. " + profile["recommendation"]
                )
            out.append(self._mk(file_path, line, col, "aes-missing-aead",
                                  f"AES-{bits}-{mode} missing-aead", "symmetric-cipher", missing_aead, snippet,
                                  specificity=2, generic=(not red_flags)))
        elif mode in ("GCM", "CCM"):
            out.append(self._mk(file_path, line, col, "aes-aead-mode", f"AES-{bits}-{mode}",
                                  "symmetric-cipher", profile, snippet, specificity=1, generic=True))
        else:
            out.append(self._mk(file_path, line, col, "aes-encryption", f"AES {direction}",
                                  "symmetric-cipher", profile, snippet, specificity=1, generic=True))
        return out

    def _check_rng_context(self, node, file_path, line, col, snippet, func_name=None) -> List[Finding]:
        target = None
        if "=" in snippet and "==" not in snippet.split("=", 1)[0]:
            candidate = snippet.split("=", 1)[0].strip()
            candidate = candidate.replace("const ", "").replace("let ", "").replace("var ", "").strip()
            if candidate.isidentifier():
                target = candidate

        is_secret_context = bool(target and _is_secret_name(target))
        # Fall back to the enclosing function's name for calls that aren't a
        # simple assignment - e.g. `return Math.random().toString(36)...`
        # inside `function generateResetToken() {...}`.
        if not is_secret_context and func_name and _is_secret_name(func_name):
            is_secret_context = True

        if is_secret_context:
            profile = dict(rules.INSECURE_RNG)
            return [self._mk(file_path, line, col, "insecure-rng", "Math.random insecure-rng", "rng",
                               profile, snippet, specificity=3)]
        return []

    def _check_binary(self, node, file_path, source_lines, scope_map=None) -> Optional[Finding]:
        if node.get("operator") not in ("===", "==", "!==", "!="):
            return None
        left, right = node.get("left", {}), node.get("right", {})

        def name_of(n):
            if not isinstance(n, dict):
                return ""
            if n.get("type") == "Identifier":
                return n.get("name", "")
            if n.get("type") == "MemberExpression":
                return (n.get("property") or {}).get("name", "")
            return ""

        def is_trivial(n):
            return isinstance(n, dict) and n.get("type") == "Literal" and n.get("value") in ("", None, 0)

        # Non-secret structural properties (buffer/string length checks etc.)
        # are a routine, *safe* precondition before a real constant-time
        # compare (crypto.timingSafeEqual requires equal-length inputs) - not
        # a secret comparison themselves. Skip these outright so the
        # function-name fallback below can't turn `a.length !== b.length`
        # inside a `verify...Key(...)`-named function into a false positive.
        NON_SECRET_PROPS = {"length", "len", "size", "count", "index"}
        if name_of(left).lower() in NON_SECRET_PROPS or name_of(right).lower() in NON_SECRET_PROPS:
            return None

        candidate = None
        for side in (left, right):
            nm = name_of(side)
            if nm and _is_secret_name(nm):
                candidate = nm
                break

        # Fall back to the enclosing function's name: param names like
        # `provided`/`expected` in `function verifyApiKey(provided, expected)`
        # carry no signal on their own, but the function name does.
        if not candidate and scope_map is not None:
            func_name = scope_map.get(id(node))
            if func_name and _is_secret_name(func_name):
                candidate = func_name

        if not candidate or is_trivial(left) or is_trivial(right):
            return None

        line, col = _loc(node)
        snippet = _line_src(source_lines, line)
        profile = dict(rules.TIMING_UNSAFE_COMPARE)
        return self._mk(file_path, line, col, "timing-unsafe-compare", "Non-constant-time secret comparison",
                          "comparison", profile, snippet, specificity=3)

    @staticmethod
    def _mk(file_path, line, col, rule_id, rule_name, category, profile, snippet, specificity=1,
            generic=False, tags=None) -> Finding:
        return Finding(
            file=file_path, line=line, column=col, language="javascript", rule_id=rule_id,
            rule_name=rule_name, category=category, algorithm=profile["algorithm"],
            severity=profile["severity"], quantum_risk=profile["quantum_risk"],
            message=f"{rule_name} at line {line}.", recommendation=profile["recommendation"],
            code_snippet=snippet, specificity=specificity, generic=generic, tags=tags or [],
        )


def _line_src(lines, lineno):
    try:
        return lines[lineno - 1].strip()
    except IndexError:
        return ""
