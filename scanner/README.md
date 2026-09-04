# CryptoScan Engine

A real, AST-based cryptographic-vulnerability scanner for Python and JavaScript/Node source. No regex pattern-matching pretending to be AST, no hardcoded target-repo logic, no mock findings — it parses whatever repo you point it at into a real syntax tree and reports whatever it actually finds. Zero findings on a clean repo is a correct result.

## Quick start

```bash
pip install -r requirements.txt

# Run scanner (on Windows):
python cli.py /path/to/repo-to-scan
# Run scanner (on Linux/macOS):
python3 cli.py /path/to/repo-to-scan
```

Options:
```bash
python cli.py /path/to/repo --json report.json      # full machine-readable report
python cli.py /path/to/repo --ext .py,.js            # restrict to specific extensions
python cli.py /path/to/repo --no-color               # plain text (CI logs)
```
Exit code is `1` if any Critical/High finding exists — safe to wire into CI.

Run the regression suite:
```bash
# On Windows:
python tests/test_scanner.py
# On Linux/macOS:
python3 tests/test_scanner.py
```

## Architecture

```
scanner/
  models.py          Finding / Severity / QuantumRisk — shared shape both analyzers emit
  rules.py            SINGLE shared table: algorithm -> (severity, quantum-risk tier, fix advice)
  python_analyzer.py  Walks Python's real `ast` module tree (hashlib, pycryptodome, `cryptography`, random, ==)
  js_analyzer.py       Walks a real esprima AST for JS/Node (crypto module, Math.random, ===)
  dedup.py             Collapses exact duplicates + suppresses generic catch-alls
  report.py            Console + JSON output
cli.py                 Walks the target path, dispatches per-file by extension, dedups, reports
tests/
  fixtures/            8 vulnerable/fixed pairs used to lock in behavior
  test_scanner.py       Automated assertions against those fixtures
```

Both language analyzers import the *same* `rules.py` table, so risk tagging can't drift between the Python path and the JS path the way it had before.

## Rule Tightening & Deduplication Design

**1. Duplicate findings on one call site.**
A specific rule (e.g. `aes-hardcoded-key`, `md5-weak-password-hash`) and a generic catch-all (`aes-encryption`, `md5-hashing`) used to both fire on the same call. Every finding now carries a `specificity`/`generic` flag; `dedup.py` groups by call site and drops any generic finding once a specific one exists there. Exact `(file, line, rule_id)` duplicates are also collapsed to one.

Note: two findings on the *same line* are still correct output when they're two genuinely distinct, independently-fixable vulnerabilities — e.g. a hardcoded key **and** missing AEAD on one `createCipheriv` call are two different CWEs with two different fixes. What's suppressed is redundant *restatement* of the same issue under a different rule name, not distinct real issues that happen to share a line.

**2. Fixed files flagged as severely as the broken version.**
`missing-aead` (non-AEAD cipher mode, e.g. plain CBC) is Low/Informational by default now, and only escalates to Critical when paired with a second concrete red flag on the *same* call (hardcoded key or a provably-static IV/nonce). A correctly-fixed file that generates a fresh IV and loads its key from an env var no longer reads as equally broken as the vulnerable version. The IV-static check was also tightened: an unresolved variable (e.g. an `iv` function parameter this single-file static pass can't trace) is treated as *unknown*, not *static* — the earlier heuristic's blind spot was flagging safe, externally-supplied IVs as static reuse.

**3. Timing-unsafe secret comparison.**
Rule (CWE-208): a `==`/`===` (or `!=`/`!==`) comparison where either operand's name matches a secret-like hint (`token`, `password`, `signature`, `hash`, `hmac`, ...) is flagged, recommending `hmac.compare_digest` / `crypto.timingSafeEqual`. Skips trivial comparisons against `""`/`None`/`0` to cut down on presence-check false positives.

**4. RSA key-size findings consolidated.**
The `rsa-key-generation` rule scales severity by modulus length (<1024 → Critical, 1024–2047 → High, ≥2048 → Medium) and **always** tags `quantum_risk = Quantum-Broken` — RSA is broken by Shor's algorithm at any key size, so it never reads as "Safe." Key size is purely a classical-strength signal now, carried as a `tags: ["undersized-classical-key"]` annotation instead of a second competing finding.

**5. JS/Python risk-tagging alignment.**
Both analyzers read from the single `rules.py` table instead of keeping separate copies, ensuring that a `Classical Risk` tag (weak for reasons unrelated to quantum computers — MD5, ECB, hardcoded keys, weak RNG, timing) cannot show up in the Python path and silently fall back to `Safe` in the JS path.

## Detected Today

| Category | Python source | JS/Node source |
|---|---|---|
| Weak hash | `hashlib.md5/sha1` (+ password-hash context) | `crypto.createHash('md5'/'sha1')` |
| Weak/legacy cipher | `Crypto.Cipher.DES/DES3/RC2/RC4` | `createCipheriv('des...'/'rc4...')` |
| ECB mode | `AES.new(key, AES.MODE_ECB)` | `createCipheriv('aes-*-ecb', ...)` |
| Hardcoded key | literal key argument to a cipher constructor | same |
| Static/reused IV | literal IV/nonce argument (not a traced RNG call) | same |
| Missing AEAD | non-GCM/CCM AES mode | same |
| Insecure RNG for secrets | `random.random/randint/...` assigned to a secret-named variable | `Math.random()` assigned to a secret-named variable |
| Undersized/any RSA | `RSA.generate(bits)`, `rsa.generate_private_key(key_size=...)` | `crypto.generateKeyPairSync('rsa', {modulusLength})` |
| EC key generation (labeled correctly, not generic "ECC") | `ec.generate_private_key(ec.SECPxxx())` | `crypto.generateKeyPairSync('ec', {namedCurve})` |
| Timing-unsafe secret comparison | `==`/`!=` on secret-named operands | `===`/`!==` on secret-named operands |

## Known Limitations

- Variable resolution is a single-pass, whole-file, last-write-wins heuristic — it will not follow values across function calls, imports, or conditional branches. This is the same tradeoff every lightweight SAST tool makes; unresolved variables are treated as *unknown* rather than guessing.
- No cross-file/cross-module data flow. A key loaded in `config.py` and passed into `cipher.py` is not traced across the file boundary.
- The "password hashing" and "insecure RNG for a secret" heuristics are name-based (checking for `password`/`key`/`token`/... in the surrounding line or target variable name).
- JS parsing uses `esprima`, which understands ES2017-era syntax. Very recent syntax (e.g. some newer class field proposals) may fail to parse; the CLI skips unparseable files rather than crashing the scan.

---

## Historical Notes: Detection Evolution & Fixes

During validation across reference repositories, key detection gaps were resolved to ensure robust AST parsing without regressions (`tests/test_scanner.py` passes 5/5):

- **DES3 classification:** `rules.py`'s classical-break table checks for pycryptodome's `DES3` class name, correctly escalating to Critical.
- **Aliased imports:** Resolves `import hashlib as _hashlib` and `from Crypto.Cipher import ARC4 as RC4Cipher` through a per-file alias map before rule matching.
- **Cipher dispatcher gating:** Broadened dispatch to avoid dropping `Blowfish`, `RC2`, and `RC4`.
- **Cryptography hazmat API:** Handles `Cipher(algorithms.AES(key), modes.ECB())` alongside pycryptodome's `AES.new(...)`, plus informational coverage for `Fernet`.
- **Inline context resolution:** Weak-RNG and timing-unsafe checks fall back to enclosing function names (e.g., `verifyApiKey(provided, expected)`), while excluding structural property checks (`length`, `size`).
- **HMAC digestmod references:** Correctly flags `hmac.new(key, msg, hashlib.sha1)` when passed by reference.
