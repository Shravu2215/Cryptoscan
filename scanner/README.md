# CryptoScan Engine

## CHANGELOG — 2026-08-27 detection fixes

Re-scanning the three demo repos surfaced real detection gaps (not just missing
test coverage). All of these are fixed in this build; `tests/test_scanner.py`
still passes (5/5) with no regressions:

- **DES3 mislabeled as Medium/"Quantum-Weakened" instead of Critical.**
  `rules.py`'s classical-break table checked for the string `"3DES"`, but
  pycryptodome's class is named `DES3` — the two never matched, so every
  `DES3.new(...)` call silently fell through to the generic catch-all rule.
- **Aliased imports defeated detection entirely.** `import hashlib as _hashlib`
  or `from Crypto.Cipher import ARC4 as RC4Cipher` meant the analyzer's
  string checks (`fname in ("hashlib.md5", ...)`) never matched, so MD5/SHA-1/
  RC4 calls made through an aliased import were invisible. The analyzer now
  builds an import-alias table per file and resolves every call name through
  it before rule matching.
- **RC4/Blowfish/RC2 blocked by an overly narrow outer gate**, even when not
  aliased — the dispatcher only let `AES`/`DES`/`DES3`/`Crypto`/`Cryptodome`
  through to the cipher check, so a direct `Blowfish.new(...)` call was
  dropped before the (already-correct) inner logic ever saw it.
- **The `cryptography` library's hazmat API wasn't handled at all** —
  `Cipher(algorithms.AES(key), modes.ECB())` is a different call shape than
  pycryptodome's `AES.new(...)`, so AES-ECB usage via this import style
  (and the equivalent Node `crypto.createCipheriv` variants) went undetected.
  Added a dedicated check for it, plus a new informational rule for `Fernet`.
- **Weak-RNG and timing-unsafe-compare checks only recognized a direct
  `var = random.choice(...)` assignment.** Anything used inline — e.g.
  `return "".join(random.choice(c) for _ in range(n))`, or a parameter-name
  comparison inside a function like `verifyApiKey(provided, expected)` —
  was invisible because neither side had a "secret-sounding" name. Both
  analyzers (Python + JS) now also fall back to the *enclosing function's
  name* as context, while excluding harmless structural comparisons like
  `a.length !== b.length` so that fallback doesn't introduce new false
  positives on the "already-fixed" reference files.
- **`hmac.new(key, msg, hashlib.sha1)` wasn't flagged** — the weak-hash check
  only fired when `hashlib.sha1(...)` was called directly, not when it's
  passed by reference as an HMAC digestmod.

Net effect on the three bundled demo repos: `demo-vulnerable-repo` 10 → 11
findings, `demo-vulnerable-repo-2` **3 → 14** findings, `crypto-errors-repo`
(Node) 14 → 17 findings (one prior false positive removed, several real misses
added).



A real, AST-based cryptographic-vulnerability scanner for Python and JavaScript/Node
source. No regex pattern-matching pretending to be AST, no hardcoded target-repo
logic, no mock findings — it parses whatever repo you point it at into a real
syntax tree and reports whatever it actually finds. Zero findings on a clean repo
is a correct result.

## Quick start

```bash
pip install -r requirements.txt
python3 cli.py /path/to/repo-to-scan
```

Options:
```bash
python3 cli.py /path/to/repo --json report.json      # full machine-readable report
python3 cli.py /path/to/repo --ext .py,.js            # restrict to specific extensions
python3 cli.py /path/to/repo --no-color               # plain text (CI logs)
```
Exit code is `1` if any Critical/High finding exists — safe to wire into CI.

Run the regression suite (locks in the specific bugs described below):
```bash
python3 tests/test_scanner.py
# or: python3 -m pytest tests/ -v
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

Both language analyzers import the *same* `rules.py` table, so risk tagging can't
drift between the Python path and the JS path the way it had before.

## What this fixes, relative to the earlier scanner

**1. Duplicate findings on one call site.**
A specific rule (e.g. `aes-hardcoded-key`, `md5-weak-password-hash`) and a generic
catch-all (`aes-encryption`, `md5-hashing`) used to both fire on the same call.
Every finding now carries a `specificity`/`generic` flag; `dedup.py` groups by
call site and drops any generic finding once a specific one exists there. Exact
`(file, line, rule_id)` duplicates are also collapsed to one.

Note: two findings on the *same line* are still correct output when they're two
genuinely distinct, independently-fixable vulnerabilities — e.g. a hardcoded key
**and** missing AEAD on one `createCipheriv` call are two different CWEs with two
different fixes. What's suppressed is redundant *restatement* of the same issue
under a different rule name, not distinct real issues that happen to share a line.

**2. Fixed files flagged as severely as the broken version.**
`missing-aead` (non-AEAD cipher mode, e.g. plain CBC) is Low/Informational by
default now, and only escalates to Critical when paired with a second concrete
red flag on the *same* call (hardcoded key or a provably-static IV/nonce). A
correctly-fixed file that generates a fresh IV and loads its key from an env var
no longer reads as equally broken as the vulnerable version. The IV-static check
was also tightened: an unresolved variable (e.g. an `iv` function parameter this
single-file static pass can't trace) is treated as *unknown*, not *static* — the
earlier heuristic's blind spot was flagging safe, externally-supplied IVs as
static reuse.

**3. Missing rule: timing-unsafe secret comparison.**
New rule (CWE-208): a `==`/`===` (or `!=`/`!==`) comparison where either operand's
name matches a secret-like hint (`token`, `password`, `signature`, `hash`, `hmac`,
...) is flagged, recommending `hmac.compare_digest` / `crypto.timingSafeEqual`.
Skips trivial comparisons against `""`/`None`/`0` to cut down on presence-check
false positives.

**4. RSA key-size findings split across two disconnected rules.**
Now one rule, `rsa-key-generation`, scales severity by modulus length
(<1024 → Critical, 1024–2047 → High, ≥2048 → Medium) and **always** tags
`quantum_risk = Quantum-Broken` — RSA is broken by Shor's algorithm at any key
size, so it never reads as "Safe." Key size is purely a classical-strength
signal now, carried as a `tags: ["undersized-classical-key"]` annotation instead
of a second competing finding.

**5. JS/Python risk-tagging drift.**
Both analyzers now read from the one `rules.py` table instead of keeping their
own copies, so a `Classical Risk` tag (weak for reasons unrelated to quantum
computers — MD5, ECB, hardcoded keys, weak RNG, timing) can't show up correctly
in the Python path and silently fall back to `Safe` in the JS path.

## Detected today

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

## Known limitations (real ones, not glossed over)

- Variable resolution is a single-pass, whole-file, last-write-wins heuristic —
  it will not follow values across function calls, imports, or conditional
  branches. This is the same tradeoff every lightweight SAST tool makes; it's
  why "unresolved" is treated as *unknown* rather than *safe* or *unsafe*
  (see fix #2 above) instead of guessing.
- No cross-file/cross-module data flow. A key loaded in `config.py` and passed
  into `cipher.py` is not traced across the file boundary.
- The "password hashing" and "insecure RNG for a secret" heuristics are
  name-based (checking for `password`/`key`/`token`/... in the surrounding
  line or target variable name). Rename your variables to defeat this like you
  could defeat any static analyzer's heuristics — it's a signal, not a proof.
- JS parsing uses `esprima`, which understands ES2017-era syntax. Very recent
  syntax (e.g. some newer class field proposals) may fail to parse; the CLI
  skips files it can't parse rather than crashing the whole scan.
