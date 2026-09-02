# CBOM + Findings Service

Serves scanner findings and generates a standardized CycloneDX Cryptographic Bill of Materials (CBOM). Provides explainable, purpose-based post-quantum migration recommendations (e.g. ML-KEM for key exchange, ML-DSA for signatures) and transparent vulnerability scoring.

> **Architectural Note**: This directory houses the **standalone CBOM microservice & test harness** (listening on `http://localhost:4003`). In the full-stack CryptoScan deployment, these same core CBOM generation algorithms are embedded natively within `backend-core` (running on `http://localhost:3000`), allowing the platform to run monolithically without requiring an external microservice process.


## Run it

```bash
npm install
npm start          # starts on http://localhost:4003
npm run seed        # in another terminal: loads data/samples/scanner-output.sample.json into scan "demo_scan_1"
npm test             # end-to-end smoke test, no server needed — boots its own instance
```

Then:

```bash
curl http://localhost:4003/scan/demo_scan_1/findings
curl http://localhost:4003/scan/demo_scan_1/cbom
```

## Endpoints (match the API contract)

| Method | Path | Purpose |
|---|---|---|
| GET | `/scan/:scanId/findings` | Enriched scanner findings (purpose, score, migration guidance per finding) |
| GET | `/scan/:scanId/cbom` | Full CycloneDX 1.6–style CBOM (`cryptographic-asset` components) |
| POST | `/internal/scan/:scanId/ingest` | **Not in the public contract** — this is how the Scanner Engine module pushes its output in. See below. |
| GET | `/health` | Liveness check |

Unknown `scanId` → `404`.

## The input contract this module expects from Scanner Engine

`POST /internal/scan/:scanId/ingest` body:

```json
{
  "repoId": "repo_demo_1",
  "language": "python",
  "findings": [
    {
      "id": "finding_1",
      "file": "src/auth/jwt.py",
      "line": 42,
      "primitive": "RSA",
      "keySize": 2048,
      "mode": null,
      "context": {
        "functionName": "sign_jwt_token",
        "surroundingCode": "signature = private_key.sign(...)",
        "imports": ["cryptography.hazmat.primitives.asymmetric.rsa"],
        "usageType": "signature"
      }
    }
  ]
}
```

Full example: `data/samples/scanner-output.sample.json` (6 findings covering
RSA-signature, ECDH-key-exchange, weak AES, MD5-password-hashing, healthy
SHA-256, and legacy DES/ECB — one of each severity band).

**`usageType`** is the important field — it's what makes purpose detection
real instead of guessed. Send one of: `key_exchange`, `signature`,
`encryption`, `password_hashing`, `mac`, `random`, `hashing`. If the
scanner can't classify it yet, omit it — this module falls back to
keyword matching against `functionName` / `surroundingCode` / `imports`,
and if that also fails, marks purpose `unknown` and returns a
"manual review required" migration recommendation instead of guessing.

Ingestion is **additive**, so Scanner Engine can POST in batches (e.g.
per file) as it scans, rather than one giant payload at the end.

## Why purpose detection isn't a hardcoded map

The brief calls this out directly: `RSA -> ML-KEM` is wrong whenever RSA
is used for signing rather than key exchange. So the lookup is two
dimensional — `(primitive family, purpose) -> migration guidance` — in
`src/services/purposeDetection.js`, `PQC_MIGRATION_TABLE`. Example: the
sample data has RSA used for JWT signing (→ recommends **ML-DSA**) and
ECDH used for a handshake (→ recommends **ML-KEM**), and the test suite
(`test/run.js`) asserts both directions explicitly.

Purpose is resolved in priority order:
1. Scanner-declared `context.usageType` (trusted).
2. Keyword match against function name / surrounding code / imports.
3. `unknown` → migration guidance says "manual review required" rather
   than fabricating an answer.

## Why vulnerability scoring isn't random

`src/services/vulnScoring.js` computes a deterministic 0–100 score as a
weighted sum of four documented sub-scores:

| Factor | Weight | What it measures |
|---|---|---|
| Quantum vulnerability | 40% | Broken outright by Shor's algorithm (RSA/ECC/DH/DSA → 100) vs. only weakened by Grover's algorithm (AES/SHA, scored by whether the *remaining* effective strength is still adequate) |
| Key strength | 30% | Observed key/curve size vs. current NIST-recommended minimums |
| Classical deprecation | 20% | Already broken today regardless of quantum computing (MD5, SHA-1, DES, RC4, ECB mode) |
| Usage criticality | 10% | Same weak algorithm is worse protecting auth/signing than something low-stakes |

Severity bands: `critical` ≥80, `high` ≥60, `medium` ≥40, `low` ≥20, else `info`.
Every finding's `vulnerability.breakdown` in the API response shows the
four sub-scores, so a reviewer (or a demo judge) can see exactly why a
number came out the way it did instead of trusting a black box.

## CBOM output shape

CycloneDX 1.6 `cryptographic-asset` components, one per unique
`(primitive family, keySize, mode)` observed. Every file/line it occurred
at is listed under that component's `occurrences`, each carrying its own
purpose, score, and migration guidance (a signature-use and a
key-exchange-use of the same algorithm won't be silently merged into one
recommendation). `summary.severityCounts` gives a quick dashboard-ready
rollup for the frontend.

## Swapping in a real database later

Everything reads/writes through `src/data/store.js` (currently an
in-memory `Map`). Once Person 1's Postgres schema is ready, replace the
four functions in that file (`ingestFindings`, `getScan`, `hasScan`,
`listScanIds`) with real queries — no route or service code needs to
change.

## What's deliberately NOT here

- Auth / repo upload — Person 1 (Backend Core).
- Actual static/AST parsing that produces `findings[]` — Person 2
  (Scanner Engine). This module only consumes that output.
- On-chain anchoring/verification of the CBOM hash — Persons 4/5.

## File map

```
src/
  server.js                    Express app + route mounting
  routes/scan.js                GET /findings, GET /cbom, POST /internal/ingest
  services/purposeDetection.js  usageType/context -> purpose, (primitive,purpose) -> PQC guidance
  services/vulnScoring.js       4-factor deterministic 0-100 score
  services/cbomGenerator.js     combines the above into the /findings and /cbom response shapes
  services/primitiveFamily.js   normalizes scanner primitive strings (ECDSA/ECDH -> ECC, etc.)
  data/store.js                 in-memory store (swap for real DB later)
  data/seed.js                  loads the sample payload into a running server
data/samples/scanner-output.sample.json   example Scanner Engine payload, 6 findings
test/run.js                    end-to-end smoke test (boots its own server instance)
```
