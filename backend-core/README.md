# CryptoScan (ECDAT) — Backend Core

Owns: Database schema, Authentication, Repository upload, Scanner dispatch, CBOM generation, and Blockchain anchoring/verification.

## Setup

```bash
npm install
cp .env.example .env       # fill in real DATABASE_URL and JWT_SECRET
npm run prisma:migrate     # creates tables from prisma/schema.prisma
npm run dev                # starts on http://localhost:3000
```

Windows note: if `DATABASE_URL` parsing fails, wrap the whole string in quotes
and URL-encode special characters in the password.

## Endpoints implemented here

| Method | Path                  | Auth | Notes |
|--------|------------------------|------|-------|
| POST   | /auth/signup           | No   | creates new user |
| POST   | /auth/login             | No   | returns JWT |
| POST   | /repos/upload           | Yes  | multipart, field name `repo`, .zip only |
| POST   | /scan/:repoId            | Yes  | creates Scan row, triggers scanner engine |
| GET    | /scan/:scanId/findings   | Yes  | reads real DB findings rows |
| GET    | /scan/:scanId/cbom       | Yes  | builds CycloneDX-compliant CBOM |
| POST   | /scan/:scanId/anchor     | Yes  | Merkle root commitment + RFC 3161 timestamp + Sepolia anchor |
| GET    | /scan/:scanId/verify     | Yes  | verifies current DB Merkle root against live Sepolia contract |

## Module Integration

- **Scanner Engine:** integrated into `src/routes/scans.js` via `python scanner/cli.py`.
- **CBOM Service:** integrated via `buildCbom()` in `src/services/cbomGenerator.js`.
- **Blockchain Module:** integrated via `anchorScan()` and `verifyScan()` in `src/routes/scans.js`.
- **Integrity Service:** provides Merkle trees, RFC 3161 timestamping, and KMS signing.


## Production Integrity Standard

No `mock`, `dummy`, `fake_tx_hash`, or `TODO: replace with real later` ships
to the demo. If something can't be done for real yet, scope it down — don't
fake the output.
