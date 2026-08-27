# CryptoScan (ECDAT) — Backend Core

Owns: DB schema, Auth, Repo upload, Scan trigger stub.

## Setup

```bash
npm install
cp .env.example .env       # fill in real DATABASE_URL and JWT_SECRET
npm run prisma:migrate     # creates tables from prisma/schema.prisma
npm run dev                # starts on http://localhost:5000
```

Windows note: if `DATABASE_URL` parsing fails, wrap the whole string in quotes
and URL-encode special characters in the password.

## Endpoints implemented here

| Method | Path                  | Auth | Notes |
|--------|------------------------|------|-------|
| POST   | /auth/signup           | No   | not in original contract, but login needs users to exist |
| POST   | /auth/login             | No   | returns JWT |
| POST   | /repos/upload           | Yes  | multipart, field name `repo`, .zip only |
| POST   | /scan/:repoId            | Yes  | creates Scan row, **Scanner team hooks in here** |
| GET    | /scan/:scanId/findings   | Yes  | reads real DB rows |

## Full API contract (for reference — other modules build against this)

```
POST /auth/login
POST /repos/upload
POST /scan/:repoId              -> triggers scanner
GET  /scan/:scanId/findings
GET  /scan/:scanId/cbom
POST /scan/:scanId/anchor       -> real hash + real sign + real blockchain tx
GET  /scan/:scanId/verify       -> reads real on-chain hash, compares
```

## For other modules

- **Scanner (Person 2):** hook your scan logic into `src/routes/scans.js`
  where marked `--- Scanner Engine hook ---`. Write results into the
  `Finding` table via `prisma.finding.createMany(...)`.
- **CBOM (Person 3):** add a `src/routes/cbom.js` with
  `GET /scan/:scanId/cbom`, write into the `Cbom` table. Schema already has
  the `Cbom` model — don't fork it, ask if you need fields added.
- **Blockchain (Person 4):** add `src/routes/anchor.js` with
  `POST /scan/:scanId/anchor`, write into the `Anchor` model.
- **Verify (Person 5):** add `GET /scan/:scanId/verify` reading from `Anchor`
  + live chain state.
- **Frontend (Person 6):** the JSON shapes above are your contract. Mock them
  exactly, swap to real fetch calls once each endpoint is live.

## Hard rule (from the team doc)

No `mock`, `dummy`, `fake_tx_hash`, or `TODO: replace with real later` ships
to the demo. If something can't be done for real yet, scope it down — don't
fake the output.
