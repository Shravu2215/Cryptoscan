# Blockchain / Smart Contract Module

Anchors a scan's content hash on-chain. Real hash, real ECDSA signature,
real transaction — no dummy tx id, no fake signature, ever.

## Setup

```bash
npm install
cp .env.example .env
```

### Local (dev / rehearsal)

```bash
npm run node               # terminal 1: starts local Hardhat chain
npm run deploy:local        # terminal 2: deploys CryptoAnchor
```

`RPC_URL` in `.env` can stay as the default `http://127.0.0.1:8545`.
Copy one of the private keys printed by `npm run node` into `PRIVATE_KEY`.

### Sepolia (real demo)

1. Get a free RPC URL from Alchemy or Infura, put it in `SEPOLIA_RPC_URL`.
2. Create a throwaway wallet, fund it from a Sepolia faucet, put its
   private key in `PRIVATE_KEY`.
3. `npm run deploy:sepolia`

Either way, deploy writes `deployed-contract.json` (address + network) —
`anchor.js` and `verify.js` read from it automatically.

## Anchor a scan

```bash
node scripts/anchor.js <scanId> <path-to-content.json>
```

Does, in order:
1. Canonicalizes CBOM components and computes a deterministic Merkle root (via merkle.js)
2. Obtains an RFC 3161 trusted timestamp for the Merkle root (via timestamp.js)
3. Signs the Merkle root content commitment with the KMS-managed key (via kms.js)
4. Submits `CryptoAnchor.anchorScan(scanId, contentHash)` on-chain
5. Prints `{ contentHash, signature, txHash, network, anchoredBy, blockNumber, merkleRoot, timestamp }`


This is exactly what `POST /scan/:scanId/anchor` (module 4/5) should write
into the `Anchor` table — call `anchorScan()` from `scripts/anchor.js`
directly instead of shelling out to the CLI.

## Verify a scan

```bash
node scripts/verify.js <scanId> <path-to-current-content.json> [signature]
```

Reads the on-chain record, recomputes the hash from current content,
compares the two, and (if a signature is passed) confirms it recovers to
the anchoring wallet's address. Exit code `0` = verified, `2` = mismatch.
This is what backs `GET /scan/:scanId/verify` (module 5).

## Contract

`contracts/CryptoAnchor.sol` — one function that matters: `anchorScan`.
It's a write-once mapping (`scanId -> {contentHash, anchoredBy, timestamp}`);
re-anchoring the same `scanId` reverts by design, since an anchor is a
one-time commitment. Re-run scans get a new `scanId`.

## Tests

```bash
npm test
```

## Handoff to Backend Core / Verify module

- `Anchor.contentHash`, `Anchor.txHash`, `Anchor.signature` in the Prisma
  schema map 1:1 to this module's output — no translation needed.
- `scanId` (a UUID string from Postgres/SQLite) gets hashed with
  `keccak256` to fit Solidity's `bytes32` key — see `scanIdToBytes32()`
  in both `anchor.js` and `verify.js`. Use the same helper on both sides
  so lookups match.
