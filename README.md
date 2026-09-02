# CryptoScan (ECDAT) — Enterprise Cryptographic Discovery & Assurance Tool

CryptoScan is an end-to-end cryptographic discovery, vulnerability remediation, and on-chain tamper-evidence assurance platform. It scans source code repositories for cryptographic assets (classical and post-quantum), detects vulnerabilities, generates standard CycloneDX Cryptographic Bill of Materials (CBOM), and anchors cryptographic audit proofs immutably to the Ethereum Sepolia blockchain with RFC 3161 trusted timestamps and NIST FIPS 204 post-quantum hybrid signatures.

---

## 🏗️ Project Architecture & Major Modules

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                             Frontend (UI/Web)                              │
│         Dashboard • Repositories • Scan • Findings • CBOM • Verification    │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ HTTP / REST
┌──────────────────────────────────────▼──────────────────────────────────────┐
│                         Backend Core (Express + Prisma)                     │
│        Auth • Repo Management • Scan Execution • Findings Persistence        │
└──────────┬───────────────────────────┬───────────────────────────┬──────────┘
           │                           │                           │
┌──────────▼──────────┐     ┌──────────▼──────────┐     ┌──────────▼──────────┐
│   Scanner Engine    │     │    CBOM Service     │     │  Integrity Service  │
│ Python AST Analysis │     │ CycloneDX CBOM Gen  │     │ Merkle Tree • KMS   │
│  Classical & PQC    │     │ Purpose Detection   │     │ RFC 3161 Timestamp  │
│ Vulnerability Rules │     │ PQC Recommendations │     │ ML-DSA-65 Hybrid Sig│
└─────────────────────┘     └─────────────────────┘     └──────────┬──────────┘
                                                                   │
                                                        ┌──────────▼──────────┐
                                                        │  Blockchain Module  │
                                                        │ CryptoAnchor.sol    │
                                                        │  Ethereum Sepolia   │
                                                        └─────────────────────┘
```

### Module Overview

1. **`backend-core/`**: Express.js REST API, SQLite database via Prisma ORM, JWT authentication, multipart repository uploads, and orchestration of scanning and verification.
2. **`scanner/`**: Python-based AST analyzer for Python (`python_analyzer.py`) and JavaScript (`js_analyzer.py`) detecting hardcoded keys, broken primitives (MD5, DES, RSA-1024), insecure RNGs, and quantum-vulnerable cryptography.
3. **`cbom-service/`**: Cryptographic Bill of Materials generator adhering to the CycloneDX standard, featuring purpose-based PQC transition recommendations (e.g. ML-KEM for key exchange, ML-DSA for digital signatures).
4. **`integrity-service/`**: Enterprise cryptographic integrity layer providing:
   - **Deterministic Merkle Trees** (`merkle.js`): Component-level leaf hashing, canonical key sorting, and independent Merkle proof verification.
   - **KMS Key Management** (`kms.js`): Redacted, secure key representations and life-cycle management.
   - **RFC 3161 Trusted Timestamping** (`timestamp.js`): Live TSA integration (DigiCert Trusted G4) producing authenticatable ASN.1 DER CMS SignedData tokens.
   - **Post-Quantum Hybrid Signatures** (`hybrid-signature.js`): Dual-layer ECDSA-secp256k1 + ML-DSA-65 (NIST FIPS 204) signing.
5. **`blockchain-module/`**: Hardhat smart-contract module deploying and interacting with `CryptoAnchor.sol` on Ethereum Sepolia. Write-once, on-chain tamper evidence.
6. **`frontend/`**: Interactive dashboard, CBOM viewer, findings browser, and live on-chain verification interface.

---

## ⚡ Live Ethereum Sepolia Deployment

- **Smart Contract:** `CryptoAnchor`
- **Network:** `sepolia`
- **Contract Address:** [`0x52B9D527e47066F6Fa8B90A6E389478c447D4C89`](https://sepolia.etherscan.io/address/0x52B9D527e47066F6Fa8B90A6E389478c447D4C89)
- **Deployment Artifact:** [`blockchain-module/deployed-contract.json`](file:///c:/Users/Shravani/Downloads/Cryptoscan-main/blockchain-module/deployed-contract.json)

> [!CAUTION]
> **SECURITY WARNING:** Never commit `.env` files, private keys, or credentials to version control. All `.env` files are strictly gitignored. Real private keys must only reside in your local `.env`.

---

## 📋 Prerequisites

- **Node.js**: v18+ (tested on Node.js v24)
- **npm**: v9+
- **Python**: 3.10+ (for Python scanner engine)
- **Git**: v2.30+

---

## 🚀 Installation & Setup

### 1. Backend Core Setup
```bash
cd backend-core
npm install
cp .env.example .env
npm run prisma:migrate
```

Configure `backend-core/.env`:
```env
DATABASE_URL="file:./dev.db"
JWT_SECRET="your-secure-random-jwt-secret"
JWT_EXPIRES_IN="7d"
PORT=3000
MAX_UPLOAD_SIZE_MB=50
RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
SEPOLIA_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
PRIVATE_KEY=0x<YOUR_SEPOLIA_PRIVATE_KEY>
```

### 2. Blockchain Module Setup
```bash
cd ../blockchain-module
npm install
cp .env.example .env
```

Configure `blockchain-module/.env`:
```env
RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
SEPOLIA_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
PRIVATE_KEY=0x<YOUR_SEPOLIA_PRIVATE_KEY>
```
*(The live Sepolia contract is pre-configured in `deployed-contract.json`, so no redeployment is necessary).*

### 3. Scanner Setup
```bash
cd ../scanner
python -m venv .venv
# On Windows:
.\.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

---

## 🖥️ Running the Application

### 1. Start Backend API
```bash
cd backend-core
npm start
# Server listens on http://localhost:3000
```

### 2. Launch Frontend
Serve the `frontend/` directory using any static web server:
```bash
cd frontend
npx serve . -l 8080
# Open http://localhost:8080 in your browser
```

---

## 🔍 Cryptographic Workflows & Verification

### Performing a Scan & Generating Findings
1. User logs in via `POST /auth/login` or signs up via `POST /auth/signup`.
2. Upload source code archive (`.zip`) via `POST /repos/upload`.
3. Trigger cryptographic analysis via `POST /scan/:repoId`.
4. Retrieve detected findings via `GET /scan/:scanId/findings`.
5. Retrieve CycloneDX-compliant CBOM via `GET /scan/:scanId/cbom`.

### Merkle Integrity & Sepolia Anchoring
1. **Anchor Scan:** Call `POST /scan/:scanId/anchor`.
   - CBOM cryptographic components are canonicalized and structured into a **deterministic binary Merkle Tree**.
   - The Merkle root is stamped by an **RFC 3161 Time Stamping Authority (DigiCert)**.
   - The commitment is signed via **KMS-managed credentials** (and optionally NIST FIPS 204 ML-DSA-65).
   - An on-chain transaction writes `(scanId, contentHash)` to `CryptoAnchor.sol` on Ethereum Sepolia.
2. **On-Chain Verification:** Call `GET /scan/:scanId/verify`.
   - Reconstructs current database components into a Merkle root.
   - Queries the live Sepolia smart contract.
   - Validates that `recomputedHash === onChainHash` and ECDSA signature recovers the anchoring authority.
3. **Tamper Detection:**
   - If any finding (algorithm, severity, file, key size) is altered in the database, recomputing the Merkle root yields an off-chain hash mismatch (`onChainHash !== offChainHash`).
   - `GET /scan/:scanId/verify` returns `verified: false`, proving data tampering.

---

## 🧪 Regression Test Suites

CryptoScan includes comprehensive automated tests covering all modules:

```bash
# 1. Integrity Service (Merkle, KMS, RFC 3161 Timestamp, Hybrid Signatures)
cd integrity-service
node hybrid-signature.test.js    # 24 tests
node merkle.test.js              # 23 tests
node timestamp.test.js           # 19 tests
node kms.test.js                 # 8 tests

# 2. Blockchain Smart Contract Suite
cd ../blockchain-module
npm test                         # 5 tests

# 3. Backend Core Integration Suite
cd ../backend-core
node test/scans.test.js          # 7 checks

# 4. Scanner AST Analysis Suite
cd ../scanner
.\.venv\Scripts\python tests/test_scanner.py  # 5 tests

# 5. CBOM & Findings Suite
cd ../cbom-service
node test/run.js                 # 16 checks
```

### ✅ Test Results Summary: **107 / 107 PASSED (100%)**
All unit, integration, live Sepolia, and regression suites are green.
