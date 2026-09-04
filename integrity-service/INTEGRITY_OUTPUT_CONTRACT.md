# CryptoScan Integrity Layer: Output Contract (v1.0)

This document freezes the **Integrity Output Contract (version 1.0)** for the CryptoScan platform. It serves as the formal design and interface specification agreed upon between the core integrity service and downstream consumers:

* **Signed CBOM Export Service**: Bundles CBOM documents with cryptographic integrity proofs.
* **Blockchain Anchoring & Verification Service**: Anchors integrity commitments on-chain and verifies tamper evidence.

> **Status Notice**: This document defines the **frozen target contract**. The sections below clearly specify which fields are currently active and tested in code versus which fields are reserved for upcoming implementation phases.

---

## 1. Baseline: Existing `anchor.js` Output

In the current baseline implementation ([`blockchain-module/scripts/anchor.js`](file:///c:/Users/Shravani/Downloads/Cryptoscan-main/blockchain-module/scripts/anchor.js)), anchoring hashes the entire scan content JSON buffer as a raw byte-for-byte blob:

```json
{
  "scanId": "uuid-string",
  "contentHash": "0x<64-character-sha256-hex>",
  "signature": "0x<ecdsa-signature-hex>",
  "txHash": "0x<transaction-hash>",
  "network": "localhost",
  "anchoredBy": "0x<wallet-address>",
  "blockNumber": 1234
}
```

### Transition to Merkle Root
In the new architecture:
* Anchoring the entire blob will be superseded conceptually by anchoring the **CBOM Merkle Root** (`merkle.root.value`).
* This enables granular, component-level cryptographic verification via Merkle proofs without requiring consumers to access or reveal the full CBOM document.

---

## 2. Frozen Target Output Contract (Version 1.0)

The target integrity output is structured as follows:

```json
{
  "version": "1.0",
  "merkle": {
    "root": {
      "hashAlgorithm": "SHA-256",
      "value": "<64-character-hex>"
    }
  },
  "signature": {
    "algorithm": "Ed25519+ML-DSA-hybrid",
    "classicalSig": "<signature>",
    "pqcSig": "<signature>"
  },
  "timestamp": {
    "type": "RFC3161",
    "token": "<timestamp-token>"
  }
}
```

---

## 3. Field-by-Field Specification

### `version`
* **Type**: `string`
* **Current Value**: `"1.0"`
* **Description**: Protocol/output schema specification version. Enforces schema stability and guarantees backward compatibility for downstream parsers without breaking changes.

### `merkle.root.hashAlgorithm`
* **Type**: `string`
* **Current Value**: `"SHA-256"`
* **Description**: Explicitly designates the cryptographic digest algorithm used to compute the leaves, intermediate nodes, and final Merkle root.

### `merkle.root.value`
* **Type**: `string` (64-character lowercase hexadecimal)
* **Description**: The deterministic Merkle root generated from CBOM components via `buildMerkleTree(cbom.components).root`. Replaces whole-blob hashing.

### `signature.algorithm`
* **Type**: `string`
* **Current Target Value**: `"Ed25519+ML-DSA-hybrid"`
* **Description**: Declares the hybrid dual-signature scheme combining a classical digital signature (e.g. Ed25519 / ECDSA) with a post-quantum digital signature (ML-DSA).
* **Implementation Status**: *Planned (Not yet implemented).*

### `signature.classicalSig`
* **Type**: `string`
* **Description**: Base64 or hexadecimal representation of the classical signature over the integrity payload.
* **Implementation Status**: *Planned (Not yet implemented).*

### `signature.pqcSig`
* **Type**: `string`
* **Description**: Base64 or hexadecimal representation of the post-quantum signature (ML-DSA or clearly documented simulation for demonstration environments).
* **Implementation Status**: *Planned (Not yet implemented).*

### `timestamp.type`
* **Type**: `string`
* **Current Target Value**: `"RFC3161"`
* **Description**: Identifies the trusted timestamping standard applied to the root / signed payload.
* **Implementation Status**: *Planned (Not yet implemented).*

### `timestamp.token`
* **Type**: `string`
* **Description**: Base64-encoded RFC 3161 Time-Stamp Token (TST) containing the timestamp authority (TSA) signature and verified epoch.
* **Implementation Status**: *Planned (Not yet implemented).*

---

## 4. Consumer Contracts

The following guarantees are established for version `1.0`:

### Consumer: Signed CBOM Export Service
The Signed CBOM Export service bundles the CBOM document with integrity metadata for external distribution and verification. It can rely on the following stable fields:
* `merkle.root.value`: To attach the verifiable root to the exported CBOM.
* `signature.algorithm`: To declare signature schemes in exported manifests.
* `signature.classicalSig`: For classical verifiers (e.g., standard PKI tools).
* `signature.pqcSig`: For post-quantum compliance verifiers.
* `timestamp.token`: For proving that the CBOM existed prior to key compromise or algorithmic deprecation.

### Consumer: Blockchain Anchoring / On-Chain Verification Service
The Blockchain module anchors the integrity state on-chain and performs on-chain or off-chain verification. It can rely on the following stable fields:
* `merkle.root.value`: The primary 32-byte (`bytes32`) hash value submitted to smart contract storage (e.g., `CryptoAnchor.anchorScan(...)`).
* `merkle.root.hashAlgorithm`: To confirm digest alignment (SHA-256).
* `signature.*`: To verify off-chain authenticity and authorization before transaction submission.
* `timestamp.*`: For off-chain audit logs and timestamp proofs.

---

## 5. Merkle Proof Contract

Individual CBOM components can be independently verified without disclosing or transmitting the entire CBOM.

### Proof Generation
```js
const proof = getProof(tree, leafIndex);
```

### Proof Structure
```json
[
  {
    "sibling": "64-character-lowercase-hex-sha256",
    "position": "left"
  },
  {
    "sibling": "64-character-lowercase-hex-sha256",
    "position": "right"
  }
]
```
* `"left"`: Sibling was the left child of the pair during tree construction.
* `"right"`: Sibling was the right child of the pair during tree construction.
* For a single-leaf tree (`tree = [[leaf]]`), `getProof` returns `[]`.

### Independent Verification
```js
const isValid = verifyProof(leaf, proof, root);
```
* **Inputs required**: Only `leaf` (64-char hex), `proof` (array), and `root` (64-char hex).
* **Zero dependencies on complete CBOM**: Verifier does **not** need the original components list, raw CBOM JSON, or access to `buildMerkleTree()`.
* **Tamper-resistant**: Uses sorted-pair hashing (`hashPair(A, B) = hashPair(B, A)`), preventing position manipulation attacks.

---

## 6. Critical Compatibility & Determinism Rules

The Merkle tree implementation in [`integrity-service/merkle.js`](file:///c:/Users/Shravani/Downloads/Cryptoscan-main/integrity-service/merkle.js) strictly adheres to these **6 deterministic rules**:

1. **Canonical Component Serialization**: Object keys are recursively sorted lexicographically at all nesting depths; array order is strictly preserved; non-mutating.
2. **SHA-256 Leaf Hashing**: Each canonicalized component produces exactly one 64-character lowercase hexadecimal SHA-256 leaf.
3. **Lexicographically Sorted Sibling Hashes**: Sibling pairs are ordered lexicographically before concatenation: `H(min(A, B) + max(A, B))`.
4. **SHA-256 Pair Hashing**: Parent hashes are computed using standard SHA-256 digests over concatenated lowercase hex strings.
5. **Duplicate-Last-Node Handling (Bitcoin-style)**: If any level has an odd node count, the last node is duplicated: `H(sort(C, C))`. No nodes are silently dropped.
6. **Direct Leaf-as-Root Behavior**: A single component tree has `root = leaf` without redundant hashing.

> **CRITICAL RULE**: These 6 rules **MUST NEVER** be altered silently. Any change to these rules will produce different Merkle roots for the same CBOM, immediately invalidating previously anchored on-chain records and previously issued Merkle proofs. Any structural modification requires a formal schema version upgrade (`version: "2.0"`).

---

## 7. Complete Example (With Placeholders)

```json
{
  "version": "1.0",
  "merkle": {
    "root": {
      "hashAlgorithm": "SHA-256",
      "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
  },
  "signature": {
    "algorithm": "Ed25519+ML-DSA-hybrid",
    "classicalSig": "BASE64_CLASSICAL_SIGNATURE",
    "pqcSig": "BASE64_PQC_SIGNATURE"
  },
  "timestamp": {
    "type": "RFC3161",
    "token": "BASE64_TIMESTAMP_TOKEN"
  }
}
```

*(Note: The hash, signatures, and token in this example are purely illustrative placeholders and not real cryptographic outputs).*

---

## 8. Implementation Status

| Feature Area | Component / Field | Status | Notes |
| :--- | :--- | :--- | :--- |
| **Merkle Tree** | `buildMerkleTree()` | **CURRENTLY IMPLEMENTED** | Pure, deterministic, handles single/odd/even leaves. |
| **Merkle Proofs** | `getProof()` | **CURRENTLY IMPLEMENTED** | Generates self-describing sibling paths. |
| **Proof Verification** | `verifyProof()` | **CURRENTLY IMPLEMENTED** | Lightweight, independent, sorted-pair verification. |
| **Canonicalization** | `canonicalize()` | **CURRENTLY IMPLEMENTED** | Recursive object key sorting, array preservation. |
| **Hashing Engine** | SHA-256 | **CURRENTLY IMPLEMENTED** | Built-in Node.js `crypto`. |
| **Runtime Agility Metadata** | `merkle.root.hashAlgorithm` | **PLANNED** | Defined in contract; not yet attached to runtime return. |
| **Hybrid Dual Signatures** | `signature.*` | **PLANNED** | Ed25519 + ML-DSA hybrid signing to be integrated. |
| **RFC 3161 Timestamping** | `timestamp.*` | **PLANNED** | External TSA client / token generation to be added. |
| **KMS Integration** | Key management | **PLANNED** | KMS wrapper for secure key lifecycle. |
| **Blockchain Module Anchor** | `anchor.js` integration | **PLANNED** | `anchor.js` remains untouched in this milestone. |
