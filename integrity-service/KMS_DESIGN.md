# KMS Key Management Architecture: Design & Rotation Policy

## 1. Overview & Architectural Role

The Key Management Service (KMS) module ([`integrity-service/kms.js`](file:///c:/Users/Shravani/Downloads/Cryptoscan-main/integrity-service/kms.js)) establishes a centralized, secure boundary for cryptographic signing keys within the CryptoScan platform.

Prior to this module, backend scripts directly accessed `process.env.PRIVATE_KEY` throughout the codebase. The KMS wrapper removes direct private-key access from application consumers such as [`blockchain-module/scripts/anchor.js`](file:///c:/Users/Shravani/Downloads/Cryptoscan-main/blockchain-module/scripts/anchor.js) and routes all key retrieval through an abstract, standardized interface.

```text
[ Consumers (e.g. anchor.js) ]
              |
              | getSigningKey() / getKeyInfo()
              v
[ KMS Wrapper (integrity-service/kms.js) ]
              |
              +---> Local Environment / process.env.PRIVATE_KEY (Current Demo)
              |
              +---> AWS KMS / Azure Key Vault / Google Cloud KMS / HSM (Future Production)
```

---

## 2. Local Demo KMS Abstraction

> **Important Disclosure**: The current implementation is a **Local KMS-equivalent abstraction** designed for development, testing, and demonstration environments. It is **NOT** a hosted production cloud KMS.

* **Secret Storage**: In the demo setup, the root secret continues to reside in the local environment (`process.env.PRIVATE_KEY`), protected by `.gitignore`.
* **Centralization**: `kms.js` is the sole authorized application boundary permitted to read `process.env.PRIVATE_KEY`.
* **Zero Logging**: Private keys are encapsulated within a `SigningKey` class with custom inspection (`[util.inspect.custom]`) and JSON serialization (`toJSON`) logic that strictly redacts the secret (`[REDACTED]`) to prevent accidental disclosure in console logs, error messages, or debugging traces.

---

## 3. Public Interface

Consumers interact with the KMS wrapper through a uniform API:

### `getSigningKey()`
* **Purpose**: Retrieves the currently active signing key.
* **Returns**: A `SigningKey` instance providing `{ keyId, privateKey }`.
* **Security**: Printing or serializing this object masks `privateKey`.
* **Error Handling**: Throws an informative error if no signing key is configured, without echoing any partial secret.

### `getKeyInfo()`
* **Purpose**: Returns non-sensitive metadata regarding the active key.
* **Returns**: `{ keyId, algorithm, status, provider }`.

### `rotateKey(options)`
* **Purpose**: Executes a controlled key rotation operation.
* **Parameters**: `options.newPrivateKey` (or string), optional `options.newKeyId`.
* **Returns**: `{ status: 'ROTATED', keyId, previousKeyId }`.

### `getKeyById(keyId)`
* **Purpose**: Retrieves a historical key by its identifier to audit or verify signatures created prior to a rotation event.

---

## 4. Key Identification & Rotation Policy

### Active Key Identification
* Each key version is assigned an opaque, non-secret identifier (e.g., `local-demo-key-v1`, `local-demo-key-v2`).
* The key identifier is safe to include in public manifests, audit records, and logs. It never derives from or exposes the private key.

### Controlled Explicit Rotation
* **Rationale**: In the CryptoScan architecture, the signing wallet corresponds to an on-chain account holding balance for transaction gas and registered in smart contracts (e.g., `CryptoAnchor`). Generating a random throwaway key on rotation would immediately break on-chain anchoring.
* **Policy**: Key rotation is an **explicit, controlled operation**. The caller must supply the replacement private key (or configure `ROTATED_PRIVATE_KEY` in the environment). Attempting rotation without an explicit replacement key raises a descriptive error and preserves the existing active key without mutation.

### Retention of Previous Keys & Verification of Historical Signatures
* When `rotateKey()` is executed:
  1. The existing active key is archived in an internal `keyHistory` registry mapped by its `keyId`.
  2. The new key is set as active with an incremented version identifier (`local-demo-key-v2`).
  3. Historical signatures generated under `local-demo-key-v1` remain verifiable by querying `getKeyById("local-demo-key-v1")`.

---

## 5. Security Invariants

The KMS implementation strictly maintains the following invariants:

1. **No Hardcoded Secrets**: Source files contain zero hardcoded private keys.
2. **No Secret Logging**: Private keys are never printed, output in `console.log`, or embedded in error messages.
3. **No Secret Leaks in APIs**: `toJSON()` outputs only `{ keyId }`.
4. **Git Protection**: Secret configuration remains confined to `.env`, which is strictly ignored by `.gitignore`.
5. **Separation of Concerns**: Application code (such as `anchor.js`) never reads environment variables for private keys directly.

---

## 6. Production Migration Roadmap

The interface exposed by `kms.js` is intentionally designed to allow zero-downtime, seamless migration to enterprise key management systems without altering consumer code:

| Cloud / HSM Provider | Underlying Mechanism | Impact on `anchor.js` |
| :--- | :--- | :--- |
| **AWS KMS** | AWS SDK `SignCommand` using an asymmetric KMS key ARN (`alias/cryptoscan-signer`). | None (`getSigningKey()` / KMS signer interface unchanged). |
| **Azure Key Vault** | Azure `@azure/keyvault-keys` `CryptographyClient.sign()`. | None. |
| **Google Cloud KMS** | `@google-cloud/kms` `KeyManagementServiceClient.asymmetricSign()`. | None. |
| **PKCS#11 / HSM** | Hardware Security Module hardware-backed key handle. | None. |
