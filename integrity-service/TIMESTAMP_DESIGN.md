# RFC 3161 Trusted Timestamp Service: Architecture & Design

## 1. Executive Summary & Production Status

CryptoScan implements a **genuine RFC 3161 Time-Stamp Protocol (TSP)** client and offline verifier within `integrity-service/timestamp.js`.

* **Primary Commercial TSA**: **DigiCert Timestamp Authority** (`http://timestamp.digicert.com`)
* **Secondary Fallback TSA**: **FreeTSA** (`https://freetsa.org/tsr`)
* **Transport**: Standards-compliant HTTP/HTTPS `POST` with `Content-Type: application/timestamp-query`.
* **Zero Simulation / Zero Fake Cryptography**: Never substitutes local system clocks (`Date.now()`), never generates self-signed/fake tokens, and never disables TLS certificate verification.

---

## 2. Selected Timestamp Authorities & Production Suitability

### Primary: DigiCert (`http://timestamp.digicert.com`)
- **Protocol Compliance**: 100% genuine RFC 3161 and RFC 5652 (CMS).
- **Trust Anchor**: WebTrust-audited, globally trusted Root CA pre-installed in Microsoft, Apple, Google, and Mozilla trust stores.
- **Clock Source**: Certified atomic clock synchronised to UTC standards.
- **Production Suitability**: **High / Commercial Grade**. Provides enterprise-grade reliability and legal recognition under global electronic signature frameworks.

### Secondary Fallback: FreeTSA (`https://freetsa.org/tsr`)
- **Protocol Compliance**: 100% genuine RFC 3161 and RFC 5652.
- **Trust Anchor**: Self-operated FreeTSA Root CA.
- **Production Suitability**: **Testing / Secondary Staging Only**. FreeTSA does not offer a commercial SLA and may enforce unannounced rate limits.

---

## 3. Cryptographic Pipeline: Exact Bytes Timestamped

A critical vulnerability in naive timestamping is stamping arbitrary non-deterministic JSON or only an unauthenticated root. CryptoScan timestamps the **exact binary digest of the Merkle root**:

```text
Merkle Root (64-character lowercase hex string)
       ↓
Convert to 32 Raw Binary Bytes: Buffer.from(merkleRootHex, 'hex')
       ↓
Compute SHA-256 Digest: crypto.createHash('sha256').update(rootBytes).digest()
       ↓
MessageImprint (32 bytes binary digest)
       ↓
Encode RFC 3161 TimeStampReq (with 64-bit random nonce & certReq: true)
       ↓
HTTP POST -> Real TSA (DigiCert / FreeTSA)
       ↓
Parse TimeStampResp (Assert PKIStatus == 0)
       ↓
TimeStampToken (CMS SignedData encapsulating TSTInfo)
```

### Hashing Details:
- **Digest Algorithm**: SHA-256 (OID: `2.16.840.1.101.3.4.2.1`).
- **Algorithm Identifier**: `06 09 60 86 48 01 65 03 04 02 01`.
- **Hashed Message**: The exact 32-byte SHA-256 hash of the 32-byte Merkle root value.

---

## 4. Cryptographically Secure Nonce Handling

To prevent replay attacks and man-in-the-middle token substitution:
1. Each request generates an 8-byte (64-bit) cryptographically secure random integer using `crypto.randomBytes(8)`.
2. The nonce is encoded as an ASN.1 INTEGER in `TimeStampReq`.
3. Upon receiving `TimeStampResp`, the client strictly parses `TSTInfo.nonce` and verifies that it equals the requested nonce before accepting the token.

---

## 5. Token Structure & Storage Format

The timestamp output complies with CryptoScan's frozen integrity output contract (`INTEGRITY_OUTPUT_CONTRACT.md`):

```json
{
  "type": "RFC3161",
  "hashAlgorithm": "SHA-256",
  "messageImprint": "ec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc5",
  "token": "MIIXaQYJKoZIhvcNAQcCoIIXWjCCF1YCAQMxDzAN...",
  "genTime": "2026-09-01T15:49:46Z",
  "tsa": "http://timestamp.digicert.com",
  "serialNumber": "60d2aeebd290b08ed73cfbee4be6dbeb"
}
```

### Fields:
* **`type`**: Fixed identifier `"RFC3161"`.
* **`hashAlgorithm`**: Fixed identifier `"SHA-256"`.
* **`messageImprint`**: 64-character hexadecimal SHA-256 digest of the Merkle root.
* **`token`**: Base64-encoded raw DER binary of the CMS `SignedData` `TimeStampToken`.
* **`genTime`**: ISO-8601 UTC timestamp certified by the TSA.
* **`tsa`**: The URL of the TSA endpoint that issued the token.
* **`serialNumber`**: Hexadecimal serial number assigned by the TSA.

---

## 6. Offline Independent Verification Workflow

Verification does **not** make any outbound network calls and runs completely offline:

```text
Input: (tokenBase64, expectedMerkleRoot)
                   |
                   v
1. Base64-decode token into CMS SignedData DER
                   |
                   v
2. Extract encapsulated TSTInfo (OID 1.2.840.113549.1.9.16.1.4)
                   |
                   v
3. Verify MessageImprint:
   - Compute expected SHA-256 digest of expectedMerkleRoot
   - Assert TSTInfo.messageImprint.hashedMessage === expectedDigest
                   |
                   v
4. Verify Signed Attributes (signedAttrs):
   - Locate message-digest attribute (OID 1.2.840.113549.1.9.4)
   - Assert message-digest === SHA-256(rawTSTInfoBytes)
                   |
                   v
5. Verify TSA Cryptographic Signature:
   - Extract TSA Certificate from SignedData.certificates (via crypto.X509Certificate)
   - Verify RSA-4096 / ECDSA signature over signedAttrs using TSA public key
                   |
                   v
6. Extract and Return Certified Metadata:
   - genTime (from GeneralizedTime)
   - serialNumber
   - tsaSubject / tsaIssuer
```

If any check fails (imprint mismatch, bit flip in token, signature mismatch), `valid` is strictly `false`.

---

## 7. Configuration & Environment Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `TSA_URL` | Primary RFC 3161 TSA endpoint URL. | `http://timestamp.digicert.com` |
| `TSA_FALLBACK_URL` | Secondary RFC 3161 TSA endpoint URL. | `https://freetsa.org/tsr` |
| `TSA_TIMEOUT_MS` | Network request timeout in milliseconds. | `10000` (10 seconds) |
| `TSA_USERNAME` | Optional HTTP Basic Auth username for enterprise TSAs. | *(none)* |
| `TSA_PASSWORD` | Optional HTTP Basic Auth password for enterprise TSAs. | *(none)* |

*Credentials are never logged or returned in signature/timestamp artifacts.*

---

## 8. Failure Modes & Anchoring Decoupling

1. **Unreachable TSA**:
   - If the primary TSA times out or returns HTTP 5xx, the client automatically attempts the fallback TSA.
   - If all TSAs are unavailable, `requestTimestamp()` throws a descriptive `Error`.
   - **Crucial Rule**: The service **never** produces a simulated timestamp or falls back to system time.
2. **Decoupling from On-Chain Anchoring**:
   - Blockchain anchoring requires only `merkle.root.value`.
   - In production pipelines, a transient TSA failure should log a `TIMESTAMP_ACQUISITION_FAILED` event and trigger an asynchronous retry, rather than corrupting the integrity record with false data.

---

## 9. Security & Legal Precision: What RFC 3161 Actually Proves

> **CRITICAL LEGAL & CRYPTOGRAPHIC DISTINCTION**:
> 
> An RFC 3161 TimeStampToken proves that **the exact cryptographic digest contained in the message imprint was presented to the Timestamp Authority at or prior to the certified generation time (`genTime`)**, as attested by the TSA's digital signature.
> 
> It does **NOT** independently prove:
> - When the software developer wrote the code.
> - When vulnerabilities or dependencies were introduced.
> - The identity of the party that generated the CBOM.
> - The truthfulness or completeness of the CBOM contents.
> 
> Its sole function is **irrefutable temporal attestation (proof of existence in time)** and **protection against post-dated signature forgery**.
