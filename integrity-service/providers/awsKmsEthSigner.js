'use strict';

/**
 * ethers-compatible Signer backed by an asymmetric AWS KMS key
 * (KeySpec: ECC_SECG_P256K1, KeyUsage: SIGN_VERIFY).
 *
 * IMPORTANT: this implements the well-documented "KMS signs a digest,
 * client reconstructs an Ethereum-shaped {r,s,v} signature" pattern used by
 * most production aws-kms-ethereum integrations. It has NOT been exercised
 * against a live AWS KMS key in this environment (no AWS credentials were
 * available here) — treat it as a structured, ready-to-wire implementation,
 * and run it against a real ECC_SECG_P256K1 KMS key + a Sepolia (or other
 * testnet) transaction before pointing it at anything holding real value.
 *
 * Enable with:
 *   KMS_PROVIDER=aws-kms
 *   AWS_KMS_KEY_ID=arn:aws:kms:...
 *   AWS_REGION=...
 * (plus standard AWS credential resolution: env vars, instance role, etc.)
 *
 * Requires the optional dependency `@aws-sdk/client-kms` to be installed
 * wherever KMS_PROVIDER=aws-kms is used.
 */

const SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const SECP256K1_HALF_N = SECP256K1_N / 2n;

let ethers;
try {
  ethers = require('ethers');
} catch {
  ethers = require('../../blockchain-module/node_modules/ethers');
}

function loadAwsKmsClient() {
  try {
    return require('@aws-sdk/client-kms');
  } catch (err) {
    throw new Error(
      'KMS_PROVIDER=aws-kms requires the optional dependency "@aws-sdk/client-kms". ' +
      'Install it in blockchain-module or integrity-service before enabling this provider.'
    );
  }
}

// Minimal DER parsers — AWS KMS returns DER for both GetPublicKey (SPKI) and
// Sign (ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }). We only need
// to pull fixed, well-known structures out, not parse arbitrary ASN.1.

function derIntegerAt(buffer, offset) {
  if (buffer[offset] !== 0x02) throw new Error('Expected DER INTEGER tag');
  const len = buffer[offset + 1];
  let start = offset + 2;
  let bytes = buffer.subarray(start, start + len);
  // Strip a single leading 0x00 sign-padding byte, if present.
  if (bytes.length > 1 && bytes[0] === 0x00) bytes = bytes.subarray(1);
  return { value: BigInt('0x' + Buffer.from(bytes).toString('hex')), nextOffset: start + len };
}

function derSignatureToRS(derSignature) {
  // SEQUENCE tag (0x30) + length byte(s) precede the two INTEGERs.
  if (derSignature[0] !== 0x30) throw new Error('Expected DER SEQUENCE tag for KMS signature');
  let offset = 2;
  if ((derSignature[1] & 0x80) !== 0) {
    // Long-form length: skip the extra length-of-length bytes.
    offset = 2 + (derSignature[1] & 0x7f);
  }
  const r = derIntegerAt(derSignature, offset);
  const s = derIntegerAt(derSignature, r.nextOffset);
  return { r: r.value, s: s.value };
}

function spkiToUncompressedPoint(spkiDer) {
  // For EC SPKI DER, the raw uncompressed point (0x04 || X(32) || Y(32), 65
  // bytes total for secp256k1) is always the tail of the structure — this is
  // the standard trick used by every AWS-KMS-to-Ethereum reference implementation.
  const point = spkiDer.subarray(spkiDer.length - 65);
  if (point[0] !== 0x04) throw new Error('Unexpected EC public key encoding from KMS (expected uncompressed point)');
  return point;
}

function publicKeyPointToAddress(point65) {
  const pubKeyNoPrefix = point65.subarray(1); // drop the 0x04 prefix
  const hash = ethers.keccak256(pubKeyNoPrefix);
  return ethers.getAddress('0x' + hash.slice(-40));
}

class AwsKmsEthSigner extends ethers.AbstractSigner {
  constructor({ keyId, region, provider }) {
    super(provider || null);
    if (!keyId) throw new Error('AwsKmsEthSigner requires a keyId');
    this.keyId = keyId;
    this.region = region;
    this._client = null;
    this._addressPromise = null;
  }

  connect(provider) {
    return new AwsKmsEthSigner({ keyId: this.keyId, region: this.region, provider });
  }

  _kms() {
    if (!this._client) {
      const { KMSClient } = loadAwsKmsClient();
      this._client = new KMSClient({ region: this.region });
    }
    return this._client;
  }

  async getAddress() {
    if (!this._addressPromise) {
      this._addressPromise = (async () => {
        const { GetPublicKeyCommand } = loadAwsKmsClient();
        const result = await this._kms().send(new GetPublicKeyCommand({ KeyId: this.keyId }));
        const point = spkiToUncompressedPoint(Buffer.from(result.PublicKey));
        return publicKeyPointToAddress(point);
      })();
    }
    return this._addressPromise;
  }

  /**
   * Signs a 32-byte digest with the KMS key and returns an Ethereum-shaped
   * {r, s, v} signature (low-s normalized, correct recovery id).
   */
  async _signDigest(digestHex) {
    const { SignCommand } = loadAwsKmsClient();
    const digest = Buffer.from(ethers.getBytes(digestHex));

    const result = await this._kms().send(new SignCommand({
      KeyId: this.keyId,
      Message: digest,
      MessageType: 'DIGEST',
      SigningAlgorithm: 'ECDSA_SHA_256',
    }));

    let { r, s } = derSignatureToRS(Buffer.from(result.Signature));

    // Ethereum requires canonical (low-s) signatures; KMS does not guarantee this.
    if (s > SECP256K1_HALF_N) {
      s = SECP256K1_N - s;
    }

    const address = await this.getAddress();
    const rHex = '0x' + r.toString(16).padStart(64, '0');
    const sHex = '0x' + s.toString(16).padStart(64, '0');

    // Recovery id isn't returned by KMS — brute-force the two candidates and
    // keep whichever recovers to this signer's known address.
    for (const yParity of [0, 1]) {
      const candidate = ethers.Signature.from({ r: rHex, s: sHex, yParity });
      const recovered = ethers.recoverAddress(digestHex, candidate);
      if (recovered.toLowerCase() === address.toLowerCase()) {
        return candidate;
      }
    }

    throw new Error('Could not determine a valid recovery id for KMS-produced signature');
  }

  async signMessage(message) {
    const digest = ethers.hashMessage(message);
    const sig = await this._signDigest(digest);
    return sig.serialized;
  }

  async signTransaction(tx) {
    const populated = await this.populateTransaction(tx);
    delete populated.from;
    const unsignedTx = ethers.Transaction.from(populated);
    const sig = await this._signDigest(unsignedTx.unsignedHash);
    unsignedTx.signature = sig;
    return unsignedTx.serialized;
  }

  async signTypedData(domain, types, value) {
    const digest = ethers.TypedDataEncoder.hash(domain, types, value);
    const sig = await this._signDigest(digest);
    return sig.serialized;
  }
}

module.exports = { AwsKmsEthSigner };
