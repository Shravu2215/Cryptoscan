'use strict';

const crypto = require('node:crypto');

/**
 * Standard RFC 3161 OIDs and constants.
 */
const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
const OID_SHA256_DER = Buffer.from('0609608648016503040201', 'hex');
const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const OID_SIGNED_DATA_DER = Buffer.from('06092a864886f70d010702', 'hex');
const OID_TST_INFO = '1.2.840.113549.1.9.16.1.4';
const OID_TST_INFO_DER = Buffer.from('060b2a864886f70d0109100104', 'hex');
const OID_MESSAGE_DIGEST = Buffer.from('06092a864886f70d010904', 'hex');

/**
 * Default Public and Commercial RFC 3161 TSA endpoints.
 */
const DEFAULT_PRIMARY_TSA = process.env.TSA_URL || 'http://timestamp.digicert.com';
const DEFAULT_FALLBACK_TSA = process.env.TSA_FALLBACK_URL || 'https://freetsa.org/tsr';
const DEFAULT_TIMEOUT_MS = parseInt(process.env.TSA_TIMEOUT_MS, 10) || 10000;

// ===========================================================================
// ASN.1 DER LOW-LEVEL ENCODING HELPERS
// ===========================================================================

function encodeDerLength(length) {
  if (length < 128) {
    return Buffer.from([length]);
  }
  if (length < 256) {
    return Buffer.from([0x81, length]);
  }
  return Buffer.from([0x82, (length >> 8) & 0xff, length & 0xff]);
}

function makeSequence(elements) {
  const body = Buffer.concat(elements);
  return Buffer.concat([Buffer.from([0x30]), encodeDerLength(body.length), body]);
}

function makeInteger(val) {
  let buf = typeof val === 'number' ? Buffer.from([val]) : val;
  if (buf[0] & 0x80) {
    buf = Buffer.concat([Buffer.from([0x00]), buf]);
  }
  return Buffer.concat([Buffer.from([0x02]), encodeDerLength(buf.length), buf]);
}

function makeSha256ImprintDer(hashBytes) {
  const algId = Buffer.concat([Buffer.from([0x30]), encodeDerLength(OID_SHA256_DER.length), OID_SHA256_DER]);
  const octetString = Buffer.concat([Buffer.from([0x04, 0x20]), hashBytes]);
  return makeSequence([algId, octetString]);
}

/**
 * Encodes an RFC 3161 TimeStampReq into ASN.1 DER.
 *
 * TimeStampReq ::= SEQUENCE {
 *    version INTEGER { v1(1) },
 *    messageImprint MessageImprint,
 *    nonce INTEGER OPTIONAL,
 *    certReq BOOLEAN DEFAULT FALSE
 * }
 *
 * @param {Buffer} hashBytes - 32-byte SHA-256 message imprint digest.
 * @param {Buffer} nonceBuf - 8-byte cryptographically secure random nonce.
 * @returns {Buffer} DER-encoded TimeStampReq.
 */
function buildTimeStampReq(hashBytes, nonceBuf) {
  const version = makeInteger(1);
  const imprint = makeSha256ImprintDer(hashBytes);
  const nonce = makeInteger(nonceBuf);
  const certReq = Buffer.from([0x01, 0x01, 0xff]); // certReq: true
  return makeSequence([version, imprint, nonce, certReq]);
}

// ===========================================================================
// ASN.1 DER LOW-LEVEL DECODING HELPERS
// ===========================================================================

function decodeDer(buf, offset = 0) {
  if (offset >= buf.length) return null;
  const tag = buf[offset];
  const lenByte = buf[offset + 1];
  let headerLen = 2;
  let length = lenByte;

  if (lenByte & 0x80) {
    const numBytes = lenByte & 0x7f;
    length = 0;
    for (let i = 0; i < numBytes; i++) {
      length = (length << 8) | buf[offset + 2 + i];
    }
    headerLen = 2 + numBytes;
  }

  const valueOffset = offset + headerLen;
  return {
    tag,
    headerLen,
    length,
    totalLen: headerLen + length,
    offset,
    valueOffset,
    value: buf.slice(valueOffset, valueOffset + length),
  };
}

function parseSequence(buf) {
  const elements = [];
  let off = 0;
  while (off < buf.length) {
    const tlv = decodeDer(buf, off);
    if (!tlv) break;
    elements.push(tlv);
    off += tlv.totalLen;
  }
  return elements;
}

function parseGeneralizedTime(str) {
  const match = str.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?(Z|[+-]\d{2}\d{2})$/);
  if (!match) return str;
  const [, y, m, d, h, min, s, frac, tz] = match;
  return `${y}-${m}-${d}T${h}:${min}:${s}${frac || ''}${tz === 'Z' ? 'Z' : tz}`;
}

// ===========================================================================
// CORE TIMESTAMP SERVICE LOGIC
// ===========================================================================

/**
 * Computes the deterministic SHA-256 message imprint for an input Merkle root.
 *
 * @param {string|Buffer} merkleRoot - 64-character lowercase hex string or 32-byte Buffer.
 * @returns {{ digest: Buffer, hex: string, algorithm: string, oid: string }}
 */
function computeMessageImprint(merkleRoot) {
  let rootBytes;
  if (typeof merkleRoot === 'string') {
    if (!/^[0-9a-fA-F]{64}$/.test(merkleRoot)) {
      throw new TypeError('Merkle root must be a 64-character hexadecimal SHA-256 string');
    }
    rootBytes = Buffer.from(merkleRoot, 'hex');
  } else if (Buffer.isBuffer(merkleRoot)) {
    if (merkleRoot.length !== 32) {
      throw new TypeError('Merkle root Buffer must be exactly 32 bytes');
    }
    rootBytes = merkleRoot;
  } else {
    throw new TypeError('Merkle root must be a 64-character hex string or 32-byte Buffer');
  }

  const digest = crypto.createHash('sha256').update(rootBytes).digest();
  return {
    digest,
    hex: digest.toString('hex'),
    algorithm: 'SHA-256',
    oid: OID_SHA256,
  };
}

/**
 * Transmits an RFC 3161 TimeStampReq to a TSA endpoint via HTTP POST.
 * Never disables TLS verification. Supports optional Basic Authentication via environment.
 */
async function postTimeStampQuery(tsaUrl, reqDer, timeoutMs) {
  const headers = {
    'Content-Type': 'application/timestamp-query',
    'User-Agent': 'CryptoScan-IntegrityService/1.0',
  };

  // Optional authenticated TSA credentials
  if (process.env.TSA_USERNAME && process.env.TSA_PASSWORD) {
    const creds = Buffer.from(`${process.env.TSA_USERNAME}:${process.env.TSA_PASSWORD}`).toString('base64');
    headers['Authorization'] = `Basic ${creds}`;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(tsaUrl, {
      method: 'POST',
      headers,
      body: reqDer,
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`TSA server responded with HTTP status ${response.status} ${response.statusText}`);
    }

    const arrayBuffer = await response.arrayBuffer();
    return Buffer.from(arrayBuffer);
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Requests a genuine RFC 3161 trusted timestamp token from a Timestamp Authority.
 *
 * @param {string|Buffer} merkleRoot - The Merkle root to authenticate.
 * @param {object} [options={}] - Configuration options.
 * @param {string} [options.tsaUrl] - Primary TSA endpoint.
 * @param {string} [options.fallbackTsaUrl] - Secondary fallback TSA endpoint.
 * @param {number} [options.timeoutMs] - Request timeout in milliseconds.
 * @param {Buffer} [options.nonce] - Optional explicit nonce (for testing).
 * @returns {Promise<{ type: string, hashAlgorithm: string, messageImprint: string, token: string, genTime: string, tsa: string, serialNumber: string }>}
 */
async function requestTimestamp(merkleRoot, options = {}) {
  const imprint = computeMessageImprint(merkleRoot);
  const nonce = options.nonce || crypto.randomBytes(8);
  const reqDer = buildTimeStampReq(imprint.digest, nonce);

  const primaryTsa = options.tsaUrl || DEFAULT_PRIMARY_TSA;
  const fallbackTsa = options.fallbackTsaUrl || DEFAULT_FALLBACK_TSA;
  const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;

  let rawResp;
  let activeTsa = primaryTsa;

  try {
    rawResp = await postTimeStampQuery(primaryTsa, reqDer, timeoutMs);
  } catch (primaryErr) {
    if (fallbackTsa && fallbackTsa !== primaryTsa) {
      try {
        activeTsa = fallbackTsa;
        rawResp = await postTimeStampQuery(fallbackTsa, reqDer, timeoutMs);
      } catch (fallbackErr) {
        throw new Error(
          `RFC 3161 timestamp acquisition failed on primary (${primaryErr.message}) and fallback (${fallbackErr.message})`
        );
      }
    } else {
      throw new Error(`RFC 3161 timestamp acquisition failed on ${primaryTsa}: ${primaryErr.message}`);
    }
  }

  // Parse TimeStampResp
  const respTlv = decodeDer(rawResp, 0);
  if (!respTlv || respTlv.tag !== 0x30) {
    throw new Error('Malformed RFC 3161 response: expected outer SEQUENCE');
  }

  const respElems = parseSequence(respTlv.value);
  if (respElems.length < 2) {
    throw new Error('Malformed RFC 3161 response: missing required elements');
  }

  // Check PKIStatusInfo
  const statusSeq = parseSequence(respElems[0].value);
  const statusCode = statusSeq[0] ? statusSeq[0].value[0] : -1;
  if (statusCode !== 0 && statusCode !== 1) {
    throw new Error(`TSA rejected timestamp request with PKIStatus: ${statusCode}`);
  }

  // Extract TimeStampToken DER buffer
  const tokenTlv = respElems[1];
  const tokenDer = rawResp.slice(respTlv.valueOffset + tokenTlv.offset, respTlv.valueOffset + tokenTlv.offset + tokenTlv.totalLen);

  // Validate internal token structures and nonce
  const verification = verifyTimestamp(tokenDer, merkleRoot, { expectedNonce: nonce });
  if (!verification.valid) {
    throw new Error(`TSA returned an invalid timestamp token: ${verification.reason}`);
  }

  return {
    type: 'RFC3161',
    hashAlgorithm: 'SHA-256',
    messageImprint: imprint.hex,
    token: tokenDer.toString('base64'),
    genTime: verification.genTime,
    tsa: activeTsa,
    serialNumber: verification.serialNumber,
  };
}

/**
 * Independently verifies an RFC 3161 TimeStampToken against a Merkle root.
 *
 * Validates:
 * 1. CMS SignedData structure encapsulating TSTInfo.
 * 2. MessageImprint algorithm is SHA-256 and matches SHA-256(merkleRoot).
 * 3. Nonce match (if expectedNonce is provided).
 * 4. TSA signing certificate extraction.
 * 5. TSA digital signature over signedAttrs containing TSTInfo digest.
 *
 * @param {string|Buffer|object} token - Base64 string, DER Buffer, or timestamp object.
 * @param {string|Buffer} merkleRoot - Expected Merkle root.
 * @param {object} [options={}] - Verification options.
 * @param {Buffer} [options.expectedNonce] - Expected nonce to assert.
 * @returns {{ valid: boolean, imprintValid: boolean, signatureValid: boolean, genTime?: string, serialNumber?: string, tsaSubject?: string, tsaIssuer?: string, reason?: string }}
 */
function verifyTimestamp(token, merkleRoot, options = {}) {
  let tokenBuf;
  if (typeof token === 'string') {
    tokenBuf = Buffer.from(token, 'base64');
  } else if (Buffer.isBuffer(token)) {
    tokenBuf = token;
  } else if (token && typeof token === 'object' && token.token) {
    tokenBuf = Buffer.from(token.token, 'base64');
  } else {
    throw new TypeError('Token must be a Base64 string, Buffer, or timestamp object');
  }

  let expectedImprint;
  try {
    expectedImprint = computeMessageImprint(merkleRoot);
  } catch (err) {
    return { valid: false, imprintValid: false, signatureValid: false, reason: err.message };
  }

  // 1. Locate SignedData OID
  const sdIdx = tokenBuf.indexOf(OID_SIGNED_DATA_DER);
  if (sdIdx === -1) {
    return { valid: false, imprintValid: false, signatureValid: false, reason: 'Missing CMS SignedData structure' };
  }

  const afterSd = tokenBuf.slice(sdIdx + OID_SIGNED_DATA_DER.length);
  const sdContent = decodeDer(afterSd);
  if (!sdContent) {
    return { valid: false, imprintValid: false, signatureValid: false, reason: 'Malformed SignedData content' };
  }

  const sdSeq = decodeDer(sdContent.value);
  const sdElems = parseSequence(sdSeq.value);
  if (sdElems.length < 5) {
    return { valid: false, imprintValid: false, signatureValid: false, reason: 'Incomplete SignedData structure' };
  }

  // 2. Locate and parse TSTInfo from encapContentInfo (sdElems[2])
  const tstOidIdx = tokenBuf.indexOf(OID_TST_INFO_DER);
  if (tstOidIdx === -1) {
    return { valid: false, imprintValid: false, signatureValid: false, reason: 'Missing id-ct-TSTInfo OID' };
  }

  const afterTstOid = tokenBuf.slice(tstOidIdx + OID_TST_INFO_DER.length);
  const explicit0 = decodeDer(afterTstOid);
  const octetStr = decodeDer(explicit0.value);
  const rawTstInfoBytes = octetStr.value; // The exact raw DER bytes of TSTInfo

  const tstSeq = decodeDer(rawTstInfoBytes);
  const tstElems = parseSequence(tstSeq.value);
  if (tstElems.length < 5) {
    return { valid: false, imprintValid: false, signatureValid: false, reason: 'Malformed TSTInfo structure' };
  }

  // TSTInfo: version(0), policy(1), messageImprint(2), serial(3), genTime(4), nonce(optional 5+)
  const imprintElems = parseSequence(tstElems[2].value);
  if (imprintElems.length < 2) {
    return { valid: false, imprintValid: false, signatureValid: false, reason: 'Malformed TSTInfo MessageImprint' };
  }

  const tokenImprintHash = imprintElems[1].value;
  const imprintValid = tokenImprintHash.equals(expectedImprint.digest);
  if (!imprintValid) {
    return {
      valid: false,
      imprintValid: false,
      signatureValid: false,
      reason: `Message imprint mismatch: expected ${expectedImprint.hex}, found ${tokenImprintHash.toString('hex')}`,
    };
  }

  // Validate Nonce if expected
  if (options.expectedNonce) {
    let nonceFound = false;
    for (let i = 5; i < tstElems.length; i++) {
      if (tstElems[i].tag === 0x02) {
        const returnedNonce = tstElems[i].value;
        const expected = options.expectedNonce;
        if (returnedNonce.equals(expected) || returnedNonce.slice(1).equals(expected) || expected.slice(1).equals(returnedNonce)) {
          nonceFound = true;
          break;
        }
      }
    }
    if (!nonceFound) {
      return { valid: false, imprintValid: true, signatureValid: false, reason: 'Nonce mismatch in timestamp token' };
    }
  }

  const genTime = parseGeneralizedTime(tstElems[4].value.toString('ascii'));
  const serialNumber = tstElems[3].value.toString('hex');

  // 3. Extract Certificates (sdElems[3])
  const certTlv = decodeDer(sdElems[3].value);
  const certBytes = sdElems[3].value.slice(0, certTlv.totalLen);
  let cert;
  try {
    cert = new crypto.X509Certificate(certBytes);
  } catch (err) {
    return { valid: false, imprintValid: true, signatureValid: false, reason: `Failed to parse TSA certificate: ${err.message}` };
  }

  // 4. Extract and verify SignerInfo (sdElems[4])
  const siSet = parseSequence(sdElems[4].value);
  if (siSet.length === 0) {
    return { valid: false, imprintValid: true, signatureValid: false, reason: 'Missing SignerInfo in token' };
  }

  const siElems = parseSequence(siSet[0].value);
  // siElems: version(0), sid(1), digestAlg(2), signedAttrs(3), sigAlg(4), signature(5)
  if (siElems.length < 6) {
    return { valid: false, imprintValid: true, signatureValid: false, reason: 'Malformed SignerInfo structure' };
  }

  const signedAttrsTlv = siElems[3];
  const sigTlv = siElems[5];

  // Verify message-digest attribute inside signedAttrs
  const mdIdx = signedAttrsTlv.value.indexOf(OID_MESSAGE_DIGEST);
  if (mdIdx === -1) {
    return { valid: false, imprintValid: true, signatureValid: false, reason: 'Missing message-digest in signedAttrs' };
  }

  const afterMd = signedAttrsTlv.value.slice(mdIdx + OID_MESSAGE_DIGEST.length);
  const mdSet = decodeDer(afterMd);
  const mdOctet = decodeDer(mdSet.value);
  const computedTstDigest = crypto.createHash('sha256').update(rawTstInfoBytes).digest();

  if (!mdOctet.value.equals(computedTstDigest)) {
    return { valid: false, imprintValid: true, signatureValid: false, reason: 'SignedAttrs message-digest mismatch' };
  }

  // In CMS: bytes to verify is signedAttrs with tag changed from 0xa0 to 0x31 (SET OF)
  const attrsToVerify = Buffer.concat([
    Buffer.from([0x31]),
    encodeDerLength(signedAttrsTlv.length),
    signedAttrsTlv.value,
  ]);

  let signatureValid = false;
  try {
    signatureValid = crypto.verify('sha256', attrsToVerify, cert.publicKey, sigTlv.value);
  } catch (err) {
    signatureValid = false;
  }

  if (!signatureValid) {
    return { valid: false, imprintValid: true, signatureValid: false, reason: 'TSA digital signature verification failed' };
  }

  return {
    valid: true,
    imprintValid: true,
    signatureValid: true,
    genTime,
    serialNumber,
    tsaSubject: cert.subject,
    tsaIssuer: cert.issuer,
  };
}

module.exports = {
  requestTimestamp,
  verifyTimestamp,
  computeMessageImprint,
  buildTimeStampReq,
  DEFAULT_PRIMARY_TSA,
  DEFAULT_FALLBACK_TSA,
  OID_SHA256,
};
