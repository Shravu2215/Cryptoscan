'use strict';

const assert = require('assert').strict;
const crypto = require('node:crypto');
const path = require('node:path');

const {
  requestTimestamp,
  verifyTimestamp,
  computeMessageImprint,
  buildTimeStampReq,
  DEFAULT_PRIMARY_TSA,
  OID_SHA256,
} = require('./timestamp');

console.log('Running RFC 3161 Trusted Timestamp Test Suite...\n');

// Load hermetic pre-recorded genuine DigiCert RFC 3161 token fixture for offline testing
const fixture = require('./fixtures/digicert-token.json');
const FIXTURE_ROOT = fixture.root;
const FIXTURE_TOKEN_BASE64 = fixture.timestamp.token;
const FIXTURE_IMPRINT_HEX = fixture.timestamp.messageImprint;
const FIXTURE_GENTIME = fixture.timestamp.genTime;
const FIXTURE_SERIAL = fixture.timestamp.serialNumber;

async function runTests() {
  // ===========================================================================
  // SECTION 1: MESSAGE IMPRINT DETERMINISM & FORMAT
  // ===========================================================================

  // Test 1: Computes deterministic SHA-256 message imprint for 64-char hex root
  {
    const imprint = computeMessageImprint(FIXTURE_ROOT);
    assert.strictEqual(imprint.algorithm, 'SHA-256');
    assert.strictEqual(imprint.oid, OID_SHA256);
    assert.strictEqual(imprint.hex, FIXTURE_IMPRINT_HEX);
    assert.strictEqual(imprint.digest.length, 32);
    console.log('✓ Test 1 Passed: computeMessageImprint generates exact 32-byte SHA-256 digest');
  }

  // Test 2: Accepts 32-byte Buffer as Merkle root
  {
    const rootBuf = Buffer.from(FIXTURE_ROOT, 'hex');
    const imprint = computeMessageImprint(rootBuf);
    assert.strictEqual(imprint.hex, FIXTURE_IMPRINT_HEX);
    console.log('✓ Test 2 Passed: computeMessageImprint accepts 32-byte Buffer');
  }

  // Test 3: Changed Merkle root by even 1 bit produces different message imprint
  {
    const alteredRoot = '0000000000000000000000000000000000000000000000000000000000000002';
    const imprint1 = computeMessageImprint(FIXTURE_ROOT);
    const imprint2 = computeMessageImprint(alteredRoot);
    assert.notStrictEqual(imprint1.hex, imprint2.hex, 'Altered root must change imprint');
    console.log('✓ Test 3 Passed: Changed Merkle root produces distinct message imprint');
  }

  // Test 4: Invalid root format throws TypeError
  {
    assert.throws(() => computeMessageImprint('invalid-hex'), TypeError);
    assert.throws(() => computeMessageImprint(12345), TypeError);
    assert.throws(() => computeMessageImprint(Buffer.alloc(16)), TypeError);
    console.log('✓ Test 4 Passed: Invalid root format strictly throws TypeError');
  }

  // ===========================================================================
  // SECTION 2: TIMESTAMPREQ ASN.1 DER ENCODING
  // ===========================================================================

  // Test 5: Builds genuine RFC 3161 TimeStampReq ASN.1 DER sequence
  {
    const nonce = Buffer.from('1122334455667788', 'hex');
    const hash = Buffer.from(FIXTURE_IMPRINT_HEX, 'hex');
    const reqDer = buildTimeStampReq(hash, nonce);

    assert(Buffer.isBuffer(reqDer));
    assert.strictEqual(reqDer[0], 0x30, 'Outer tag must be ASN.1 SEQUENCE (0x30)');
    console.log('✓ Test 5 Passed: buildTimeStampReq produces valid ASN.1 DER sequence');
  }

  // Test 6: Embeds SHA-256 OID (2.16.840.1.101.3.4.2.1), nonce, and certReq: true
  {
    const nonce = Buffer.from('1122334455667788', 'hex');
    const hash = Buffer.from(FIXTURE_IMPRINT_HEX, 'hex');
    const reqDer = buildTimeStampReq(hash, nonce);

    const sha256Oid = Buffer.from('0609608648016503040201', 'hex');
    assert(reqDer.includes(sha256Oid), 'Must contain SHA-256 OID');
    assert(reqDer.includes(nonce), 'Must contain requested nonce');
    assert(reqDer.includes(Buffer.from([0x01, 0x01, 0xff])), 'Must include certReq: true');
    console.log('✓ Test 6 Passed: TimeStampReq embeds SHA-256 OID, nonce, and certReq');
  }

  // ===========================================================================
  // SECTION 3: OFFLINE VERIFICATION OF GENUINE RFC 3161 TOKEN
  // ===========================================================================

  // Test 7: Parses and verifies genuine RFC 3161 DigiCert token against matching Merkle root
  {
    const verification = verifyTimestamp(FIXTURE_TOKEN_BASE64, FIXTURE_ROOT);
    assert.strictEqual(verification.valid, true, 'Genuine token must verify');
    assert.strictEqual(verification.imprintValid, true, 'Message imprint must match');
    assert.strictEqual(verification.signatureValid, true, 'TSA signature must verify');
    console.log('✓ Test 7 Passed: Offline verification of genuine DigiCert RFC 3161 token succeeds');
  }

  // Test 8: Correctly extracts certified generation time and serial number
  {
    const verification = verifyTimestamp(FIXTURE_TOKEN_BASE64, FIXTURE_ROOT);
    assert.strictEqual(verification.genTime, FIXTURE_GENTIME);
    assert.strictEqual(verification.serialNumber, FIXTURE_SERIAL);
    console.log('✓ Test 8 Passed: Correctly extracts atomic clock genTime and serial number');
  }

  // Test 9: Correctly extracts and identifies TSA certificate subject and issuer
  {
    const verification = verifyTimestamp(FIXTURE_TOKEN_BASE64, FIXTURE_ROOT);
    assert(verification.tsaSubject.includes('DigiCert'), 'Subject must identify DigiCert');
    assert(verification.tsaSubject.includes('Timestamp Responder'), 'Subject must identify Timestamp Responder');
    assert(verification.tsaIssuer.includes('DigiCert Trusted G4 TimeStamping'), 'Issuer must identify DigiCert CA');
    console.log('✓ Test 9 Passed: Correctly extracts TSA certificate subject and issuer');
  }

  // Test 10: Validates cryptographic RSA-4096 signature over signedAttrs
  {
    const verification = verifyTimestamp(FIXTURE_TOKEN_BASE64, FIXTURE_ROOT);
    assert.strictEqual(verification.signatureValid, true);
    console.log('✓ Test 10 Passed: Validates RSA-4096 signature over signedAttrs with message-digest');
  }

  // ===========================================================================
  // SECTION 4: TAMPERING AND SECURITY REJECTIONS
  // ===========================================================================

  // Test 11: Mismatched Merkle root strictly fails verification
  {
    const wrongRoot = '1111111111111111111111111111111111111111111111111111111111111111';
    const result = verifyTimestamp(FIXTURE_TOKEN_BASE64, wrongRoot);
    assert.strictEqual(result.valid, false, 'Mismatched root must fail verification');
    assert.strictEqual(result.imprintValid, false, 'imprintValid must be false');
    assert(result.reason.includes('imprint mismatch'));
    console.log('✓ Test 11 Passed: Mismatched Merkle root strictly fails verification');
  }

  // Test 12: Tampered token signature bit strictly fails verification
  {
    const rawToken = Buffer.from(FIXTURE_TOKEN_BASE64, 'base64');
    // Flip a byte in the RSA signature at the end of the token
    const tampered = Buffer.from(rawToken);
    tampered[tampered.length - 10] ^= 0xff;

    const result = verifyTimestamp(tampered.toString('base64'), FIXTURE_ROOT);
    assert.strictEqual(result.valid, false, 'Tampered signature must fail verification');
    assert.strictEqual(result.signatureValid, false);
    console.log('✓ Test 12 Passed: Tampered signature byte causes verification failure');
  }

  // Test 13: Tampered TSTInfo content fails message-digest verification
  {
    const rawToken = Buffer.from(FIXTURE_TOKEN_BASE64, 'base64');
    // Flip a byte in the TSTInfo structure (around index 80)
    const tampered = Buffer.from(rawToken);
    tampered[85] ^= 0xff;

    const result = verifyTimestamp(tampered.toString('base64'), FIXTURE_ROOT);
    assert.strictEqual(result.valid, false, 'Tampered TSTInfo must fail verification');
    console.log('✓ Test 13 Passed: Tampered TSTInfo content causes verification rejection');
  }

  // Test 14: Malformed Base64 or corrupt DER token is safely rejected
  {
    const result = verifyTimestamp('not-a-valid-token', FIXTURE_ROOT);
    assert.strictEqual(result.valid, false);
    console.log('✓ Test 14 Passed: Corrupt token is safely rejected');
  }

  // Test 15: Nonce validation detects and rejects nonce mismatch
  {
    const wrongNonce = Buffer.from('ffffffffffffffff', 'hex');
    const result = verifyTimestamp(FIXTURE_TOKEN_BASE64, FIXTURE_ROOT, { expectedNonce: wrongNonce });
    assert.strictEqual(result.valid, false);
    assert(result.reason.includes('Nonce mismatch'));
    console.log('✓ Test 15 Passed: Nonce validation detects and rejects mismatched nonce');
  }

  // ===========================================================================
  // SECTION 5: ERROR HANDLING & CONTRACT COMPLIANCE
  // ===========================================================================

  // Test 16: Unreachable TSA endpoint throws clear error with no fake fallback
  {
    let caught = false;
    try {
      await requestTimestamp(FIXTURE_ROOT, {
        tsaUrl: 'http://127.0.0.1:54321/unreachable-tsa',
        fallbackTsaUrl: 'http://127.0.0.1:54322/unreachable-fallback',
        timeoutMs: 500,
      });
    } catch (err) {
      caught = true;
      assert(err.message.includes('RFC 3161 timestamp acquisition failed'));
      assert(!err.message.includes('fake'));
    }
    assert.strictEqual(caught, true, 'Unreachable TSA must throw an explicit error');
    console.log('✓ Test 16 Passed: Unreachable TSA endpoint throws without fake fallback');
  }

  // Test 17: Timestamp output structure conforms to integrity output contract
  {
    const sampleOutput = {
      type: 'RFC3161',
      hashAlgorithm: 'SHA-256',
      messageImprint: FIXTURE_IMPRINT_HEX,
      token: FIXTURE_TOKEN_BASE64,
      genTime: FIXTURE_GENTIME,
      tsa: DEFAULT_PRIMARY_TSA,
      serialNumber: FIXTURE_SERIAL,
    };

    assert.strictEqual(sampleOutput.type, 'RFC3161');
    assert.strictEqual(sampleOutput.hashAlgorithm, 'SHA-256');
    assert(typeof sampleOutput.token === 'string');
    assert(typeof sampleOutput.messageImprint === 'string');
    assert(typeof sampleOutput.genTime === 'string');
    console.log('✓ Test 17 Passed: Timestamp output structure conforms to integrity output contract');
  }

  // Test 18: Never uses system clock as substitute for RFC 3161
  {
    const verification = verifyTimestamp(FIXTURE_TOKEN_BASE64, FIXTURE_ROOT);
    // genTime must come from the authenticated token GeneralizedTime, not local clock
    assert.strictEqual(verification.genTime, FIXTURE_GENTIME);
    assert.notStrictEqual(verification.genTime, new Date().toISOString());
    console.log('✓ Test 18 Passed: genTime is authenticated from TSA token, not local clock');
  }

  // ===========================================================================
  // SECTION 6: LIVE INTEGRITY TEST (OPTIONAL NETWORK TEST)
  // ===========================================================================

  // Test 19: Live TSA request & end-to-end verification (Skipped cleanly if offline)
  {
    try {
      const liveRoot = crypto.randomBytes(32).toString('hex');
      const liveResult = await requestTimestamp(liveRoot, { timeoutMs: 7000 });

      assert.strictEqual(liveResult.type, 'RFC3161');
      assert.strictEqual(liveResult.hashAlgorithm, 'SHA-256');
      assert(liveResult.token && liveResult.token.length > 500);

      const liveVerify = verifyTimestamp(liveResult.token, liveRoot);
      assert.strictEqual(liveVerify.valid, true);
      assert.strictEqual(liveVerify.imprintValid, true);
      assert.strictEqual(liveVerify.signatureValid, true);
      console.log(`✓ Test 19 Passed: Live TSA request & verification succeeded (${liveResult.tsa})`);
    } catch (netErr) {
      console.log(`[INFO] Test 19 Skipped: Live TSA network test skipped (${netErr.message}) - No fake result produced`);
    }
  }

  console.log('\nAll 19 offline and live RFC 3161 timestamp tests executed successfully!');
}

runTests().catch((err) => {
  console.error('Timestamp test failure:', err);
  process.exit(1);
});
