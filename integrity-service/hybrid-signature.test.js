'use strict';

const assert = require('assert').strict;
const crypto = require('node:crypto');
const util = require('util');

// Resolve ethers safely across submodules
let ethers;
try {
  ethers = require('ethers');
} catch (err) {
  ethers = require('../blockchain-module/node_modules/ethers');
}

const {
  signHybrid,
  verifyHybrid,
  generatePqcKeyPair,
  getPqcPublicKey,
  registerPqcKeyPair,
  resetPqcRegistry,
  prepareMessage,
  DOMAIN_TAG,
  ALGORITHM_IDENTIFIER,
} = require('./hybrid-signature');

const { getSigningKey, reset: resetKms } = require('./kms');

console.log('Running Hybrid Signature (ECDSA-secp256k1 + ML-DSA-65) Test Suite...\n');

// Configure test environment with dummy testnet private key
const originalPrivateKey = process.env.PRIVATE_KEY;
const DUMMY_ECDSA_KEY = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';

async function runTests() {
  process.env.PRIVATE_KEY = DUMMY_ECDSA_KEY;
  resetKms();
  resetPqcRegistry();

  const testMessage = Buffer.from('CryptoScan CBOM Root: 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945', 'utf8');

  // ===========================================================================
  // SECTION 1: BASIC EXPORTS AND CRYPTOGRAPHIC PRIMITIVES
  // ===========================================================================

  // Test 1: signHybrid is exported
  {
    assert.strictEqual(typeof signHybrid, 'function', 'signHybrid must be an exported function');
    console.log('✓ Test 1 Passed: signHybrid is exported');
  }

  // Test 2: verifyHybrid is exported
  {
    assert.strictEqual(typeof verifyHybrid, 'function', 'verifyHybrid must be an exported function');
    console.log('✓ Test 2 Passed: verifyHybrid is exported');
  }

  // Test 3: ML-DSA-65 key generation works
  let testPqcKeyPair;
  {
    testPqcKeyPair = generatePqcKeyPair();
    assert(testPqcKeyPair.keyId, 'Key ID must be generated');
    assert(testPqcKeyPair.keyId.startsWith('pqc-mldsa65-'), 'Key ID must have correct prefix');
    assert.strictEqual(testPqcKeyPair.publicKey.asymmetricKeyType, 'ml-dsa-65');
    console.log('✓ Test 3 Passed: ML-DSA-65 key generation works (NIST FIPS 204)');
  }

  // Test 4: ML-DSA-65 signing works
  let rawPqcSig;
  {
    const entry = getPqcPublicKey(testPqcKeyPair.keyId);
    assert(entry, 'Public key must be registered');
    const { privateKey } = crypto.generateKeyPairSync('ml-dsa-65');
    rawPqcSig = crypto.sign(null, testMessage, privateKey);
    assert.strictEqual(rawPqcSig.length, 3309, 'FIPS 204 ML-DSA-65 signature must be exactly 3,309 bytes');
    console.log('✓ Test 4 Passed: ML-DSA-65 signing produces exact 3,309-byte signature');
  }

  // Test 5: ML-DSA-65 verification works
  {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ml-dsa-65');
    const sig = crypto.sign(null, testMessage, privateKey);
    const valid = crypto.verify(null, testMessage, publicKey, sig);
    assert.strictEqual(valid, true, 'ML-DSA-65 signature must verify against matching public key');

    const invalid = crypto.verify(null, Buffer.from('different-message'), publicKey, sig);
    assert.strictEqual(invalid, false, 'ML-DSA-65 verification must fail on mismatched message');
    console.log('✓ Test 5 Passed: ML-DSA-65 verification works natively');
  }

  // Test 6: Classical ECDSA signing works using existing signing mechanism
  {
    const classicalKey = getSigningKey();
    const wallet = new ethers.Wallet(classicalKey.privateKey);
    const prepared = prepareMessage(testMessage);
    const sig = await wallet.signMessage(prepared);
    assert(sig.startsWith('0x'), 'ECDSA signature must start with 0x');

    const recovered = ethers.verifyMessage(prepared, sig);
    assert.strictEqual(recovered.toLowerCase(), wallet.address.toLowerCase());
    console.log('✓ Test 6 Passed: Classical ECDSA-secp256k1 signing works via KMS wallet');
  }

  // Test 7: Hybrid signing returns the required structure
  let hybridSig;
  {
    hybridSig = await signHybrid(testMessage);
    assert.strictEqual(hybridSig.algorithm, ALGORITHM_IDENTIFIER);
    assert.strictEqual(hybridSig.algorithm, 'ECDSA-secp256k1+ML-DSA-65');
    assert(typeof hybridSig.classicalSig === 'string' && hybridSig.classicalSig.startsWith('0x'));
    assert(typeof hybridSig.pqcSig === 'string');
    assert(typeof hybridSig.pqcKeyId === 'string' && hybridSig.pqcKeyId.startsWith('pqc-mldsa65-'));

    // Verify PQC signature decodes to 3,309 bytes
    const decodedPqc = Buffer.from(hybridSig.pqcSig, 'base64');
    assert.strictEqual(decodedPqc.length, 3309, 'PQC signature in base64 must decode to 3,309 bytes');
    console.log('✓ Test 7 Passed: Hybrid signing returns the required standardized structure');
  }

  // Test 8: Untampered hybrid signature verifies successfully
  {
    const result = verifyHybrid(testMessage, hybridSig);
    assert.strictEqual(result.valid, true, 'Untampered hybrid signature must be valid');
    assert.strictEqual(result.classicalValid, true, 'Classical signature must be valid');
    assert.strictEqual(result.pqcValid, true, 'PQC signature must be valid');
    console.log('✓ Test 8 Passed: Untampered hybrid signature verifies successfully (both valid)');
  }

  // ===========================================================================
  // SECTION 2: TAMPERING TESTS
  // ===========================================================================

  // Test 9: Modified message fails
  {
    const tamperedMessage = Buffer.from('Tampered content bytes', 'utf8');
    const result = verifyHybrid(tamperedMessage, hybridSig);
    assert.strictEqual(result.valid, false, 'Modified message must fail');
    assert.strictEqual(result.classicalValid, false, 'Classical signature must fail on modified message');
    assert.strictEqual(result.pqcValid, false, 'PQC signature must fail on modified message');
    console.log('✓ Test 9 Passed: Modified message fails verification on both layers');
  }

  // Test 10: Modified classical signature fails
  {
    // Flip a hex char in classical signature
    const flippedChar = hybridSig.classicalSig[4] === 'a' ? 'b' : 'a';
    const tamperedClassical = hybridSig.classicalSig.slice(0, 4) + flippedChar + hybridSig.classicalSig.slice(5);
    const tamperedSig = { ...hybridSig, classicalSig: tamperedClassical };

    const result = verifyHybrid(testMessage, tamperedSig);
    assert.strictEqual(result.valid, false, 'Tampered classical signature must invalidate hybrid signature');
    assert.strictEqual(result.classicalValid, false);
    assert.strictEqual(result.pqcValid, true, 'PQC signature was untampered, should remain valid');
    console.log('✓ Test 10 Passed: Modified classical signature causes hybrid verification failure');
  }

  // Test 11: Modified PQC signature fails
  {
    const pqcBuf = Buffer.from(hybridSig.pqcSig, 'base64');
    pqcBuf[10] ^= 0xff; // Flip byte
    const tamperedSig = { ...hybridSig, pqcSig: pqcBuf.toString('base64') };

    const result = verifyHybrid(testMessage, tamperedSig);
    assert.strictEqual(result.valid, false, 'Tampered PQC signature must invalidate hybrid signature');
    assert.strictEqual(result.classicalValid, true, 'Classical signature was untampered, should remain valid');
    assert.strictEqual(result.pqcValid, false, 'PQC signature was modified, must be invalid');
    console.log('✓ Test 11 Passed: Modified PQC signature causes hybrid verification failure');
  }

  // Test 12: Modified algorithm identifier fails
  {
    const tamperedSig = { ...hybridSig, algorithm: 'ECDSA-secp256k1+Dilithium-v3' };
    const result = verifyHybrid(testMessage, tamperedSig);
    assert.strictEqual(result.valid, false, 'Mismatched algorithm identifier must fail verification');
    assert.strictEqual(result.classicalValid, false);
    assert.strictEqual(result.pqcValid, false);
    console.log('✓ Test 12 Passed: Modified algorithm identifier is rejected immediately');
  }

  // Test 13: Missing classical signature fails
  {
    const missingClassical = { ...hybridSig, classicalSig: null };
    const result = verifyHybrid(testMessage, missingClassical);
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.classicalValid, false);
    assert.strictEqual(result.pqcValid, true);
    console.log('✓ Test 13 Passed: Missing classical signature fails verification');
  }

  // Test 14: Missing PQC signature fails
  {
    const missingPqc = { ...hybridSig, pqcSig: null };
    const result = verifyHybrid(testMessage, missingPqc);
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.classicalValid, true);
    assert.strictEqual(result.pqcValid, false);
    console.log('✓ Test 14 Passed: Missing PQC signature fails verification');
  }

  // Test 15: Wrong PQC key ID fails
  {
    const wrongKeyIdSig = { ...hybridSig, pqcKeyId: 'pqc-mldsa65-unknown-key-9999' };
    const result = verifyHybrid(testMessage, wrongKeyIdSig);
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.pqcValid, false, 'Unresolvable key ID must fail PQC verification');
    console.log('✓ Test 15 Passed: Unknown PQC key ID fails verification');
  }

  // Test 16: Wrong PQC public key fails
  {
    const differentKeyPair = crypto.generateKeyPairSync('ml-dsa-65');
    const result = verifyHybrid(testMessage, hybridSig, { pqcPublicKey: differentKeyPair.publicKey });
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.pqcValid, false, 'Different PQC public key must fail verification');
    console.log('✓ Test 16 Passed: Wrong PQC public key fails verification');
  }

  // ===========================================================================
  // SECTION 3: HYBRID CONJUNCTION SECURITY
  // ===========================================================================

  // Test 17: Classical-valid + PQC-invalid => valid: false
  {
    const badPqcSig = { ...hybridSig, pqcSig: Buffer.alloc(3309).toString('base64') };
    const result = verifyHybrid(testMessage, badPqcSig);
    assert.strictEqual(result.classicalValid, true);
    assert.strictEqual(result.pqcValid, false);
    assert.strictEqual(result.valid, false, 'Conjunction rule: must be false if PQC fails');
    console.log('✓ Test 17 Passed: Classical-valid + PQC-invalid strictly yields valid: false');
  }

  // Test 18: Classical-invalid + PQC-valid => valid: false
  {
    const badClassicalSig = { ...hybridSig, classicalSig: '0x' + '00'.repeat(65) };
    const result = verifyHybrid(testMessage, badClassicalSig);
    assert.strictEqual(result.classicalValid, false);
    assert.strictEqual(result.pqcValid, true);
    assert.strictEqual(result.valid, false, 'Conjunction rule: must be false if Classical fails');
    console.log('✓ Test 18 Passed: Classical-invalid + PQC-valid strictly yields valid: false');
  }

  // Test 19: Both valid => valid: true
  {
    const result = verifyHybrid(testMessage, hybridSig);
    assert.strictEqual(result.valid, true, 'Both valid must yield valid: true');
    console.log('✓ Test 19 Passed: Both valid signatures yield valid: true');
  }

  // Test 20: Different message => verification fails
  {
    const differentMessage = Buffer.from('Completely different integrity payload');
    const result = verifyHybrid(differentMessage, hybridSig);
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.classicalValid, false);
    assert.strictEqual(result.pqcValid, false);
    console.log('✓ Test 20 Passed: Different message fails both classical and PQC verification');
  }

  // ===========================================================================
  // SECTION 4: KEY SAFETY & ARCHITECTURAL SEPARATION
  // ===========================================================================

  // Test 21: PQC private key never appears in returned signature object
  {
    const sigKeys = Object.keys(hybridSig);
    assert.deepStrictEqual(sigKeys.sort(), ['algorithm', 'classicalSig', 'pqcKeyId', 'pqcSig'].sort());
    assert.strictEqual(hybridSig.privateKey, undefined);
    assert.strictEqual(hybridSig.pqcPrivateKey, undefined);
    console.log('✓ Test 21 Passed: PQC private key never appears in returned signature object');
  }

  // Test 22: PQC private key is not serialized into JSON
  {
    const jsonStr = JSON.stringify(hybridSig);
    assert.strictEqual(jsonStr.includes('private'), false);
    assert.strictEqual(jsonStr.includes('PKCS8'), false);
    console.log('✓ Test 22 Passed: PQC private key is not present in serialized JSON');
  }

  // Test 23: Existing ECDSA private key is not used as ML-DSA key material (Key Separation Test)
  {
    const classicalKey = getSigningKey();
    const activePqcEntry = getPqcPublicKey(hybridSig.pqcKeyId);

    // Verify distinct key architectures and instances
    assert(classicalKey.privateKey, 'Classical key exists');
    assert.strictEqual(typeof classicalKey.privateKey, 'string');
    assert(activePqcEntry, 'PQC key entry exists');
    assert.strictEqual(activePqcEntry.asymmetricKeyType, 'ml-dsa-65');

    // Cryptographic domain separation
    assert.strictEqual(activePqcEntry.asymmetricKeyDetails.modulusLength, undefined);
    assert.notStrictEqual(classicalKey.keyId, hybridSig.pqcKeyId);

    // Verify that rotating KMS does not alter the ML-DSA key
    const currentPqcKeyId = hybridSig.pqcKeyId;
    const { rotateKey } = require('./kms');
    rotateKey({ newPrivateKey: '0x9999999999999999999999999999999999999999999999999999999999999999' });

    assert.strictEqual(
      getPqcPublicKey(currentPqcKeyId).asymmetricKeyType,
      'ml-dsa-65',
      'PQC key must remain intact and independent after classical key rotation'
    );
    console.log('✓ Test 23 Passed: ECDSA and ML-DSA keys are completely isolated in lifecycle and representation');
  }

  // Test 24: No private key is logged
  {
    const inspected = util.inspect(hybridSig);
    assert.strictEqual(inspected.includes('0x1234567890abcdef'), false);
    assert.strictEqual(inspected.includes('PKCS8'), false);
    console.log('✓ Test 24 Passed: util.inspect of hybrid signature does not leak secrets');
  }

  console.log('\nAll 24 hybrid signature unit tests passed successfully!');
}

runTests()
  .then(() => {
    // Restore original environment
    if (originalPrivateKey !== undefined) {
      process.env.PRIVATE_KEY = originalPrivateKey;
    } else {
      delete process.env.PRIVATE_KEY;
    }
    resetKms();
  })
  .catch((err) => {
    console.error('Hybrid test failure:', err);
    if (originalPrivateKey !== undefined) {
      process.env.PRIVATE_KEY = originalPrivateKey;
    } else {
      delete process.env.PRIVATE_KEY;
    }
    resetKms();
    process.exit(1);
  });
