'use strict';

const assert = require('assert').strict;
const util = require('util');
let ethers;
try {
  ethers = require('ethers');
} catch (err) {
  ethers = require('../blockchain-module/node_modules/ethers');
}
const {
  getSigningKey,
  rotateKey,
  getKeyInfo,
  getKeyById,
  reset,
  kms,
} = require('./kms');

console.log('Running KMS Key Management Wrapper Test Suite...\n');

// Backup environment variables
const originalPrivateKey = process.env.PRIVATE_KEY;
const originalRotatedKey = process.env.ROTATED_PRIVATE_KEY;

// Controlled test secrets (dummy testnet values, never real secrets)
const DUMMY_KEY_V1 = '0x1111111111111111111111111111111111111111111111111111111111111111';
const DUMMY_KEY_V2 = '0x2222222222222222222222222222222222222222222222222222222222222222';

try {
  // ---------------------------------------------------------------------------
  // Test 1: getSigningKey() exists
  // ---------------------------------------------------------------------------
  {
    assert.strictEqual(typeof getSigningKey, 'function', 'getSigningKey must be a function');
    assert.strictEqual(typeof kms.getSigningKey, 'function', 'kms.getSigningKey must be a function');
    console.log('✓ Test 1 Passed: getSigningKey() is exported and callable');
  }

  // ---------------------------------------------------------------------------
  // Test 2: Missing configuration produces a clear error
  // ---------------------------------------------------------------------------
  {
    delete process.env.PRIVATE_KEY;
    reset();

    assert.throws(
      () => getSigningKey(),
      (err) => {
        assert(err instanceof Error);
        assert.strictEqual(
          err.message,
          'Signing key not configured — refusing to sign without a real signer'
        );
        return true;
      },
      'Test 2 Failed: Missing PRIVATE_KEY must throw expected error'
    );
    console.log('✓ Test 2 Passed: Missing configuration produces a clear, secure error');
  }

  // ---------------------------------------------------------------------------
  // Test 3: A configured key can be retrieved through the wrapper
  // ---------------------------------------------------------------------------
  {
    process.env.PRIVATE_KEY = DUMMY_KEY_V1;
    reset();

    const key = getSigningKey();
    assert(key, 'Signing key object must be returned');
    assert.strictEqual(
      key.privateKey,
      DUMMY_KEY_V1,
      'Retrieved private key must match configured secret'
    );
    console.log('✓ Test 3 Passed: Configured key successfully retrieved through wrapper');
  }

  // ---------------------------------------------------------------------------
  // Test 4: Key ID does not expose the private key
  // ---------------------------------------------------------------------------
  {
    const key = getSigningKey();
    assert.strictEqual(typeof key.keyId, 'string');
    assert.strictEqual(
      key.keyId.includes('1111111111111111'),
      false,
      'Key ID must NOT contain or derive from private key'
    );
    assert.strictEqual(key.keyId, 'local-demo-key-v1');
    console.log('✓ Test 4 Passed: Key ID is opaque and does not expose private key');
  }

  // ---------------------------------------------------------------------------
  // Test 5: rotateKey() exists
  // ---------------------------------------------------------------------------
  {
    assert.strictEqual(typeof rotateKey, 'function', 'rotateKey must be a function');
    assert.strictEqual(typeof kms.rotateKey, 'function', 'kms.rotateKey must be a function');
    console.log('✓ Test 5 Passed: rotateKey() is exported and callable');
  }

  // ---------------------------------------------------------------------------
  // Test 6: Rotation behavior is deterministic and does not silently break configuration
  // ---------------------------------------------------------------------------
  {
    // Calling rotateKey without a replacement key must throw without invalidating active key
    delete process.env.ROTATED_PRIVATE_KEY;
    assert.throws(
      () => rotateKey(),
      (err) => {
        assert(err instanceof Error);
        assert(
          err.message.includes('Key rotation requires an explicit new private key'),
          'Error must explain that explicit key is required to avoid breaking active wallet'
        );
        return true;
      }
    );

    // Active key remains valid and unchanged
    assert.strictEqual(getSigningKey().keyId, 'local-demo-key-v1');
    assert.strictEqual(getSigningKey().privateKey, DUMMY_KEY_V1);

    // Controlled explicit rotation
    const receipt = rotateKey({ newPrivateKey: DUMMY_KEY_V2 });
    assert.strictEqual(receipt.status, 'ROTATED');
    assert.strictEqual(receipt.keyId, 'local-demo-key-v2');
    assert.strictEqual(receipt.previousKeyId, 'local-demo-key-v1');

    // New active key is returned by getSigningKey()
    const active = getSigningKey();
    assert.strictEqual(active.keyId, 'local-demo-key-v2');
    assert.strictEqual(active.privateKey, DUMMY_KEY_V2);

    // Historical key is retained for auditing past signatures
    const oldKey = getKeyById('local-demo-key-v1');
    assert(oldKey, 'Old key must be preserved in history');
    assert.strictEqual(oldKey.keyId, 'local-demo-key-v1');
    assert.strictEqual(oldKey.privateKey, DUMMY_KEY_V1);

    console.log('✓ Test 6 Passed: Rotation is explicit, controlled, and preserves historical keys');
  }

  // ---------------------------------------------------------------------------
  // Test 7: Private key is never printed by the module
  // ---------------------------------------------------------------------------
  {
    const key = getSigningKey();

    // util.inspect (used by console.log)
    const inspected = util.inspect(key);
    assert.strictEqual(
      inspected.includes('2222222222222222'),
      false,
      'util.inspect must NOT contain raw private key'
    );
    assert(inspected.includes('[REDACTED]'), 'util.inspect must show [REDACTED]');

    // JSON.stringify
    const jsonStr = JSON.stringify(key);
    assert.strictEqual(
      jsonStr.includes('2222222222222222'),
      false,
      'JSON.stringify must NOT contain raw private key'
    );
    assert.deepStrictEqual(JSON.parse(jsonStr), { keyId: 'local-demo-key-v2' });

    // String conversion
    const strRep = String(key);
    assert.strictEqual(
      strRep.includes('2222222222222222'),
      false,
      'String(key) must NOT contain raw private key'
    );

    // Metadata endpoint
    const info = getKeyInfo();
    assert.strictEqual(info.keyId, 'local-demo-key-v2');
    assert.strictEqual(
      JSON.stringify(info).includes('2222222222222222'),
      false,
      'getKeyInfo() must not leak secret'
    );

    console.log('✓ Test 7 Passed: Private key is masked and strictly redacted across all representations');
  }

  // ---------------------------------------------------------------------------
  // Test 8: Signing interoperability with ethers.Wallet
  // ---------------------------------------------------------------------------
  {
    const signingKey = getSigningKey();
    const wallet = new ethers.Wallet(signingKey.privateKey);

    assert(wallet.address, 'Wallet must have an address');

    // Test that wallet can sign messages with the KMS-provided key
    const messageHash = ethers.id('CryptoScan-KMS-Integration-Test');
    const signature = wallet.signMessageSync(ethers.getBytes(messageHash));
    assert(signature.startsWith('0x'), 'Signature must be a valid hex string');

    // Verify signature matches wallet address
    const recoveredAddress = ethers.verifyMessage(ethers.getBytes(messageHash), signature);
    assert.strictEqual(
      recoveredAddress.toLowerCase(),
      wallet.address.toLowerCase(),
      'Recovered address must match wallet address'
    );

    console.log('✓ Test 8 Passed: KMS key integrates seamlessly with ethers.Wallet and message signing');
  }

  console.log('\nAll 8 KMS tests passed successfully!');
} finally {
  // Restore original environment
  if (originalPrivateKey !== undefined) {
    process.env.PRIVATE_KEY = originalPrivateKey;
  } else {
    delete process.env.PRIVATE_KEY;
  }

  if (originalRotatedKey !== undefined) {
    process.env.ROTATED_PRIVATE_KEY = originalRotatedKey;
  } else {
    delete process.env.ROTATED_PRIVATE_KEY;
  }

  reset();
}
