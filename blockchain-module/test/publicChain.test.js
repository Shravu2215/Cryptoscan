'use strict';

const assert = require('assert');
const path = require('path');
const fs = require('fs');
const { ethers } = require('ethers');
const {
  prepareScanBatch,
  verifyBatchScan,
} = require('../scripts/batchAnchor');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
require('dotenv').config();

describe('Public Chain Sepolia (Phase 11)', function () {
  this.timeout(60000);

  let provider;
  let sepoliaRecord;
  let localRecord;

  const realSepoliaBatchId = 'batch:bb05c48ca63e011b371e8a60aff04beedbb6040ddd81757a626e7af3e2d26d05';
  const testScan1 = {
    scanId: 'sepolia-demo-scan-1',
    merkleRoot: 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90',
    orgId: 'cryptoscan-global',
    scannerVersion: '1.0.0',
  };
  const testScan2 = {
    scanId: 'sepolia-demo-scan-2',
    merkleRoot: 'b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1',
    orgId: 'cryptoscan-global',
    scannerVersion: '1.0.0',
  };

  before(async function () {
    const rpcUrl = process.env.PUBLIC_RPC_URL || process.env.SEPOLIA_RPC_URL || process.env.RPC_URL;
    provider = new ethers.JsonRpcProvider(rpcUrl);
    localRecord = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'deployed-localhost.json'), 'utf8'));
    sepoliaRecord = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'deployed-sepolia.json'), 'utf8'));
  });

  it('validates Sepolia RPC and Chain ID (11155111)', async function () {
    const network = await provider.getNetwork();
    assert.strictEqual(network.chainId.toString(), '11155111');
  });

  it('records localhost and Sepolia deployments separately without overwriting', function () {
    assert.strictEqual(localRecord.network, 'localhost');
    assert.strictEqual(sepoliaRecord.network, 'sepolia');
    assert.notStrictEqual(localRecord.address.toLowerCase(), sepoliaRecord.address.toLowerCase());
  });

  it('verifies Sepolia contract bytecode, owner, and writer authorization on-chain', async function () {
    const code = await provider.getCode(sepoliaRecord.address);
    assert.ok(code.length > 2);

    const artifact = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'artifacts', 'contracts', 'CryptoAnchor.sol', 'CryptoAnchor.json'), 'utf8'));
    const contract = new ethers.Contract(sepoliaRecord.address, artifact.abi, provider);

    const owner = await contract.owner();
    const signerWallet = new ethers.Wallet(process.env.PRIVATE_KEY);
    assert.strictEqual(owner.toLowerCase(), signerWallet.address.toLowerCase());

    const isWriter = await contract.authorizedWriters(owner);
    assert.strictEqual(isWriter, true);
  });

  it('confirms batch-only public semantics (aggregates scans into single root)', async function () {
    const scanA = { scanId: 'pub-test-scan-a', merkleRoot: '1111111111111111111111111111111111111111111111111111111111111111', orgId: 'pub-org', scannerVersion: '1.0.0' };
    const scanB = { scanId: 'pub-test-scan-b', merkleRoot: '2222222222222222222222222222222222222222222222222222222222222222', orgId: 'pub-org', scannerVersion: '1.0.0' };
    const batch = await prepareScanBatch([scanA, scanB], { mockIpfs: true });

    assert.strictEqual(batch.scanCount, 2);
    assert.ok(batch.batchId.startsWith('batch:'));
    assert.strictEqual(batch.batchIdBytes32.length, 66);
  });

  it('reads and independently verifies real on-chain Sepolia batch anchor', async function () {
    const reBatch = await prepareScanBatch([testScan1, testScan2], { mockIpfs: true });
    assert.strictEqual(reBatch.batchId, realSepoliaBatchId);

    const proof = reBatch.scans[0].proof;
    const verifyResult = await verifyBatchScan(realSepoliaBatchId, testScan1, proof, { chainMode: 'public' });

    assert.strictEqual(verifyResult.verified, true);
    assert.strictEqual(verifyResult.proofValid, true);
    assert.strictEqual(verifyResult.onChainBatchRoot, reBatch.batchRoot);
    assert.strictEqual(verifyResult.scanId, 'sepolia-demo-scan-1');
    assert.ok(verifyResult.timestamp > 0);
  });

  it('strictly rejects tampered scan against real Sepolia batch anchor', async function () {
    const reBatch = await prepareScanBatch([testScan1, testScan2], { mockIpfs: true });
    const proof = reBatch.scans[0].proof;
    const tamperedScan = { ...testScan1, merkleRoot: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' };
    const tamperedResult = await verifyBatchScan(realSepoliaBatchId, tamperedScan, proof, { chainMode: 'public' });

    assert.strictEqual(tamperedResult.verified, false);
    assert.strictEqual(tamperedResult.proofValid, false);
  });
});
