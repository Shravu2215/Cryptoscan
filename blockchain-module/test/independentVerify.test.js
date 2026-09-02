'use strict';

const assert = require('assert');
const path = require('path');
const fs = require('fs');
const {
  fetchOnChainAnchor,
  computeIndependentLeaf,
  verifyIndependentProof,
  performIndependentAudit,
} = require('../scripts/independentVerify');
const { prepareScanBatch, anchorBatchOnChain } = require('../scripts/batchAnchor');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
require('dotenv').config();

describe('Independent Verification (Phase 12)', function () {
  this.timeout(60000);

  let localRecord;
  let sepoliaRecord;
  let localRpcUrl;
  let sepoliaRpcUrl;
  let localScans;
  let localPrepared;

  const sepoliaBatchId = 'batch:bb05c48ca63e011b371e8a60aff04beedbb6040ddd81757a626e7af3e2d26d05';
  const expectedSepoliaRoot = 'bb05c48ca63e011b371e8a60aff04beedbb6040ddd81757a626e7af3e2d26d05';
  const sepoliaScans = [
    {
      scanId: 'sepolia-demo-scan-1',
      merkleRoot: 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90',
      orgId: 'cryptoscan-global',
      scannerVersion: '1.0.0',
    },
    {
      scanId: 'sepolia-demo-scan-2',
      merkleRoot: 'b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1',
      orgId: 'cryptoscan-global',
      scannerVersion: '1.0.0',
    },
  ];

  before(async function () {
    localRecord = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'deployed-localhost.json'), 'utf8'));
    sepoliaRecord = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'deployed-sepolia.json'), 'utf8'));
    localRpcUrl = process.env.PERMISSIONED_RPC_URL || 'http://127.0.0.1:8545';
    sepoliaRpcUrl = process.env.PUBLIC_RPC_URL || process.env.SEPOLIA_RPC_URL || process.env.RPC_URL;

    localScans = [
      {
        scanId: `audit-scan-1-${Date.now()}`,
        merkleRoot: '1010101010101010101010101010101010101010101010101010101010101010',
        orgId: 'audit-org',
        scannerVersion: '2.0.0',
      },
      {
        scanId: `audit-scan-2-${Date.now()}`,
        merkleRoot: '2020202020202020202020202020202020202020202020202020202020202020',
        orgId: 'audit-org',
        scannerVersion: '2.0.0',
      },
      {
        scanId: `audit-scan-3-${Date.now()}`,
        merkleRoot: '3030303030303030303030303030303030303030303030303030303030303030',
        orgId: 'audit-org',
        scannerVersion: '2.0.0',
      },
    ];

    localPrepared = await prepareScanBatch(localScans, { mockIpfs: true });
    await anchorBatchOnChain(localPrepared, { chainMode: 'permissioned' });
  });

  it('independently reads on-chain batch anchor using only address, RPC, and batchId', async function () {
    const onChain = await fetchOnChainAnchor(localRecord.address, localRpcUrl, localPrepared.batchId);
    assert.strictEqual(onChain.exists, true);
    assert.strictEqual(onChain.merkleRootClean, localPrepared.batchRoot);
    assert.ok(onChain.timestamp > 0);
  });

  it('verifies all individual scan Merkle proofs in multi-scan batch against on-chain root', async function () {
    const audit = await performIndependentAudit({
      contractAddress: localRecord.address,
      rpcUrl: localRpcUrl,
      batchId: localPrepared.batchId,
      scans: localScans,
      expectedBatchRoot: localPrepared.batchRoot,
    });

    assert.strictEqual(audit.overallPass, true);
    assert.strictEqual(audit.batchRootMatchesOnChain, true);
    assert.strictEqual(audit.expectedRootMatches, true);
    assert.strictEqual(audit.scansAuditedCount, 3);
    assert.strictEqual(audit.scansPassedCount, 3);

    for (const sv of audit.scanVerifications) {
      assert.strictEqual(sv.valid, true);
      assert.ok(sv.proofLength > 0);
    }
  });

  it('strictly rejects tampered scan data during independent verification', async function () {
    const tamperedScans = [
      localScans[0],
      { ...localScans[1], merkleRoot: '9999999999999999999999999999999999999999999999999999999999999999' },
      localScans[2],
    ];

    const auditTampered = await performIndependentAudit({
      contractAddress: localRecord.address,
      rpcUrl: localRpcUrl,
      batchId: localPrepared.batchId,
      scans: tamperedScans,
      proofs: localPrepared.scans,
    });

    assert.strictEqual(auditTampered.overallPass, false);
    assert.strictEqual(auditTampered.batchRootMatchesOnChain, false);
    assert.strictEqual(auditTampered.scansPassedCount, 2);

    const failedScan = auditTampered.scanVerifications.find((s) => s.scanId === localScans[1].scanId);
    assert.strictEqual(failedScan.valid, false);
  });

  it('strictly rejects tampered Merkle proof paths', async function () {
    const targetScan = localPrepared.scans[0];
    const corruptedProof = targetScan.proof.map((step, idx) => {
      if (idx === 0) {
        return { ...step, sibling: step.sibling.slice(0, -2) + '00' };
      }
      return step;
    });

    const res = verifyIndependentProof(targetScan, corruptedProof, localPrepared.batchRoot);
    assert.strictEqual(res.valid, false);
    assert.notStrictEqual(res.derivedRoot, res.targetRoot);
  });

  it('strictly rejects wrong or mismatched expected batch root', async function () {
    const wrongRoot = '0000000000000000000000000000000000000000000000000000000000000001';
    const auditWrong = await performIndependentAudit({
      contractAddress: localRecord.address,
      rpcUrl: localRpcUrl,
      batchId: localPrepared.batchId,
      scans: localScans,
      expectedBatchRoot: wrongRoot,
    });

    assert.strictEqual(auditWrong.overallPass, false);
    assert.strictEqual(auditWrong.expectedRootMatches, false);
  });

  it('independently queries real Sepolia batch anchor on-chain', async function () {
    const onChainSepolia = await fetchOnChainAnchor(sepoliaRecord.address, sepoliaRpcUrl, sepoliaBatchId);
    assert.strictEqual(onChainSepolia.exists, true);
    assert.strictEqual(onChainSepolia.merkleRootClean, expectedSepoliaRoot);
    assert.strictEqual(onChainSepolia.anchoredBy.toLowerCase(), '0xE516ce8b5E30aB4e3aFbb796f59cA28AaC2C7631'.toLowerCase());
    assert.ok(onChainSepolia.timestamp > 0);
  });

  it('independently audits real Sepolia batch anchor and all scan proofs with zero trust', async function () {
    const sepoliaAudit = await performIndependentAudit({
      contractAddress: sepoliaRecord.address,
      rpcUrl: sepoliaRpcUrl,
      batchId: sepoliaBatchId,
      scans: sepoliaScans,
      expectedBatchRoot: expectedSepoliaRoot,
    });

    assert.strictEqual(sepoliaAudit.overallPass, true);
    assert.strictEqual(sepoliaAudit.batchRootMatchesOnChain, true);
    assert.strictEqual(sepoliaAudit.expectedRootMatches, true);
    assert.strictEqual(sepoliaAudit.scansAuditedCount, 2);
    assert.strictEqual(sepoliaAudit.scansPassedCount, 2);

    for (const sv of sepoliaAudit.scanVerifications) {
      assert.strictEqual(sv.valid, true);
      assert.strictEqual(sv.proofLength, 1);
    }
  });

  it('rejects forged scan identity against real Sepolia batch anchor', async function () {
    const forgedSepoliaScans = [
      { ...sepoliaScans[0], scanId: 'forged-scan-name' },
      sepoliaScans[1],
    ];

    const reBatch = await prepareScanBatch(sepoliaScans, { mockIpfs: true });
    const forgedAudit = await performIndependentAudit({
      contractAddress: sepoliaRecord.address,
      rpcUrl: sepoliaRpcUrl,
      batchId: sepoliaBatchId,
      scans: forgedSepoliaScans,
      proofs: reBatch.scans,
    });

    assert.strictEqual(forgedAudit.overallPass, false);
    assert.strictEqual(forgedAudit.batchRootMatchesOnChain, false);
    assert.strictEqual(forgedAudit.scansPassedCount, 1);
  });
});
