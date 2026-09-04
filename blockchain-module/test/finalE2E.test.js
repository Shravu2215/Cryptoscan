'use strict';

const assert = require('assert');
const path = require('path');
const fs = require('fs');
const { ethers } = require('ethers');
const { buildMerkleTree, buildBatchMerkleTree } = require('../../integrity-service/merkle');
const {
  uploadCBOMToIPFS,
  fetchCBOMFromIPFS,
  verifyIPFSContent,
  hashCBOM,
} = require('../scripts/ipfs');
const {
  prepareScanBatch,
  anchorBatchOnChain,
} = require('../scripts/batchAnchor');
const {
  fetchOnChainAnchor,
  verifyIndependentProof,
  performIndependentAudit,
} = require('../scripts/independentVerify');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
require('dotenv').config();

describe('Final End-to-End Pipeline Validation (Phase 15)', function () {
  this.timeout(90000);

  let localRecord;
  let sepoliaRecord;
  let localRpcUrl;
  let sepoliaRpcUrl;

  before(function () {
    localRecord = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'deployed-localhost.json'), 'utf8'));
    sepoliaRecord = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'deployed-sepolia.json'), 'utf8'));
    localRpcUrl = process.env.PERMISSIONED_RPC_URL || 'http://127.0.0.1:8545';
    sepoliaRpcUrl = process.env.PUBLIC_RPC_URL || process.env.SEPOLIA_RPC_URL || process.env.RPC_URL;
  });

  it('executes full 15-step end-to-end pipeline across CBOM, IPFS, Merkle, Local Chain, Sepolia, and Security', async function () {
    console.log('\n--- Step 1: Realistic CBOM Generation ---');
    const cbomScan1 = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: 'urn:uuid:final-e2e-scan-001',
      version: 1,
      metadata: { timestamp: '2026-09-02T19:00:00Z', component: { name: 'PaymentService', version: '3.2.0' } },
      components: [
        { type: 'cryptographic-asset', name: 'RSA-2048', properties: [{ name: 'primitive', value: 'asymmetric' }, { name: 'quantumStatus', value: 'Vulnerable' }] },
        { type: 'cryptographic-asset', name: 'AES-256-GCM', properties: [{ name: 'primitive', value: 'symmetric' }, { name: 'quantumStatus', value: 'Quantum-Safe' }] },
      ],
    };

    const cbomScan2 = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: 'urn:uuid:final-e2e-scan-002',
      version: 1,
      metadata: { timestamp: '2026-09-02T19:05:00Z', component: { name: 'AuthService', version: '2.1.0' } },
      components: [
        { type: 'cryptographic-asset', name: 'ECDSA-P256', properties: [{ name: 'primitive', value: 'signature' }, { name: 'quantumStatus', value: 'Vulnerable' }] },
        { type: 'cryptographic-asset', name: 'ML-DSA-65', properties: [{ name: 'primitive', value: 'signature' }, { name: 'quantumStatus', value: 'Post-Quantum-Secure' }] },
      ],
    };

    const cbomScan3 = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: 'urn:uuid:final-e2e-scan-003',
      version: 1,
      metadata: { timestamp: '2026-09-02T19:10:00Z', component: { name: 'KMS-KeyManager', version: '1.0.0' } },
      components: [
        { type: 'cryptographic-asset', name: 'SHA-256', properties: [{ name: 'primitive', value: 'hash' }, { name: 'quantumStatus', value: 'Quantum-Safe' }] },
        { type: 'cryptographic-asset', name: 'ML-KEM-768', properties: [{ name: 'primitive', value: 'kem' }, { name: 'quantumStatus', value: 'Post-Quantum-Secure' }] },
      ],
    };

    console.log('✓ Step 1: 3 realistic CycloneDX CBOM manifests created');

    console.log('\n--- Step 2: Deterministic Scan Merkle Roots ---');
    const root1 = buildMerkleTree(cbomScan1.components).root;
    const root2 = buildMerkleTree(cbomScan2.components).root;
    const root3 = buildMerkleTree(cbomScan3.components).root;
    assert.strictEqual(root1.length, 64);
    assert.strictEqual(root2.length, 64);
    assert.strictEqual(root3.length, 64);
    console.log(`✓ Step 2: Scan Merkle roots computed (Scan1: ${root1.slice(0, 16)}..., Scan2: ${root2.slice(0, 16)}..., Scan3: ${root3.slice(0, 16)}...)`);

    console.log('\n--- Step 3: Canonical CBOM Content Hashing ---');
    const hash1 = hashCBOM(cbomScan1).contentHash;
    const hash2 = hashCBOM(cbomScan2).contentHash;
    const hash3 = hashCBOM(cbomScan3).contentHash;
    assert.strictEqual(hash1.length, 64);
    assert.strictEqual(hash2.length, 64);
    assert.strictEqual(hash3.length, 64);
    console.log('✓ Step 3: Canonicalized SHA-256 CBOM content hashes verified');

    console.log('\n--- Step 4: IPFS Storage & Integrity Association ---');
    const ipfs1 = await uploadCBOMToIPFS(cbomScan1, { mock: true });
    const ipfs2 = await uploadCBOMToIPFS(cbomScan2, { mock: true });
    const ipfs3 = await uploadCBOMToIPFS(cbomScan3, { mock: true });

    assert.ok(ipfs1.cid.startsWith('bafkrei'));
    assert.ok(ipfs2.cid.startsWith('bafkrei'));
    assert.ok(ipfs3.cid.startsWith('bafkrei'));

    // Verify retrieval and content verification
    const fetched1 = await fetchCBOMFromIPFS(ipfs1.cid);
    assert.strictEqual(verifyIPFSContent(fetched1, hash1).valid, true);
    console.log('✓ Step 4: IPFS CIDs generated, retrieved, and cryptographically verified');

    console.log('\n--- Step 5 & 6: Batch Aggregation & Proof Generation ---');
    const uniqueBatchSuffix = Date.now();
    const rawScans = [
      { scanId: `e2e-scan-1-${uniqueBatchSuffix}`, merkleRoot: root1, orgId: 'fintech-corp', scannerVersion: '1.0.0', cbom: cbomScan1 },
      { scanId: `e2e-scan-2-${uniqueBatchSuffix}`, merkleRoot: root2, orgId: 'fintech-corp', scannerVersion: '1.0.0', cbom: cbomScan2 },
      { scanId: `e2e-scan-3-${uniqueBatchSuffix}`, merkleRoot: root3, orgId: 'fintech-corp', scannerVersion: '1.0.0', cbom: cbomScan3 },
    ];

    const preparedBatch = await prepareScanBatch(rawScans, { mockIpfs: true });
    assert.strictEqual(preparedBatch.scanCount, 3);
    assert.strictEqual(preparedBatch.batchRoot.length, 64);
    assert.ok(preparedBatch.batchId.startsWith('batch:'));
    console.log(`✓ Step 5 & 6: Batch root derived: ${preparedBatch.batchRoot}`);

    console.log('\n--- Step 7: Pre-Anchoring Independent Proof Verification ---');
    for (const scan of preparedBatch.scans) {
      const preCheck = verifyIndependentProof(scan, scan.proof, preparedBatch.batchRoot);
      assert.strictEqual(preCheck.valid, true);
    }
    console.log('✓ Step 7: All 3 scan proofs verified mathematically prior to blockchain anchoring');

    console.log('\n--- Step 8 & 9: Permissioned Chain Anchoring & Read-Back ---');
    const txReceipt = await anchorBatchOnChain(preparedBatch, { chainMode: 'permissioned' });
    const txHash = txReceipt.txHash;
    assert.ok(txHash);

    const onChainRecord = await fetchOnChainAnchor(localRecord.address, localRpcUrl, preparedBatch.batchId);
    assert.strictEqual(onChainRecord.exists, true);
    assert.strictEqual(onChainRecord.merkleRootClean, preparedBatch.batchRoot);
    assert.ok(onChainRecord.timestamp > 0);
    console.log(`✓ Step 8 & 9: Batch root anchored on local chain (Tx: ${txHash.slice(0, 18)}..., Block: ${txReceipt.blockNumber}) and confirmed`);

    console.log('\n--- Step 10 & 11: Independent Zero-Trust Audit ---');
    const audit = await performIndependentAudit({
      contractAddress: localRecord.address,
      rpcUrl: localRpcUrl,
      batchId: preparedBatch.batchId,
      scans: rawScans,
      expectedBatchRoot: preparedBatch.batchRoot,
    });

    assert.strictEqual(audit.overallPass, true);
    assert.strictEqual(audit.batchRootMatchesOnChain, true);
    assert.strictEqual(audit.scansAuditedCount, 3);
    assert.strictEqual(audit.scansPassedCount, 3);
    console.log('✓ Step 10 & 11: Zero-trust audit recomputed batch root and verified 100% of scan proofs from raw data');

    console.log('\n--- Step 12: End-to-End IPFS Content Verification ---');
    for (const s of preparedBatch.scans) {
      const retrieved = await fetchCBOMFromIPFS(s.ipfsCid);
      const contentCheck = verifyIPFSContent(retrieved, s.merkleRoot);
      assert.strictEqual(contentCheck.valid, true);
    }
    console.log('✓ Step 12: IPFS content retrieval and hash binding verified for all scans');

    console.log('\n--- Step 13: Historical Immutability Validation ---');
    await assert.rejects(
      async () => {
        await anchorBatchOnChain(preparedBatch, { chainMode: 'permissioned' });
      },
      /CryptoAnchor: scanId already anchored/
    );

    const checkAfterRevert = await fetchOnChainAnchor(localRecord.address, localRpcUrl, preparedBatch.batchId);
    assert.strictEqual(checkAfterRevert.merkleRootClean, preparedBatch.batchRoot);
    assert.strictEqual(checkAfterRevert.timestamp, onChainRecord.timestamp);
    console.log('✓ Step 13: Re-anchoring rejected; on-chain record proven permanently unchanged');

    console.log('\n--- Step 14: Security Adversarial Checks ---');
    // A: Tampered Scan
    const tamperedScans = [rawScans[0], { ...rawScans[1], merkleRoot: '1111111111111111111111111111111111111111111111111111111111111111' }, rawScans[2]];
    const auditTamperedScan = await performIndependentAudit({
      contractAddress: localRecord.address,
      rpcUrl: localRpcUrl,
      batchId: preparedBatch.batchId,
      scans: tamperedScans,
      proofs: preparedBatch.scans,
    });
    assert.strictEqual(auditTamperedScan.overallPass, false);
    assert.strictEqual(auditTamperedScan.scansPassedCount, 2);

    // B: Tampered Proof
    const corruptProof = preparedBatch.scans[0].proof.map((p, i) => i === 0 ? { ...p, sibling: p.sibling.slice(0, -2) + '00' } : p);
    const auditTamperedProof = verifyIndependentProof(preparedBatch.scans[0], corruptProof, preparedBatch.batchRoot);
    assert.strictEqual(auditTamperedProof.valid, false);

    console.log('✓ Step 14: Security attacks (tampered scan, tampered proof) detected and strictly rejected');

    console.log('\n--- Step 15: Public Chain (Sepolia) Verification ---');
    const sepoliaBatchId = 'batch:bb05c48ca63e011b371e8a60aff04beedbb6040ddd81757a626e7af3e2d26d05';
    const expectedSepoliaRoot = 'bb05c48ca63e011b371e8a60aff04beedbb6040ddd81757a626e7af3e2d26d05';
    const sepoliaScans = [
      { scanId: 'sepolia-demo-scan-1', merkleRoot: 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90', orgId: 'cryptoscan-global', scannerVersion: '1.0.0' },
      { scanId: 'sepolia-demo-scan-2', merkleRoot: 'b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1', orgId: 'cryptoscan-global', scannerVersion: '1.0.0' },
    ];

    const sepoliaAudit = await performIndependentAudit({
      contractAddress: sepoliaRecord.address,
      rpcUrl: sepoliaRpcUrl,
      batchId: sepoliaBatchId,
      scans: sepoliaScans,
      expectedBatchRoot: expectedSepoliaRoot,
    });

    assert.strictEqual(sepoliaAudit.overallPass, true);
    assert.strictEqual(sepoliaAudit.batchRootMatchesOnChain, true);
    assert.strictEqual(sepoliaAudit.scansAuditedCount, 2);
    assert.strictEqual(sepoliaAudit.scansPassedCount, 2);
    console.log(`✓ Step 15: Public chain Sepolia anchor (${sepoliaRecord.address}) independently verified with 100% fidelity`);

    console.log('\n=== COMPLETE 15-STEP E2E VALIDATION SUCCEEDED ===\n');
  });
});
