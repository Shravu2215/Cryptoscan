'use strict';

const assert = require('assert');
const crypto = require('crypto');
const {
  prepareScanBatch,
  anchorBatchOnChain,
  verifyBatchScan,
} = require('../scripts/batchAnchor');
const { buildMerkleTree } = require('../../integrity-service/merkle');

function makeTestScan(id, content, orgId = 'acme-cyber-defense', version = '1.0.0') {
  const component = { name: 'RSA-OAEP', keyLength: 2048, content };
  const { root } = buildMerkleTree([component]);
  return {
    scanId: id,
    merkleRoot: root,
    orgId,
    scannerVersion: version,
    cbom: {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: `urn:uuid:${id}`,
      components: [component],
    },
  };
}

describe('Batch Anchoring (Phase 10)', function () {
  this.timeout(60000);

  let preparedBatch;
  let batchScans;

  before(async function () {
    const uniquePrefix = 'phase10-' + Date.now();
    batchScans = [
      makeTestScan(`${uniquePrefix}-scan-a`, 'components-for-batch-a'),
      makeTestScan(`${uniquePrefix}-scan-b`, 'components-for-batch-b'),
      makeTestScan(`${uniquePrefix}-scan-c`, 'components-for-batch-c'),
    ];

    preparedBatch = await prepareScanBatch(batchScans, { mockIpfs: true });
    await anchorBatchOnChain(preparedBatch);
  });

  it('prepares 2-scan batch manifest with IPFS CIDs and proofs', async function () {
    const scans = [
      makeTestScan('scan-001', 'payload-alpha'),
      makeTestScan('scan-002', 'payload-beta'),
    ];

    const batch = await prepareScanBatch(scans, { mockIpfs: true });

    assert.strictEqual(batch.scanCount, 2);
    assert.deepStrictEqual(batch.scanIds, ['scan-001', 'scan-002']);
    assert.strictEqual(batch.batchRoot.length, 64);
    assert.strictEqual(batch.batchRootHex, '0x' + batch.batchRoot);
    assert.ok(batch.batchId.startsWith('batch:'));
    assert.strictEqual(batch.batchIdBytes32.length, 66);

    for (const s of batch.scans) {
      assert.ok(Array.isArray(s.proof));
      assert.ok(s.proof.length > 0);
      assert.ok(s.ipfsCid && s.ipfsCid.startsWith('bafkrei'));
      assert.strictEqual(s.ipfsUri, `ipfs://${s.ipfsCid}`);
    }
  });

  it('sorts multiple scans deterministically in ascending order', async function () {
    const unorderedScans = [
      makeTestScan('scan-005', 'data-5'),
      makeTestScan('scan-002', 'data-2'),
      makeTestScan('scan-004', 'data-4'),
      makeTestScan('scan-001', 'data-1'),
      makeTestScan('scan-003', 'data-3'),
    ];

    const batch = await prepareScanBatch(unorderedScans, { mockIpfs: true });
    assert.strictEqual(batch.scanCount, 5);
    assert.deepStrictEqual(batch.scanIds, ['scan-001', 'scan-002', 'scan-003', 'scan-004', 'scan-005']);
  });

  it('generates 100% deterministic batch root regardless of input order', async function () {
    const sA = makeTestScan('s-1', 'content-a');
    const sB = makeTestScan('s-2', 'content-b');
    const sC = makeTestScan('s-3', 'content-c');

    const batch1 = await prepareScanBatch([sA, sB, sC], { mockIpfs: true });
    const batch2 = await prepareScanBatch([sC, sA, sB], { mockIpfs: true });

    assert.strictEqual(batch1.batchRoot, batch2.batchRoot);
    assert.strictEqual(batch1.batchId, batch2.batchId);
    assert.strictEqual(batch1.batchIdBytes32, batch2.batchIdBytes32);
  });

  it('successfully anchors batch root on-chain', async function () {
    assert.strictEqual(preparedBatch.scanCount, 3);
    assert.ok(preparedBatch.batchRoot.length === 64);
  });

  it('independently verifies all individual scan proofs against on-chain batch root', async function () {
    for (const scan of preparedBatch.scans) {
      const verifyRes = await verifyBatchScan(
        preparedBatch.batchId,
        scan,
        scan.proof
      );

      assert.strictEqual(verifyRes.verified, true);
      assert.strictEqual(verifyRes.proofValid, true);
      assert.strictEqual(verifyRes.onChainBatchRoot, preparedBatch.batchRoot);
      assert.strictEqual(verifyRes.scanId, scan.scanId);
      assert.ok(verifyRes.timestamp > 0);
    }
  });

  it('strictly rejects corrupted proof path', async function () {
    const targetScan = preparedBatch.scans[0];
    const corruptedProof = targetScan.proof.map((p, idx) => {
      if (idx === 0) {
        return { ...p, sibling: p.sibling.slice(0, -2) + 'aa' };
      }
      return p;
    });

    const verifyRes = await verifyBatchScan(
      preparedBatch.batchId,
      targetScan,
      corruptedProof
    );

    assert.strictEqual(verifyRes.verified, false);
    assert.strictEqual(verifyRes.proofValid, false);
    assert.ok(verifyRes.reason.includes('Merkle proof verification failed'));
  });

  it('strictly rejects modified scan record / Merkle root', async function () {
    const targetScan = preparedBatch.scans[1];
    const tamperedScan = {
      ...targetScan,
      merkleRoot: '1111111111111111111111111111111111111111111111111111111111111111',
    };

    const verifyRes = await verifyBatchScan(
      preparedBatch.batchId,
      tamperedScan,
      targetScan.proof
    );

    assert.strictEqual(verifyRes.verified, false);
    assert.strictEqual(verifyRes.proofValid, false);
  });

  it('safely returns verified: false for non-existent batch identifier', async function () {
    const nonExistentBatchId = 'batch:0000000000000000000000000000000000000000000000000000000000000000';
    const verifyRes = await verifyBatchScan(
      nonExistentBatchId,
      preparedBatch.scans[0],
      preparedBatch.scans[0].proof
    );

    assert.strictEqual(verifyRes.verified, false);
    assert.ok(verifyRes.reason.includes('does not exist on-chain'));
  });

  it('strictly rejects outsider scan claiming batch membership', async function () {
    const outsiderScan = makeTestScan('outsider-scan-999', 'outsider-components');
    const verifyRes = await verifyBatchScan(
      preparedBatch.batchId,
      outsiderScan,
      preparedBatch.scans[0].proof
    );

    assert.strictEqual(verifyRes.verified, false);
    assert.strictEqual(verifyRes.proofValid, false);
  });

  it('strictly rejects duplicate batch anchoring under contract immutability', async function () {
    await assert.rejects(
      async () => {
        await anchorBatchOnChain(preparedBatch);
      },
      /CryptoAnchor: scanId already anchored/
    );
  });

  it('associates and verifies off-chain IPFS CID metadata and CBOM content integrity', async function () {
    const scanWithCbom = {
      ...preparedBatch.scans[0],
      cbom: batchScans[0].cbom,
    };

    const verifyRes = await verifyBatchScan(
      preparedBatch.batchId,
      scanWithCbom,
      preparedBatch.scans[0].proof
    );

    assert.strictEqual(verifyRes.verified, true);
    assert.strictEqual(verifyRes.ipfsVerified, true);
    assert.ok(scanWithCbom.ipfsCid.startsWith('bafkrei'));
  });
});
