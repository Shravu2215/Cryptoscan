'use strict';

const assert = require('assert');
const path = require('path');
const fs = require('fs');
const { ethers } = require('ethers');
const {
  fetchOnChainAnchor,
} = require('../scripts/independentVerify');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
require('dotenv').config();

describe('Historical Anchoring & Immutability (Phase 13)', function () {
  this.timeout(60000);

  let contract;
  let owner;
  let writer;
  let provider;
  let sepoliaRecord;
  let sepoliaRpcUrl;

  before(async function () {
    const [deployer, writerAccount] = await hre.ethers.getSigners();
    owner = deployer;
    writer = writerAccount;

    const CryptoAnchor = await hre.ethers.getContractFactory('CryptoAnchor');
    contract = await CryptoAnchor.deploy();
    await contract.waitForDeployment();

    sepoliaRecord = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'deployed-sepolia.json'), 'utf8'));
    sepoliaRpcUrl = process.env.PUBLIC_RPC_URL || process.env.SEPOLIA_RPC_URL || process.env.RPC_URL;
  });

  function makeScanId(label) {
    return ethers.keccak256(ethers.toUtf8Bytes(label));
  }

  function makeRoot(hexChar) {
    return '0x' + hexChar.repeat(64);
  }

  it('preserves historical data when attempting to re-anchor same scanId with SAME root', async function () {
    const scanId = makeScanId('history-scan-same-root');
    const root = makeRoot('a');
    const orgId = 'acme-cyber-defense';
    const version = '1.0.0';

    // 1. Initial Anchor
    const tx = await contract.anchorScan(scanId, root, orgId, version);
    await tx.wait();

    // Take snapshot of initial record
    const [initialRoot, initialBy, initialTs, initialOrg, initialVer, initialExists] =
      await contract.getAnchor(scanId);

    assert.strictEqual(initialExists, true);
    assert.strictEqual(initialRoot, root);
    assert.strictEqual(initialBy, owner.address);
    assert.ok(initialTs > 0n);
    assert.strictEqual(initialOrg, orgId);
    assert.strictEqual(initialVer, version);

    // 2. Attempt duplicate anchor with identical data -> MUST REVERT
    await assert.rejects(
      async () => {
        await contract.anchorScan(scanId, root, orgId, version);
      },
      /CryptoAnchor: scanId already anchored/
    );

    // 3. Verify original record remains completely untouched
    const [afterRoot, afterBy, afterTs, afterOrg, afterVer, afterExists] =
      await contract.getAnchor(scanId);

    assert.strictEqual(afterRoot, initialRoot);
    assert.strictEqual(afterBy, initialBy);
    assert.strictEqual(afterTs, initialTs);
    assert.strictEqual(afterOrg, initialOrg);
    assert.strictEqual(afterVer, initialVer);
    assert.strictEqual(afterExists, initialExists);
  });

  it('preserves historical data when attempting to re-anchor same scanId with DIFFERENT root', async function () {
    const scanId = makeScanId('history-scan-diff-root');
    const root1 = makeRoot('1');
    const root2 = makeRoot('2');
    const orgId1 = 'original-org';
    const orgId2 = 'attacker-org';
    const version1 = '1.0.0';
    const version2 = '2.0.0-forged';

    // 1. Initial Anchor
    const tx = await contract.anchorScan(scanId, root1, orgId1, version1);
    await tx.wait();

    const [origRoot, origBy, origTs, origOrg, origVer, origExists] =
      await contract.getAnchor(scanId);

    // 2. Attempt overwrite with different root -> MUST REVERT
    await assert.rejects(
      async () => {
        await contract.anchorScan(scanId, root2, orgId2, version2);
      },
      /CryptoAnchor: scanId already anchored/
    );

    // 3. Verify complete historical immutability (original values preserved)
    const [currRoot, currBy, currTs, currOrg, currVer, currExists] =
      await contract.getAnchor(scanId);

    assert.strictEqual(currRoot, origRoot);
    assert.notStrictEqual(currRoot, root2);
    assert.strictEqual(currBy, origBy);
    assert.strictEqual(currTs, origTs);
    assert.strictEqual(currOrg, origOrg);
    assert.notStrictEqual(currOrg, orgId2);
    assert.strictEqual(currVer, origVer);
    assert.notStrictEqual(currVer, version2);
    assert.strictEqual(currExists, true);
  });

  it('proves historical anchors for DIFFERENT identifiers coexist independently', async function () {
    const scanIdA = makeScanId('coexist-scan-alpha');
    const scanIdB = makeScanId('coexist-scan-beta');
    const scanIdC = makeScanId('coexist-scan-gamma');

    const rootA = makeRoot('a');
    const rootB = makeRoot('b');
    const rootC = makeRoot('c');

    // Anchor all three sequentially
    await (await contract.anchorScan(scanIdA, rootA, 'org-a', '1.0.0')).wait();
    await (await contract.anchorScan(scanIdB, rootB, 'org-b', '1.1.0')).wait();
    await (await contract.anchorScan(scanIdC, rootC, 'org-c', '1.2.0')).wait();

    // Query each independently
    const [resA_Root, , , resA_Org, resA_Ver, resA_Exists] = await contract.getAnchor(scanIdA);
    const [resB_Root, , , resB_Org, resB_Ver, resB_Exists] = await contract.getAnchor(scanIdB);
    const [resC_Root, , , resC_Org, resC_Ver, resC_Exists] = await contract.getAnchor(scanIdC);

    assert.strictEqual(resA_Exists, true);
    assert.strictEqual(resB_Exists, true);
    assert.strictEqual(resC_Exists, true);

    assert.strictEqual(resA_Root, rootA);
    assert.strictEqual(resB_Root, rootB);
    assert.strictEqual(resC_Root, rootC);

    assert.strictEqual(resA_Org, 'org-a');
    assert.strictEqual(resB_Org, 'org-b');
    assert.strictEqual(resC_Org, 'org-c');

    assert.strictEqual(resA_Ver, '1.0.0');
    assert.strictEqual(resB_Ver, '1.1.0');
    assert.strictEqual(resC_Ver, '1.2.0');
  });

  it('allows individual scan anchors and batch root anchors to coexist without conflict', async function () {
    const individualScanId = makeScanId('individual-scan-001');
    const batchAnchorId = ethers.keccak256(ethers.toUtf8Bytes('batch:deterministic-batch-hash-001'));

    const indRoot = makeRoot('7');
    const batchRoot = makeRoot('8');

    await (await contract.anchorScan(individualScanId, indRoot, 'corp-security', '1.0.0')).wait();
    await (await contract.anchorScan(batchAnchorId, batchRoot, 'corp-security', '1.0.0')).wait();

    const [readIndRoot, , , , , indExists] = await contract.getAnchor(individualScanId);
    const [readBatchRoot, , , , , batchExists] = await contract.getAnchor(batchAnchorId);

    assert.strictEqual(indExists, true);
    assert.strictEqual(batchExists, true);
    assert.strictEqual(readIndRoot, indRoot);
    assert.strictEqual(readBatchRoot, batchRoot);
  });

  it('verifies historical immutability on live Sepolia deployment without creating new transactions', async function () {
    const sepoliaBatchId = 'batch:bb05c48ca63e011b371e8a60aff04beedbb6040ddd81757a626e7af3e2d26d05';
    const expectedRoot = 'bb05c48ca63e011b371e8a60aff04beedbb6040ddd81757a626e7af3e2d26d05';

    // Read live Sepolia historical anchor
    const onChain = await fetchOnChainAnchor(sepoliaRecord.address, sepoliaRpcUrl, sepoliaBatchId);

    assert.strictEqual(onChain.exists, true);
    assert.strictEqual(onChain.merkleRootClean, expectedRoot);
    assert.strictEqual(onChain.anchoredBy.toLowerCase(), '0xE516ce8b5E30aB4e3aFbb796f59cA28AaC2C7631'.toLowerCase());
    assert.strictEqual(onChain.timestamp, 1788359556);
    assert.strictEqual(onChain.orgId, 'default-org');
    assert.strictEqual(onChain.scannerVersion, '1.0.0');
  });
});
