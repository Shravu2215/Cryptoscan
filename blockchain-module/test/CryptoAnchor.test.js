const { expect } = require('chai');
const { ethers } = require('hardhat');
const crypto = require('crypto');

describe('CryptoAnchor', function () {
  let contract;
  let owner;

  beforeEach(async function () {
    [owner] = await ethers.getSigners();
    const CryptoAnchor = await ethers.getContractFactory('CryptoAnchor');
    contract = await CryptoAnchor.deploy();
    await contract.waitForDeployment();
  });

  function makeScanId(label) {
    return ethers.keccak256(ethers.toUtf8Bytes(label));
  }

  function makeContentHash(content) {
    return '0x' + crypto.createHash('sha256').update(content).digest('hex');
  }

  it('anchors a scan and emits ScanAnchored', async function () {
    const scanId = makeScanId('scan-1');
    const contentHash = makeContentHash('findings+cbom content for scan-1');

    await expect(contract.anchorScan(scanId, contentHash))
      .to.emit(contract, 'ScanAnchored')
      .withArgs(scanId, contentHash, owner.address, (ts) => ts > 0n);
  });

  it('stores a retrievable record after anchoring', async function () {
    const scanId = makeScanId('scan-2');
    const contentHash = makeContentHash('findings+cbom content for scan-2');

    await contract.anchorScan(scanId, contentHash);
    const [storedHash, anchoredBy, , exists] = await contract.getAnchor(scanId);

    expect(exists).to.equal(true);
    expect(storedHash).to.equal(contentHash);
    expect(anchoredBy).to.equal(owner.address);
  });

  it('rejects re-anchoring the same scanId', async function () {
    const scanId = makeScanId('scan-3');
    const contentHash = makeContentHash('content-v1');

    await contract.anchorScan(scanId, contentHash);
    await expect(
      contract.anchorScan(scanId, makeContentHash('content-v2'))
    ).to.be.revertedWith('CryptoAnchor: scanId already anchored');
  });

  it('rejects an empty content hash', async function () {
    const scanId = makeScanId('scan-4');
    await expect(
      contract.anchorScan(scanId, ethers.ZeroHash)
    ).to.be.revertedWith('CryptoAnchor: empty contentHash');
  });

  it('reports isAnchored correctly for unknown scanId', async function () {
    const unknownScanId = makeScanId('never-anchored');
    expect(await contract.isAnchored(unknownScanId)).to.equal(false);
  });
});
