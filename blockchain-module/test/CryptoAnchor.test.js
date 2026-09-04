const { expect } = require('chai');
const { ethers } = require('hardhat');
const crypto = require('crypto');

describe('CryptoAnchor', function () {
  let contract;
  let owner;
  let writer;
  let unauthorized;

  beforeEach(async function () {
    [owner, writer, unauthorized] = await ethers.getSigners();
    const CryptoAnchor = await ethers.getContractFactory('CryptoAnchor');
    contract = await CryptoAnchor.deploy();
    await contract.waitForDeployment();
  });

  function makeScanId(label) {
    return ethers.keccak256(ethers.toUtf8Bytes(label));
  }

  function makeMerkleRoot(content) {
    return '0x' + crypto.createHash('sha256').update(content).digest('hex');
  }

  it('anchors a scan and emits ScanAnchored with all Person 5 fields', async function () {
    const scanId = makeScanId('scan-1');
    const merkleRoot = makeMerkleRoot('canonical-cbom-components-for-scan-1');
    const orgId = 'org-crypto-defense-01';
    const scannerVersion = '2.4.0';

    await expect(contract.anchorScan(scanId, merkleRoot, orgId, scannerVersion))
      .to.emit(contract, 'ScanAnchored')
      .withArgs(
        scanId,
        merkleRoot,
        owner.address,
        (ts) => ts > 0n,
        orgId,
        scannerVersion
      );
  });

  it('stores and retrieves a complete record after anchoring', async function () {
    const scanId = makeScanId('scan-2');
    const merkleRoot = makeMerkleRoot('canonical-cbom-components-for-scan-2');
    const orgId = 'acme-security-team';
    const scannerVersion = '1.0.0-pqc';

    await contract.anchorScan(scanId, merkleRoot, orgId, scannerVersion);
    const [storedRoot, anchoredBy, timestamp, storedOrg, storedVersion, exists] =
      await contract.getAnchor(scanId);

    expect(exists).to.equal(true);
    expect(storedRoot).to.equal(merkleRoot);
    expect(anchoredBy).to.equal(owner.address);
    expect(timestamp).to.be.greaterThan(0n);
    expect(storedOrg).to.equal(orgId);
    expect(storedVersion).to.equal(scannerVersion);
  });

  it('preserves historical anchoring: rejects re-anchoring the same scanId', async function () {
    const scanId = makeScanId('scan-3');
    const root1 = makeMerkleRoot('content-v1');
    const root2 = makeMerkleRoot('content-v2');

    await contract.anchorScan(scanId, root1, 'org-alpha', '1.0.0');

    // Attempting to re-anchor must revert and not overwrite
    await expect(
      contract.anchorScan(scanId, root2, 'org-beta', '2.0.0')
    ).to.be.revertedWith('CryptoAnchor: scanId already anchored');

    // Original history remains completely intact
    const [storedRoot, , , storedOrg, storedVersion, exists] =
      await contract.getAnchor(scanId);
    expect(exists).to.equal(true);
    expect(storedRoot).to.equal(root1);
    expect(storedOrg).to.equal('org-alpha');
    expect(storedVersion).to.equal('1.0.0');
  });

  it('rejects an empty merkleRoot', async function () {
    const scanId = makeScanId('scan-4');
    await expect(
      contract.anchorScan(scanId, ethers.ZeroHash, 'org-test', '1.0.0')
    ).to.be.revertedWith('CryptoAnchor: empty merkleRoot');
  });

  it('reports isAnchored and getAnchor correctly for unknown scanId', async function () {
    const unknownScanId = makeScanId('never-anchored');
    expect(await contract.isAnchored(unknownScanId)).to.equal(false);

    const [root, by, ts, org, ver, exists] = await contract.getAnchor(unknownScanId);
    expect(exists).to.equal(false);
    expect(root).to.equal(ethers.ZeroHash);
    expect(by).to.equal(ethers.ZeroAddress);
    expect(ts).to.equal(0n);
    expect(org).to.equal('');
    expect(ver).to.equal('');
  });

  it('rejects unauthorized writers from anchoring', async function () {
    const scanId = makeScanId('scan-unauthorized');
    const merkleRoot = makeMerkleRoot('unauthorized-payload');

    await expect(
      contract.connect(unauthorized).anchorScan(scanId, merkleRoot, 'org-rogue', '1.0.0')
    ).to.be.revertedWith('CryptoAnchor: unauthorized writer');
  });

  it('allows owner to authorize and revoke writer accounts, rejecting non-owners', async function () {
    const scanId1 = makeScanId('scan-authorized-1');
    const scanId2 = makeScanId('scan-authorized-2');
    const root = makeMerkleRoot('authorized-content');

    // Non-owner cannot manage authorized writers
    await expect(
      contract.connect(unauthorized).setAuthorizedWriter(writer.address, true)
    ).to.be.revertedWith('CryptoAnchor: caller is not the owner');

    // Authorize writer
    await expect(contract.setAuthorizedWriter(writer.address, true))
      .to.emit(contract, 'WriterAuthorized')
      .withArgs(writer.address);

    // Authorized writer can successfully anchor
    await expect(
      contract.connect(writer).anchorScan(scanId1, root, 'org-corp', '1.2.0')
    ).to.emit(contract, 'ScanAnchored');
    expect(await contract.isAnchored(scanId1)).to.equal(true);

    // Revoke writer
    await expect(contract.setAuthorizedWriter(writer.address, false))
      .to.emit(contract, 'WriterRevoked')
      .withArgs(writer.address);

    // Revoked writer is rejected
    await expect(
      contract.connect(writer).anchorScan(scanId2, root, 'org-corp', '1.2.0')
    ).to.be.revertedWith('CryptoAnchor: unauthorized writer');
  });

  it('supports backward-compatible 2-parameter anchorScan overload', async function () {
    const scanId = makeScanId('scan-legacy');
    const merkleRoot = makeMerkleRoot('legacy-content');

    await contract['anchorScan(bytes32,bytes32)'](scanId, merkleRoot);
    const [storedRoot, anchoredBy, timestamp, storedOrg, storedVersion, exists] =
      await contract.getAnchor(scanId);

    expect(exists).to.equal(true);
    expect(storedRoot).to.equal(merkleRoot);
    expect(anchoredBy).to.equal(owner.address);
    expect(timestamp).to.be.greaterThan(0n);
    expect(storedOrg).to.equal('default-org');
    expect(storedVersion).to.equal('1.0.0');
  });
});

