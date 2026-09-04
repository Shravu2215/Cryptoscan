'use strict';

const assert = require('assert');
const {
  uploadCBOMToIPFS,
  fetchCBOMFromIPFS,
  verifyIPFSContent,
  hashCBOM,
} = require('../scripts/ipfs');

const sampleCBOM = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  serialNumber: 'urn:uuid:7256051a-e1d9-42c0-bb5f-8543477acd92',
  version: 1,
  metadata: {
    scanId: '7256051a-e1d9-42c0-bb5f-8543477acd92',
    timestamp: '2026-09-02T12:45:00Z',
    component: {
      type: 'application',
      name: 'CryptoScan-Demo',
      version: '1.0.0',
    },
  },
  components: [
    {
      type: 'cryptographic-asset',
      name: 'RSA-2048',
      properties: [
        { name: 'primitive', value: 'asymmetric-encryption' },
        { name: 'keyLength', value: '2048' },
        { name: 'quantumStatus', value: 'Vulnerable' },
      ],
    },
    {
      type: 'cryptographic-asset',
      name: 'AES-GCM',
      properties: [
        { name: 'primitive', value: 'symmetric-encryption' },
        { name: 'keyLength', value: '256' },
        { name: 'quantumStatus', value: 'Quantum-Safe' },
      ],
    },
  ],
};

describe('IPFS Storage & Integrity (Phase 9)', function () {
  this.timeout(30000);

  it('computes deterministic CBOM canonical hash invariant to key order', function () {
    const res1 = hashCBOM(sampleCBOM);
    const res2 = hashCBOM(JSON.stringify(sampleCBOM));

    const permutedCBOM = {
      version: 1,
      components: sampleCBOM.components,
      metadata: sampleCBOM.metadata,
      serialNumber: sampleCBOM.serialNumber,
      specVersion: '1.5',
      bomFormat: 'CycloneDX',
    };
    const resPermuted = hashCBOM(permutedCBOM);

    assert.strictEqual(res1.contentHash, res2.contentHash);
    assert.strictEqual(res1.contentHash, resPermuted.contentHash);
    assert.strictEqual(res1.contentHash.length, 64);
    assert.strictEqual(res1.contentHashHex, '0x' + res1.contentHash);
  });

  it('uploads to mock IPFS boundary producing valid CIDv1', async function () {
    const uploadResult = await uploadCBOMToIPFS(sampleCBOM, { mock: true });

    assert.strictEqual(typeof uploadResult.cid, 'string');
    assert.ok(uploadResult.cid.startsWith('bafkrei'));
    assert.strictEqual(uploadResult.uri, `ipfs://${uploadResult.cid}`);
    assert.strictEqual(uploadResult.contentHash.length, 64);
    assert.strictEqual(uploadResult.scanId, '7256051a-e1d9-42c0-bb5f-8543477acd92');
    assert.strictEqual(uploadResult.provider, 'mock-ipfs-gateway');
    assert.strictEqual(uploadResult.isMock, true);
  });

  it('guarantees deterministic content-addressed CID generation', async function () {
    const upload1 = await uploadCBOMToIPFS(sampleCBOM, { mock: true });
    const upload2 = await uploadCBOMToIPFS(sampleCBOM, { mock: true });

    assert.strictEqual(upload1.cid, upload2.cid);
    assert.strictEqual(upload1.contentHash, upload2.contentHash);

    const modifiedCBOM = { ...sampleCBOM, version: 2 };
    const uploadModified = await uploadCBOMToIPFS(modifiedCBOM, { mock: true });
    assert.notStrictEqual(upload1.cid, uploadModified.cid);
  });

  it('retrieves uploaded CBOM through CID', async function () {
    const uploadResult = await uploadCBOMToIPFS(sampleCBOM, { mock: true });
    const retrieved = await fetchCBOMFromIPFS(uploadResult.cid);

    assert.deepStrictEqual(retrieved.components, sampleCBOM.components);
    assert.strictEqual(retrieved.serialNumber, sampleCBOM.serialNumber);
  });

  it('verifies content integrity against contentHash and Merkle root', async function () {
    const uploadResult = await uploadCBOMToIPFS(sampleCBOM, { mock: true });
    const retrieved = await fetchCBOMFromIPFS(uploadResult.cid);

    const check1 = verifyIPFSContent(retrieved, uploadResult.contentHash);
    assert.strictEqual(check1.valid, true);

    const check2 = verifyIPFSContent(retrieved, uploadResult.contentHashHex);
    assert.strictEqual(check2.valid, true);

    const check3 = verifyIPFSContent(retrieved, uploadResult.merkleRoot);
    assert.strictEqual(check3.valid, true);
  });

  it('strictly rejects tampered CBOM content', async function () {
    const uploadResult = await uploadCBOMToIPFS(sampleCBOM, { mock: true });
    const retrieved = await fetchCBOMFromIPFS(uploadResult.cid);

    const tampered = JSON.parse(JSON.stringify(retrieved));
    tampered.components[0].properties[2].value = 'Post-Quantum-Secure';

    const tamperCheck = verifyIPFSContent(tampered, uploadResult.contentHash);
    assert.strictEqual(tamperCheck.valid, false);
    assert.notStrictEqual(tamperCheck.recomputedHash, uploadResult.contentHash);
  });

  it('fails with clear error when required live credentials are missing', async function () {
    await assert.rejects(
      async () => {
        await uploadCBOMToIPFS(sampleCBOM, {
          requireLive: true,
          pinataJwt: '',
        });
      },
      /Missing required PINATA_JWT credentials/
    );
  });

  it('rejects upstream API failure without reporting false success', async function () {
    await assert.rejects(
      async () => {
        await uploadCBOMToIPFS(sampleCBOM, {
          pinataJwt: 'invalid-jwt-token-for-test',
          apiUrl: 'https://api.pinata.cloud',
        });
      },
      /IPFS upload failed/
    );
  });
});
