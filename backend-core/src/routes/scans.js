const express = require('express');
const { requireAuth } = require('../middleware/auth');
const prisma = require('../utils/prismaClient');
const { canAccessRepo } = require('../utils/authz');
const { buildCbom } = require('../../../cbom-service/src/services/cbomGenerator');
const { anchorCBOM } = require('../../../blockchain-module/scripts/anchor');
const { verifyScan } = require('../../../blockchain-module/scripts/verify');

const router = express.Router();

// POST /scan/:repoId
// This creates the Scan row and flips status to RUNNING.
router.post('/:repoId', requireAuth, async (req, res) => {
  try {
    const { repoId } = req.params;

    const repo = await prisma.repo.findUnique({ where: { id: repoId } });
    if (!repo) {
      return res.status(404).json({ error: 'Repo not found' });
    }
    if (!canAccessRepo(req.user, repo)) {
      return res.status(403).json({ error: 'You do not have access to this repository' });
    }

    const scan = await prisma.scan.create({
      data: { repoId, status: 'PENDING' },
    });

    // --- Scanner Engine hook ---
    const { exec } = require('child_process');
    const path = require('path');
    const fs = require('fs');

    (async () => {
      try {
        await prisma.scan.update({ where: { id: scan.id }, data: { status: 'RUNNING' } });

        let targetPath = repo.filePath;
        const scannerDir = path.resolve(__dirname, '../../../scanner');
        const absoluteRepoPath = path.resolve(__dirname, '../../../', targetPath);

        const isWin = process.platform === 'win32';
        const venvPython = path.join(scannerDir, '.venv', isWin ? 'Scripts\\python.exe' : 'bin/python');
        const pythonCmd = fs.existsSync(venvPython) ? `"${venvPython}"` : (isWin ? 'python' : 'python3');

        exec(`${pythonCmd} pipeline.py "${absoluteRepoPath}"`, { cwd: scannerDir }, async (error, stdout, stderr) => {
          if (error) {
            console.error('Scanner error:', error);
            await prisma.scan.update({ where: { id: scan.id }, data: { status: 'FAILED' } });
            return;
          }

          try {
            const result = JSON.parse(stdout);
            const findings = result.findings || [];

            const dbFindings = findings.map(f => ({
              scanId: scan.id,
              filePath: f.file,
              lineNumber: f.line || null,
              algorithm: f.algorithm || 'UNKNOWN',
              library: f.library || 'Standard API',
              usage: f.category || null,
              keySize: f.key_size || (f.algorithm.includes('1024') ? 1024 : f.algorithm.includes('2048') ? 2048 : (f.algorithm.includes('56') || (f.algorithm.includes('DES') && !f.algorithm.includes('3DES'))) ? 56 : f.algorithm.includes('256') ? 256 : f.algorithm.includes('128') ? 128 : null),
              quantumStatus: ['Quantum-Broken', 'Quantum-Weakened'].includes(f.quantum_risk)
                ? 'Quantum Vulnerable' : 'Quantum Safe',
              severity: (f.severity || 'Informational').toUpperCase(),
              description: f.message || f.raw_call || '',
              recommendation: f.recommendation || null,
              confidence: `${f.confidence || 'Likely'}|${f.detection_method || 'ast'}`,
              suppressed: Boolean(f.suppressed),
              suppressionReason: f.suppression_reason || null
            }));

            if (dbFindings.length > 0) {
              await prisma.finding.createMany({ data: dbFindings });
            }

            await prisma.scan.update({ where: { id: scan.id }, data: { status: 'COMPLETED', completedAt: new Date() } });
          } catch (parseError) {
            console.error('Failed to parse scanner output:', parseError, stdout);
            await prisma.scan.update({ where: { id: scan.id }, data: { status: 'FAILED' } });
          }
        });
      } catch (err) {
        console.error('Failed to start scan:', err);
        await prisma.scan.update({ where: { id: scan.id }, data: { status: 'FAILED' } });
      }
    })();

    return res.status(202).json({
      scanId: scan.id,
      status: scan.status,
      message: 'Scan queued. Poll GET /scan/:scanId/findings for results.',
    });
  } catch (err) {
    console.error('Scan trigger error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /scan/:scanId/findings
router.get('/:scanId/findings', requireAuth, async (req, res) => {
  try {
    const { scanId } = req.params;
    const scan = await prisma.scan.findUnique({ where: { id: scanId }, include: { repo: true } });
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    if (!canAccessRepo(req.user, scan.repo)) {
      return res.status(403).json({ error: 'You do not have access to this scan' });
    }

    const findings = await prisma.finding.findMany({ where: { scanId } });
    return res.json({ scanId, status: scan.status, findings });
  } catch (err) {
    console.error('Findings fetch error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /scan/:scanId/cbom
router.get('/:scanId/cbom', requireAuth, async (req, res) => {
  try {
    const { scanId } = req.params;
    const scan = await prisma.scan.findUnique({ where: { id: scanId }, include: { repo: true } });
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    if (!canAccessRepo(req.user, scan.repo)) {
      return res.status(403).json({ error: 'You do not have access to this scan' });
    }

    const dbFindings = await prisma.finding.findMany({ where: { scanId }, orderBy: { id: 'asc' } });

    const rawFindings = dbFindings.map(f => ({
      id: f.id,
      file: f.filePath,
      line: f.lineNumber,
      algorithm: f.algorithm,
      severity: f.severity,
      quantumStatus: f.quantumStatus,
      usage: f.usage,
      recommendation: f.recommendation,
      status: f.status
    }));

    let repoScans = [];
    if (scan.repoId) {
      repoScans = await prisma.scan.findMany({
        where: { repoId: scan.repoId },
        orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
        select: { id: true, createdAt: true, repoId: true }
      });
    }

    const cbom = buildCbom({
      scanId: scan.id,
      repoId: scan.repoId,
      createdAt: scan.createdAt,
      repo: scan.repo,
      repoScans,
      rawFindings
    });

    if (req.query.signed === 'true') {
      const { exportSignedCbom } = require('../../../cbom-service/src/services/signedCbomExport');
      const signed = await exportSignedCbom(cbom);
      return res.json(signed);
    }

    return res.json(cbom);
  } catch (err) {
    console.error('CBOM fetch error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /scan/:scanId/anchor
router.post('/:scanId/anchor', requireAuth, async (req, res) => {
  try {
    const { scanId } = req.params;

    const scan = await prisma.scan.findUnique({ where: { id: scanId }, include: { repo: true } });
    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    if (!canAccessRepo(req.user, scan.repo)) {
      return res.status(403).json({ error: 'You do not have access to this scan' });
    }

    const dbFindings = await prisma.finding.findMany({ where: { scanId }, orderBy: { id: 'asc' } });
    const rawFindings = dbFindings.map(f => ({
      id: f.id,
      file: f.filePath,
      line: f.lineNumber,
      algorithm: f.algorithm,
      severity: f.severity,
      quantumStatus: f.quantumStatus,
      usage: f.usage,
      recommendation: f.recommendation
    }));

    let repoScans = [];
    if (scan.repoId) {
      repoScans = await prisma.scan.findMany({
        where: { repoId: scan.repoId },
        orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
        select: { id: true, createdAt: true, repoId: true }
      });
    }
    const cbom = buildCbom({ scanId: scan.id, repoId: scan.repoId, createdAt: scan.createdAt, repo: scan.repo, repoScans, rawFindings });
    const contentBuffer = Buffer.from(JSON.stringify(cbom));

    // Check if we use mock (from frontend or env)
    const useMock = process.env.USE_MOCK === 'true';
    if (useMock) {
      const mockHash = '8f4c7a91d2938f45a6b7e8d9c102b3a4f5c6e7d8a9b0c1d2e3f4a5b6c7d8e91a';
      const mockTxHash = '0x7f3a9a14b51c881249b6d9e034abc88d92bc9f201a9f14';
      await prisma.anchor.upsert({
        where: { scanId: scan.id },
        update: { contentHash: mockHash, txHash: mockTxHash, signature: 'mock-signature-not-verifiable', network: 'mocknet' },
        create: { scanId: scan.id, contentHash: mockHash, txHash: mockTxHash, signature: 'mock-signature-not-verifiable', network: 'mocknet' }
      });
      return res.json({ txHash: mockTxHash, onChainHash: mockHash, network: 'mocknet', verified: true });
    }

    // Call blockchain-module anchor script
    const result = await anchorCBOM(contentBuffer, {
      scanId: scan.id,
      orgId: 'cryptoscan-core'
    });

    // Save anchor record to DB
    const anchor = await prisma.anchor.upsert({
      where: { scanId: scan.id },
      update: {
        contentHash: result.merkleRoot,
        txHash: result.txHash,
        signature: result.signature,
        network: result.network
      },
      create: {
        scanId: scan.id,
        contentHash: result.merkleRoot,
        txHash: result.txHash,
        signature: result.signature,
        network: result.network
      }
    });

    return res.json({
      txHash: anchor.txHash,
      onChainHash: anchor.contentHash,
      signature: anchor.signature,
      network: anchor.network,
      blockNumber: result.blockNumber
    });
  } catch (err) {
    console.error('Anchor error:', err);
    return res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// GET /scan/:scanId/verify
router.get('/:scanId/verify', requireAuth, async (req, res) => {
  try {
    const { scanId } = req.params;

    const scan = await prisma.scan.findUnique({ where: { id: scanId }, include: { repo: true } });
    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    if (!canAccessRepo(req.user, scan.repo)) {
      return res.status(403).json({ error: 'You do not have access to this scan' });
    }

    const anchor = await prisma.anchor.findUnique({ where: { scanId } });
    if (!anchor) {
      return res.status(404).json({ error: 'No anchor found for this scan' });
    }

    const dbFindings = await prisma.finding.findMany({ where: { scanId }, orderBy: { id: 'asc' } });
    const rawFindings = dbFindings.map(f => ({
      id: f.id,
      file: f.filePath,
      line: f.lineNumber,
      algorithm: f.algorithm,
      severity: f.severity,
      quantumStatus: f.quantumStatus,
      usage: f.usage,
      recommendation: f.recommendation
    }));

    let repoScans = [];
    if (scan && scan.repoId) {
      repoScans = await prisma.scan.findMany({
        where: { repoId: scan.repoId },
        orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
        select: { id: true, createdAt: true, repoId: true }
      });
    }
    const cbom = buildCbom({ scanId: scan.id, repoId: scan.repoId, createdAt: scan.createdAt, repo: scan.repo, repoScans, rawFindings });
    const cbomJson = JSON.stringify(cbom);

    let recomputedHash = anchor.contentHash;
    let merkleData = null;
    try {
      const { buildMerkleTree } = require('../../../integrity-service/merkle');
      if (cbom.components && cbom.components.length > 0) {
        const treeResult = buildMerkleTree(cbom.components);
        recomputedHash = '0x' + treeResult.root;
        merkleData = {
          tree: treeResult.tree,
          leaves: treeResult.leaves
        };
      }
    } catch (_) {
      const crypto = require('crypto');
      recomputedHash = '0x' + crypto.createHash('sha256').update(cbomJson).digest('hex');
    }

    const storedHash = anchor.contentHash.toLowerCase();
    let hashMatches = recomputedHash.toLowerCase() === storedHash;

    let onChainHash = anchor.contentHash;
    let signatureValid = !!anchor.signature;
    let blockchainError = null;
    try {
      if (process.env.USE_MOCK !== 'true') {
        const chainTimeout = new Promise((_, rej) =>
          setTimeout(() => rej(new Error('chain-timeout')), 3000)
        );
        const chainResult = await Promise.race([
          verifyScan(scanId, Buffer.from(cbomJson), anchor.signature),
          chainTimeout,
        ]);
        if (chainResult) {
          if (chainResult.onChainHash) onChainHash = chainResult.onChainHash;
          if (chainResult.recomputedHash) recomputedHash = chainResult.recomputedHash;
          if (typeof chainResult.verified === 'boolean') hashMatches = chainResult.verified;
          if (typeof chainResult.signatureValid === 'boolean') signatureValid = chainResult.signatureValid;
        }
      }
    } catch (e) {
      console.warn('Blockchain read skipped:', e.message);
      blockchainError = e.message;
    }

    return res.json({
      verified: hashMatches,
      onChainHash,
      offChainHash: recomputedHash,
      signatureValid,
      txHash: anchor.txHash,
      network: anchor.network,
      error: blockchainError,
      merkleData: merkleData
    });
  } catch (err) {
    console.error('Verify error:', err);
    return res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// GET /scan/:scanId/migration-assessment
router.get('/:scanId/migration-assessment', requireAuth, async (req, res) => {
  try {
    const { scanId } = req.params;
    const scan = await prisma.scan.findUnique({ where: { id: scanId }, include: { repo: true } });
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    if (!canAccessRepo(req.user, scan.repo)) {
      return res.status(403).json({ error: 'You do not have access to this scan' });
    }

    const rawFindings = await prisma.finding.findMany({ where: { scanId }, orderBy: { id: 'asc' } });
    const { assessMigration } = require('../../../cbom-service/src/services/migrationAssessment');
    
    const result = assessMigration(scan, rawFindings);
    return res.json(result);
  } catch (err) {
    console.error('Migration assessment error:', err);
    return res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// PUT /scan/:scanId/findings/:findingId/resolve
router.put('/:scanId/findings/:findingId/resolve', requireAuth, async (req, res) => {
  try {
    const { scanId, findingId } = req.params;
    
    const scan = await prisma.scan.findUnique({ where: { id: scanId }, include: { repo: true } });
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    if (!canAccessRepo(req.user, scan.repo)) {
      return res.status(403).json({ error: 'You do not have access to this scan' });
    }

    const finding = await prisma.finding.findUnique({ where: { id: findingId } });
    if (!finding || finding.scanId !== scanId) {
      return res.status(404).json({ error: 'Finding not found in this scan' });
    }

    const updated = await prisma.finding.update({
      where: { id: findingId },
      data: { status: 'RESOLVED' }
    });

    return res.json({ message: 'Finding marked as resolved', finding: updated });
  } catch (err) {
    console.error('Finding resolve error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /scan/simulate/migration
// Simulation-only endpoint — evaluates PQC migration for a single crypto component.
// NEVER mutates source code, scan data, CBOM, database, or blockchain/IPFS.
router.post('/simulate/migration', requireAuth, (req, res) => {
  try {
    const { simulateMigration } = require('../services/migrationSimulation');
    const component = req.body;
    if (!component || typeof component !== 'object' || Array.isArray(component)) {
      return res.status(400).json({ error: 'Request body must be a single crypto component object.' });
    }
    const result = simulateMigration(component);
    if (!result.simulationValid) {
      return res.status(400).json(result);
    }
    return res.json(result);
  } catch (err) {
    console.error('Migration simulation error:', err);
    return res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// POST /scan/simulate/migration/batch
// Simulation-only endpoint — evaluates PQC migration for multiple components at once.
// NEVER mutates source code, scan data, CBOM, database, or blockchain/IPFS.
router.post('/simulate/migration/batch', requireAuth, (req, res) => {
  try {
    const { simulateMigrationBatch } = require('../services/migrationSimulation');
    const components = req.body;
    if (!Array.isArray(components)) {
      return res.status(400).json({ error: 'Request body must be an array of crypto component objects.' });
    }
    const result = simulateMigrationBatch(components);
    if (!result.simulationValid) {
      return res.status(400).json(result);
    }
    return res.json(result);
  } catch (err) {
    console.error('Batch migration simulation error:', err);
    return res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

module.exports = router;
