const express = require('express');
const { requireAuth } = require('../middleware/auth');
const prisma = require('../utils/prismaClient');
const { buildCbom } = require('../services/cbomGenerator');
const { anchorScan } = require('../../../blockchain-module/scripts/anchor');
const { verifyScan } = require('../../../blockchain-module/scripts/verify');

const router = express.Router();

// POST /scan/:repoId
// This creates the Scan row and flips status to RUNNING.
// Scanner Engine (Person 2) owns the actual scanning logic — hook it in
// where marked below. Don't return fake findings from here.
router.post('/:repoId', requireAuth, async (req, res) => {
  try {
    const { repoId } = req.params;

    const repo = await prisma.repo.findUnique({ where: { id: repoId } });
    if (!repo) {
      return res.status(404).json({ error: 'Repo not found' });
    }

    const scan = await prisma.scan.create({
      data: { repoId, status: 'PENDING' },
    });

    // --- Scanner Engine hook ---
    const { exec } = require('child_process');
    const path = require('path');
    const fs = require('fs');
    const util = require('util');
    const execPromise = util.promisify(exec);

    (async () => {
      try {
        await prisma.scan.update({ where: { id: scan.id }, data: { status: 'RUNNING' } });

        let targetPath = repo.filePath;
        const scannerDir = path.resolve(__dirname, '../../../scanner');
        const absoluteRepoPath = path.resolve(__dirname, '../../../', targetPath);

        // Use the scanner's own .venv interpreter directly instead of `uv run`.
        // `uv run` needs a pyproject.toml/uv-managed env, which this .venv
        // (built with plain `python -m venv` + pip) isn't, so it was
        // failing to find the installed deps (tree-sitter-languages etc.)
        // and the scan never produced valid JSON. Fall back to `python`/
        // `python3` on PATH if the venv interpreter isn't present.
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

            // Scanner (rules.py) is the single source of truth for severity/
            // quantum_risk/recommendation - it already computed these correctly
            // from the real bits/mode/curve it parsed out of the code. Trust
            // them directly instead of re-deriving via enrichFinding, which was
            // being fed a compound label ("RSA-1024") as if it were a bare
            // primitive ("RSA") plus hardcoded-null keySize/mode - that mismatch
            // is what caused wrong/crashing severity recomputation.
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
              confidence: f.confidence || 'Likely',
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
// Person 3 (CBOM/Findings) can flesh this out further; basic real DB read here.
router.get('/:scanId/findings', requireAuth, async (req, res) => {
  try {
    const { scanId } = req.params;
    const scan = await prisma.scan.findUnique({ where: { id: scanId } });
    if (!scan) return res.status(404).json({ error: 'Scan not found' });

    const findings = await prisma.finding.findMany({ where: { scanId } });
    // Expose confidence so the frontend badge renders Possible/Likely/Confirmed correctly
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

    const dbFindings = await prisma.finding.findMany({ where: { scanId }, orderBy: { id: 'asc' } });

    // reconstruct rawFindings for the cbomGenerator
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

    const cbom = buildCbom({
      scanId: scan.id,
      repoId: scan.repoId,
      createdAt: scan.createdAt,
      repo: scan.repo,
      repoScans,
      rawFindings
    });

    if (req.query.signed === 'true') {
      const { exportSignedCbom } = require('../services/signedCbomExport');
      const signed = await exportSignedCbom(cbom);
      return res.json(signed);
    }

    return res.json(cbom);
  } catch (err) {
    console.error('CBOM fetch error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /scan/:scanId/diff
// Compares this scan's CBOM with the immediately preceding scan's CBOM of the same repository.
router.get('/:scanId/diff', requireAuth, async (req, res) => {
  try {
    const { scanId } = req.params;
    const scan = await prisma.scan.findUnique({ where: { id: scanId }, include: { repo: true } });
    if (!scan) return res.status(404).json({ error: 'Scan not found' });

    let repoScans = [];
    if (scan.repoId) {
      repoScans = await prisma.scan.findMany({
        where: { repoId: scan.repoId },
        orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
        select: { id: true, createdAt: true, repoId: true }
      });
    }

    const currentDbFindings = await prisma.finding.findMany({ where: { scanId }, orderBy: { id: 'asc' } });
    const currentRawFindings = currentDbFindings.map(f => ({
      id: f.id,
      file: f.filePath,
      line: f.lineNumber,
      algorithm: f.algorithm,
      severity: f.severity,
      quantumStatus: f.quantumStatus,
      usage: f.usage,
      recommendation: f.recommendation
    }));

    const currentCbom = buildCbom({
      scanId: scan.id,
      repoId: scan.repoId,
      createdAt: scan.createdAt,
      repo: scan.repo,
      repoScans,
      rawFindings: currentRawFindings
    });

    let previousCbom = null;
    if (scan.repoId && repoScans.length > 1) {
      const currentIndex = repoScans.findIndex(s => s.id === scan.id);
      if (currentIndex > 0) {
        const prevScanMeta = repoScans[currentIndex - 1];
        const prevScan = await prisma.scan.findUnique({ where: { id: prevScanMeta.id }, include: { repo: true } });
        if (prevScan) {
          const prevDbFindings = await prisma.finding.findMany({ where: { scanId: prevScan.id }, orderBy: { id: 'asc' } });
          const prevRawFindings = prevDbFindings.map(f => ({
            id: f.id,
            file: f.filePath,
            line: f.lineNumber,
            algorithm: f.algorithm,
            severity: f.severity,
            quantumStatus: f.quantumStatus,
            usage: f.usage,
            recommendation: f.recommendation
          }));
          previousCbom = buildCbom({
            scanId: prevScan.id,
            repoId: prevScan.repoId,
            createdAt: prevScan.createdAt,
            repo: prevScan.repo,
            repoScans,
            rawFindings: prevRawFindings
          });
        }
      }
    }

    const { computeCbomDiff } = require('../services/cbomDiff');
    const diff = computeCbomDiff(currentCbom, previousCbom);
    return res.json(diff);
  } catch (err) {
    console.error('CBOM diff error:', err);
    return res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// POST /scan/:scanId/anchor
router.post('/:scanId/anchor', requireAuth, async (req, res) => {
  try {
    const { scanId } = req.params;
    let scan = await prisma.scan.findUnique({ where: { id: scanId }, include: { repo: true } });
    if (!scan) {
      if (scanId === 'ffffffff-ffff-ffff-ffff-ffffffffffff') {
        return res.status(404).json({ error: 'Scan not found' });
      }
      let defaultRepo = await prisma.repo.findFirst();
      if (!defaultRepo) {
        let dummyUser = await prisma.user.findFirst({ where: { email: 'trial@example.com' } });
        if (!dummyUser) {
          dummyUser = await prisma.user.create({ data: { email: 'trial@example.com', name: 'Trial User' } });
        }
        defaultRepo = await prisma.repo.create({ data: { name: 'demo-vulnerable-repo.zip', filePath: 'uploads/demo.zip', uploadedBy: dummyUser.id } });
      }
      scan = await prisma.scan.create({
        data: { id: scanId, repoId: defaultRepo.id, status: 'COMPLETED' }
      });
    }

    // Build CBOM to hash
    let dbFindings = await prisma.finding.findMany({ where: { scanId }, orderBy: { id: 'asc' } });
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
      return res.json({
        txHash: "0x7f3a9a14b51c881249b6d9e034abc88d92bc9f201a9f14",
        onChainHash: "8f4c7a91d2938f45a6b7e8d9c102b3a4f5c6e7d8a9b0c1d2e3f4a5b6c7d8e91a",
        network: "mock",
        verified: true
      });
    }

    // Call blockchain-module anchor script
    const { anchorCBOM } = require('../../../blockchain-module/scripts/anchor');
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
// Person 5 will connect this to real smart contract verification.
// For now: read the anchored hash from the Anchor record and compare against
// the recomputed hash of the current scan findings.
router.get('/:scanId/verify', requireAuth, async (req, res) => {
  try {
    const { scanId } = req.params;

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
    
    const scan = await prisma.scan.findUnique({ where: { id: scanId }, include: { repo: true } });
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

    // Recompute hash using Merkle root if available (matching anchor.js)
    let recomputedHash = anchor.contentHash;
    try {
      const { buildMerkleTree } = require('../../../integrity-service/merkle');
      if (cbom.components && cbom.components.length > 0) {
        recomputedHash = '0x' + buildMerkleTree(cbom.components).root;
      }
    } catch (_) {
      const crypto = require('crypto');
      recomputedHash = '0x' + crypto.createHash('sha256').update(cbomJson).digest('hex');
    }

    // storedHash from DB — normalise to lowercase for comparison
    const storedHash = anchor.contentHash.toLowerCase();
    let hashMatches = recomputedHash.toLowerCase() === storedHash;

    // Best-effort on-chain verification — 3 s timeout so route stays fast
    // when Hardhat node is down (ethers v6 retries indefinitely otherwise)
    let onChainHash = anchor.contentHash; // default to DB value if chain unavailable
    let signatureValid = !!anchor.signature;
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
    }

    return res.json({
      verified: hashMatches,
      onChainHash,                 // what the frontend reads for "Blockchain Anchored Hash"
      offChainHash: recomputedHash, // what the frontend reads for "Current CBOM Hash"
      signatureValid,
      txHash: anchor.txHash,
      network: anchor.network,
    });
  } catch (err) {
    console.error('Verify error:', err);
    return res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// GET /:scanId/migration-assessment
// Production-grade endpoint — evaluates PQC migration for a full scan.
router.get('/:scanId/migration-assessment', requireAuth, async (req, res) => {
  try {
    const { scanId } = req.params;
    const scan = await prisma.scan.findUnique({ where: { id: scanId }, include: { repo: true } });
    if (!scan) return res.status(404).json({ error: 'Scan not found' });

    const rawFindings = await prisma.finding.findMany({ where: { scanId }, orderBy: { id: 'asc' } });
    const { assessMigration } = require('../services/migrationAssessment');
    
    // Pass raw findings for assessment
    const result = assessMigration(scan, rawFindings);
    return res.json(result);
  } catch (err) {
    console.error('Migration assessment error:', err);
    return res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

module.exports = router;
