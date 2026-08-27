const express = require('express');
const { requireAuth } = require('../middleware/auth');
const prisma = require('../utils/prismaClient');
const { enrichFinding, buildCbom } = require('../services/cbomGenerator');
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

            const dbFindings = findings.map(f => {
              const raw = {
                id: f.id,
                file: f.file,
                line: f.line,
                primitive: f.primitive,
                keySize: f.key_size,
                mode: f.mode,
                context: {
                  usageType: f.purpose,
                  functionName: f.raw_call
                }
              };
              const enriched = enrichFinding(raw);

              return {
                scanId: scan.id,
                filePath: enriched.file,
                lineNumber: enriched.line || null,
                algorithm: enriched.primitiveFamily || enriched.primitive || 'UNKNOWN',
                library: f.library || null,
                usage: enriched.purpose.value || null,
                keySize: enriched.keySize || null,
                quantumStatus: enriched.vulnerability.breakdown.quantumVulnerability > 50 ? 'Quantum Vulnerable' : 'Quantum Safe',
                severity: enriched.vulnerability.severity.toUpperCase(),
                description: f.raw_call || '',
                recommendation: enriched.pqcMigration.recommendation || null
              };
            });

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
    const scan = await prisma.scan.findUnique({ where: { id: scanId } });
    if (!scan) return res.status(404).json({ error: 'Scan not found' });

    const dbFindings = await prisma.finding.findMany({ where: { scanId } });

    // reconstruct rawFindings for the cbomGenerator
    const rawFindings = dbFindings.map(f => ({
      id: f.id,
      file: f.filePath,
      line: f.lineNumber,
      primitive: f.algorithm,
      keySize: f.keySize,
      mode: null,
      context: {
        usageType: f.usage,
        functionName: f.description
      }
    }));

    const cbom = buildCbom({
      scanId: scan.id,
      repoId: scan.repoId,
      rawFindings
    });

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
    const scan = await prisma.scan.findUnique({ where: { id: scanId } });
    if (!scan) return res.status(404).json({ error: 'Scan not found' });

    // Build CBOM to hash
    const dbFindings = await prisma.finding.findMany({ where: { scanId } });
    const rawFindings = dbFindings.map(f => ({
      id: f.id,
      file: f.filePath,
      line: f.lineNumber,
      primitive: f.algorithm,
      keySize: f.keySize,
      mode: null,
      context: {
        usageType: f.usage,
        functionName: f.description
      }
    }));
    const cbom = buildCbom({ scanId: scan.id, repoId: scan.repoId, rawFindings });
    const contentBuffer = Buffer.from(JSON.stringify(cbom));

    // Check if we use mock (from frontend or env)
    const useMock = process.env.USE_MOCK === 'true';
    if (useMock) {
      return res.json({
        txHash: "0x7f3a9a14b51c881249b6d9e034abc88d92bc9f201a9f14",
        onChainHash: "8f4c7a91d2938f45a6b7e8d9c102b3a4f5c6e7d8a9b0c1d2e3f4a5b6c7d8e91a",
        network: "mocknet"
      });
    }

    const anchorResult = await anchorScan(scanId, contentBuffer);

    // Save to DB
    await prisma.anchor.create({
      data: {
        scanId: scan.id,
        contentHash: anchorResult.contentHash,
        txHash: anchorResult.txHash,
        signature: anchorResult.signature,
        network: anchorResult.network || "localhost"
      }
    });

    return res.json(anchorResult);
  } catch (err) {
    console.error('Anchor error:', err);
    return res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// GET /scan/:scanId/verify
router.get('/:scanId/verify', requireAuth, async (req, res) => {
  try {
    const { scanId } = req.params;
    const scan = await prisma.scan.findUnique({ where: { id: scanId } });
    if (!scan) return res.status(404).json({ error: 'Scan not found' });

    // Check if we use mock
    const useMock = process.env.USE_MOCK === 'true';
    if (useMock) {
      return res.json({
        verified: true,
        onChainHash: "8f4c7a91d2938f45a6b7e8d9c102b3a4f5c6e7d8a9b0c1d2e3f4a5b6c7d8e91a",
        offChainHash: "8f4c7a91d2938f45a6b7e8d9c102b3a4f5c6e7d8a9b0c1d2e3f4a5b6c7d8e91a"
      });
    }

    // Build CBOM to hash
    const dbFindings = await prisma.finding.findMany({ where: { scanId } });
    const rawFindings = dbFindings.map(f => ({
      id: f.id,
      file: f.filePath,
      line: f.lineNumber,
      primitive: f.algorithm,
      keySize: f.keySize,
      mode: null,
      context: {
        usageType: f.usage,
        functionName: f.description
      }
    }));
    const cbom = buildCbom({ scanId: scan.id, repoId: scan.repoId, rawFindings });
    const contentBuffer = Buffer.from(JSON.stringify(cbom));

    // Read stored signature if it exists
    const storedAnchor = await prisma.anchor.findUnique({ where: { scanId } });
    const signature = storedAnchor ? storedAnchor.signature : null;

    const verifyResult = await verifyScan(scanId, contentBuffer, signature);

    return res.json({
      verified: verifyResult.verified,
      onChainHash: verifyResult.onChainHash,
      offChainHash: verifyResult.recomputedHash,
      signatureValid: verifyResult.signatureValid
    });
  } catch (err) {
    console.error('Verify error:', err);
    return res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

module.exports = router;