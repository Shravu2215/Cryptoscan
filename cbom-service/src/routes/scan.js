const express = require('express');
const store = require('../data/store');
const { buildFindingsResponse, buildCbom } = require('../services/cbomGenerator');

const router = express.Router();

/**
 * Internal ingest endpoint — the Scanner Engine module (Person 2) POSTs
 * its structured output here. Not part of the public API contract, but
 * needed so this module has real data to serve instead of being
 * permanently stuck on mock JSON.
 *
 * Body: { repoId?, language?, findings: [ {...} ] }
 * See data/samples/scanner-output.sample.json for the expected finding shape.
 */
router.post('/internal/scan/:scanId/ingest', (req, res) => {
  try {
    const record = store.ingestFindings(req.params.scanId, req.body || {});
    res.status(201).json({
      scanId: record.scanId,
      totalFindingsStored: record.rawFindings.length,
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// GET /scan/:scanId/findings — scanner output, enriched, served over the API.
router.get('/scan/:scanId/findings', (req, res) => {
  const scan = store.getScan(req.params.scanId);
  if (!scan) {
    return res.status(404).json({ error: `No findings ingested yet for scanId "${req.params.scanId}"` });
  }
  res.json(buildFindingsResponse(scan));
});

// GET /scan/:scanId/cbom — full Cryptographic Bill of Materials.
router.get('/scan/:scanId/cbom', async (req, res) => {
  try {
    const scan = store.getScan(req.params.scanId);
    if (!scan) {
      return res.status(404).json({ error: `No findings ingested yet for scanId "${req.params.scanId}"` });
    }
    const repoScans = store.getRepoScans ? store.getRepoScans(scan.repoId) : [];
    const cbom = buildCbom({ ...scan, repoScans });

    if (req.query.signed === 'true') {
      const { exportSignedCbom } = require('../services/signedCbomExport');
      const signed = await exportSignedCbom(cbom);
      return res.json(signed);
    }

    res.json(cbom);
  } catch (err) {
    console.error('CBOM fetch error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /scan/:scanId/diff — compare with previous scan of same repository
router.get('/scan/:scanId/diff', (req, res) => {
  const scan = store.getScan(req.params.scanId);
  if (!scan) {
    return res.status(404).json({ error: `No findings ingested yet for scanId "${req.params.scanId}"` });
  }
  const repoScans = store.getRepoScans ? store.getRepoScans(scan.repoId) : [];
  const currentCbom = buildCbom({ ...scan, repoScans });

  let previousCbom = null;
  if (scan.repoId && repoScans.length > 1) {
    const currentIndex = repoScans.findIndex(s => s.scanId === scan.scanId);
    if (currentIndex > 0) {
      const prevScan = repoScans[currentIndex - 1];
      previousCbom = buildCbom({ ...prevScan, repoScans });
    }
  }

  const { computeCbomDiff } = require('../services/cbomDiff');
  res.json(computeCbomDiff(currentCbom, previousCbom));
});

// GET /scan/:scanId/migration-assessment
// Production-grade endpoint — evaluates PQC migration for a full scan.
router.get('/scan/:scanId/migration-assessment', (req, res) => {
  try {
    const scan = store.getScan(req.params.scanId);
    if (!scan) {
      return res.status(404).json({ error: `No findings ingested yet for scanId "${req.params.scanId}"` });
    }
    const { assessMigration } = require('../services/migrationAssessment');
    const result = assessMigration(scan, scan.rawFindings || []);
    return res.json(result);
  } catch (err) {
    return res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

module.exports = router;

