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
router.get('/scan/:scanId/cbom', (req, res) => {
  const scan = store.getScan(req.params.scanId);
  if (!scan) {
    return res.status(404).json({ error: `No findings ingested yet for scanId "${req.params.scanId}"` });
  }
  res.json(buildCbom(scan));
});

module.exports = router;
