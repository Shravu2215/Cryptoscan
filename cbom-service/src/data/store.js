/**
 * In-memory store, keyed by scanId.
 *
 * This is intentionally swappable: everything reads/writes through the
 * functions below, so replacing this file with a real Postgres/Mongo
 * layer later (once Person 1's DB module is ready) doesn't touch any
 * route or service code.
 *
 * Shape stored per scanId:
 * {
 *   scanId, repoId, receivedAt,
 *   rawFindings: [ ...as received from Scanner Engine... ]
 * }
 */

const scans = new Map();

function ingestFindings(scanId, payload) {
  if (!scanId) throw new Error('scanId is required');
  if (!Array.isArray(payload.findings)) {
    throw new Error('payload.findings must be an array');
  }

  const existing = scans.get(scanId);
  const record = {
    scanId,
    repoId: payload.repoId || (existing && existing.repoId) || null,
    language: payload.language || (existing && existing.language) || null,
    receivedAt: new Date().toISOString(),
    // Ingest is additive so the Scanner Engine can stream findings in
    // batches (e.g. per-file) instead of one giant payload at the end.
    rawFindings: [...(existing ? existing.rawFindings : []), ...payload.findings],
  };

  scans.set(scanId, record);
  return record;
}

function getScan(scanId) {
  return scans.get(scanId) || null;
}

function hasScan(scanId) {
  return scans.has(scanId);
}

function listScanIds() {
  return Array.from(scans.keys());
}

function reset() {
  scans.clear();
}

module.exports = { ingestFindings, getScan, hasScan, listScanIds, reset };
