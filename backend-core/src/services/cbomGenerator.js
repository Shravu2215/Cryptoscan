const { detectPurpose, getMigrationGuidance } = require('./purposeDetection');
const { scoreFinding } = require('./vulnScoring');
const { normalizeFamily } = require('./primitiveFamily');

/**
 * Enriches one raw scanner finding with purpose, migration guidance, and
 * a vulnerability score. Used by both /findings (lighter view) and
 * /cbom (full CycloneDX-style view).
 */
function enrichFinding(raw) {
  const family = normalizeFamily(raw.primitive);
  const { purpose, confidence, source } = detectPurpose(raw);
  const migration = getMigrationGuidance(family, purpose);
  const vulnerability = scoreFinding(raw, purpose);

  return {
    id: raw.id,
    file: raw.file,
    line: raw.line,
    primitive: raw.primitive,
    primitiveFamily: family,
    keySize: raw.keySize ?? null,
    mode: raw.mode ?? null,
    purpose: { value: purpose, confidence, source },
    vulnerability,
    pqcMigration: migration,
  };
}

/**
 * GET /scan/:scanId/findings payload — the enriched-but-flat list.
 */
function buildFindingsResponse(scan) {
  const findings = scan.rawFindings.map(enrichFinding);
  return {
    scanId: scan.scanId,
    repoId: scan.repoId,
    receivedAt: scan.receivedAt,
    findingCount: findings.length,
    findings,
  };
}

/**
 * CycloneDX 1.6-shaped Cryptographic Bill of Materials.
 * Each unique (primitive, keySize, mode) observed becomes one
 * "cryptographic-asset" component; every file/line it was found at is
 * listed under `occurrences`, and per-occurrence purpose/score/migration
 * data is kept in `properties` so nothing from the enrichment is lost.
 *
 * Spec reference: CycloneDX Cryptography (BOM) — cryptographic-asset
 * component type, assetType "algorithm".
 */
function buildCbom(scan) {
  const enriched = scan.rawFindings.map(enrichFinding);

  const componentsByKey = new Map();
  for (const f of enriched) {
    const key = `${f.primitiveFamily}|${f.keySize}|${f.mode}`;
    if (!componentsByKey.has(key)) {
      componentsByKey.set(key, {
        type: 'cryptographic-asset',
        name: f.primitive,
        'bom-ref': `crypto-asset/${key.replace(/\|/g, '-').toLowerCase()}`,
        cryptoProperties: {
          assetType: 'algorithm',
          algorithmProperties: {
            primitive: f.primitiveFamily,
            parameterSetIdentifier: f.keySize ? String(f.keySize) : 'unspecified',
            mode: f.mode || undefined,
          },
        },
        occurrences: [],
        maxVulnerabilityScore: 0,
        maxSeverity: 'info',
      });
    }
    const component = componentsByKey.get(key);
    component.occurrences.push({
      file: f.file,
      line: f.line,
      findingId: f.id,
      purpose: f.purpose,
      vulnerability: f.vulnerability,
      pqcMigration: f.pqcMigration,
    });
    if (f.vulnerability.score > component.maxVulnerabilityScore) {
      component.maxVulnerabilityScore = f.vulnerability.score;
      component.maxSeverity = f.vulnerability.severity;
    }
  }

  const components = Array.from(componentsByKey.values());

  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of enriched) severityCounts[f.vulnerability.severity]++;

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:cbom-${scan.scanId}`,
    version: 1,
    metadata: {
      timestamp: scan.createdAt ? new Date(scan.createdAt).toISOString() : new Date(0).toISOString(),
      component: {
        type: 'application',
        name: scan.repoId || scan.scanId,
      },
      properties: [
        { name: 'scanId', value: scan.scanId },
        { name: 'findingCount', value: String(enriched.length) },
      ],
    },
    components,
    summary: {
      totalCryptoAssets: components.length,
      totalFindings: enriched.length,
      severityCounts,
    },
  };
}

module.exports = { enrichFinding, buildFindingsResponse, buildCbom };
