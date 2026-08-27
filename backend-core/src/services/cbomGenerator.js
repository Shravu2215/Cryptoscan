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

// Rough ordinal weight per severity label, used only to pick the "worst"
// occurrence for a component's maxSeverity/maxVulnerabilityScore - not a
// re-derivation of risk, severity itself always comes from the scanner.
const SEVERITY_WEIGHT = { CRITICAL: 100, HIGH: 75, MEDIUM: 50, LOW: 25, INFORMATIONAL: 0, INFO: 0 };

/**
 * CycloneDX 1.6-shaped Cryptographic Bill of Materials.
 * Each unique algorithm label observed (as reported by the scanner - e.g.
 * "RSA-1024", "AES-256-CBC") becomes one "cryptographic-asset" component;
 * every file/line it was found at is listed under `occurrences`.
 *
 * `scan.rawFindings` here are DB Finding rows (or the equivalent shape),
 * already carrying the scanner's own severity/quantumStatus/recommendation -
 * this function does not recompute risk, it only groups and summarizes it.
 *
 * Spec reference: CycloneDX Cryptography (BOM) — cryptographic-asset
 * component type, assetType "algorithm".
 */
function buildCbom(scan) {
  const findings = scan.rawFindings;

  const componentsByKey = new Map();
  for (const f of findings) {
    const key = f.algorithm || 'UNKNOWN';
    if (!componentsByKey.has(key)) {
      componentsByKey.set(key, {
        type: 'cryptographic-asset',
        name: key,
        'bom-ref': `crypto-asset/${key.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}`,
        cryptoProperties: {
          assetType: 'algorithm',
          algorithmProperties: { primitive: key },
        },
        occurrences: [],
        maxVulnerabilityScore: 0,
        maxSeverity: 'INFO',
      });
    }
    const component = componentsByKey.get(key);
    component.occurrences.push({
      file: f.file,
      line: f.line,
      findingId: f.id,
      usage: f.usage,
      severity: f.severity,
      quantumStatus: f.quantumStatus,
      recommendation: f.recommendation,
    });
    const weight = SEVERITY_WEIGHT[(f.severity || 'INFO').toUpperCase()] ?? 0;
    if (weight > component.maxVulnerabilityScore) {
      component.maxVulnerabilityScore = weight;
      component.maxSeverity = f.severity;
    }
  }

  const components = Array.from(componentsByKey.values());

  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    const sev = (f.severity || 'INFO').toLowerCase();
    const bucket = sev === 'informational' ? 'info' : sev;
    if (severityCounts[bucket] !== undefined) severityCounts[bucket]++;
  }

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
        { name: 'findingCount', value: String(findings.length) },
      ],
    },
    components,
    summary: {
      totalCryptoAssets: components.length,
      totalFindings: findings.length,
      severityCounts,
    },
  };
}

module.exports = { enrichFinding, buildFindingsResponse, buildCbom };
