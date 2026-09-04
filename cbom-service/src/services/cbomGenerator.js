const { detectPurpose, getMigrationGuidance } = require('./purposeDetection');
const { scoreFinding } = require('./vulnScoring');
const { normalizeFamily } = require('./primitiveFamily');
const { getRepoBusinessImportance } = require('./repoContext');

/**
 * Enriches one raw scanner finding with purpose, migration guidance, and
 * a vulnerability score. Used by both /findings (lighter view) and
 * /cbom (full CycloneDX-style view).
 */
function enrichFinding(raw, businessImportance) {
  raw.primitive = raw.primitive || raw.algorithm;
  const family = normalizeFamily(raw.primitive);
  const { purpose, confidence, source } = detectPurpose(raw);
  const migration = getMigrationGuidance(family, purpose, raw);
  const vulnerability = scoreFinding(raw, purpose, { businessImportance });

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
  const biz = getRepoBusinessImportance(scan.repoId);
  const rawFindings = (scan.rawFindings || []).filter(f => !f.suppressed);
  const findings = rawFindings.map(f => enrichFinding(f, biz));
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
  scan = scan || {};
  const biz = require('./repoContext').getRepoBusinessImportance(scan.repoId);
  const rawFindings = (scan.rawFindings || []).filter(f => !f.suppressed);
  // Ensure we have enriched findings if they aren't pre-enriched (either flat from mocks or nested from /findings API)
  const findings = rawFindings.map(f => (f.severity || f.vulnerability) ? f : enrichFinding(f, biz));

  const componentsByKey = new Map();
  for (const f of findings) {
    const primitive = f.primitive || f.algorithm || 'UNKNOWN';
    const key = `${primitive}-${f.keySize || 'default'}-${f.mode || 'default'}`;
    if (!componentsByKey.has(key)) {
      componentsByKey.set(key, {
        type: 'cryptographic-asset',
        name: primitive,
        'bom-ref': `crypto-asset/${primitive.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}`,
        cryptoProperties: {
          assetType: 'algorithm',
          algorithmProperties: { primitive: primitive },
        },
        occurrences: [],
        maxVulnerabilityScore: 0,
        maxSeverity: 'INFO',
      });
    }
    const component = componentsByKey.get(key);
    
    // Read from either the flat structure (backend-core) or the enriched structure (cbom-service)
    const severity = f.severity || (f.vulnerability && f.vulnerability.severity) || 'INFO';
    const usage = f.usage || (f.purpose && f.purpose.value) || null;
    const quantumStatus = f.quantumStatus || (f.pqcMigration && f.pqcMigration.quantumExposure) || null;
    const recommendation = f.recommendation || (f.pqcMigration && f.pqcMigration.recommendation) || null;

    component.occurrences.push({
      file: f.file,
      line: f.line,
      findingId: f.id,
      usage: usage,
      severity: severity,
      quantumStatus: quantumStatus,
      recommendation: recommendation,
    });
    const weight = SEVERITY_WEIGHT[severity.toUpperCase()] ?? 0;
    if (weight > component.maxVulnerabilityScore) {
      component.maxVulnerabilityScore = weight;
      component.maxSeverity = severity;
    }
  }

  const components = Array.from(componentsByKey.values());

  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    const sev = (f.severity || (f.vulnerability && f.vulnerability.severity) || 'INFO').toLowerCase();
    const bucket = sev === 'informational' ? 'info' : sev;
    if (severityCounts[bucket] !== undefined) severityCounts[bucket]++;
  }

  const { assessMigration } = require('./migrationAssessment');
  const migrationPlan = assessMigration(scan, findings);

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:cbom-${scan.scanId}`,
    version: resolveCbomVersion(scan),
    businessImportance: getRepoBusinessImportance(scan.repoId),
    cbomVersion: `CBOM-v${resolveCbomVersion(scan)}`,
    provenance: { scanTimestamp: resolveScanTimestamp(scan), scannerVersion: resolveScannerVersion(scan), cbomVersion: `CBOM-v${resolveCbomVersion(scan)}`, version: resolveCbomVersion(scan) },
    metadata: {
      timestamp: resolveScanTimestamp(scan),
      tools: { components: [{ type: 'application', name: 'CryptoScan Scanner', version: resolveScannerVersion(scan) }] },
      provenance: { scanTimestamp: resolveScanTimestamp(scan), scannerVersion: resolveScannerVersion(scan), cbomVersion: `CBOM-v${resolveCbomVersion(scan)}`,
        version: resolveCbomVersion(scan) },
      component: {
        type: 'application',
        name: scan.repoId || scan.scanId,
        'bom-ref': `urn:uuid:cbom-${scan.scanId}`
      },
      properties: [
        { name: 'scanId', value: scan.scanId },
        { name: 'findingCount', value: String(findings.length) },
        { name: 'commitHash', value: resolveCommitHash(scan) },
        { name: 'cbomVersion', value: `CBOM-v${resolveCbomVersion(scan)}` },
        { name: 'pqcMigrationAssessment', value: JSON.stringify(migrationPlan) }
      ],
    },
    components,
    dependencies: buildDependencies(scan),
    summary: {
      totalCryptoAssets: components.length,
      totalFindings: findings.length,
      severityCounts,
    },
  };
}


function resolveCommitHash(s) { 
  if (s && s.commitHash) return s.commitHash;
  if (s && s.repo && s.repo.commitHash) return s.repo.commitHash;
  if (s && s.revision) return s.revision;
  if (s && s.repoPath) {
    try {
      return require('child_process').execSync('git rev-parse HEAD', { cwd: s.repoPath, stdio: 'pipe' }).toString().trim();
    } catch(e) {
      console.warn(`[Provenance Warning] Failed to resolve commit hash via git in ${s.repoPath}. Ensure deploy context includes .git history.`);
      return 'unavailable';
    }
  }
  return 'unavailable';
}

function resolveCbomVersion(scan) {
  if (scan && scan.version) return parseInt(scan.version);
  if (scan && scan.cbomVersion) return parseInt(scan.cbomVersion.replace('CBOM-v', ''));
  if (!scan || !scan.repoScans || !scan.createdAt) return 1;
  const scans = scan.repoScans.filter(s => s.repoId === scan.repoId);
  scans.sort((a,b) => new Date(a.createdAt) - new Date(b.createdAt));
  const idx = scans.findIndex(s => s.id === scan.scanId || s.scanId === scan.scanId);
  return idx >= 0 ? idx + 1 : 1;
}
function resolveScanTimestamp(s) { 
  if (s && s.scanTimestamp) return new Date(s.scanTimestamp).toISOString();
  if (s && s.createdAt) { try { return new Date(s.createdAt).toISOString(); } catch(e) {} }
  if (s && s.receivedAt) return new Date(s.receivedAt).toISOString();
  return new Date().toISOString();
}
function resolveScannerVersion(s) { 
  if (s && s.scannerVersion) return s.scannerVersion;
  return process.env.SCANNER_VERSION || '2.4.0';
}
function buildDependencies(scan) {
  const root = `urn:uuid:cbom-${scan.scanId}`;
  const deps = [];
  const compMap = new Map();
  if (scan.rawFindings) {
    for (const f of scan.rawFindings) {
      const ref = `crypto-asset/${(f.algorithm || 'UNKNOWN').replace(/[^a-z0-9]+/gi, '-').toLowerCase()}`;
      if (!compMap.has(ref)) compMap.set(ref, new Set());
      if (f.dependsOn && Array.isArray(f.dependsOn)) {
        for (const d of f.dependsOn) {
          compMap.get(ref).add(`crypto-asset/${d.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}`);
        }
      }
    }
  }
  deps.push({ ref: root, dependsOn: Array.from(compMap.keys()) });
  for (const [ref, dependsOnSet] of compMap.entries()) {
    deps.push({ ref: ref, dependsOn: Array.from(dependsOnSet) });
  }
  return deps;
}
module.exports = { enrichFinding, buildFindingsResponse, buildCbom, resolveCommitHash, resolveScanTimestamp, resolveScannerVersion, buildDependencies, resolveCbomVersion };






