/**
 * CBOM Versioning & Diff Engine
 *
 * Provides CBOM-v1, CBOM-v2, ... versioning per repo, and a diff function
 * that shows added, removed, and changed cryptographic components between
 * two CBOM versions.
 *
 * Storage strategy: in-memory map for the cbom-service standalone use;
 * persistence is handled by the backend-core via the CbomVersion Prisma model.
 */

// In-memory store keyed by repoId — used when persistence is not available.
const _versionStore = new Map(); // repoId => Array<{versionNumber, scanId, content, createdAt}>

/**
 * Saves a new CBOM version for a repo.
 * Auto-increments version number (CBOM-v1, CBOM-v2, ...).
 *
 * @param {string} repoId
 * @param {string} scanId
 * @param {object} cbomContent - Parsed CBOM object (not a JSON string)
 * @param {object} [store] - Optional external map for dependency injection / testing
 * @returns {{ versionNumber: number, versionLabel: string, repoId: string, scanId: string, createdAt: string }}
 */
function saveCbomVersion(repoId, scanId, cbomContent, store = _versionStore) {
  if (!repoId || !scanId || !cbomContent) {
    throw new Error('saveCbomVersion: repoId, scanId, and cbomContent are required');
  }

  if (!store.has(repoId)) store.set(repoId, []);
  const versions = store.get(repoId);
  const versionNumber = versions.length + 1;
  const versionLabel = `CBOM-v${versionNumber}`;
  const entry = {
    versionNumber,
    versionLabel,
    repoId,
    scanId,
    content: cbomContent,
    createdAt: new Date().toISOString(),
  };
  versions.push(entry);

  return { versionNumber, versionLabel, repoId, scanId, createdAt: entry.createdAt };
}

/**
 * Retrieves the version history for a repo.
 *
 * @param {string} repoId
 * @param {object} [store]
 * @returns {Array<{versionNumber, versionLabel, scanId, createdAt}>}
 */
function listCbomVersions(repoId, store = _versionStore) {
  const versions = store.get(repoId) || [];
  return versions.map(({ versionNumber, versionLabel, scanId, createdAt }) => ({
    versionNumber,
    versionLabel,
    scanId,
    createdAt,
  }));
}

/**
 * Retrieves the full CBOM content for a specific version.
 *
 * @param {string} repoId
 * @param {number} versionNumber
 * @param {object} [store]
 * @returns {object|null} CBOM content or null if not found
 */
function getCbomVersion(repoId, versionNumber, store = _versionStore) {
  const versions = store.get(repoId) || [];
  const entry = versions.find((v) => v.versionNumber === versionNumber);
  return entry ? entry.content : null;
}

/**
 * Builds a stable key for a CBOM component to enable identity comparison.
 * Uses primitiveFamily + parameterSetIdentifier + mode.
 */
function componentKey(component) {
  const algo = component.cryptoProperties && component.cryptoProperties.algorithmProperties;
  if (!algo) return component['bom-ref'] || component.name || JSON.stringify(component);
  const primitive = algo.primitive || '';
  const keySize = algo.parameterSetIdentifier || 'unspecified';
  const mode = algo.mode || '';
  return `${primitive}|${keySize}|${mode}`.toLowerCase();
}

/**
 * Compares two CBOM documents and returns a structured diff.
 *
 * @param {object} oldCbom - Previous CBOM content (parsed object)
 * @param {object} newCbom - Current CBOM content (parsed object)
 * @returns {{
 *   added: Array,
 *   removed: Array,
 *   changed: Array<{key, before, after, changedFields}>,
 *   unchanged: number
 * }}
 */
function diffCbomVersions(oldCbom, newCbom) {
  const oldComponents = oldCbom && Array.isArray(oldCbom.components) ? oldCbom.components : [];
  const newComponents = newCbom && Array.isArray(newCbom.components) ? newCbom.components : [];

  const oldMap = new Map(oldComponents.map((c) => [componentKey(c), c]));
  const newMap = new Map(newComponents.map((c) => [componentKey(c), c]));

  const added = [];
  const removed = [];
  const changed = [];
  let unchanged = 0;

  for (const [key, newComp] of newMap) {
    if (!oldMap.has(key)) {
      added.push(newComp);
    } else {
      const oldComp = oldMap.get(key);
      const changedFields = detectChangedFields(oldComp, newComp);
      if (changedFields.length > 0) {
        changed.push({ key, before: oldComp, after: newComp, changedFields });
      } else {
        unchanged++;
      }
    }
  }

  for (const [key, oldComp] of oldMap) {
    if (!newMap.has(key)) {
      removed.push(oldComp);
    }
  }

  return { added, removed, changed, unchanged };
}

/**
 * Returns list of field paths that changed between two components.
 * Checks: name, maxSeverity, maxVulnerabilityScore, occurrences count,
 * and algorithmProperties.
 */
function detectChangedFields(oldComp, newComp) {
  const fields = [];

  if (oldComp.name !== newComp.name) fields.push('name');
  if (oldComp.maxSeverity !== newComp.maxSeverity) fields.push('maxSeverity');
  if (oldComp.maxVulnerabilityScore !== newComp.maxVulnerabilityScore) fields.push('maxVulnerabilityScore');

  const oldOccurrences = (oldComp.occurrences || []).length;
  const newOccurrences = (newComp.occurrences || []).length;
  if (oldOccurrences !== newOccurrences) fields.push('occurrences');

  // Check algorithmProperties changes
  const oldAlgo = (oldComp.cryptoProperties || {}).algorithmProperties || {};
  const newAlgo = (newComp.cryptoProperties || {}).algorithmProperties || {};
  for (const field of ['primitive', 'parameterSetIdentifier', 'mode']) {
    if (oldAlgo[field] !== newAlgo[field]) fields.push(`algorithmProperties.${field}`);
  }

  return fields;
}

module.exports = {
  saveCbomVersion,
  listCbomVersions,
  getCbomVersion,
  diffCbomVersions,
  componentKey,
  _versionStore,
};
