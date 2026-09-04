/**
 * CBOM Diff Service (Person 3 — Phase 3)
 *
 * Compares two CycloneDX CBOMs (typically current vs immediately preceding scan
 * of the same repository) and detects added, removed, and modified cryptographic components.
 */

/**
 * Resolves a stable unique identifier for a CycloneDX component.
 * Uses bom-ref if present, falling back to name or primitive family/mode/keySize.
 */
function getComponentIdentity(component) {
  if (!component || typeof component !== 'object') return null;
  if (component['bom-ref']) return String(component['bom-ref']);
  if (component.name) return String(component.name);
  const crypto = component.cryptoProperties?.algorithmProperties;
  if (crypto) {
    return `${crypto.primitive || 'unknown'}-${crypto.parameterSetIdentifier || ''}-${crypto.mode || ''}`;
  }
  return null;
}

/**
 * Compares two components with the same identity to determine if they changed
 * and what specifically changed.
 */
function diffComponent(curr, prev) {
  const changes = {};
  let hasChanges = false;

  // 1. Severity change
  const currSev = (curr.maxSeverity || '').toUpperCase();
  const prevSev = (prev.maxSeverity || '').toUpperCase();
  if (currSev !== prevSev) {
    changes.maxSeverity = { previous: prev.maxSeverity, current: curr.maxSeverity };
    hasChanges = true;
  }

  // 2. Vulnerability score change
  const currScore = curr.maxVulnerabilityScore ?? 0;
  const prevScore = prev.maxVulnerabilityScore ?? 0;
  if (currScore !== prevScore) {
    changes.maxVulnerabilityScore = { previous: prevScore, current: currScore };
    hasChanges = true;
  }

  // 3. Crypto properties change
  const currCrypto = JSON.stringify(curr.cryptoProperties || {});
  const prevCrypto = JSON.stringify(prev.cryptoProperties || {});
  if (currCrypto !== prevCrypto) {
    changes.cryptoProperties = {
      previous: prev.cryptoProperties || null,
      current: curr.cryptoProperties || null,
    };
    hasChanges = true;
  }

  // 4. Occurrences change
  const currOcc = Array.isArray(curr.occurrences) ? curr.occurrences : [];
  const prevOcc = Array.isArray(prev.occurrences) ? prev.occurrences : [];

  const occKey = (o) => `${o.file || o.filePath}:${o.line || o.lineNumber}:${o.usage || ''}`;
  const prevOccKeys = new Set(prevOcc.map(occKey));
  const currOccKeys = new Set(currOcc.map(occKey));

  const addedOcc = currOcc.filter(o => !prevOccKeys.has(occKey(o)));
  const removedOcc = prevOcc.filter(o => !currOccKeys.has(occKey(o)));

  if (addedOcc.length > 0 || removedOcc.length > 0 || currOcc.length !== prevOcc.length) {
    changes.occurrences = {
      previousCount: prevOcc.length,
      currentCount: currOcc.length,
      addedCount: addedOcc.length,
      removedCount: removedOcc.length,
      added: addedOcc,
      removed: removedOcc,
    };
    hasChanges = true;
  }

  return { hasChanges, changes };
}

/**
 * Computes deterministic diff between current CBOM and previous CBOM.
 *
 * @param {object} currentCbom - Current scan CBOM document
 * @param {object|null} previousCbom - Previous scan CBOM document (or null/undefined)
 * @returns {object} Diff report containing added, removed, changed, and summary metrics
 */
function computeCbomDiff(currentCbom, previousCbom) {
  const currSafe = (currentCbom && typeof currentCbom === 'object') ? currentCbom : null;
  const prevSafe = (previousCbom && typeof previousCbom === 'object') ? previousCbom : null;

  const currentComponents = (currSafe && Array.isArray(currSafe.components)) ? currSafe.components : [];
  const previousComponents = (prevSafe && Array.isArray(prevSafe.components)) ? prevSafe.components : [];

  const currentVersion = currSafe?.cbomVersion || (currSafe?.version ? `CBOM-v${currSafe.version}` : 'CBOM-v1');
  const previousVersion = prevSafe?.cbomVersion || (prevSafe?.version ? `CBOM-v${prevSafe.version}` : null);
  const repoId = currSafe?.metadata?.component?.name || prevSafe?.metadata?.component?.name || null;

  // Case 1: No previous CBOM (First scan or missing/malformed previous)
  if (!prevSafe || !Array.isArray(prevSafe.components)) {
    return {
      hasPrevious: false,
      currentVersion,
      previousVersion: null,
      repoId,
      identical: false,
      summary: {
        addedCount: currentComponents.length,
        removedCount: 0,
        changedCount: 0,
        unchangedCount: 0,
        totalCurrent: currentComponents.length,
        totalPrevious: 0,
      },
      added: currentComponents,
      removed: [],
      changed: [],
      unchanged: [],
    };
  }

  // Map components by stable identity
  const currMap = new Map();
  for (const c of currentComponents) {
    const id = getComponentIdentity(c);
    if (id) currMap.set(id, c);
  }

  const prevMap = new Map();
  for (const c of previousComponents) {
    const id = getComponentIdentity(c);
    if (id) prevMap.set(id, c);
  }

  const added = [];
  const removed = [];
  const changed = [];
  const unchanged = [];

  // Check current components against previous
  for (const [id, currComp] of currMap.entries()) {
    if (!prevMap.has(id)) {
      added.push(currComp);
    } else {
      const prevComp = prevMap.get(id);
      const { hasChanges, changes } = diffComponent(currComp, prevComp);
      if (hasChanges) {
        changed.push({
          ref: id,
          name: currComp.name || id,
          changes,
          previousComponent: prevComp,
          currentComponent: currComp,
        });
      } else {
        unchanged.push(currComp);
      }
    }
  }

  // Check for removed components
  for (const [id, prevComp] of prevMap.entries()) {
    if (!currMap.has(id)) {
      removed.push(prevComp);
    }
  }

  const identical = added.length === 0 && removed.length === 0 && changed.length === 0;

  return {
    hasPrevious: true,
    currentVersion,
    previousVersion,
    repoId,
    identical,
    summary: {
      addedCount: added.length,
      removedCount: removed.length,
      changedCount: changed.length,
      unchangedCount: unchanged.length,
      totalCurrent: currentComponents.length,
      totalPrevious: previousComponents.length,
    },
    added,
    removed,
    changed,
    unchanged,
  };
}

module.exports = {
  computeCbomDiff,
  getComponentIdentity,
  diffComponent,
};
