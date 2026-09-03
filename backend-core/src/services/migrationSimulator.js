/**
 * Migration Simulator Engine (migrationSimulator.js)
 *
 * Projects the risk-score drop if a target component alone is migrated to its recommended algorithm.
 * Computes real projected score drops by re-running the scoring engine with the target component's
 * post-migration primitive and key size.
 */

const { scoreFinding } = require('./vulnScoring');
const { getMigrationGuidance } = require('./purposeDetection');

/**
 * PQC-safe primitive properties to assume after a successful migration.
 */
const POST_MIGRATION_PROPERTIES = {
  'ML-KEM': { primitive: 'ML-KEM', keySize: 768, mode: null },
  'ML-DSA': { primitive: 'ML-DSA', keySize: 1312, mode: null },
  'SLH-DSA': { primitive: 'SLH-DSA', keySize: null, mode: null },
  'AES-256': { primitive: 'AES', keySize: 256, mode: 'GCM' },
  'SHA-256': { primitive: 'SHA-256', keySize: null, mode: null },
  'Keep AES-256': { primitive: 'AES', keySize: 256, mode: 'GCM' },
  'Keep ChaCha20': { primitive: 'ChaCha20', keySize: 256, mode: 'Poly1305' },
};

function resolvePostMigrationProps(recommendation) {
  if (!recommendation) return null;
  for (const [prefix, props] of Object.entries(POST_MIGRATION_PROPERTIES)) {
    if (recommendation.startsWith(prefix)) return props;
  }
  return null;
}

/**
 * Takes a target component and current findings/score, and projects the resulting risk-score drop
 * if that component alone were migrated to its recommended algorithm.
 *
 * Returns: { targetComponent, currentScore, projectedScore, projectedScoreDrop }
 *
 * @param {object|string} targetComponent - Component object or component identifier/primitive
 * @param {Array} [currentFindings] - Array of enriched finding objects for the scan
 * @param {number} [currentScore] - Optional overall current score (recomputed if not provided)
 */
function simulateMigration(targetComponent, currentFindings = [], currentScore) {
  const findings = Array.isArray(currentFindings) ? currentFindings : [];
  
  const targetId = typeof targetComponent === 'string'
    ? targetComponent
    : (targetComponent.id || targetComponent['bom-ref'] || targetComponent.primitive || '');

  // Calculate current score if not explicitly provided
  let currentSum = 0;
  for (const f of findings) {
    const purpose = (f.purpose && f.purpose.value) ? f.purpose.value : (f.purpose || 'unknown');
    const scoreObj = scoreFinding(f, purpose);
    currentSum += scoreObj.score;
  }

  const baselineScore = currentScore ?? (findings.length > 0 ? Math.round(currentSum / findings.length) : 0);

  // Compute projected score by replacing target component's score with recommended replacement score
  let projectedSum = 0;
  let targetFound = false;

  for (const f of findings) {
    const primitiveName = f.primitiveFamily || f.primitive || '';
    const isTarget = f.id === targetId ||
      primitiveName.toUpperCase() === String(targetId).toUpperCase() ||
      (typeof targetComponent === 'object' && targetComponent !== null && (targetComponent.id === f.id || targetComponent.primitive === f.primitive));

    const purpose = (f.purpose && f.purpose.value) ? f.purpose.value : (f.purpose || 'unknown');

    if (isTarget) {
      targetFound = true;
      const guidance = getMigrationGuidance(primitiveName, purpose);
      const postProps = resolvePostMigrationProps(guidance.recommendation);
      if (postProps) {
        const migratedFinding = { primitive: postProps.primitive, keySize: postProps.keySize, mode: postProps.mode };
        const migratedVuln = scoreFinding(migratedFinding, purpose);
        projectedSum += migratedVuln.score;
      } else {
        const vuln = scoreFinding(f, purpose);
        projectedSum += vuln.score;
      }
    } else {
      const vuln = scoreFinding(f, purpose);
      projectedSum += vuln.score;
    }
  }

  // Fallback for single component simulation when currentFindings is empty
  if (findings.length === 0 && typeof targetComponent === 'object' && targetComponent !== null) {
    const primitiveName = targetComponent.primitive || targetComponent.primitiveFamily || 'RSA';
    const purpose = targetComponent.purpose || 'key_exchange';
    const currentVuln = scoreFinding(targetComponent, purpose);
    const guidance = getMigrationGuidance(primitiveName, purpose);
    const postProps = resolvePostMigrationProps(guidance.recommendation);
    
    let projScore = currentVuln.score;
    if (postProps) {
      const migrated = scoreFinding({ primitive: postProps.primitive, keySize: postProps.keySize }, purpose);
      projScore = migrated.score;
    }

    const drop = Math.max(0, currentVuln.score - projScore);
    return {
      targetComponent,
      currentScore: currentVuln.score,
      projectedScore: projScore,
      projectedScoreDrop: drop,
    };
  }

  const projectedScore = findings.length > 0 ? Math.round(projectedSum / findings.length) : baselineScore;
  const projectedScoreDrop = Math.max(0, baselineScore - projectedScore);

  return {
    targetComponent,
    currentScore: baselineScore,
    projectedScore,
    projectedScoreDrop,
  };
}

module.exports = { simulateMigration, resolvePostMigrationProps };
