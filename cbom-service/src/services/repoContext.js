/**
 * Repository Context Store (Person 3 — Phase 5)
 *
 * Persists repository-level metadata such as Business Importance
 * across consecutive and future scans of the same repository.
 */

const repoImportanceMap = new Map();

function normalizeBusinessImportance(value) {
  if (typeof value !== 'string') return 'Standard';
  const trimmed = value.trim().toLowerCase();
  if (trimmed === 'critical') return 'Critical';
  if (trimmed === 'important') return 'Important';
  if (trimmed === 'standard') return 'Standard';
  return 'Standard';
}

function setRepoBusinessImportance(repoId, importance) {
  if (!repoId) return;
  const normalized = normalizeBusinessImportance(importance);
  repoImportanceMap.set(String(repoId), normalized);
}

function getRepoBusinessImportance(repoId) {
  if (!repoId) return 'Standard';
  return repoImportanceMap.get(String(repoId)) || 'Standard';
}

function clearRepoBusinessImportance() {
  repoImportanceMap.clear();
}

module.exports = {
  setRepoBusinessImportance,
  getRepoBusinessImportance,
  normalizeBusinessImportance,
  clearRepoBusinessImportance,
};
