'use strict';

// Roles that can see/act on any repo or scan across the organisation
// (security/compliance staff), as opposed to Developers who should only
// see their own uploads.
const ELEVATED_ROLES = Object.freeze(['Admin', 'Security Team', 'Auditor']);

function canAccessRepo(user, repo) {
  if (!user || !repo) return false;
  if (ELEVATED_ROLES.includes(user.role)) return true;
  return repo.uploadedBy === user.id;
}

module.exports = { canAccessRepo, ELEVATED_ROLES };
