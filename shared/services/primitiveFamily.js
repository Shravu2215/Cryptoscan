/**
 * Normalizes scanner-reported primitive strings ("ECDSA", "ecdh",
 * "SHA-256", "sha256") into the family keys used by the PQC migration
 * table and vulnerability scorer, so the scanner team doesn't have to
 * match our internal naming exactly.
 */
function normalizeFamily(primitive) {
  const p = (primitive || '').toUpperCase().replace(/[\s_]/g, '-');
  if (['ECDSA', 'ECDH', 'EDDSA', 'ECC', 'EC'].includes(p)) return 'ECC';
  if (p === 'SHA256' || p === 'SHA-256') return 'SHA-256';
  if (p === 'SHA1' || p === 'SHA-1') return 'SHA1';
  if (['MD5', 'RSA', 'DSA', 'DH', 'AES', 'DES', '3DES', 'RC4', 'CHACHA20'].includes(p)) return p;
  return p; // pass through; downstream lookups fall back to "unknown"/manual review
}

module.exports = { normalizeFamily };
