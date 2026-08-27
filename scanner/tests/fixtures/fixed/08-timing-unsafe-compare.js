const crypto = require('crypto');
function verifySignature(expectedSignature, providedSignature) {
  const a = Buffer.from(expectedSignature);
  const b = Buffer.from(providedSignature);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}
module.exports = { verifySignature };
