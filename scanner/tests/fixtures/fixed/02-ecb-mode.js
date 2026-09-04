const crypto = require('crypto');
function encrypt(data, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(data), cipher.final()]);
  return { iv, ct, tag: cipher.getAuthTag() };
}
module.exports = { encrypt };
