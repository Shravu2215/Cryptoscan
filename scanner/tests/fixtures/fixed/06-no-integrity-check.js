const crypto = require('crypto');
function encrypt(data, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(data), cipher.final()]);
  return { iv, ct, tag: cipher.getAuthTag() };
}
function decrypt(payload, key) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, payload.iv);
  decipher.setAuthTag(payload.tag);
  return Buffer.concat([decipher.update(payload.ct), decipher.final()]);
}
module.exports = { encrypt, decrypt };
