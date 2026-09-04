const crypto = require('crypto');
const KEY = Buffer.from(process.env.APP_ENC_KEY, 'hex');
function encrypt(data) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const ct = Buffer.concat([cipher.update(data), cipher.final()]);
  return { iv, ct, tag: cipher.getAuthTag() };
}
module.exports = { encrypt };
