const crypto = require('crypto');
function encrypt(data, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const ct = Buffer.concat([cipher.update(data), cipher.final()]);
  return { iv, ct };
}
module.exports = { encrypt };
