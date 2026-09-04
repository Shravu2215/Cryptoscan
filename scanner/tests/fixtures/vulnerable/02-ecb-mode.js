const crypto = require('crypto');
function encrypt(data, key) {
  const cipher = crypto.createCipheriv('aes-256-ecb', key, null);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}
module.exports = { encrypt };
