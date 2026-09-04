const crypto = require('crypto');
const IV = Buffer.from('0000000000000000', 'hex');
function encrypt(data, key) {
  const cipher = crypto.createCipheriv('aes-256-cbc', key, IV);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}
module.exports = { encrypt };
