const crypto = require('crypto');
const KEY = "supersecretkey1234567890123456!!";
function encrypt(data) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', KEY, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}
module.exports = { encrypt };
