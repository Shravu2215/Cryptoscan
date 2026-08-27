const crypto = require('crypto');
const scrypt = require('scrypt-kdf');
async function hashPassword(password) {
  const key = await scrypt.kdf(password, { logN: 15 });
  return key.toString('hex');
}
module.exports = { hashPassword };
