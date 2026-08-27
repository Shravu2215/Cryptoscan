const crypto = require('crypto');
function genKeyPair() {
  return crypto.generateKeyPairSync('rsa', { modulusLength: 512 });
}
module.exports = { genKeyPair };
