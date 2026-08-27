const crypto = require('crypto');
function genKeyPair() {
  return crypto.generateKeyPairSync('rsa', { modulusLength: 3072 });
}
module.exports = { genKeyPair };
