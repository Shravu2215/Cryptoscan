const crypto = require('crypto');
function generateToken() {
  const token = crypto.randomBytes(32).toString('hex');
  return token;
}
module.exports = { generateToken };
