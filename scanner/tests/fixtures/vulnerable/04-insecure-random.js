function generateToken() {
  const token = Math.random().toString(36).slice(2);
  return token;
}
module.exports = { generateToken };
