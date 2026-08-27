function verifySignature(expectedSignature, providedSignature) {
  return expectedSignature === providedSignature;
}
module.exports = { verifySignature };
