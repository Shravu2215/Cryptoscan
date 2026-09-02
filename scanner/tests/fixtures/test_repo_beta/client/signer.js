const jsrsasign = require("jsrsasign");
const crypto = require("crypto");

function createLegacySignature(data, prvKey) {
    // Deprecated SHA1withRSA signature
    const sig = new jsrsasign.KJUR.crypto.Signature({ alg: "SHA1withRSA" });
    sig.init(prvKey);
    sig.updateString(data);
    return sig.sign();
}

function calculateSecureDigest(content) {
    // Modern SHA-512 digest - should not be flagged
    return crypto.createHash("sha512").update(content).digest("hex");
}

module.exports = { createLegacySignature, calculateSecureDigest };
