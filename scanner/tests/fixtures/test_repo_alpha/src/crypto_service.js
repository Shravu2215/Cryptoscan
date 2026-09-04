const CryptoJS = require("crypto-js");

function encryptPayload(text, secretKey) {
    // Deprecated DES encryption
    return CryptoJS.DES.encrypt(text, secretKey).toString();
}

function encryptSecure(text, secretKey) {
    // Modern AES-256-GCM / AES encryption
    return CryptoJS.AES.encrypt(text, secretKey).toString();
}

module.exports = { encryptPayload, encryptSecure };
