'use strict';

const crypto = require('crypto');

const PREFIX = 'enc:v1';

function encryptionKey() {
  const encoded = process.env.DATA_ENCRYPTION_KEY;
  if (!encoded) throw new Error('DATA_ENCRYPTION_KEY must be configured (base64-encoded 32-byte AES-256 key)');
  const key = Buffer.from(encoded, 'base64');
  if (key.length !== 32) throw new Error('DATA_ENCRYPTION_KEY must decode to exactly 32 bytes');
  return key;
}

function encrypt(plaintext) {
  if (plaintext === null || plaintext === undefined) return plaintext;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [PREFIX, iv.toString('base64url'), tag.toString('base64url'), ciphertext.toString('base64url')].join(':');
}

function decrypt(value) {
  if (value === null || value === undefined || !String(value).startsWith(`${PREFIX}:`)) return value;
  const [, , ivText, tagText, ciphertextText] = String(value).split(':');
  if (!ivText || !tagText || !ciphertextText) throw new Error('Invalid encrypted field format');
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey(), Buffer.from(ivText, 'base64url'));
  decipher.setAuthTag(Buffer.from(tagText, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(ciphertextText, 'base64url')), decipher.final()]).toString('utf8');
}

function redact(value) { return value === null || value === undefined ? value : '[encrypted]'; }

module.exports = { encrypt, decrypt, redact, PREFIX };
