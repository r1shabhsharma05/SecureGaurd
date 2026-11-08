const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
// PAT / Slack-webhook encryption key: a dedicated, independent 256-bit key.
// ENCRYPTION_KEY must be a 64-hex-char string (32 bytes, hex-decoded).
// It is NEVER derived from JWT_SECRET and there is no passphrase
// fallback: a missing or malformed key is a startup error, not a silent
// fallback to weaker key material. config/env.js validateEnv() requires
// the variable; deriveKey() below enforces the format at require time.
function deriveKey() {
  const raw = process.env.ENCRYPTION_KEY;
  if (!raw || !/^[0-9a-fA-F]{64}$/.test(raw)) {
    throw new Error('ENCRYPTION_KEY must be a 64-hex-char (256-bit) key');
  }
  return Buffer.from(raw, 'hex');
}
const SECRET_KEY = deriveKey();

function encrypt(text) {
  if (!text) return text;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, SECRET_KEY, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

function decrypt(encryptedText) {
  if (!encryptedText) return encryptedText;
  const parts = encryptedText.split(':');
  // Legacy-plaintext passthrough ONLY for values that are not in the
  // 3-part iv:tag:ciphertext shape (e.g. PATs stored before encryption
  // was introduced). Anything in the encrypted shape that fails GCM
  // authentication throws — a failed decrypt must never be returned as
  // if it were plaintext.
  if (parts.length !== 3) {
    console.warn('[crypto] decrypt: value is not in encrypted (iv:tag:ciphertext) shape; returning as legacy plaintext');
    return encryptedText;
  }
  const iv = Buffer.from(parts[0], 'hex');
  const authTag = Buffer.from(parts[1], 'hex');
  const encrypted = parts[2];
  const decipher = crypto.createDecipheriv(ALGORITHM, SECRET_KEY, iv);
  decipher.setAuthTag(authTag);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

module.exports = { encrypt, decrypt };
