const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
// JWT_SECRET is guaranteed present by config/env.js validateEnv() at startup,
// so the hardcoded default fallback is gone — secrets come from env only.
//
// Day 7 live-bug fix: ENCRYPTION_KEY is a STRING in env, but aes-256-gcm
// needs exactly 32 key BYTES — passing the raw string to createCipheriv
// throws "Invalid key length", which made every encrypt() call in
// production fail (alert settings with a webhook URL, PAT saves: both
// 500). Normalize: a 64-hex-char value is a hex-encoded 32-byte key;
// any other string is hashed to 32 bytes (deterministic, so decrypt
// keeps working for values encrypted under the normalized key). When
// ENCRYPTION_KEY is unset, the old JWT_SECRET-hash fallback is preserved.
function deriveKey() {
  const raw = process.env.ENCRYPTION_KEY;
  if (raw && /^[0-9a-fA-F]{64}$/.test(raw)) return Buffer.from(raw, 'hex');
  if (raw) return crypto.createHash('sha256').update(raw).digest();
  return crypto.createHash('sha256').update(process.env.JWT_SECRET).digest();
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
  if (parts.length !== 3) return encryptedText; // Fallback for unencrypted legacy data
  try {
    const iv = Buffer.from(parts[0], 'hex');
    const authTag = Buffer.from(parts[1], 'hex');
    const encrypted = parts[2];
    const decipher = crypto.createDecipheriv(ALGORITHM, SECRET_KEY, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (err) {
    console.error('Decryption failed:', err.message);
    return encryptedText;
  }
}

module.exports = { encrypt, decrypt };
