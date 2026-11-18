'use strict';

const crypto = require('crypto');

// Scopes an API key may carry. 'read' = GET findings/scans/SBOMs;
// 'scan:trigger' = POST /api/scans/trigger. Nothing else is reachable
// with a key: writes are denied at auth, not at the handler.
const API_KEY_SCOPES = ['read', 'scan:trigger'];

function hashApiKey(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

// Returns { key, keyPrefix, keyHash }. The full key is shown once at
// creation and never stored — only keyHash reaches the database.
function generateApiKey() {
  const key = `sg_${crypto.randomBytes(24).toString('hex')}`;
  return { key, keyPrefix: key.slice(0, 12), keyHash: hashApiKey(key) };
}

module.exports = { API_KEY_SCOPES, generateApiKey, hashApiKey };
