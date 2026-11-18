'use strict';
// Redis read-through cache for vulnerability lists + scan results.
//
// Rules:
// - Keys are always org-scoped: one org can never read another org's
//   cached rows, even if a key is guessed (org id is part of the key).
// - Non-terminal scans (queued/running) are NEVER cached: the dashboard
//   polls GET /api/scans/:id every 2 s and a cached "running" would lie.
//   Only completed/failed scans are cached (terminal rows are immutable).
// - Writes invalidate: scan completion clears the org's scan/vuln keys,
//   a vuln status/label change clears the org's vuln keys.
// - Redis down or unset => bypass: fetch from Postgres, count a bypass,
//   never throw. A cache failure must never fail a request.
const { getRedis } = require('./redis');

const PREFIX = 'sg:cache:v1';
const TTL = { list: 60, detail: 120, summary: 30, terminalScan: 300 };

const stats = { hits: 0, misses: 0, bypasses: 0, sets: 0, invalidations: 0 };
function getStats() { return { ...stats }; }
function resetStats() { stats.hits = 0; stats.misses = 0; stats.bypasses = 0; stats.sets = 0; stats.invalidations = 0; }

function key(orgId, kind, suffix = '') {
  return `${PREFIX}:org:${orgId}:${kind}${suffix ? `:${suffix}` : ''}`;
}
const keys = {
  vulnList: (orgId, q) => key(orgId, 'vulns', q),
  vulnDetail: (orgId, id) => key(orgId, 'vuln', String(id)),
  scanList: (orgId) => key(orgId, 'scans'),
  scanDetail: (orgId, id) => key(orgId, 'scan', String(id)),
  scanSummary: (orgId) => key(orgId, 'scans-summary'),
};

async function get(keyStr) {
  const client = getRedis();
  if (!client) { stats.bypasses++; return { hit: false, value: null, reason: 'no-redis' }; }
  try {
    const raw = await client.get(keyStr);
    if (raw === null) { stats.misses++; return { hit: false, value: null }; }
    stats.hits++;
    return { hit: true, value: JSON.parse(raw) };
  } catch (err) {
    stats.bypasses++;
    return { hit: false, value: null, reason: 'redis-error' };
  }
}

async function set(keyStr, value, ttlSec) {
  const client = getRedis();
  if (!client) return;
  try {
    await client.set(keyStr, JSON.stringify(value), 'EX', ttlSec);
    stats.sets++;
  } catch { /* cache write failure is never fatal */ }
}

// Read-through: returns { value, hit, reason }. fetchFn runs on miss/bypass.
async function getOrSet(keyStr, ttlSec, fetchFn) {
  const found = await get(keyStr);
  if (found.hit) return { value: found.value, hit: true };
  const value = await fetchFn();
  if (value !== null && value !== undefined) await set(keyStr, value, ttlSec);
  return { value, hit: false, reason: found.reason };
}

async function invalidateOrg(orgId) {
  const client = getRedis();
  if (!client) return;
  const pattern = `${PREFIX}:org:${orgId}:*`;
  try {
    let cursor = '0';
    do {
      const [next, found] = await client.scan(cursor, 'MATCH', pattern, 'COUNT', 100);
      cursor = next;
      if (found.length) await client.del(...found);
    } while (cursor !== '0');
    stats.invalidations++;
  } catch { /* invalidation failure leaves at most TTL-stale rows, never an error */ }
}

module.exports = { TTL, keys, get, set, getOrSet, invalidateOrg, getStats, resetStats };
