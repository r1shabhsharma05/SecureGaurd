'use strict';

// Scan queue + cache unit tests. Offline: no Redis, no Postgres.
// Run: node --test backend/tests/scanQueueCache.test.js
//   from SecureGaurd-main.
const test = require('node:test');
const assert = require('node:assert/strict');

delete process.env.REDIS_URL; // force inline queue + (for cache) injected fake client

// ── Fake Redis client (in-memory Map) ─────────────────────────────────────
function fakeRedis() {
  const store = new Map();
  return {
    store,
    async get(k) { return store.has(k) ? store.get(k) : null; },
    async set(k, v) { store.set(k, v); return 'OK'; },
    async del(...ks) { let n = 0; for (const k of ks) if (store.delete(k)) n++; return n; },
    async scan(cursor, ...args) {
      const match = args[args.indexOf('MATCH') + 1];
      const prefix = match.replace(/\*$/, '');
      const found = [...store.keys()].filter((k) => k.startsWith(prefix));
      return ['0', found];
    },
    on() {},
  };
}

const cache = require('../utils/cache');
const redis = require('../utils/redis');

test('cache: miss then hit, stats count both, invalidateOrg drops the key', async () => {
  const client = fakeRedis();
  redis.__setCacheClient(client);
  cache.resetStats();
  let fetches = 0;
  const fetchFn = async () => { fetches++; return [{ id: 1 }]; };
  const key = cache.keys.vulnList(7, '{"severity":null,"status":null,"scanId":null}');

  const first = await cache.getOrSet(key, 60, fetchFn);
  assert.equal(first.hit, false);
  assert.equal(fetches, 1);
  const second = await cache.getOrSet(key, 60, fetchFn);
  assert.equal(second.hit, true);
  assert.equal(fetches, 1); // second read served from cache, no refetch
  assert.deepEqual(second.value, [{ id: 1 }]);

  const stats = cache.getStats();
  assert.equal(stats.misses, 1);
  assert.equal(stats.hits, 1);

  await cache.invalidateOrg(7);
  const third = await cache.getOrSet(key, 60, fetchFn);
  assert.equal(third.hit, false);
  assert.equal(fetches, 2);

  // Another org's keys are untouched by the invalidation.
  const otherKey = cache.keys.vulnList(8, '{"severity":null,"status":null,"scanId":null}');
  await cache.getOrSet(otherKey, 60, fetchFn);
  await cache.invalidateOrg(7);
  const otherAgain = await cache.getOrSet(otherKey, 60, fetchFn);
  assert.equal(otherAgain.hit, true);
  redis.__setCacheClient(null);
});

test('cache: no Redis configured => bypass, never throws', async () => {
  redis.__setCacheClient(null);
  cache.resetStats();
  const res = await cache.getOrSet('sg:cache:v1:org:1:vulns:x', 60, async () => ({ a: 1 }));
  assert.equal(res.hit, false);
  assert.deepEqual(res.value, { a: 1 });
  assert.equal(cache.getStats().bypasses, 1);
});

// ── Inline queue (no REDIS_URL): enqueue runs the job, stats track it ────
const scanRunnerPath = require.resolve('../services/scanRunner');
const executed = [];
// Indirection: scanQueue destructures executeScan once at require time,
// so the stub must dispatch through a mutable holder to change behaviour.
const stub = { fn: async (job) => { executed.push(job); return { ok: true, scanId: job.scanId }; } };
require.cache[scanRunnerPath] = {
  id: scanRunnerPath, filename: scanRunnerPath, loaded: true,
  exports: { executeScan: (...args) => stub.fn(...args) },
};
const scanQueue = require('../queues/scanQueue');

test('queue: inline mode enqueues and runs the job with the same payload', async () => {
  scanQueue.__resetForTests();
  executed.length = 0;
  await scanQueue.enqueueScan({ scanId: 42, organizationId: 1, userId: 7, repositoryId: 1 });
  // Inline pump runs via setImmediate: wait until the job completes.
  for (let i = 0; i < 100 && executed.length === 0; i++) await new Promise((r) => setTimeout(r, 10));
  assert.equal(executed.length, 1);
  assert.deepEqual(executed[0], { scanId: 42, organizationId: 1, userId: 7, repositoryId: 1 });
  const stats = await scanQueue.getQueueStats();
  assert.equal(stats.mode, 'inline');
  assert.equal(stats.completed, 1);
  assert.equal(stats.failed, 0);
  await scanQueue.closeQueue();
});

test('queue: a failing job counts as failed, never retries', async () => {
  scanQueue.__resetForTests();
  stub.fn = async () => ({ ok: false, error: 'boom' });
  await scanQueue.enqueueScan({ scanId: 43, organizationId: 1, userId: 7, repositoryId: 1 });
  for (let i = 0; i < 100; i++) {
    const s = await scanQueue.getQueueStats();
    if (s.failed === 1) break;
    await new Promise((r) => setTimeout(r, 10));
  }
  const stats = await scanQueue.getQueueStats();
  assert.equal(stats.completed, 0);
  assert.equal(stats.failed, 1);
  await scanQueue.closeQueue();
});
