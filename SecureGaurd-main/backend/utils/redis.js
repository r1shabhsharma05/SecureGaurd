'use strict';
// Redis connections for SecureGaurd (queue + cache).
//
// REDIS_URL is OPTIONAL: without it the queue runs in-process and the
// cache is bypassed, so the server still boots and scans still run (see
// queues/scanQueue.js + utils/cache.js). With it set — Render Key Value,
// Upstash, or local `redis-server` — BullMQ and the cache use real Redis.
// Nothing here connects at require time: clients are created lazily so
// unit tests and offline boots never touch the network.
const Redis = require('ioredis');

let cacheClient = null;

function redisUrl() {
  return process.env.REDIS_URL || null;
}

function isRedisConfigured() {
  return Boolean(redisUrl());
}

// Cache client: fails FAST (1 retry, 1 s connect timeout, no offline
// queue) so a dead Redis degrades to uncached reads, never a hung request.
function getRedis() {
  if (cacheClient) return cacheClient;
  const url = redisUrl();
  if (!url) return null;
  cacheClient = new Redis(url, {
    maxRetriesPerRequest: 1,
    connectTimeout: 1000,
    enableOfflineQueue: false,
    lazyConnect: true,
  });
  cacheClient.on('error', (err) => {
    console.error('[redis] cache client error:', err.message);
  });
  return cacheClient;
}

// BullMQ needs maxRetriesPerRequest: null (it blocks on Redis commands).
// Each caller gets its own connection; BullMQ also opens its own.
function createQueueConnection() {
  const url = redisUrl();
  if (!url) return null;
  return new Redis(url, {
    maxRetriesPerRequest: null,
    enableReadyCheck: false,
    lazyConnect: true,
  });
}

async function closeRedis() {
  if (cacheClient) {
    const c = cacheClient;
    cacheClient = null;
    try { await c.quit(); } catch { try { c.disconnect(); } catch { /* already gone */ } }
  }
}

// Test hook: swap the cache client (unit tests inject an in-memory fake).
function __setCacheClient(client) {
  cacheClient = client;
}

module.exports = { getRedis, createQueueConnection, isRedisConfigured, closeRedis, __setCacheClient };
