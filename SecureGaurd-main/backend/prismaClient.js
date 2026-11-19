require('dotenv').config({ path: require('path').resolve(__dirname, '.env') });
const { PrismaClient } = require('./generated/prisma/client');
const { PrismaPg } = require('@prisma/adapter-pg');
const { Pool } = require('pg');

// Pool tuning (19 Nov 2026 perf fix): pg defaults reaped idle clients
// after 30 s (idleTimeoutMillis) and kept at most 10. The database is a
// region away from the app server, so every reaped client cost the next
// page load a fresh cross-region TCP+TLS+auth handshake, and the five
// parallel dashboard requests (each running 1-2 RLS transactions) queued
// behind 10 clients until transaction starts timed out (P2028 retries
// stretched page loads to ~20 s). Keep clients warm instead: never reap
// on idle, TCP keepalive so the pooler/NAT doesn't drop them silently,
// and a slightly larger pool. The keepalive workflow's /health ping
// exercises one connection every 10 min (see server.js).
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 15,
  idleTimeoutMillis: 0,
  keepAlive: true,
  keepAliveInitialDelayMillis: 10_000,
});

// An idle client can still die server-side (pooler restart, network
// reset). pg emits 'error' on the pool for that; without a listener the
// event is unhandled and crashes the process. Log and let pg drop the
// dead client — the next query opens a fresh one.
pool.on('error', (err) => {
  console.error('pg pool error (idle client dropped):', err.message);
});

const adapter = new PrismaPg(pool);
const prisma = new PrismaClient({ adapter });

module.exports = prisma;
