'use strict';
// Scan queue: BullMQ on Redis when REDIS_URL is set, in-process FIFO
// otherwise. Same API both ways, so the server boots and scans run with
// or without Redis — Redis only changes durability and scale.
//
// BullMQ mode: jobs survive a process restart (they live in Redis) and
// a second API instance shares the same queue. Concurrency is
// SCAN_WORKER_CONCURRENCY (default 2): two scans run at once, the rest
// wait — the old code ran every scan inline in its request, so N
// concurrent triggers serialized on the event loop and the p95 grew with
// N (measured: 10 concurrent => p95 3,889 ms).
// Inline mode: same FIFO + concurrency, but jobs live in memory — a
// crash loses queued jobs (their scan rows stay 'queued'; re-trigger).
// No job is ever retried automatically: executeScan marks failures
// itself and returns { ok: false }, so a retry would just re-run a scan
// that already failed honestly.
const { Queue, Worker } = require('bullmq');
const { createQueueConnection, isRedisConfigured } = require('../utils/redis');
const { executeScan } = require('../services/scanRunner');

const QUEUE_NAME = 'secureguard-scans';

function workerConcurrency() {
  const n = Number.parseInt(process.env.SCAN_WORKER_CONCURRENCY || '2', 10);
  return Number.isNaN(n) || n < 1 ? 2 : n;
}

let queue = null;
let worker = null;
let mode = null; // 'bullmq' | 'inline'

// ── Inline fallback ───────────────────────────────────────────────────────
const inline = { pending: [], active: 0, completed: 0, failed: 0, started: false };
function inlinePump() {
  while (inline.active < workerConcurrency() && inline.pending.length > 0) {
    const job = inline.pending.shift();
    inline.active++;
    setImmediate(async () => {
      try {
        const res = await executeScan(job.data);
        if (res.ok) inline.completed++; else inline.failed++;
      } catch (err) {
        inline.failed++;
        console.error('[scanQueue] inline job failed:', err.message);
      } finally {
        inline.active--;
        inlinePump();
      }
    });
  }
}

function ensureMode() {
  if (mode) return mode;
  mode = isRedisConfigured() ? 'bullmq' : 'inline';
  if (mode === 'bullmq') {
    queue = new Queue(QUEUE_NAME, { connection: createQueueConnection() });
  }
  return mode;
}

async function enqueueScan(jobData) {
  ensureMode();
  if (mode === 'bullmq') {
    await queue.add('scan', jobData, {
      // Scan ids are Postgres-autoincrement and never repeat, so the
      // jobId is unique per scan — a re-trigger always creates a new job.
      // attempts: 1 is explicit: a failed scan is never retried blindly.
      jobId: `scan-${jobData.scanId}`,
      attempts: 1,
      removeOnComplete: 100,
      removeOnFail: 100,
    });
  } else {
    inline.pending.push({ data: jobData });
    inlinePump();
  }
  return { mode, scanId: jobData.scanId };
}

// Starts the worker. Called once from server.js (main process only).
// In inline mode there is nothing to start — enqueueScan pumps itself.
async function startWorker() {
  ensureMode();
  if (mode !== 'bullmq' || worker) return { mode };
  // executeScan never throws and marks the scan row itself; a { ok: false }
  // result must still surface as a failed BullMQ job (not "completed"),
  // so the queue stats stay honest. attempts: 1, so it is never retried.
  worker = new Worker(QUEUE_NAME, async (job) => {
    const res = await executeScan(job.data);
    if (!res.ok) throw new Error(res.error || 'scan failed');
    return res;
  }, {
    connection: createQueueConnection(),
    concurrency: workerConcurrency(),
  });
  worker.on('failed', (job, err) => {
    console.error(`[scanQueue] job ${job?.id} failed:`, err.message);
  });
  return { mode };
}

async function getQueueStats() {
  ensureMode();
  if (mode === 'bullmq') {
    const counts = await queue.getJobCounts('waiting', 'active', 'completed', 'failed', 'delayed');
    return { mode, concurrency: workerConcurrency(), ...counts };
  }
  return {
    mode,
    concurrency: workerConcurrency(),
    waiting: inline.pending.length,
    active: inline.active,
    completed: inline.completed,
    failed: inline.failed,
  };
}

async function closeQueue() {
  if (worker) { try { await worker.close(); } catch { /* shutting down */ } worker = null; }
  if (queue) { try { await queue.close(); } catch { /* shutting down */ } queue = null; }
  mode = null;
}

// Test hook: reset module state so tests can switch modes.
function __resetForTests() {
  queue = null;
  worker = null;
  mode = null;
  inline.pending.length = 0;
  inline.active = 0;
  inline.completed = 0;
  inline.failed = 0;
}

module.exports = { enqueueScan, startWorker, getQueueStats, closeQueue, workerConcurrency, __resetForTests };
