'use strict';
// Persistent worker-thread pool for scans.
//
// Spawning a thread per scan cost ~250 ms (V8 isolate + @babel/parser
// require) — more than the ~90 ms scan itself on a small repo, so a
// 100-scan burst at concurrency 2 took 17 s mean turnaround. Warm
// threads remove that cost: the pool pays spawn once, then reuses.
// Pool size defaults to SCAN_WORKER_CONCURRENCY (same as the BullMQ
// worker concurrency), so a job never waits for a thread it cannot get.
// A dead/stuck thread fails its job honestly (scanRunner falls back to
// inline) and is replaced on demand.
const { Worker } = require('worker_threads');
const path = require('path');

const SCAN_THREAD_TIMEOUT_MS = Number.parseInt(process.env.SCAN_THREAD_TIMEOUT_MS || '600000', 10);

function poolSize() {
  const n = Number.parseInt(process.env.SCAN_THREAD_POOL_SIZE || process.env.SCAN_WORKER_CONCURRENCY || '2', 10);
  return Number.isNaN(n) || n < 1 ? 2 : n;
}

const pool = []; // { worker, busy, job }
const waiters = []; // { id, scanPath, customRules, resolve, reject, timeout }
let nextId = 1;

function removeEntry(entry) {
  const i = pool.indexOf(entry);
  if (i >= 0) pool.splice(i, 1);
  try { entry.worker.terminate().catch(() => {}); } catch { /* already gone */ }
}

function spawn() {
  const entry = { worker: null, busy: false, job: null };
  entry.worker = new Worker(path.join(__dirname, 'scanThread.js'));
  entry.worker.on('message', (msg) => {
    const job = entry.job;
    entry.job = null;
    entry.busy = false;
    if (!job) return; // stale reply for a job the timeout already failed
    clearTimeout(job.timeout);
    if (msg.ok) job.resolve(msg.result);
    else job.reject(new Error(msg.error || 'Scan worker failed'));
    pump();
  });
  entry.worker.on('error', (err) => {
    const job = entry.job;
    entry.job = null;
    entry.busy = false;
    removeEntry(entry);
    if (job) { clearTimeout(job.timeout); job.reject(err); }
    pump();
  });
  entry.worker.on('exit', (code) => {
    const job = entry.job;
    entry.job = null;
    entry.busy = false;
    removeEntry(entry);
    if (job) { clearTimeout(job.timeout); job.reject(new Error(`Scan worker exited with code ${code}`)); }
    pump();
  });
  pool.push(entry);
  return entry;
}

function pump() {
  while (waiters.length > 0) {
    let entry = pool.find((e) => !e.busy);
    if (!entry && pool.length < poolSize()) {
      try {
        entry = spawn();
      } catch (err) {
        // Cannot spawn (resource limits): fail the job, the caller runs inline.
        const job = waiters.shift();
        job.reject(err);
        continue;
      }
    }
    if (!entry) return; // all threads busy: wait for one to free up
    const job = waiters.shift();
    entry.busy = true;
    entry.job = job;
    job.timeout = setTimeout(() => {
      // Thread stuck (pathological repo?): kill it, fail the job honestly.
      removeEntry(entry);
      job.reject(new Error(`Scan timed out after ${SCAN_THREAD_TIMEOUT_MS} ms in worker thread`));
      pump();
    }, SCAN_THREAD_TIMEOUT_MS);
    if (typeof job.timeout.unref === 'function') job.timeout.unref();
    entry.worker.postMessage({ id: job.id, scanPath: job.scanPath, customRules: job.customRules });
  }
}

function runScanInThread(scanPath, customRules) {
  return new Promise((resolve, reject) => {
    waiters.push({ id: nextId++, scanPath, customRules, resolve, reject, timeout: null });
    pump();
  });
}

async function closePool() {
  waiters.length = 0;
  const workers = pool.splice(0).map((e) => e.worker);
  await Promise.all(workers.map((w) => w.terminate().catch(() => {})));
}

module.exports = { runScanInThread, closePool };
