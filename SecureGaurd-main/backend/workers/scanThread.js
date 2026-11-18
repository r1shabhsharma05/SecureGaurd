'use strict';
// Worker-thread entry (persistent — see scanThreadPool.js): runs the
// CPU-bound synchronous scan off the event loop, so scan work never
// stalls HTTP responses. Receives plain JSON (scanPath + parsed custom
// rules — no functions) and posts the plain scan result back, tagged
// with the job id. Any throw is reported, never swallowed.
const { parentPort } = require('worker_threads');
const { runSecurityScan } = require('../utils/securityScanner');

parentPort.on('message', ({ id, scanPath, customRules }) => {
  try {
    const result = runSecurityScan(scanPath, customRules || []);
    parentPort.postMessage({ id, ok: true, result });
  } catch (err) {
    parentPort.postMessage({ id, ok: false, error: err.message || String(err) });
  }
});
