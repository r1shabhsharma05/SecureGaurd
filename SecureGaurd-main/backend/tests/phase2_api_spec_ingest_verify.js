/**
 * Day 5 — API spec ingestion verification.
 * Verifies: SSRF guard IP ranges, scheme/credential rejection, DNS results
 * where ANY private address blocks, redirect-to-private blocking, the
 * public-fetch happy path (stubbed), and scanAPISpecFile on an ingested
 * spec written to a temp file (the route's exact path minus HTTP plumbing).
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { isPrivateIp, fetchPublicSpec } = require('../utils/ssrfGuard');
const { scanAPISpecFile } = require('../utils/apiSpecScanner');

let passed = 0;
let total = 0;
function assert(cond, msg) {
  total++;
  if (cond) { console.log(`  ✓ PASS: ${msg}`); passed++; }
  else { console.error(`  ✗ FAIL: ${msg}`); }
}

// Stub DNS: hostname -> list of addresses.
function stubLookup(mapping) {
  return (hostname, _opts, cb) => {
    const addrs = mapping[hostname];
    if (!addrs) return cb(new Error('ENOTFOUND'));
    cb(null, addrs.map(address => ({ address, family: 4 })));
  };
}

// Stub fetch: url -> { status, location?, bodyText }.
function stubFetch(mapping) {
  return async (url) => {
    const entry = mapping[url];
    if (!entry) throw new Error(`unexpected fetch: ${url}`);
    return {
      status: entry.status,
      headers: { get: (name) => (name.toLowerCase() === 'location' ? (entry.location || null) : null) },
      body: { arrayBuffer: async () => Buffer.from(entry.bodyText || '') }
    };
  };
}

const VULN_SPEC = `
openapi: 3.0.0
info:
  title: Vulnerable API
  version: 1.0.0
servers:
  - url: http://api.example.com/v1
paths:
  /admin/deleteUser:
    post:
      summary: Delete user
      security: []
      parameters:
        - name: access_token
          in: query
          required: true
          schema:
            type: string
`;

(async function run() {
  console.log('\n=== Day 5 — API Spec Ingestion / SSRF Verification ===\n');

  console.log('[Group 1] Private / reserved IP ranges blocked');
  for (const ip of ['127.0.0.1', '10.0.0.5', '172.16.0.1', '172.31.255.255', '192.168.1.1',
    '169.254.169.254', '0.0.0.0', '100.64.0.1', '224.0.0.1', '::1', 'fe80::1', 'fc00::1',
    '::ffff:127.0.0.1', 'not-an-ip']) {
    assert(isPrivateIp(ip) === true, `isPrivateIp blocks ${ip}`);
  }

  console.log('\n[Group 2] Public IPs allowed');
  for (const ip of ['8.8.8.8', '93.184.216.34', '1.1.1.1']) {
    assert(isPrivateIp(ip) === false, `isPrivateIp allows ${ip}`);
  }

  console.log('\n[Group 3] URL validation');
  await assertRejects(fetchPublicSpec('ftp://example.com/spec.yaml', { lookupImpl: stubLookup({}), fetchImpl: stubFetch({}) }),
    'ftp scheme rejected');
  await assertRejects(fetchPublicSpec('https://user:pass@example.com/spec.yaml', { lookupImpl: stubLookup({}), fetchImpl: stubFetch({}) }),
    'credential URL rejected');
  await assertRejects(fetchPublicSpec('not a url', { lookupImpl: stubLookup({}), fetchImpl: stubFetch({}) }),
    'malformed URL rejected');

  console.log('\n[Group 4] DNS-gated fetch');
  await assertRejects(
    fetchPublicSpec('http://internal.example/spec.yaml', {
      lookupImpl: stubLookup({ 'internal.example': ['169.254.169.254'] }),
      fetchImpl: stubFetch({})
    }), 'metadata IP host blocked before any fetch');
  await assertRejects(
    fetchPublicSpec('http://mixed.example/spec.yaml', {
      lookupImpl: stubLookup({ 'mixed.example': ['93.184.216.34', '10.1.2.3'] }),
      fetchImpl: stubFetch({})
    }), 'one private address among public ones still blocks');
  const ok = await fetchPublicSpec('https://public.example/openapi.yaml', {
    lookupImpl: stubLookup({ 'public.example': ['93.184.216.34'] }),
    fetchImpl: stubFetch({ 'https://public.example/openapi.yaml': { status: 200, bodyText: VULN_SPEC } })
  });
  assert(ok.content.includes('openapi: 3.0.0'), 'public host fetch returns spec content');

  console.log('\n[Group 5] Redirect hop re-validation');
  await assertRejects(
    fetchPublicSpec('https://public.example/start', {
      lookupImpl: stubLookup({ 'public.example': ['93.184.216.34'], 'evil.example': ['127.0.0.1'] }),
      fetchImpl: stubFetch({
        'https://public.example/start': { status: 302, location: 'http://evil.example/spec.yaml' }
      })
    }), 'redirect to private host blocked');

  console.log('\n[Group 6] Ingested spec scans through the real API scanner');
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-ingest-'));
  try {
    const tmpFile = path.join(tmpDir, 'spec.yaml');
    fs.writeFileSync(tmpFile, ok.content, 'utf8');
    const findings = scanAPISpecFile(tmpFile, 'spec.yaml');
    const ids = findings.map(f => f.ruleId);
    assert(ids.includes('API-001'), 'ingested spec: API-001 missing auth');
    assert(ids.includes('API-002'), 'ingested spec: API-002 sensitive op without auth');
    assert(ids.includes('API-003'), 'ingested spec: API-003 http server URL');
    assert(ids.includes('API-005'), 'ingested spec: API-005 token in query');
    assert(ids.includes('API-006'), 'ingested spec: API-006 no security schemes');
    assert(findings.every(f => f.type === 'api' && f.mlFeatures.isApi === true),
      'ingested findings carry type api + isApi for the classifier path');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  console.log(`\n==================================================`);
  console.log(`Verification Summary: ${passed}/${total} tests passed.`);
  console.log(`==================================================\n`);
  if (passed !== total) process.exit(1);

  async function assertRejects(promise, msg) {
    total++;
    try {
      await promise;
      console.error(`  ✗ FAIL: ${msg} (resolved unexpectedly)`);
    } catch (e) {
      console.log(`  ✓ PASS: ${msg}`);
      passed++;
    }
  }
})();
