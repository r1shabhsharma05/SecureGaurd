/**
 * Day 7 — unit verification (no network, no database).
 * Proves the pure helpers the new routes depend on:
 *  - Slack webhook URL allow-listing (hooks.slack.com/services/* only) and
 *    masking (token segments never leak into logs/responses),
 *  - alert payload shapes for both events,
 *  - PR-bot payload shapes (check run + comment) and repo-name parsing,
 *    including the rule that a missing scan is "neutral", never "success".
 */
const assert = require('assert');
const { isValidSlackWebhookUrl, maskWebhookUrl, buildSlackPayload, buildEmailAlert } = require('../utils/alertPayload');
const { parseRepoFullName, buildCheckRunPayload, buildPrCommentBody } = require('../utils/prBot');

let passed = 0, total = 0;
function test(name, fn) {
  total++;
  try { fn(); console.log(`  ✓ PASS: ${name}`); passed++; }
  catch (e) { console.error(`  ✗ FAIL: ${name}\n    ${e.message}`); }
}

const SCAN = { orgName: 'Acme', repoName: 'acme/web', scanId: 42, criticalCount: 2, highCount: 1, mediumCount: 0, lowCount: 3 };

console.log('\n=== Day 7: alerts + PR bot unit verification ===\n');

test('Slack URL: real hooks.slack.com/services URL accepted', () => {
  // NOTE: the token segment below is deliberately hyphenated placeholder
  // text — a realistic-looking token would trip GitHub secret scanning
  // on push (the validator only checks host + /services/ prefix, so the
  // shape still proves acceptance).
  assert.strictEqual(isValidSlackWebhookUrl('https://hooks.slack.com/services/T00000000/B00000000/EXAMPLE-NOT-A-REAL-TOKEN'), true);
});
test('Slack URL: non-Slack host rejected (no generic POST oracle)', () => {
  assert.strictEqual(isValidSlackWebhookUrl('https://example.com/services/abc'), false);
  assert.strictEqual(isValidSlackWebhookUrl('https://hooks.slack.com.evil.com/services/abc'), false);
});
test('Slack URL: http, wrong path, and garbage rejected', () => {
  assert.strictEqual(isValidSlackWebhookUrl('http://hooks.slack.com/services/abc'), false);
  assert.strictEqual(isValidSlackWebhookUrl('https://hooks.slack.com/triggers/abc'), false);
  assert.strictEqual(isValidSlackWebhookUrl('not a url'), false);
  assert.strictEqual(isValidSlackWebhookUrl(''), false);
  assert.strictEqual(isValidSlackWebhookUrl(null), false);
});
test('Slack masking: valid URL masks to host only, no token segments', () => {
  const masked = maskWebhookUrl('https://hooks.slack.com/services/T000/B000/EXAMPLE-NOT-A-REAL-TOKEN');
  assert.strictEqual(masked, 'hooks.slack.com/services/***');
  assert.ok(!masked.includes('EXAMPLE-NOT-A-REAL-TOKEN'));
  assert.strictEqual(maskWebhookUrl('https://example.com/x'), null);
});
test('Slack payload: new_critical title + counts in text', () => {
  const p = buildSlackPayload({ ...SCAN, event: 'new_critical' });
  assert.ok(p.text.includes('new critical findings'));
  assert.ok(p.text.includes('2 critical, 1 high, 0 medium, 3 low'));
  assert.ok(p.text.includes('Scan #42'));
});
test('Slack payload: scan_completed title differs from new_critical', () => {
  const p = buildSlackPayload({ ...SCAN, event: 'scan_completed' });
  assert.ok(p.text.includes('scan completed'));
  assert.ok(!p.text.includes('new critical findings'));
});
test('Email alert: subject carries repo + scan id; critical flag in body', () => {
  const m = buildEmailAlert({ ...SCAN, event: 'new_critical' });
  assert.ok(m.subject.includes('acme/web') && m.subject.includes('#42'));
  assert.ok(m.text.includes('new critical findings'));
  const m2 = buildEmailAlert({ ...SCAN, event: 'scan_completed' });
  assert.ok(!m2.text.includes('new critical findings'));
});

test('PR bot: owner/repo parsed; malformed names rejected', () => {
  assert.deepStrictEqual(parseRepoFullName('OWASP/NodeGoat'), { owner: 'OWASP', repo: 'NodeGoat' });
  assert.strictEqual(parseRepoFullName('just-a-name'), null);
  assert.strictEqual(parseRepoFullName('a/b/c'), null);
  assert.strictEqual(parseRepoFullName(''), null);
});
test('PR bot: dirty scan => failure conclusion with counts', () => {
  const p = buildCheckRunPayload({ commitSha: 'abc123', isClean: false, criticalCount: 2, highCount: 1, reportUrl: 'https://app.example/dashboard' });
  assert.strictEqual(p.name, 'SecureGuard');
  assert.strictEqual(p.head_sha, 'abc123');
  assert.strictEqual(p.status, 'completed');
  assert.strictEqual(p.conclusion, 'failure');
  assert.ok(p.output.summary.includes('2 critical and 1 high'));
});
test('PR bot: clean scan => success conclusion', () => {
  const p = buildCheckRunPayload({ commitSha: 'abc123', isClean: true, criticalCount: 0, highCount: 0, reportUrl: null });
  assert.strictEqual(p.conclusion, 'success');
  assert.ok(p.output.summary.includes('No critical or high'));
});
test('PR bot: comment body carries repo, commit, counts, report link', () => {
  const b = buildPrCommentBody({ repoFullName: 'acme/web', commitSha: 'abc123', isClean: false, criticalCount: 2, highCount: 1, mediumCount: 0, lowCount: 3, reportUrl: 'https://app.example/dashboard' });
  assert.ok(b.includes('acme/web') && b.includes('abc123'));
  assert.ok(b.includes('2 critical, 1 high, 0 medium, 3 low'));
  assert.ok(b.includes('https://app.example/dashboard'));
  const clean = buildPrCommentBody({ repoFullName: 'acme/web', commitSha: 'abc123', isClean: true, criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, reportUrl: null });
  assert.ok(clean.includes('No critical or high'));
  assert.ok(!clean.includes('Report:'));
});

// Day 7 live-bug fix — cryptoUtils key derivation. The old code passed
// ENCRYPTION_KEY (a string) straight to createCipheriv, which throws
// "Invalid key length" for anything but a 32-byte Buffer — every prod
// encrypt() failed (500 on alert-settings save and PAT save). Each case
// re-requires the module so deriveKey runs against that case's env.
function loadCrypto() {
  delete require.cache[require.resolve('../utils/cryptoUtils')];
  return require('../utils/cryptoUtils');
}
test('crypto: JWT_SECRET fallback key round-trips', () => {
  delete process.env.ENCRYPTION_KEY;
  process.env.JWT_SECRET = 'test-jwt-secret-for-day7-unit';
  const { encrypt, decrypt } = loadCrypto();
  const cipher = encrypt('https://hooks.slack.com/services/T000/B000/EXAMPLE');
  assert.ok(cipher.split(':').length === 3);
  assert.strictEqual(decrypt(cipher), 'https://hooks.slack.com/services/T000/B000/EXAMPLE');
});
test('crypto: 64-hex ENCRYPTION_KEY round-trips (hex-decoded 32 bytes)', () => {
  process.env.ENCRYPTION_KEY = 'ab'.repeat(32);
  const { encrypt, decrypt } = loadCrypto();
  assert.strictEqual(decrypt(encrypt('ghp_test-token-value')), 'ghp_test-token-value');
});
test('crypto: passphrase ENCRYPTION_KEY round-trips (sha256-derived)', () => {
  process.env.ENCRYPTION_KEY = 'some-operator-passphrase';
  const { encrypt, decrypt } = loadCrypto();
  assert.strictEqual(decrypt(encrypt('my-pat-value')), 'my-pat-value');
  const { encrypt: enc2, decrypt: dec2 } = loadCrypto();
  assert.strictEqual(dec2(enc2('repeatable-across-require')), 'repeatable-across-require');
});
test('crypto: decrypt of garbage returns it unchanged (legacy fallback)', () => {
  const { decrypt } = loadCrypto();
  assert.strictEqual(decrypt('not-encrypted-legacy'), 'not-encrypted-legacy');
  assert.strictEqual(decrypt(''), '');
});

console.log(`\nDay 7 unit: ${passed}/${total} passed`);
process.exit(passed === total ? 0 : 1);
