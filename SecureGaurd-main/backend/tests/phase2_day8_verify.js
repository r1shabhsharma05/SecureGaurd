/**
 * Day 8 — unit verification (no network, no database).
 * Proves the pure helpers the public-site routes depend on:
 *  - analytics event allow-list + flat short-string props (no PII keys,
 *    no nested values, no oversized values),
 *  - contact validation (lengths, email shape, honeypot),
 *  - contact recipient resolution (CONTACT_EMAIL first, EMAIL_FROM
 *    fallback, null when neither is configured — never a faked address).
 */
const assert = require('assert');
const {
  isAllowedAnalyticsEvent,
  sanitizeAnalyticsProps,
  validateContactInput,
  resolveContactRecipient,
} = require('../utils/publicSite');

let passed = 0, total = 0;
function test(name, fn) {
  total++;
  try { fn(); console.log(`  ✓ PASS: ${name}`); passed++; }
  catch (e) { console.error(`  ✗ FAIL: ${name}\n    ${e.message}`); }
}

console.log('\n=== Day 8: analytics + contact unit verification ===\n');

test('analytics: allow-listed events accepted, unknown rejected', () => {
  assert.strictEqual(isAllowedAnalyticsEvent('page_view'), true);
  assert.strictEqual(isAllowedAnalyticsEvent('scan_started'), true);
  assert.strictEqual(isAllowedAnalyticsEvent('contact_sent'), true);
  assert.strictEqual(isAllowedAnalyticsEvent('pwned_everything'), false);
  assert.strictEqual(isAllowedAnalyticsEvent(''), false);
  assert.strictEqual(isAllowedAnalyticsEvent(null), false);
});

test('analytics props: flat short strings pass through', () => {
  assert.deepStrictEqual(
    sanitizeAnalyticsProps({ framework: 'SOC2', count: 3, ok: true }),
    { framework: 'SOC2', count: 3, ok: true },
  );
  assert.deepStrictEqual(sanitizeAnalyticsProps(undefined), {});
});

test('analytics props: PII keys, nested values, oversize rejected', () => {
  assert.strictEqual(sanitizeAnalyticsProps({ email: 'a@b.com' }), null);
  assert.strictEqual(sanitizeAnalyticsProps({ token: 'abc' }), null);
  assert.strictEqual(sanitizeAnalyticsProps({ nested: { a: 1 } }), null);
  assert.strictEqual(sanitizeAnalyticsProps({ arr: [1] }), null);
  assert.strictEqual(sanitizeAnalyticsProps({ big: 'x'.repeat(201) }), null);
  assert.strictEqual(sanitizeAnalyticsProps({ a: 1, b: 2, c: 3, d: 4, e: 5, f: 6, g: 7, h: 8, i: 9, j: 10, k: 11 }), null);
});

test('contact: valid message passes, fields trimmed', () => {
  const r = validateContactInput({ name: '  Ada  ', email: 'ada@example.com', subject: ' Hi ', message: 'Hello, I would like a demo please.' });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.value.name, 'Ada');
  assert.strictEqual(r.value.subject, 'Hi');
});

test('contact: bad email, short message, long subject rejected', () => {
  assert.strictEqual(validateContactInput({ name: 'Ada', email: 'not-an-email', message: 'Hello there, demo please.' }).ok, false);
  assert.strictEqual(validateContactInput({ name: 'Ada', email: 'ada@example.com', message: 'short' }).ok, false);
  assert.strictEqual(validateContactInput({ name: 'A', email: 'ada@example.com', message: 'Hello there, demo please.' }).ok, false);
  assert.strictEqual(validateContactInput({ name: 'Ada', email: 'ada@example.com', subject: 'x'.repeat(141), message: 'Hello there, demo please.' }).ok, false);
  assert.strictEqual(validateContactInput({ name: 'Ada', email: 'ada@example.com', message: 'x'.repeat(2001) }).ok, false);
});

test('contact: filled honeypot reported as honeypot', () => {
  const r = validateContactInput({ name: 'Bot', email: 'bot@example.com', message: 'Hello there, demo please.', company: 'Acme Inc' });
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.message, 'honeypot');
});

test('recipient: CONTACT_EMAIL wins; EMAIL_FROM fallback; null when none', () => {
  assert.strictEqual(resolveContactRecipient({ CONTACT_EMAIL: 'inbox@example.com', EMAIL_FROM: 'sender@example.com' }), 'inbox@example.com');
  assert.strictEqual(resolveContactRecipient({ EMAIL_FROM: 'SecureGuard <sender@example.com>' }), 'sender@example.com');
  assert.strictEqual(resolveContactRecipient({ EMAIL_FROM: 'sender@example.com' }), 'sender@example.com');
  assert.strictEqual(resolveContactRecipient({}), null);
  assert.strictEqual(resolveContactRecipient({ EMAIL_FROM: 'no-reply@localhost' }), null);
});

console.log(`\n${passed}/${total} passed`);
process.exit(passed === total ? 0 : 1);
