// Unit tests for backend/utils/validation.js (SEC-18 / SEC-22).
// Run: node --test tests/validation.test.js (no DB, no network, no keys).
const test = require('node:test');
const assert = require('node:assert/strict');

const {
  zEmail,
  zPassword,
  zIntId,
  zString,
  zPagination,
  contactSchema,
  scanTriggerSchema,
  vulnStatusSchema,
  vulnLabelSchema,
  createSubscriptionSchema,
  createApiKeySchema,
  alertSettingsSchema,
  alertTestSchema,
  complianceGenerateSchema,
  createRepoSchema,
  orgNameSchema,
  memberRoleSchema,
  transferOwnershipSchema,
  inviteMemberSchema,
  customRuleCreateSchema,
  customRulePatchSchema,
  customRuleTestSchema,
  customRuleTestScanSchema,
  integrationTokensSchema,
  prBotSchema,
  mlRankSchema,
  apiSpecSchema,
  patchMeSchema,
  analyticsEventSchema,
  validateBody,
  validateQuery,
} = require('../utils/validation');

function mockRes() {
  const res = { statusCode: null, body: null };
  res.status = (code) => { res.statusCode = code; return res; };
  res.json = (body) => { res.body = body; return res; };
  return res;
}

function runMiddleware(mw, req) {
  const res = mockRes();
  let nextCalled = false;
  mw(req, res, () => { nextCalled = true; });
  return { res, nextCalled };
}

test('zEmail accepts a valid address, normalises case/whitespace, rejects bad ones', () => {
  assert.equal(zEmail.parse('  Alice@Example.com '), 'alice@example.com');
  assert.equal(zEmail.safeParse('not-an-email').success, false);
  assert.equal(zEmail.safeParse('a@b').success, false);
  assert.equal(zEmail.safeParse('').success, false);
  assert.equal(zEmail.safeParse(42).success, false);
});

test('zPassword enforces the 8–128 floor without weakening it', () => {
  assert.equal(zPassword.safeParse('short').success, false);
  assert.equal(zPassword.safeParse('long-enough-1').success, true);
  assert.equal(zPassword.safeParse('x'.repeat(129)).success, false);
});

test('zIntId coerces "12" but rejects "12abc", 0, negatives and fractions', () => {
  assert.equal(zIntId.parse('12'), 12);
  assert.equal(zIntId.parse(7), 7);
  assert.equal(zIntId.safeParse('12abc').success, false);
  assert.equal(zIntId.safeParse('0').success, false);
  assert.equal(zIntId.safeParse('-3').success, false);
  assert.equal(zIntId.safeParse('1.5').success, false);
  assert.equal(zIntId.safeParse('abc').success, false);
});

test('zString trims and enforces bounds', () => {
  const s = zString(2, 5);
  assert.equal(s.parse('  abc  '), 'abc');
  assert.equal(s.safeParse('a').success, false);
  assert.equal(s.safeParse('abcdef').success, false);
});

test('zPagination defaults limit 1000/page 1 and clamps limit at 5000', () => {
  assert.deepEqual(zPagination.parse({}), { limit: 1000, page: 1 });
  assert.equal(zPagination.parse({ limit: '50' }).limit, 50);
  assert.equal(zPagination.parse({ limit: '99999' }).limit, 5000);
  assert.equal(zPagination.safeParse({ limit: '0' }).success, false);
  assert.equal(zPagination.safeParse({ limit: 'abc' }).success, false);
});

test('contactSchema mirrors validateContactInput bounds', () => {
  const ok = contactSchema.parse({
    name: 'Ada', email: 'ada@example.com', message: 'Hello, this is a real message.',
  });
  assert.equal(ok.email, 'ada@example.com');
  assert.equal(ok.subject, '');
  assert.equal(contactSchema.safeParse({ name: 'A', email: 'a@b.co', message: 'long enough message' }).success, false);
  assert.equal(contactSchema.safeParse({ name: 'Ada', email: 'bad', message: 'long enough message' }).success, false);
  assert.equal(contactSchema.safeParse({ name: 'Ada', email: 'a@b.co', message: 'short' }).success, false);
  // Honeypot field passes the shape guard; the route answers it, not this schema.
  assert.equal(contactSchema.parse({
    name: 'Ada', email: 'a@b.co', message: 'long enough message', company: 'bot',
  }).company, 'bot');
});

test('scanTriggerSchema accepts an integer repositoryId, rejects the rest', () => {
  assert.deepEqual(scanTriggerSchema.parse({ repositoryId: '42' }), { repositoryId: 42 });
  assert.equal(scanTriggerSchema.safeParse({}).success, false);
  assert.equal(scanTriggerSchema.safeParse({ repositoryId: '12abc' }).success, false);
});

test('validateBody passes valid input with parsed values and calls next()', () => {
  const { res, nextCalled } = runMiddleware(
    validateBody(scanTriggerSchema),
    { body: { repositoryId: '42' } },
  );
  assert.equal(nextCalled, true);
  assert.equal(res.statusCode, null);
});

test('validateBody rejects invalid input with 400 and a field error, without next()', () => {
  const req = { body: { repositoryId: '12abc' } };
  const { res, nextCalled } = runMiddleware(validateBody(scanTriggerSchema), req);
  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 400);
  assert.equal(typeof res.body.message, 'string');
  assert.equal(res.body.errors[0].field, 'repositoryId');
});

test('validateQuery parses pagination from query strings', () => {
  const req = { query: { limit: '50', page: '2' } };
  const { nextCalled } = runMiddleware(validateQuery(zPagination), req);
  assert.equal(nextCalled, true);
  assert.deepEqual(req.query, { limit: 50, page: 2 });
});

// Regression: Express 5 defines req.query as a getter-only property —
// assigning req.query throws a TypeError and 500s the route. The middleware
// must work through a real Express 5 app, not just a mock req object.
test('validateQuery works through a real Express 5 app (getter-only req.query)', async () => {
  const express = require('express');
  const app = express();
  app.get('/t', validateQuery(zPagination), (req, res) => {
    res.json({ limit: req.query.limit, page: req.query.page });
  });
  const server = app.listen(0);
  try {
    const port = server.address().port;
    const ok = await fetch(`http://127.0.0.1:${port}/t?limit=5`);
    assert.equal(ok.status, 200);
    assert.deepEqual(await ok.json(), { limit: 5, page: 1 });
    const bad = await fetch(`http://127.0.0.1:${port}/t?limit=abc`);
    assert.equal(bad.status, 400);
  } finally {
    server.close();
  }
});

// ── Authenticated-route schemas (SEC-18 / SEC-22 completion) ─────────────────
// Each schema is a looseObject: declared fields are type-checked, unknown
// fields pass through (handlers keep their business checks as layer two).
// These tests pin: valid input accepted unchanged, wrong-shaped input
// rejected, unknown fields preserved.

test('vuln status/label schemas accept only the handler enums', () => {
  assert.equal(vulnStatusSchema.safeParse({ status: 'fixed' }).success, true);
  assert.equal(vulnStatusSchema.safeParse({ status: 'bogus' }).success, false);
  assert.equal(vulnStatusSchema.safeParse({}).success, false);
  assert.equal(vulnLabelSchema.safeParse({ label: 'real' }).success, true);
  assert.equal(vulnLabelSchema.safeParse({ label: 'maybe' }).success, false);
});

test('looseObject schemas pass unknown fields through untouched', () => {
  const parsed = vulnStatusSchema.parse({ status: 'open', futureField: 42 });
  assert.equal(parsed.futureField, 42);
});

test('billing/api-key schemas prove shape, handlers keep policy', () => {
  assert.equal(createSubscriptionSchema.safeParse({ plan: 'PRO' }).success, true);
  assert.equal(createSubscriptionSchema.safeParse({}).success, false);
  assert.equal(createApiKeySchema.safeParse({ name: 'ci-key', scopes: ['read'], expiresAt: null }).success, true);
  assert.equal(createApiKeySchema.safeParse({ name: 'x', scopes: 'read' }).success, false);
  assert.equal(createApiKeySchema.safeParse({ scopes: [] }).success, false);
});

test('alert schemas: settings all-optional, test channel is an enum', () => {
  assert.equal(alertSettingsSchema.safeParse({}).success, true);
  assert.equal(alertSettingsSchema.safeParse({ slackEnabled: true, slackWebhookUrl: null }).success, true);
  assert.equal(alertSettingsSchema.safeParse({ slackEnabled: 'yes' }).success, false);
  assert.equal(alertTestSchema.safeParse({ channel: 'email' }).success, true);
  assert.equal(alertTestSchema.safeParse({ channel: 'sms' }).success, false);
});

test('compliance/repo schemas require their ids and strings', () => {
  assert.equal(complianceGenerateSchema.safeParse({ repositoryId: '25' }).success, true);
  assert.equal(complianceGenerateSchema.safeParse({ repositoryId: 'x' }).success, false);
  assert.equal(createRepoSchema.safeParse({ name: 'r', url: 'https://github.com/a/b' }).success, true);
  assert.equal(createRepoSchema.safeParse({ name: 'r' }).success, false);
});

test('organization schemas: name floor, role enum, member id, invite email', () => {
  assert.equal(orgNameSchema.safeParse({ name: 'Acme' }).success, true);
  assert.equal(orgNameSchema.safeParse({ name: ' A ' }).success, false);
  assert.equal(memberRoleSchema.safeParse({ role: 'AUDITOR' }).success, true);
  assert.equal(memberRoleSchema.safeParse({ role: 'SUPERUSER' }).success, false);
  assert.equal(transferOwnershipSchema.safeParse({ memberId: '9' }).success, true);
  assert.equal(transferOwnershipSchema.safeParse({ memberId: 'x' }).success, false);
  assert.equal(inviteMemberSchema.safeParse({ email: 'a@b.com', role: 'ADMIN' }).success, true);
  assert.equal(inviteMemberSchema.safeParse({ email: 'not-an-email' }).success, false);
});

test('custom rule schemas: yaml required on create, code capped on test', () => {
  assert.equal(customRuleCreateSchema.safeParse({ yaml: 'id: x' }).success, true);
  assert.equal(customRuleCreateSchema.safeParse({}).success, false);
  assert.equal(customRulePatchSchema.safeParse({ enabled: false }).success, true);
  assert.equal(customRulePatchSchema.safeParse({ yaml: null }).success, true);
  assert.equal(customRuleTestSchema.safeParse({ code: 'x'.repeat(200001) }).success, false);
  assert.equal(customRuleTestScanSchema.safeParse({ scanId: 3 }).success, true);
});

test('integration/ml/api-spec/profile/analytics schemas', () => {
  assert.equal(integrationTokensSchema.safeParse({ githubToken: 'ghp_x' }).success, true);
  assert.equal(integrationTokensSchema.safeParse({ githubToken: 42 }).success, false);
  assert.equal(prBotSchema.safeParse({ repositoryId: 1, commitSha: 'a'.repeat(40), prNumber: 7 }).success, true);
  assert.equal(prBotSchema.safeParse({ repositoryId: 1, commitSha: 'short', prNumber: 7 }).success, false);
  assert.equal(mlRankSchema.safeParse({ vulnerabilityIds: [1, 2] }).success, true);
  assert.equal(mlRankSchema.safeParse({ vulnerabilityIds: [] }).success, false);
  assert.equal(apiSpecSchema.safeParse({ specContent: 'openapi: 3.0.0' }).success, true);
  assert.equal(apiSpecSchema.safeParse({ specUrl: 'https://x.test/s.yaml' }).success, true);
  assert.equal(patchMeSchema.safeParse({ firstName: 'Rishabh' }).success, true);
  assert.equal(patchMeSchema.safeParse({ firstName: 42 }).success, false);
  assert.equal(analyticsEventSchema.safeParse({ event: 'page_view', path: '/home' }).success, true);
  assert.equal(analyticsEventSchema.safeParse({ event: 'page_view', path: 'x'.repeat(501) }).success, false);
});

test('validateBody with a route schema 400s bad input and passes good input through', () => {
  const bad = runMiddleware(validateBody(vulnStatusSchema), { body: { status: 'nope' } });
  assert.equal(bad.res.statusCode, 400);
  assert.equal(bad.nextCalled, false);
  const req = { body: { status: 'ignored', extra: 'kept' } };
  const good = runMiddleware(validateBody(vulnStatusSchema), req);
  assert.equal(good.nextCalled, true);
  assert.equal(req.body.extra, 'kept');
});
