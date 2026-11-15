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
