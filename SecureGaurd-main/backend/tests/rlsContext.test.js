// Unit tests for the RLS session-context helpers (SEC-31).
// Run: node --test tests/rlsContext.test.js (no DB, no network, no keys).
// The helpers are exercised against a fake Prisma client whose
// $transaction hands back a mock tx recording every raw call, so the
// tests assert exactly which set_config statements the real code issues.
const test = require('node:test');
const assert = require('node:assert/strict');

const {
  parseContextId,
  assertContextId,
  setOrgContext,
  setUserContext,
  setOrgOnlyContext,
  createRlsContext,
  rlsContextMiddleware,
  getRequestContext,
} = require('../utils/rlsContext');

// Mock tx: records $executeRaw template-tag calls as { sql, params } and
// $queryRaw calls the same way; resolvers answer from a canned row.
function mockTx(queryRow) {
  const calls = [];
  return {
    calls,
    async $executeRaw(strings, ...values) {
      calls.push({ sql: String.raw(strings, ...values.map(() => '?')), params: values });
      return 1;
    },
    async $queryRaw(strings, ...values) {
      calls.push({ sql: String.raw(strings, ...values.map(() => '?')), params: values });
      return [queryRow];
    },
  };
}

function mockClient(tx) {
  return {
    $transaction: async (fn) => fn(tx),
  };
}

test('parseContextId accepts plain integers and digit strings', () => {
  assert.equal(parseContextId(12), 12);
  assert.equal(parseContextId('12'), 12);
  assert.equal(parseContextId(1), 1);
});

test('parseContextId rejects the parseInt-coercion trap and other junk (fail closed)', () => {
  // parseInt("12abc") === 12 is the SEC-15/S3 bug class — must not pass.
  assert.equal(parseContextId('12abc'), null);
  assert.equal(parseContextId('12.5'), null);
  assert.equal(parseContextId(12.5), null);
  assert.equal(parseContextId(''), null);
  assert.equal(parseContextId(null), null);
  assert.equal(parseContextId(undefined), null);
  assert.equal(parseContextId(0), null);
  assert.equal(parseContextId(-3), null);
  assert.equal(parseContextId(' 12'), null);
  assert.equal(parseContextId({}), null);
  assert.equal(parseContextId(NaN), null);
});

test('assertContextId throws on invalid ids', () => {
  assert.throws(() => assertContextId('12abc', 'organizationId'), /Invalid RLS context/);
  assert.throws(() => assertContextId(null, 'userId'), /Invalid RLS context/);
  assert.equal(assertContextId('7', 'organizationId'), 7);
});

test('setOrgContext issues exactly two SET LOCAL calls, org then user, parameterized', async () => {
  const tx = mockTx();
  await setOrgContext(tx, 12, 34);
  assert.equal(tx.calls.length, 2);
  assert.match(tx.calls[0].sql, /set_config\('app\.current_org_id', \?, true\)/);
  assert.deepEqual(tx.calls[0].params, ['12']);
  assert.match(tx.calls[1].sql, /set_config\('app\.current_user_id', \?, true\)/);
  assert.deepEqual(tx.calls[1].params, ['34']);
});

test('setOrgContext throws before any SQL when an id is invalid', async () => {
  const tx = mockTx();
  await assert.rejects(() => setOrgContext(tx, '12abc', 34), /Invalid RLS context/);
  assert.equal(tx.calls.length, 0);
});

test('setUserContext issues only the user SET LOCAL', async () => {
  const tx = mockTx();
  await setUserContext(tx, '5');
  assert.equal(tx.calls.length, 1);
  assert.match(tx.calls[0].sql, /set_config\('app\.current_user_id', \?, true\)/);
  assert.deepEqual(tx.calls[0].params, ['5']);
});

test('withOrgContext opens a transaction, sets context, then runs fn(tx)', async () => {
  const tx = mockTx();
  const { withOrgContext } = createRlsContext(mockClient(tx));
  let seenTx = null;
  const out = await withOrgContext(9, 3, async (t) => { seenTx = t; return 'ok'; });
  assert.equal(out, 'ok');
  assert.equal(seenTx, tx);
  assert.equal(tx.calls.length, 2); // context set before fn ran (fn adds no calls here)
});

test('withOrgContext rejects invalid ids without opening a transaction', async () => {
  let opened = false;
  const client = { $transaction: async () => { opened = true; } };
  const { withOrgContext } = createRlsContext(client);
  await assert.rejects(() => withOrgContext('9x', 3, async () => {}), /Invalid RLS context/);
  assert.equal(opened, false);
});

test('setOrgOnlyContext issues exactly one SET LOCAL, org only (rule 6)', async () => {
  const tx = mockTx();
  await setOrgOnlyContext(tx, 12);
  assert.equal(tx.calls.length, 1);
  assert.match(tx.calls[0].sql, /set_config\('app\.current_org_id', \?, true\)/);
  assert.deepEqual(tx.calls[0].params, ['12']);
});

test('setOrgOnlyContext throws before any SQL when the org id is invalid', async () => {
  const tx = mockTx();
  await assert.rejects(() => setOrgOnlyContext(tx, '12abc'), /Invalid RLS context/);
  assert.equal(tx.calls.length, 0);
});

test('withOrgOnlyContext opens a transaction, sets only the org variable', async () => {
  const tx = mockTx();
  const { withOrgOnlyContext } = createRlsContext(mockClient(tx));
  let seenTx = null;
  const out = await withOrgOnlyContext(9, async (t) => { seenTx = t; return 'ok'; });
  assert.equal(out, 'ok');
  assert.equal(seenTx, tx);
  assert.equal(tx.calls.length, 1); // org only — no user variable
  assert.match(tx.calls[0].sql, /app\.current_org_id/);
});

test('resolveOrgIdForInvitationAny passes the secret through and returns the id', async () => {
  const tx = mockTx({ orgId: 55 });
  const ctx = createRlsContext(mockClient(tx));
  assert.equal(await ctx.resolveOrgIdForInvitationAny(tx, 'deadbeef'), 55);
  assert.match(tx.calls[0].sql, /app_org_id_for_invitation_any\(\?\)/);
  assert.deepEqual(tx.calls[0].params, ['deadbeef']);
  assert.equal(await ctx.resolveOrgIdForInvitationAny(tx, ''), null); // empty secret: no query
  assert.equal(tx.calls.length, 1);
});

test('withUserContext sets only the user variable', async () => {
  const tx = mockTx();
  const { withUserContext } = createRlsContext(mockClient(tx));
  await withUserContext(44, async () => 'done');
  assert.equal(tx.calls.length, 1);
  assert.match(tx.calls[0].sql, /app\.current_user_id/);
});

test('resolvers pass the secret through as a parameter and return the id (or null)', async () => {
  const tx = mockTx({ orgId: 77 });
  const ctx = createRlsContext(mockClient(tx));
  assert.equal(await ctx.resolveOrgIdForInvitation(tx, 'deadbeef'), 77);
  assert.match(tx.calls[0].sql, /app_org_id_for_invitation\(\?\)/);
  assert.deepEqual(tx.calls[0].params, ['deadbeef']);

  const empty = mockTx({ orgId: null });
  const ctx2 = createRlsContext(mockClient(empty));
  assert.equal(await ctx2.resolveOrgIdForRazorpaySubscription(empty, 'sub_123'), null);
  assert.equal(await ctx2.resolveOrgIdForInvitation(empty, ''), null); // empty secret: no query
  assert.equal(empty.calls.length, 1); // only the Razorpay call above
});

test('rlsContextMiddleware carries ids per request and does not leak across requests', async () => {
  const run = (userId, organizationId) => new Promise((resolve) => {
    const req = { userId, organizationId };
    rlsContextMiddleware(req, {}, () => {
      // Read the context asynchronously to prove ALS scoping, not closure.
      setImmediate(() => resolve(getRequestContext()));
    });
  });
  const [a, b] = await Promise.all([run(1, 10), run(2, 20)]);
  assert.deepEqual(a, { userId: 1, organizationId: 10 });
  assert.deepEqual(b, { userId: 2, organizationId: 20 });
  assert.deepEqual(getRequestContext(), { userId: null, organizationId: null }); // outside a request
});

test('rlsContextMiddleware stores nulls for missing ids (fail closed downstream)', async () => {
  const seen = await new Promise((resolve) => {
    rlsContextMiddleware({}, {}, () => resolve(getRequestContext()));
  });
  assert.deepEqual(seen, { userId: null, organizationId: null });
});
