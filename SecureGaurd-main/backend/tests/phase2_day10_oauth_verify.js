/**
 * Day 10 — unit verification for SSO/OIDC helpers (offline, no network:
 * fetch is stubbed). Proves the pure pieces the OAuth routes depend on:
 *  - PKCE S256 challenge matches the RFC 7636 test vector,
 *  - state signing/verification rejects tampering,
 *  - authorize URLs carry the right params per provider,
 *  - profile normalization (Google verified, GitHub hidden-email via
 *    /user/emails, GitLab confirmed_at) and fail-closed config checks,
 *  - token exchange + profile fetch against stubbed fetch.
 * A live provider round-trip is NOT claimed here — it needs HIS STEP
 * (OAuth apps registered, docs/OAUTH_SSO.md) and is proven in the report
 * only as fail-closed (501 / no buttons) until then.
 */
const assert = require('assert');
const crypto = require('crypto');
const {
  providerConfig,
  isProviderConfigured,
  configuredProviders,
  buildAuthorizeUrl,
  pkcePair,
  signState,
  verifyState,
  exchangeCode,
  fetchProfile,
  normalizeProfile,
} = require('../utils/oauth');

let passed = 0, total = 0;
function test(name, fn) {
  total++;
  return Promise.resolve()
    .then(fn)
    .then(() => { passed++; console.log(`  ✓ PASS: ${name}`); })
    .catch((e) => { console.error(`  ✗ FAIL: ${name}\n    ${e.message}`); });
}

function stubFetch(routes) {
  return async (url, options) => {
    for (const [prefix, handler] of routes) {
      if (url.startsWith(prefix)) return handler(url, options);
    }
    throw new Error(`unexpected fetch: ${url}`);
  };
}
const okJson = (data) => ({ ok: true, status: 200, json: async () => data });

(async () => {
  await test('PKCE challenge matches RFC 7636 test vector', () => {
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
    assert.strictEqual(challenge, 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
    const pair = pkcePair();
    assert.ok(pair.verifier.length >= 32 && pair.challenge.length === 43);
  });

  await test('state sign/verify accepts genuine, rejects tampered', () => {
    const secret = 'test-secret';
    const state = signState('abc123', secret);
    assert.ok(verifyState(state, secret));
    assert.ok(!verifyState(`${state}x`, secret));
    assert.ok(!verifyState('abc123.deadbeef', secret));
    assert.ok(!verifyState('no-dot', secret));
    assert.ok(!verifyState(signState('abc123', 'other-secret'), secret));
  });

  await test('authorize URLs: provider params + PKCE', () => {
    const google = new URL(buildAuthorizeUrl('google', { clientId: 'gid', redirectUri: 'https://x/cb', state: 's', codeChallenge: 'c' }));
    assert.strictEqual(google.hostname, 'accounts.google.com');
    assert.strictEqual(google.searchParams.get('scope'), 'openid email profile');
    assert.strictEqual(google.searchParams.get('code_challenge_method'), 'S256');
    const github = new URL(buildAuthorizeUrl('github', { clientId: 'hid', redirectUri: 'https://x/cb', state: 's', codeChallenge: 'c' }));
    assert.strictEqual(github.hostname, 'github.com');
    assert.strictEqual(github.searchParams.get('scope'), 'read:user user:email');
    assert.strictEqual(providerConfig('bogus'), null);
  });

  await test('config: unconfigured without both id+secret; configured list', () => {
    assert.strictEqual(isProviderConfigured('google', {}), false);
    assert.strictEqual(isProviderConfigured('google', { GOOGLE_CLIENT_ID: 'x' }), false);
    assert.strictEqual(isProviderConfigured('google', { GOOGLE_CLIENT_ID: 'x', GOOGLE_CLIENT_SECRET: 'y' }), true);
    assert.deepStrictEqual(configuredProviders({}), []);
    assert.deepStrictEqual(
      configuredProviders({ GITHUB_CLIENT_ID: 'x', GITHUB_CLIENT_SECRET: 'y' }),
      [{ provider: 'github', label: 'GitHub' }],
    );
  });

  await test('normalize Google profile', () => {
    const n = normalizeProfile('google', { sub: '123', email: 'a@b.com', email_verified: true, given_name: 'Ada', family_name: 'Lovelace', name: 'Ada Lovelace' });
    assert.deepStrictEqual(n, { providerId: '123', email: 'a@b.com', emailVerified: true, firstName: 'Ada', lastName: 'Lovelace' });
    const unverified = normalizeProfile('google', { sub: '1', email: 'a@b.com', email_verified: false });
    assert.strictEqual(unverified.emailVerified, false);
  });

  await test('normalize GitHub profile via verified primary email', () => {
    const n = normalizeProfile('github', { id: 42, email: null, login: 'octocat', name: null }, [
      { email: 'hidden@example.com', primary: false, verified: true },
      { email: 'main@example.com', primary: true, verified: true },
    ]);
    assert.strictEqual(n.email, 'main@example.com');
    assert.strictEqual(n.emailVerified, true);
    assert.strictEqual(n.firstName, 'octocat');
    const none = normalizeProfile('github', { id: 43, email: null, login: 'x' }, []);
    assert.strictEqual(none.emailVerified, false);
  });

  await test('normalize GitLab profile requires confirmed_at', () => {
    const ok = normalizeProfile('gitlab', { id: 7, email: 'g@x.com', confirmed_at: '2026-01-01T00:00:00Z', name: 'Grace Hopper' });
    assert.strictEqual(ok.emailVerified, true);
    assert.strictEqual(ok.firstName, 'Grace');
    const no = normalizeProfile('gitlab', { id: 8, email: 'g@x.com', confirmed_at: null, username: 'gh' });
    assert.strictEqual(no.emailVerified, false);
  });

  await test('exchangeCode + fetchProfile via stubbed fetch', async () => {
    const fetchImpl = stubFetch([
      ['https://oauth2.googleapis.com/token', async () => okJson({ access_token: 'tok123' })],
      ['https://openidconnect.googleapis.com/v1/userinfo', async () => okJson({ sub: '9', email: 'z@x.com' })],
    ]);
    const token = await exchangeCode('google', { clientId: 'i', clientSecret: 's', redirectUri: 'r', code: 'c' }, fetchImpl);
    assert.strictEqual(token, 'tok123');
    const { profile } = await fetchProfile('google', token, fetchImpl);
    assert.strictEqual(profile.sub, '9');
    const badFetch = stubFetch([['https://', async () => ({ ok: false, status: 400, json: async () => ({}) })]]);
    await assert.rejects(() => exchangeCode('google', { clientId: 'i', clientSecret: 's', redirectUri: 'r', code: 'c' }, badFetch));
  });

  console.log(`\n${passed}/${total} OAuth unit tests passed`);
  process.exit(passed === total ? 0 : 1);
})();
