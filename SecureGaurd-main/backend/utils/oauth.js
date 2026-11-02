/**
 * SSO / OIDC provider logic (Day 10) — pure functions + injectable fetch.
 * No new dependencies: authorization-code flow with PKCE (S256) over the
 * global fetch, state signed with HMAC-SHA256. A provider is usable only
 * when BOTH its client id and secret are set in the environment; otherwise
 * the routes answer 501 and the frontend shows no button for it (fail
 * closed, never a dead button). No OAuth app is registered by this code —
 * creating the Google/GitHub/GitLab apps is HIS STEP (docs/OAUTH_SSO.md).
 */
const crypto = require('crypto');

const PROVIDERS = {
  google: {
    label: 'Google',
    authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    userinfoUrl: 'https://openidconnect.googleapis.com/v1/userinfo',
    scopes: ['openid', 'email', 'profile'],
    idField: 'oauthGoogleId',
    envId: 'GOOGLE_CLIENT_ID',
    envSecret: 'GOOGLE_CLIENT_SECRET',
  },
  github: {
    label: 'GitHub',
    authorizeUrl: 'https://github.com/login/oauth/authorize',
    tokenUrl: 'https://github.com/login/oauth/access_token',
    userinfoUrl: 'https://api.github.com/user',
    emailsUrl: 'https://api.github.com/user/emails',
    scopes: ['read:user', 'user:email'],
    idField: 'oauthGithubId',
    envId: 'GITHUB_CLIENT_ID',
    envSecret: 'GITHUB_CLIENT_SECRET',
  },
  gitlab: {
    label: 'GitLab',
    authorizeUrl: 'https://gitlab.com/oauth/authorize',
    tokenUrl: 'https://gitlab.com/oauth/token',
    userinfoUrl: 'https://gitlab.com/api/v4/user',
    scopes: ['read_user'],
    idField: 'oauthGitlabId',
    envId: 'GITLAB_CLIENT_ID',
    envSecret: 'GITLAB_CLIENT_SECRET',
  },
};

function providerConfig(provider) {
  return PROVIDERS[provider] || null;
}

function isProviderConfigured(provider, env = process.env) {
  const cfg = providerConfig(provider);
  if (!cfg) return false;
  return Boolean(env[cfg.envId] && env[cfg.envSecret]);
}

function configuredProviders(env = process.env) {
  return Object.keys(PROVIDERS)
    .filter((p) => isProviderConfigured(p, env))
    .map((p) => ({ provider: p, label: PROVIDERS[p].label }));
}

/** Callback URL the provider redirects to: this backend's public origin. */
function callbackUrl(req, provider) {
  const base = (process.env.BACKEND_URL || '').replace(/\/$/, '');
  if (base) return `${base}/api/auth/oauth/${provider}/callback`;
  return `${req.protocol}://${req.get('host')}/api/auth/oauth/${provider}/callback`;
}

function buildAuthorizeUrl(provider, { clientId, redirectUri, state, codeChallenge }) {
  const cfg = providerConfig(provider);
  const url = new URL(cfg.authorizeUrl);
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', cfg.scopes.join(' '));
  url.searchParams.set('state', state);
  if (codeChallenge) {
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');
  }
  if (provider === 'google') {
    url.searchParams.set('access_type', 'offline');
    url.searchParams.set('prompt', 'select_account');
  }
  return url.toString();
}

/** PKCE pair (RFC 7636). Returns { verifier, challenge }. */
function pkcePair() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

/** Sign a random state value so the callback can tell forgery from the real one. */
function signState(random, secret) {
  const sig = crypto.createHmac('sha256', secret).update(random).digest('hex');
  return `${random}.${sig}`;
}

function verifyState(state, secret) {
  if (typeof state !== 'string') return false;
  const dot = state.lastIndexOf('.');
  if (dot <= 0) return false;
  const random = state.slice(0, dot);
  const sig = state.slice(dot + 1);
  if (!/^[a-f0-9]{64}$/.test(sig)) return false;
  const expected = crypto.createHmac('sha256', secret).update(random).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
  } catch {
    return false;
  }
}

async function exchangeCode(provider, { clientId, clientSecret, redirectUri, code, codeVerifier }, fetchImpl = fetch) {
  const cfg = providerConfig(provider);
  const body = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri: redirectUri,
    grant_type: 'authorization_code',
    code,
  });
  if (codeVerifier) body.set('code_verifier', codeVerifier);
  const res = await fetchImpl(cfg.tokenUrl, {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  if (!res.ok) throw new Error(`OAuth token exchange failed (${res.status})`);
  const data = await res.json();
  if (!data.access_token) throw new Error('OAuth token exchange returned no access token');
  return data.access_token;
}

async function fetchProfile(provider, accessToken, fetchImpl = fetch) {
  const cfg = providerConfig(provider);
  const res = await fetchImpl(cfg.userinfoUrl, {
    headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' },
  });
  if (!res.ok) throw new Error(`OAuth profile fetch failed (${res.status})`);
  const profile = await res.json();
  let emails = null;
  if (cfg.emailsUrl) {
    const emRes = await fetchImpl(cfg.emailsUrl, {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' },
    });
    if (emRes.ok) emails = await emRes.json();
  }
  return { profile, emails };
}

function splitName(fullName, fallback) {
  const name = (fullName || '').trim();
  if (!name) return [fallback, ''];
  const parts = name.split(/\s+/);
  return [parts[0], parts.slice(1).join(' ')];
}

function normalizeProfile(provider, raw, emails) {
  if (provider === 'google') {
    const [firstName, lastName] = splitName(raw.name, 'Google');
    return {
      providerId: String(raw.sub),
      email: raw.email || null,
      emailVerified: raw.email_verified === true,
      firstName: raw.given_name || firstName,
      lastName: raw.family_name || lastName,
    };
  }
  if (provider === 'github') {
    // GitHub may hide the primary email on /user; the /user/emails list is
    // authoritative. Only a primary+verified address counts as verified.
    let email = raw.email || null;
    let emailVerified = false;
    if (Array.isArray(emails)) {
      const verified = emails.filter((e) => e.verified);
      const primary = verified.find((e) => e.primary) || verified[0];
      if (primary) {
        email = primary.email;
        emailVerified = true;
      }
    }
    const [firstName, lastName] = splitName(raw.name || raw.login, 'GitHub');
    return { providerId: String(raw.id), email, emailVerified, firstName, lastName };
  }
  if (provider === 'gitlab') {
    const [firstName, lastName] = splitName(raw.name || raw.username, 'GitLab');
    return {
      providerId: String(raw.id),
      email: raw.email || null,
      emailVerified: Boolean(raw.confirmed_at),
      firstName,
      lastName,
    };
  }
  throw new Error(`Unknown provider: ${provider}`);
}

module.exports = {
  PROVIDERS,
  providerConfig,
  isProviderConfigured,
  configuredProviders,
  callbackUrl,
  buildAuthorizeUrl,
  pkcePair,
  signState,
  verifyState,
  exchangeCode,
  fetchProfile,
  normalizeProfile,
  splitName,
};
