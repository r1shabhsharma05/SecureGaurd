const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const prisma = require('../prismaClient');
const authMiddleware = require('../middleware/auth');
const { sendMail, isMailConfigured } = require('../utils/mailer');
const { requireTurnstile } = require('../utils/turnstile');
const { planAccountDeletion } = require('../utils/accountDeletion');
const { cancelOrgProviderSubscription } = require('./organizations');
const {
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
} = require('../utils/oauth');

const rateLimit = require('express-rate-limit');

const ACCESS_EXPIRY  = '15m';   // short-lived access token
const REFRESH_EXPIRY = '7d';    // long-lived refresh token

// Rate Limiters
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: { message: 'Too many authentication attempts, please try again after 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const resetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5,
  message: { message: 'Too many password reset attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Day 9 — account deletion is destructive and session-bound: 3 attempts/hour
// is plenty for a real user and stops session-replay deletion probing.
const accountDeleteLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: { message: 'Too many account deletion attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ── Helpers ──────────────────────────────────────────────────────────────────
function generateAccessToken(userId) {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: ACCESS_EXPIRY });
}

function generateRefreshToken(userId) {
  return jwt.sign({ id: userId }, process.env.JWT_REFRESH_SECRET, { expiresIn: REFRESH_EXPIRY });
}

// One-way hash for bearer tokens stored at rest (password-reset and
// email-verification tokens). The raw token is emailed to the user; only
// its SHA-256 hash is stored, and lookups hash the presented token.
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function setRefreshCookie(res, token) {
  res.cookie('sg_refresh', token, {
    httpOnly: true,
    // Cross-origin: frontend (Vercel) and backend (Render) are different sites,
    // so the cookie must be SameSite=None (Lax is never sent on cross-site fetch).
    // SameSite=None requires Secure; localhost counts as a secure context.
    secure: true,
    sameSite: 'none',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in ms
    path: '/api/auth',
  });
}

function frontendBaseUrl() {
  return (process.env.FRONTEND_URL || 'http://localhost:5173').replace(/\/$/, '');
}

function clearRefreshCookie(res) {
  // Attributes must match the cookie being cleared, otherwise the browser keeps it.
  res.clearCookie('sg_refresh', { path: '/api/auth', sameSite: 'none', secure: true });
}

// ── POST /api/auth/register ───────────────────────────────────────────────────
// Day 9: Turnstile captcha guard (env-gated — see utils/turnstile.js).
router.post('/register', authLimiter, requireTurnstile(), async (req, res) => {
  const { firstName, lastName, email, password } = req.body;

  if (!firstName || !lastName || !email || !password)
    return res.status(400).json({ message: 'All fields are required' });

  if (password.length < 8)
    return res.status(400).json({ message: 'Password must be at least 8 characters' });

  try {
    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) return res.status(400).json({ message: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 12);
    const emailVerifyToken = crypto.randomBytes(32).toString('hex');
    // Store only the SHA-256 hash of the verification token (a DB read
    // must not yield a usable token) with a 24 h expiry. Requires the
    // User.emailVerifyTokenExpiresAt column (schema worker owns it).
    const emailVerifyExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);

    const newUser = await prisma.user.create({
      data: { firstName, lastName, email, password: hashedPassword, emailVerifyToken: hashToken(emailVerifyToken), emailVerifyTokenExpiresAt: emailVerifyExpiry },
    });

    const accessToken  = generateAccessToken(newUser.id);
    const refreshToken = generateRefreshToken(newUser.id);

    // Store hashed refresh token in DB
    const hashedRefresh = await bcrypt.hash(refreshToken, 10);
    await prisma.user.update({ where: { id: newUser.id }, data: { refreshToken: hashedRefresh } });

    setRefreshCookie(res, refreshToken);

    // Best-effort verification email: registration must not fail when SMTP
    // is unconfigured or down — the token stays stored for /verify-email.
    if (isMailConfigured()) {
      const verifyUrl = `${req.protocol}://${req.get('host') || 'localhost'}/api/auth/verify-email?token=${emailVerifyToken}`;
      try {
        await sendMail({
          to: email,
          subject: 'Verify your SecureGuard email',
          text: `Welcome to SecureGuard. Verify your email address: ${verifyUrl}`,
          html: `<p>Welcome to SecureGuard.</p><p><a href="${verifyUrl}">Verify your email address</a></p>`,
        });
      } catch (mailErr) {
        console.error('Failed to send verification email:', mailErr);
      }
    }

    res.status(201).json({
      accessToken,
      user: { id: newUser.id, firstName, lastName, email, isEmailVerified: false, onboardingCompleted: false },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ── GET|POST /api/auth/verify-email ───────────────────────────────────────────
// Consumes the token generated at register. Only the SHA-256 hash of the
// token is stored (User.emailVerifyToken), with a 24 h expiry
// (User.emailVerifyTokenExpiresAt — schema worker owns the column); the
// presented token is hashed before lookup and the token is single-use.
async function verifyEmailHandler(req, res) {
  const token = req.query?.token || req.body?.token;
  if (!token) return res.status(400).json({ message: 'Verification token is required' });

  try {
    const user = await prisma.user.findFirst({
      where: {
        emailVerifyToken: hashToken(token),
        emailVerifyTokenExpiresAt: { gt: new Date() },
      },
    });
    if (!user) return res.status(400).json({ message: 'Invalid or expired verification token' });

    await prisma.user.update({
      where: { id: user.id },
      data: { isEmailVerified: true, emailVerifyToken: null, emailVerifyTokenExpiresAt: null },
    });

    res.json({ message: 'Email verified successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
}
router.get('/verify-email', verifyEmailHandler);
router.post('/verify-email', verifyEmailHandler);

// ── POST /api/auth/login ──────────────────────────────────────────────────────
router.post('/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'All fields are required' });

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const accessToken  = generateAccessToken(user.id);
    const refreshToken = generateRefreshToken(user.id);

    // Rotate: store new hashed refresh token
    const hashedRefresh = await bcrypt.hash(refreshToken, 10);
    await prisma.user.update({ where: { id: user.id }, data: { refreshToken: hashedRefresh } });

    setRefreshCookie(res, refreshToken);

    res.json({
      accessToken,
      user: { id: user.id, firstName: user.firstName, lastName: user.lastName, email: user.email, isEmailVerified: user.isEmailVerified, onboardingCompleted: !!user.onboardingCompleted },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ── POST /api/auth/refresh ────────────────────────────────────────────────────
// Rotating refresh with a 60 s grace window for the superseded token.
// Race safety: the rotation is an atomic compare-and-swap on the verified
// hash — a concurrent request that loses the race re-reads the row and is
// honored via the grace window instead of being logged out. A token presented
// outside its grace window (unknown or replayed) invalidates the session:
// that is token-reuse detection, and the session is killed.
const REFRESH_GRACE_MS = 60 * 1000;

function publicUser(user) {
  return {
    id: user.id,
    firstName: user.firstName,
    lastName: user.lastName,
    email: user.email,
    isEmailVerified: user.isEmailVerified,
    onboardingCompleted: !!user.onboardingCompleted,
  };
}

// Atomically rotate the refresh token: succeeds only if the stored current
// hash still equals the one we verified. Returns the new access token, or
// null when another request rotated first (caller re-reads and retries).
async function rotateRefreshToken(userId, verifiedCurrentHash, res) {
  const newRefreshToken = generateRefreshToken(userId);
  const hashedRefresh = await bcrypt.hash(newRefreshToken, 10);
  const result = await prisma.user.updateMany({
    where: { id: userId, refreshToken: verifiedCurrentHash },
    data: {
      previousRefreshToken: verifiedCurrentHash,
      refreshGraceExpiresAt: new Date(Date.now() + REFRESH_GRACE_MS),
      refreshToken: hashedRefresh,
    },
  });
  if (result.count === 0) return null;
  setRefreshCookie(res, newRefreshToken);
  return generateAccessToken(userId);
}

router.post('/refresh', async (req, res) => {
  const token = req.cookies?.sg_refresh;
  if (!token) return res.status(401).json({ message: 'No refresh token' });

  let decoded;
  try {
    decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
  } catch {
    clearRefreshCookie(res);
    return res.status(401).json({ message: 'Session expired, please login again' });
  }

  for (let attempt = 0; attempt < 2; attempt++) {
    const user = await prisma.user.findUnique({ where: { id: decoded.id } });

    if (!user || !user.refreshToken) {
      clearRefreshCookie(res);
      return res.status(401).json({ message: 'Session expired, please login again' });
    }

    // Path 1: token matches the current hash → rotate.
    if (await bcrypt.compare(token, user.refreshToken)) {
      const accessToken = await rotateRefreshToken(user.id, user.refreshToken, res);
      if (accessToken) {
        return res.json({ accessToken, user: publicUser(user) });
      }
      continue; // lost the atomic race — re-read; the grace path below catches it
    }

    // Path 2: superseded token presented inside its grace window → honor once, rotate again.
    if (
      user.previousRefreshToken &&
      user.refreshGraceExpiresAt &&
      user.refreshGraceExpiresAt > new Date() &&
      (await bcrypt.compare(token, user.previousRefreshToken))
    ) {
      const accessToken = await rotateRefreshToken(user.id, user.refreshToken, res);
      if (accessToken) {
        return res.json({ accessToken, user: publicUser(user) });
      }
      continue;
    }

    break;
  }

  // Reuse outside the grace window (or a token that was never issued):
  // possible theft — kill the session server-side and drop the cookie.
  try {
    await prisma.user.update({
      where: { id: decoded.id },
      data: { refreshToken: null, previousRefreshToken: null, refreshGraceExpiresAt: null },
    });
  } catch { /* user row may already be gone */ }
  clearRefreshCookie(res);
  return res.status(401).json({ message: 'Session expired, please login again' });
});

// ── POST /api/auth/logout ─────────────────────────────────────────────────────
router.post('/logout', async (req, res) => {
  const token = req.cookies?.sg_refresh;
  if (token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
      // Invalidate stored refresh token and any in-grace superseded token
      await prisma.user.update({ where: { id: decoded.id }, data: { refreshToken: null, previousRefreshToken: null, refreshGraceExpiresAt: null } });
    } catch { /* already expired */ }
  }
  clearRefreshCookie(res);
  res.json({ message: 'Logged out successfully' });
});

// ── POST /api/auth/forgot-password ───────────────────────────────────────────
// Day 9: Turnstile captcha guard (env-gated — see utils/turnstile.js).
router.post('/forgot-password', resetLimiter, requireTurnstile(), async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: 'Email is required' });

  try {
    const user = await prisma.user.findUnique({ where: { email } });

    if (user) {
      const resetToken  = crypto.randomBytes(32).toString('hex');
      const resetExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

      // Store only the SHA-256 hash of the reset token; the raw token is
      // emailed to the user and is single-use with a 1-hour expiry.
      await prisma.user.update({
        where: { id: user.id },
        data: { passwordResetToken: hashToken(resetToken), passwordResetExpiry: resetExpiry },
      });

      // Honest failure instead of a false "link sent" claim: mail delivery
      // being unconfigured is a server-config fact, not user data.
      if (!isMailConfigured()) {
        return res.status(503).json({ message: 'Password reset email is not configured on the server, so a reset link cannot be sent. Please contact support.' });
      }

      const resetUrl = `${frontendBaseUrl()}/reset-password?token=${resetToken}`;
      try {
        await sendMail({
          to: email,
          subject: 'Reset your SecureGuard password',
          text: `Reset your SecureGuard password (link expires in 1 hour): ${resetUrl}\nOr enter this token in the app: ${resetToken}`,
          html: `<p>Reset your SecureGuard password (link expires in 1 hour):</p><p><a href="${resetUrl}">Reset password</a></p>`,
        });
      } catch (mailErr) {
        console.error('Failed to send password reset email:', mailErr);
        return res.status(503).json({ message: 'Password reset email could not be delivered. Please try again later.' });
      }
    } else if (!isMailConfigured()) {
      // Same honest config response for unknown emails (no enumeration gain).
      return res.status(503).json({ message: 'Password reset email is not configured on the server, so a reset link cannot be sent. Please contact support.' });
    }

    // Always return 200 to prevent email enumeration (mail-configured path)
    res.json({
      message: 'If that email exists, a password reset link has been sent to your email.'
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ── POST /api/auth/reset-password ────────────────────────────────────────────
// Day 9: rate-limited like forgot-password — the token endpoint had no
// limiter, so a stolen token could be brute-forced without friction.
router.post('/reset-password', resetLimiter, async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) return res.status(400).json({ message: 'Token and new password are required' });
  if (newPassword.length < 8) return res.status(400).json({ message: 'Password must be at least 8 characters' });

  try {
    const user = await prisma.user.findFirst({
      where: {
        passwordResetToken: hashToken(token),
        passwordResetExpiry: { gt: new Date() }, // not expired
      },
    });

    if (!user) return res.status(400).json({ message: 'Invalid or expired reset token' });

    const hashedPassword = await bcrypt.hash(newPassword, 12);

    await prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        passwordResetToken: null,
        passwordResetExpiry: null,
        refreshToken: null, // invalidate all existing sessions
        previousRefreshToken: null,
        refreshGraceExpiresAt: null,
      },
    });

    clearRefreshCookie(res);
    res.json({ message: 'Password reset successfully. Please login with your new password.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ── GET /api/auth/me ──────────────────────────────────────────────────────────
// Used by frontend to restore session from refresh cookie on page load
router.get('/me', async (req, res) => {
  const token = req.cookies?.sg_refresh;
  if (!token) return res.status(401).json({ message: 'Not authenticated' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    const user = await prisma.user.findUnique({ where: { id: decoded.id } });
    if (!user || !user.refreshToken) return res.status(401).json({ message: 'Session expired' });

    // Accept the current token, or a superseded token inside its rotation
    // grace window (a concurrent /refresh may have just rotated it).
    const currentValid = await bcrypt.compare(token, user.refreshToken);
    const graceValid =
      !currentValid &&
      !!user.previousRefreshToken &&
      !!user.refreshGraceExpiresAt &&
      user.refreshGraceExpiresAt > new Date() &&
      (await bcrypt.compare(token, user.previousRefreshToken));
    if (!currentValid && !graceValid) return res.status(401).json({ message: 'Invalid session' });

    // Read-only session restore: do NOT rotate the refresh token here.
    // Rotating on every /me call made concurrent restores (multiple tabs /
    // in-flight requests) invalidate each other and caused spurious
    // logouts. Rotation stays exclusive to POST /refresh.
    const newAccessToken = generateAccessToken(user.id);

    res.json({
      accessToken: newAccessToken,
      user: { id: user.id, firstName: user.firstName, lastName: user.lastName, email: user.email, isEmailVerified: user.isEmailVerified, onboardingCompleted: !!user.onboardingCompleted },
    });
  } catch {
    clearRefreshCookie(res);
    return res.status(401).json({ message: 'Session expired' });
  }
});

// ── SSO / OIDC (Day 10) ───────────────────────────────────────────────────────
// "Continue with Google / GitHub / GitLab": real authorization-code + PKCE
// flows (utils/oauth.js). A provider works only when its client id + secret
// are set; otherwise /providers omits it (no button) and /:provider answers
// 501 (never a dead redirect). Account linking: a verified provider email
// matching an existing account links that account; a new email creates an
// account with an unusable random password hash (password login can never
// guess it; forgot-password still works). SAML is NOT implemented: see
// docs/OAUTH_SSO.md — the config surface deliberately 501s rather than
// pretending a SAML login exists.
const oauthCallbackLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 30,
  message: { message: 'Too many sign-in attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

function oauthStateCookieOptions() {
  return { httpOnly: true, secure: true, sameSite: 'none', maxAge: 10 * 60 * 1000, path: '/api/auth' };
}
function clearOauthCookies(res) {
  res.clearCookie('sg_oauth_state', { path: '/api/auth', sameSite: 'none', secure: true });
  res.clearCookie('sg_oauth_pkce', { path: '/api/auth', sameSite: 'none', secure: true });
}

// GET /api/auth/oauth/providers — public list of configured providers.
router.get('/oauth/providers', async (req, res) => {
  res.json({ providers: configuredProviders() });
});

// GET /api/auth/oauth/:provider — start the provider flow (302 redirect).
router.get('/oauth/:provider', async (req, res) => {
  const cfg = providerConfig(req.params.provider);
  if (!cfg) return res.status(404).json({ message: 'Unknown sign-in provider' });
  if (!isProviderConfigured(req.params.provider)) {
    return res.status(501).json({
      message: `${cfg.label} sign-in is not configured on the server.`,
      provider: req.params.provider,
      configured: false,
    });
  }
  const state = signState(crypto.randomBytes(16).toString('hex'), process.env.JWT_SECRET);
  const { verifier, challenge } = pkcePair();
  res.cookie('sg_oauth_state', state, oauthStateCookieOptions());
  res.cookie('sg_oauth_pkce', verifier, oauthStateCookieOptions());
  const redirectUri = callbackUrl(req, req.params.provider);
  res.redirect(buildAuthorizeUrl(req.params.provider, {
    clientId: process.env[cfg.envId],
    redirectUri,
    state,
    codeChallenge: challenge,
  }));
});

// GET /api/auth/oauth/:provider/callback — provider redirects here with a
// code. On success the refresh cookie is set and the browser lands on the
// frontend /oauth/callback page, which restores the session via /refresh.
// On any failure the browser lands on /login with ?oauth_error=<code>;
// provider error details are logged, never shown (no account enumeration).
router.get('/oauth/:provider/callback', oauthCallbackLimiter, async (req, res) => {
  const provider = req.params.provider;
  const cfg = providerConfig(provider);
  const fail = (code) => {
    clearOauthCookies(res);
    return res.redirect(`${frontendBaseUrl()}/login?oauth_error=${code}`);
  };
  if (!cfg || !isProviderConfigured(provider)) return fail('provider_not_configured');
  if (req.query.error) {
    console.error(`OAuth ${provider} returned error: ${req.query.error}`);
    return fail('provider_error');
  }
  const { code, state } = req.query;
  const stateCookie = req.cookies?.sg_oauth_state;
  if (!code || !state || !stateCookie || state !== stateCookie || !verifyState(state, process.env.JWT_SECRET)) {
    return fail('invalid_state');
  }
  try {
    const redirectUri = callbackUrl(req, provider);
    const accessToken = await exchangeCode(provider, {
      clientId: process.env[cfg.envId],
      clientSecret: process.env[cfg.envSecret],
      redirectUri,
      code,
      codeVerifier: req.cookies?.sg_oauth_pkce,
    });
    const { profile, emails } = await fetchProfile(provider, accessToken);
    const normalized = normalizeProfile(provider, profile, emails);
    if (!normalized.email || !normalized.emailVerified) return fail('email_not_verified');

    const idField = cfg.idField;
    let user = await prisma.user.findFirst({ where: { [idField]: normalized.providerId } });
    if (!user) {
      const byEmail = await prisma.user.findUnique({ where: { email: normalized.email } });
      if (byEmail && byEmail[idField] && byEmail[idField] !== normalized.providerId) {
        return fail('account_link_conflict');
      }
      if (byEmail) {
        user = await prisma.user.update({
          where: { id: byEmail.id },
          data: { [idField]: normalized.providerId, isEmailVerified: true },
        });
      } else {
        // Unusable password: a random secret only the server ever hashed.
        const unusable = await bcrypt.hash(crypto.randomBytes(32).toString('hex'), 12);
        user = await prisma.user.create({
          data: {
            firstName: normalized.firstName,
            lastName: normalized.lastName,
            email: normalized.email,
            password: unusable,
            isEmailVerified: true,
            onboardingCompleted: false,
            [idField]: normalized.providerId,
          },
        });
      }
    }

    const refreshToken = generateRefreshToken(user.id);
    const hashedRefresh = await bcrypt.hash(refreshToken, 10);
    await prisma.user.update({ where: { id: user.id }, data: { refreshToken: hashedRefresh } });
    setRefreshCookie(res, refreshToken);
    clearOauthCookies(res);
    return res.redirect(`${frontendBaseUrl()}/oauth/callback`);
  } catch (err) {
    console.error(`OAuth ${provider} callback failed:`, err.message);
    return fail('failed');
  }
});

// ── POST /api/auth/complete-onboarding ────────────────────────────────────────
router.post('/complete-onboarding', authMiddleware, async (req, res) => {
  try {
    const user = await prisma.user.update({
      where: { id: req.userId },
      data: { onboardingCompleted: true }
    });
    res.json({
      message: 'Onboarding completed successfully',
      user: {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        isEmailVerified: user.isEmailVerified,
        onboardingCompleted: true
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error completing onboarding' });
  }
});

// ── DELETE /api/auth/account — Delete my account (Day 9) ─────────────────────
// Real deletion, not deactivation. Requires the current password (a stolen
// session token alone must not delete an account) plus the typed
// confirmation "DELETE". Organization handoff follows the planner in
// utils/accountDeletion.js: sole-owner orgs with other members transfer
// to the oldest Admin/member (and the departing user's org-owned repos,
// scans and reports are reassigned to the successor so the transfer does
// not gut the org); sole-member orgs are deleted with the account;
// every other membership is removed only after the departing user's
// org assets are reassigned to a remaining OWNER/ADMIN (the same handoff
// as transfers), so leaving never destroys a surviving org's assets.
// Personal data cascades via
// Prisma (repos, scans, compliance reports, memberships); invitations
// the user sent keep their rows with a null inviter; audit rows keep
// theirs with a null actor.
router.delete('/account', accountDeleteLimiter, authMiddleware, async (req, res) => {
  const { password, confirmation } = req.body || {};
  if (!password || confirmation !== 'DELETE') {
    return res.status(400).json({ message: 'Your current password and the typed confirmation DELETE are required.' });
  }
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.userId },
      include: {
        memberships: { include: { organization: { include: { memberships: true } } } },
      },
    });
    if (!user) return res.status(404).json({ message: 'Account not found' });
    if (!(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: 'Password is incorrect' });
    }
    const memberships = user.memberships.map((m) => ({
      organizationId: m.organizationId,
      role: m.role,
      members: m.organization.memberships.map((x) => ({ userId: x.userId, role: x.role, createdAt: x.createdAt })),
    }));
    const plan = planAccountDeletion(req.userId, memberships);
    // Org-scoped assets reassigned on account deletion, per organization,
    // disclosed in the response (finding 1). CustomRule.createdById is a
    // plain nullable Int (no User relation), so it is reassigned the same
    // way instead of dangling at the deleted user id.
    const reassignedAssets = { repositories: 0, scans: 0, complianceReports: 0, customRules: 0 };
    const reassignedAssetsByOrganization = {};
    async function reassignOrgAssets(tx, organizationId, successorId) {
      const counts = {
        repositories: (await tx.repository.updateMany({ where: { organizationId, userId: req.userId }, data: { userId: successorId } })).count,
        scans: (await tx.scan.updateMany({ where: { organizationId, userId: req.userId }, data: { userId: successorId } })).count,
        complianceReports: (await tx.complianceReport.updateMany({ where: { organizationId, userId: req.userId }, data: { userId: successorId } })).count,
        customRules: (await tx.customRule.updateMany({ where: { organizationId, createdById: req.userId }, data: { createdById: successorId } })).count,
      };
      for (const [key, value] of Object.entries(counts)) reassignedAssets[key] += value;
      reassignedAssetsByOrganization[organizationId] = counts;
      return counts;
    }
    // Cancel-then-delete for sole-owned orgs slated for deletion: their
    // Subscription rows cascade-delete with the org, destroying the only
    // provider ids needed to cancel. Fail closed (502) so a live paid
    // subscription is never orphaned by account deletion.
    for (const orgId of plan.deletions) {
      const sub = await prisma.subscription.findUnique({ where: { organizationId: orgId } });
      const billingBlock = await cancelOrgProviderSubscription(sub);
      if (billingBlock) {
        return res.status(billingBlock.status).json({ message: billingBlock.message });
      }
    }
    await prisma.$transaction(async (tx) => {
      for (const t of plan.transfers) {
        await tx.organizationMembership.update({
          where: { userId_organizationId: { userId: t.newOwnerId, organizationId: t.organizationId } },
          data: { role: 'OWNER' },
        });
        await reassignOrgAssets(tx, t.organizationId, t.newOwnerId);
      }
      for (const orgId of plan.leaves) {
        // Leaves used to only delete the membership, so the later
        // tx.user.delete cascade-destroyed every repository, scan and
        // compliance report the departing user created in a surviving
        // org. Reassign them first, exactly as on transfers, to a
        // remaining OWNER, else the oldest ADMIN, else the oldest
        // remaining member (a leave always has other members by
        // construction, so a successor exists).
        const remaining = await tx.organizationMembership.findMany({
          where: { organizationId: orgId, userId: { not: req.userId } },
          orderBy: [{ createdAt: 'asc' }, { userId: 'asc' }],
        });
        const successor = remaining.find((m) => m.role === 'OWNER')
          || remaining.find((m) => m.role === 'ADMIN')
          || remaining[0];
        if (successor) await reassignOrgAssets(tx, orgId, successor.userId);
        await tx.organizationMembership.delete({
          where: { userId_organizationId: { userId: req.userId, organizationId: orgId } },
        });
      }
      for (const orgId of plan.deletions) {
        await tx.organization.delete({ where: { id: orgId } });
      }
      // Audit INSIDE the transaction, before the user row is deleted:
      // createAuditLog uses the global prisma client and cannot run in
      // this transaction, so the rows are written via tx.auditLog.create
      // directly while actorId still references a live user. After the
      // delete commits, the SetNull relation nulls actorId and the rows
      // survive. (Writing them after the transaction, as before, meant
      // the insert referenced a deleted user and was silently swallowed.)
      for (const t of plan.transfers) {
        await tx.auditLog.create({
          data: { organizationId: t.organizationId, actorId: req.userId, action: 'OWNERSHIP_TRANSFERRED', targetType: 'ORGANIZATION', targetId: String(t.organizationId), details: { reason: 'account_deletion', newOwnerId: t.newOwnerId } },
        });
      }
      for (const orgId of plan.leaves) {
        await tx.auditLog.create({
          data: { organizationId: orgId, actorId: req.userId, action: 'MEMBER_REMOVED', targetType: 'USER', targetId: String(req.userId), details: { reason: 'account_deletion' } },
        });
      }
      await tx.user.delete({ where: { id: req.userId } });
    });
    clearRefreshCookie(res);
    res.json({
      message: 'Account deleted.',
      transferredOrganizations: plan.transfers.map((t) => t.organizationId),
      deletedOrganizations: plan.deletions,
      leftOrganizations: plan.leaves,
      reassignedAssets,
      reassignedAssetsByOrganization,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;



