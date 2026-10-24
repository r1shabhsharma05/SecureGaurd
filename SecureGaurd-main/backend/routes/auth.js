const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const prisma = require('../prismaClient');
const authMiddleware = require('../middleware/auth');
const { sendMail, isMailConfigured } = require('../utils/mailer');

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

// ── Helpers ──────────────────────────────────────────────────────────────────
function generateAccessToken(userId) {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: ACCESS_EXPIRY });
}

function generateRefreshToken(userId) {
  return jwt.sign({ id: userId }, process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET + '_refresh', { expiresIn: REFRESH_EXPIRY });
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
router.post('/register', authLimiter, async (req, res) => {
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

    const newUser = await prisma.user.create({
      data: { firstName, lastName, email, password: hashedPassword, emailVerifyToken },
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
// Consumes the token generated at register (User.emailVerifyToken, stored in
// plaintext like the password-reset token) and marks the email verified.
async function verifyEmailHandler(req, res) {
  const token = req.query?.token || req.body?.token;
  if (!token) return res.status(400).json({ message: 'Verification token is required' });

  try {
    const user = await prisma.user.findFirst({ where: { emailVerifyToken: token } });
    if (!user) return res.status(400).json({ message: 'Invalid or expired verification token' });

    await prisma.user.update({
      where: { id: user.id },
      data: { isEmailVerified: true, emailVerifyToken: null },
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
    decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET + '_refresh');
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
      const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET + '_refresh');
      // Invalidate stored refresh token and any in-grace superseded token
      await prisma.user.update({ where: { id: decoded.id }, data: { refreshToken: null, previousRefreshToken: null, refreshGraceExpiresAt: null } });
    } catch { /* already expired */ }
  }
  clearRefreshCookie(res);
  res.json({ message: 'Logged out successfully' });
});

// ── POST /api/auth/forgot-password ───────────────────────────────────────────
router.post('/forgot-password', resetLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: 'Email is required' });

  try {
    const user = await prisma.user.findUnique({ where: { email } });

    if (user) {
      const resetToken  = crypto.randomBytes(32).toString('hex');
      const resetExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

      await prisma.user.update({
        where: { id: user.id },
        data: { passwordResetToken: resetToken, passwordResetExpiry: resetExpiry },
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
router.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) return res.status(400).json({ message: 'Token and new password are required' });
  if (newPassword.length < 8) return res.status(400).json({ message: 'Password must be at least 8 characters' });

  try {
    const user = await prisma.user.findFirst({
      where: {
        passwordResetToken: token,
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
    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET + '_refresh');
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

module.exports = router;



