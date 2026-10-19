const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const prisma = require('../prismaClient');
const authMiddleware = require('../middleware/auth');

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

    res.status(201).json({
      accessToken,
      user: { id: newUser.id, firstName, lastName, email, isEmailVerified: false, onboardingCompleted: false },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

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
router.post('/refresh', async (req, res) => {
  const token = req.cookies?.sg_refresh;
  if (!token) return res.status(401).json({ message: 'No refresh token' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET + '_refresh');
    const user = await prisma.user.findUnique({ where: { id: decoded.id } });

    if (!user || !user.refreshToken)
      return res.status(401).json({ message: 'Session expired, please login again' });

    // Validate stored hash matches the cookie token
    const valid = await bcrypt.compare(token, user.refreshToken);
    if (!valid) return res.status(401).json({ message: 'Invalid refresh token' });

    // Rotate — issue new pair
    const newAccessToken  = generateAccessToken(user.id);
    const newRefreshToken = generateRefreshToken(user.id);
    const hashedRefresh   = await bcrypt.hash(newRefreshToken, 10);
    await prisma.user.update({ where: { id: user.id }, data: { refreshToken: hashedRefresh } });

    setRefreshCookie(res, newRefreshToken);

    res.json({
      accessToken: newAccessToken,
      user: { id: user.id, firstName: user.firstName, lastName: user.lastName, email: user.email, isEmailVerified: user.isEmailVerified, onboardingCompleted: !!user.onboardingCompleted },
    });
  } catch {
    clearRefreshCookie(res);
    return res.status(401).json({ message: 'Session expired, please login again' });
  }
});

// ── POST /api/auth/logout ─────────────────────────────────────────────────────
router.post('/logout', async (req, res) => {
  const token = req.cookies?.sg_refresh;
  if (token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET + '_refresh');
      // Invalidate stored refresh token
      await prisma.user.update({ where: { id: decoded.id }, data: { refreshToken: null } });
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

    // Always return 200 to prevent email enumeration
    if (!user) return res.json({ message: 'If that email exists, a reset link has been sent.' });

    const resetToken  = crypto.randomBytes(32).toString('hex');
    const resetExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    await prisma.user.update({
      where: { id: user.id },
      data: { passwordResetToken: resetToken, passwordResetExpiry: resetExpiry },
    });

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

    const valid = await bcrypt.compare(token, user.refreshToken);
    if (!valid) return res.status(401).json({ message: 'Invalid session' });

    const newAccessToken  = generateAccessToken(user.id);
    const newRefreshToken = generateRefreshToken(user.id);
    const hashedRefresh   = await bcrypt.hash(newRefreshToken, 10);
    await prisma.user.update({ where: { id: user.id }, data: { refreshToken: hashedRefresh } });
    setRefreshCookie(res, newRefreshToken);

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



