const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const dotenv = require('dotenv');
const cookieParser = require('cookie-parser');

dotenv.config();

const { validateEnv } = require('./config/env');

// Fail fast on missing secrets/config — never run half-configured.
// NOTE: this MUST run before the route requires below. routes/integration.js
// -> utils/cryptoUtils.js reads process.env.JWT_SECRET at require time, so a
// missing JWT_SECRET would otherwise crash with a cryptic TypeError before
// this clear error ever fires.
validateEnv();

// Day 9 — Sentry error tracking (env-gated, inert without SENTRY_DSN).
const { initSentry, sentryErrorHandler } = require('./utils/sentry');
initSentry();

const authRoutes = require('./routes/auth');
const repoRoutes = require('./routes/repos');
const scanRoutes = require('./routes/scans');
const vulnRoutes = require('./routes/vulnerabilities');
const integrationRoutes = require('./routes/integration');
const aiRoutes = require('./routes/ai');
const classifierRoutes = require('./routes/classifier');
const mlRoutes = require('./routes/ml');
const complianceRoutes = require('./routes/compliance');
const orgRoutes = require('./routes/organizations');
const invitationRoutes = require('./routes/invitations');
const billingWebhookRoutes = require('./routes/billingWebhook');
const billingRoutes = require('./routes/billing');
const sbomRoutes = require('./routes/sboms');
const alertRoutes = require('./routes/alerts');
const customRulesRoutes = require('./routes/customRules');
const publicRoutes = require('./routes/public');
const prisma = require('./prismaClient');
const { getAllowedOrigins } = require('./config/cors');

const app = express();

const allowedOrigins = getAllowedOrigins();
// Trust-proxy hop count is env-configurable: the hosted Vercel -> Render
// path appends X-Forwarded-For twice, so it needs TRUST_PROXY_HOPS=2;
// the on-prem nginx path is a single hop (default 1). Undercounting
// collapses req.ip to a shared edge IP and every per-IP rate limiter
// shares one bucket.
const trustProxyHops = Number.parseInt(process.env.TRUST_PROXY_HOPS || '1', 10);
app.set('trust proxy', Number.isNaN(trustProxyHops) ? 1 : trustProxyHops);
// Security headers (F12). Helmet defaults are safe alongside CORS for a
// JSON API; crossOriginResourcePolicy is relaxed to "cross-origin" so the
// separately-hosted frontend can consume API responses (incl. generated
// reports) without CORP blocking — CORS above remains the access gate.
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Blocked by CORS policy: Origin not allowed'));
    }
  },
  credentials: true
}));

// Mount Webhook route BEFORE express.json parser so raw signature verification works
app.use('/api/billing/webhook', billingWebhookRoutes);

app.use(express.json({
  limit: '1mb',
  // Keep the exact request bytes so webhook handlers can verify HMAC
  // signatures over the raw body (re-serialized JSON does not match).
  verify: (req, res, buf) => { req.rawBody = buf; },
}));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(cookieParser());

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Day 9 — forced Sentry test error. Exists ONLY when SENTRY_TEST_ROUTE is
// explicitly 'enabled' (never by default in production): hit it once after
// setting SENTRY_DSN, confirm the error in the Sentry dashboard, then
// remove the env var. The global error handler below captures it.
if (process.env.SENTRY_TEST_ROUTE === 'enabled') {
  app.get('/api/_test-error', (req, res, next) => {
    next(new Error('SecureGuard Sentry test error — ignore'));
  });
}

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/repos', repoRoutes);
app.use('/api/scans', scanRoutes);
app.use('/api/vulnerabilities', vulnRoutes);
app.use('/api/integration', integrationRoutes);
app.use('/api/ai', aiRoutes);
app.use('/api/classifier', classifierRoutes);
app.use('/api/v2/ml', mlRoutes);
app.use('/api/compliance', complianceRoutes);
app.use('/api/organizations', orgRoutes);
app.use('/api/invitations', invitationRoutes);
app.use('/api/billing', billingRoutes);
app.use('/api/sboms', sbomRoutes);
app.use('/api/alerts', alertRoutes);
app.use('/api/custom-rules', customRulesRoutes);
app.use('/api', publicRoutes);

// Day 9 — global error handler (last): captures to Sentry when configured
// and answers with a generic 500. Stack traces never reach clients.
app.use(sentryErrorHandler);

// Test PostgreSQL connection
prisma.$connect()
  .then(() => console.log('PostgreSQL database successfully connected via Prisma'))
  .catch((err) => console.error('Database connection error:', err));

const PORT = process.env.PORT || 5000;

if (require.main === module) {
  app.listen(PORT, '0.0.0.0', () => console.log(`Server running on port ${PORT}`));
}

module.exports = app;
