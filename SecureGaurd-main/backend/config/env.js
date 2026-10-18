/**
 * Startup environment validation.
 *
 * Fails fast when required secrets/config are missing so the server never
 * runs in a half-configured (insecure) state — e.g. signing JWTs with an
 * undefined secret or deriving the PAT encryption key from a hardcoded
 * default. Optional integrations only warn; their features stay disabled.
 *
 * Call `validateEnv()` once in server.js right after `dotenv.config()`.
 */

const REQUIRED_VARS = [
  {
    name: 'JWT_SECRET',
    why: 'signs access tokens (middleware/auth.js, routes/auth.js); also seeds the PAT encryption key',
  },
  {
    name: 'DATABASE_URL',
    why: 'PostgreSQL connection string for Prisma (prismaClient.js)',
  },
];

const OPTIONAL_VARS = [
  { name: 'JWT_REFRESH_SECRET', why: 'signs refresh tokens (falls back to a JWT_SECRET-derived value)' },
  { name: 'ENCRYPTION_KEY', why: 'AES-256-GCM key for PAT encryption at rest (utils/cryptoUtils.js)' },
  { name: 'WEBHOOK_SECRET', why: 'fallback secret for webhook signature verification' },
  { name: 'FRONTEND_URL', why: 'production frontend origin for the CORS allow-list' },
  { name: 'GEMINI_API_KEY', why: 'AI fix engine: official Gemini API' },
  { name: 'GEMINI_WEB2API_KEY', why: 'AI fix engine: web2api proxy bearer token' },
  { name: 'GEMINI_WEB2API_URL', why: 'AI fix engine: web2api proxy base URL' },
  { name: 'FP_CLASSIFIER_URL', why: 'Python ML false-positive classifier service URL' },
  { name: 'CLASSIFIER_API_KEY', why: 'auth token for the FP classifier service' },
];

function validateEnv(env = process.env) {
  for (const { name, why } of OPTIONAL_VARS) {
    if (!env[name]) {
      console.warn(`[env] ${name} is not set (${why}). Related features will be disabled.`);
    }
  }

  const missing = REQUIRED_VARS.filter(({ name }) => !env[name]);
  if (missing.length > 0) {
    const details = missing.map(({ name, why }) => `  - ${name}: ${why}`).join('\n');
    throw new Error(
      `Missing required environment variables:\n${details}\nSee backend/.env.example for the full list.`,
    );
  }
}

module.exports = { validateEnv, REQUIRED_VARS, OPTIONAL_VARS };
