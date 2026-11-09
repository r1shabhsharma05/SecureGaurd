const localOrigins = [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'http://localhost:3000',
  'http://127.0.0.1:3000'
];

function getAllowedOrigins(env = process.env) {
  const configuredOrigins = [env.FRONTEND_URL, ...(env.FRONTEND_URLS || '').split(',')]
    .filter(Boolean)
    .map((origin) => origin.trim())
    .filter(Boolean)
    .filter((origin) => {
      try {
        return ['http:', 'https:'].includes(new URL(origin).protocol);
      } catch {
        return false;
      }
    });

  return [...new Set([...localOrigins, ...configuredOrigins])];
}

// Vercel Preview deployments of this project share one shape:
//   secureguard-main-<suffix>-rish0000-dots-projects.vercel.app
// (branch aliases: secureguard-main-git-<branch>-rish0000-dots-projects;
//  per-deployment URLs: secureguard-main-<hash>-rish0000-dots-projects).
// The team slug is part of the pattern on purpose: without it the regex
// would also match another team's production site named e.g.
// secureguard-main-evil.vercel.app (project names are unique per team,
// not globally). Production (secureguard-main.vercel.app) is allowlisted
// via FRONTEND_URL above. Without this, every Preview deployment got a
// 500 "Server error" on all API calls: the CORS callback threw for the
// unlisted origin and Express turned it into a 500 (fixed in server.js
// alongside).
const PREVIEW_ORIGIN_PATTERN = /^https:\/\/secureguard-main-[a-z0-9-]+-rish0000-dots-projects\.vercel\.app$/;

function isAllowedOrigin(origin, env = process.env) {
  if (!origin) return true;
  if (getAllowedOrigins(env).includes(origin)) return true;
  return PREVIEW_ORIGIN_PATTERN.test(origin);
}

module.exports = { getAllowedOrigins, isAllowedOrigin };