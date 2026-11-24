'use strict';

// Day 6 — shared input validation (SEC-18 / SEC-22). Before this, every
// route validated ad-hoc (or not at all); a missed check on a new route was
// a live bug. Standardise on zod here: schemas are the single source of
// truth, and validateBody / validateQuery enforce them at the trust
// boundary. The auth routes are wired to the same exports (register,
// login, email-only, reset-password, delete-account schemas below).
// Pure zod: no DB, no network, no secrets. Day 6 wired the auth routes
// (register, login, resend-verification, forgot/reset-password, delete
// account) to the same exports — see the route schemas below.
const { z } = require('zod');

// Common field schemas -------------------------------------------------------

// Email: trimmed, lower-cased (lookup keys are stored lower-case), RFC-ish
// shape via zod, 254-char cap (RFC 5321). Never log the value.
const zEmail = z
  .string({ error: 'A valid email address is required.' })
  .trim()
  .toLowerCase()
  .max(254, 'Email address is too long.')
  .email('A valid email address is required.');

// Password: 8–128 chars. No complexity rule here — the auth routes own
// policy (and must not be weakened to make a test pass); this is the floor.
const zPassword = z
  .string({ error: 'Password is required.' })
  .min(8, 'Password must be at least 8 characters.')
  .max(128, 'Password must be at most 128 characters.');

// Integer id from a JSON body / query string. Coerces "12" -> 12, but
// rejects "12abc" (Number("12abc") is NaN — unlike parseInt, which would
// silently coerce it to 12; that parseInt coercion is Day 1 finding S3's
// cousin). Rejects 0, negatives, fractions and non-numbers.
const zIntId = z.coerce
  .number({ error: 'A valid integer id is required.' })
  .int('Id must be an integer.')
  .positive('Id must be a positive integer.');
// Strict id from a path or query param (Day 11, SEC-18 / SEC-22).
// parseInt("12abc") silently yields 12 and Number("12.5") yields 12.5 —
// a malformed id then resolves to a real record (or a Prisma type error)
// instead of a 400. Accept only a digits-only string that is a safe
// positive integer; anything else is null and the caller answers its
// existing 400. Leading zeros still parse ("007" -> 7), as parseInt did.
function parseIdParam(value) {
  if (typeof value !== 'string' || !/^\d+$/.test(value)) return null;
  const n = Number(value);
  return Number.isSafeInteger(n) && n > 0 ? n : null;
}

// Bounded string helper for free-text fields: trims, enforces length.
function zString(min, max) {
  return z
    .string()
    .trim()
    .min(min, `Must be at least ${min} characters.`)
    .max(max, `Must be at most ${max} characters.`);
}

// Pagination for list/export query strings: ?limit= (default 1000, clamped
// to 5000 — matching the export-feedback route's existing clamp, not a
// rejection) and ?page= (default 1). Coerces numeric strings; rejects the rest.
const zPagination = z.object({
  limit: z.coerce.number().int().min(1).transform((v) => Math.min(v, 5000)).default(1000),
  page: z.coerce.number().int().min(1).default(1),
});

// Route schemas --------------------------------------------------------------

// Contact form (POST /api/contact). Bounds mirror utils/publicSite.js
// validateContactInput exactly — validateBody is a shape guard in front of
// it, not a replacement: the honeypot field still goes through
// validateContactInput in the route, which answers a filled honeypot with
// fake success so a bot cannot tell it was caught.
const contactSchema = z.object({
  name: zString(2, 100),
  email: zEmail,
  subject: zString(0, 140).optional().default(''),
  message: zString(10, 2000),
  // Honeypot: present in the form, must stay empty. Allowed through here
  // so validateContactInput can answer it with fake success.
  company: z.string().optional(),
});

// Scan trigger (POST /api/scans/trigger): the only body field is the repo id.
const scanTriggerSchema = z.object({
  repositoryId: zIntId,
});

// Auth (Day 6, SEC-18 / SEC-22): the shared library now covers the auth
// routes too. Each schema mirrors the inline check it replaces — same
// 400, same boundary — so wiring it in changes no accepted input, only
// where the rejection happens (at the trust boundary, before any DB or
// mail call). verify-email is deliberately NOT here: its token comes
// from the query string OR the body, and the handler's presence check
// already covers both.

// Register (POST /api/auth/register). firstName/lastName are trimmed
// non-empty strings with no upper cap — the old code had none, and a cap
// would newly reject long names. Password takes the 8–128 floor.
const registerSchema = z.object({
  firstName: z.string().trim().min(1, 'First name is required.'),
  lastName: z.string().trim().min(1, 'Last name is required.'),
  email: zEmail,
  password: zPassword,
});

// Login (POST /api/auth/login). Password is a non-empty string, NOT
// zPassword: the old code only required presence, and a length floor here
// would answer a short password with a different message than "Invalid
// credentials" — same 400, but a behaviour change for no gain.
const loginSchema = z.object({
  email: zEmail,
  password: z.string().min(1, 'Password is required.'),
});

// Single-email routes (POST /api/auth/resend-verification,
// POST /api/auth/forgot-password). Handlers keep their anti-enumeration
// behaviour; this only proves the shape.
const emailOnlySchema = z.object({
  email: zEmail,
});

// Reset password (POST /api/auth/reset-password). Token is an opaque
// non-empty string; newPassword takes the same 8–128 floor as register
// and change-password.
const resetPasswordSchema = z.object({
  token: z.string().min(1, 'Reset token is required.'),
  newPassword: zPassword,
});

// Delete account (DELETE /api/auth/account). Confirmation must be the
// literal string DELETE — a mistyped confirmation is a 400, as before.
const deleteAccountSchema = z.object({
  password: z.string().min(1, 'Current password is required.'),
  confirmation: z.literal('DELETE'),
});

// Authenticated mutating routes (SEC-18 / SEC-22 completion). Every schema
// below is a looseObject: the declared fields are type-checked at the
// boundary, unknown fields pass through untouched, and each handler keeps
// its existing business checks (enums with role logic, URL formats, date
// math) as the second layer. Bounds mirror the inline checks they front —
// wiring these in changes no accepted input, only where wrong-shaped
// input is rejected. Optional fields are nullish where the handler
// already tolerates null.
const vulnStatusSchema = z.looseObject({
  status: z.enum(['open', 'fixed', 'ignored', 'false_positive']),
});

const vulnLabelSchema = z.looseObject({
  label: z.enum(['real', 'false_positive']),
});

// Billing (POST /api/billing/create-subscription). getPlanConfig stays
// the authority on which plan keys are purchasable.
const createSubscriptionSchema = z.looseObject({
  plan: z.string().min(1, 'Plan is required.'),
});

// API keys (POST /api/api-keys). The handler keeps the name regex, scope
// filtering and future-date check.
const createApiKeySchema = z.looseObject({
  name: z.string().min(1, 'Name is required.'),
  scopes: z.array(z.string()).optional(),
  expiresAt: z.string().nullish(),
});

// Alerts (PUT /api/alerts/settings, POST /api/alerts/test).
const alertSettingsSchema = z.looseObject({
  slackWebhookUrl: z.string().nullish(),
  slackEnabled: z.boolean().optional(),
  emailEnabled: z.boolean().optional(),
  notifyOnScanComplete: z.boolean().optional(),
  notifyOnNewCritical: z.boolean().optional(),
});

const alertTestSchema = z.looseObject({
  channel: z.enum(['slack', 'email']),
});

// Compliance (POST /api/compliance/generate). The handler keeps framework
// normalisation and date-range parsing.
const complianceGenerateSchema = z.looseObject({
  repositoryId: zIntId,
  framework: z.string().nullish(),
  dateRangeOption: z.string().nullish(),
  customFromDate: z.string().nullish(),
  customToDate: z.string().nullish(),
  reportName: z.string().nullish(),
});

// Repositories (POST /api/repos). The handler keeps the name/URL format
// checks and the reachability probe.
const createRepoSchema = z.looseObject({
  name: z.string().min(1, 'name and url are required'),
  url: z.string().min(1, 'name and url are required'),
  fullName: z.string().nullish(),
  platform: z.string().nullish(),
  language: z.string().nullish(),
});

// Organizations (create / rename share the name rule; member role;
// transfer ownership; invite).
const orgNameSchema = z.looseObject({
  name: z.string().trim().min(2, 'Organization name must be at least 2 characters'),
});

const memberRoleSchema = z.looseObject({
  role: z.enum(['OWNER', 'ADMIN', 'DEVELOPER', 'AUDITOR']),
});

const transferOwnershipSchema = z.looseObject({
  memberId: zIntId,
});

const inviteMemberSchema = z.looseObject({
  email: zEmail,
  role: z.string().nullish(),
});

// Custom rules (create / patch / test / test-scan). YAML parsing and the
// 200 KB code cap stay in the handlers; these prove the shape.
const customRuleCreateSchema = z.looseObject({
  yaml: z.string().min(1, 'yaml is required.'),
});

const customRulePatchSchema = z.looseObject({
  yaml: z.string().nullish(),
  enabled: z.boolean().optional(),
});

const customRuleTestSchema = z.looseObject({
  code: z.string().min(1, 'code must be a non-empty string under 200 KB').max(200000, 'code must be a non-empty string under 200 KB'),
  filePath: z.string().nullish(),
});

const customRuleTestScanSchema = z.looseObject({
  scanId: zIntId,
});

// Integrations (POST /api/integration/tokens, POST /api/integration/pr-bot).
const integrationTokensSchema = z.looseObject({
  githubToken: z.string().nullish(),
  gitlabToken: z.string().nullish(),
});

const prBotSchema = z.looseObject({
  repositoryId: zIntId,
  commitSha: z.string().regex(/^[0-9a-f]{40}$/i, 'commitSha must be a 40-character hex SHA'),
  prNumber: zIntId,
});

// ML ranker (POST /api/ml/rank). The handler keeps its integer filter.
const mlRankSchema = z.looseObject({
  vulnerabilityIds: z.array(z.unknown()).min(1, 'vulnerabilityIds must be a non-empty array (max 100)').max(100, 'vulnerabilityIds must be a non-empty array (max 100)'),
});

// API-spec scan (POST /api/scans/api-spec). The handler keeps the
// exactly-one-of rule and the byte-size check.
const apiSpecSchema = z.looseObject({
  specUrl: z.string().max(2048, 'Invalid specUrl.').nullish(),
  specContent: z.string().min(1, 'specContent must be a non-empty string under 2 MB.').nullish(),
  fileName: z.string().nullish(),
});

// Profile update (PATCH /api/auth/me). The handler keeps its name regex.
const patchMeSchema = z.looseObject({
  firstName: z.string().nullish(),
  lastName: z.string().nullish(),
});

// Public analytics (POST /api/analytics/events). The handler keeps the
// event allowlist and props sanitiser.
const analyticsEventSchema = z.looseObject({
  event: z.string().min(1, 'Unknown analytics event.'),
  path: z.string().min(1, 'A valid page path is required.').max(500, 'A valid page path is required.'),
  sessionId: z.string().nullish(),
  props: z.unknown().optional(),
});

// Middleware -----------------------------------------------------------------

// Formats zod issues into the API's existing { message } error shape, plus
// a per-field detail array for clients that want it. Never echoes secrets:
// only field names and validation messages are returned, never values.
function formatIssues(issues) {
  const errors = (issues || []).map((issue) => ({
    field: Array.isArray(issue.path) ? issue.path.join('.') : String(issue.path || ''),
    message: issue.message || 'Invalid value.',
  }));
  return {
    message: errors[0] ? errors[0].message : 'Invalid request.',
    errors,
  };
}

function validateWith(schema, source) {
  return (req, res, next) => {
    const result = schema.safeParse(req[source] || {});
    if (!result.success) {
      return res.status(400).json(formatIssues(result.error.issues));
    }
    // Parsed (coerced / defaulted / trimmed) data replaces the raw input,
    // so handlers downstream only ever see validated values.
    // shortcut: Express 5 defines req.query as a getter-only property, so
    // assigning req.query throws (TypeError) — shadow it with an own data
    // property instead. When to upgrade: if a future Express makes req.query
    // writable again, the else-branch covers both.
    if (source === 'query') {
      Object.defineProperty(req, 'query', {
        value: result.data,
        writable: true,
        configurable: true,
        enumerable: true,
      });
    } else {
      req[source] = result.data;
    }
    return next();
  };
}

// Validate req.body against a zod object schema.
function validateBody(schema) {
  return validateWith(schema, 'body');
}

// Validate req.query against a zod object schema.
function validateQuery(schema) {
  return validateWith(schema, 'query');
}

module.exports = {
  z,
  zEmail,
  zPassword,
  zIntId,
  parseIdParam,
  zString,
  zPagination,
  contactSchema,
  scanTriggerSchema,
  registerSchema,
  loginSchema,
  emailOnlySchema,
  resetPasswordSchema,
  deleteAccountSchema,
  vulnStatusSchema,
  vulnLabelSchema,
  createSubscriptionSchema,
  createApiKeySchema,
  alertSettingsSchema,
  alertTestSchema,
  complianceGenerateSchema,
  createRepoSchema,
  orgNameSchema,
  memberRoleSchema,
  transferOwnershipSchema,
  inviteMemberSchema,
  customRuleCreateSchema,
  customRulePatchSchema,
  customRuleTestSchema,
  customRuleTestScanSchema,
  integrationTokensSchema,
  prBotSchema,
  mlRankSchema,
  apiSpecSchema,
  patchMeSchema,
  analyticsEventSchema,
  validateBody,
  validateQuery,
};
