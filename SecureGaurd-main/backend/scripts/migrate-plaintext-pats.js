'use strict';
/**
 * Migrate legacy PLAINTEXT PATs / Slack webhook URLs to AES-256-GCM at rest.
 *
 * BACKGROUND (SEC-04)
 * --------------------
 * backend/utils/cryptoUtils.js encrypts PATs at rest, but decrypt() still
 * passes through values that are not in the 3-part iv:tag:ciphertext shape
 * (cryptoUtils.js:36-42) so PATs stored before encryption was introduced
 * keep working as plaintext. That passthrough is a migration gap, not a
 * live leak — but every plaintext PAT in the database stays readable to
 * anyone with DB read access until this script runs.
 *
 * WHY THIS SCRIPT EXISTS NEXT TO scripts/reencrypt-pat-keys.js
 * ------------------------------------------------------------
 * reencrypt-pat-keys.js already encrypts plaintext values (its step 3),
 * but it ALSO requires the OLD JWT_SECRET (legacy key SHA256(JWT_SECRET))
 * just to start, because it re-encrypts legacy-key ciphertext too. This
 * script does the plaintext-only migration and needs only ENCRYPTION_KEY
 * + DATABASE_URL — no old JWT secret. Use this script when the only gap
 * is plaintext values; use reencrypt-pat-keys.js when legacy-key
 * ciphertext also needs moving.
 *
 * WHAT IT READS / WRITES
 * -----------------------
 *   - User.githubToken, User.gitlabToken (GitHub/GitLab PATs)
 *   - AlertSetting.slackWebhookUrl (Slack webhook URLs)
 * For each non-empty value it classifies it as:
 *   - encrypted   — 3-part shape AND decrypts under the current
 *                    ENCRYPTION_KEY (already migrated, skipped);
 *   - plaintext   — not in 3-part shape (pre-encryption storage);
 *                    encrypted with cryptoUtils.encrypt() and updated;
 *   - corrupt     — 3-part shape but GCM authentication fails
 *                    (wrong key / tampered); left untouched and reported
 *                    (operator must ask the user to reconnect).
 *
 * USAGE (run from SecureGaurd-main/backend, with backend/.env present)
 * ---------------------------------------------------------------------
 *   node scripts/migrate-plaintext-pats.js --self-test
 *       # offline self-test, no DB, no .env needed (generates a throwaway
 *       # ENCRYPTION_KEY in-process); exit 0 = all assertions pass.
 *   node scripts/migrate-plaintext-pats.js --dry-run
 *       # report only, no writes. DEFAULT when neither flag is given.
 *   node scripts/migrate-plaintext-pats.js --apply
 *       # perform the migration (encrypt plaintext values in place).
 *
 * REQUIRED ENVIRONMENT (from backend/.env via prismaClient.js)
 *   DATABASE_URL    — Postgres connection string
 *   ENCRYPTION_KEY  — the CURRENT 64-hex-char key (must match the key the
 *                     production backend runs with, or already-encrypted
 *                     values will be misclassified as corrupt)
 *
 * SAFETY
 * ------
 * - Dry-run first, and take a database backup before --apply.
 * - The script never prints a token, webhook URL, or key — only row ids
 *   and counts. Run it once; plaintext count should be 0 on a re-run.
 * - NOT executed as part of any deploy. After a successful run, the
 *   plaintext passthrough in cryptoUtils.js:36-42 can be removed in a
 *   follow-up change (separate decision — do not remove it in this run).
 */

const DRY_RUN = !process.argv.includes('--apply');
const SELF_TEST = process.argv.includes('--self-test');

// cryptoUtils is required lazily: it throws at require time unless
// ENCRYPTION_KEY is a valid 64-hex-char key, and --self-test must set a
// throwaway key BEFORE requiring it. Never require it at module top.
let cryptoUtils = null;
function getCryptoUtils() {
  if (!cryptoUtils) cryptoUtils = require('../utils/cryptoUtils');
  return cryptoUtils;
}

/** Classify one stored value without ever logging it. */
function classify(value) {
  if (!value) return 'empty';
  const parts = value.split(':');
  if (parts.length !== 3) return 'plaintext';
  try {
    getCryptoUtils().decrypt(value);
    return 'encrypted';
  } catch {
    return 'corrupt';
  }
}

function selfTest() {
  // Throwaway key, generated in-process, never printed, never persisted.
  const crypto = require('crypto');
  process.env.ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');
  const { encrypt, decrypt } = getCryptoUtils();

  const results = [];
  const check = (name, cond) => {
    results.push({ name, pass: !!cond });
    console.log(`  ${cond ? 'PASS' : 'FAIL'} ${name}`);
  };

  // 1. Round-trip: encrypt -> decrypt returns the original.
  const sample = 'ghp_plaintext-pat-for-self-test-only';
  check('encrypt/decrypt round-trip', decrypt(encrypt(sample)) === sample);
  // 2. Encrypted shape is 3-part iv:tag:ciphertext.
  check('encrypted value has 3-part shape', encrypt(sample).split(':').length === 3);
  // 3. Plaintext values are classified as plaintext (incl. values that
  //    themselves contain ':' but are not 3-part).
  check('legacy plaintext classified plaintext', classify('ghp_legacyplaintext') === 'plaintext');
  check('colon-containing plaintext classified plaintext', classify('https://hooks.slack.com/services/T00/B00/xxx') === 'plaintext');
  // 4. A value encrypted under the current key is classified encrypted.
  check('current-key ciphertext classified encrypted', classify(encrypt(sample)) === 'encrypted');
  // 5. A 3-part value that fails GCM auth is classified corrupt, never
  //    passed through as if it were plaintext.
  const parts = encrypt(sample).split(':');
  parts[2] = '00'.repeat(16);
  check('tampered ciphertext classified corrupt', classify(parts.join(':')) === 'corrupt');
  // 6. Empty values are skipped, not encrypted.
  check('empty value classified empty', classify('') === 'empty' && classify(null) === 'empty');

  const failed = results.filter((r) => !r.pass).length;
  console.log(`SELF-TEST: ${results.length - failed}/${results.length} passed`);
  process.exit(failed === 0 ? 0 : 1);
}

async function main() {
  // Fail fast on a missing/malformed key before touching the database.
  getCryptoUtils();
  const { encrypt } = getCryptoUtils();
  // prismaClient reads backend/.env (DATABASE_URL) at require time.
  const prisma = require('../prismaClient');

  console.log(`migrate-plaintext-pats: ${DRY_RUN ? 'DRY RUN (no writes)' : 'LIVE RUN (--apply)'}`);

  const targets = [
    {
      label: 'User.githubToken',
      list: () => prisma.user.findMany({ where: { githubToken: { not: null } }, select: { id: true, githubToken: true } }),
      get: (row) => row.githubToken,
      save: (row, value) => prisma.user.update({ where: { id: row.id }, data: { githubToken: value } }),
    },
    {
      label: 'User.gitlabToken',
      list: () => prisma.user.findMany({ where: { gitlabToken: { not: null } }, select: { id: true, gitlabToken: true } }),
      get: (row) => row.gitlabToken,
      save: (row, value) => prisma.user.update({ where: { id: row.id }, data: { gitlabToken: value } }),
    },
    {
      label: 'AlertSetting.slackWebhookUrl',
      list: () => prisma.alertSetting.findMany({ where: { slackWebhookUrl: { not: null } }, select: { id: true, slackWebhookUrl: true } }),
      get: (row) => row.slackWebhookUrl,
      save: (row, value) => prisma.alertSetting.update({ where: { id: row.id }, data: { slackWebhookUrl: value } }),
    },
  ];

  const totals = { examined: 0, encrypted: 0, plaintext: 0, corrupt: 0 };
  const corrupt = [];

  for (const target of targets) {
    const rows = await target.list();
    const counts = { examined: 0, encrypted: 0, plaintext: 0, corrupt: 0 };
    for (const row of rows) {
      const value = target.get(row);
      if (!value) continue;
      counts.examined++;
      const kind = classify(value);
      if (kind === 'encrypted') { counts.encrypted++; continue; }
      if (kind === 'plaintext') {
        counts.plaintext++;
        if (!DRY_RUN) await target.save(row, encrypt(value));
        continue;
      }
      counts.corrupt++;
      corrupt.push(`${target.label} id=${row.id}`);
    }
    for (const key of Object.keys(counts)) totals[key] += counts[key];
    console.log(`  ${target.label}: examined=${counts.examined} already-encrypted=${counts.encrypted} plaintext-encrypted=${counts.plaintext} corrupt=${counts.corrupt}`);
  }

  console.log(`TOTAL: examined=${totals.examined} already-encrypted=${totals.encrypted} plaintext-encrypted=${totals.plaintext} corrupt=${totals.corrupt}`);
  if (corrupt.length > 0) {
    console.log('CORRUPT (left untouched — user must reconnect):');
    for (const entry of corrupt) console.log(`  - ${entry}`);
  }
  if (DRY_RUN && totals.plaintext > 0) {
    console.log('Dry run only — re-run with --apply to encrypt the plaintext values.');
  }
  if (!DRY_RUN && totals.plaintext === 0 && totals.corrupt === 0) {
    console.log('No plaintext values remain. Verify with a re-run: plaintext-encrypted should stay 0.');
  }
}

if (SELF_TEST) {
  selfTest();
} else {
  main()
    .catch((err) => { console.error('migrate-plaintext-pats: failed:', err.message); process.exit(1); })
    .finally(() => {
      // prisma is only required inside main(); disconnect if it loaded.
      try { require('../prismaClient').$disconnect(); } catch { /* self-test / early-fail path: nothing to disconnect */ }
    });
}
