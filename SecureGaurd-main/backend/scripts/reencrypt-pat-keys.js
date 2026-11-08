'use strict';
/**
 * One-off re-encryption of stored PATs and Slack webhook URLs.
 *
 * BACKGROUND
 * ----------
 * Before the security-audit fix, utils/cryptoUtils.js derived the AES-256-GCM
 * key as SHA256(JWT_SECRET) whenever ENCRYPTION_KEY was unset (and as a
 * single SHA-256 of a passphrase otherwise). The fix makes ENCRYPTION_KEY a
 * required 64-hex-char (256-bit) key and deletes both fallbacks, so values
 * encrypted under the legacy key can no longer be decrypted by the app.
 * This script moves them to the new key.
 *
 * WHAT IT READS / WRITES
 * -----------------------
 *   - User.githubToken, User.gitlabToken (GitHub/GitLab PATs)
 *   - AlertSetting.slackWebhookUrl (Slack webhook URLs)
 * For each non-empty value it tries, in order:
 *   1. decrypt with the NEW key (ENCRYPTION_KEY) — already migrated, skip;
 *   2. decrypt with the LEGACY key SHA256(JWT_SECRET) — re-encrypt with the
 *      new key and update the row;
 *   3. value is not in iv:tag:ciphertext shape — it is a legacy PLAINTEXT
 *      value, encrypt it under the new key and update the row;
 *   4. neither key decrypts it — leave the row untouched and report it as
 *      UNDECRYPTABLE (operator must ask the user to reconnect).
 *
 * USAGE (run from SecureGaurd-main/backend, with backend/.env present)
 * ---------------------------------------------------------------------
 *   node scripts/reencrypt-pat-keys.js --dry-run   # report only, no writes
 *   node scripts/reencrypt-pat-keys.js             # perform the migration
 *
 * REQUIRED ENVIRONMENT (from backend/.env via prismaClient.js)
 *   DATABASE_URL     — Postgres connection string
 *   JWT_SECRET       — the OLD secret the legacy key was derived from
 *                      (SHA256(JWT_SECRET)); must be the value in use when
 *                      the stored values were encrypted
 *   ENCRYPTION_KEY   — the NEW 64-hex-char key (must already be set in the
 *                      deployment environment before the fixed backend runs)
 *
 * SAFETY
 * ------
 * - Dry-run first, and take a database backup before the real run.
 * - The script never prints a token, webhook URL, or key — only row ids
 *   and counts. Run it once, then delete or archive it; it needs the old
 *   JWT_SECRET, which must be rotated afterwards (it is already exposed
 *   in pushed git history — see the audit report).
 * - NOT executed as part of any deploy. Do not run against production
 *   until ENCRYPTION_KEY is set in the production environment.
 */

const crypto = require('crypto');
const prisma = require('../prismaClient');

const ALGORITHM = 'aes-256-gcm';
const DRY_RUN = process.argv.includes('--dry-run');

function fail(message) {
  console.error(`reencrypt-pat-keys: ${message}`);
  process.exit(1);
}

function newKey() {
  const raw = process.env.ENCRYPTION_KEY;
  if (!raw || !/^[0-9a-fA-F]{64}$/.test(raw)) {
    fail('ENCRYPTION_KEY must be set to a 64-hex-char (256-bit) key.');
  }
  return Buffer.from(raw, 'hex');
}

function legacyKey() {
  if (!process.env.JWT_SECRET) fail('JWT_SECRET must be set (legacy key is SHA256(JWT_SECRET)).');
  return crypto.createHash('sha256').update(process.env.JWT_SECRET).digest();
}

function encryptWith(key, text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return `${iv.toString('hex')}:${cipher.getAuthTag().toString('hex')}:${encrypted}`;
}

function tryDecryptWith(key, value) {
  const parts = value.split(':');
  if (parts.length !== 3) return { ok: false, reason: 'not-encrypted-shape' };
  try {
    const decipher = crypto.createDecipheriv(ALGORITHM, key, Buffer.from(parts[0], 'hex'));
    decipher.setAuthTag(Buffer.from(parts[1], 'hex'));
    let out = decipher.update(parts[2], 'hex', 'utf8');
    out += decipher.final('utf8');
    return { ok: true, plaintext: out };
  } catch {
    return { ok: false, reason: 'decrypt-failed' };
  }
}

async function main() {
  const NEW_KEY = newKey();
  const LEGACY_KEY = legacyKey();
  if (NEW_KEY.equals(LEGACY_KEY)) {
    fail('ENCRYPTION_KEY decodes to the legacy SHA256(JWT_SECRET) key — pick an independent key.');
  }
  console.log(`reencrypt-pat-keys: ${DRY_RUN ? 'DRY RUN (no writes)' : 'LIVE RUN'}`);

  // Each entry: how to list rows, how to read the stored value, how to
  // write the re-encrypted value back. No secret value is ever logged.
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

  const totals = { examined: 0, alreadyNewKey: 0, reencrypted: 0, plaintextEncrypted: 0, undecryptable: 0 };
  const undecryptable = [];

  for (const target of targets) {
    const rows = await target.list();
    const counts = { examined: 0, alreadyNewKey: 0, reencrypted: 0, plaintextEncrypted: 0, undecryptable: 0 };
    for (const row of rows) {
      const value = target.get(row);
      if (!value) continue;
      counts.examined++;
      const withNew = tryDecryptWith(NEW_KEY, value);
      if (withNew.ok) { counts.alreadyNewKey++; continue; }
      const withLegacy = tryDecryptWith(LEGACY_KEY, value);
      if (withLegacy.ok) {
        counts.reencrypted++;
        if (!DRY_RUN) await target.save(row, encryptWith(NEW_KEY, withLegacy.plaintext));
        continue;
      }
      if (withLegacy.reason === 'not-encrypted-shape') {
        // Legacy plaintext value (pre-encryption storage): encrypt it.
        counts.plaintextEncrypted++;
        if (!DRY_RUN) await target.save(row, encryptWith(NEW_KEY, value));
        continue;
      }
      counts.undecryptable++;
      undecryptable.push(`${target.label} id=${row.id}`);
    }
    for (const key of Object.keys(counts)) totals[key] += counts[key];
    console.log(`  ${target.label}: examined=${counts.examined} already-new-key=${counts.alreadyNewKey} re-encrypted=${counts.reencrypted} plaintext-encrypted=${counts.plaintextEncrypted} undecryptable=${counts.undecryptable}`);
  }

  console.log(`TOTAL: examined=${totals.examined} already-new-key=${totals.alreadyNewKey} re-encrypted=${totals.reencrypted} plaintext-encrypted=${totals.plaintextEncrypted} undecryptable=${totals.undecryptable}`);
  if (undecryptable.length > 0) {
    console.log('UNDECRYPTABLE (left untouched — user must reconnect):');
    for (const entry of undecryptable) console.log(`  - ${entry}`);
  }
  if (DRY_RUN && (totals.reencrypted > 0 || totals.plaintextEncrypted > 0)) {
    console.log('Dry run only — re-run without --dry-run to apply the migration.');
  }
}

main()
  .catch((err) => { console.error('reencrypt-pat-keys: failed:', err.message); process.exit(1); })
  .finally(() => prisma.$disconnect());
