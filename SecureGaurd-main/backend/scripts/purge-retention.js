// Retention purge (SEC-33) — deletes expired rows from the NO-RLS tables
// only. Dry-run by default; --apply deletes. Prints per-table counts;
// exit 0 on success, 1 on error.
//
// Covered here (DATA_RETENTION.md §1 — these tables have no RLS, so the
// app role can purge them before AND after the RLS migration lands):
//   AnalyticsEvent      createdAt   < 90 days
//   ContactMessage      createdAt   < 2 years ("resolved + 90d, max 2y";
//                                      no resolved marker exists, so the
//                                      2-year max is the bound)
//   StripeWebhookEvent  processedAt < 90 days
//   RazorpayWebhookEvent processedAt < 90 days
//   WebhookDelivery     receivedAt  < 90 days
//
// NOT purged here — deliberate, owner-role SQL only (DATA_RETENTION.md §3):
// - AuditLog: the append-only trigger (migration §6) blocks direct DELETE
//   while the org exists — the §3 AuditLog DELETE fails once the migration
//   is applied. Needs a decision: amend the trigger with a retention
//   carve-out, or accept indefinite AuditLog retention.
// - AlertLog / OrganizationInvitation: RLS tables. The app role cannot
//   enumerate orgs to purge per-org, and a context-free delete removes
//   zero rows (fail closed).
// - Scan / Vulnerability / Sbom / ComplianceReport / Repository /
//   CustomRule / AlertSetting / Subscription: org-lifetime data (§1),
//   deleted with the org — never age-purged.
//
// Scheduling: this backend has no in-process scheduler. Run monthly via a
// Render Cron Job (`node scripts/purge-retention.js --apply`) or the
// equivalent, and record the run in DATA_RETENTION.md §4.
// Run: node scripts/purge-retention.js [--apply]
'use strict';

const prisma = require('../prismaClient');

const RETENTION = [
  { model: 'analyticsEvent', label: 'AnalyticsEvent', field: 'createdAt', days: 90 },
  { model: 'contactMessage', label: 'ContactMessage', field: 'createdAt', days: 730 },
  { model: 'stripeWebhookEvent', label: 'StripeWebhookEvent', field: 'processedAt', days: 90 },
  { model: 'razorpayWebhookEvent', label: 'RazorpayWebhookEvent', field: 'processedAt', days: 90 },
  { model: 'webhookDelivery', label: 'WebhookDelivery', field: 'receivedAt', days: 90 },
];

function cutoff(days, now = new Date()) {
  return new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
}

// Pure against `db` (the Prisma client or a stub with the same methods),
// so tests can assert the windows without a database.
async function purgeRetention(db, { apply = false, now = new Date() } = {}) {
  const results = [];
  for (const t of RETENTION) {
    const where = { [t.field]: { lt: cutoff(t.days, now) } };
    const count = await db[t.model].count({ where });
    let deleted = 0;
    if (apply && count > 0) {
      ({ count: deleted } = await db[t.model].deleteMany({ where }));
    }
    results.push({ label: t.label, field: t.field, days: t.days, expired: count, deleted });
  }
  return results;
}

async function main() {
  const apply = process.argv.includes('--apply');
  try {
    const results = await purgeRetention(prisma, { apply });
    for (const r of results) {
      console.log(`${r.label}: ${r.expired} expired (>${r.days}d)${apply ? `, deleted ${r.deleted}` : ' — dry run, nothing deleted'}`);
    }
    if (!apply) console.log('Dry run. Re-run with --apply to delete.');
  } catch (err) {
    console.error('Purge failed:', err.message);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

if (require.main === module) main();

module.exports = { purgeRetention, RETENTION, cutoff };
