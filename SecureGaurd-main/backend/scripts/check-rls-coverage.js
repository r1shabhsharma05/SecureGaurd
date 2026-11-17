// Static RLS coverage check (SEC-31). Fails if any code path still reads
// or writes an RLS table through the bare Prisma client instead of a
// context transaction (withRequestOrgContext / withOrgContext /
// withUserContext / withOrgOnlyContext / setOrgContext inside an existing
// $transaction). Run: node scripts/check-rls-coverage.js
// Exit 0 = no bare tenant-table access found; exit 1 = violations listed.
// Known-good exceptions (kept in ALLOW): prisma.$transaction itself
// (resolver + context transactions run on it by design) and the no-RLS
// models (User, WebhookDelivery, AnalyticsEvent, ContactMessage, webhook
// event tables) — those are NOT in TENANT_MODELS below.
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const DIRS = ['routes', 'services', 'utils', 'middleware'];
const TENANT_MODELS = [
  'organization', 'organizationMembership', 'organizationInvitation',
  'auditLog', 'subscription', 'alertSetting', 'alertLog', 'customRule',
  'repository', 'scan', 'complianceReport', 'sbom', 'vulnerability',
];
const PATTERN = new RegExp(`\\bprisma\\.(${TENANT_MODELS.join('|')})\\s*\\.`, 'g');

let violations = [];
let filesChecked = 0;

for (const dir of DIRS) {
  const full = path.join(ROOT, dir);
  if (!fs.existsSync(full)) continue;
  for (const file of fs.readdirSync(full).filter((f) => f.endsWith('.js'))) {
    filesChecked++;
    const rel = `${dir}/${file}`;
    const lines = fs.readFileSync(path.join(full, file), 'utf8').split('\n');
    lines.forEach((line, i) => {
      const stripped = line.replace(/\/\/.*$/, '');
      const m = stripped.match(PATTERN);
      if (m) violations.push(`${rel}:${i + 1}: ${m.join(', ')} — ${stripped.trim()}`);
    });
  }
}

if (violations.length > 0) {
  console.error(`RLS coverage check FAILED: ${violations.length} bare tenant-table access(es) via prisma.*`);
  violations.forEach((v) => console.error(`  ${v}`));
  process.exit(1);
}
console.log(`RLS coverage check passed: ${filesChecked} files, no bare prisma.<tenant-table> access.`);
