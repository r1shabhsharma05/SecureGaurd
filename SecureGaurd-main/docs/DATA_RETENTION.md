# Data retention — SecureGuard

**Status:** rules defined 2026-11-16 (Day 3, Unit G, SEC-33). The rules below
are policy, not yet automation: **no scheduled purge job exists** and no
purge has ever run. Until the purge job lands, retention is enforced by the
manual SQL in §3, run monthly by the owner. Do not report retention as
enforced until a purge run is recorded in §4.

Related: `BACKUP_AND_RESTORE.md` (backups are the other half of retention —
a row deleted from the live database still exists in backup archives until
they age out, §2 below) and migration `20261116_rls_policies` (AuditLog
append-only trigger; RLS scoping for every tenant table).

## 1. Rules

| Data | Retain | Then | Basis |
|---|---|---|---|
| `AuditLog` | 365 days minimum | Export to cold archive, then delete rows older than 365 days | Audit trail must survive an incident review cycle; append-only (trigger) while live — never edited, never deleted except by org deletion cascade |
| `AnalyticsEvent` | 90 days | Delete | Product analytics; stores no IP and no user identity by design, so 90 days is enough for trend windows |
| `ContactMessage` | Until resolved + 90 days, max 2 years | Delete | Support correspondence; a row exists only after Brevo accepted the email |
| `AlertLog` | 180 days | Delete | Delivery receipts; 6 months covers billing-dispute and missed-alert investigations |
| `StripeWebhookEvent`, `RazorpayWebhookEvent`, `WebhookDelivery` | 90 days | Delete | Idempotency window is days; 90 days covers duplicate-delivery and dispute forensics |
| `Scan`, `Vulnerability`, `Sbom`, `ComplianceReport`, `Repository`, `CustomRule`, `AlertSetting`, `Subscription` | While the organization exists | Deleted with the organization (`ON DELETE CASCADE`) | Product data; no separate retention — the org is the unit of deletion |
| `User`, `OrganizationMembership`, `OrganizationInvitation` | While the account / membership exists | Account deletion follows `backend/utils/accountDeletion.js` (password + typed `DELETE`, org-asset handoff to a remaining OWNER/ADMIN); expired invitations may be deleted once `status` is `EXPIRED`/`REVOKED` and `expiresAt` is past | Auth data; invitations carry a single-use token hash — dead invitations are not kept |
| Auth tokens in `User` | `passwordResetToken` 1 h; `emailVerifyToken` 24 h; refresh tokens rotate with reuse detection | Expired values are inert (checked against expiry on use) and cleared on next login/password reset | Already enforced in `backend/routes/auth.js`; no purge needed |
| Backup archives (`backup-db.sh`) | 30 days | Script prunes older archives | The script's own rule; see `BACKUP_AND_RESTORE.md` §2 |

## 2. What retention does NOT do

- **Backups keep deleted data for up to 30 days.** Deleting a row (or an
  org) removes it from the live database immediately, but the newest backup
  archive still contains it until that archive ages out. Tell a user who
  asks for deletion that propagation to backups completes within 30 days.
- **The append-only AuditLog trigger does not stop org deletion.** Deleting
  an organization cascade-deletes its `AuditLog` rows — that is the
  intended SEC-12 account/org deletion path, not tampering. The trigger
  blocks direct `UPDATE`/`DELETE` of log rows while the org exists.
- **Retention is per organization, not per user.** A user in two orgs has
  their rows governed by each org's lifetime, not by their account alone.

## 3. Purge SQL (manual, monthly, until automated)

Run as the table owner / `postgres` superuser in the SQL Editor — **not**
as the least-privilege app role: a purge run as the app role with no RLS
session variables set deletes zero rows (fail closed), and with variables
set it can only delete one org's rows. Purges are cross-tenant by nature
and belong to the owner role. Run inside one transaction and record the
deleted counts.

```sql
BEGIN;
-- AuditLog: archive first (COPY to a file / export), then delete.
DELETE FROM "AuditLog" WHERE "createdAt" < now() - interval '365 days';
DELETE FROM "AnalyticsEvent" WHERE "createdAt" < now() - interval '90 days';
DELETE FROM "AlertLog" WHERE "createdAt" < now() - interval '180 days';
DELETE FROM "StripeWebhookEvent" WHERE "processedAt" < now() - interval '90 days';
DELETE FROM "RazorpayWebhookEvent" WHERE "processedAt" < now() - interval '90 days';
DELETE FROM "WebhookDelivery" WHERE "receivedAt" < now() - interval '90 days';
DELETE FROM "ContactMessage" WHERE "createdAt" < now() - interval '2 years';
-- Dead invitations only: PENDING invitations are never purged (acceptance
-- flow needs them until expiry, and expiry itself flips them to EXPIRED).
DELETE FROM "OrganizationInvitation"
  WHERE status IN ('EXPIRED', 'REVOKED') AND "expiresAt" < now() - interval '30 days';
COMMIT;
```

Do not purge `Scan` / `Vulnerability` / `Sbom` / `ComplianceReport` /
`Repository` by age — they are org-lifetime data (§1) and a scan from a
year ago is still the org's evidence. If storage ever forces an age-based
purge of scans, that is a product decision, not an ops cleanup — get
Rishabh's word first and record it here.

## 4. Purge log

| Date | Ran by | Result |
|---|---|---|
| — | — | No purge has ever run. First run due with the first monthly ops pass after the Day 7 gate. |
