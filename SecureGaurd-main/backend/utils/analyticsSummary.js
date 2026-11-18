'use strict';

// Product-activity summary for the Day-9 analytics dashboard (Day 8's
// AnalyticsEvent rows + real product tables). Aggregate counts only —
// no per-user rows, no emails, no IPs leave the server. `db` is the
// Prisma client (or a stub with the same methods in unit tests).
const RANGES = { '7d': 7, '30d': 30, '90d': 90 };

// Real app routes (App.tsx). Anything else in AnalyticsEvent.path is a
// probe, a 404, or a mistyped URL — not a visited page.
const KNOWN_APP_PATHS = [
  '/', '/login', '/signup', '/contact', '/privacy', '/terms', '/onboarding',
  '/verify-email', '/dashboard', '/vulnerabilities', '/scans',
  '/accept-invite', '/reset-password', '/oauth/callback',
];

function parseSummaryRange(raw) {
  if (typeof raw !== 'string') return 30;
  return RANGES[raw] || null;
}

function dayKey(date) {
  return date.toISOString().slice(0, 10);
}

function bucketByDay(rows, from, days) {
  const buckets = new Map();
  for (let i = 0; i < days; i++) {
    const d = new Date(from.getTime() + i * 24 * 60 * 60 * 1000);
    buckets.set(dayKey(d), 0);
  }
  for (const row of rows) {
    const key = dayKey(new Date(row.createdAt));
    if (buckets.has(key)) buckets.set(key, buckets.get(key) + 1);
  }
  return [...buckets.entries()].map(([date, count]) => ({ date, count }));
}

async function buildAnalyticsSummary(db, { from, to, days }) {
  const where = { createdAt: { gte: from, lte: to } };
  const [signups, scansCompleted, fixesApplied, pageViews, contactMessages, eventsByType, topPaths, signupRows, scanRows] =
    await Promise.all([
      db.user.count({ where }),
      db.scan.count({ where: { completedAt: { gte: from, lte: to }, status: 'completed' } }),
      db.vulnerability.count({
        where: { aiFixApplied: true, scan: { completedAt: { gte: from, lte: to } } },
      }),
      db.analyticsEvent.count({ where: { ...where, event: 'page_view' } }),
      db.contactMessage.count({ where }),
      db.analyticsEvent.groupBy({ by: ['event'], where, _count: { event: true } }),
      db.analyticsEvent.groupBy({
        by: ['path'],
        where: { ...where, event: 'page_view' },
        _count: { path: true },
        orderBy: { _count: { path: 'desc' } },
        take: 10,
      }),
      db.user.findMany({ where, select: { createdAt: true } }),
      db.scan.findMany({
        where: { completedAt: { gte: from, lte: to }, status: 'completed' },
        select: { completedAt: true },
      }),
    ]);
  return {
    rangeDays: days,
    from: from.toISOString(),
    to: to.toISOString(),
    totals: { signups, scansCompleted, fixesApplied, pageViews, contactMessages },
    eventsByType: eventsByType
      .map((r) => ({ event: r.event, count: r._count.event }))
      .sort((a, b) => b.count - a.count),
    topPaths: topPaths
      // Probe/404 paths (e.g. /__day8_probe__, /this-page-does-not-exist-123)
      // are recorded by ingestion and used to top the "most visited" list.
      // Only real app routes count as visited pages.
      .filter((r) => KNOWN_APP_PATHS.some((p) => r.path === p || r.path.startsWith(`${p}/`)))
      .map((r) => ({ path: r.path, count: r._count.path })),
    signupsByDay: bucketByDay(signupRows, from, days),
    scansByDay: bucketByDay(
      scanRows.map((r) => ({ createdAt: r.completedAt })),
      from,
      days,
    ),
  };
}

module.exports = { parseSummaryRange, buildAnalyticsSummary };
