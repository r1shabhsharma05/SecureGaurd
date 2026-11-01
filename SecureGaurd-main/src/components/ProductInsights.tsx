import { useCallback, useEffect, useState } from 'react';
import { apiUrl } from '../config/api';
import { SkeletonCard, SkeletonTable } from './Skeleton';
import EmptyState from './EmptyState';
import './ProductInsights.css';

// Day 9 — product-activity dashboard: the Day-8 AnalyticsEvent rows plus
// real product totals (signups, completed scans, fixes applied) from
// GET /api/analytics/summary. Aggregate counts only — the endpoint
// returns no per-user rows. Rendered at the top of the Dashboard
// Analytics tab, above the org-scoped vulnerability breakdown.
interface Summary {
  rangeDays: number;
  totals: { signups: number; scansCompleted: number; fixesApplied: number; pageViews: number; contactMessages: number };
  eventsByType: Array<{ event: string; count: number }>;
  topPaths: Array<{ path: string; count: number }>;
  signupsByDay: Array<{ date: string; count: number }>;
  scansByDay: Array<{ date: string; count: number }>;
}

type Range = '7d' | '30d' | '90d';

function DailyBars({ data, label }: { data: Array<{ date: string; count: number }>; label: string }) {
  const max = Math.max(1, ...data.map((d) => d.count));
  return (
    <div className="insights-bars" role="img" aria-label={`${label}: ${data.map((d) => `${d.date} ${d.count}`).join(', ')}`}>
      {data.map((d) => (
        <div key={d.date} className="insights-bar-col" title={`${d.date}: ${d.count}`}>
          <span className="insights-bar-value">{d.count}</span>
          <div className="insights-bar" style={{ height: `${Math.max(4, (d.count / max) * 72)}px` }} />
          <span className="insights-bar-date">{d.date.slice(5)}</span>
        </div>
      ))}
    </div>
  );
}

export default function ProductInsights({ accessToken }: { accessToken: string | null }) {
  const [range, setRange] = useState<Range>('30d');
  const [summary, setSummary] = useState<Summary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    if (!accessToken) return;
    setLoading(true);
    setError('');
    try {
      const res = await fetch(apiUrl(`/api/analytics/summary?range=${range}`), {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.message || 'Could not load product activity.');
      setSummary(data as Summary);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load product activity.');
    } finally {
      setLoading(false);
    }
  }, [accessToken, range]);

  // Initial + range-change load. The fetch runs async (state updates only
  // after the await), so no synchronous setState-in-effect; the Retry
  // button reuses `load` directly.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!accessToken) return;
      try {
        const res = await fetch(apiUrl(`/api/analytics/summary?range=${range}`), {
          headers: { Authorization: `Bearer ${accessToken}` },
        });
        const data = await res.json().catch(() => ({}));
        if (cancelled) return;
        if (!res.ok) throw new Error(data.message || 'Could not load product activity.');
        setSummary(data as Summary);
        setError('');
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Could not load product activity.');
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [accessToken, range]);

  const totals = summary?.totals;
  const allZero = totals && Object.values(totals).every((v) => v === 0);

  return (
    <section className="insights-section" aria-label="Product activity">
      <div className="insights-header">
        <h3 className="analytics-card-title">Product activity</h3>
        <label className="insights-range">
          <span>Range</span>
          <select value={range} onChange={(e) => setRange(e.target.value as Range)} aria-label="Activity range">
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
            <option value="90d">Last 90 days</option>
          </select>
        </label>
      </div>

      {loading && (
        <div className="insights-loading">
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonTable rows={3} />
        </div>
      )}

      {!loading && error && (
        <div className="insights-error" role="alert">
          <p>{error}</p>
          <button type="button" className="connect-repo-btn" onClick={() => void load()}>
            Retry
          </button>
        </div>
      )}

      {!loading && !error && summary && allZero && (
        <EmptyState
          title="No product activity yet"
          body="No signups, scans, or page views were recorded in this range. Activity appears here once visitors use the site."
        />
      )}

      {!loading && !error && summary && !allZero && (
        <>
          <div className="insights-cards">
            <div className="insights-card"><span className="insights-card-value">{totals!.signups}</span><span className="insights-card-label">Signups</span></div>
            <div className="insights-card"><span className="insights-card-value">{totals!.scansCompleted}</span><span className="insights-card-label">Scans completed</span></div>
            <div className="insights-card"><span className="insights-card-value">{totals!.fixesApplied}</span><span className="insights-card-label">AI fixes applied</span></div>
            <div className="insights-card"><span className="insights-card-value">{totals!.pageViews}</span><span className="insights-card-label">Page views</span></div>
            <div className="insights-card"><span className="insights-card-value">{totals!.contactMessages}</span><span className="insights-card-label">Contact messages</span></div>
          </div>
          <div className="insights-grid">
            <div className="analytics-card">
              <h3 className="analytics-card-title">Signups per day</h3>
              <DailyBars data={summary.signupsByDay} label="Signups per day" />
            </div>
            <div className="analytics-card">
              <h3 className="analytics-card-title">Scans per day</h3>
              <DailyBars data={summary.scansByDay} label="Scans per day" />
            </div>
            <div className="analytics-card">
              <h3 className="analytics-card-title">Events recorded</h3>
              <ul className="insights-list">
                {summary.eventsByType.map((e) => (
                  <li key={e.event}><span>{e.event}</span><strong>{e.count}</strong></li>
                ))}
              </ul>
            </div>
            <div className="analytics-card">
              <h3 className="analytics-card-title">Most visited pages</h3>
              <ul className="insights-list">
                {summary.topPaths.map((p) => (
                  <li key={p.path}><span>{p.path}</span><strong>{p.count}</strong></li>
                ))}
              </ul>
            </div>
          </div>
          <p className="insights-note">
            Aggregate counts across all accounts for the selected range. Page views are recorded only for
            visitors who granted analytics consent.
          </p>
        </>
      )}
    </section>
  );
}
