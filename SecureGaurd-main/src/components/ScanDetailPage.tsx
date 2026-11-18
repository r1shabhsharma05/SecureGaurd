import { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { Shield, ArrowLeft, AlertTriangle } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useOrganization } from '../context/OrganizationContext';
import { PageSkeleton } from './Skeleton';
import { formatVulnId } from '../utils/formatVulnId';
import './VulnerabilityDetailsPage.css';

interface ScanFinding {
  id: number;
  severity: string;
  title: string;
  filePath: string;
  lineStart: number;
  status: string;
}

interface ScanDetail {
  id: number;
  status: string;
  branch: string;
  commitSha: string | null;
  totalFiles: number;
  totalLines: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  durationMs: number;
  errorMessage?: string | null;
  createdAt: string;
  completedAt: string | null;
  repository: { name: string; fullName: string; url: string; platform: string };
  vulnerabilities: ScanFinding[];
}

// Scan rows in the dashboard were not clickable and no detail page
// existed — a scan could only be seen as one table row.
export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { user, loading: authLoading } = useAuth();
  const { orgFetch } = useOrganization();
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);
  const [error, setError] = useState('');

  // Inline async fetch in the effect: calling a fetcher that sets state
  // synchronously (setLoading(true)) trips react-hooks/set-state-in-effect.
  const invalidId = !id || isNaN(Number(id));
  useEffect(() => {
    if (authLoading || invalidId) return;
    if (!user) { navigate('/login'); return; }
    let cancelled = false;
    (async () => {
      try {
        const res = await orgFetch(`/api/scans/${id}`);
        if (cancelled) return;
        if (res.status === 404) { setNotFound(true); return; }
        if (!res.ok) throw new Error(`Failed to load scan (${res.status})`);
        setScan(await res.json());
      } catch (err: unknown) {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load scan.');
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [id, invalidId, user, authLoading, navigate, orgFetch]);

  if (invalidId) {
    return (
      <div className="vuln-detail-page">
        <main className="vuln-detail-container">
          <p>Scan not found.</p>
          <Link to="/dashboard?tab=scans">← Back to scan history</Link>
        </main>
      </div>
    );
  }

  if (loading || authLoading) {
    return (
      <div className="vuln-detail-page">
        <main className="vuln-detail-container"><PageSkeleton /></main>
      </div>
    );
  }

  if (notFound || !scan) {
    return (
      <div className="vuln-detail-page">
        <main className="vuln-detail-container">
          <p>{notFound ? 'Scan not found.' : error || 'Scan not found.'}</p>
          <Link to="/dashboard?tab=scans">← Back to scan history</Link>
        </main>
      </div>
    );
  }

  const total = scan.criticalCount + scan.highCount + scan.mediumCount + scan.lowCount;

  return (
    <div className="vuln-detail-page">
      <header className="vuln-detail-navbar">
        <Link to="/dashboard?tab=scans" className="detail-back-link"><ArrowLeft size={16} /> Scan history</Link>
        <span className="detail-brand"><Shield size={18} /> SecureGuard</span>
      </header>
      <main className="vuln-detail-container">
        <h1>Scan #S-{String(scan.id).padStart(4, '0')} — {scan.repository.fullName}</h1>
        <p style={{ color: 'var(--text-dim)', fontSize: '0.85rem' }}>
          {scan.branch} {scan.commitSha ? `· ${scan.commitSha.slice(0, 7)}` : ''} · {new Date(scan.createdAt).toLocaleString()}
        </p>

        <section className="detail-section">
          <div className="metric-row"><span className="metric-label">Status</span><span className="metric-value">{scan.status.toUpperCase()}</span></div>
          <div className="metric-row"><span className="metric-label">Files scanned</span><span className="metric-value">{scan.totalFiles} files · {scan.totalLines} lines</span></div>
          <div className="metric-row"><span className="metric-label">Duration</span><span className="metric-value">{(scan.durationMs / 1000).toFixed(2)}s</span></div>
          <div className="metric-row">
            <span className="metric-label">Findings (at scan time)</span>
            <span className="metric-value">
              {total === 0 && scan.status === 'completed' ? 'Clean Scan' : `${scan.criticalCount} critical · ${scan.highCount} high · ${scan.mediumCount} medium · ${scan.lowCount} low`}
            </span>
          </div>
          {scan.status === 'failed' && (
            <div className="metric-row">
              <span className="metric-label">Failure reason</span>
              <span className="metric-value" style={{ color: 'var(--accent-red)' }}>{scan.errorMessage || 'Scan failed (no reason recorded).'}</span>
            </div>
          )}
          <p style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '0.5rem' }}>
            Counts are as recorded when this scan finished. Findings fixed or marked afterwards show in the Vulnerability Database.
          </p>
        </section>

        <section className="detail-section">
          <h2>Findings in this scan ({scan.vulnerabilities.length})</h2>
          {scan.vulnerabilities.length === 0 ? (
            <p style={{ color: 'var(--text-dim)', fontSize: '0.85rem' }}>
              {scan.status === 'completed' ? 'No findings — clean scan.' : 'No findings were recorded for this scan.'}
            </p>
          ) : (
            <div className="table-scroll-x">
              <table className="scan-history-table">
                <thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>File</th><th>Status</th></tr></thead>
                <tbody>
                  {scan.vulnerabilities.map((v) => (
                    <tr key={v.id} onClick={() => navigate(`/vulnerabilities/${v.id}`)} style={{ cursor: 'pointer' }}>
                      <td><code>{formatVulnId(v.id)}</code></td>
                      <td><span className="highlight">{v.title}</span></td>
                      <td><span className={`badge badge--${v.severity.toLowerCase()}`}>{v.severity.toUpperCase()}</span></td>
                      <td><span className="repo-card-fullname">{v.filePath}:{v.lineStart}</span></td>
                      <td>{v.status}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {scan.status === 'failed' && (
          <p style={{ fontSize: '0.85rem', color: 'var(--text-dim)' }}>
            <AlertTriangle size={13} style={{ verticalAlign: '-2px', marginRight: '4px' }} />
            This scan failed before it could finish — check the repository URL is a reachable public repo, then re-run it from the dashboard.
          </p>
        )}
      </main>
    </div>
  );
}
