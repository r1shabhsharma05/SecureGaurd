import { useState, useEffect, useCallback } from 'react';
import { RefreshCw, CheckCircle2, XCircle } from 'lucide-react';
import { useOrganization } from '../context/OrganizationContext';

interface AlertSetting {
  configured: boolean;
  slackEnabled: boolean;
  emailEnabled: boolean;
  notifyOnScanComplete: boolean;
  notifyOnNewCritical: boolean;
  hasSlackWebhook: boolean;
  slackWebhookMasked: string | null;
}

interface AlertLogRow {
  id: number;
  channel: string;
  event: string;
  targetMasked: string | null;
  status: string;
  providerId: string | null;
  error: string | null;
  createdAt: string;
}

// Day 7 — alerts configuration tab: Slack webhook + email alerts on scan
// completion / new critical findings, with a real delivery log. The webhook
// URL itself is never displayed back (the API only reports a masked form),
// and test buttons report the provider's actual outcome.
export default function AlertsSettings() {
  const { orgFetch, activeRole } = useOrganization();
  const canEdit = activeRole === 'OWNER' || activeRole === 'ADMIN';

  const [setting, setSetting] = useState<AlertSetting | null>(null);
  const [logs, setLogs] = useState<AlertLogRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState<string | null>(null);
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');

  const [slackUrl, setSlackUrl] = useState('');
  const [slackEnabled, setSlackEnabled] = useState(false);
  const [emailEnabled, setEmailEnabled] = useState(false);
  const [notifyComplete, setNotifyComplete] = useState(true);
  const [notifyCritical, setNotifyCritical] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [sRes, lRes] = await Promise.all([orgFetch('/api/alerts/settings'), orgFetch('/api/alerts/logs')]);
      if (sRes.ok) {
        const data: AlertSetting = await sRes.json();
        setSetting(data);
        setSlackEnabled(data.slackEnabled);
        setEmailEnabled(data.emailEnabled);
        setNotifyComplete(data.notifyOnScanComplete);
        setNotifyCritical(data.notifyOnNewCritical);
      }
      if (lRes.ok) setLogs(await lRes.json());
    } catch {
      setError('Failed to load alert settings.');
    } finally {
      setLoading(false);
    }
  }, [orgFetch]);

  useEffect(() => { load(); }, [load]);

  const save = async () => {
    setSaving(true);
    setNotice('');
    setError('');
    try {
      const body: Record<string, unknown> = { slackEnabled, emailEnabled, notifyOnScanComplete: notifyComplete, notifyOnNewCritical: notifyCritical };
      if (slackUrl.trim()) body.slackWebhookUrl = slackUrl.trim();
      const res = await orgFetch('/api/alerts/settings', { method: 'PUT', body: JSON.stringify(body) });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Failed to save settings');
      setSetting(data);
      setSlackUrl('');
      setNotice('Alert settings saved.');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  const test = async (channel: 'slack' | 'email') => {
    setTesting(channel);
    setNotice('');
    setError('');
    try {
      const res = await orgFetch('/api/alerts/test', { method: 'POST', body: JSON.stringify({ channel }) });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || data.message || 'Test alert failed');
      setNotice(`${channel === 'slack' ? 'Slack' : 'Email'} test alert delivered.`);
      await load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Test alert failed');
      await load();
    } finally {
      setTesting(null);
    }
  };

  if (loading) {
    return (
      <div style={{ padding: '2rem', color: 'var(--text-dim)', fontSize: '0.85rem' }}>
        <RefreshCw size={14} className="spin-icon" style={{ display: 'inline', marginRight: '8px' }} />Loading alerts…
      </div>
    );
  }

  return (
    <div className="scans-tab-container">
      <div className="tab-section-header">
        <h2 className="tab-title">Scan Alerts</h2>
      </div>
      <p style={{ fontSize: '0.85rem', color: 'var(--text-dim)', marginBottom: '1rem' }}>
        Get notified when a scan completes or when new critical findings appear. Slack alerts post to your workspace webhook; email alerts go to every member of this organization via Brevo. Nothing is sent until you enable a channel here.
      </p>
      {error && <div style={{ padding: '0.75rem 1rem', borderRadius: '8px', background: 'rgba(239,68,68,0.12)', border: '1px solid rgba(239,68,68,0.4)', color: '#fca5a5', fontSize: '0.85rem', marginBottom: '1rem' }}>{error}</div>}
      {notice && <div style={{ padding: '0.75rem 1rem', borderRadius: '8px', background: 'rgba(16,185,129,0.12)', border: '1px solid rgba(16,185,129,0.4)', color: '#6ee7b7', fontSize: '0.85rem', marginBottom: '1rem' }}>{notice}</div>}
      {!canEdit && <p style={{ fontSize: '0.85rem', color: 'var(--text-dim)' }}>Only Owners and Admins can change alert settings.</p>}

      <div className="settings-card">
        <h3 className="settings-section-title">Channels</h3>
        <label style={{ display: 'block', fontSize: '0.8rem', marginBottom: '0.5rem' }}>
          <input type="checkbox" checked={slackEnabled} disabled={!canEdit} onChange={(e) => setSlackEnabled(e.target.checked)} /> Slack alerts
        </label>
        <input
          type="password"
          value={slackUrl}
          onChange={(e) => setSlackUrl(e.target.value)}
          disabled={!canEdit}
          placeholder={setting?.hasSlackWebhook ? 'Webhook stored (masked: ' + (setting.slackWebhookMasked || '') + ') — paste a new one to replace it' : 'https://hooks.slack.com/services/T…/B…/…'}
          style={{ width: '100%', padding: '0.6rem', borderRadius: '6px', border: '1px solid var(--border-color)', background: 'var(--bg-card)', color: '#fff', marginBottom: '0.75rem' }}
        />
        <label style={{ display: 'block', fontSize: '0.8rem', marginBottom: '0.5rem' }}>
          <input type="checkbox" checked={emailEnabled} disabled={!canEdit} onChange={(e) => setEmailEnabled(e.target.checked)} /> Email alerts (Brevo, to all org members)
        </label>
        <label style={{ display: 'block', fontSize: '0.8rem', marginBottom: '0.5rem' }}>
          <input type="checkbox" checked={notifyComplete} disabled={!canEdit} onChange={(e) => setNotifyComplete(e.target.checked)} /> On every scan completion
        </label>
        <label style={{ display: 'block', fontSize: '0.8rem', marginBottom: '1rem' }}>
          <input type="checkbox" checked={notifyCritical} disabled={!canEdit} onChange={(e) => setNotifyCritical(e.target.checked)} /> On new critical findings
        </label>
        {canEdit && (
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <button className="connect-repo-btn" onClick={save} disabled={saving}>{saving ? 'Saving…' : 'Save Settings'}</button>
            <button className="connect-repo-btn" onClick={() => test('slack')} disabled={testing !== null}> {testing === 'slack' ? 'Sending…' : 'Send Slack Test'} </button>
            <button className="connect-repo-btn" onClick={() => test('email')} disabled={testing !== null}> {testing === 'email' ? 'Sending…' : 'Send Email Test'} </button>
            <button className="connect-repo-btn" onClick={load}><RefreshCw size={13} /> Refresh Log</button>
          </div>
        )}
      </div>

      <div className="settings-card">
        <h3 className="settings-section-title">Delivery Log</h3>
        {logs.length === 0 ? (
          <p style={{ fontSize: '0.85rem', color: 'var(--text-dim)' }}>No alerts sent yet. Save a channel above, then run a scan or send a test alert — every attempt lands here with its real provider outcome.</p>
        ) : (
          <table className="scan-history-table">
            <thead>
              <tr><th>When</th><th>Channel</th><th>Event</th><th>Target</th><th>Status</th><th>Detail</th></tr>
            </thead>
            <tbody>
              {logs.map((l) => (
                <tr key={l.id}>
                  <td>{new Date(l.createdAt).toLocaleString()}</td>
                  <td>{l.channel}</td>
                  <td>{l.event}</td>
                  <td><span className="repo-card-fullname">{l.targetMasked || '—'}</span></td>
                  <td>{l.status === 'delivered' ? <CheckCircle2 size={14} color="#34d399" /> : <XCircle size={14} color="#f87171" />} {l.status}</td>
                  <td style={{ fontSize: '0.75rem' }}>{l.error || (l.providerId ? `provider id ${l.providerId}` : '—')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
