import React, { useState, useEffect } from 'react';
import { FileCode2, Search, Trash2, Play, CheckCircle, ShieldAlert } from 'lucide-react';
import { useOrganization } from '../context/OrganizationContext';
import { SkeletonCard } from './Skeleton';
import EmptyState from './EmptyState';
import './CustomRulesPage.css';

interface CustomRule {
  id: number;
  ruleId: string;
  title: string;
  severity: string;
  type: string;
  pattern: string;
  ignoreCase: boolean;
  filePattern: string;
  excludePattern: string | null;
  description: string;
  remediation: string;
  cweId: string | null;
  enabled: boolean;
}

interface BuiltInRule {
  id: string;
  title: string;
  severity: string;
  type: string;
  description: string;
  pattern: string | null;
  framework: string;
}

const SAMPLE_YAML = `id: CUSTOM-001
title: No eval on request data
severity: high
type: sast
pattern: 'eval\\s*\\(.*req\\.'
filePattern: '\\.(js|ts|jsx|tsx)$'
description: Eval on request data is code injection.
remediation: Avoid eval; parse and validate input explicitly.
cweId: CWE-95
`;

const SAMPLE_CODE = "const result = eval(req.body.code);\nconst safe = 1;\n";

/**
 * Custom Rules tab (Day 10, PRD §4.2.1): org-authored YAML detection rules.
 * Authors write a rule, test it against sample code or a past scan's repo,
 * then enable it — enabled rules fire in real scans. AUDITOR is read-only
 * (the API enforces the same gate server-side).
 */
export default function CustomRulesPage() {
  const { activeOrgId, activeRole, orgFetch } = useOrganization();
  const canWrite = activeRole === 'OWNER' || activeRole === 'ADMIN' || activeRole === 'DEVELOPER';

  const [rules, setRules] = useState<CustomRule[]>([]);
  const [library, setLibrary] = useState<BuiltInRule[]>([]);
  const [scans, setScans] = useState<{ id: number; repository?: { fullName: string } }[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState('');

  const [yaml, setYaml] = useState(SAMPLE_YAML);
  const [creating, setCreating] = useState(false);
  const [showLibrary, setShowLibrary] = useState(false);

  const [testRuleId, setTestRuleId] = useState<number | null>(null);
  const [testCode, setTestCode] = useState(SAMPLE_CODE);
  const [testFilePath, setTestFilePath] = useState('app.js');
  const [testScanId, setTestScanId] = useState('');
  const [testResult, setTestResult] = useState<{ matchCount: number; matches: { lineStart: number; codeSnippet: string }[]; note?: string } | null>(null);
  const [testing, setTesting] = useState(false);
  const [confirmingDeleteId, setConfirmingDeleteId] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!activeOrgId) return;
      try {
        const [rulesRes, libRes, scansRes] = await Promise.all([
          orgFetch('/api/custom-rules'),
          orgFetch('/api/custom-rules/library'),
          orgFetch('/api/scans'),
        ]);
        if (cancelled) return;
        if (rulesRes.ok) setRules(await rulesRes.json());
        if (libRes.ok) {
          const lib = await libRes.json();
          setLibrary(lib.builtin || []);
        }
        if (scansRes.ok) setScans(await scansRes.json());
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load custom rules');
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [activeOrgId, orgFetch]);

  const createRule = async () => {
    setCreating(true);
    setError(null);
    setNotice('');
    try {
      const res = await orgFetch('/api/custom-rules', { method: 'POST', body: JSON.stringify({ yaml }) });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Failed to create rule');
      setRules((prev) => [...prev, data].sort((a, b) => a.ruleId.localeCompare(b.ruleId)));
      setNotice(`Rule ${data.ruleId} created. Enable it and it will fire in the next scan.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create rule');
    } finally {
      setCreating(false);
    }
  };

  const toggleRule = async (rule: CustomRule) => {
    try {
      const res = await orgFetch(`/api/custom-rules/${rule.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ enabled: !rule.enabled }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Failed to update rule');
      setRules((prev) => prev.map((r) => (r.id === rule.id ? data : r)));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update rule');
    }
  };

  const deleteRule = async (rule: CustomRule) => {
    try {
      const res = await orgFetch(`/api/custom-rules/${rule.id}`, { method: 'DELETE' });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.message || 'Failed to delete rule');
      }
      setRules((prev) => prev.filter((r) => r.id !== rule.id));
      setConfirmingDeleteId(null);
      if (testRuleId === rule.id) setTestRuleId(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete rule');
    }
  };

  const runTest = async (rule: CustomRule, mode: 'sample' | 'scan') => {
    setTesting(true);
    setError(null);
    setTestResult(null);
    try {
      const url = mode === 'sample'
        ? `/api/custom-rules/${rule.id}/test`
        : `/api/custom-rules/${rule.id}/test-scan`;
      const body = mode === 'sample'
        ? { code: testCode, filePath: testFilePath }
        : { scanId: parseInt(testScanId, 10) };
      if (mode === 'scan' && !body.scanId) throw new Error('Choose a scan to test against.');
      const res = await orgFetch(url, { method: 'POST', body: JSON.stringify(body) });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Test failed');
      setTestResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Test failed');
    } finally {
      setTesting(false);
    }
  };

  if (loading) return <SkeletonCard />;

  return (
    <div className="custom-rules-page">
      <div className="custom-rules-header">
        <h2>Custom Detection Rules</h2>
        <p>Write your own YAML rules for this organization. Enabled rules run in every scan alongside the built-in rules.</p>
        {!canWrite && <p className="custom-rules-readonly">You have read-only access (Auditor). Only Owners, Admins and Developers can create or change rules.</p>}
      </div>

      {error && <div className="auth-alert auth-alert--error custom-rules-alert">{error}</div>}
      {notice && <div className="auth-alert auth-alert--success custom-rules-alert">{notice}</div>}

      <button type="button" className="custom-rules-library-toggle" onClick={() => setShowLibrary(!showLibrary)}>
        {showLibrary ? 'Hide' : 'Show'} built-in rule library ({library.length} rules)
      </button>
      {showLibrary && (
        <div className="custom-rules-library">
          {library.map((r) => (
            <div key={r.id} className="custom-rules-library-row">
              <code>{r.id}</code>
              <span>{r.title}</span>
              <span className={`custom-rules-severity custom-rules-severity--${r.severity}`}>{r.severity}</span>
              <span className="custom-rules-library-framework">{r.framework}</span>
            </div>
          ))}
        </div>
      )}

      {rules.length === 0 ? (
        <EmptyState
          icon={<FileCode2 size={48} />}
          title="No custom rules yet"
          body="Create your first rule below. Rules you enable will fire in the next scan of any repository in this organization."
        />
      ) : (
        <div className="custom-rules-list">
          {rules.map((rule) => (
            <div key={rule.id} className="custom-rules-card">
              <div className="custom-rules-card-top">
                <div>
                  <strong>{rule.title}</strong>
                  <span className="custom-rules-card-id">{rule.ruleId}</span>
                </div>
                <span className={`custom-rules-severity custom-rules-severity--${rule.severity}`}>{rule.severity}</span>
              </div>
              <p className="custom-rules-card-desc">{rule.description || 'No description.'}</p>
              <code className="custom-rules-pattern">{rule.pattern}</code>
              <div className="custom-rules-card-meta">
                <span>type: {rule.type}</span>
                <span>files: {rule.filePattern}</span>
                {rule.cweId && <span>{rule.cweId}</span>}
                <span>{rule.enabled ? 'Enabled' : 'Disabled'}</span>
              </div>
              {rule.remediation && <p className="custom-rules-card-remediation">Fix: {rule.remediation}</p>}
              <div className="custom-rules-card-actions">
                <button type="button" onClick={() => { setTestRuleId(rule.id); setTestResult(null); }}>
                  <Play size={13} /> Test
                </button>
                {canWrite && (
                  <>
                    <button type="button" onClick={() => toggleRule(rule)}>
                      {rule.enabled ? 'Disable' : 'Enable'}
                    </button>
                    {confirmingDeleteId === rule.id ? (
                      <button type="button" className="custom-rules-delete-confirm" onClick={() => deleteRule(rule)}>
                        <Trash2 size={13} /> Confirm delete
                      </button>
                    ) : (
                      <button type="button" onClick={() => setConfirmingDeleteId(rule.id)}>
                        <Trash2 size={13} /> Delete
                      </button>
                    )}
                  </>
                )}
              </div>
              {testRuleId === rule.id && (
                <div className="custom-rules-test">
                  <label>
                    Sample code
                    <textarea value={testCode} onChange={(e) => setTestCode(e.target.value)} rows={4} spellCheck={false} />
                  </label>
                  <label>
                    File name
                    <input value={testFilePath} onChange={(e) => setTestFilePath(e.target.value)} />
                  </label>
                  <div className="custom-rules-test-actions">
                    <button type="button" disabled={testing} onClick={() => runTest(rule, 'sample')}>
                      <Search size={13} /> Test sample code
                    </button>
                    {canWrite && scans.length > 0 && (
                      <>
                        <select value={testScanId} onChange={(e) => setTestScanId(e.target.value)}>
                          <option value="">Choose a past scan…</option>
                          {scans.map((s) => (
                            <option key={s.id} value={s.id}>Scan #{s.id} — {s.repository?.fullName || 'repository'}</option>
                          ))}
                        </select>
                        <button type="button" disabled={testing || !testScanId} onClick={() => runTest(rule, 'scan')}>
                          Test against scan&apos;s repository
                        </button>
                      </>
                    )}
                  </div>
                  {testResult && (
                    <div className="custom-rules-test-result">
                      <p>
                        {testResult.matchCount === 0
                          ? 'No matches — the rule did not fire.'
                          : `${testResult.matchCount} match${testResult.matchCount === 1 ? '' : 'es'}:`}
                      </p>
                      {testResult.matches.map((m, i) => (
                        <div key={i} className="custom-rules-match">
                          <span>Line {m.lineStart}</span>
                          <code>{m.codeSnippet}</code>
                        </div>
                      ))}
                      {testResult.note && <p className="custom-rules-test-note">{testResult.note}</p>}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {canWrite && (
        <div className="custom-rules-create">
          <h3>Create a rule (YAML)</h3>
          <p>One rule per document. <code>id</code> must start with <code>CUSTOM-</code>. The pattern is a regular expression matched per line.</p>
          <textarea value={yaml} onChange={(e) => setYaml(e.target.value)} rows={12} spellCheck={false} aria-label="Rule YAML" />
          <div className="custom-rules-create-actions">
            <button type="button" onClick={() => setYaml(SAMPLE_YAML)}>Reset example</button>
            <button type="button" className="custom-rules-create-btn" disabled={creating} onClick={createRule}>
              {creating ? 'Creating…' : 'Create rule'}
            </button>
          </div>
        </div>
      )}

      <div className="custom-rules-footnote">
        <p><ShieldAlert size={13} /> Custom findings carry no ML classification, so the false-positive classifier can never suppress them. Disabling a rule stops it firing in new scans; past findings keep the rule id.</p>
        <p><CheckCircle size={13} /> Rules are validated when saved: bad YAML, an unknown field, or an invalid pattern is rejected with the exact problem.</p>
      </div>
    </div>
  );
}
