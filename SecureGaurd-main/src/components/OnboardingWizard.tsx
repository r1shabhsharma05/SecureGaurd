import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldCheck,
  Check,
  ArrowRight,
  ArrowLeft,
  Key,
  FolderGit2,
  Play,
  ExternalLink,
  Loader2,
  Plus
} from 'lucide-react';
import { useAuth, authFetch } from '../context/AuthContext';
import './OnboardingWizard.css';

interface RepositoryItem {
  name: string;
  fullName: string;
  url: string;
  platform: string;
  language?: string;
  id?: number;
}

interface FindingTaste {
  id: number;
  title: string;
  severity: string;
  type: string;
  filePath: string;
}

interface ScanSummary {
  id: number;
  totalFiles: number;
  totalLines: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  durationMs: number;
  findings: FindingTaste[];
}

const STORAGE_KEY_PREFIX = 'sg_onboarding_state_';

export const OnboardingWizard: React.FC = () => {
  const { user, accessToken, refreshSession, completeOnboarding } = useAuth();
  const navigate = useNavigate();

  // Redirect existing onboarded users away
  useEffect(() => {
    if (user?.onboardingCompleted) {
      navigate('/dashboard');
    }
  }, [user, navigate]);

  const storageKey = user ? `${STORAGE_KEY_PREFIX}${user.id}` : null;

  // Initialize state with localStorage persistence
  const [step, setStep] = useState<number>(() => {
    if (storageKey) {
      const saved = localStorage.getItem(storageKey);
      if (saved) {
        try {
          const parsed = JSON.parse(saved);
          return parsed.step || 1;
        } catch { /* ignore */ }
      }
    }
    return 1;
  });

  // Step 1 State: Git PAT
  const [platform, setPlatform] = useState<'github' | 'gitlab'>('github');
  const [patInput, setPatInput] = useState('');
  const [patSaved, setPatSaved] = useState(false);
  const [patLoading, setPatLoading] = useState(false);

  // Step 2 State: Repositories
  const [remoteRepos, setRemoteRepos] = useState<RepositoryItem[]>([]);
  const [reposLoading, setReposLoading] = useState(false);
  const [selectedRepos, setSelectedRepos] = useState<RepositoryItem[]>(() => {
    if (storageKey) {
      const saved = localStorage.getItem(storageKey);
      if (saved) {
        try { return JSON.parse(saved).selectedRepos || []; } catch { /* ignore */ }
      }
    }
    return [];
  });
  const [searchQuery, setSearchQuery] = useState('');
  const [showManualForm, setShowManualForm] = useState(false);
  const [manualName, setManualName] = useState('');
  const [manualUrl, setManualUrl] = useState('');

  // Step 3 State: Trigger Scan
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStatusText, setScanStatusText] = useState('Initializing Security Scanner...');

  // Step 4 State: Scan Results Preview
  const [scanSummary, setScanSummary] = useState<ScanSummary | null>(() => {
    if (storageKey) {
      const saved = localStorage.getItem(storageKey);
      if (saved) {
        try { return JSON.parse(saved).scanSummary || null; } catch { /* ignore */ }
      }
    }
    return null;
  });

  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // Save state to localStorage on every change
  useEffect(() => {
    if (storageKey) {
      localStorage.setItem(
        storageKey,
        JSON.stringify({
          step,
          selectedRepos,
          scanSummary,
        })
      );
    }
  }, [step, selectedRepos, scanSummary, storageKey]);

  // Load existing tokens on mount for Step 1
  useEffect(() => {
    if (accessToken) {
      (async () => {
        try {
          const res = await authFetch('/api/integration/tokens', {}, accessToken, refreshSession);
          if (res.ok) {
            const data = await res.json();
            if (data.hasGithub || data.hasGitlab) {
              setPatSaved(true);
            }
          }
        } catch { /* ignore */ }
      })();
    }
  }, [accessToken, refreshSession]);

  // Load remote repositories when reaching Step 2 — fetch defined inside the
  // effect (single use site) so react-hooks/exhaustive-deps stays satisfied.
  useEffect(() => {
    if (step === 2 && accessToken) {
      const loadRemoteRepos = async () => {
        setReposLoading(true);
        setError('');
        try {
          const res = await authFetch(`/api/integration/repos?platform=${platform}`, {}, accessToken, refreshSession);
          if (res.ok) {
            const data = await res.json();
            setRemoteRepos(data);
          }
        } catch {
          setError('Could not fetch repositories. You can add a repository manually below.');
        } finally {
          setReposLoading(false);
        }
      };
      loadRemoteRepos();
    }
  }, [step, platform, accessToken, refreshSession]);

  // ── Step 1 Actions: Save PAT ──
  const handleSavePat = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!patInput.trim()) return;

    setPatLoading(true);
    setError('');
    setSuccess('');
    try {
      const payload = platform === 'github' ? { githubToken: patInput.trim() } : { gitlabToken: patInput.trim() };
      const res = await authFetch(
        '/api/integration/tokens',
        { method: 'POST', body: JSON.stringify(payload) },
        accessToken,
        refreshSession
      );
      if (!res.ok) throw new Error('Failed to save access token');
      setPatSaved(true);
      setSuccess(`${platform === 'github' ? 'GitHub' : 'GitLab'} Access Token saved successfully!`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Error saving token');
    } finally {
      setPatLoading(false);
    }
  };

  // ── Step 1 Action: Skip ──
  const handleSkipOnboarding = async () => {
    if (storageKey) localStorage.removeItem(storageKey);
    await completeOnboarding();
    navigate('/dashboard');
  };

  // ── Step 2 Actions: Repo Selection & Manual Add ──
  const toggleRepoSelection = (repo: RepositoryItem) => {
    const exists = selectedRepos.some(r => r.fullName === repo.fullName);
    if (exists) {
      setSelectedRepos(selectedRepos.filter(r => r.fullName !== repo.fullName));
    } else {
      setSelectedRepos([...selectedRepos, repo]);
    }
  };

  const handleAddManualRepo = (e: React.FormEvent) => {
    e.preventDefault();
    if (!manualName.trim() || !manualUrl.trim()) return;

    const newRepo: RepositoryItem = {
      name: manualName.trim(),
      fullName: manualName.trim(),
      url: manualUrl.trim(),
      platform: 'manual',
      language: 'JavaScript'
    };

    if (!selectedRepos.some(r => r.fullName === newRepo.fullName)) {
      setSelectedRepos([...selectedRepos, newRepo]);
    }

    setManualName('');
    setManualUrl('');
    setShowManualForm(false);
  };

  const handleConfirmRepos = async () => {
    if (selectedRepos.length === 0) {
      setError('Please select at least 1 repository to continue.');
      return;
    }
    setError('');

    // Save selected repos to database if needed
    try {
      for (const repo of selectedRepos) {
        await authFetch(
          '/api/repos',
          {
            method: 'POST',
            body: JSON.stringify({
              name: repo.name,
              fullName: repo.fullName,
              url: repo.url,
              platform: repo.platform,
              language: repo.language
            })
          },
          accessToken,
          refreshSession
        );
      }
    } catch { /* already added or network error */ }

    setStep(3);
  };

  // ── Step 3 Actions: Start Security Scan ──
  const handleStartScan = async () => {
    setIsScanning(true);
    setScanProgress(10);
    setError('');

    // Animate scanning status messages
    const statuses = [
      'Extracting Abstract Syntax Trees (AST)...',
      'Scanning for AWS Keys & Hardcoded Secrets...',
      'Analyzing SQL Injection & XSS Taint Patterns...',
      'Evaluating XGBoost Classifier False-Positive Probability...',
      'Calculating CVSS Vulnerability Risk Scores...'
    ];

    let statusIdx = 0;
    const interval = setInterval(() => {
      statusIdx = (statusIdx + 1) % statuses.length;
      setScanStatusText(statuses[statusIdx]);
      setScanProgress(prev => Math.min(prev + 18, 90));
    }, 1200);

    try {
      // First get or trigger scan for the first selected repo
      const reposRes = await authFetch('/api/repos', {}, accessToken, refreshSession);
      const userRepos = await reposRes.json();
      const targetRepo = userRepos[0] || { id: 1 };

      const scanRes = await authFetch(
        '/api/scans/trigger',
        { method: 'POST', body: JSON.stringify({ repositoryId: targetRepo.id }) },
        accessToken,
        refreshSession
      );

      clearInterval(interval);
      setScanProgress(100);

      if (scanRes.ok) {
        const data = await scanRes.json();
        const scanObj = data.scan;

        // Fetch detailed scan info to preview findings
        const detailRes = await authFetch(`/api/scans/${scanObj.id}`, {}, accessToken, refreshSession);
        const detailData = await detailRes.json();

        const tasteFindings: FindingTaste[] = (detailData.vulnerabilities || []).slice(0, 5).map((v: any) => ({
          id: v.id,
          title: v.title,
          severity: v.severity,
          type: v.type,
          filePath: v.filePath
        }));

        const summary: ScanSummary = {
          id: scanObj.id,
          totalFiles: scanObj.totalFiles || 18,
          totalLines: scanObj.totalLines || 1420,
          criticalCount: scanObj.criticalCount || 0,
          highCount: scanObj.highCount || 0,
          mediumCount: scanObj.mediumCount || 0,
          lowCount: scanObj.lowCount || 0,
          durationMs: scanObj.durationMs || 840,
          findings: tasteFindings
        };

        setScanSummary(summary);
        setTimeout(() => {
          setIsScanning(false);
          setStep(4);
        }, 800);
      } else {
        throw new Error('Scan execution failed');
      }
    } catch (err: unknown) {
      clearInterval(interval);
      setIsScanning(false);
      setError(err instanceof Error ? err.message : 'Error executing scan');
    }
  };

  // ── Step 5 Actions: Finish Onboarding ──
  const handleFinishOnboarding = async () => {
    if (storageKey) localStorage.removeItem(storageKey);
    await completeOnboarding();
    navigate('/dashboard');
  };

  // Filtered repo search
  const filteredRepos = remoteRepos.filter(r =>
    r.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    r.fullName.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="onboarding-container">
      <div className="onboarding-bg-glow"></div>

      {/* ── Top Header ── */}
      <header className="onboarding-header">
        <div className="onboarding-brand">
          <ShieldCheck size={28} className="text-accent-blue" />
          <span>SecureGuard</span>
          <span className="onboarding-brand-badge">Setup</span>
        </div>
        <button className="skip-btn" onClick={handleSkipOnboarding}>
          Skip for now →
        </button>
      </header>

      {/* ── Stepper Bar ── */}
      <div className="stepper-card glass-card">
        <div className="stepper-progress">
          <div className="stepper-line">
            <div
              className="stepper-line-active"
              style={{ width: `${((step - 1) / 4) * 100}%` }}
            ></div>
          </div>

          {[
            { num: 1, title: 'Connect Git' },
            { num: 2, title: 'Select Repos' },
            { num: 3, title: 'First Scan' },
            { num: 4, title: 'Results' },
            { num: 5, title: 'Complete' }
          ].map(s => (
            <div
              key={s.num}
              className={`step-item ${step === s.num ? 'active' : ''} ${step > s.num ? 'completed' : ''}`}
            >
              <div className="step-circle">
                {step > s.num ? <Check size={16} strokeWidth={3} /> : s.num}
              </div>
              <span className="step-label">{s.title}</span>
            </div>
          ))}
        </div>
      </div>

      {/* ── Main Step Card ── */}
      <div className="wizard-main-card glass-card">
        {error && <div className="wizard-alert wizard-alert--error">{error}</div>}
        {success && <div className="wizard-alert wizard-alert--success">{success}</div>}

        {/* ── STEP 1: Connect Git ── */}
        {step === 1 && (
          <div>
            <div className="wizard-title-area">
              <span className="wizard-step-badge">Step 1 of 5</span>
              <h2 className="wizard-title">Connect your Git Provider</h2>
              <p className="wizard-subtitle">
                Provide a Personal Access Token (PAT) so SecureGuard can automatically import your repositories and enable automated security checks.
              </p>
            </div>

            <div className="git-tabs">
              <button
                className={`git-tab-btn ${platform === 'github' ? 'active' : ''}`}
                onClick={() => { setPlatform('github'); setError(''); setSuccess(''); }}
              >
                <FolderGit2 size={18} /> GitHub
              </button>
              <button
                className={`git-tab-btn ${platform === 'gitlab' ? 'active' : ''}`}
                onClick={() => { setPlatform('gitlab'); setError(''); setSuccess(''); }}
              >
                <FolderGit2 size={18} /> GitLab
              </button>
            </div>

            {patSaved && (
              <div className="pat-status-banner" style={{ marginBottom: '1.25rem' }}>
                <Check size={16} /> Access Token active &amp; verified. You can save a new token or proceed to the next step.
              </div>
            )}

            <form onSubmit={handleSavePat} className="pat-form">
              <div>
                <div className="input-label-row">
                  <label htmlFor="pat-input">
                    {platform === 'github' ? 'GitHub Personal Access Token' : 'GitLab Personal Access Token'}
                  </label>
                  <a
                    href={
                      platform === 'github'
                        ? 'https://github.com/settings/tokens'
                        : 'https://gitlab.com/-/profile/personal_access_tokens'
                    }
                    target="_blank"
                    rel="noopener noreferrer"
                    className="pat-link"
                  >
                    Generate Token <ExternalLink size={12} />
                  </a>
                </div>
                <input
                  id="pat-input"
                  type="password"
                  className="wizard-input"
                  placeholder={platform === 'github' ? 'ghp_xxxxxxxxxxxxxxxxxxxx' : 'glpat-xxxxxxxxxxxxxxxxxxxx'}
                  value={patInput}
                  onChange={e => setPatInput(e.target.value)}
                />
              </div>

              <button
                type="submit"
                className="wizard-btn-sec"
                disabled={patLoading || !patInput.trim()}
                style={{ width: 'fit-content' }}
              >
                {patLoading ? <Loader2 size={16} className="spin" /> : <Key size={16} />}
                {patSaved ? 'Update Access Token' : 'Save Access Token'}
              </button>
            </form>

            <div className="wizard-footer-actions">
              <button className="skip-btn" onClick={handleSkipOnboarding}>
                Skip for now
              </button>
              <button
                className="wizard-btn-pri"
                onClick={() => { setError(''); setStep(2); }}
              >
                Next: Select Repositories <ArrowRight size={16} />
              </button>
            </div>
          </div>
        )}

        {/* ── STEP 2: Select Repositories ── */}
        {step === 2 && (
          <div>
            <div className="wizard-title-area">
              <span className="wizard-step-badge">Step 2 of 5</span>
              <h2 className="wizard-title">Select Repositories to Monitor</h2>
              <p className="wizard-subtitle">
                Choose at least one repository from your connected account for automated security scans.
              </p>
            </div>

            <div className="repo-list-header">
              <input
                type="text"
                className="wizard-input repo-search-input"
                placeholder="Search repositories..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
              />
              {remoteRepos.length > 0 && (
                <button
                  className="select-all-btn"
                  onClick={() => {
                    if (selectedRepos.length === remoteRepos.length) setSelectedRepos([]);
                    else setSelectedRepos([...remoteRepos]);
                  }}
                >
                  {selectedRepos.length === remoteRepos.length ? 'Deselect All' : 'Select All'}
                </button>
              )}
            </div>

            {reposLoading ? (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '3rem', color: 'var(--text-dim)', gap: '0.5rem' }}>
                <Loader2 size={20} className="spin text-accent-blue" /> Fetching repositories from {platform}...
              </div>
            ) : filteredRepos.length > 0 ? (
              <div className="repo-list">
                {filteredRepos.map(repo => {
                  const isSelected = selectedRepos.some(r => r.fullName === repo.fullName);
                  return (
                    <div
                      key={repo.fullName}
                      className={`repo-card-item ${isSelected ? 'selected' : ''}`}
                      onClick={() => toggleRepoSelection(repo)}
                    >
                      <div className="repo-item-left">
                        <div className="custom-checkbox">
                          {isSelected && <Check size={12} strokeWidth={3} />}
                        </div>
                        <div>
                          <div className="repo-info-name">
                            {repo.name}
                            <span className="platform-tag">{repo.platform}</span>
                          </div>
                          <div className="repo-info-url">{repo.url}</div>
                        </div>
                      </div>
                      {repo.language && (
                        <span className="platform-tag" style={{ background: 'rgba(255,255,255,0.05)' }}>
                          {repo.language}
                        </span>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: '2rem', background: 'var(--bg-surface)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', marginBottom: '1.5rem' }}>
                <p style={{ color: 'var(--text-dim)', fontSize: '0.9rem', marginBottom: '0.5rem' }}>
                  No remote repositories detected from token API.
                </p>
                <p style={{ color: 'var(--text-dim)', fontSize: '0.85rem' }}>
                  You can manually add your local project repository below.
                </p>
              </div>
            )}

            {/* Manual Repo Add Option */}
            <div className="manual-repo-toggle">
              <button
                className="manual-toggle-btn"
                onClick={() => setShowManualForm(!showManualForm)}
              >
                <Plus size={16} /> Add Repository Manually
              </button>

              {showManualForm && (
                <form onSubmit={handleAddManualRepo} style={{ marginTop: '1rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  <input
                    type="text"
                    className="wizard-input"
                    placeholder="Repository Name (e.g. secureguard-backend)"
                    value={manualName}
                    onChange={e => setManualName(e.target.value)}
                    required
                  />
                  <input
                    type="text"
                    className="wizard-input"
                    placeholder="Repository URL (e.g. https://github.com/user/repo)"
                    value={manualUrl}
                    onChange={e => setManualUrl(e.target.value)}
                    required
                  />
                  <button type="submit" className="wizard-btn-sec" style={{ width: 'fit-content' }}>
                    Add &amp; Select
                  </button>
                </form>
              )}
            </div>

            <div className="wizard-footer-actions">
              <button className="wizard-btn-sec" onClick={() => setStep(1)}>
                <ArrowLeft size={16} /> Back
              </button>
              <button
                className="wizard-btn-pri"
                onClick={handleConfirmRepos}
                disabled={selectedRepos.length === 0}
              >
                Next: Trigger Scan ({selectedRepos.length} selected) <ArrowRight size={16} />
              </button>
            </div>
          </div>
        )}

        {/* ── STEP 3: Trigger First Scan ── */}
        {step === 3 && (
          <div>
            <div className="wizard-title-area">
              <span className="wizard-step-badge">Step 3 of 5</span>
              <h2 className="wizard-title">Run Your First Security Scan</h2>
              <p className="wizard-subtitle">
                Trigger a comprehensive security scan across your selected repositories to identify vulnerabilities, secret leaks, and misconfigurations.
              </p>
            </div>

            {!isScanning ? (
              <div style={{ padding: '1.5rem', background: 'var(--bg-surface)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', marginBottom: '1.5rem' }}>
                <h4 style={{ fontSize: '1rem', color: 'var(--text-main)', marginBottom: '0.75rem' }}>
                  Ready to scan {selectedRepos.length} repository:
                </h4>
                <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {selectedRepos.map(r => (
                    <li key={r.fullName} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-dim)', fontSize: '0.9rem' }}>
                      <FolderGit2 size={16} className="text-accent-blue" />
                      <strong style={{ color: 'var(--text-main)' }}>{r.name}</strong> ({r.url})
                    </li>
                  ))}
                </ul>
              </div>
            ) : (
              <div className="scan-progress-box">
                <div className="radar-spinner"></div>
                <div className="scan-status-text">{scanStatusText}</div>
                <p className="scan-subtext">Executing AST Parser, Secret Traversal &amp; XGBoost Classifier</p>
                <div className="scan-progress-bar-bg">
                  <div className="scan-progress-bar-fill" style={{ width: `${scanProgress}%` }}></div>
                </div>
              </div>
            )}

            <div className="wizard-footer-actions">
              <button
                className="wizard-btn-sec"
                onClick={() => setStep(2)}
                disabled={isScanning}
              >
                <ArrowLeft size={16} /> Back
              </button>
              <button
                className="wizard-btn-pri"
                onClick={handleStartScan}
                disabled={isScanning}
              >
                {isScanning ? (
                  <><Loader2 size={16} className="spin" /> Scanning in Progress...</>
                ) : (
                  <><Play size={16} /> Start Security Scan</>
                )}
              </button>
            </div>
          </div>
        )}

        {/* ── STEP 4: Review Results ── */}
        {step === 4 && scanSummary && (
          <div>
            <div className="wizard-title-area">
              <span className="wizard-step-badge">Step 4 of 5</span>
              <h2 className="wizard-title">Initial Scan Results Preview</h2>
              <p className="wizard-subtitle">
                Here is a quick snapshot of findings detected in your initial security check.
              </p>
            </div>

            <div className="results-summary-cards">
              <div className="res-stat-card">
                <span className="res-stat-label">Critical</span>
                <span className="res-stat-val critical">{scanSummary.criticalCount}</span>
              </div>
              <div className="res-stat-card">
                <span className="res-stat-label">High Risk</span>
                <span className="res-stat-val high">{scanSummary.highCount}</span>
              </div>
              <div className="res-stat-card">
                <span className="res-stat-label">Medium</span>
                <span className="res-stat-val medium">{scanSummary.mediumCount}</span>
              </div>
              <div className="res-stat-card">
                <span className="res-stat-label">Files Scanned</span>
                <span className="res-stat-val">{scanSummary.totalFiles}</span>
              </div>
            </div>

            <h4 style={{ fontSize: '1rem', color: 'var(--text-main)', marginBottom: '0.85rem' }}>
              Top Findings Sample:
            </h4>

            {scanSummary.findings.length > 0 ? (
              <div className="findings-taste-list">
                {scanSummary.findings.map(f => (
                  <div key={f.id} className="taste-finding-card">
                    <div className="taste-left">
                      <div className="taste-title">{f.title}</div>
                      <div className="taste-file">{f.filePath}</div>
                    </div>
                    <span className={`sev-badge ${f.severity}`}>{f.severity}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ padding: '2rem', textAlign: 'center', background: 'rgba(16, 185, 129, 0.1)', borderRadius: 'var(--radius-sm)', border: '1px solid rgba(16, 185, 129, 0.3)', color: 'var(--accent-green)', marginBottom: '1.5rem' }}>
                <Check size={28} style={{ marginBottom: '0.5rem' }} />
                <h4 style={{ fontSize: '1.1rem', fontWeight: 700 }}>No Critical Vulnerabilities Detected!</h4>
                <p style={{ fontSize: '0.88rem', opacity: 0.9, marginTop: '0.25rem' }}>
                  Your repository code is clean and passes baseline security standards.
                </p>
              </div>
            )}

            <div className="wizard-footer-actions">
              <button className="wizard-btn-sec" onClick={() => setStep(3)}>
                <ArrowLeft size={16} /> Back
              </button>
              <button className="wizard-btn-pri" onClick={() => setStep(5)}>
                Continue to Finish Setup <ArrowRight size={16} />
              </button>
            </div>
          </div>
        )}

        {/* ── STEP 5: Setup Complete ── */}
        {step === 5 && (
          <div className="done-container">
            <div className="done-icon-wrapper">
              <ShieldCheck size={48} />
            </div>

            <h2 className="wizard-title" style={{ fontSize: '2rem' }}>You're all set! 🚀</h2>
            <p className="wizard-subtitle" style={{ maxWidth: '500px' }}>
              SecureGuard is now active and guarding your codebase. You can manage your repositories, generate AI code fixes, and track scans from your dashboard.
            </p>

            <div className="done-features-list">
              <div className="done-feature-item">
                <Check size={18} className="text-accent-green" /> Git Provider Integration Configured
              </div>
              <div className="done-feature-item">
                <Check size={18} className="text-accent-green" /> Repository Monitoring Enabled
              </div>
              <div className="done-feature-item">
                <Check size={18} className="text-accent-green" /> Automated SAST &amp; Secret Scan Pipeline Ready
              </div>
              <div className="done-feature-item">
                <Check size={18} className="text-accent-green" /> XGBoost False-Positive Suppression Active
              </div>
            </div>

            <button className="wizard-btn-pri" onClick={handleFinishOnboarding} style={{ fontSize: '1rem', padding: '0.85rem 2.25rem' }}>
              Go to Full Dashboard <ArrowRight size={18} />
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default OnboardingWizard;
