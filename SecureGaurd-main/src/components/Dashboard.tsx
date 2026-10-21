import { useState, useEffect, useCallback } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import {
  Shield, LayoutDashboard, GitBranch, Search,
  ChevronDown, LogOut, AlertTriangle,
  CheckCircle2, XCircle, Clock, Activity,
  FileCode2, Zap, Settings, Database, BarChart3,
  Play, RefreshCw, Filter, ArrowUpRight,
  Plus, X, Trash2, Globe, FileCheck, Users, CreditCard, Layers
} from 'lucide-react';
import { useAuth, authFetch } from '../context/AuthContext';
import { useOrganization } from '../context/OrganizationContext';
import { OrganizationSwitcher } from './OrganizationSwitcher';
import { OrganizationSettingsModal } from './OrganizationSettingsModal';
import ComplianceReports from './ComplianceReports';
import SbomPage from './SbomPage';
import { filterVulns, filterRepos } from '../utils/vulnFilters';
import { fixedPercentage } from '../utils/vulnStats';
import { apiUrl } from '../config/api';
import {
  SEVERITY_FILTER_OPTIONS,
  SCAN_TYPE_FILTER_OPTIONS,
} from '../config/filterOptions';
import './Dashboard.css';

// Feature flag: severity-priority ranker (Day 6). Off by default — the
// AI Priority toggle below only renders when VITE_ENABLE_SEVERITY_RANK === 'true'.
const SEVERITY_RANK_ENABLED = import.meta.env.VITE_ENABLE_SEVERITY_RANK === 'true';

// ── Types ─────────────────────────────────────────────────────────────────────
interface Vulnerability {
  id: number;
  scanId: number;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  codeSnippet: string;
  status: 'open' | 'fixed' | 'ignored' | 'false_positive';
  cweId?: string;
  aiFix?: string;
  aiFixApplied?: boolean;
  description?: string;
  createdAt: string;
  mlFeatures?: any;
}

interface Scan {
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
  completedAt: string | null;
  createdAt: string;
  repository: {
    name: string;
  };
}

interface Repository {
  id: number;
  name: string;
  fullName: string;
  url: string;
  platform: string;
  language: string | null;
  riskLevel: 'none' | 'low' | 'medium' | 'high' | 'critical';
  scans: Array<{ status: string; createdAt: string }>;
  _count?: {
    scans: number;
  };
}

// ── Severity Badge ────────────────────────────────────────────────────────────
function SeverityBadge({ s }: { s: string }) {
  return <span className={`badge badge--${s.toLowerCase()}`}>{s.toUpperCase()}</span>;
}

// ── Status Badge ──────────────────────────────────────────────────────────────
function StatusBadge({ s }: { s: string }) {
  const icons = { open: XCircle, fixed: CheckCircle2, ignored: Clock, false_positive: Clock };
  const Icon = (icons as any)[s] || Clock;
  const labelMap: Record<string, string> = {
    open: 'Open',
    fixed: 'Fixed',
    ignored: 'Ignored',
    false_positive: 'False Positive'
  };
  return (
    <span className={`status-badge status-badge--${s}`}>
      <Icon size={12} /> {labelMap[s] || s}
    </span>
  );
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
export default function Dashboard() {
  const navigate = useNavigate();
  const { user, accessToken, loading: authLoading, refreshSession, logout } = useAuth();
  const { activeOrg, activeOrgId, activeRole, orgFetch } = useOrganization();
  
  // Navigation
  const [activeNav, setActiveNav] = useState('overview');
  const [isOrgSettingsOpen, setIsOrgSettingsOpen] = useState(false);
  const [orgSettingsTab, setOrgSettingsTab] = useState<'members' | 'invitations' | 'audit' | 'billing' | 'settings'>('billing');
  
  // DB Connected states
  const [repos, setRepos] = useState<Repository[]>([]);
  const [selectedRepo, setSelectedRepo] = useState<Repository | null>(null);
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [rankMode, setRankMode] = useState<'severity' | 'ai'>('severity');
  const [rankScores, setRankScores] = useState<Record<number, { score: number; band: string; fallback?: boolean }>>({});
  const [ranking, setRanking] = useState(false);
  const [rankDegraded, setRankDegraded] = useState(false);
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [stats, setStats] = useState({
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    total: 0,
    health: 100,
    filesScanned: 0,
    scanTime: 0
  });

  // UI Control states
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanFile, setScanFile] = useState('');
  const [filterSev, setFilterSev] = useState<string>('ALL');
  const [filterType, setFilterType] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [isConnectModalOpen, setIsConnectModalOpen] = useState(false);

  // New Repository Form Fields
  const [newRepoName, setNewRepoName] = useState('');
  const [newRepoFullName, setNewRepoFullName] = useState('');
  const [newRepoUrl, setNewRepoUrl] = useState('');
  const [newRepoLang, setNewRepoLang] = useState('TypeScript');
  const [newRepoPlatform, setNewRepoPlatform] = useState('github');

  // Integration States
  const [githubToken, setGithubToken] = useState('');
  const [gitlabToken, setGitlabToken] = useState('');
  const [hasGithubToken, setHasGithubToken] = useState(false);
  const [hasGitlabToken, setHasGitlabToken] = useState(false);
  const [remoteRepos, setRemoteRepos] = useState<any[]>([]);
  const [loadingRemote, setLoadingRemote] = useState(false);
  const [generatingFix, setGeneratingFix] = useState(false);

  // New PRD Missing Screen States
  const [isOnboardingOpen, setIsOnboardingOpen] = useState(false);
  const [onboardingStep, setOnboardingStep] = useState(1);
  const [isFullDetailOpen, setIsFullDetailOpen] = useState(false);
  const [fullDetailVuln, setFullDetailVuln] = useState<any | null>(null);

  // Guard — redirect if not authenticated or onboarding incomplete.
  // Wait for the AuthContext session-restore check first: on a page refresh
  // user starts as null while /me is still in flight; redirecting on that
  // would log the user out on every refresh.
  useEffect(() => {
    if (authLoading) return;
    if (!user) {
      navigate('/login');
    } else if (user.onboardingCompleted === false) {
      navigate('/onboarding');
    }
  }, [user, authLoading, navigate]);

  // Fetch initial repositories and stats whenever activeOrgId or token changes
  // Memoized so effects can safely list it as a dependency (react-hooks/exhaustive-deps)
  const fetchData = useCallback(async () => {
    if (!accessToken) return;
    try {
      // 1. Fetch repositories
      const reposRes = await orgFetch('/api/repos');
      if (reposRes.ok) {
        const reposData = await reposRes.json();
        setRepos(reposData);
        if (reposData.length > 0) {
          setSelectedRepo(reposData[0]);
        } else {
          setSelectedRepo(null);
        }
      }

      // 2. Fetch stats
      const statsRes = await orgFetch('/api/scans/stats/summary');
      if (statsRes.ok) {
        const statsData = await statsRes.json();
        setStats({
          critical: statsData.critical,
          high: statsData.high,
          medium: statsData.medium,
          low: statsData.low,
          total: statsData.total,
          health: statsData.health,
          filesScanned: statsData.lastScan?.totalFiles || 0,
          scanTime: statsData.lastScan?.durationMs || 0
        });
      }

      // 3. Fetch vulnerabilities
      const vulnsRes = await orgFetch('/api/vulnerabilities');
      if (vulnsRes.ok) {
        const vulnsData = await vulnsRes.json();
        setVulns(vulnsData);
        if (vulnsData.length > 0) {
          setSelectedVuln((prev: any) => {
            if (!prev) return vulnsData[0];
            const match = vulnsData.find((x: any) => x.id === prev.id);
            return match || vulnsData[0];
          });
        } else {
          setSelectedVuln(null);
        }
      }

      // 4. Fetch Scan logs
      const scansRes = await orgFetch('/api/scans');
      if (scansRes.ok) {
        const scansData = await scansRes.json();
        setScans(scansData);
      }

      // 5. Fetch integration tokens status
      const tokensRes = await orgFetch('/api/integration/tokens');
      if (tokensRes.ok) {
        const tokensData = await tokensRes.json();
        setHasGithubToken(tokensData.hasGithub);
        setHasGitlabToken(tokensData.hasGitlab);
      }
    } catch (err) {
      console.error('Error fetching dashboard data:', err);
    }
  }, [accessToken, orgFetch]);

  // (Initial data load is handled by the effect below, which also waits for user.)

  const handleSaveTokens = async (platform: 'github' | 'gitlab', tokenValue: string) => {
    if (!accessToken) return;
    try {
      const res = await authFetch(
        '/api/integration/tokens',
        {
          method: 'POST',
          body: JSON.stringify({
            [platform === 'github' ? 'githubToken' : 'gitlabToken']: tokenValue
          })
        },
        accessToken,
        refreshSession,
        () => accessToken
      );
      if (res.ok) {
        alert(`${platform.toUpperCase()} Token successfully updated!`);
        if (platform === 'github') setGithubToken('');
        if (platform === 'gitlab') setGitlabToken('');
        fetchData();
      } else {
        alert('Failed to update integration tokens.');
      }
    } catch (err) {
      console.error(err);
    }
  };

  const fetchRemoteRepos = useCallback(async (platform: 'github' | 'gitlab') => {
    if (!accessToken) return;
    setLoadingRemote(true);
    setRemoteRepos([]);
    try {
      const res = await orgFetch(`/api/integration/repos?platform=${platform}`);
      if (res.ok) {
        const data = await res.json();
        setRemoteRepos(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingRemote(false);
    }
  }, [accessToken, orgFetch]);

  useEffect(() => {
    if (user && accessToken && activeOrgId) {
      fetchData();
    }
  }, [user, accessToken, activeOrgId, fetchData]);

  useEffect(() => {
    if (isConnectModalOpen && (newRepoPlatform === 'github' || newRepoPlatform === 'gitlab')) {
      const hasToken = newRepoPlatform === 'github' ? hasGithubToken : hasGitlabToken;
      if (hasToken) {
        fetchRemoteRepos(newRepoPlatform);
      } else {
        setRemoteRepos([]);
      }
    } else {
      setRemoteRepos([]);
    }
  }, [isConnectModalOpen, newRepoPlatform, hasGithubToken, hasGitlabToken, fetchRemoteRepos]);

  // Seed default repository if none connected in active organization
  useEffect(() => {
    const seedDefaultRepo = async () => {
      if (user && accessToken && activeOrgId && repos.length === 0) {
        try {
          await orgFetch('/api/repos', {
            method: 'POST',
            body: JSON.stringify({
              name: 'secureguard-main',
              fullName: `${user.firstName.toLowerCase()}/secureguard-main`,
              url: `https://github.com/${user.firstName.toLowerCase()}/secureguard-main`,
              platform: 'github',
              language: 'TypeScript'
            })
          });
          fetchData();
        } catch (e) {
          console.error(e);
        }
      }
    };
    seedDefaultRepo();
  }, [repos, user, accessToken, activeOrgId, fetchData, orgFetch]);

  const handleLogout = async () => {
    await logout();
    navigate('/');
  };

  const handleAddRepo = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!accessToken) return;
    try {
      const res = await orgFetch('/api/repos', {
        method: 'POST',
        body: JSON.stringify({
          name: newRepoName,
          fullName: newRepoFullName || newRepoName,
          url: newRepoUrl,
          platform: newRepoPlatform,
          language: newRepoLang
        })
      });
      if (res.ok) {
        setIsConnectModalOpen(false);
        setNewRepoName('');
        setNewRepoFullName('');
        setNewRepoUrl('');
        fetchData();
      } else {
        const errData = await res.json();
        alert(errData.message || 'Failed to connect repository.');
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleDeleteRepo = async (id: number) => {
    if (!window.confirm('Are you sure you want to disconnect this repository?') || !accessToken) return;
    try {
      const res = await orgFetch(`/api/repos/${id}`, { method: 'DELETE' });
      if (res.ok) {
        if (selectedRepo?.id === id) {
          setSelectedRepo(null);
        }
        fetchData();
      } else {
        const errData = await res.json();
        alert(errData.message || 'Failed to delete repository.');
      }
    } catch (err) {
      console.error(err);
    }
  };

  const SCAN_FILES = [
    'auth/login.js', 'config/db.js', 'routes/user.js',
    'middleware/auth.js', 'utils/upload.js', 'services/payment.js',
    'controllers/admin.js', 'lib/crypto.js',
  ];

  const triggerScan = async () => {
    if (scanning || !selectedRepo || !accessToken) return;
    setScanning(true);
    setScanProgress(0);
    setScanFile('');

    let i = 0;
    const interval = setInterval(() => {
      i++;
      setScanFile(SCAN_FILES[Math.floor(Math.random() * SCAN_FILES.length)]);
      setScanProgress(Math.min(Math.round((i / 20) * 100), 100));
      if (i >= 20) {
        clearInterval(interval);
        
        (async () => {
          try {
            const res = await orgFetch('/api/scans/trigger', {
              method: 'POST',
              body: JSON.stringify({ repositoryId: selectedRepo.id })
            });
            if (res.ok) {
              await fetchData();
            }
          } catch (err) {
            console.error(err);
          } finally {
            setScanning(false);
            setScanProgress(100);
          }
        })();
      }
    }, 120);
  };

  const handleUpdateVulnStatus = async (vulnId: number, status: string) => {
    if (!accessToken) return;
    try {
      const res = await orgFetch(`/api/vulnerabilities/${vulnId}/status`, {
        method: 'PATCH',
        body: JSON.stringify({ status })
      });
      if (res.ok) {
        fetchData();
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleGenerateAiFix = async (vulnId: number) => {
    if (!accessToken) return;
    setGeneratingFix(true);
    try {
      const res = await orgFetch(`/api/ai/fix/${vulnId}`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setSelectedVuln((prev: any) => {
          if (prev && prev.id === vulnId) {
            return {
              ...prev,
              aiFix: data.fixedCode,
              description: data.explanation,
              cweId: data.cweId,
            };
          }
          return prev;
        });
        fetchData();
      } else {
        alert('Failed to generate AI fix.');
      }
    } catch (err) {
      console.error(err);
    } finally {
      setGeneratingFix(false);
    }
  };

  const handleApplyAiFix = async (vulnId: number) => {
    if (!accessToken) return;
    try {
      const res = await orgFetch(`/api/ai/fix/${vulnId}/apply`, { method: 'PATCH' });
      if (res.ok) {
        setSelectedVuln((prev: any) => {
          if (prev && prev.id === vulnId) {
            return { ...prev, aiFixApplied: true, status: 'fixed' };
          }
          return prev;
        });
        alert('AI Fix applied successfully!');
        fetchData();
      } else {
        alert('Failed to apply AI fix.');
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleMarkFalsePositive = async (vulnId: number) => {
    if (!accessToken) return;
    try {
      const res = await orgFetch(`/api/ai/false-positive/${vulnId}`, { method: 'PATCH' });
      if (res.ok) {
        setSelectedVuln((prev: any) => {
          if (prev && prev.id === vulnId) {
            return { ...prev, status: 'false_positive' };
          }
          return prev;
        });
        alert('Finding marked as false positive.');
        fetchData();
      } else {
        alert('Failed to update finding.');
      }
    } catch (err) {
      console.error(err);
    }
  };

  // ── Computations ──
  const totalCrit  = stats.critical;
  const totalHigh  = stats.high;
  const totalMed   = stats.medium;
  const totalLow   = stats.low;
  const totalVulns = totalCrit + totalHigh + totalMed + totalLow;

  // Degrees for Conic Gradient Donut Chart
  const critPct = totalVulns > 0 ? (totalCrit / totalVulns) * 360 : 0;
  const highPct = totalVulns > 0 ? ((totalCrit + totalHigh) / totalVulns) * 360 : 0;
  const medPct  = totalVulns > 0 ? ((totalCrit + totalHigh + totalMed) / totalVulns) * 360 : 0;

  // Filtering (predicates live in utils/vulnFilters.ts)
  const filteredVulns = filterVulns(vulns, filterSev, filterType, searchQuery);
  // AI-priority ordering (feature-flagged). Unscored findings (no stored
  // mlFeatures) keep their relative order at the end of the list.
  const displayedVulns = rankMode === 'ai'
    ? [...filteredVulns].sort((a, b) => {
        const sa = rankScores[a.id]?.score;
        const sb = rankScores[b.id]?.score;
        if (sa == null && sb == null) return 0;
        if (sa == null) return 1;
        if (sb == null) return -1;
        return sb - sa;
      })
    : filteredVulns;

  const toggleRankMode = useCallback(async () => {
    if (rankMode === 'ai') { setRankMode('severity'); return; }
    const ids = filteredVulns.map((v) => v.id);
    if (ids.length === 0) return;
    setRanking(true);
    try {
      const res = await orgFetch('/api/v2/ml/rank', {
        method: 'POST',
        body: JSON.stringify({ vulnerabilityIds: ids }),
      });
      if (!res.ok) return;
      const data = await res.json();
      const scores: Record<number, { score: number; band: string; fallback?: boolean }> = {};
      for (const r of data.ranked || []) {
        scores[r.id] = { score: r.priority_score, band: r.band, fallback: r.fallback };
      }
      setRankScores(scores);
      setRankDegraded(!!data.degraded);
      setRankMode('ai');
    } catch {
      // Network/auth failure: stay on severity order; nothing to roll back.
    } finally {
      setRanking(false);
    }
  }, [rankMode, filteredVulns, orgFetch]);

  const filteredRepos = filterRepos(repos, searchQuery);

  const CI_CD_YAML = [
    'name: SecureGuard Security Scan',
    '',
    'on:',
    '  pull_request:',
    '    branches: [main, develop]',
    '',
    'jobs:',
    '  security-scan:',
    '    runs-on: ubuntu-latest',
    '    steps:',
    '      - uses: actions/checkout@v3',
    '      - name: Trigger SecureGuard Scan',
    '        run: |',
    '          curl -X POST https://YOUR_SECUREGUARD_URL/api/integration/webhook/github \\',
    '            -H "Content-Type: application/json" \\',
    "            -d '{ \"repository\": { \"full_name\": \"$GH_REPO\" }, \"after\": \"$GH_SHA\", \"ref\": \"refs/heads/$GH_BRANCH\" }'",
  ].join('\n');

  if (!user) return null;

  return (
    <div className="dash-root">
      {/* ── Sidebar ── */}
      <aside className="dash-sidebar">
        <div className="dash-brand">
          <Link to="/" className="dash-brand-logo">
            <Shield size={22} className="brand-shield" />
            <span>Secure<strong>Guard</strong></span>
          </Link>
        </div>

        <nav className="dash-nav">
          <button
            className={`dash-nav-item ${activeNav === 'overview' ? 'active' : ''}`}
            onClick={() => setActiveNav('overview')}
          >
            <LayoutDashboard size={17} />
            <span>Overview</span>
          </button>
          <button
            className={`dash-nav-item ${activeNav === 'repos' ? 'active' : ''}`}
            onClick={() => setActiveNav('repos')}
          >
            <GitBranch size={17} />
            <span>Repositories</span>
            {repos.length > 0 && <span className="nav-badge">{repos.length}</span>}
          </button>
          <button
            className={`dash-nav-item ${activeNav === 'scans' ? 'active' : ''}`}
            onClick={() => setActiveNav('scans')}
          >
            <Shield size={17} />
            <span>Security Scans</span>
            {scans.length > 0 && <span className="nav-badge" style={{background: 'var(--accent-blue)'}}>{scans.length}</span>}
          </button>
          <button
            className={`dash-nav-item ${activeNav === 'vulndb' ? 'active' : ''}`}
            onClick={() => setActiveNav('vulndb')}
          >
            <Database size={17} />
            <span>Vuln Database</span>
            {stats.total > 0 && <span className="nav-badge">{stats.total}</span>}
          </button>
          <button
            className={`dash-nav-item ${activeNav === 'analytics' ? 'active' : ''}`}
            onClick={() => setActiveNav('analytics')}
          >
            <BarChart3 size={17} />
            <span>Analytics</span>
          </button>
          <button
            className={`dash-nav-item ${activeNav === 'compliance' ? 'active' : ''}`}
            onClick={() => setActiveNav('compliance')}
          >
            <FileCheck size={17} />
            <span>Compliance Reports</span>
          </button>
          <button
            className={`dash-nav-item ${activeNav === 'sbom' ? 'active' : ''}`}
            onClick={() => setActiveNav('sbom')}
          >
            <Layers size={17} />
            <span>Software SBOM</span>
          </button>
          <button
            className="dash-nav-item"
            onClick={() => { setOrgSettingsTab('members'); setIsOrgSettingsOpen(true); }}
          >
            <Users size={17} />
            <span>Team & Members</span>
          </button>
          <button
            className="dash-nav-item"
            onClick={() => { setOrgSettingsTab('billing'); setIsOrgSettingsOpen(true); }}
          >
            <CreditCard size={17} />
            <span>Billing & Usage</span>
          </button>
          <button
            className={`dash-nav-item ${activeNav === 'settings' ? 'active' : ''}`}
            onClick={() => setActiveNav('settings')}
          >
            <Settings size={17} />
            <span>Settings</span>
          </button>
        </nav>

        <div className="dash-sidebar-footer">
          <div className="dash-user-pill">
            <div className="dash-user-avatar">
              {user.firstName[0]}{user.lastName[0]}
            </div>
            <div className="dash-user-info">
              <p className="dash-user-name">{user.firstName} {user.lastName}</p>
              <p className="dash-user-email">{user.email}</p>
            </div>
            <button className="dash-logout-btn" onClick={handleLogout} title="Logout">
              <LogOut size={15} />
            </button>
          </div>
        </div>
      </aside>

      {/* ── Main ── */}
      <main className="dash-main">
        {/* Header */}
        <header className="dash-header">
          <div className="dash-header-left">
            <h1 className="dash-page-title">
              {activeNav === 'overview' && 'Security Overview'}
              {activeNav === 'repos' && 'Repositories'}
              {activeNav === 'scans' && 'Scan Log History'}
              {activeNav === 'vulndb' && 'Vulnerability Database'}
              {activeNav === 'analytics' && 'Analytics'}
              {activeNav === 'compliance' && 'Compliance Reports'}
              {activeNav === 'settings' && 'Account Settings'}
            </h1>
            <p className="dash-page-sub">
              {activeNav === 'overview' && (
                <>
                  Monitoring{' '}
                  {selectedRepo ? (
                    <button className="repo-switcher">
                      {selectedRepo.name} <ChevronDown size={14} />
                    </button>
                  ) : (
                    <span className="highlight">No repos connected</span>
                  )}
                </>
              )}
              {activeNav === 'repos' && 'Manage your integrated code repositories'}
              {activeNav === 'scans' && 'Timeline of evaluated codebase scan audits'}
              {activeNav === 'vulndb' && 'Exploration index of all detected system vulnerabilities'}
              {activeNav === 'analytics' && 'Interactive vulnerability and risk reporting breakdowns'}
              {activeNav === 'compliance' && 'Generate security compliance reports from your organization\'s scan results'}
              {activeNav === 'settings' && 'Manage passwords and workspace configurations'}
            </p>
          </div>
          <div className="dash-header-right">
            <OrganizationSwitcher onOpenSettings={() => setIsOrgSettingsOpen(true)} />
            <div className="dash-search">
              <Search size={15} />
              <input 
                type="text" 
                placeholder={activeNav === 'repos' ? 'Search repos…' : 'Search files, vulns…'} 
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
              />
            </div>
            {activeNav === 'overview' && (
              <button
                className={`scan-trigger-btn ${scanning ? 'scanning' : ''}`}
                onClick={triggerScan}
                disabled={scanning || !selectedRepo}
              >
                {scanning ? (
                  <><RefreshCw size={15} className="spin-icon" /> Scanning…</>
                ) : (
                  <><Play size={15} /> Trigger Scan</>
                )}
              </button>
            )}
            {activeNav === 'repos' && (
              <button className="connect-repo-btn" onClick={() => setIsConnectModalOpen(true)}>
                <Plus size={15} /> Connect Repository
              </button>
            )}
          </div>
        </header>

        {/* Scan Progress Bar */}
        {scanning && activeNav === 'overview' && (
          <div className="scan-progress-bar-wrap">
            <div className="scan-progress-meta">
              <Activity size={13} className="spin-icon" />
              <span>Scanning <code>{scanFile}</code></span>
              <span className="scan-pct">{scanProgress}%</span>
            </div>
            <div className="scan-progress-track">
              <div className="scan-progress-fill" style={{ width: `${scanProgress}%` }} />
            </div>
          </div>
        )}

        {/* ── Tab: Overview ── */}
        {activeNav === 'overview' && (
          <>
            {/* Stats Row */}
            <div className="stats-grid">
              <div className="stat-card">
                <div className="stat-top">
                  <span className="stat-label">Health Score</span>
                  <Activity size={16} className="stat-icon" />
                </div>
                <div className="stat-value" style={{ color: stats.health > 60 ? 'var(--accent-green)' : 'var(--accent-red)' }}>
                  {stats.health}<span className="stat-unit">/100</span>
                </div>
                <div className="stat-bar-wrap">
                  <div className="stat-bar" style={{ width: `${stats.health}%`, background: stats.health > 60 ? 'var(--accent-green)' : 'var(--accent-red)' }} />
                </div>
              </div>
              <div className="stat-card">
                <div className="stat-top">
                  <span className="stat-label">Critical</span>
                  <XCircle size={16} style={{ color: 'var(--accent-red)' }} />
                </div>
                <div className="stat-value" style={{ color: 'var(--accent-red)' }}>{stats.critical}</div>
                <p className="stat-hint">Requires immediate action</p>
              </div>
              <div className="stat-card">
                <div className="stat-top">
                  <span className="stat-label">High / Medium</span>
                  <AlertTriangle size={16} style={{ color: 'var(--accent-yellow)' }} />
                </div>
                <div className="stat-value" style={{ color: 'var(--accent-yellow)' }}>
                  {stats.high}<span className="stat-sep">/</span>{stats.medium}
                </div>
                <p className="stat-hint">Review when possible</p>
              </div>
              <div className="stat-card">
                <div className="stat-top">
                  <span className="stat-label">Files Scanned</span>
                  <FileCode2 size={16} className="stat-icon" />
                </div>
                <div className="stat-value">{stats.filesScanned > 0 ? stats.filesScanned.toLocaleString() : '0'}</div>
                <p className="stat-hint">Ephemerally evaluated</p>
              </div>
              <div className="stat-card">
                <div className="stat-top">
                  <span className="stat-label">Avg Scan Time</span>
                  <Zap size={16} className="stat-icon" />
                </div>
                <div className="stat-value">
                  {stats.scanTime > 0 ? (stats.scanTime / 1000).toFixed(2) : '0.00'}
                  <span className="stat-unit">s</span>
                </div>
                <p className="stat-hint">Lightning fast detection</p>
              </div>
            </div>

            {/* Main Content: Table + Detail Panel */}
            <div className="dash-content-row">
              <section className="vuln-section">
                <div className="vuln-section-head">
                  <div>
                    <h2 className="section-title">Detected Issues</h2>
                    <p className="section-sub">{filteredVulns.length} vulnerabilities found{rankMode === 'ai' && (rankDegraded ? ' · fallback order (classifier unreachable)' : ' · AI priority order')}</p>
                  </div>
                  <div className="vuln-filters" style={{ flexWrap: 'wrap', gap: '6px' }}>
                    <Filter size={14} />
                    {SEVERITY_FILTER_OPTIONS.map(s => (
                      <button
                        key={s}
                        className={`filter-btn ${filterSev === s ? 'active' : ''}`}
                        onClick={() => setFilterSev(s)}
                      >
                        {s}
                      </button>
                    ))}
                    <div style={{ height: '16px', width: '1px', background: 'var(--border-color)', margin: '0 2px' }} />
                    {SCAN_TYPE_FILTER_OPTIONS.map(t => (
                      <button
                        key={t}
                        className={`filter-btn ${filterType === t ? 'active' : ''}`}
                        onClick={() => setFilterType(t)}
                      >
                        {t}
                      </button>
                    ))}
                    {SEVERITY_RANK_ENABLED && (
                      <>
                        <div style={{ height: '16px', width: '1px', background: 'var(--border-color)', margin: '0 2px' }} />
                        <button
                          className={`filter-btn ${rankMode === 'ai' ? 'active' : ''}`}
                          onClick={toggleRankMode}
                          disabled={ranking}
                          title={rankMode === 'ai' ? 'Back to severity order' : 'Sort by AI priority score (severity-priority ranker)'}
                        >
                          {ranking ? 'Ranking...' : 'AI Priority'}
                        </button>
                      </>
                    )}
                  </div>
                </div>

                <div className="vuln-table-wrap">
                  {displayedVulns.length > 0 ? (
                    <table className="vuln-table">
                      <thead>
                        <tr>
                          <th>ID</th>
                          <th>File</th>
                          <th>Type</th>
                          <th>Severity</th>
                          <th>Status</th>
                          <th></th>
                        </tr>
                      </thead>
                      <tbody>
                        {displayedVulns.map(v => (
                          <tr
                            key={v.id}
                            className={`vuln-row ${selectedVuln?.id === v.id ? 'vuln-row--active' : ''}`}
                            onClick={() => setSelectedVuln(v)}
                            onDoubleClick={() => navigate(`/vulnerabilities/${v.id}`)}
                          >
                            <td><code className="vuln-id" style={{cursor: 'pointer'}} onClick={() => navigate(`/vulnerabilities/${v.id}`)}>V-{String(v.id).padStart(3, '0')}</code></td>
                            <td><span className="vuln-file"><FileCode2 size={13} />{v.filePath}</span></td>
                            <td><span style={{cursor: 'pointer', fontWeight: 600, color: '#e0e7ff'}} onClick={() => navigate(`/vulnerabilities/${v.id}`)}>{v.title}</span></td>
                            <td><SeverityBadge s={v.severity} />
                              {rankMode === 'ai' && rankScores[v.id] != null && (
                                <span
                                  title={`AI priority score: ${rankScores[v.id].score} (${rankScores[v.id].band})`}
                                  style={{ marginLeft: 6, fontSize: 11, padding: '2px 6px', borderRadius: 999, background: 'rgba(129,140,248,0.15)', color: '#a5b4fc', border: '1px solid rgba(129,140,248,0.35)', verticalAlign: 'middle' }}
                                >
                                  {rankScores[v.id].score.toFixed(0)}
                                </span>
                              )}</td>
                            <td><StatusBadge s={v.status} /></td>
                            <td>
                              <button className="row-action-btn" title="View Full Details" onClick={e => { e.stopPropagation(); navigate(`/vulnerabilities/${v.id}`); }}>
                                <ArrowUpRight size={14} />
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <div className="vuln-empty-state" style={{padding: '3rem', textAlign: 'center'}}>
                      <CheckCircle2 size={40} style={{color: 'var(--accent-green)', marginBottom: '1rem'}} />
                      <h3>No vulnerabilities detected</h3>
                      <p style={{color: 'var(--text-dim)', fontSize: '0.85rem', marginTop: '0.25rem'}}>Trigger a scan to run SecureGuard SAST analysis on your code.</p>
                    </div>
                  )}
                </div>
              </section>

              {/* Detail Panel */}
              {selectedVuln && (
                <aside className="detail-panel">
                  <div className="detail-header">
                    <div>
                      <p className="detail-label">Vulnerability Detail</p>
                      <h3 className="detail-title">{selectedVuln.title}</h3>
                    </div>
                    <SeverityBadge s={selectedVuln.severity} />
                  </div>

                  <div className="detail-meta-grid">
                    <div className="detail-meta-item">
                      <span className="detail-meta-key">File</span>
                      <span className="detail-meta-val">{selectedVuln.filePath}</span>
                    </div>
                    <div className="detail-meta-item">
                      <span className="detail-meta-key">Line</span>
                      <span className="detail-meta-val">{selectedVuln.lineStart > 0 ? `#${selectedVuln.lineStart}` : '—'}</span>
                    </div>
                    <div className="detail-meta-item">
                      <span className="detail-meta-key">Status</span>
                      <StatusBadge s={selectedVuln.status} />
                    </div>
                    <div className="detail-meta-item">
                      <span className="detail-meta-key">Type</span>
                      <span className="detail-meta-val">{selectedVuln.type.toUpperCase()}</span>
                    </div>
                  </div>

                  {selectedVuln.codeSnippet && (
                    <>
                      <div className="detail-code-label">
                        <FileCode2 size={13} /> Code Snippet — Line {selectedVuln.lineStart}
                      </div>
                      <div className="detail-code-block">
                        <div className="code-line-num">{selectedVuln.lineStart}</div>
                        <code className="code-snippet">{selectedVuln.codeSnippet}</code>
                      </div>
                    </>
                  )}

                  {selectedVuln.mlFeatures && (
                    <div className="ml-explanation-section" style={{
                      marginTop: '1rem',
                      marginBottom: '1rem',
                      padding: '1rem',
                      background: 'rgba(59, 130, 246, 0.05)',
                      borderRadius: '8px',
                      border: '1px dashed rgba(59, 130, 246, 0.2)'
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                        <span style={{ fontSize: '0.8rem', fontWeight: 600, color: '#60a5fa', display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <Shield size={14} /> ML FP Suppressor
                        </span>
                        <span className={`status-badge status-badge--${selectedVuln.mlFeatures.ml_prediction === 'FALSE_POSITIVE' ? 'ignored' : 'open'}`} style={{ fontSize: '0.7rem', padding: '2px 6px' }}>
                          {selectedVuln.mlFeatures.ml_prediction === 'FALSE_POSITIVE' ? 'SUPPRESSED (FP)' : 'CONFIRMED REAL'}
                        </span>
                      </div>
                      <p style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.7)', margin: '0 0 0.5rem 0' }}>
                        Risk Probability: <strong style={{ color: selectedVuln.mlFeatures.ml_prediction === 'FALSE_POSITIVE' ? '#34d399' : '#f87171' }}>{(selectedVuln.mlFeatures.ml_confidence * 100).toFixed(1)}%</strong>
                      </p>
                      {selectedVuln.mlFeatures.ml_explanation && selectedVuln.mlFeatures.ml_explanation.length > 0 && (
                        <ul style={{ paddingLeft: '1.2rem', margin: 0, fontSize: '0.72rem', color: '#cbd5e1', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                          {selectedVuln.mlFeatures.ml_explanation.map((exp: string, idx: number) => (
                            <li key={idx}>{exp}</li>
                          ))}
                        </ul>
                      )}
                    </div>
                  )}

                  {/* AI Remediation Section */}
                  <div className="ai-fix-section">
                    <div className="ai-fix-header">
                      <span className="ai-fix-label">
                        <Zap size={14} style={{ fill: '#a78bfa' }} />
                        AI Remediation
                      </span>
                      <span className="ai-badge">SECUREGUARD AI</span>
                    </div>

                    {selectedVuln.aiFix ? (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                        <p style={{ fontSize: '0.8rem', color: '#ddd', lineHeight: '1.4' }}>
                          {selectedVuln.description || 'AI analyzed fix generated for this vulnerability.'}
                        </p>

                        <div className="ai-meta-row">
                          {selectedVuln.cweId && (
                            <span className="ai-meta-chip">{selectedVuln.cweId}</span>
                          )}
                          <span className="ai-meta-chip ai-meta-chip--green">CVSS 8.5</span>
                        </div>

                        <div className="ai-diff-wrap">
                          <div className="ai-diff-header">
                            <span>Suggested Code Diff</span>
                            <span style={{color: 'var(--text-dim)'}}>Remediation</span>
                          </div>
                          <div className="ai-diff-body">
                            <span className="diff-line-old">- {selectedVuln.codeSnippet}</span>
                            <span className="diff-line-new">+ {selectedVuln.aiFix}</span>
                          </div>
                        </div>

                        <div className="ai-action-row">
                          {selectedVuln.aiFixApplied ? (
                            <div className="ai-applied-badge">
                              <CheckCircle2 size={13} />
                              AI Fix Applied
                            </div>
                          ) : (
                            <>
                              <button
                                className="ai-apply-btn"
                                onClick={() => handleApplyAiFix(selectedVuln.id)}
                              >
                                <CheckCircle2 size={13} /> Apply Fix
                              </button>
                              <button
                                className="ai-fp-btn"
                                onClick={() => handleMarkFalsePositive(selectedVuln.id)}
                              >
                                False Positive
                              </button>
                            </>
                          )}
                        </div>
                      </div>
                    ) : (
                      <div>
                        <button
                          className="ai-generate-btn"
                          onClick={() => handleGenerateAiFix(selectedVuln.id)}
                          disabled={generatingFix}
                        >
                          {generatingFix ? (
                            <><RefreshCw size={13} className="spin-icon" /> Generating Fix...</>
                          ) : (
                            <><Zap size={13} /> Generate AI Fix</>
                          )}
                        </button>
                      </div>
                    )}
                  </div>

                  <div className="detail-actions" style={{ borderTop: '1px solid var(--border-color)', paddingTop: '1rem', marginTop: '0.5rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    <button 
                      className="detail-action-btn detail-action-btn--primary"
                      style={{ background: 'linear-gradient(135deg, #6366f1 0%, #4f46e5 100%)', color: '#fff', fontWeight: 600 }}
                      onClick={() => navigate(`/vulnerabilities/${selectedVuln.id}`)}
                    >
                      <ArrowUpRight size={14} /> Open Full Details Page
                    </button>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
                      {selectedVuln.status === 'open' ? (
                        <>
                          <button 
                            className="detail-action-btn"
                            style={{ background: 'rgba(16, 185, 129, 0.15)', color: '#34d399', border: '1px solid rgba(16, 185, 129, 0.3)' }}
                            onClick={() => handleUpdateVulnStatus(selectedVuln.id, 'fixed')}
                          >
                            <CheckCircle2 size={13} /> Resolve
                          </button>
                          <button 
                            className="detail-action-btn"
                            onClick={() => handleUpdateVulnStatus(selectedVuln.id, 'ignored')}
                          >
                            Ignore
                          </button>
                        </>
                      ) : (
                        <button 
                          className="detail-action-btn"
                          style={{ gridColumn: 'span 2' }}
                          onClick={() => handleUpdateVulnStatus(selectedVuln.id, 'open')}
                        >
                          Reopen Finding
                        </button>
                      )}
                    </div>
                  </div>
                </aside>
              )}
            </div>

            {/* Scan Activity Section */}
            <section className="activity-section">
              <h2 className="section-title">Scan Activity</h2>
              <div className="activity-chart">
                {[4, 8, 3, 12, 6, 9, 2, 7, 5, 11, 3, 8, stats.critical + stats.high].map((h, i) => (
                  <div key={i} className="activity-col">
                    <div
                      className="activity-bar"
                      style={{
                        height: `${Math.max(8, (h / 13) * 100)}%`,
                        background: i === 12
                          ? 'var(--accent-blue)'
                          : h > 8
                            ? 'rgba(239,68,68,0.5)'
                            : 'rgba(255,255,255,0.1)',
                      }}
                      title={`${h} issues`}
                    />
                    <span className="activity-label">{['M', 'T', 'W', 'T', 'F', 'S', 'S', 'M', 'T', 'W', 'T', 'F', 'Now'][i]}</span>
                  </div>
                ))}
              </div>
            </section>
          </>
        )}

        {/* ── Tab: Repositories ── */}
        {activeNav === 'repos' && (
          <div className="repos-grid-container">
            <div className="tab-section-header">
              <h2 className="tab-title">Connected Code Repositories ({filteredRepos.length})</h2>
            </div>
            
            <div className="repos-grid">
              {filteredRepos.map(r => (
                <div key={r.id} className="repo-card">
                  <div className="repo-card-header">
                    <div className="repo-card-title-wrap">
                      <a href={r.url} target="_blank" rel="noopener noreferrer" className="repo-card-name">
                        {r.name}
                      </a>
                      <span className="repo-card-fullname">{r.fullName}</span>
                    </div>
                    {r.platform === 'github' ? (
                      <GitBranch size={20} className="brand-shield" />
                    ) : (
                      <Globe size={20} className="brand-shield" />
                    )}
                  </div>

                  <div className="repo-badge-row">
                    <span className="repo-platform-badge">{r.platform}</span>
                    {r.language && <span className="repo-lang-badge">{r.language}</span>}
                    <span className={`badge badge--${r.riskLevel.toLowerCase()}`}>
                      Risk: {r.riskLevel}
                    </span>
                  </div>

                  <div className="repo-card-body">
                    <div className="repo-meta-row">
                      <span>Total Scans:</span>
                      <span className="highlight">{r._count?.scans || 0}</span>
                    </div>
                    <div className="repo-meta-row">
                      <span>Integration Status:</span>
                      <span className="highlight" style={{color: 'var(--accent-green)'}}>Active</span>
                    </div>
                  </div>

                  <div className="repo-card-actions">
                    <button 
                      className="repo-action-btn-small"
                      onClick={() => {
                        setSelectedRepo(r);
                        setActiveNav('overview');
                        triggerScan();
                      }}
                    >
                      <Play size={12} /> Scan Now
                    </button>
                    <button 
                      className="repo-action-btn-small repo-delete-btn"
                      onClick={() => handleDeleteRepo(r.id)}
                    >
                      <Trash2 size={12} /> Disconnect
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── Tab: Security Scans ── */}
        {activeNav === 'scans' && (
          <div className="scans-tab-container">
            <div className="tab-section-header">
              <h2 className="tab-title font-heading">Security Audit Scan Logs</h2>
            </div>

            <table className="scan-history-table">
              <thead>
                <tr>
                  <th>Scan ID</th>
                  <th>Repository</th>
                  <th>Branch</th>
                  <th>Status</th>
                  <th>Vulnerability Summary</th>
                  <th>Files Scanned</th>
                  <th>Duration</th>
                  <th>Evaluated On</th>
                </tr>
              </thead>
              <tbody>
                {scans.map(s => (
                  <tr key={s.id}>
                    <td><code>#S-{String(s.id).padStart(4, '0')}</code></td>
                    <td><span className="highlight">{s.repository.name}</span></td>
                    <td><span className="scan-commit-link">{s.branch}</span></td>
                    <td>
                      <span className="status-badge status-badge--resolved" style={{
                        background: s.status === 'completed' ? 'rgba(16,185,129,0.1)' : 'rgba(239,68,68,0.1)',
                        color: s.status === 'completed' ? 'var(--accent-green)' : 'var(--accent-red)'
                      }}>
                        {s.status.toUpperCase()}
                      </span>
                    </td>
                    <td>
                      {s.criticalCount > 0 && <span className="severity-pill-count severity-pill-count--critical">{s.criticalCount} Critical</span>}
                      {s.highCount > 0 && <span className="severity-pill-count severity-pill-count--high">{s.highCount} High</span>}
                      {s.mediumCount > 0 && <span className="severity-pill-count severity-pill-count--medium">{s.mediumCount} Med</span>}
                      {s.lowCount > 0 && <span className="severity-pill-count severity-pill-count--low">{s.lowCount} Low</span>}
                      {s.criticalCount + s.highCount + s.mediumCount + s.lowCount === 0 && (
                        <span className="status-badge status-badge--resolved">Clean Scan</span>
                      )}
                    </td>
                    <td>{s.totalFiles} files</td>
                    <td>{(s.durationMs / 1000).toFixed(2)}s</td>
                    <td>{new Date(s.createdAt).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* ── Tab: Vuln Database ── */}
        {activeNav === 'vulndb' && (
          <div className="scans-tab-container">
            <div className="tab-section-header">
              <h2 className="tab-title">Vulnerability Master Database ({filteredVulns.length})</h2>
              <div className="vuln-filters">
                <Filter size={14} />
                {SEVERITY_FILTER_OPTIONS.map(s => (
                  <button
                    key={s}
                    className={`filter-btn ${filterSev === s ? 'active' : ''}`}
                    onClick={() => setFilterSev(s)}
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>

            <table className="scan-history-table">
              <thead>
                <tr>
                  <th>Vulnerability ID</th>
                  <th>Title / CWE</th>
                  <th>Severity</th>
                  <th>Affected File</th>
                  <th>Vulnerable Line</th>
                  <th>Current Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredVulns.map(v => (
                  <tr key={v.id}>
                    <td><code>V-{String(v.id).padStart(4, '0')}</code></td>
                    <td><span className="highlight">{v.title}</span></td>
                    <td><SeverityBadge s={v.severity} /></td>
                    <td><span className="repo-card-fullname">{v.filePath}</span></td>
                    <td><code>Line {v.lineStart}</code></td>
                    <td><StatusBadge s={v.status} /></td>
                    <td>
                      <button 
                        className="connect-repo-btn" 
                        style={{padding: '4px 10px', fontSize: '0.75rem', display: 'inline-flex', alignItems: 'center', gap: '4px'}}
                        onClick={() => navigate(`/vulnerabilities/${v.id}`)}
                      >
                        <ArrowUpRight size={13} /> View Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* ── Tab: Analytics ── */}
        {activeNav === 'analytics' && (
          <div className="analytics-container">
            <h2 className="tab-title">Security Risk Intelligence Report</h2>

            <div className="analytics-top-grid">
              {/* Donut Chart Card */}
              <div className="analytics-card">
                <h3 className="analytics-card-title">Severity Breakdown</h3>
                <div className="donut-chart-wrapper">
                  <div 
                    className="donut-chart-ring"
                    style={{
                      '--crit-deg': `${critPct}deg`,
                      '--high-deg': `${highPct}deg`,
                      '--med-deg': `${medPct}deg`,
                    } as React.CSSProperties}
                  >
                    <div className="donut-chart-hole">
                      <span className="donut-chart-value">{totalVulns}</span>
                      <span className="donut-chart-label">Issues</span>
                    </div>
                  </div>

                  <div className="donut-chart-legend">
                    <div className="legend-item">
                      <div className="legend-color" style={{background: '#f87171'}} />
                      <span>Critical ({totalCrit})</span>
                    </div>
                    <div className="legend-item">
                      <div className="legend-color" style={{background: '#fbbf24'}} />
                      <span>High ({totalHigh})</span>
                    </div>
                    <div className="legend-item">
                      <div className="legend-color" style={{background: '#fcd34d'}} />
                      <span>Medium ({totalMed})</span>
                    </div>
                    <div className="legend-item">
                      <div className="legend-color" style={{background: '#34d399'}} />
                      <span>Low ({totalLow})</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* SAST Security Summary */}
              <div className="analytics-card" style={{display: 'flex', flexDirection: 'column', gap: '1.2rem'}}>
                <h3 className="analytics-card-title">Vulnerability Remediation Health</h3>
                <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1.5rem'}}>
                  <div className="stat-card" style={{border: '1px solid var(--border-color)', borderRadius: '8px'}}>
                    <span className="stat-label">Security Health</span>
                    <span className="stat-value">{stats.health}%</span>
                  </div>
                  <div className="stat-card" style={{border: '1px solid var(--border-color)', borderRadius: '8px'}}>
                    <span className="stat-label">Fixed Finding Pct</span>
                    <span className="stat-value" style={{color: 'var(--accent-green)'}}>
                      {fixedPercentage(vulns, totalVulns)}%
                    </span>
                  </div>
                  <div className="stat-card" style={{border: '1px solid var(--border-color)', borderRadius: '8px'}}>
                    <span className="stat-label">Risk Rating</span>
                    <span className="stat-value" style={{color: stats.health > 80 ? 'var(--accent-green)' : stats.health > 50 ? 'var(--accent-yellow)' : 'var(--accent-red)'}}>
                      {stats.health > 80 ? 'A' : stats.health > 50 ? 'B' : 'F'}
                    </span>
                  </div>
                </div>

                <div style={{marginTop: '1rem'}}>
                  <h4 style={{fontSize: '0.85rem', fontWeight: '700', marginBottom: '0.5rem'}}>Mitigation Recommendations</h4>
                  <ul style={{fontSize: '0.8rem', color: 'var(--text-dim)', paddingLeft: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.4rem'}}>
                    <li>Ensure all Critical severity tokens and hardcoded secrets are rotated immediately.</li>
                    <li>Verify inputs in routes using parametrized queries to eliminate SQL injections.</li>
                    <li>Update Axios or other HTTP handlers to enforce secure CORS/HSTS configurations.</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ── Tab: Settings ── */}
        {activeNav === 'settings' && (
          <div className="settings-container">
            <h2 className="tab-title">Settings</h2>

            <div className="settings-card">
              <h3 className="settings-section-title">User Information</h3>
              <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', fontSize: '0.85rem'}}>
                <div>
                  <span style={{color: 'var(--text-dim)', display: 'block', fontSize: '0.75rem', textTransform: 'uppercase', marginBottom: '2px'}}>First Name</span>
                  <span className="highlight">{user.firstName}</span>
                </div>
                <div>
                  <span style={{color: 'var(--text-dim)', display: 'block', fontSize: '0.75rem', textTransform: 'uppercase', marginBottom: '2px'}}>Last Name</span>
                  <span className="highlight">{user.lastName}</span>
                </div>
                <div style={{gridColumn: 'span 2'}}>
                  <span style={{color: 'var(--text-dim)', display: 'block', fontSize: '0.75rem', textTransform: 'uppercase', marginBottom: '2px'}}>Email Address</span>
                  <span className="highlight">{user.email}</span>
                </div>
              </div>
            </div>

            {/* GitHub Integration */}
            <div className="settings-card">
              <h3 className="settings-section-title">GitHub Integration</h3>
              <div style={{display:'flex', alignItems:'center', gap:'0.5rem', marginBottom:'0.75rem'}}>
                <span style={{fontSize:'0.8rem', color:'var(--text-dim)'}}>Status:</span>
                <span style={{fontSize:'0.8rem', fontWeight:700, color: hasGithubToken ? 'var(--accent-green)' : 'var(--text-dim)'}}>
                  {hasGithubToken ? '✓ Connected' : 'Not Connected'}
                </span>
              </div>
              <p style={{fontSize:'0.8rem', color:'var(--text-dim)', marginBottom:'0.75rem'}}>
                Enter a GitHub Personal Access Token (PAT) with <code>repo</code> scope to enable one-click repo import and webhook auto-scans.
              </p>
              <div style={{display:'flex', gap:'0.5rem'}}>
                <input
                  type="password"
                  placeholder={hasGithubToken ? '••••••••••••••••• (already set)' : 'ghp_xxxxxxxxxxxxxxxxxxxx'}
                  value={githubToken}
                  onChange={e => setGithubToken(e.target.value)}
                  style={{background:'var(--bg-card)', border:'1px solid var(--border-color)', padding:'0.6rem', color:'#fff', borderRadius:'6px', flex:1, fontSize:'0.82rem'}}
                />
                <button
                  className="connect-repo-btn"
                  onClick={() => githubToken && handleSaveTokens('github', githubToken)}
                  disabled={!githubToken}
                >
                  Save
                </button>
              </div>
              <p style={{fontSize:'0.72rem', color:'var(--text-dim)', marginTop:'0.5rem'}}>
                Webhook URL for auto-scans on push: <code style={{color:'var(--accent-blue)'}}>{apiUrl('/api/integration/webhook/github')}</code>
              </p>
            </div>

            {/* GitLab Integration */}
            <div className="settings-card">
              <h3 className="settings-section-title">GitLab Integration</h3>
              <div style={{display:'flex', alignItems:'center', gap:'0.5rem', marginBottom:'0.75rem'}}>
                <span style={{fontSize:'0.8rem', color:'var(--text-dim)'}}>Status:</span>
                <span style={{fontSize:'0.8rem', fontWeight:700, color: hasGitlabToken ? 'var(--accent-green)' : 'var(--text-dim)'}}>
                  {hasGitlabToken ? '✓ Connected' : 'Not Connected'}
                </span>
              </div>
              <p style={{fontSize:'0.8rem', color:'var(--text-dim)', marginBottom:'0.75rem'}}>
                Enter a GitLab Personal Access Token with <code>read_api</code> &amp; <code>read_repository</code> scope.
              </p>
              <div style={{display:'flex', gap:'0.5rem'}}>
                <input
                  type="password"
                  placeholder={hasGitlabToken ? '••••••••••••••••• (already set)' : 'glpat-xxxxxxxxxxxxxxxxxxxx'}
                  value={gitlabToken}
                  onChange={e => setGitlabToken(e.target.value)}
                  style={{background:'var(--bg-card)', border:'1px solid var(--border-color)', padding:'0.6rem', color:'#fff', borderRadius:'6px', flex:1, fontSize:'0.82rem'}}
                />
                <button
                  className="connect-repo-btn"
                  onClick={() => gitlabToken && handleSaveTokens('gitlab', gitlabToken)}
                  disabled={!gitlabToken}
                >
                  Save
                </button>
              </div>
              <p style={{fontSize:'0.72rem', color:'var(--text-dim)', marginTop:'0.5rem'}}>
                Webhook URL: <code style={{color:'var(--accent-blue)'}}>{apiUrl('/api/integration/webhook/gitlab')}</code>
              </p>
            </div>

            {/* CI/CD GitHub Actions Template */}
            <div className="settings-card">
              <h3 className="settings-section-title">CI/CD — GitHub Actions Template</h3>
              <p style={{fontSize:'0.8rem', color:'var(--text-dim)', marginBottom:'0.75rem'}}>
                Add this workflow file to <code>.github/workflows/secureguard.yml</code> to auto-scan every Pull Request.
              </p>
              <pre style={{background:'var(--bg-card)', border:'1px solid var(--border-color)', borderRadius:'6px', padding:'1rem', fontSize:'0.72rem', color:'#a5b4fc', overflowX:'auto', whiteSpace:'pre-wrap'}}>{CI_CD_YAML}</pre>
              <button
                className="connect-repo-btn"
                style={{marginTop:'0.75rem'}}
                onClick={() => navigator.clipboard.writeText(CI_CD_YAML).then(() => alert('Copied to clipboard!'))}
              >
                Copy YAML
              </button>
            </div>

            <div className="settings-card">
              <h3 className="settings-section-title">Security &amp; API Keys</h3>
              <div style={{fontSize: '0.85rem', display: 'flex', flexDirection: 'column', gap: '0.5rem'}}>
                <p style={{color: 'var(--text-dim)'}}>Connect plugins using your workspace API Token:</p>
                <div style={{display: 'flex', gap: '0.5rem', marginTop: '0.25rem'}}>
                  <code style={{background: 'var(--bg-card)', padding: '0.5rem 1rem', border: '1px solid var(--border-color)', borderRadius: '6px', flex: 1, fontSize: '0.75rem'}}>
                    sg_live_token_7fd82390ab12cf9845de7201bc3b
                  </code>
                  <button className="connect-repo-btn" style={{padding: '0.5rem'}} onClick={() => navigator.clipboard.writeText('sg_live_token_7fd82390ab12cf9845de7201bc3b').then(() => alert('Copied!'))}>
                    Copy Key
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ── Tab: Compliance Reports ── */}
        {activeNav === 'compliance' && (
          <ComplianceReports
            accessToken={accessToken}
            refreshSession={refreshSession}
            repos={repos}
          />
        )}

        {/* ── Tab: Software Bill of Materials (SBOM) ── */}
        {activeNav === 'sbom' && (
          <SbomPage selectedRepoId={selectedRepo?.id} />
        )}
      </main>

      {/* ── Connect Repository Modal ── */}
      {isConnectModalOpen && (
        <div className="modal-overlay" onClick={() => setIsConnectModalOpen(false)}>
          <div className="modal-card" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3 className="modal-title">Connect Code Repository</h3>
              <button className="modal-close-btn" onClick={() => setIsConnectModalOpen(false)}>
                <X size={18} />
              </button>
            </div>
            <form onSubmit={handleAddRepo} className="modal-form">
              <div className="modal-body">
                <div style={{display: 'flex', flexDirection: 'column', gap: '1rem'}}>

                  {/* Platform selector */}
                  <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem'}}>
                    <div style={{display: 'flex', flexDirection: 'column', gap: '4px'}}>
                      <label style={{fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-dim)'}}>Platform</label>
                      <select
                        value={newRepoPlatform}
                        onChange={e => { setNewRepoPlatform(e.target.value); setNewRepoName(''); setNewRepoFullName(''); setNewRepoUrl(''); }}
                        style={{background: 'var(--bg-card)', border: '1px solid var(--border-color)', padding: '0.6rem', color: '#fff', borderRadius: '6px'}}
                      >
                        <option value="github">GitHub</option>
                        <option value="gitlab">GitLab</option>
                        <option value="manual">Manual/Git URL</option>
                      </select>
                    </div>
                    <div style={{display: 'flex', flexDirection: 'column', gap: '4px'}}>
                      <label style={{fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-dim)'}}>Language</label>
                      <select
                        value={newRepoLang}
                        onChange={e => setNewRepoLang(e.target.value)}
                        style={{background: 'var(--bg-card)', border: '1px solid var(--border-color)', padding: '0.6rem', color: '#fff', borderRadius: '6px'}}
                      >
                        <option value="TypeScript">TypeScript</option>
                        <option value="JavaScript">JavaScript</option>
                        <option value="Python">Python</option>
                        <option value="Golang">Golang</option>
                        <option value="Java">Java</option>
                      </select>
                    </div>
                  </div>

                  {/* Remote repo import (GitHub/GitLab) */}
                  {(newRepoPlatform === 'github' || newRepoPlatform === 'gitlab') && (
                    <div style={{display: 'flex', flexDirection: 'column', gap: '4px'}}>
                      <label style={{fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-dim)'}}>
                        Import from {newRepoPlatform === 'github' ? 'GitHub' : 'GitLab'}
                      </label>
                      {loadingRemote ? (
                        <div style={{fontSize: '0.8rem', color: 'var(--text-dim)', padding: '0.5rem 0'}}>
                          <RefreshCw size={13} className="spin-icon" style={{display:'inline', marginRight:'6px'}} />
                          Fetching repositories…
                        </div>
                      ) : remoteRepos.length > 0 ? (
                        <select
                          defaultValue=""
                          onChange={e => {
                            const r = remoteRepos.find(x => x.fullName === e.target.value);
                            if (r) { setNewRepoName(r.name); setNewRepoFullName(r.fullName); setNewRepoUrl(r.url); setNewRepoLang(r.language || 'JavaScript'); }
                          }}
                          style={{background: 'var(--bg-card)', border: '1px solid var(--accent-blue)', padding: '0.6rem', color: '#fff', borderRadius: '6px'}}
                        >
                          <option value="">— Select a repository to auto-fill —</option>
                          {remoteRepos.map(r => (
                            <option key={r.fullName} value={r.fullName}>{r.fullName}</option>
                          ))}
                        </select>
                      ) : (
                        <p style={{fontSize: '0.78rem', color: 'var(--text-dim)', padding: '0.4rem 0'}}>
                          ⚠ No token configured for {newRepoPlatform === 'github' ? 'GitHub' : 'GitLab'}. Go to <strong>Settings → {newRepoPlatform === 'github' ? 'GitHub' : 'GitLab'} Integration</strong> to add your PAT.
                        </p>
                      )}
                    </div>
                  )}

                  <div style={{display: 'flex', flexDirection: 'column', gap: '4px'}}>
                    <label style={{fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-dim)'}}>Repository Name</label>
                    <input
                      type="text"
                      placeholder="e.g. backend-api"
                      value={newRepoName}
                      onChange={e => setNewRepoName(e.target.value)}
                      required
                      style={{background: 'var(--bg-card)', border: '1px solid var(--border-color)', padding: '0.6rem', color: '#fff', borderRadius: '6px'}}
                    />
                  </div>
                  <div style={{display: 'flex', flexDirection: 'column', gap: '4px'}}>
                    <label style={{fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-dim)'}}>Owner / Full Name</label>
                    <input
                      type="text"
                      placeholder="e.g. company/backend-api"
                      value={newRepoFullName}
                      onChange={e => setNewRepoFullName(e.target.value)}
                      style={{background: 'var(--bg-card)', border: '1px solid var(--border-color)', padding: '0.6rem', color: '#fff', borderRadius: '6px'}}
                    />
                  </div>
                  <div style={{display: 'flex', flexDirection: 'column', gap: '4px'}}>
                    <label style={{fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-dim)'}}>Clone / Web URL</label>
                    <input
                      type="url"
                      placeholder="https://github.com/company/backend-api"
                      value={newRepoUrl}
                      onChange={e => setNewRepoUrl(e.target.value)}
                      required
                      style={{background: 'var(--bg-card)', border: '1px solid var(--border-color)', padding: '0.6rem', color: '#fff', borderRadius: '6px'}}
                    />
                  </div>
                </div>
              </div>
              <div className="modal-footer">
                <button type="button" className="repo-action-btn-small" style={{flex: 'none'}} onClick={() => setIsConnectModalOpen(false)}>
                  Cancel
                </button>
                <button type="submit" className="connect-repo-btn">
                  Connect Repository
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      <OrganizationSettingsModal
        isOpen={isOrgSettingsOpen}
        onClose={() => setIsOrgSettingsOpen(false)}
        initialTab={orgSettingsTab}
      />
    </div>
  );
}
