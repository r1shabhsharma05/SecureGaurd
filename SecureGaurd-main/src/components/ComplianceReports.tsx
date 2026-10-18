import React, { useState, useEffect } from 'react';
import {
  FileCheck, Plus, Download, Eye, Trash2, Shield,
  AlertTriangle, Search,
  RefreshCw, X, Filter, FileText, FileCode, Check
} from 'lucide-react';
import { useOrganization } from '../context/OrganizationContext';
import { toErrorMessage } from '../services/ApiError';
import './ComplianceReports.css';

interface Repository {
  id: number;
  name: string;
  fullName: string;
  platform: string;
  language: string | null;
}

interface ComplianceReportItem {
  id: number;
  name: string;
  framework: string;
  dateRangeOption: string;
  fromDate: string;
  toDate: string;
  status: string;
  complianceScore: number;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  passedControls: number;
  partialControls: number;
  failedControls: number;
  createdAt: string;
  repository: {
    id?: number;
    name: string;
    fullName: string;
    platform?: string;
  };
  reportData?: any;
}

interface Props {
  accessToken: string | null;
  refreshSession: () => Promise<string | null>;
  repos: Repository[];
}

const FRAMEWORKS = [
  {
    id: 'SOC2',
    name: 'SOC 2 Type II',
    badge: 'Trust Services',
    description: 'Evaluates Security, Availability, and Confidentiality controls based on AICPA Trust Services Criteria.',
    color: '#0055FF'
  },
  {
    id: 'HIPAA',
    name: 'HIPAA Security Rule',
    badge: 'Healthcare Data',
    description: 'Evaluates Administrative, Physical, and Technical safeguards for Protected Health Information (ePHI).',
    color: '#10B981'
  },
  {
    id: 'PCI-DSS',
    name: 'PCI-DSS v4.0',
    badge: 'Payment Security',
    description: 'Evaluates Payment Card Industry Data Security Standard controls for cardholder data environments.',
    color: '#F59E0B'
  },
  {
    id: 'GDPR',
    name: 'GDPR Privacy & Security',
    badge: 'EU Data Protection',
    description: 'Evaluates Article 25 & 32 technical data protection, pseudonymization, and encryption standards.',
    color: '#8B5CF6'
  }
];

export default function ComplianceReports({ accessToken, refreshSession, repos }: Props) {
  const { activeOrgId, orgFetch } = useOrganization();
  const [reports, setReports] = useState<ComplianceReportItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedFrameworkFilter, setSelectedFrameworkFilter] = useState('ALL');

  // Modal State: Create Report
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [selectedRepoId, setSelectedRepoId] = useState<number | ''>(repos.length > 0 ? repos[0].id : '');
  const [selectedFramework, setSelectedFramework] = useState('SOC2');
  const [dateRangeOption, setDateRangeOption] = useState('30d');
  const [customFrom, setCustomFrom] = useState('');
  const [customTo, setCustomTo] = useState('');
  const [customReportName, setCustomReportName] = useState('');
  const [generating, setGenerating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  // Drawer / Modal State: Report Preview
  const [previewReport, setPreviewReport] = useState<ComplianceReportItem | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [activePreviewTab, setActivePreviewTab] = useState<'controls' | 'findings' | 'recommendations'>('controls');

  useEffect(() => {
    if (repos.length > 0 && selectedRepoId === '') {
      setSelectedRepoId(repos[0].id);
    }
  }, [repos]);

  const fetchReports = async () => {
    if (!accessToken) return;
    setLoading(true);
    try {
      const res = await orgFetch('/api/compliance/reports');
      if (res.ok) {
        const data = await res.json();
        setReports(data);
      }
    } catch (err) {
      console.error('Error fetching compliance reports:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (accessToken && activeOrgId) {
      fetchReports();
    }
  }, [accessToken, activeOrgId]);

  const handleGenerateReport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!accessToken || !selectedRepoId) return;

    setGenerating(true);
    setCreateError(null);

    try {
      const payload = {
        repositoryId: Number(selectedRepoId),
        framework: selectedFramework,
        dateRangeOption,
        customFromDate: dateRangeOption === 'custom' ? customFrom : undefined,
        customToDate: dateRangeOption === 'custom' ? customTo : undefined,
        reportName: customReportName.trim() || undefined
      };

      const res = await orgFetch('/api/compliance/generate', {
        method: 'POST',
        body: JSON.stringify(payload)
      });

      if (res.ok) {
        const newReport = await res.json();
        setIsCreateModalOpen(false);
        setCustomReportName('');
        await fetchReports();
        // Automatically open preview for the generated report
        openPreview(newReport.id);
      } else {
        const errData = await res.json();
        setCreateError(errData.message || 'Failed to generate report');
      }
    } catch (err: unknown) {
      setCreateError(toErrorMessage(err, 'Error generating report'));
    } finally {
      setGenerating(false);
    }
  };

  const openPreview = async (reportId: number) => {
    if (!accessToken) return;
    setPreviewLoading(true);
    try {
      const res = await orgFetch(`/api/compliance/reports/${reportId}`);
      if (res.ok) {
        const data = await res.json();
        setPreviewReport(data);
      }
    } catch (err) {
      console.error('Error fetching report details:', err);
    } finally {
      setPreviewLoading(false);
    }
  };

  const handleDeleteReport = async (id: number, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!window.confirm('Are you sure you want to delete this compliance report?') || !accessToken) return;

    try {
      const res = await orgFetch(`/api/compliance/reports/${id}`, { method: 'DELETE' });
      if (res.ok) {
        if (previewReport?.id === id) setPreviewReport(null);
        fetchReports();
      }
    } catch (err) {
      console.error('Error deleting report:', err);
    }
  };

  const downloadPdf = async (id: number, reportName: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    if (!accessToken) return;

    try {
      const res = await orgFetch(`/api/compliance/reports/${id}/pdf`);

      if (res.ok) {
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${reportName.replace(/[^a-zA-Z0-9_-]/g, '_')}.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
      } else {
        alert('Failed to download PDF report');
      }
    } catch (err) {
      console.error('Error downloading PDF:', err);
    }
  };

  const downloadJson = async (id: number, reportName: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    if (!accessToken) return;

    try {
      const res = await orgFetch(`/api/compliance/reports/${id}/json`);

      if (res.ok) {
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${reportName.replace(/[^a-zA-Z0-9_-]/g, '_')}.json`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
      } else {
        alert('Failed to download JSON report');
      }
    } catch (err) {
      console.error('Error downloading JSON:', err);
    }
  };

  // Filtered reports list
  const filteredReports = reports.filter(r => {
    const matchesSearch = r.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          r.repository?.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          r.framework.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesFw = selectedFrameworkFilter === 'ALL' || r.framework === selectedFrameworkFilter;
    return matchesSearch && matchesFw;
  });

  return (
    <div className="compliance-root">
      {/* ── Main Top Bar ── */}
      <div className="compliance-header">
        <div className="compliance-header-title">
          <h2>Security Compliance Reports</h2>
          <p>Generate & audit formal security assessment reports mapped against SOC 2, HIPAA, PCI-DSS, and GDPR framework controls.</p>
        </div>
        <button
          className="compliance-btn-primary"
          onClick={() => setIsCreateModalOpen(true)}
        >
          <Plus size={16} /> Generate Report
        </button>
      </div>

      {/* ── Sub Header / Filters Row ── */}
      <div className="compliance-toolbar">
        <div className="compliance-search">
          <Search size={15} />
          <input
            type="text"
            placeholder="Filter reports by name, repository, framework…"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
          />
        </div>

        <div className="compliance-fw-filters">
          <span className="filter-label"><Filter size={13} /> Framework:</span>
          {['ALL', 'SOC2', 'HIPAA', 'PCI-DSS', 'GDPR'].map(fw => (
            <button
              key={fw}
              className={`fw-chip ${selectedFrameworkFilter === fw ? 'active' : ''}`}
              onClick={() => setSelectedFrameworkFilter(fw)}
            >
              {fw}
            </button>
          ))}
        </div>
      </div>

      {/* ── Report History List / Table ── */}
      {loading ? (
        <div className="compliance-loading">
          <RefreshCw size={24} className="spin-icon" />
          <p>Loading compliance reports…</p>
        </div>
      ) : filteredReports.length === 0 ? (
        <div className="compliance-empty">
          <div className="empty-icon-wrap">
            <FileCheck size={40} />
          </div>
          <h3>No Compliance Reports Found</h3>
          <p>
            {searchQuery || selectedFrameworkFilter !== 'ALL'
              ? 'No reports match your current search/filter parameters.'
              : 'You have not generated any security compliance reports yet. Select a repository to generate your first audit report.'}
          </p>
          <button
            className="compliance-btn-primary"
            onClick={() => setIsCreateModalOpen(true)}
            style={{ marginTop: '1rem' }}
          >
            <Plus size={16} /> Create First Report
          </button>
        </div>
      ) : (
        <div className="compliance-table-wrap">
          <table className="compliance-table">
            <thead>
              <tr>
                <th>REPORT NAME</th>
                <th>REPOSITORY</th>
                <th>FRAMEWORK</th>
                <th>SCORE</th>
                <th>FINDINGS</th>
                <th>GENERATED AT</th>
                <th style={{ textAlign: 'right' }}>ACTIONS</th>
              </tr>
            </thead>
            <tbody>
              {filteredReports.map(rep => {
                let scoreClass = 'score-high';
                if (rep.complianceScore < 60) scoreClass = 'score-low';
                else if (rep.complianceScore < 80) scoreClass = 'score-med';

                return (
                  <tr key={rep.id} className="compliance-row" onClick={() => openPreview(rep.id)}>
                    <td className="col-name">
                      <div className="name-box">
                        <FileText size={16} className="report-icon" />
                        <div>
                          <span className="report-title">{rep.name}</span>
                          <span className="report-meta">Period: {rep.dateRangeOption.toUpperCase()}</span>
                        </div>
                      </div>
                    </td>
                    <td className="col-repo">
                      <code className="repo-code">{rep.repository?.fullName || rep.repository?.name || 'N/A'}</code>
                    </td>
                    <td className="col-fw">
                      <span className={`fw-badge fw-badge--${rep.framework.toLowerCase().replace('-', '')}`}>
                        {rep.framework}
                      </span>
                    </td>
                    <td className="col-score">
                      <div className={`score-badge ${scoreClass}`}>
                        {rep.complianceScore}<span>/100</span>
                      </div>
                    </td>
                    <td className="col-findings">
                      <div className="findings-pill-group">
                        <span className="vuln-pill c" title="Critical">{rep.criticalCount} C</span>
                        <span className="vuln-pill h" title="High">{rep.highCount} H</span>
                        <span className="vuln-pill m" title="Medium">{rep.mediumCount} M</span>
                        <span className="vuln-pill l" title="Low">{rep.lowCount} L</span>
                      </div>
                    </td>
                    <td className="col-date">
                      {new Date(rep.createdAt).toLocaleDateString(undefined, {
                        month: 'short',
                        day: 'numeric',
                        year: 'numeric'
                      })}
                    </td>
                    <td className="col-actions" style={{ textAlign: 'right' }}>
                      <div className="action-btn-group" onClick={e => e.stopPropagation()}>
                        <button
                          className="action-icon-btn"
                          title="Preview Summary"
                          onClick={() => openPreview(rep.id)}
                        >
                          <Eye size={15} />
                        </button>
                        <button
                          className="action-icon-btn highlight-blue"
                          title="Download PDF"
                          onClick={e => downloadPdf(rep.id, rep.name, e)}
                        >
                          <Download size={15} /> <span className="btn-label">PDF</span>
                        </button>
                        <button
                          className="action-icon-btn highlight-green"
                          title="Download JSON"
                          onClick={e => downloadJson(rep.id, rep.name, e)}
                        >
                          <FileCode size={15} /> <span className="btn-label">JSON</span>
                        </button>
                        <button
                          className="action-icon-btn danger"
                          title="Delete Report"
                          onClick={e => handleDeleteReport(rep.id, e)}
                        >
                          <Trash2 size={15} />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* ── CREATE REPORT MODAL ── */}
      {isCreateModalOpen && (
        <div className="modal-overlay">
          <div className="modal-card compliance-modal">
            <div className="modal-header">
              <div>
                <h3 className="modal-title">Generate Compliance Report</h3>
                <p className="modal-sub">Evaluate scan findings against regulatory compliance frameworks.</p>
              </div>
              <button className="modal-close-btn" onClick={() => setIsCreateModalOpen(false)}>
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleGenerateReport} className="compliance-form">
              {createError && (
                <div className="form-error-alert">
                  <AlertTriangle size={16} />
                  <span>{createError}</span>
                </div>
              )}

              {/* 1. Repository Selection */}
              <div className="form-group">
                <label className="form-label">Target Repository *</label>
                {repos.length === 0 ? (
                  <div className="form-warning">No connected repositories. Connect a repository first.</div>
                ) : (
                  <select
                    className="form-select"
                    value={selectedRepoId}
                    onChange={e => setSelectedRepoId(Number(e.target.value))}
                    required
                  >
                    {repos.map(r => (
                      <option key={r.id} value={r.id}>
                        {r.fullName} ({r.language || 'Codebase'})
                      </option>
                    ))}
                  </select>
                )}
              </div>

              {/* 2. Compliance Framework Selection */}
              <div className="form-group">
                <label className="form-label">Compliance Framework *</label>
                <div className="fw-grid">
                  {FRAMEWORKS.map(fw => (
                    <div
                      key={fw.id}
                      className={`fw-card ${selectedFramework === fw.id ? 'selected' : ''}`}
                      onClick={() => setSelectedFramework(fw.id)}
                    >
                      <div className="fw-card-top">
                        <span className="fw-card-name">{fw.name}</span>
                        {selectedFramework === fw.id && <Check size={16} className="fw-check" />}
                      </div>
                      <p className="fw-card-desc">{fw.description}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* 3. Date Range Options */}
              <div className="form-group">
                <label className="form-label">Assessment Date Range *</label>
                <div className="date-options-row">
                  {[
                    { id: '7d', label: 'Last 7 Days' },
                    { id: '30d', label: 'Last 30 Days' },
                    { id: '90d', label: 'Last 90 Days' },
                    { id: 'custom', label: 'Custom Range' }
                  ].map(opt => (
                    <button
                      key={opt.id}
                      type="button"
                      className={`date-chip ${dateRangeOption === opt.id ? 'active' : ''}`}
                      onClick={() => setDateRangeOption(opt.id)}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>

                {dateRangeOption === 'custom' && (
                  <div className="custom-date-grid">
                    <div>
                      <label className="form-sublabel">From Date</label>
                      <input
                        type="date"
                        className="form-input"
                        value={customFrom}
                        onChange={e => setCustomFrom(e.target.value)}
                        required
                      />
                    </div>
                    <div>
                      <label className="form-sublabel">To Date</label>
                      <input
                        type="date"
                        className="form-input"
                        value={customTo}
                        onChange={e => setCustomTo(e.target.value)}
                        required
                      />
                    </div>
                  </div>
                )}
              </div>

              {/* 4. Report Name */}
              <div className="form-group">
                <label className="form-label">Custom Report Name (Optional)</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder={`e.g. ${selectedFramework} Security Audit - ${repos.find(r => r.id === selectedRepoId)?.name || 'Repo'}`}
                  value={customReportName}
                  onChange={e => setCustomReportName(e.target.value)}
                />
              </div>

              <div className="modal-actions">
                <button
                  type="button"
                  className="compliance-btn-secondary"
                  onClick={() => setIsCreateModalOpen(false)}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="compliance-btn-primary"
                  disabled={generating || repos.length === 0}
                >
                  {generating ? (
                    <>
                      <RefreshCw size={15} className="spin-icon" /> Evaluating Compliance…
                    </>
                  ) : (
                    'Generate Report'
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── REPORT PREVIEW DRAWER / MODAL ── */}
      {previewReport && (
        <div className="modal-overlay">
          <div className="modal-card preview-modal">
            {/* Header */}
            <div className="preview-modal-header">
              <div className="preview-brand-title">
                <Shield size={20} style={{ color: 'var(--accent-blue)' }} />
                <div>
                  <h3>{previewReport.name}</h3>
                  <p className="preview-subtitle">
                    {previewReport.repository?.fullName} • Generated {new Date(previewReport.createdAt).toLocaleDateString()}
                  </p>
                </div>
              </div>
              <div className="preview-header-actions">
                <button
                  className="compliance-btn-secondary icon-only"
                  title="Download PDF"
                  onClick={() => downloadPdf(previewReport.id, previewReport.name)}
                >
                  <Download size={16} /> PDF
                </button>
                <button
                  className="compliance-btn-secondary icon-only"
                  title="Download JSON"
                  onClick={() => downloadJson(previewReport.id, previewReport.name)}
                >
                  <FileCode size={16} /> JSON
                </button>
                <button className="modal-close-btn" onClick={() => setPreviewReport(null)}>
                  <X size={18} />
                </button>
              </div>
            </div>

            {/* Score & Summary Banner */}
            <div className="preview-summary-banner">
              <div className="summary-card score-card">
                <span className="summary-card-title">COMPLIANCE SCORE</span>
                <div className="score-flex">
                  <span className={`score-value ${previewReport.complianceScore < 60 ? 'red' : previewReport.complianceScore < 80 ? 'yellow' : 'green'}`}>
                    {previewReport.complianceScore}
                  </span>
                  <span className="score-max">/100</span>
                </div>
              </div>

              <div className="summary-card">
                <span className="summary-card-title">VULNERABILITY FINDINGS</span>
                <div className="stat-counts-row">
                  <span className="count-tag c">{previewReport.criticalCount} Critical</span>
                  <span className="count-tag h">{previewReport.highCount} High</span>
                  <span className="count-tag m">{previewReport.mediumCount} Medium</span>
                  <span className="count-tag l">{previewReport.lowCount} Low</span>
                </div>
              </div>

              <div className="summary-card">
                <span className="summary-card-title">CONTROL STATUS</span>
                <div className="ctrl-status-row">
                  <span className="ctrl-tag pass">✓ {previewReport.passedControls} PASS</span>
                  <span className="ctrl-tag partial">! {previewReport.partialControls} PARTIAL</span>
                  <span className="ctrl-tag fail">✕ {previewReport.failedControls} FAIL</span>
                </div>
              </div>
            </div>

            {/* Tabs */}
            <div className="preview-tabs">
              <button
                className={`tab-btn ${activePreviewTab === 'controls' ? 'active' : ''}`}
                onClick={() => setActivePreviewTab('controls')}
              >
                Framework Controls ({previewReport.reportData?.controls?.length || 0})
              </button>
              <button
                className={`tab-btn ${activePreviewTab === 'findings' ? 'active' : ''}`}
                onClick={() => setActivePreviewTab('findings')}
              >
                Security Findings ({previewReport.reportData?.findings?.length || 0})
              </button>
              <button
                className={`tab-btn ${activePreviewTab === 'recommendations' ? 'active' : ''}`}
                onClick={() => setActivePreviewTab('recommendations')}
              >
                Recommendations ({previewReport.reportData?.recommendations?.length || 0})
              </button>
            </div>

            {/* Content Body */}
            <div className="preview-body">
              {activePreviewTab === 'controls' && (
                <div className="controls-list">
                  {previewReport.reportData?.controls?.map((ctrl: any) => (
                    <div key={ctrl.id} className={`control-item-card ${ctrl.status.toLowerCase()}`}>
                      <div className="ctrl-top">
                        <div>
                          <span className="ctrl-id">{ctrl.id}</span>
                          <span className="ctrl-name">{ctrl.name}</span>
                        </div>
                        <span className={`ctrl-badge ${ctrl.status.toLowerCase()}`}>
                          {ctrl.status}
                        </span>
                      </div>
                      <p className="ctrl-desc">{ctrl.description}</p>
                      <div className="ctrl-evidence">
                        <strong>Evidence:</strong> {ctrl.evidence}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {activePreviewTab === 'findings' && (
                <div className="findings-list">
                  {previewReport.reportData?.findings?.length === 0 ? (
                    <div className="no-findings">✓ No open security vulnerabilities found during scan period.</div>
                  ) : (
                    previewReport.reportData?.findings?.map((f: any) => (
                      <div key={f.id} className="finding-item-card">
                        <div className="finding-top">
                          <span className={`badge badge--${(f.severity || 'low').toLowerCase()}`}>
                            {(f.severity || 'low').toUpperCase()}
                          </span>
                          <span className="finding-title">{f.title}</span>
                          <span className="finding-cwe">{f.cweId || 'N/A'}</span>
                        </div>
                        <div className="finding-meta">
                          <code>{f.filePath}:{f.lineStart}</code> • Status: <strong>{f.status}</strong>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              )}

              {activePreviewTab === 'recommendations' && (
                <div className="recommendations-list">
                  {previewReport.reportData?.recommendations?.map((rec: any, i: number) => (
                    <div key={i} className="rec-card">
                      <div className="rec-priority">[{rec.priority}]</div>
                      <div className="rec-content">
                        <h4>{rec.title}</h4>
                        <p>{rec.action}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Footer Disclaimer */}
            <div className="preview-disclaimer">
              {previewReport.reportData?.disclaimer}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
