import React, { useState, useEffect } from 'react';
import {
  Layers, Search, Download, ShieldAlert, CheckCircle, Package,
  FileCode, Copy, Check, Info, ArrowUpRight
} from 'lucide-react';
import { useOrganization } from '../context/OrganizationContext';
import { useNavigate } from 'react-router-dom';

interface SbomComponent {
  SPDXID: string;
  name: string;
  versionInfo: string;
  licenseConcluded: string;
  externalRefs?: Array<{
    referenceCategory: string;
    referenceType: string;
    referenceLocator: string;
  }>;
  comment?: string;
}

interface SbomRecord {
  id: number;
  name: string;
  spdxVersion: string;
  documentNamespace: string;
  componentCount: number;
  directCount: number;
  transitiveCount: number;
  vulnerableCount: number;
  ecosystems: string[];
  createdAt: string;
  repository?: {
    id: number;
    name: string;
    fullName: string;
    platform: string;
  };
  scan?: {
    id: number;
    branch: string;
    commitSha: string | null;
    createdAt: string;
  };
  spdxDoc?: {
    packages: SbomComponent[];
    relationships: any[];
  };
}

export default function SbomPage({ selectedRepoId }: { selectedRepoId?: number }) {
  const { activeOrgId, orgFetch } = useOrganization();
  const navigate = useNavigate();

  const [sboms, setSboms] = useState<SbomRecord[]>([]);
  const [selectedSbom, setSelectedSbom] = useState<SbomRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters & Search
  const [searchQuery, setSearchQuery] = useState('');
  const [filterEcosystem, setFilterEcosystem] = useState('ALL');
  const [filterType, setFilterType] = useState('ALL'); // ALL | direct | transitive
  const [filterSafety, setFilterSafety] = useState('ALL'); // ALL | vulnerable | safe
  const [copiedPurl, setCopiedPurl] = useState<string | null>(null);

  // Detail Modal
  const [activeComponent, setActiveComponent] = useState<any | null>(null);

  useEffect(() => {
    fetchSboms();
  }, [activeOrgId, selectedRepoId]);

  const fetchSboms = async () => {
    setLoading(true);
    setError(null);
    try {
      const url = selectedRepoId
        ? `/api/sboms/repository/${selectedRepoId}`
        : '/api/sboms';

      const res = await orgFetch(url);
      if (res.ok) {
        const data = await res.json();
        const list = Array.isArray(data) ? data : [data];
        setSboms(list);
        if (list.length > 0) {
          // Load complete details for first SBOM
          fetchSbomDetails(list[0].id);
        } else {
          setSelectedSbom(null);
        }
      } else {
        setSboms([]);
        setSelectedSbom(null);
      }
    } catch (err: unknown) {
      console.error('Failed to load SBOMs:', err);
      setError('Unable to load Software Bill of Materials.');
    } finally {
      setLoading(false);
    }
  };

  const fetchSbomDetails = async (id: number) => {
    try {
      const res = await orgFetch(`/api/sboms/${id}`);
      if (res.ok) {
        const data = await res.json();
        setSelectedSbom(data);
      }
    } catch (err) {
      console.error('Error fetching SBOM detail:', err);
    }
  };

  const handleDownloadSpdx = async () => {
    if (!selectedSbom) return;
    try {
      const res = await orgFetch(`/api/sboms/${selectedSbom.id}/download`);
      if (res.ok) {
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${selectedSbom.name || 'sbom'}.spdx.json`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      }
    } catch (err) {
      console.error('Failed to download SPDX:', err);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedPurl(text);
    setTimeout(() => setCopiedPurl(null), 2000);
  };

  // Process packages from selected SBOM
  const packagesList = (selectedSbom?.spdxDoc?.packages || []).filter(
    pkg => !pkg.SPDXID.includes('-Root-')
  ).map(pkg => {
    let metadata: any = {};
    try {
      metadata = pkg.comment ? JSON.parse(pkg.comment) : {};
    } catch {
      metadata = {};
    }

    const purlObj = pkg.externalRefs?.find(r => r.referenceType === 'purl');
    const purl = purlObj?.referenceLocator || '';

    // Infer ecosystem from purl or SPDXID
    let ecosystem = 'generic';
    if (purl.startsWith('pkg:npm')) ecosystem = 'npm';
    else if (purl.startsWith('pkg:pypi')) ecosystem = 'pypi';
    else if (purl.startsWith('pkg:maven')) ecosystem = 'maven';
    else if (purl.startsWith('pkg:golang')) ecosystem = 'golang';
    else if (purl.startsWith('pkg:cargo')) ecosystem = 'cargo';
    else if (purl.startsWith('pkg:composer')) ecosystem = 'composer';
    else if (purl.startsWith('pkg:rubygems')) ecosystem = 'rubygems';

    return {
      spdxId: pkg.SPDXID,
      name: pkg.name,
      version: pkg.versionInfo,
      license: pkg.licenseConcluded || 'NOASSERTION',
      purl,
      ecosystem,
      dependencyType: metadata.dependencyType || 'direct',
      packageManager: metadata.packageManager || ecosystem,
      manifestSources: metadata.manifestSources || [],
      vulnerabilitiesCount: metadata.vulnerabilitiesCount || 0,
      vulnerabilities: metadata.vulnerabilities || []
    };
  });

  // Filtering packages
  const filteredPackages = packagesList.filter(pkg => {
    const matchesSearch =
      pkg.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      pkg.version.toLowerCase().includes(searchQuery.toLowerCase()) ||
      pkg.purl.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesEco =
      filterEcosystem === 'ALL' || pkg.ecosystem.toLowerCase() === filterEcosystem.toLowerCase();

    const matchesType =
      filterType === 'ALL' || pkg.dependencyType.toLowerCase() === filterType.toLowerCase();

    const matchesSafety =
      filterSafety === 'ALL' ||
      (filterSafety === 'vulnerable' && pkg.vulnerabilitiesCount > 0) ||
      (filterSafety === 'safe' && pkg.vulnerabilitiesCount === 0);

    return matchesSearch && matchesEco && matchesType && matchesSafety;
  });

  if (loading) {
    return (
      <div className="sbom-loading-container" style={{ padding: '3rem', textAlign: 'center', color: '#94a3b8' }}>
        <div className="spinner" style={{ margin: '0 auto 1rem auto' }} />
        <p>Analyzing Software Bill of Materials (SBOM)...</p>
      </div>
    );
  }

  if (sboms.length === 0) {
    return (
      <div className="sbom-empty-card" style={{
        background: 'rgba(30, 41, 59, 0.5)',
        border: '1px border var(--border-color)',
        borderRadius: '12px',
        padding: '3rem',
        textAlign: 'center',
        margin: '1.5rem 0'
      }}>
        <Layers size={48} style={{ color: '#64748b', marginBottom: '1rem' }} />
        <h3 style={{ fontSize: '1.25rem', color: '#f8fafc', marginBottom: '0.5rem' }}>No SBOM Available Yet</h3>
        <p style={{ color: '#94a3b8', maxWidth: '500px', margin: '0 auto 1.5rem auto' }}>
          Run a security scan on your repository to automatically generate an industry-standard SPDX 2.3 Software Bill of Materials.
        </p>
      </div>
    );
  }

  return (
    <div className="sbom-page-wrapper" style={{ padding: '1rem 0' }}>
      {/* Selector & Download Toolbar */}
      <div className="sbom-header-toolbar" style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '1rem',
        marginBottom: '1.5rem'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <Layers size={22} style={{ color: '#38bdf8' }} />
          <div>
            <h2 style={{ margin: 0, fontSize: '1.4rem', color: '#f8fafc' }}>Software Bill of Materials (SBOM)</h2>
            <p style={{ margin: '2px 0 0 0', fontSize: '0.85rem', color: '#94a3b8' }}>
              SPDX 2.3 Compliant • Software Supply Chain Visibility
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {sboms.length > 1 && (
            <select
              value={selectedSbom?.id}
              onChange={(e) => fetchSbomDetails(Number(e.target.value))}
              style={{
                background: '#0f172a',
                border: '1px solid #334155',
                color: '#f8fafc',
                padding: '0.5rem 1rem',
                borderRadius: '8px',
                fontSize: '0.9rem'
              }}
            >
              {sboms.map(s => (
                <option key={s.id} value={s.id}>
                  {s.repository?.name || s.name} ({new Date(s.createdAt).toLocaleDateString()})
                </option>
              ))}
            </select>
          )}

          <button
            onClick={handleDownloadSpdx}
            className="btn btn--primary"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.5rem',
              background: 'linear-gradient(135deg, #0284c7 0%, #2563eb 100%)',
              color: '#ffffff',
              border: 'none',
              padding: '0.55rem 1.2rem',
              borderRadius: '8px',
              fontWeight: 600,
              cursor: 'pointer'
            }}
          >
            <Download size={16} />
            Export SPDX 2.3 JSON
          </button>
        </div>
      </div>

      {/* Summary Cards */}
      {selectedSbom && (
        <div className="sbom-summary-grid" style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: '1rem',
          marginBottom: '1.5rem'
        }}>
          <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '10px', padding: '1.25rem' }}>
            <span style={{ fontSize: '0.8rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Total Components</span>
            <div style={{ fontSize: '1.8rem', fontWeight: 700, color: '#f8fafc', marginTop: '0.25rem' }}>
              {selectedSbom.componentCount}
            </div>
            <span style={{ fontSize: '0.8rem', color: '#38bdf8' }}>Unique packages mapped</span>
          </div>

          <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '10px', padding: '1.25rem' }}>
            <span style={{ fontSize: '0.8rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Direct vs Transitive</span>
            <div style={{ fontSize: '1.3rem', fontWeight: 600, color: '#f8fafc', marginTop: '0.25rem' }}>
              <span style={{ color: '#4ade80' }}>{selectedSbom.directCount} Direct</span> / <span style={{ color: '#a78bfa' }}>{selectedSbom.transitiveCount} Transitive</span>
            </div>
            <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>Manifest graph depth</span>
          </div>

          <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '10px', padding: '1.25rem' }}>
            <span style={{ fontSize: '0.8rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Ecosystems</span>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', marginTop: '0.5rem' }}>
              {(selectedSbom.ecosystems || []).map((eco: string) => (
                <span key={eco} style={{
                  background: 'rgba(56, 189, 248, 0.15)',
                  color: '#38bdf8',
                  padding: '2px 8px',
                  borderRadius: '4px',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  textTransform: 'uppercase'
                }}>
                  {eco}
                </span>
              ))}
            </div>
          </div>

          <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '10px', padding: '1.25rem' }}>
            <span style={{ fontSize: '0.8rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Vulnerable Components</span>
            <div style={{ fontSize: '1.8rem', fontWeight: 700, color: selectedSbom.vulnerableCount > 0 ? '#ef4444' : '#4ade80', marginTop: '0.25rem' }}>
              {selectedSbom.vulnerableCount}
            </div>
            <span style={{ fontSize: '0.8rem', color: selectedSbom.vulnerableCount > 0 ? '#fca5a5' : '#86efac' }}>
              {selectedSbom.vulnerableCount > 0 ? 'Requires remediation' : 'No known vulnerabilities'}
            </span>
          </div>
        </div>
      )}

      {/* Table Filters & Search */}
      <div style={{
        background: '#0f172a',
        border: '1px solid #1e293b',
        borderRadius: '12px 12px 0 0',
        padding: '1rem 1.25rem',
        display: 'flex',
        flexWrap: 'wrap',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '1rem'
      }}>
        {/* Search */}
        <div style={{ position: 'relative', flex: '1', minWidth: '240px' }}>
          <Search size={16} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: '#64748b' }} />
          <input
            type="text"
            placeholder="Search package name, version, or PURL..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              width: '100%',
              background: '#020617',
              border: '1px solid #334155',
              borderRadius: '6px',
              padding: '0.5rem 0.5rem 0.5rem 2.2rem',
              color: '#f8fafc',
              fontSize: '0.875rem'
            }}
          />
        </div>

        {/* Filters */}
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
          <select
            value={filterEcosystem}
            onChange={(e) => setFilterEcosystem(e.target.value)}
            style={{ background: '#020617', border: '1px solid #334155', color: '#cbd5e1', padding: '0.45rem 0.75rem', borderRadius: '6px', fontSize: '0.85rem' }}
          >
            <option value="ALL">All Ecosystems</option>
            <option value="npm">npm</option>
            <option value="pypi">PyPI</option>
            <option value="maven">Maven</option>
            <option value="golang">Go</option>
            <option value="cargo">Cargo</option>
            <option value="composer">Composer</option>
            <option value="rubygems">RubyGems</option>
          </select>

          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            style={{ background: '#020617', border: '1px solid #334155', color: '#cbd5e1', padding: '0.45rem 0.75rem', borderRadius: '6px', fontSize: '0.85rem' }}
          >
            <option value="ALL">All Dependency Types</option>
            <option value="direct">Direct</option>
            <option value="transitive">Transitive</option>
          </select>

          <select
            value={filterSafety}
            onChange={(e) => setFilterSafety(e.target.value)}
            style={{ background: '#020617', border: '1px solid #334155', color: '#cbd5e1', padding: '0.45rem 0.75rem', borderRadius: '6px', fontSize: '0.85rem' }}
          >
            <option value="ALL">All Security Statuses</option>
            <option value="vulnerable">Vulnerable Only</option>
            <option value="safe">Safe Only</option>
          </select>
        </div>
      </div>

      {/* Component Table */}
      <div style={{ background: '#020617', border: '1px solid #1e293b', borderTop: 'none', borderRadius: '0 0 12px 12px', overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.875rem' }}>
          <thead>
            <tr style={{ background: '#0f172a', borderBottom: '1px solid #1e293b', color: '#94a3b8' }}>
              <th style={{ padding: '0.75rem 1rem' }}>Package Name</th>
              <th style={{ padding: '0.75rem 1rem' }}>Version</th>
              <th style={{ padding: '0.75rem 1rem' }}>Ecosystem</th>
              <th style={{ padding: '0.75rem 1rem' }}>Type</th>
              <th style={{ padding: '0.75rem 1rem' }}>License</th>
              <th style={{ padding: '0.75rem 1rem' }}>Security</th>
              <th style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredPackages.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ padding: '2.5rem', textAlign: 'center', color: '#64748b' }}>
                  No software components matched your filters.
                </td>
              </tr>
            ) : (
              filteredPackages.map((pkg, idx) => (
                <tr key={idx} style={{ borderBottom: '1px solid #0f172a', transition: 'background 0.2s' }} className="table-row-hover">
                  <td style={{ padding: '0.85rem 1rem', fontWeight: 600, color: '#f8fafc' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <Package size={15} style={{ color: '#38bdf8' }} />
                      <span>{pkg.name}</span>
                    </div>
                  </td>
                  <td style={{ padding: '0.85rem 1rem', color: '#cbd5e1', fontFamily: 'monospace' }}>
                    {pkg.version}
                  </td>
                  <td style={{ padding: '0.85rem 1rem' }}>
                    <span style={{
                      background: 'rgba(51, 65, 85, 0.5)',
                      color: '#cbd5e1',
                      padding: '2px 8px',
                      borderRadius: '4px',
                      fontSize: '0.75rem',
                      fontWeight: 600,
                      textTransform: 'uppercase'
                    }}>
                      {pkg.ecosystem}
                    </span>
                  </td>
                  <td style={{ padding: '0.85rem 1rem' }}>
                    <span style={{
                      background: pkg.dependencyType === 'direct' ? 'rgba(74, 222, 128, 0.15)' : 'rgba(167, 139, 250, 0.15)',
                      color: pkg.dependencyType === 'direct' ? '#4ade80' : '#a78bfa',
                      padding: '2px 8px',
                      borderRadius: '4px',
                      fontSize: '0.75rem',
                      fontWeight: 600,
                      textTransform: 'capitalize'
                    }}>
                      {pkg.dependencyType}
                    </span>
                  </td>
                  <td style={{ padding: '0.85rem 1rem', color: '#94a3b8', fontSize: '0.8rem' }}>
                    {pkg.license}
                  </td>
                  <td style={{ padding: '0.85rem 1rem' }}>
                    {pkg.vulnerabilitiesCount > 0 ? (
                      <span style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '4px',
                        background: 'rgba(239, 68, 68, 0.15)',
                        color: '#f87171',
                        padding: '3px 8px',
                        borderRadius: '4px',
                        fontSize: '0.75rem',
                        fontWeight: 600
                      }}>
                        <ShieldAlert size={12} /> {pkg.vulnerabilitiesCount} CVE Finding(s)
                      </span>
                    ) : (
                      <span style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '4px',
                        color: '#4ade80',
                        fontSize: '0.75rem'
                      }}>
                        <CheckCircle size={12} /> Safe
                      </span>
                    )}
                  </td>
                  <td style={{ padding: '0.85rem 1rem', textAlign: 'right' }}>
                    <button
                      onClick={() => setActiveComponent(pkg)}
                      style={{
                        background: '#1e293b',
                        border: '1px solid #334155',
                        color: '#f8fafc',
                        padding: '0.35rem 0.75rem',
                        borderRadius: '6px',
                        fontSize: '0.75rem',
                        cursor: 'pointer'
                      }}
                    >
                      Details
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Component Detail Drawer / Modal */}
      {activeComponent && (
        <div style={{
          position: 'fixed',
          top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0, 0, 0, 0.75)',
          backdropFilter: 'blur(4px)',
          display: 'flex',
          justifyContent: 'flex-end',
          zIndex: 1000
        }}>
          <div style={{
            width: '100%',
            maxWidth: '520px',
            background: '#0f172a',
            borderLeft: '1px solid #1e293b',
            height: '100%',
            overflowY: 'auto',
            padding: '2rem',
            display: 'flex',
            flexDirection: 'column'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.5rem' }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '1.25rem', color: '#f8fafc' }}>{activeComponent.name}</h3>
                <p style={{ margin: '4px 0 0 0', fontSize: '0.85rem', color: '#94a3b8' }}>Version: {activeComponent.version}</p>
              </div>
              <button
                onClick={() => setActiveComponent(null)}
                style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', fontSize: '1.2rem' }}
              >
                ✕
              </button>
            </div>

            {/* PURL Card */}
            <div style={{ background: '#020617', border: '1px solid #1e293b', borderRadius: '8px', padding: '1rem', marginBottom: '1.5rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                <span style={{ fontSize: '0.75rem', color: '#94a3b8', fontWeight: 600 }}>PACKAGE URL (PURL)</span>
                <button
                  onClick={() => copyToClipboard(activeComponent.purl)}
                  style={{ background: 'none', border: 'none', color: '#38bdf8', cursor: 'pointer', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '4px' }}
                >
                  {copiedPurl === activeComponent.purl ? <Check size={12} /> : <Copy size={12} />}
                  {copiedPurl === activeComponent.purl ? 'Copied' : 'Copy'}
                </button>
              </div>
              <code style={{ fontSize: '0.8rem', color: '#38bdf8', wordBreak: 'break-all', fontFamily: 'monospace' }}>
                {activeComponent.purl}
              </code>
            </div>

            {/* Metadata Info */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
              <div>
                <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Ecosystem</span>
                <p style={{ margin: '2px 0 0 0', fontWeight: 600, color: '#f8fafc' }}>{activeComponent.ecosystem.toUpperCase()}</p>
              </div>
              <div>
                <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Dependency Type</span>
                <p style={{ margin: '2px 0 0 0', fontWeight: 600, color: activeComponent.dependencyType === 'direct' ? '#4ade80' : '#a78bfa' }}>
                  {activeComponent.dependencyType}
                </p>
              </div>
              <div>
                <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>License</span>
                <p style={{ margin: '2px 0 0 0', color: '#cbd5e1' }}>{activeComponent.license}</p>
              </div>
              <div>
                <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Package Manager</span>
                <p style={{ margin: '2px 0 0 0', color: '#cbd5e1' }}>{activeComponent.packageManager}</p>
              </div>
            </div>

            {/* Manifest Sources */}
            <div style={{ marginBottom: '1.5rem' }}>
              <span style={{ fontSize: '0.75rem', color: '#94a3b8', fontWeight: 600 }}>SOURCE MANIFESTS</span>
              <div style={{ marginTop: '0.5rem', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                {(activeComponent.manifestSources || []).map((src: string, i: number) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', color: '#cbd5e1', background: '#020617', padding: '0.4rem 0.75rem', borderRadius: '6px' }}>
                    <FileCode size={13} style={{ color: '#38bdf8' }} />
                    <span>{src}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Vulnerability Links */}
            <div style={{ marginTop: 'auto' }}>
              <span style={{ fontSize: '0.75rem', color: '#94a3b8', fontWeight: 600 }}>SECURITY FINDINGS ({activeComponent.vulnerabilitiesCount})</span>
              {activeComponent.vulnerabilitiesCount === 0 ? (
                <div style={{ background: 'rgba(74, 222, 128, 0.1)', border: '1px solid rgba(74, 222, 128, 0.2)', padding: '0.75rem', borderRadius: '8px', marginTop: '0.5rem', color: '#4ade80', fontSize: '0.85rem' }}>
                  No security vulnerabilities detected for this component.
                </div>
              ) : (
                <div style={{ marginTop: '0.5rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {(activeComponent.vulnerabilities || []).map((v: any) => (
                    <div
                      key={v.id}
                      onClick={() => navigate(`/vulnerabilities/${v.id}`)}
                      style={{
                        background: 'rgba(239, 68, 68, 0.1)',
                        border: '1px solid rgba(239, 68, 68, 0.2)',
                        padding: '0.75rem',
                        borderRadius: '8px',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between'
                      }}
                    >
                      <div>
                        <div style={{ fontSize: '0.85rem', fontWeight: 600, color: '#f87171' }}>{v.title}</div>
                        <span style={{ fontSize: '0.75rem', color: '#cbd5e1' }}>{v.cweId || 'SCA Finding'}</span>
                      </div>
                      <ArrowUpRight size={16} style={{ color: '#f87171' }} />
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
