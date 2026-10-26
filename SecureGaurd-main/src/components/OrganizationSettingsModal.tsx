import React, { useState, useEffect, useCallback } from 'react';
import { useOrganization } from '../context/OrganizationContext';
import { useAuth } from '../context/AuthContext';
import { Check, AlertCircle, CreditCard } from 'lucide-react';
import { toErrorMessage } from '../services/ApiError';
import './OrganizationSettingsModal.css';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  initialTab?: 'members' | 'invitations' | 'audit' | 'billing' | 'settings';
}

interface BillingUsage {
  plan: string;
  planName: string;
  priceMonthly: number;
  status: string;
  cancelAtPeriodEnd: boolean;
  currentPeriodStart: string;
  currentPeriodEnd: string;
  usage: {
    scans: { used: number; limit: number; remaining: number };
    repositories: { used: number; limit: number; remaining: number };
    members: { used: number; limit: number; remaining: number };
  };
  features: string[];
}

interface BillingInvoice {
  id: string;
  number: string | null;
  status: string;
  amountDue: number;
  amountPaid: number;
  currency: string;
  created: number;
  hostedInvoiceUrl: string | null;
  invoicePdf: string | null;
}

export const OrganizationSettingsModal: React.FC<Props> = ({ isOpen, onClose, initialTab }) => {
  const { user } = useAuth();
  const {
    activeOrg,
    activeRole,
    members,
    invitations,
    auditLogs,
    orgFetch,
    fetchMembers,
    updateMemberRole,
    removeMember,
    leaveOrganization,
    transferOwnership,
    fetchInvitations,
    inviteMember,
    revokeInvitation,
    fetchAuditLogs,
    updateOrgName,
    deleteOrganization,
  } = useOrganization();

  const [activeTab, setActiveTab] = useState<'members' | 'invitations' | 'audit' | 'billing' | 'settings'>(initialTab || 'billing');

  // Billing state
  const [billingData, setBillingData] = useState<BillingUsage | null>(null);
  const [loadingBilling, setLoadingBilling] = useState(false);
  const [invoices, setInvoices] = useState<BillingInvoice[]>([]);
  const [loadingInvoices, setLoadingInvoices] = useState(false);
  const [checkoutLoading, setCheckoutLoading] = useState<string | null>(null);
  const [portalLoading, setPortalLoading] = useState(false);
  const [canceling, setCanceling] = useState(false);

  // Member invite form state
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<'OWNER' | 'ADMIN' | 'DEVELOPER' | 'AUDITOR'>('DEVELOPER');
  const [inviting, setInviting] = useState(false);
  const [inviteResult, setInviteResult] = useState<{ token: string; invitationUrl: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Settings state
  const [leaving, setLeaving] = useState(false);
  const [orgNameInput, setOrgNameInput] = useState(activeOrg ? activeOrg.name : '');
  const [savingName, setSavingName] = useState(false);
  const [deleteConfirmInput, setDeleteConfirmInput] = useState('');
  const [deleting, setDeleting] = useState(false);

  // Memoized so the load effect can safely list it as a dependency (react-hooks/exhaustive-deps)
  const fetchBillingUsage = useCallback(async () => {
    setLoadingBilling(true);
    try {
      const res = await orgFetch('/api/billing/usage');
      if (res.ok) {
        const data = await res.json();
        setBillingData(data);
      }
    } catch (err) {
      console.error('Error fetching billing data:', err);
    } finally {
      setLoadingBilling(false);
    }
  }, [orgFetch]);

  // Invoices come straight from Stripe (no local copy); OWNER/ADMIN only,
  // matching the API gate. A failed fetch leaves the list empty, never fake.
  const fetchBillingInvoices = useCallback(async () => {
    setLoadingInvoices(true);
    try {
      const res = await orgFetch('/api/billing/invoices');
      if (res.ok) {
        const data = await res.json();
        setInvoices(Array.isArray(data.invoices) ? data.invoices : []);
      }
    } catch (err) {
      console.error('Error fetching billing invoices:', err);
    } finally {
      setLoadingInvoices(false);
    }
  }, [orgFetch]);

  useEffect(() => {
    if (isOpen && activeOrg) {
      if (initialTab) setActiveTab(initialTab);
      setOrgNameInput(activeOrg.name);
      fetchMembers();
      fetchBillingUsage();
      if (activeRole === 'OWNER' || activeRole === 'ADMIN') {
        fetchInvitations();
        fetchAuditLogs();
        fetchBillingInvoices();
      }
    }
  }, [isOpen, activeOrg, activeRole, initialTab, fetchMembers, fetchBillingUsage, fetchInvitations, fetchAuditLogs, fetchBillingInvoices]);

  if (!isOpen || !activeOrg) return null;

  const canManageMembers = activeRole === 'OWNER' || activeRole === 'ADMIN';
  const isOwner = activeRole === 'OWNER';

  const handleSendInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inviteEmail.trim()) return;
    setInviting(true);
    setError(null);
    setInviteResult(null);

    try {
      const res = await inviteMember(inviteEmail.trim(), inviteRole);
      setInviteResult(res);
      setInviteEmail('');
    } catch (err: unknown) {
      setError(toErrorMessage(err, 'Failed to send invitation'));
    } finally {
      setInviting(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleUpdateName = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!orgNameInput.trim()) return;
    setSavingName(true);
    setError(null);

    try {
      await updateOrgName(orgNameInput.trim());
    } catch (err: unknown) {
      setError(toErrorMessage(err, 'Failed to update organization name'));
    } finally {
      setSavingName(false);
    }
  };

  const handleDeleteOrg = async () => {
    if (deleteConfirmInput !== activeOrg.name) return;
    setDeleting(true);
    setError(null);

    try {
      await deleteOrganization();
      onClose();
    } catch (err: unknown) {
      setError(toErrorMessage(err, 'Failed to delete organization'));
    } finally {
      setDeleting(false);
    }
  };

  const handleLeaveOrganization = async () => {
    if (!window.confirm('Leave this organization? You will lose access to its repositories, scans, and reports.')) return;
    setLeaving(true);
    setError(null);

    try {
      await leaveOrganization();
      onClose();
    } catch (err: unknown) {
      setError(toErrorMessage(err, 'Failed to leave organization'));
    } finally {
      setLeaving(false);
    }
  };

  const handleTransferOwnership = async (memberId: number, memberName: string) => {
    if (!window.confirm(`Transfer ownership to ${memberName}? You will become an Admin and can no longer transfer ownership or delete this organization.`)) return;
    setError(null);

    try {
      await transferOwnership(memberId);
    } catch (err: unknown) {
      setError(toErrorMessage(err, 'Failed to transfer ownership'));
    }
  };

  const handleUpgrade = async (planKey: string) => {
    if (!isOwner) return;
    setCheckoutLoading(planKey);
    setError(null);

    try {
      const res = await orgFetch('/api/billing/create-checkout-session', {
        method: 'POST',
        body: JSON.stringify({ plan: planKey })
      });

      const data = await res.json();
      if (res.ok && data.url) {
        window.location.href = data.url;
      } else {
        setError(data.message || 'Failed to initiate checkout session');
      }
    } catch (err: unknown) {
      setError(toErrorMessage(err, 'Error starting upgrade checkout'));
    } finally {
      setCheckoutLoading(null);
    }
  };

  const handleOpenPortal = async () => {
    if (!isOwner) return;
    setPortalLoading(true);
    setError(null);

    try {
      const res = await orgFetch('/api/billing/create-portal-session', {
        method: 'POST'
      });

      const data = await res.json();
      if (res.ok && data.url) {
        window.location.href = data.url;
      } else {
        setError(data.message || 'Failed to open billing portal');
      }
    } catch (err: unknown) {
      setError(toErrorMessage(err, 'Error launching billing portal'));
    } finally {
      setPortalLoading(false);
    }
  };

  const handleCancelSubscription = async () => {
    if (!isOwner) return;
    if (!window.confirm('Are you sure you want to schedule cancellation at the end of the billing period?')) return;

    setCanceling(true);
    setError(null);

    try {
      const res = await orgFetch('/api/billing/cancel-subscription', {
        method: 'POST'
      });

      if (res.ok) {
        await fetchBillingUsage();
      } else {
        const data = await res.json();
        setError(data.message || 'Failed to cancel subscription');
      }
    } catch (err: unknown) {
      setError(toErrorMessage(err, 'Error canceling subscription'));
    } finally {
      setCanceling(false);
    }
  };

  return (
    <div className="org-modal-overlay" onClick={onClose}>
      <div className="org-settings-card" onClick={e => e.stopPropagation()}>
        <div className="org-settings-header">
          <div className="org-settings-title">
            <div className="org-title-avatar">{activeOrg.name.charAt(0).toUpperCase()}</div>
            <div>
              <h2>{activeOrg.name}</h2>
              <span className="org-slug-subtitle">/{activeOrg.slug} • Role: {activeRole}</span>
            </div>
          </div>
          <button className="close-btn" onClick={onClose}>✕</button>
        </div>

        {error && <div className="org-modal-error">{error}</div>}

        <div className="org-settings-tabs">
          <button 
            className={`tab-btn ${activeTab === 'billing' ? 'active' : ''}`}
            onClick={() => setActiveTab('billing')}
          >
            Billing & Usage
          </button>
          
          <button 
            className={`tab-btn ${activeTab === 'members' ? 'active' : ''}`}
            onClick={() => setActiveTab('members')}
          >
            Members ({members.length})
          </button>

          {canManageMembers && (
            <button 
              className={`tab-btn ${activeTab === 'invitations' ? 'active' : ''}`}
              onClick={() => setActiveTab('invitations')}
            >
              Pending Invites ({invitations.length})
            </button>
          )}

          {canManageMembers && (
            <button 
              className={`tab-btn ${activeTab === 'audit' ? 'active' : ''}`}
              onClick={() => setActiveTab('audit')}
            >
              Audit Logs
            </button>
          )}

          <button 
            className={`tab-btn ${activeTab === 'settings' ? 'active' : ''}`}
            onClick={() => setActiveTab('settings')}
          >
            General Settings
          </button>
        </div>

        <div className="org-settings-body">
          {/* TAB 0: BILLING & USAGE */}
          {activeTab === 'billing' && (
            <div className="tab-content">
              {loadingBilling && !billingData ? (
                <div className="empty-state">Loading subscription and usage data...</div>
              ) : billingData ? (
                <div className="billing-tab-container">
                  {/* Current Subscription Card */}
                  <div className="billing-status-card">
                    <div className="billing-status-main">
                      <div>
                        <span className="billing-badge-plan">{billingData.planName} Plan</span>
                        <span className={`status-pill status-${billingData.status}`}>
                          {billingData.status.toUpperCase()}
                        </span>
                        {billingData.cancelAtPeriodEnd && (
                          <span className="cancel-notice">Cancels at period end</span>
                        )}
                      </div>
                      <p className="billing-renew-text">
                        Current period ends: {new Date(billingData.currentPeriodEnd).toLocaleDateString()}
                      </p>
                    </div>

                    {isOwner && (
                      <div className="billing-actions">
                        <button 
                          className="btn-secondary-portal" 
                          onClick={handleOpenPortal} 
                          disabled={portalLoading}
                        >
                          <CreditCard size={15} />
                          {portalLoading ? 'Opening Portal...' : 'Manage Billing (Stripe)'}
                        </button>

                        {billingData.plan !== 'FREE' && !billingData.cancelAtPeriodEnd && (
                          <button 
                            className="btn-danger-cancel"
                            onClick={handleCancelSubscription}
                            disabled={canceling}
                          >
                            {canceling ? 'Canceling...' : 'Cancel Subscription'}
                          </button>
                        )}
                      </div>
                    )}

                    {!isOwner && (
                      <div className="billing-role-restriction">
                        <AlertCircle size={15} />
                        <span>Billing management is restricted to Organization Owners.</span>
                      </div>
                    )}
                  </div>

                  {/* Metered Usage Progress */}
                  <div className="usage-meter-grid">
                    <div className="usage-meter-box">
                      <div className="usage-meter-header">
                        <span>Monthly Scans</span>
                        <strong>{billingData.usage.scans.used} / {billingData.usage.scans.limit >= 9000 ? '∞' : billingData.usage.scans.limit}</strong>
                      </div>
                      <div className="progress-bar-bg">
                        <div 
                          className="progress-bar-fill" 
                          style={{
                            width: `${Math.min(100, (billingData.usage.scans.used / billingData.usage.scans.limit) * 100)}%`,
                            backgroundColor: billingData.usage.scans.remaining === 0 ? 'var(--accent-red, #ff4d4f)' : '#0055ff'
                          }}
                        />
                      </div>
                      <p className="usage-subtext">{billingData.usage.scans.remaining} scans remaining this billing period</p>
                    </div>

                    <div className="usage-meter-box">
                      <div className="usage-meter-header">
                        <span>Repositories</span>
                        <strong>{billingData.usage.repositories.used} / {billingData.usage.repositories.limit >= 9000 ? '∞' : billingData.usage.repositories.limit}</strong>
                      </div>
                      <div className="progress-bar-bg">
                        <div 
                          className="progress-bar-fill" 
                          style={{
                            width: `${Math.min(100, (billingData.usage.repositories.used / billingData.usage.repositories.limit) * 100)}%`,
                            backgroundColor: '#10b981'
                          }}
                        />
                      </div>
                      <p className="usage-subtext">{billingData.usage.repositories.remaining} repository slots remaining</p>
                    </div>

                    <div className="usage-meter-box">
                      <div className="usage-meter-header">
                        <span>Team Members</span>
                        <strong>{billingData.usage.members.used} / {billingData.usage.members.limit >= 9000 ? '∞' : billingData.usage.members.limit}</strong>
                      </div>
                      <div className="progress-bar-bg">
                        <div 
                          className="progress-bar-fill" 
                          style={{
                            width: `${Math.min(100, (billingData.usage.members.used / billingData.usage.members.limit) * 100)}%`,
                            backgroundColor: '#8b5cf6'
                          }}
                        />
                      </div>
                      <p className="usage-subtext">{billingData.usage.members.remaining} member seats available</p>
                    </div>
                  </div>

                  {/* Plan Cards Comparison */}
                  <h4 className="plans-heading">Available Subscription Plans</h4>
                  <div className="plans-grid">
                    {/* FREE PLAN */}
                    <div className={`plan-card ${billingData.plan === 'FREE' ? 'plan-card-active' : ''}`}>
                      <div className="plan-card-header">
                        <h3>Free</h3>
                        <div className="plan-price">$0 <span>/ month</span></div>
                      </div>
                      <ul className="plan-features-list">
                        <li><Check size={14} /> 3 Code Repositories</li>
                        <li><Check size={14} /> 10 Scans per month</li>
                        <li><Check size={14} /> Up to 3 Team Members</li>
                        <li><Check size={14} /> Basic Vulnerability Scanner</li>
                        <li><Check size={14} /> SOC2 & HIPAA Compliance Reports</li>
                      </ul>
                      {billingData.plan === 'FREE' ? (
                        <button className="btn-plan-active" disabled>Current Plan</button>
                      ) : (
                        <button className="btn-plan-action" disabled={!isOwner}>Downgrade to Free</button>
                      )}
                    </div>

                    {/* PRO PLAN */}
                    <div className={`plan-card plan-card-featured ${billingData.plan === 'PRO' ? 'plan-card-active' : ''}`}>
                      <div className="featured-badge">MOST POPULAR</div>
                      <div className="plan-card-header">
                        <h3>Pro</h3>
                        <div className="plan-price">$49 <span>/ month</span></div>
                      </div>
                      <ul className="plan-features-list">
                        <li><Check size={14} /> 25 Code Repositories</li>
                        <li><Check size={14} /> 200 Scans per month</li>
                        <li><Check size={14} /> 15 Team Members</li>
                        <li><Check size={14} /> AI Vulnerability Fixes</li>
                        <li><Check size={14} /> ML False Positive Classifier</li>
                        <li><Check size={14} /> PDF & JSON Export Reports</li>
                      </ul>
                      {billingData.plan === 'PRO' ? (
                        <button className="btn-plan-active" disabled>Current Plan</button>
                      ) : (
                        <button 
                          className="btn-plan-upgrade" 
                          disabled={!isOwner || checkoutLoading === 'PRO'}
                          onClick={() => handleUpgrade('PRO')}
                        >
                          {checkoutLoading === 'PRO' ? 'Redirecting to Stripe...' : 'Upgrade to Pro'}
                        </button>
                      )}
                    </div>

                    {/* ENTERPRISE PLAN */}
                    <div className={`plan-card ${billingData.plan === 'ENTERPRISE' ? 'plan-card-active' : ''}`}>
                      <div className="plan-card-header">
                        <h3>Enterprise</h3>
                        <div className="plan-price">$299 <span>/ month</span></div>
                      </div>
                      <ul className="plan-features-list">
                        <li><Check size={14} /> Unlimited Repositories</li>
                        <li><Check size={14} /> Unlimited Monthly Scans</li>
                        <li><Check size={14} /> Unlimited Team Members</li>
                        <li><Check size={14} /> Dedicated AI Remediation Engine</li>
                        <li><Check size={14} /> Custom Compliance Frameworks</li>
                        <li><Check size={14} /> 24/7 SLA Engineer Support</li>
                      </ul>
                      {billingData.plan === 'ENTERPRISE' ? (
                        <button className="btn-plan-active" disabled>Current Plan</button>
                      ) : (
                        <button
                          className="btn-plan-upgrade"
                          disabled={!isOwner || checkoutLoading === 'ENTERPRISE'}
                          onClick={() => handleUpgrade('ENTERPRISE')}
                        >
                          {checkoutLoading === 'ENTERPRISE' ? 'Redirecting to Stripe...' : 'Upgrade to Enterprise'}
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Invoices from Stripe (OWNER/ADMIN only) */}
                  {canManageMembers && (
                    <div className="invoices-section">
                      <h4 className="plans-heading">Invoices</h4>
                      {loadingInvoices ? (
                        <div className="empty-state">Loading invoices...</div>
                      ) : invoices.length === 0 ? (
                        <div className="empty-state">No invoices yet — invoices appear here after your first payment.</div>
                      ) : (
                        <ul className="invoices-list">
                          {invoices.map((inv) => (
                            <li key={inv.id} className="invoice-row">
                              <span className="invoice-number">{inv.number || inv.id}</span>
                              <span className="invoice-date">
                                {new Date(inv.created * 1000).toLocaleDateString()}
                              </span>
                              <span className="invoice-amount">
                                {(inv.amountPaid / 100).toFixed(2)} {inv.currency.toUpperCase()}
                              </span>
                              <span className={`status-pill status-${inv.status}`}>{inv.status.toUpperCase()}</span>
                              <span className="invoice-links">
                                {inv.hostedInvoiceUrl && (
                                  <a href={inv.hostedInvoiceUrl} target="_blank" rel="noreferrer">View</a>
                                )}
                                {inv.invoicePdf && (
                                  <a href={inv.invoicePdf} target="_blank" rel="noreferrer">PDF</a>
                                )}
                              </span>
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  )}
                </div>
              ) : null}
            </div>
          )}

          {/* TAB 1: MEMBERS */}
          {activeTab === 'members' && (
            <div className="tab-content">
              {canManageMembers && (
                <div className="invite-box">
                  <h4>Invite Team Member</h4>
                  <form onSubmit={handleSendInvite} className="invite-form">
                    <input
                      type="email"
                      placeholder="colleague@company.com"
                      value={inviteEmail}
                      onChange={e => setInviteEmail(e.target.value)}
                      required
                    />
                    <select
                      value={inviteRole}
                      onChange={e => setInviteRole(e.target.value as any)}
                    >
                      <option value="DEVELOPER">Developer (Read/Scan)</option>
                      <option value="AUDITOR">Auditor (Read-only)</option>
                      <option value="ADMIN">Admin (Full Access)</option>
                      {isOwner && <option value="OWNER">Owner (Full Control)</option>}
                    </select>
                    <button type="submit" disabled={inviting}>
                      {inviting ? 'Inviting...' : 'Send Invite'}
                    </button>
                  </form>

                  {inviteResult && (
                    <div className="invite-result-box">
                      <p>✓ Invitation created!</p>
                      <div className="invite-url-row">
                        <input type="text" readOnly value={inviteResult.invitationUrl} />
                        <button onClick={() => copyToClipboard(inviteResult.invitationUrl)}>
                          {copied ? 'Copied!' : 'Copy Link'}
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}

              <div className="members-table-wrapper">
                <table className="members-table">
                  <thead>
                    <tr>
                      <th>User</th>
                      <th>Role</th>
                      <th>Joined</th>
                      {canManageMembers && <th>Actions</th>}
                    </tr>
                  </thead>
                  <tbody>
                    {members.map(m => {
                      const isSelf = m.userId === user?.id;
                      const canEditRole = isOwner || (activeRole === 'ADMIN' && m.role === 'DEVELOPER');
                      const canRemove = (isOwner && !isSelf) || (activeRole === 'ADMIN' && m.role === 'DEVELOPER');

                      return (
                        <tr key={m.id}>
                          <td>
                            <div className="user-cell">
                              <div className="user-avatar">{m.firstName.charAt(0)}</div>
                              <div>
                                <div className="user-name">{m.firstName} {m.lastName} {isSelf && '(You)'}</div>
                                <div className="user-email">{m.email}</div>
                              </div>
                            </div>
                          </td>
                          <td>
                            {canEditRole && !isSelf ? (
                              <select
                                className="role-select"
                                value={m.role}
                                onChange={e => updateMemberRole(m.id, e.target.value)}
                              >
                                {isOwner && <option value="OWNER">OWNER</option>}
                                <option value="ADMIN">ADMIN</option>
                                <option value="DEVELOPER">DEVELOPER</option>
                                <option value="AUDITOR">AUDITOR</option>
                              </select>
                            ) : (
                              <span className={`role-badge role-badge-${m.role.toLowerCase()}`}>{m.role}</span>
                            )}
                          </td>
                          <td>{new Date(m.joinedAt).toLocaleDateString()}</td>
                          {canManageMembers && (
                            <td>
                              {isOwner && !isSelf && (
                                <button className="btn-remove-member" onClick={() => handleTransferOwnership(m.id, `${m.firstName} ${m.lastName}`)}>
                                  Transfer ownership
                                </button>
                              )}
                              {canRemove ? (
                                <button className="btn-remove-member" onClick={() => removeMember(m.id)}>
                                  Remove
                                </button>
                              ) : (
                                !(isOwner && !isSelf) && <span className="text-muted">—</span>
                              )}
                            </td>
                          )}
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 2: INVITATIONS */}
          {activeTab === 'invitations' && (
            <div className="tab-content">
              {invitations.length === 0 ? (
                <div className="empty-state">No pending invitations</div>
              ) : (
                <table className="members-table">
                  <thead>
                    <tr>
                      <th>Invited Email</th>
                      <th>Role</th>
                      <th>Expires</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {invitations.map(inv => (
                      <tr key={inv.id}>
                        <td>{inv.invitedEmail}</td>
                        <td><span className={`role-badge role-badge-${inv.role.toLowerCase()}`}>{inv.role}</span></td>
                        <td>{new Date(inv.expiresAt).toLocaleDateString()}</td>
                        <td>
                          <button className="btn-remove-member" onClick={() => revokeInvitation(inv.id)}>
                            Revoke
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}

          {/* TAB 3: AUDIT LOGS */}
          {activeTab === 'audit' && (
            <div className="tab-content">
              <div className="audit-log-list">
                {auditLogs.length === 0 ? (
                  <div className="empty-state">No audit logs recorded yet</div>
                ) : (
                  auditLogs.map(log => (
                    <div key={log.id} className="audit-log-item">
                      <div className="audit-log-badge">{log.action}</div>
                      <div className="audit-log-details">
                        <span className="audit-actor">
                          {log.actor ? `${log.actor.firstName} ${log.actor.lastName} (${log.actor.email})` : 'System'}
                        </span>
                        {log.details && (
                          <pre className="audit-json">{JSON.stringify(log.details, null, 2)}</pre>
                        )}
                      </div>
                      <span className="audit-time">{new Date(log.createdAt).toLocaleString()}</span>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}

          {/* TAB 4: GENERAL SETTINGS */}
          {activeTab === 'settings' && (
            <div className="tab-content">
              <div className="settings-section">
                <h4>Workspace Name</h4>
                <form onSubmit={handleUpdateName} className="settings-form">
                  <input
                    type="text"
                    value={orgNameInput}
                    onChange={e => setOrgNameInput(e.target.value)}
                    disabled={!canManageMembers}
                    required
                  />
                  {canManageMembers && (
                    <button type="submit" disabled={savingName}>
                      {savingName ? 'Saving...' : 'Save Name'}
                    </button>
                  )}
                </form>
              </div>

              <div className="settings-section">
                <h4>Leave Organization</h4>
                {isOwner && members.filter(m => m.role === 'OWNER').length <= 1 ? (
                  <p className="text-muted">You are the sole owner of this organization. Transfer ownership to another member before leaving.</p>
                ) : (
                  <>
                    <p className="text-muted">Leaving removes your access to this organization. This cannot be undone except by a new invitation.</p>
                    <button
                      className="btn-remove-member"
                      disabled={leaving}
                      onClick={handleLeaveOrganization}
                    >
                      {leaving ? 'Leaving...' : 'Leave organization'}
                    </button>
                  </>
                )}
              </div>

              {isOwner && (
                <div className="danger-zone">
                  <h4>Danger Zone</h4>
                  <p>Deleting this organization will permanently destroy all connected repositories, scan histories, compliance reports, and audit logs.</p>
                  <div className="delete-confirm-box">
                    <label>Type <strong>{activeOrg.name}</strong> to confirm deletion:</label>
                    <input
                      type="text"
                      placeholder={activeOrg.name}
                      value={deleteConfirmInput}
                      onChange={e => setDeleteConfirmInput(e.target.value)}
                    />
                    <button
                      className="btn-danger"
                      disabled={deleteConfirmInput !== activeOrg.name || deleting}
                      onClick={handleDeleteOrg}
                    >
                      {deleting ? 'Deleting Workspace...' : 'Delete Workspace Permanently'}
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
