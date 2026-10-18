import React, { useState } from 'react';
import { useOrganization } from '../context/OrganizationContext';
import { toErrorMessage } from '../services/ApiError';
import './OrganizationSwitcher.css';

interface Props {
  onOpenSettings?: () => void;
}

export const OrganizationSwitcher: React.FC<Props> = ({ onOpenSettings }) => {
  const { organizations, activeOrg, activeRole, setActiveOrgId, createOrganization } = useOrganization();
  const [isOpen, setIsOpen] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newOrgName, setNewOrgName] = useState('');
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSelect = (id: number) => {
    setActiveOrgId(id);
    setIsOpen(false);
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newOrgName.trim()) return;
    setCreating(true);
    setError(null);
    try {
      await createOrganization(newOrgName.trim());
      setNewOrgName('');
      setShowCreateModal(false);
      setIsOpen(false);
    } catch (err: unknown) {
      setError(toErrorMessage(err, 'Failed to create workspace'));
    } finally {
      setCreating(false);
    }
  };

  const roleColors: Record<string, string> = {
    OWNER: 'role-badge-owner',
    ADMIN: 'role-badge-admin',
    DEVELOPER: 'role-badge-dev',
  };

  return (
    <div className="org-switcher-container">
      <button 
        className="org-switcher-trigger"
        onClick={() => setIsOpen(!isOpen)}
        aria-label="Organization selector"
      >
        <div className="org-avatar">
          {activeOrg ? activeOrg.name.charAt(0).toUpperCase() : 'W'}
        </div>
        <div className="org-info">
          <span className="org-name">{activeOrg ? activeOrg.name : 'Loading workspace...'}</span>
          {activeRole && (
            <span className={`org-role-badge ${roleColors[activeRole] || ''}`}>
              {activeRole}
            </span>
          )}
        </div>
        <svg className={`chevron ${isOpen ? 'open' : ''}`} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <polyline points="6 9 12 15 18 9"></polyline>
        </svg>
      </button>

      {isOpen && (
        <div className="org-dropdown">
          <div className="org-dropdown-header">
            <span>Workspaces ({organizations.length})</span>
          </div>
          <div className="org-list">
            {organizations.map((org) => (
              <button
                key={org.id}
                className={`org-item ${activeOrg?.id === org.id ? 'active' : ''}`}
                onClick={() => handleSelect(org.id)}
              >
                <div className="org-item-avatar">
                  {org.name.charAt(0).toUpperCase()}
                </div>
                <div className="org-item-details">
                  <span className="org-item-name">{org.name}</span>
                  <span className="org-item-meta">{org.repositoryCount || 0} Repos • {org.memberCount || 1} Members</span>
                </div>
                <span className={`org-role-badge ${roleColors[org.role] || ''}`}>
                  {org.role}
                </span>
              </button>
            ))}
          </div>

          <div className="org-dropdown-divider"></div>

          <div className="org-dropdown-actions">
            {onOpenSettings && (
              <button className="org-dropdown-btn settings" onClick={() => { setIsOpen(false); onOpenSettings(); }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="3"></circle>
                  <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
                </svg>
                Team & Settings
              </button>
            )}

            <button className="org-dropdown-btn create" onClick={() => setShowCreateModal(true)}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <line x1="12" y1="5" x2="12" y2="19"></line>
                <line x1="5" y1="12" x2="19" y2="12"></line>
              </svg>
              Create New Workspace
            </button>
          </div>
        </div>
      )}

      {showCreateModal && (
        <div className="org-modal-overlay" onClick={() => setShowCreateModal(false)}>
          <div className="org-modal-card" onClick={e => e.stopPropagation()}>
            <div className="org-modal-header">
              <h3>Create New Organization</h3>
              <button className="close-btn" onClick={() => setShowCreateModal(false)}>✕</button>
            </div>

            {error && <div className="org-modal-error">{error}</div>}

            <form onSubmit={handleCreate}>
              <div className="form-group">
                <label>Organization Name</label>
                <input
                  type="text"
                  placeholder="e.g. Acme Cyber Security"
                  value={newOrgName}
                  onChange={e => setNewOrgName(e.target.value)}
                  autoFocus
                  required
                />
              </div>

              <div className="org-modal-actions">
                <button type="button" className="btn-cancel" onClick={() => setShowCreateModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn-create" disabled={creating}>
                  {creating ? 'Creating...' : 'Create Workspace'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
