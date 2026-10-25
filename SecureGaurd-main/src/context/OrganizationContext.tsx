import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { useAuth } from './AuthContext';
import { apiUrl } from '../config/api';

export interface Organization {
  id: number;
  name: string;
  slug: string;
  role: 'OWNER' | 'ADMIN' | 'DEVELOPER' | 'AUDITOR';
  memberCount?: number;
  repositoryCount?: number;
  createdAt: string;
}

export interface OrganizationMember {
  id: number;
  userId: number;
  firstName: string;
  lastName: string;
  email: string;
  role: 'OWNER' | 'ADMIN' | 'DEVELOPER' | 'AUDITOR';
  joinedAt: string;
}

export interface PendingInvitation {
  id: number;
  invitedEmail: string;
  role: 'OWNER' | 'ADMIN' | 'DEVELOPER' | 'AUDITOR';
  status: string;
  expiresAt: string;
  createdAt: string;
}

export interface AuditLogItem {
  id: number;
  action: string;
  actorId?: number;
  actor?: {
    firstName: string;
    lastName: string;
    email: string;
  };
  targetType?: string;
  targetId?: string;
  details?: any;
  createdAt: string;
}

interface OrganizationContextType {
  organizations: Organization[];
  activeOrg: Organization | null;
  activeOrgId: number | null;
  activeRole: 'OWNER' | 'ADMIN' | 'DEVELOPER' | 'AUDITOR' | null;
  loadingOrgs: boolean;
  members: OrganizationMember[];
  invitations: PendingInvitation[];
  auditLogs: AuditLogItem[];
  setActiveOrgId: (id: number) => void;
  fetchOrganizations: () => Promise<void>;
  createOrganization: (name: string) => Promise<Organization>;
  updateOrgName: (name: string) => Promise<void>;
  deleteOrganization: () => Promise<void>;
  fetchMembers: () => Promise<void>;
  updateMemberRole: (memberId: number, role: string) => Promise<void>;
  removeMember: (memberId: number) => Promise<void>;
  leaveOrganization: () => Promise<void>;
  transferOwnership: (memberId: number) => Promise<void>;
  fetchInvitations: () => Promise<void>;
  inviteMember: (email: string, role: string) => Promise<{ token: string; invitationUrl: string }>;
  revokeInvitation: (invitationId: number) => Promise<void>;
  fetchAuditLogs: () => Promise<void>;
  orgFetch: (url: string, options?: RequestInit) => Promise<Response>;
}

const OrganizationContext = createContext<OrganizationContextType | null>(null);

export function OrganizationProvider({ children }: { children: React.ReactNode }) {
  const { user, accessToken, refreshSession } = useAuth();
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [activeOrgId, setActiveOrgIdState] = useState<number | null>(() => {
    const saved = localStorage.getItem('sg_active_org_id');
    return saved ? parseInt(saved) : null;
  });
  const [loadingOrgs, setLoadingOrgs] = useState<boolean>(true);
  const [members, setMembers] = useState<OrganizationMember[]>([]);
  const [invitations, setInvitations] = useState<PendingInvitation[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogItem[]>([]);

  // Active Organization object lookup
  const activeOrg = organizations.find(o => o.id === activeOrgId) || organizations[0] || null;
  const activeRole = activeOrg ? activeOrg.role : null;

  // Custom authenticated fetch wrapper that includes x-organization-id
  const orgFetch = useCallback(
    async (url: string, options: RequestInit = {}): Promise<Response> => {
      const targetOrgId = activeOrgId || activeOrg?.id;
      const headers = {
        ...(options.headers || {}),
        'Content-Type': 'application/json',
        ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
        ...(targetOrgId ? { 'x-organization-id': String(targetOrgId) } : {}),
      };

      let res = await fetch(apiUrl(url), { ...options, headers, credentials: 'include' });

      if (res.status === 401) {
        const ok = await refreshSession();
        if (ok) {
          res = await fetch(apiUrl(url), {
            ...options,
            headers: {
              ...headers,
              ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
            },
            credentials: 'include',
          });
        }
      }
      return res;
    },
    [accessToken, activeOrgId, activeOrg?.id, refreshSession]
  );

  const fetchOrganizations = useCallback(async () => {
    if (!user) {
      setOrganizations([]);
      setLoadingOrgs(false);
      return;
    }

    try {
      setLoadingOrgs(true);
      const res = await orgFetch('/api/organizations');
      if (res.ok) {
        const data: Organization[] = await res.json();
        setOrganizations(data);

        // If no active org selected or selected org no longer exists, select first available
        if (data.length > 0) {
          const currentValid = data.find(o => o.id === activeOrgId);
          if (!currentValid) {
            setActiveOrgIdState(data[0].id);
            localStorage.setItem('sg_active_org_id', String(data[0].id));
          }
        }
      }
    } catch (err) {
      console.error('Failed to fetch organizations:', err);
    } finally {
      setLoadingOrgs(false);
    }
  }, [user, activeOrgId, orgFetch]);

  useEffect(() => {
    fetchOrganizations();
  }, [fetchOrganizations]);

  const setActiveOrgId = (id: number) => {
    setActiveOrgIdState(id);
    localStorage.setItem('sg_active_org_id', String(id));
  };

  const createOrganization = async (name: string): Promise<Organization> => {
    const res = await orgFetch('/api/organizations', {
      method: 'POST',
      body: JSON.stringify({ name }),
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to create organization');

    await fetchOrganizations();
    setActiveOrgId(data.id);
    return data;
  };

  const updateOrgName = async (name: string) => {
    if (!activeOrg) return;
    const res = await orgFetch(`/api/organizations/${activeOrg.id}`, {
      method: 'PATCH',
      body: JSON.stringify({ name }),
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to update organization');

    setOrganizations(prev => prev.map(o => o.id === activeOrg.id ? { ...o, name: data.name } : o));
  };

  const deleteOrganization = async () => {
    if (!activeOrg) return;
    const res = await orgFetch(`/api/organizations/${activeOrg.id}`, {
      method: 'DELETE',
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to delete organization');

    localStorage.removeItem('sg_active_org_id');
    setActiveOrgIdState(null);
    await fetchOrganizations();
  };

  // Memoized (referentially stable) so consumers can list these in effect
  // dependency arrays without re-running effects on every render.
  const fetchMembers = useCallback(async () => {
    if (!activeOrg) return;
    try {
      const res = await orgFetch(`/api/organizations/${activeOrg.id}/members`);
      if (res.ok) {
        const data = await res.json();
        setMembers(data);
      }
    } catch (err) {
      console.error('Failed to fetch members:', err);
    }
  }, [activeOrg, orgFetch]);

  const updateMemberRole = async (memberId: number, role: string) => {
    if (!activeOrg) return;
    const res = await orgFetch(`/api/organizations/${activeOrg.id}/members/${memberId}`, {
      method: 'PATCH',
      body: JSON.stringify({ role }),
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to update role');

    await fetchMembers();
  };

  const removeMember = async (memberId: number) => {
    if (!activeOrg) return;
    const res = await orgFetch(`/api/organizations/${activeOrg.id}/members/${memberId}`, {
      method: 'DELETE',
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to remove member');

    await fetchMembers();
  };

  const leaveOrganization = async () => {
    if (!activeOrg) return;
    const res = await orgFetch(`/api/organizations/${activeOrg.id}/leave`, {
      method: 'POST',
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to leave organization');

    // The left org is gone from this user's list: drop the saved selection
    // and refresh (same pattern as deleteOrganization).
    localStorage.removeItem('sg_active_org_id');
    setActiveOrgIdState(null);
    await fetchOrganizations();
  };

  const transferOwnership = async (memberId: number) => {
    if (!activeOrg) return;
    const res = await orgFetch(`/api/organizations/${activeOrg.id}/transfer-ownership`, {
      method: 'POST',
      body: JSON.stringify({ memberId }),
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to transfer ownership');

    // The caller's own role drops to ADMIN: refresh members and the org list.
    await fetchMembers();
    await fetchOrganizations();
  };

  const fetchInvitations = useCallback(async () => {
    if (!activeOrg || (activeRole !== 'OWNER' && activeRole !== 'ADMIN')) return;
    try {
      const res = await orgFetch(`/api/organizations/${activeOrg.id}/invitations`);
      if (res.ok) {
        const data = await res.json();
        setInvitations(data);
      }
    } catch (err) {
      console.error('Failed to fetch invitations:', err);
    }
  }, [activeOrg, activeRole, orgFetch]);

  const inviteMember = async (email: string, role: string) => {
    if (!activeOrg) throw new Error('No active organization');
    const res = await orgFetch(`/api/organizations/${activeOrg.id}/invitations`, {
      method: 'POST',
      body: JSON.stringify({ email, role }),
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to send invitation');

    await fetchInvitations();
    return { token: data.token, invitationUrl: data.invitationUrl };
  };

  const revokeInvitation = async (invitationId: number) => {
    if (!activeOrg) return;
    const res = await orgFetch(`/api/organizations/${activeOrg.id}/invitations/${invitationId}`, {
      method: 'DELETE',
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to revoke invitation');

    await fetchInvitations();
  };

  const fetchAuditLogs = useCallback(async () => {
    if (!activeOrg || (activeRole !== 'OWNER' && activeRole !== 'ADMIN')) return;
    try {
      const res = await orgFetch(`/api/organizations/${activeOrg.id}/audit-logs`);
      if (res.ok) {
        const data = await res.json();
        setAuditLogs(data);
      }
    } catch (err) {
      console.error('Failed to fetch audit logs:', err);
    }
  }, [activeOrg, activeRole, orgFetch]);

  return (
    <OrganizationContext.Provider
      value={{
        organizations,
        activeOrg,
        activeOrgId: activeOrg ? activeOrg.id : null,
        activeRole,
        loadingOrgs,
        members,
        invitations,
        auditLogs,
        setActiveOrgId,
        fetchOrganizations,
        createOrganization,
        updateOrgName,
        deleteOrganization,
        fetchMembers,
        updateMemberRole,
        removeMember,
        leaveOrganization,
        transferOwnership,
        fetchInvitations,
        inviteMember,
        revokeInvitation,
        fetchAuditLogs,
        orgFetch,
      }}
    >
      {children}
    </OrganizationContext.Provider>
  );
}

export function useOrganization() {
  const ctx = useContext(OrganizationContext);
  if (!ctx) throw new Error('useOrganization must be used inside <OrganizationProvider>');
  return ctx;
}
