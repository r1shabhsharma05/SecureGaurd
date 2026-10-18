import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { useOrganization } from '../context/OrganizationContext';
import { fetchInvitation, acceptInvitation } from '../services/invitationService';
import { toErrorMessage } from '../services/ApiError';
import './AcceptInvitePage.css';

interface Props {
  token: string;
  onAccepted: () => void;
  onNavigateAuth: () => void;
}

export const AcceptInvitePage: React.FC<Props> = ({ token, onAccepted, onNavigateAuth }) => {
  const { user } = useAuth();
  const { fetchOrganizations, setActiveOrgId } = useOrganization();

  const [loading, setLoading] = useState(true);
  const [invitation, setInvitation] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [accepting, setAccepting] = useState(false);
  const [acceptedOrg, setAcceptedOrg] = useState<any>(null);

  useEffect(() => {
    (async () => {
      try {
        setLoading(true);
        const data = await fetchInvitation(token);
        setInvitation(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to inspect invitation');
      } finally {
        setLoading(false);
      }
    })();
  }, [token]);

  const handleAccept = async () => {
    if (!user) {
      onNavigateAuth();
      return;
    }

    setAccepting(true);
    setError(null);

    try {
      const data = await acceptInvitation(token);

      setAcceptedOrg(data.organization);
      await fetchOrganizations();
      if (data.organization?.id) {
        setActiveOrgId(data.organization.id);
      }
    } catch (err: unknown) {
      setError(toErrorMessage(err, 'Failed to accept invitation'));
    } finally {
      setAccepting(false);
    }
  };

  if (loading) {
    return (
      <div className="invite-page-container">
        <div className="invite-card">
          <div className="spinner"></div>
          <p>Verifying invitation token...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="invite-page-container">
        <div className="invite-card error-card">
          <div className="error-icon">⚠️</div>
          <h2>Invitation Invalid</h2>
          <p>{error}</p>
          <button className="btn-primary" onClick={onAccepted}>Go to Dashboard</button>
        </div>
      </div>
    );
  }

  if (acceptedOrg) {
    return (
      <div className="invite-page-container">
        <div className="invite-card success-card">
          <div className="success-icon">🎉</div>
          <h2>Welcome to {acceptedOrg.name}!</h2>
          <p>You have successfully joined the organization workspace.</p>
          <button className="btn-primary" onClick={onAccepted}>Go to Dashboard</button>
        </div>
      </div>
    );
  }

  return (
    <div className="invite-page-container">
      <div className="invite-card">
        <div className="org-invite-avatar">{invitation.organization.name.charAt(0).toUpperCase()}</div>
        <h2>Join {invitation.organization.name}</h2>
        <p className="invite-subtitle">
          Invited by <strong>{invitation.invitedBy.firstName} {invitation.invitedBy.lastName}</strong> as a 
          <span className="role-tag"> {invitation.role}</span>
        </p>

        {!user ? (
          <div className="auth-required-box">
            <p>Please log in or sign up with <strong>{invitation.invitedEmail}</strong> to accept this invitation.</p>
            <button className="btn-primary" onClick={onNavigateAuth}>Log In / Sign Up</button>
          </div>
        ) : (
          <div className="accept-box">
            <p>Logged in as <strong>{user.email}</strong></p>
            <button className="btn-primary" onClick={handleAccept} disabled={accepting}>
              {accepting ? 'Joining Workspace...' : `Accept & Join ${invitation.organization.name}`}
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
