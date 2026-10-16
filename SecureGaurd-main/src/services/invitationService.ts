import { apiRequest } from './apiClient';
import { apiUrl } from '../config/api';

export interface InvitationDetails {
  // Invitation payload shape is decided by the backend; keep it loose here
  // so the service stays decoupled from backend internals.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any;
}

export interface AcceptInvitationResponse {
  organization?: { id?: string };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any;
}

/**
 * Organization-invitation API calls.
 * AcceptInvitePage previously embedded these fetch calls inline;
 * they now live in the service layer.
 */
export async function fetchInvitation(token: string): Promise<InvitationDetails> {
  return apiRequest<InvitationDetails>(`/api/invitations/${token}`);
}

export async function acceptInvitation(
  token: string,
): Promise<AcceptInvitationResponse> {
  // NOTE: the accept endpoint requires cookies, so it uses a raw fetch
  // instead of apiRequest (which sets Content-Type: application/json).
  const res = await fetch(apiUrl(`/api/invitations/${token}/accept`), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
  });
  const data = (await res.json()) as AcceptInvitationResponse;
  if (!res.ok) {
    throw new Error(data?.message || 'Failed to accept invitation');
  }
  return data;
}
