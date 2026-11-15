import { apiRequest } from './apiClient';
import { apiUrl } from '../config/api';

export interface PasswordResetRequest {
  email: string;
  /** Cloudflare Turnstile token (Day 9). Sent only when the widget is active. */
  turnstileToken?: string;
}

export interface PasswordResetResponse {
  message: string;
  /** Present in dev environments to auto-fill the reset token. */
  resetToken?: string;
}

export interface ResetPasswordRequest {
  token: string;
  newPassword: string;
}

export interface ResetPasswordResponse {
  message: string;
}

/**
 * Auth-related API calls that don't require a session.
 * Kept out of UI components so AuthPage only handles presentation state.
 */
export async function requestPasswordReset(
  email: string,
  turnstileToken?: string,
): Promise<PasswordResetResponse> {
  return apiRequest<PasswordResetResponse>('/api/auth/forgot-password', {
    method: 'POST',
    body: JSON.stringify({ email, ...(turnstileToken ? { turnstileToken } : {}) } satisfies PasswordResetRequest),
  });
}

export async function resetPassword(
  token: string,
  newPassword: string,
): Promise<ResetPasswordResponse> {
  return apiRequest<ResetPasswordResponse>('/api/auth/reset-password', {
    method: 'POST',
    body: JSON.stringify({ token, newPassword } satisfies ResetPasswordRequest),
  });
}

/** Re-send the email-verification link (SEC-09). Generic message by design. */
export async function resendVerification(email: string): Promise<{ message: string }> {
  return apiRequest<{ message: string }>('/api/auth/resend-verification', {
    method: 'POST',
    body: JSON.stringify({ email }),
  });
}

export interface ChangePasswordRequest {
  currentPassword: string;
  newPassword: string;
}

/**
 * Signed-in password change (SEC-38). Server requires the current
 * password and clears all sessions afterwards — the caller must treat a
 * success as a logout and send the user back to login.
 */
export async function changePassword(
  accessToken: string,
  currentPassword: string,
  newPassword: string,
): Promise<{ message: string }> {
  const res = await fetch(apiUrl('/api/auth/change-password'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` },
    credentials: 'include',
    body: JSON.stringify({ currentPassword, newPassword } satisfies ChangePasswordRequest),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.message || 'Password change failed.');
  return data;
}

/**
 * Delete the signed-in account (Day 9). Requires the current password and
 * the typed confirmation "DELETE" — enforced server-side. Returns the
 * handoff summary (transferred / deleted / left organizations).
 */
export async function deleteAccount(
  accessToken: string,
  password: string,
  confirmation: string,
): Promise<{ message: string; transferredOrganizations: number[]; deletedOrganizations: number[]; leftOrganizations: number[] }> {
  const res = await fetch(apiUrl('/api/auth/account'), {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` },
    credentials: 'include',
    body: JSON.stringify({ password, confirmation }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.message || 'Account deletion failed.');
  return data;
}
