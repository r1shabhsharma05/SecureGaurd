import { apiRequest } from './apiClient';

export interface PasswordResetRequest {
  email: string;
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
): Promise<PasswordResetResponse> {
  return apiRequest<PasswordResetResponse>('/api/auth/forgot-password', {
    method: 'POST',
    body: JSON.stringify({ email } satisfies PasswordResetRequest),
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
