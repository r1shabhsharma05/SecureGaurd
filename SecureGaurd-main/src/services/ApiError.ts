/**
 * Typed error for failed API requests.
 *
 * Carries the HTTP status so callers can branch on it (e.g. 401 -> prompt
 * re-login) instead of parsing message strings. Thrown by `apiRequest`
 * for every non-2xx response.
 */
export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message?: string) {
    super(message || statusMessage(status));
    this.name = 'ApiError';
    this.status = status;
  }
}

const STATUS_MESSAGES: Record<number, string> = {
  400: 'The request was invalid. Please check your input and try again.',
  401: 'Your session has expired. Please sign in again.',
  403: 'You do not have permission to perform this action.',
  404: 'The requested resource was not found.',
  409: 'This conflicts with an existing record.',
  422: 'The request could not be processed. Please check your input.',
  429: 'Too many requests. Please wait a moment and try again.',
  500: 'Something went wrong on our end. Please try again later.',
  502: 'The server is temporarily unavailable. Please try again later.',
  503: 'The service is temporarily unavailable. Please try again later.',
};

export function statusMessage(status: number): string {
  if (STATUS_MESSAGES[status]) return STATUS_MESSAGES[status];
  if (status >= 500) return 'Something went wrong on our end. Please try again later.';
  if (status >= 400) return 'The request could not be completed.';
  return 'An unexpected error occurred.';
}

/**
 * Extract a human-readable message from an unknown caught value.
 * Replaces the unsafe `catch (err: any) { err.message }` pattern so
 * components handle errors with full type safety.
 */
export function toErrorMessage(err: unknown, fallback: string): string {
  if (err instanceof Error) return err.message || fallback;
  if (typeof err === 'string' && err) return err;
  return fallback;
}
