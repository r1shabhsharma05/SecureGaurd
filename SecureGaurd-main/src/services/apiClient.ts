import { apiUrl } from '../config/api';

/**
 * Shared JSON request helper for service-layer API calls.
 * Centralizes response parsing and error handling so UI components
 * stay free of fetch boilerplate (separation of concerns).
 */
export async function apiRequest<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const res = await fetch(apiUrl(path), {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });

  let data: T;
  try {
    data = (await res.json()) as T;
  } catch {
    throw new Error(`Request to ${path} returned a non-JSON response`);
  }

  if (!res.ok) {
    const message =
      (data as unknown as { message?: string })?.message ||
      `Request to ${path} failed with status ${res.status}`;
    throw new Error(message);
  }

  return data;
}
