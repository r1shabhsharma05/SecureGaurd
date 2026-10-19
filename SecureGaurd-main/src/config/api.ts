const configuredApiUrl = import.meta.env.VITE_API_URL?.trim() || '';
export const API_BASE_URL = configuredApiUrl.replace(/\/$/, '');

export function apiUrl(path: string): string {
  const p = path.startsWith('/') ? path : `/${path}`;
  // Production: the API is proxied same-origin through the Vercel /api/* rewrite,
  // so the session cookie stays first-party (browsers block third-party cookies).
  if (import.meta.env.PROD) return p;
  return `${API_BASE_URL}${p}`;
}