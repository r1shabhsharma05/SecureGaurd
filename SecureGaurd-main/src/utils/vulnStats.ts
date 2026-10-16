/**
 * Vulnerability statistics helpers, extracted from Dashboard.tsx.
 * Pure functions over vulnerability lists — no UI concerns.
 */

export interface StatusCountable {
  status: string;
}

/**
 * Percentage of vulnerabilities with status 'fixed', as a whole-number
 * string (e.g. "42"). Returns '0' when there is nothing to measure.
 */
export function fixedPercentage(
  vulns: StatusCountable[],
  totalVulns: number,
): string {
  if (totalVulns <= 0) return '0';
  const fixed = vulns.filter((v) => v.status === 'fixed').length;
  return ((fixed / totalVulns) * 100).toFixed(0);
}
