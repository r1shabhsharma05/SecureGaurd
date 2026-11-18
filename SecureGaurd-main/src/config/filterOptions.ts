/**
 * Shared dashboard filter option lists.
 * Previously duplicated inline in Dashboard.tsx in two places;
 * centralized here so labels stay consistent everywhere.
 */
export const SEVERITY_FILTER_OPTIONS = [
  'ALL',
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
] as const;

export const SCAN_TYPE_FILTER_OPTIONS = [
  'ALL',
  'SAST',
  'IAC',
  'API',
  'TERRAFORM',
  'KUBERNETES',
  'DOCKER',
] as const;

// Finding lifecycle status. 'ALL' means every status (the list API
// defaults to open only when no ?status= is passed).
export const STATUS_FILTER_OPTIONS = [
  'ALL',
  'OPEN',
  'FIXED',
  'IGNORED',
  'FALSE_POSITIVE',
] as const;
