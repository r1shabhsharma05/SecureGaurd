/**
 * Dashboard filtering predicates, extracted from Dashboard.tsx.
 * Keeping data-transformation logic in utils/ separates business logic
 * from UI rendering and makes the filters unit-testable.
 */

export interface FilterableVuln {
  severity: string;
  type: string;
  title: string;
  filePath: string;
  mlFeatures?: { framework?: string } | null;
}

export interface FilterableRepo {
  name: string;
  fullName: string;
}

export function filterVulns<T extends FilterableVuln>(
  vulns: T[],
  filterSev: string,
  filterType: string,
  searchQuery: string,
): T[] {
  // Generic passthrough: callers keep their richer type (e.g. Vulnerability
  // with .id), so downstream code stays typechecked instead of degrading to
  // the minimal filter interface.
  const query = searchQuery.toLowerCase();
  return vulns.filter((v) => {
    const matchesSev =
      filterSev === 'ALL' || v.severity.toUpperCase() === filterSev;
    const matchesType =
      filterType === 'ALL' ||
      v.type.toUpperCase() === filterType ||
      (v.mlFeatures?.framework != null &&
        v.mlFeatures.framework.toUpperCase() === filterType);
    const matchesSearch =
      v.title.toLowerCase().includes(query) ||
      v.filePath.toLowerCase().includes(query);
    return matchesSev && matchesType && matchesSearch;
  });
}

export function filterRepos<T extends FilterableRepo>(
  repos: T[],
  searchQuery: string,
): T[] {
  // Generic passthrough — same rationale as filterVulns above.
  const query = searchQuery.toLowerCase();
  return repos.filter(
    (r) =>
      r.name.toLowerCase().includes(query) ||
      r.fullName.toLowerCase().includes(query),
  );
}
