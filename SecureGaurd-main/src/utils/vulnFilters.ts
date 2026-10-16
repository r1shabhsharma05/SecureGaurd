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

export function filterVulns(
  vulns: FilterableVuln[],
  filterSev: string,
  filterType: string,
  searchQuery: string,
): FilterableVuln[] {
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

export function filterRepos(
  repos: FilterableRepo[],
  searchQuery: string,
): FilterableRepo[] {
  const query = searchQuery.toLowerCase();
  return repos.filter(
    (r) =>
      r.name.toLowerCase().includes(query) ||
      r.fullName.toLowerCase().includes(query),
  );
}
