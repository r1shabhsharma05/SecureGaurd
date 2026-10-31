import './Skeleton.css';

// Day 8 — shared loading skeletons. Every async view renders one of these
// while its data is in flight instead of a bare "Loading…" line or a
// flash of empty content. The shimmer is disabled under
// prefers-reduced-motion (Skeleton.css).
export function Skeleton({ width, height, label }: { width?: string; height?: string; label?: string }) {
  return (
    <div
      className="skeleton"
      role="status"
      aria-label={label ?? 'Loading'}
      style={{ width: width ?? '100%', height: height ?? '1rem' }}
    />
  );
}

export function SkeletonCard() {
  return (
    <div className="skeleton-card" role="status" aria-label="Loading">
      <Skeleton height="1.25rem" width="55%" />
      <Skeleton height="0.9rem" width="85%" />
      <Skeleton height="0.9rem" width="70%" />
    </div>
  );
}

export function SkeletonTable({ rows = 4 }: { rows?: number }) {
  return (
    <div role="status" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} height="2.75rem" label={i === 0 ? 'Loading' : undefined} />
      ))}
    </div>
  );
}

export function PageSkeleton() {
  return (
    <div className="skeleton-page" role="status" aria-label="Loading page">
      <Skeleton height="2rem" width="40%" />
      <div className="skeleton-grid">
        <SkeletonCard />
        <SkeletonCard />
        <SkeletonCard />
      </div>
      <SkeletonTable rows={4} />
    </div>
  );
}
