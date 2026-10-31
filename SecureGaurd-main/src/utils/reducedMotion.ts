// Day 8 — single source of truth for the reduced-motion preference, shared
// by the GSAP entrance animations. CSS animations/transitions are handled by
// the prefers-reduced-motion block in index.css / Skeleton.css; framer-motion
// is handled by <MotionConfig reducedMotion="user"> in App.tsx.
export function prefersReducedMotion(): boolean {
  return typeof window !== 'undefined'
    && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}
