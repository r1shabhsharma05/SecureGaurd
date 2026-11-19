'use strict';

/**
 * Short-lived cache for requireOrgContext membership resolutions.
 *
 * Why: requireOrgContext runs a full RLS transaction (BEGIN + set_config +
 * lookup + COMMIT) on EVERY request just to resolve (userId, orgId) ->
 * membership. The database sits a region away from the app server, so
 * that is ~4 network round trips (~0.8 s) paid before the handler's own
 * transaction even starts — on every API call, including the five
 * parallel dashboard loads. Caching the resolution for 60 s removes
 * that transaction from the hot path.
 *
 * Safety: only successful resolutions are cached. Membership mutations
 * (role change, remove, leave, ownership transfer) clear the whole
 * cache in routes/organizations.js, so a removed/demoted member loses
 * access immediately, not after the TTL. The TTL only bounds staleness
 * for changes made outside those handlers (e.g. direct DB edits).
 */

function createMembershipCache(ttlMs = 60_000, maxEntries = 500) {
  const map = new Map(); // key -> { value, expiresAt }
  return {
    get(key) {
      const entry = map.get(key);
      if (!entry) return null;
      if (Date.now() >= entry.expiresAt) {
        map.delete(key);
        return null;
      }
      return entry.value;
    },
    set(key, value) {
      // Membership resolutions are few (users x orgs); a hard cap keeps
      // a pathological key spray from growing memory without bound.
      if (map.size >= maxEntries) map.clear();
      map.set(key, { value, expiresAt: Date.now() + ttlMs });
    },
    clear() {
      map.clear();
    },
    size() {
      return map.size;
    },
  };
}

const membershipCache = createMembershipCache();

module.exports = { createMembershipCache, membershipCache };
