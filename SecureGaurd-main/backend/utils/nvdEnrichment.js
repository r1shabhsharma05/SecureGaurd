/**
 * Live NVD (National Vulnerability Database) threat-intel enrichment — Day 6.
 *
 * No API key is configured, so this module talks to the public NVD API 2.0
 * under its unauthenticated rate limit (5 requests / 30 s): calls are
 * spaced >= 6 s apart inside this process, and a 403/429 from NVD surfaces
 * as an honest error (never as an empty "no CVEs" answer — an empty answer
 * is only returned when NVD itself answered with zero version matches).
 *
 * Matching is deliberately strict: a CVE is reported for an installed
 * version ONLY when a CPE match in its configuration carries a version
 * range covering that version, or an exact CPE version equal to it. A
 * keyword hit whose ranges do not cover the installed version is NOT
 * reported — keyword search alone over-claims (e.g. lodash 4.17.10 is not
 * affected by CVE-2018-3721, whose range ends at 4.17.5).
 *
 * Cache: in-memory, keyed name@version, 24 h TTL. Every response carries
 * fetchedAt (when NVD was actually queried) and `cached` so callers can
 * tell a fresh lookup from a cached one. The cache lives in the process
 * only — Render restarts clear it, and the next call re-queries NVD.
 */
const NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const MIN_INTERVAL_MS = 6000; // unauthenticated NVD limit: 5 req / 30 s

const cache = new Map();
let lastCallAt = 0;

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function compareVersions(a, b) {
  const pa = String(a).split('.').map((x) => parseInt(x, 10) || 0);
  const pb = String(b).split('.').map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d !== 0) return d;
  }
  return 0;
}

function versionInRange(version, match) {
  const cpeVersion = (match.criteria || '').split(':')[5];
  if (cpeVersion && cpeVersion !== '*') {
    // CPE with an explicit version: exact match only.
    return compareVersions(version, cpeVersion) === 0;
  }
  if (match.versionStartIncluding && compareVersions(version, match.versionStartIncluding) < 0) return false;
  if (match.versionStartExcluding && compareVersions(version, match.versionStartExcluding) <= 0) return false;
  if (match.versionEndIncluding && compareVersions(version, match.versionEndIncluding) > 0) return false;
  if (match.versionEndExcluding && compareVersions(version, match.versionEndExcluding) >= 0) return false;
  // A wildcard CPE with no range at all claims every version — treat as
  // unproven and do NOT match (ranges are what make an NVD hit actionable).
  return Boolean(match.versionStartIncluding || match.versionStartExcluding
    || match.versionEndIncluding || match.versionEndExcluding);
}

function parseNvdResponse(body) {
  const out = [];
  for (const item of body.vulnerabilities || []) {
    const cve = item.cve || {};
    const metrics = cve.metrics || {};
    const cvss = (metrics.cvssMetricV31 && metrics.cvssMetricV31[0]?.cvssData)
      || (metrics.cvssMetricV30 && metrics.cvssMetricV30[0]?.cvssData)
      || (metrics.cvssMetricV2 && metrics.cvssMetricV2[0]?.cvssData)
      || null;
    const cpeMatches = [];
    for (const cfg of cve.configurations || []) {
      for (const node of cfg.nodes || []) {
        for (const m of node.cpeMatch || []) cpeMatches.push(m);
      }
    }
    out.push({
      cveId: cve.id,
      description: (cve.descriptions || []).find((d) => d.lang === 'en')?.value || '',
      published: cve.published || null,
      lastModified: cve.lastModified || null,
      vulnStatus: cve.vulnStatus || null,
      cvssScore: cvss?.baseScore ?? null,
      cvssSeverity: cvss?.baseSeverity || null,
      cvssVector: cvss?.vectorString || null,
      cpeMatches: cpeMatches.map((m) => ({
        criteria: m.criteria,
        versionStartIncluding: m.versionStartIncluding || null,
        versionStartExcluding: m.versionStartExcluding || null,
        versionEndIncluding: m.versionEndIncluding || null,
        versionEndExcluding: m.versionEndExcluding || null,
      })),
    });
  }
  return { totalResults: body.totalResults ?? out.length, cves: out };
}

async function queryNvd(keyword, fetchImpl = fetch) {
  const wait = MIN_INTERVAL_MS - (Date.now() - lastCallAt);
  if (wait > 0) await sleep(wait);
  lastCallAt = Date.now();
  const url = `${NVD_API}?keywordSearch=${encodeURIComponent(keyword)}&resultsPerPage=20`;
  const res = await fetchImpl(url, {
    headers: { 'User-Agent': 'SecureGuard-ThreatIntel/1.0' },
    signal: AbortSignal.timeout(15000),
  });
  if (res.status === 403 || res.status === 429) {
    throw new Error(`NVD rate limited (HTTP ${res.status}) — retry later; no CVE data returned`);
  }
  if (!res.ok) throw new Error(`NVD request failed (HTTP ${res.status})`);
  return parseNvdResponse(await res.json());
}

async function enrichComponent({ name, version }, fetchImpl = fetch) {
  const key = `${name}@${version}`;
  const hit = cache.get(key);
  if (hit && Date.now() - hit.fetchedAtMs < CACHE_TTL_MS) {
    return { ...hit.result, cached: true };
  }
  const { totalResults, cves } = await queryNvd(name, fetchImpl);
  const matched = cves.filter((c) =>
    c.cpeMatches.some((m) => versionInRange(version, m)));
  const result = {
    component: key,
    source: 'NVD API 2.0',
    fetchedAt: new Date().toISOString(),
    cached: false,
    nvdTotalResults: totalResults,
    cves: matched,
  };
  cache.set(key, { fetchedAtMs: Date.now(), result });
  return result;
}

function clearNvdCache() {
  cache.clear();
  lastCallAt = 0;
}

module.exports = {
  queryNvd, enrichComponent, parseNvdResponse, versionInRange,
  compareVersions, clearNvdCache, NVD_API,
};
