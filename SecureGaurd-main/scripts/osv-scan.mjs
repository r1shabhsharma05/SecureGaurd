// OSV dependency vulnerability scan — SEC-13.
// Reads both package-lock.json files (root + backend), extracts every
// unique package@version, and queries the OSV API (api.osv.dev, no auth)
// for known vulnerabilities. Used because `npm audit` is BLOCKED on this
// VM (registry returns 403 policy_denied on the audit endpoint).
//
// Usage:
//   node scripts/osv-scan.mjs [--out results.json]
// Default output: ./osv-scan-results.json (gitignored — do not commit).
// Exit code: 0 = scan completed (even with findings); 1 = scan failed
// (network / parse error). Findings never fail the scan itself; the CI
// workflow (dependency-scan.yml) decides the gate.
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const LOCKFILES = [
  path.join(ROOT, 'package-lock.json'),
  path.join(ROOT, 'backend', 'package-lock.json'),
];
const OSV_URL = 'https://api.osv.dev/v1/querybatch';
const BATCH_SIZE = 100;

function parseArgs() {
  const outIdx = process.argv.indexOf('--out');
  return {
    out: outIdx >= 0 && process.argv[outIdx + 1]
      ? path.resolve(process.argv[outIdx + 1])
      : path.join(ROOT, 'osv-scan-results.json'),
  };
}

// lockfile v3 "packages" keys look like "node_modules/foo" or
// "node_modules/@scope/foo" (nested: ".../node_modules/bar").
function pkgNameFromKey(key) {
  const idx = key.lastIndexOf('node_modules/');
  if (idx === -1) return null;
  return key.slice(idx + 'node_modules/'.length);
}

async function collectPackages() {
  const found = new Map(); // "name@version" -> { name, version, sources: Set }
  for (const file of LOCKFILES) {
    const lock = JSON.parse(await readFile(file, 'utf8'));
    for (const [key, entry] of Object.entries(lock.packages ?? {})) {
      if (!key || !entry?.version) continue;
      const name = pkgNameFromKey(key);
      if (!name) continue;
      const id = `${name}@${entry.version}`;
      if (!found.has(id)) found.set(id, { name, version: entry.version, sources: new Set() });
      found.get(id).sources.add(path.relative(ROOT, file));
    }
  }
  return [...found.values()].map((p) => ({ ...p, sources: [...p.sources].sort() }));
}

async function queryOsvBatch(queries) {
  const res = await fetch(OSV_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ queries }),
  });
  if (!res.ok) throw new Error(`OSV querybatch HTTP ${res.status} ${res.statusText}`);
  return res.json();
}

function fixedVersions(vuln) {
  const fixed = new Set();
  for (const affected of vuln.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) fixed.add(event.fixed);
      }
    }
  }
  return [...fixed].sort();
}

function severities(vuln) {
  return (vuln.severity ?? []).map((s) => ({ type: s.type, score: s.score }));
}

// querybatch returns minimal records (id + modified only); enrich each
// finding with a full GET /v1/vulns/{id} for summary, severity, aliases,
// references and fixed versions.
async function enrich(findings) {
  for (const f of findings) {
    const res = await fetch(`${OSV_URL.replace('/querybatch', '')}/vulns/${encodeURIComponent(f.id)}`);
    if (!res.ok) { f.enrichError = `HTTP ${res.status}`; continue; }
    const v = await res.json();
    f.summary = v.summary ?? '';
    f.details = v.details ?? '';
    f.severity = severities(v);
    f.githubSeverity = v.database_specific?.severity ?? null;
    f.fixedVersions = fixedVersions(v);
    f.aliases = v.aliases ?? [];
    f.cweIds = v.database_specific?.cwe_ids ?? [];
    f.published = v.published ?? null;
    f.references = (v.references ?? []).map((r) => r.url);
  }
  return findings;
}

const { out } = parseArgs();
const packages = await collectPackages();
console.log(`Packages scanned: ${packages.length} unique name@version pairs`);
console.log(`  from: ${LOCKFILES.map((f) => path.relative(ROOT, f)).join(', ')}`);

const findings = [];
for (let i = 0; i < packages.length; i += BATCH_SIZE) {
  const chunk = packages.slice(i, i + BATCH_SIZE);
  const data = await queryOsvBatch(chunk.map((p) => ({ package: { name: p.name, ecosystem: 'npm' }, version: p.version })));
  for (let j = 0; j < chunk.length; j++) {
    const vulns = data.results?.[j]?.vulns ?? [];
    for (const v of vulns) {
      findings.push({
        package: chunk[j].name,
        version: chunk[j].version,
        sources: chunk[j].sources,
        id: v.id,
        summary: v.summary ?? '',
        severity: severities(v),
        fixedVersions: fixedVersions(v),
        aliases: v.aliases ?? [],
        references: (v.references ?? []).map((r) => r.url),
      });
    }
  }
  console.log(`  queried ${Math.min(i + BATCH_SIZE, packages.length)}/${packages.length}`);
}

const withSeverity = findings.filter((f) => f.severity.length > 0);
console.log(`Vulnerable packages: ${new Set(findings.map((f) => `${f.package}@${f.version}`)).size}`);
console.log(`Total findings (pre-enrichment): ${findings.length}`);

await enrich(findings);
const enriched = findings.filter((f) => !f.enrichError);
const withSev = enriched.filter((f) => f.severity.length > 0 || f.githubSeverity);
console.log(`Enriched: ${enriched.length}/${findings.length} (${withSev.length} with OSV severity or GitHub severity)`);
for (const f of findings) {
  const sev = f.severity.map((s) => `${s.type}:${s.score}`).join(', ')
    || (f.githubSeverity ? `GitHub:${f.githubSeverity}` : 'no severity published by OSV');
  console.log(`  ${f.id} ${f.package}@${f.version} [${sev}] fixed in: ${f.fixedVersions.join(', ') || 'none listed'}${f.aliases.length ? ` aliases: ${f.aliases.join(', ')}` : ''}`);
}

await writeFile(out, JSON.stringify({
  scannedAt: new Date().toISOString(),
  lockfiles: LOCKFILES.map((f) => path.relative(ROOT, f)),
  totalPackages: packages.length,
  findings,
}, null, 2));
console.log(`Results written to ${out}`);
