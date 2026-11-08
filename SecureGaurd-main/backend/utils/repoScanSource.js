// Resolve the working tree a scan should actually run over: the CONNECTED
// repository's own source, never SecureGaurd's own checkout.
//
// Resolution order:
//   1. A local path, but ONLY inside the explicitly allowlisted base
//      directory SCAN_LOCAL_BASE (realpath-resolved, containment verified).
//      When SCAN_LOCAL_BASE is unset, no local path is allowed at all.
//   2. A remote git URL on an allowlisted host (github.com, gitlab.com,
//      plus EXTRA_GIT_HOSTS), with no embedded credentials and every
//      resolved address public → shallow clone into a temp dir under
//      ~/workspace/tmp-work/scan-clones (override with SCAN_CLONE_DIR).
// Throws with a clear message when no source is reachable, so callers can
// fail the scan honestly instead of silently scanning the wrong tree.
const fs = require('fs');
const path = require('path');
const net = require('net');
const { execFileSync } = require('child_process');
const { isPrivateIp } = require('./ssrfGuard');

const CLONE_BASE = process.env.SCAN_CLONE_DIR
  || path.resolve(__dirname, '../../../../tmp-work/scan-clones');

// Clone hosts are allowlisted: a public git host only. Extra hosts come
// solely from EXTRA_GIT_HOSTS (comma-separated), never from the repo URL.
const ALLOWED_CLONE_HOSTS = new Set(['github.com', 'gitlab.com',
  ...(process.env.EXTRA_GIT_HOSTS || '').split(',').map((h) => h.trim().toLowerCase()).filter(Boolean)]);

function normalizeCloneUrl(repo) {
  let url = (repo.url || '').trim();
  if (!url && repo.fullName) {
    if (repo.platform === 'github') url = `https://github.com/${repo.fullName}.git`;
    else if (repo.platform === 'gitlab') url = `https://gitlab.com/${repo.fullName}.git`;
  }
  // SSH-style remote for a public host → anonymous HTTPS clone.
  const sshMatch = url.match(/^git@([^:]+):(.+)$/);
  if (sshMatch) url = `https://${sshMatch[1]}/${sshMatch[2]}`;
  return url;
}

// Local paths are confined to SCAN_LOCAL_BASE. The base is resolved fresh
// on each call (env may be set after this module loads); when it is unset
// or does not exist, no local path is allowed.
function resolveLocalPath(candidate) {
  const baseEnv = process.env.SCAN_LOCAL_BASE;
  if (!baseEnv) return null;
  let base;
  try {
    base = fs.realpathSync(baseEnv);
  } catch {
    return null;
  }
  let real;
  try {
    real = fs.realpathSync(candidate);
  } catch {
    return null;
  }
  if (real !== base && !real.startsWith(base + path.sep)) return null;
  return real;
}

// resolveScanTarget is synchronous (every caller invokes it without await),
// so DNS resolution must be synchronous too: `getent ahosts` performs the
// same system-resolver lookup dns.lookup would, in-process. Any resolution
// failure fails closed — the clone never runs.
function lookupHostAddresses(hostname) {
  if (net.isIP(hostname)) return [hostname];
  let out;
  try {
    out = execFileSync('getent', ['ahosts', hostname], {
      timeout: 5000, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch {
    throw new Error(`Could not resolve clone host ${hostname}`);
  }
  const addresses = [...new Set(out.split('\n')
    .map((line) => line.trim().split(/\s+/)[0])
    .filter((addr) => addr && net.isIP(addr)))];
  if (addresses.length === 0) throw new Error(`Clone host ${hostname} does not resolve`);
  return addresses;
}

// SSRF guard for the clone path, run before any git invocation: reject
// credentials in the URL, enforce the host allowlist, and require EVERY
// resolved address of the host to be public (reuse isPrivateIp).
// NOTE: the DNS check is time-of-check/time-of-use — the address git
// resolves could change between validation and the clone. The host
// allowlist is what bounds that residual rebinding risk: only
// github.com/gitlab.com (plus EXTRA_GIT_HOSTS) can ever be reached.
function validateCloneUrl(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Repository URL is not a valid remote git URL: ${url}`);
  }
  if (!['http:', 'https:', 'git:'].includes(parsed.protocol)) {
    throw new Error(`Repository URL must use http, https or git: ${url}`);
  }
  if (parsed.username || parsed.password) {
    throw new Error('Repository URL must not contain credentials');
  }
  const host = parsed.hostname.toLowerCase();
  if (!ALLOWED_CLONE_HOSTS.has(host)) {
    throw new Error(`Clone host ${host} is not allowlisted`);
  }
  for (const addr of lookupHostAddresses(host)) {
    if (isPrivateIp(addr)) {
      throw new Error(`Clone host ${host} resolves to a non-public address`);
    }
  }
}

function resolveScanTarget(repo, options = {}) {
  const url = normalizeCloneUrl(repo);

  // Local path source, confined to SCAN_LOCAL_BASE (unset → none allowed).
  const localCandidate = (repo.url || '').trim();
  const localPath = (localCandidate && resolveLocalPath(localCandidate))
    || (url && resolveLocalPath(url));
  if (localPath) {
    return { scanPath: localPath, cleanup: () => {} };
  }

  if (!url || !/^(https?:\/\/|git:\/\/)/i.test(url)) {
    throw new Error(`Repository ${repo.fullName || repo.id} has no reachable source (remote git URL required; local paths are only allowed inside SCAN_LOCAL_BASE)`);
  }

  validateCloneUrl(url);

  fs.mkdirSync(CLONE_BASE, { recursive: true });
  const dir = fs.mkdtempSync(path.join(CLONE_BASE, 'scan-'));
  // http.followRedirects=false so a redirect cannot carry the clone to an
  // unvalidated host (git would otherwise follow it silently).
  const args = ['-c', 'http.followRedirects=false', 'clone', '--depth', '1'];
  if (options.branch) args.push('--branch', options.branch);
  args.push(url, dir);
  try {
    execFileSync('git', args, { timeout: 180000, stdio: ['ignore', 'ignore', 'pipe'] });
  } catch (err) {
    fs.rmSync(dir, { recursive: true, force: true });
    const detail = (err.stderr || err.message || 'git clone failed').toString().trim().split('\n').pop();
    throw new Error(`Could not clone repository ${repo.fullName || ''} from ${url}: ${detail}`);
  }

  let cleaned = false;
  return {
    scanPath: dir,
    cleanup: () => {
      if (cleaned) return;
      cleaned = true;
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

module.exports = { resolveScanTarget };
