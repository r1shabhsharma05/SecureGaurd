// Resolve the working tree a scan should actually run over: the CONNECTED
// repository's own source, never SecureGaurd's own checkout.
//
// Resolution order:
//   1. repo.url (or a URL built from platform + fullName) that points at an
//      existing local directory → scan it in place.
//   2. A remote git URL → shallow clone into a temp dir under
//      ~/workspace/tmp-work/scan-clones (override with SCAN_CLONE_DIR).
// Throws with a clear message when no source is reachable, so callers can
// fail the scan honestly instead of silently scanning the wrong tree.
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const CLONE_BASE = process.env.SCAN_CLONE_DIR
  || path.resolve(__dirname, '../../../../tmp-work/scan-clones');

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

function resolveScanTarget(repo, options = {}) {
  const url = normalizeCloneUrl(repo);

  // Local path source (stored path or a url that is a filesystem path).
  const localCandidate = (repo.url || '').trim();
  if (localCandidate && !/^https?:\/\//i.test(localCandidate) && fs.existsSync(localCandidate)) {
    return { scanPath: localCandidate, cleanup: () => {} };
  }
  if (url && fs.existsSync(url)) {
    return { scanPath: url, cleanup: () => {} };
  }

  if (!url || !/^(https?:\/\/|git:\/\/)/i.test(url)) {
    throw new Error(`Repository ${repo.fullName || repo.id} has no reachable source (no cloneable URL or local path)`);
  }

  fs.mkdirSync(CLONE_BASE, { recursive: true });
  const dir = fs.mkdtempSync(path.join(CLONE_BASE, 'scan-'));
  const args = ['clone', '--depth', '1'];
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
