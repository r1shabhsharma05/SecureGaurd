const dns = require('dns');
const net = require('net');

// SSRF guard for fetching user-supplied spec URLs (Day 5: spec/URL ingestion
// is an injection surface). Every redirect hop is re-validated, and EVERY
// resolved address of the host must be public — one private A record among
// public ones is enough to block, because the fetcher could use any of them.

const MAX_REDIRECTS = 3;
const MAX_SPEC_BYTES = 2 * 1024 * 1024;
const FETCH_TIMEOUT_MS = 10000;

function isPrivateIPv4(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(n => Number.isNaN(n) || n < 0 || n > 255)) return true;
  const [a, b] = parts;
  return (
    a === 10 ||
    a === 127 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) ||
    a === 0 ||
    (a === 100 && b >= 64 && b <= 127) || // CGNAT, not internet-routable
    (a === 192 && b === 0) || // IETF protocol assignments incl. 192.0.0.x/192.0.2.x
    (a === 198 && (b === 18 || b === 19)) || // benchmarking
    (a === 198 && b === 51) || // documentation TEST-NET-2
    (a === 203 && b === 0) || // documentation TEST-NET-3
    a >= 224 // multicast + reserved
  );
}

function isPrivateIp(ip) {
  if (!net.isIP(ip)) return true;
  if (net.isIPv4(ip)) return isPrivateIPv4(ip);
  // IPv6: loopback, link-local, unique-local, unspecified, IPv4-mapped
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::') return true;
  if (lower.startsWith('fe8') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) return true;
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
  const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateIPv4(mapped[1]);
  return false;
}

function lookupAll(hostname, lookupImpl) {
  return new Promise((resolve, reject) => {
    lookupImpl(hostname, { all: true }, (err, addresses) => {
      if (err) return reject(err);
      resolve((addresses || []).map(a => a.address));
    });
  });
}

async function assertPublicHost(url, lookupImpl) {
  const addresses = await lookupAll(url.hostname, lookupImpl);
  if (addresses.length === 0) {
    throw new Error('Spec URL host does not resolve');
  }
  for (const addr of addresses) {
    if (isPrivateIp(addr)) {
      throw new Error('Spec URL blocked: host resolves to a non-public address');
    }
  }
}

async function readCapped(body, maxBytes) {
  if (body && typeof body.getReader === 'function') {
    const reader = body.getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        try { await reader.cancel(); } catch (e) {}
        throw new Error('Spec too large (over 2 MB)');
      }
      chunks.push(Buffer.from(value));
    }
    return Buffer.concat(chunks).toString('utf8');
  }
  // Fallback for fetch implementations without a stream reader (tests).
  const buf = Buffer.from(await body.arrayBuffer());
  if (buf.byteLength > maxBytes) throw new Error('Spec too large (over 2 MB)');
  return buf.toString('utf8');
}

/**
 * Fetch a user-supplied spec URL with SSRF protection.
 * fetchImpl / lookupImpl are injectable for tests; defaults are global
 * fetch and dns.lookup. Returns { content, finalUrl }.
 */
async function fetchPublicSpec(urlString, opts = {}) {
  const fetchImpl = opts.fetchImpl || fetch;
  const lookupImpl = opts.lookupImpl || dns.lookup;
  let current;
  try {
    current = new URL(urlString);
  } catch (e) {
    throw new Error('Invalid spec URL');
  }
  if (current.protocol !== 'http:' && current.protocol !== 'https:') {
    throw new Error('Spec URL must use http or https');
  }
  if (current.username || current.password) {
    throw new Error('Spec URL must not contain credentials');
  }

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    await assertPublicHost(current, lookupImpl);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    let res;
    try {
      res = await fetchImpl(current.toString(), {
        redirect: 'manual',
        signal: controller.signal,
        headers: { Accept: 'application/json, application/yaml, text/yaml, text/plain, */*' }
      });
    } finally {
      clearTimeout(timeoutId);
    }

    if (res.status >= 300 && res.status < 400 && res.headers && res.headers.get('location')) {
      if (hop === MAX_REDIRECTS) throw new Error('Spec URL redirects too many times');
      const next = new URL(res.headers.get('location'), current.toString());
      if (next.protocol !== 'http:' && next.protocol !== 'https:') {
        throw new Error('Spec URL redirect must use http or https');
      }
      current = next;
      continue;
    }

    if (res.status < 200 || res.status >= 300) {
      throw new Error(`Spec URL returned HTTP ${res.status}`);
    }
    const content = await readCapped(res.body, MAX_SPEC_BYTES);
    return { content, finalUrl: current.toString() };
  }
  throw new Error('Spec URL redirects too many times');
}

module.exports = { isPrivateIp, fetchPublicSpec, MAX_SPEC_BYTES };
