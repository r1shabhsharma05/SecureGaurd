const dns = require('dns');
const net = require('net');
const http = require('http');
const https = require('https');
const tls = require('tls');

// SSRF guard for fetching user-supplied spec URLs (Day 5: spec/URL ingestion
// is an injection surface). Every redirect hop is re-validated, and EVERY
// resolved address of the host must be public — one private A record among
// public ones is enough to block, because the fetcher could use any of them.
//
// DNS-rebinding fix: the host is resolved ONCE per hop and the fetch dials
// ONLY a validated public IP from that single resolution (custom
// createConnection over a pre-connected, verified socket, with the Host
// header and TLS servername preserved for the hostname). After connect,
// socket.remoteAddress is checked against the validated set before any
// request bytes are sent or read. There is no second DNS lookup between
// validation and fetch, so a flipping DNS answer cannot redirect the
// connection to a private address.

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

async function resolvePublicAddresses(url, lookupImpl) {
  const addresses = await lookupAll(url.hostname, lookupImpl);
  if (addresses.length === 0) {
    throw new Error('Spec URL host does not resolve');
  }
  for (const addr of addresses) {
    if (isPrivateIp(addr)) {
      throw new Error('Spec URL blocked: host resolves to a non-public address');
    }
  }
  return addresses;
}

function normalizeIp(ip) {
  const mapped = String(ip || '').toLowerCase().match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  return mapped ? mapped[1] : String(ip || '').toLowerCase();
}

// Same URL with the hostname replaced by one validated IP, for dialing
// only. The Host header / TLS servername still carry the hostname.
function pinnedUrlFor(url, ip) {
  const host = net.isIPv6(ip) ? `[${ip}]` : ip;
  const port = url.port ? `:${url.port}` : '';
  return `${url.protocol}//${host}${port}${url.pathname}${url.search}`;
}

function defaultPort(url) {
  if (url.port) return Number(url.port);
  return url.protocol === 'https:' ? 443 : 80;
}

function hostHeaderFor(url) {
  const standardPort = url.protocol === 'https:' ? 443 : 80;
  return url.port && Number(url.port) !== standardPort
    ? `${url.hostname}:${url.port}`
    : url.hostname;
}

// Dial ONLY the validated IP, verify the address the socket actually
// connected to is in the validated set, then (https) wrap it in TLS with
// the hostname as servername. No DNS is consulted here at all.
async function connectVerifiedSocket(url, ip, validated) {
  const port = defaultPort(url);
  const socket = await new Promise((resolve, reject) => {
    const s = net.connect({ host: ip, port });
    const timer = setTimeout(() => { s.destroy(); reject(new Error('Spec fetch timed out')); }, FETCH_TIMEOUT_MS);
    s.once('connect', () => { clearTimeout(timer); resolve(s); });
    s.once('error', (err) => { clearTimeout(timer); reject(err); });
  });
  if (!validated.has(normalizeIp(socket.remoteAddress))) {
    socket.destroy();
    throw new Error('Spec URL blocked: connection reached an unvalidated address');
  }
  if (url.protocol !== 'https:') return socket;
  const secure = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('Spec fetch timed out')); }, FETCH_TIMEOUT_MS);
    const s = tls.connect({ socket, servername: url.hostname });
    s.once('secureConnect', () => { clearTimeout(timer); resolve(s); });
    s.once('error', (err) => { clearTimeout(timer); reject(err); });
  });
  if (!validated.has(normalizeIp(secure.remoteAddress))) {
    secure.destroy();
    throw new Error('Spec URL blocked: connection reached an unvalidated address');
  }
  return secure;
}

// One GET over an already-connected, verified socket. Returns a fetch-like
// { status, headers, body } with the body capped at MAX_SPEC_BYTES while
// streaming (an over-large body aborts the request instead of buffering).
function requestOverSocket(url, ip, socket) {
  return new Promise((resolve, reject) => {
    const lib = url.protocol === 'https:' ? https : http;
    const req = lib.request({
      method: 'GET',
      // Dial the validated IP literally (no DNS is consulted for an IP
      // literal); Host carries the real hostname, servername the SNI.
      // createConnection returns the pre-connected, verified socket.
      host: ip,
      port: defaultPort(url),
      path: `${url.pathname}${url.search}`,
      headers: {
        Host: hostHeaderFor(url),
        Accept: 'application/json, application/yaml, text/yaml, text/plain, */*',
      },
      servername: url.protocol === 'https:' ? url.hostname : undefined,
      createConnection: () => socket,
      agent: false,
    });
    const timer = setTimeout(() => req.destroy(new Error('Spec fetch timed out')), FETCH_TIMEOUT_MS);
    req.once('error', (err) => { clearTimeout(timer); reject(err); });
    req.once('response', (res) => {
      const chunks = [];
      let total = 0;
      let failed = false;
      res.on('data', (chunk) => {
        total += chunk.length;
        if (total > MAX_SPEC_BYTES) {
          failed = true;
          req.destroy();
          reject(new Error('Spec too large (over 2 MB)'));
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => {
        if (failed) return;
        clearTimeout(timer);
        const buf = Buffer.concat(chunks);
        resolve({
          status: res.statusCode,
          headers: { get: (name) => res.headers[name.toLowerCase()] ?? null },
          body: { arrayBuffer: async () => buf },
        });
      });
      res.on('error', (err) => { if (!failed) { clearTimeout(timer); reject(err); } });
    });
    req.end();
  });
}

// Fetch one hop over pinned addresses only. Tries each validated address
// in turn (all from the single resolution — never a fresh lookup).
async function fetchPinned(url, addresses, validated) {
  let lastErr = null;
  for (const ip of addresses) {
    try {
      const socket = await connectVerifiedSocket(url, ip, validated);
      return await requestOverSocket(url, ip, socket);
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr || new Error('Spec fetch failed');
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
 * fetchImpl / lookupImpl are injectable for tests; defaults are the pinned
 * socket transport and dns.lookup. fetchImpl is a test-only transport seam:
 * it is called with the PINNED-IP URL (never the hostname), so even a
 * stubbed transport cannot re-resolve the hostname. Production callers
 * pass no fetchImpl and always use the pinned transport. Returns
 * { content, finalUrl } with finalUrl the hostname URL that was fetched.
 */
async function fetchPublicSpec(urlString, opts = {}) {
  const fetchImpl = opts.fetchImpl || null;
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
    // Resolve ONCE per hop; the returned set is the only addresses this
    // hop may dial. Re-resolved on every redirect hop the same way.
    const addresses = await resolvePublicAddresses(current, lookupImpl);
    const validated = new Set(addresses.map(normalizeIp));

    let res;
    if (fetchImpl) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
      try {
        res = await fetchImpl(pinnedUrlFor(current, addresses[0]), {
          redirect: 'manual',
          signal: controller.signal,
          headers: { Accept: 'application/json, application/yaml, text/yaml, text/plain, */*' },
        });
      } finally {
        clearTimeout(timeoutId);
      }
    } else {
      res = await fetchPinned(current, addresses, validated);
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

module.exports = { isPrivateIp, fetchPublicSpec, fetchPinned, MAX_SPEC_BYTES };
