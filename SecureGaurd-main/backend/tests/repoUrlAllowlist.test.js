// F-02 (ARTEX 28 Nov 2026): the repo-connect reachability probe ran
// `git ls-remote` against ANY host — a blind SSRF oracle (a real GET
// reached a local listener). The probe now only touches the hosts the
// scanner can clone. Run: node --test tests/repoUrlAllowlist.test.js
// (pure function — no DNS, no network, no DB — so a rejected URL proves
// the refusal happens before any connection attempt).
const test = require('node:test');
const assert = require('node:assert/strict');

const { isAllowedRepoHost } = require('../utils/repoScanSource');

const ALLOWED = [
  'https://github.com/r1shabhsharma05/SecureGaurd.git',
  'https://gitlab.com/acme/web.git',
  'http://github.com/acme/web.git',
  'git://github.com/acme/web.git',
  'git@github.com:acme/web.git',
  'git@gitlab.com:acme/web.git',
  'https://GitHub.com/acme/web.git', // host match is case-insensitive
  'https://github.com:443/acme/web.git', // explicit default port: fine
];

const REJECTED = [
  'http://127.0.0.1:18099/evil.git', // F-02 PoC: loopback listener
  'http://localhost/acme/web.git',
  'http://[::1]/acme/web.git',
  'https://192.168.1.10/acme/web.git',
  'https://10.0.0.5/acme/web.git',
  'https://172.16.0.9/acme/web.git',
  'https://bitbucket.org/acme/web.git', // not a clone host for this product
  'https://evil.example.com/acme/web.git',
  'https://github.com:8443/acme/web.git', // non-standard port
  'https://user:pass@github.com/acme/web.git', // embedded credentials
  'git@evil.example.com:acme/web.git',
  'ftp://github.com/acme/web.git',
  '/etc/passwd',
  'not a url',
  '',
];

test('allowlisted git hosts pass (https, git://, ssh, case, default port)', () => {
  for (const url of ALLOWED) assert.equal(isAllowedRepoHost(url), true, url);
});

test('localhost, private IPs, raw IPs, other hosts, ports, credentials rejected', () => {
  for (const url of REJECTED) assert.equal(isAllowedRepoHost(url), false, url);
});
