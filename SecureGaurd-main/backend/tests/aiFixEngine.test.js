// Regression tests for the audit finding "rule-based AI fix returns the
// original vulnerable code as the fix when its narrow regex does not
// match" (SecureGaurd-main/backend/utils/aiFixEngine.js).
// Run: node --test tests/aiFixEngine.test.js (no DB, no network, no keys).
const test = require('node:test');
const assert = require('node:assert/strict');

const { generateAiFix } = require('../utils/aiFixEngine');

// The rule engine is the default only when no Gemini key is configured.
const savedWeb2ApiKey = process.env.GEMINI_WEB2API_KEY;
const savedApiKey = process.env.GEMINI_API_KEY;
delete process.env.GEMINI_WEB2API_KEY;
delete process.env.GEMINI_API_KEY;

test.after(() => {
  if (savedWeb2ApiKey !== undefined) process.env.GEMINI_WEB2API_KEY = savedWeb2ApiKey;
  if (savedApiKey !== undefined) process.env.GEMINI_API_KEY = savedApiKey;
});

// The audit's three non-matching payloads: none of these match the
// templates' narrow regexes, so the fix must be the safe fallback
// template — never the input snippet verbatim.
const NON_MATCHING = [
  {
    name: 'double-quoted SQL concat',
    vuln: {
      title: 'Potential SQL Injection',
      codeSnippet: 'db.query("SELECT * FROM users WHERE id = " + req.query.id)',
      filePath: 'src/api.js',
      severity: 'critical',
    },
  },
  {
    name: 'res.json XSS',
    vuln: {
      title: 'Cross-Site Scripting (XSS)',
      codeSnippet: 'res.json({ name: req.query.name })',
      filePath: 'src/api.js',
      severity: 'high',
    },
  },
  {
    name: 'jwt.verify with a variable secret',
    vuln: {
      title: 'Weak JWT Signature Verification',
      codeSnippet: 'jwt.verify(token, secret)',
      filePath: 'src/auth.js',
      severity: 'critical',
    },
  },
];

for (const { name, vuln } of NON_MATCHING) {
  test(`non-matching ${name}: fix is the safe fallback, never the input`, async () => {
    const result = await generateAiFix(vuln);
    assert.equal(result.engine, 'rule-based');
    assert.equal(result.noFixAvailable, undefined);
    assert.ok(result.fixedCode, 'expected a fallback fix, got none');
    assert.notEqual(result.fixedCode, vuln.codeSnippet);
    assert.notEqual(result.fixedCode.trim(), vuln.codeSnippet.trim());
  });
}

// Matching-shape controls: the templates must still rewrite on a match.
const MATCHING = [
  {
    name: 'backtick SQL template literal',
    vuln: {
      title: 'Potential SQL Injection',
      codeSnippet: 'db.query(`SELECT * FROM users WHERE id = ${req.query.id}`)',
      filePath: 'src/api.js',
      severity: 'critical',
    },
    expect: '?',
  },
  {
    name: 'res.send template literal XSS',
    vuln: {
      title: 'Cross-Site Scripting (XSS)',
      codeSnippet: 'res.send(`<h1>Hello ${req.query.name}</h1>`)',
      filePath: 'src/api.js',
      severity: 'high',
    },
    expect: 'sanitized',
  },
  {
    name: 'jwt.verify with a quoted secret',
    vuln: {
      title: 'Weak JWT Signature Verification',
      codeSnippet: "jwt.verify(token, 'hardcoded-secret')",
      filePath: 'src/auth.js',
      severity: 'critical',
    },
    expect: 'process.env.JWT_SECRET',
  },
];

for (const { name, vuln, expect } of MATCHING) {
  test(`matching ${name}: template still rewrites the snippet`, async () => {
    const result = await generateAiFix(vuln);
    assert.equal(result.engine, 'rule-based');
    assert.notEqual(result.fixedCode, vuln.codeSnippet);
    assert.ok(result.fixedCode.includes(expect), `expected fix to contain ${expect}`);
  });
}

// Boundary guard: if any engine (here a stubbed Gemini) echoes the input
// back as the "fix", generateAiFix must return an explicit no-fix result.
test('boundary: Gemini echoing the input yields noFixAvailable, not the snippet', async () => {
  const input = 'db.query("SELECT * FROM users WHERE id = " + req.query.id)';
  const vuln = {
    title: 'Potential SQL Injection',
    codeSnippet: input,
    filePath: 'src/api.js',
    severity: 'critical',
  };

  const realFetch = globalThis.fetch;
  let capturedUrl;
  let capturedHeaders;
  process.env.GEMINI_API_KEY = 'dummy-test-key';
  globalThis.fetch = async (url, opts) => {
    capturedUrl = String(url);
    capturedHeaders = opts.headers;
    return {
      ok: true,
      json: async () => ({
        candidates: [{
          content: { parts: [{ text: JSON.stringify({ fixedCode: input, explanation: 'echo', confidence: 97, cweId: 'CWE-89' }) }] },
        }],
      }),
    };
  };
  try {
    const result = await generateAiFix(vuln);
    assert.equal(result.noFixAvailable, true);
    assert.equal(result.fixedCode, null);
    assert.equal(result.confidence, 0);
    // The key must travel as a header, never as a ?key= query parameter.
    assert.ok(!capturedUrl.includes('key='), `key leaked into URL: ${capturedUrl}`);
    assert.equal(capturedHeaders['x-goog-api-key'], 'dummy-test-key');
  } finally {
    globalThis.fetch = realFetch;
    delete process.env.GEMINI_API_KEY;
  }
});
