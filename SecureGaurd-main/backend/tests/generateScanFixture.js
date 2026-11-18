'use strict';
// Fixture generator for the scan performance harness.
//
// Regenerates the 152-file `small-repo` the harness measures against:
// 150 handler modules (lib/ = multiples of 3, src/ = the rest), lib/util.js
// and package.json. Every 10th module carries one planted finding, cycling
// SQLi -> AWS key -> XSS -> password -> command exec, so each scan finds
// exactly 15 findings (12 critical, 3 high, 6 secrets).
//
// The secrets below are DUMMY values, planted only so the scanner has
// something to find: the AWS key is Amazon's own published example key
// (AKIAIOSFODNN7EXAMPLE) and the password is a placeholder. Never replace
// them with real credentials.
//
// Usage (from SecureGaurd-main):
//   SCAN_LOCAL_BASE=/path/to/scan-fixtures \
//     node backend/tests/generateScanFixture.js [--force]
//   node backend/tests/generateScanFixture.js /path/to/small-repo [--force]
//
// Then run the harness against it:
//   SCAN_LOCAL_BASE=/path/to/scan-fixtures HARNESS_OUT=/path/to/out.json \
//     node backend/tests/scanPerfHarness.js after concurrent100
// Refuses to overwrite a non-empty directory unless --force is given.

const fs = require('fs');
const path = require('path');

const MODULES = 150;
const PATTERNS = [
  // SQL injection (critical, SAST)
  (n) => `const q = "SELECT * FROM users WHERE id = " + req.query.id;\ndb.query(q);\n`,
  // Hardcoded AWS key (critical, secret) — Amazon's published example key.
  () => `const apiKey = "AKIAIOSFODNN7EXAMPLE";\nmodule.exports = { apiKey };\n`,
  // XSS (high, SAST)
  () => `res.send("<h1>" + req.query.name + "</h1>");\n`,
  // Hardcoded password (critical, secret) — placeholder only.
  () => `const password = "hunter2-secret-123";\nlogin(user, password);\n`,
  // Command execution (critical, SAST)
  () => `child_process.exec("ls " + req.query.dir, (e, o) => console.log(o));\n`,
];

function handlerBody(n) {
  return `// module ${n}\nconst { helper } = require('../lib/util');\n`
    + `function handler${n}(req, res) {\n`
    + `  const name = String(req.query.name || '');\n`
    + `  return res.json({ ok: true, name: helper(name) });\n}\n`
    + `module.exports = { handler${n} };\n`;
}

function main() {
  const args = process.argv.slice(2);
  const force = args.includes('--force');
  const destArg = args.find((a) => a !== '--force');
  const dest = destArg
    ? path.resolve(destArg)
    : process.env.SCAN_LOCAL_BASE
      ? path.join(path.resolve(process.env.SCAN_LOCAL_BASE), 'small-repo')
      : null;
  if (!dest) {
    console.error('usage: node backend/tests/generateScanFixture.js [dest] [--force]\n'
      + '   or set SCAN_LOCAL_BASE to the fixtures base directory.');
    process.exit(1);
  }
  if (fs.existsSync(dest) && fs.readdirSync(dest).length > 0 && !force) {
    console.error(`refusing to overwrite non-empty directory: ${dest}\nre-run with --force to regenerate it.`);
    process.exit(1);
  }
  fs.mkdirSync(path.join(dest, 'lib'), { recursive: true });
  fs.mkdirSync(path.join(dest, 'src'), { recursive: true });
  for (let n = 0; n < MODULES; n++) {
    const dir = n % 3 === 0 ? 'lib' : 'src';
    const prefix = n % 10 === 0 ? PATTERNS[(n / 10) % PATTERNS.length](n) : '';
    fs.writeFileSync(path.join(dest, dir, `module${n}.js`), prefix + handlerBody(n));
  }
  fs.writeFileSync(path.join(dest, 'lib', 'util.js'),
    `function helper(s) { return String(s).trim(); }\nmodule.exports = { helper };\n`);
  // No trailing newline: matches the original fixture byte-for-byte.
  fs.writeFileSync(path.join(dest, 'package.json'),
    '{\n  "name": "fixture-repo",\n  "version": "1.0.0",\n'
    + '  "dependencies": {\n    "express": "^4.18.0",\n    "lodash": "^4.17.21"\n  }\n}');
  const files = [];
  (function walk(d) {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else files.push(p);
    }
  })(dest);
  console.log(`wrote ${files.length} files to ${dest}`);
  console.log('expected per scan: 15 findings (12 critical, 3 high, 6 secrets)');
}

main();
