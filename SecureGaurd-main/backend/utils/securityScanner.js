const fs = require('fs');
const path = require('path');

// ── Security Rules Configuration ──────────────────────────────────────────────
const RULES = [
  // 1. Secrets & Credentials Detection
  {
    id: 'SEC-001',
    title: 'Exposed AWS Access Key',
    regex: /AKIA[0-9A-Z]{16}/,
    severity: 'critical',
    type: 'secret',
    description: 'Detected a hardcoded AWS Access Key. Exposed cloud credentials can lead to account compromise.'
  },
  {
    id: 'SEC-002',
    title: 'Exposed Private Key',
    regex: /-----BEGIN [A-Z]+ PRIVATE KEY-----/,
    severity: 'critical',
    type: 'secret',
    description: 'Found an exposed Private Key block. Private keys should be stored in secure vault managers.'
  },
  {
    id: 'SEC-003',
    title: 'Hardcoded Secret Key',
    regex: /(?:secret|password|passwd|token|jwt_secret)\s*=\s*['"`][a-zA-Z0-9_\-!@#$%^&*()+=]{8,}['"`]/i,
    // Avoid triggering on environment variables
    exclude: /process\.env/i,
    severity: 'critical',
    type: 'secret',
    description: 'Potential hardcoded security secret or API credential detected in code.'
  },

  // 2. SAST (Static Application Security Testing)
  {
    id: 'SAST-001',
    title: 'Potential SQL Injection',
    regex: /SELECT\s+.*\s+FROM\s+.*\s*\+\s*[a-zA-Z0-9_.]|SELECT\s+.*\s+FROM\s+.*\$\{.*\}/i,
    severity: 'critical',
    type: 'sast',
    description: 'SQL queries created with string concatenation or templates can allow SQL Injection attacks. Use parametrized queries instead.'
  },
  {
    id: 'SAST-002',
    title: 'Cross-Site Scripting (XSS)',
    regex: /res\.send\(.*\+\s*req\.(query|body|params)|dangerouslySetInnerHTML/i,
    severity: 'high',
    type: 'sast',
    description: 'Rendering user-supplied input directly to the client response causes XSS. Encode inputs before rendering.'
  },
  {
    id: 'SAST-003',
    title: 'Path Traversal Vulnerability',
    regex: /fs\.(?:readFile|writeFile|createReadStream|createWriteStream)\(.*req\.(?:query|body|params)/i,
    severity: 'high',
    type: 'sast',
    description: 'User-controlled inputs in filesystem operations can lead to unauthorized file reading or modifications.'
  },
  {
    id: 'SAST-004',
    title: 'Weak JWT Signature Verification',
    regex: /jwt\.verify\([^,]+,\s*['"`][a-zA-Z0-9_\-]+['"`]\)/i,
    severity: 'high',
    type: 'sast',
    description: 'Detected hardcoded JWT signature secrets. Always load JWT verification secrets from server environment variables.'
  },
  {
    id: 'SAST-005',
    title: 'Remote Command Execution',
    regex: /child_process\.(?:exec|spawn)\(.*req\.(?:query|body|params|headers)/i,
    severity: 'critical',
    type: 'sast',
    description: 'Passing untrusted inputs into command shells can allow attackers to execute arbitrary server code.'
  },

  // 3. Infrastructure as Code (IaC) Scanning
  {
    id: 'IAC-001',
    title: 'Dockerfile Root Execution',
    regex: /^USER\s+root$/mi,
    severity: 'medium',
    type: 'iac',
    description: 'Running container processes as the root user violates the principle of least privilege.'
  },
  {
    id: 'IAC-002',
    title: 'Exposed Port in Dockerfile',
    regex: /^EXPOSE\s+22$/mi,
    severity: 'medium',
    type: 'iac',
    description: 'Exposing port 22 (SSH) inside a Docker image increases external attack surface.'
  }
];

// ── Vulnerable Dependency Dictionary ──────────────────────────────────────────
const VULNERABLE_DEPENDENCIES = {
  'lodash': { maxVulnerable: '4.17.20', severity: 'medium', title: 'Prototype Pollution in Lodash' },
  'axios': { maxVulnerable: '0.21.0', severity: 'high', title: 'SSRF in Axios' },
  'express': { maxVulnerable: '4.16.0', severity: 'medium', title: 'Open Redirect in Express' },
  'jsonwebtoken': { maxVulnerable: '8.5.1', severity: 'high', title: 'Signature Verification Bypass in jsonwebtoken' }
};

// Helper: check version vulnerability (basic semver comparison)
function isVulnerable(versionStr, maxVulnerable) {
  try {
    const clean = versionStr.replace(/[^0-9.]/g, '');
    const parts = clean.split('.').map(Number);
    const maxParts = maxVulnerable.split('.').map(Number);
    
    for (let i = 0; i < Math.max(parts.length, maxParts.length); i++) {
      const p = parts[i] || 0;
      const m = maxParts[i] || 0;
      if (p < m) return true;
      if (p > m) return false;
    }
    return true; // Match equals max vulnerable version
  } catch {
    return false;
  }
}

const { scanTerraformFile } = require('./iacTerraformScanner');
const { scanKubernetesFile } = require('./iacK8sScanner');
const { scanDockerfile } = require('./iacDockerScanner');
const { scanAPISpecFile } = require('./apiSpecScanner');
const { scanCloudFormationFile } = require('./iacCloudFormationScanner');
const { compileCustomRules, matchCustomRules } = require('./customRules');

// ── Recursive Directory Traversal ─────────────────────────────────────────────
// customRules: normalized org rules (utils/customRules.js shape); compiled
// once per scan, applied to the same code files as the built-in rules.
//
// Symlink containment: entries are lstat'ed, never stat'ed — a symlink
// (file or directory) is skipped outright, so a link inside the clone can
// never pull in files from outside the scan root. Directories are also
// resolved with realpathSync and required to stay inside the realpath of
// the scan root, visited directory inodes are tracked (a directory is
// never traversed twice), and traversal depth is capped.
const MAX_TRAVERSAL_DEPTH = 32;

// Secret rules must never persist the secret value itself: the finding
// snippet is the evidence, not a copy of the credential. Mirror the
// TF-005 pattern (generic snippet, no value): keep the key name and at
// most the first two characters of the value, then '****'. Applies to
// SEC-001 (AWS key), SEC-002 (private key block) and SEC-003 (hardcoded
// secret); SAST/IaC lines are code, not credentials, and are untouched.
const SECRET_RULE_IDS = new Set(['SEC-001', 'SEC-002', 'SEC-003']);

function redactSecretSnippet(ruleId, lineContent) {
  const line = lineContent.trim();
  if (ruleId === 'SEC-001') {
    const m = line.match(/AKIA[0-9A-Z]{16}/);
    return m ? `Exposed AWS Access Key: ${m[0].slice(0, 2)}****` : 'Exposed AWS Access Key (value redacted)';
  }
  if (ruleId === 'SEC-002') {
    return 'Exposed Private Key block (contents redacted)';
  }
  // SEC-003: `name = "value"` — keep the key name + first two value chars.
  const m = line.match(/(secret|password|passwd|token|jwt_secret)\s*=\s*['"`]([^'"`]{2})/i);
  if (m) return `${m[1]} = "${m[2]}****"`;
  return 'Hardcoded secret (value redacted)';
}

function scanDirectory(dir, rootDir, findings = [], fileCountRef = { count: 0 }, lineCountRef = { count: 0 }, compiledCustomRules = [], depth = 0, visited = new Set(), rootReal = null) {
  if (depth > MAX_TRAVERSAL_DEPTH) return;
  if (rootReal === null) {
    try {
      rootReal = fs.realpathSync(rootDir);
    } catch {
      rootReal = rootDir;
    }
  }
  const list = fs.readdirSync(dir);
  
  for (const item of list) {
    const fullPath = path.join(dir, item);
    const relPath = path.relative(rootDir, fullPath);
    
    // Ignore patterns to prevent infinite scans / performance blocks
    if (
      item === 'node_modules' ||
      item === '.git' ||
      item === 'dist' ||
      item === 'build' ||
      item === '.next' ||
      item === 'prisma' ||
      relPath.endsWith('.webp') ||
      relPath.endsWith('.png') ||
      relPath.endsWith('.jpg') ||
      relPath.endsWith('.jpeg') ||
      relPath.endsWith('.ico')
    ) {
      continue;
    }

    // lstat, not stat: a symlink must never be followed — it is skipped,
    // so scan input can only come from inside the clone tree.
    let stat;
    try {
      stat = fs.lstatSync(fullPath);
    } catch {
      continue;
    }
    if (stat.isSymbolicLink()) continue;
    if (stat.isDirectory()) {
      // Containment + loop guard: resolve the real path, require it inside
      // the real scan root, and traverse each directory inode only once.
      let realPath;
      try {
        realPath = fs.realpathSync(fullPath);
      } catch {
        continue;
      }
      if (realPath !== rootReal && !realPath.startsWith(rootReal + path.sep)) continue;
      const inodeKey = `${stat.dev}:${stat.ino}`;
      if (visited.has(inodeKey)) continue;
      visited.add(inodeKey);
      scanDirectory(fullPath, rootDir, findings, fileCountRef, lineCountRef, compiledCustomRules, depth + 1, visited, rootReal);
    } else if (stat.isFile()) {
      fileCountRef.count++;
      
      // 1. Dependency Scanner (package.json check)
      if (item === 'package.json') {
        try {
          const content = fs.readFileSync(fullPath, 'utf8');
          const pkg = JSON.parse(content);
          const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
          
          for (const [dep, version] of Object.entries(allDeps)) {
            if (VULNERABLE_DEPENDENCIES[dep]) {
              const vulnInfo = VULNERABLE_DEPENDENCIES[dep];
              if (isVulnerable(version, vulnInfo.maxVulnerable)) {
                findings.push({
                  type: 'dependency',
                  severity: vulnInfo.severity,
                  title: vulnInfo.title,
                  filePath: relPath,
                  lineStart: 1,
                  lineEnd: 1,
                  codeSnippet: `"${dep}": "${version}"`,
                  status: 'open'
                });
              }
            }
          }
        } catch (e) {
          // ignore parsing error
        }
      }

      // 2. Advanced IaC & API Specification Scanners
      const ext = path.extname(item).toLowerCase();
      const lowerItem = item.toLowerCase();

      // Terraform (.tf, .tf.json)
      if (ext === '.tf' || item.endsWith('.tf.json')) {
        const tfFindings = scanTerraformFile(fullPath, relPath);
        findings.push(...tfFindings);
      }

      // Kubernetes, CloudFormation & OpenAPI (.yaml, .yml)
      if (ext === '.yaml' || ext === '.yml') {
        try {
          const sampleContent = fs.readFileSync(fullPath, 'utf8');
          if (/AWSTemplateFormatVersion/i.test(sampleContent) || (/^Resources\s*:/m.test(sampleContent) && /AWS::/.test(sampleContent))) {
            const cfnFindings = scanCloudFormationFile(fullPath, relPath);
            findings.push(...cfnFindings);
          }
          if (/(?:openapi|swagger)\s*:/i.test(sampleContent) || /openapi|swagger/i.test(lowerItem)) {
            const apiFindings = scanAPISpecFile(fullPath, relPath);
            findings.push(...apiFindings);
          }
          if (/apiVersion\s*:/i.test(sampleContent) && /kind\s*:/i.test(sampleContent)) {
            const k8sFindings = scanKubernetesFile(fullPath, relPath);
            findings.push(...k8sFindings);
          }
        } catch (e) {}
      }

      // OpenAPI JSON, or CloudFormation JSON template (scanner no-ops on
      // non-templates, so plain .json files are safe to pass through)
      if (ext === '.json') {
        if (lowerItem.includes('openapi') || lowerItem.includes('swagger')) {
          const apiFindings = scanAPISpecFile(fullPath, relPath);
          findings.push(...apiFindings);
        } else if (!item.endsWith('.tf.json')) {
          const cfnFindings = scanCloudFormationFile(fullPath, relPath);
          findings.push(...cfnFindings);
        }
      }

      // Dockerfile
      if (lowerItem === 'dockerfile' || lowerItem.startsWith('dockerfile.') || ext === '.dockerfile') {
        const dockerFindings = scanDockerfile(fullPath, relPath);
        findings.push(...dockerFindings);
      }

      // 3. Code Security Scanner (SAST & Secrets)
      const isCodeFile = ['.js', '.jsx', '.ts', '.tsx', '.py', '.tf', 'Dockerfile'].includes(ext) || item === 'Dockerfile';
      
      if (isCodeFile && ext !== '.tf' && lowerItem !== 'dockerfile') {
        try {
          const content = fs.readFileSync(fullPath, 'utf8');
          const lines = content.split('\n');
          lineCountRef.count += lines.length;

          for (let lineNum = 0; lineNum < lines.length; lineNum++) {
            const lineContent = lines[lineNum];
            
            for (const rule of RULES) {
              if (rule.regex.test(lineContent)) {
                // If rule has exclusions, verify line does not match them
                if (rule.exclude && rule.exclude.test(lineContent)) {
                  continue;
                }

                const findingSnippet = SECRET_RULE_IDS.has(rule.id)
                  ? redactSecretSnippet(rule.id, lineContent)
                  : lineContent.trim();
                let mlFeatures = null;
                
                // CWE mapping per rule
                const CWE_MAP = {
                  'SEC-001': 'CWE-798', 'SEC-002': 'CWE-321', 'SEC-003': 'CWE-798',
                  'SAST-001': 'CWE-89', 'SAST-002': 'CWE-79', 'SAST-003': 'CWE-22',
                  'SAST-004': 'CWE-347', 'SAST-005': 'CWE-78',
                  'IAC-001': 'CWE-250', 'IAC-002': 'CWE-200'
                };
                const cweId = CWE_MAP[rule.id] || 'CWE-Other';

                const isSastRule = rule.id.startsWith('SAST-');
                if (isSastRule && ['.js', '.jsx', '.ts', '.tsx'].includes(ext)) {
                  const { extractASTFeatures } = require('./astExtractor');
                  mlFeatures = extractASTFeatures(content, relPath, rule.id, lineNum + 1);
                }

                findings.push({
                  ruleId: rule.id,
                  cweId: cweId,
                  type: rule.type,
                  severity: rule.severity,
                  title: rule.title,
                  filePath: relPath,
                  lineStart: lineNum + 1,
                  lineEnd: lineNum + 1,
                  codeSnippet: findingSnippet,
                  status: 'open',
                  mlFeatures: mlFeatures
                });
              }
            }

            // Day 10 — org custom rules (compiled once per scan, passed in
            // via scanDirectory). No mlFeatures: the FP classifier is
            // SAST-trained, so custom findings must never be suppressed.
            if (compiledCustomRules.length > 0) {
              findings.push(...matchCustomRules(compiledCustomRules, relPath, lineContent, lineNum + 1));
            }
          }
        } catch (e) {
          // ignore file read error
        }
      }
    }
  }
}

const { extractRepositorySbomComponents } = require('./sbomExtractor');

// ── Main Scan Execution Endpoint ──────────────────────────────────────────────
// customRules: normalized org rules (utils/customRules.js shape); compiled
// once here and applied to the same code files as the built-in rules.
function runSecurityScan(projectPath, customRules = []) {
  const findings = [];
  const fileCountRef = { count: 0 };
  const lineCountRef = { count: 0 };
  const compiledCustomRules = compileCustomRules(customRules);

  const startTime = Date.now();
  if (fs.existsSync(projectPath)) {
    scanDirectory(projectPath, projectPath, findings, fileCountRef, lineCountRef, compiledCustomRules);
  }
  const endTime = Date.now();

  const sbomComponents = extractRepositorySbomComponents(projectPath);

  const summaryStats = {
    sourceCodeCount: findings.filter(f => f.type === 'sast' || f.type === 'secret' || f.type === 'dependency').length,
    iacCount: findings.filter(f => f.type === 'iac').length,
    apiCount: findings.filter(f => f.type === 'api').length,
    terraformCount: findings.filter(f => f.mlFeatures?.framework === 'Terraform').length,
    k8sCount: findings.filter(f => f.mlFeatures?.framework === 'Kubernetes').length,
    dockerCount: findings.filter(f => f.mlFeatures?.framework === 'Docker').length,
    cloudFormationCount: findings.filter(f => f.mlFeatures?.framework === 'CloudFormation').length,
    openApiCount: findings.filter(f => f.mlFeatures?.framework === 'OpenAPI').length,
    sbomComponentCount: sbomComponents.length
  };
  
  return {
    findings,
    sbomComponents,
    summaryStats,
    totalFiles: fileCountRef.count,
    totalLines: lineCountRef.count,
    durationMs: endTime - startTime
  };
}

module.exports = { runSecurityScan, BUILTIN_RULES: RULES };
