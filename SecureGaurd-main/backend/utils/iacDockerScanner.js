const fs = require('fs');
const { IAC_RULES } = require('./rules/iacRules');

function createDockerFinding(ruleId, filePath, lineStart, codeSnippet) {
  const rule = IAC_RULES[ruleId];
  if (!rule) return null;

  return {
    ruleId: rule.ruleId,
    cweId: rule.cweId,
    type: 'iac',
    severity: rule.severity,
    title: rule.title,
    description: rule.description,
    filePath,
    lineStart: lineStart || 1,
    lineEnd: lineStart || 1,
    codeSnippet: codeSnippet ? codeSnippet.trim() : 'Dockerfile instruction',
    status: 'open',
    mlFeatures: {
      framework: rule.framework,
      category: rule.category,
      resourceType: 'Dockerfile',
      resourceName: filePath,
      ruleId: rule.ruleId,
      cweId: rule.cweId,
      isIaC: true
    }
  };
}

/**
 * Dockerfile Static Security Scanner
 */
function scanDockerfile(fullPath, relPath) {
  const findings = [];
  try {
    const content = fs.readFileSync(fullPath, 'utf8');
    const lines = content.split('\n');

    let hasUserInstruction = false;

    for (let i = 0; i < lines.length; i++) {
      const lineNum = i + 1;
      const line = lines[i];
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;

      // Track USER instruction
      if (/^USER\s+/i.test(trimmed)) {
        hasUserInstruction = true;
        if (/^USER\s+root$/i.test(trimmed) || /^USER\s+0$/i.test(trimmed)) {
          findings.push(createDockerFinding('DOCKER-001', relPath, lineNum, line));
        }
      }

      // DOCKER-002 Exposed Sensitive Port
      if (/^EXPOSE\s+.*(?:22|2375|3389).*/i.test(trimmed)) {
        findings.push(createDockerFinding('DOCKER-002', relPath, lineNum, line));
      }

      // DOCKER-003 Hardcoded Secrets in ENV/ARG. Redact the secret value
      // (K8S-009 pattern): keep the variable name and the first two
      // characters only — the value must never reach the finding snippet.
      if (/^(?:ENV|ARG)\s+.*(?:secret|password|passwd|token|key|cred).*\s*=\s*["']?[a-zA-Z0-9_\-!@#$%^&*()+=]{6,}["']?/i.test(trimmed)) {
        const secretMatch = trimmed.match(/^(ENV|ARG)\s+.*?([A-Za-z0-9_]*(?:secret|password|passwd|token|key|cred)[A-Za-z0-9_]*)\s*=\s*["']?([a-zA-Z0-9_\-!@#$%^&*()+=]{6,})/i);
        const redacted = secretMatch
          ? `${secretMatch[1]} ${secretMatch[2]}="${secretMatch[3].substring(0, 2)}****"`
          : 'Hardcoded secret in Dockerfile ENV/ARG';
        findings.push(createDockerFinding('DOCKER-003', relPath, lineNum, redacted));
      }

      // DOCKER-004 Risky ADD instruction
      if (/^ADD\s+/i.test(trimmed) && !/\.(tar|gz|bz2|xz)\b/i.test(trimmed)) {
        findings.push(createDockerFinding('DOCKER-004', relPath, lineNum, line));
      }

      // DOCKER-005 Dangerous Command Execution in RUN
      if (/^RUN\s+.*(?:curl|wget).*(?:\|\s*sh|\|\s*bash|chmod\s+777)/i.test(trimmed)) {
        findings.push(createDockerFinding('DOCKER-005', relPath, lineNum, line));
      }
    }

    // DOCKER-001 Missing USER instruction across whole Dockerfile
    if (!hasUserInstruction && lines.length > 3) {
      findings.push(createDockerFinding('DOCKER-001', relPath, 1, 'Missing USER instruction in Dockerfile'));
    }

  } catch (err) {
    // Malformed file handling
  }

  return findings;
}

module.exports = { scanDockerfile };
