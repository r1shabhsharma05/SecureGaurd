const fs = require('fs');
const path = require('path');
const { IAC_RULES } = require('./rules/iacRules');

function createIaCFinding(ruleId, filePath, lineStart, codeSnippet, resourceType = 'terraform_resource', resourceName = 'unknown') {
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
    codeSnippet: codeSnippet ? codeSnippet.trim() : `${resourceType}.${resourceName}`,
    status: 'open',
    mlFeatures: {
      framework: rule.framework,
      category: rule.category,
      resourceType,
      resourceName,
      ruleId: rule.ruleId,
      cweId: rule.cweId,
      isIaC: true
    }
  };
}

/**
 * Static Analysis Scanner for Terraform (.tf and .tf.json)
 */
function scanTerraformFile(fullPath, relPath) {
  const findings = [];
  try {
    const content = fs.readFileSync(fullPath, 'utf8');
    const lines = content.split('\n');

    // 1. JSON-formatted Terraform (.tf.json)
    if (relPath.endsWith('.tf.json')) {
      try {
        const json = JSON.parse(content);
        const resourceBlocks = json.resource || {};
        
        for (const [resType, resGroup] of Object.entries(resourceBlocks)) {
          for (const [resName, config] of Object.entries(resGroup)) {
            // TF-001 Public S3 Bucket
            if (resType === 'aws_s3_bucket') {
              if (config.acl === 'public-read' || config.acl === 'public-read-write') {
                findings.push(createIaCFinding('TF-001', relPath, 1, `"acl": "${config.acl}"`, resType, resName));
              }
              if (!config.server_side_encryption_configuration) {
                findings.push(createIaCFinding('TF-002', relPath, 1, `"aws_s3_bucket": "${resName}"`, resType, resName));
              }
            }
            // TF-003 Permissive Network
            if (resType === 'aws_security_group' || resType === 'aws_security_group_rule') {
              const ingressRules = Array.isArray(config.ingress) ? config.ingress : [config.ingress].filter(Boolean);
              for (const ing of ingressRules) {
                if (ing.cidr_blocks && ing.cidr_blocks.includes('0.0.0.0/0')) {
                  findings.push(createIaCFinding('TF-003', relPath, 1, `"cidr_blocks": ["0.0.0.0/0"]`, resType, resName));
                }
              }
            }
            // TF-005 Hardcoded secrets
            const strConfig = JSON.stringify(config);
            if (/(?:access_key|secret_key|password)\s*:\s*["'][a-zA-Z0-9_\-!@#$%^&*()+=]{8,}["']/i.test(strConfig)) {
              findings.push(createIaCFinding('TF-005', relPath, 1, `Hardcoded credential in ${resName}`, resType, resName));
            }
          }
        }
      } catch (err) {
        // Safe skip malformed JSON
      }
      return findings;
    }

    // 2. Standard HCL Terraform (.tf)
    let currentResourceType = '';
    let currentResourceName = '';
    let inResourceBlock = false;
    let blockStartLine = 1;

    for (let i = 0; i < lines.length; i++) {
      const lineNum = i + 1;
      const line = lines[i];
      const trimmed = line.trim();

      // Resource header detection
      const resMatch = trimmed.match(/^resource\s+["']([^"']+)["']\s+["']([^"']+)["']/);
      if (resMatch) {
        currentResourceType = resMatch[1];
        currentResourceName = resMatch[2];
        inResourceBlock = true;
        blockStartLine = lineNum;
      }

      // Check TF-001: Public S3 Bucket or Azure Storage
      if (/acl\s*=\s*["']public-read(?:-write)?["']/i.test(trimmed)) {
        findings.push(createIaCFinding('TF-001', relPath, lineNum, line, currentResourceType || 'aws_s3_bucket', currentResourceName || 's3_bucket'));
      }
      if (/allow_blob_public_access\s*=\s*true/i.test(trimmed)) {
        findings.push(createIaCFinding('TF-001', relPath, lineNum, line, 'azurerm_storage_account', currentResourceName || 'storage_account'));
      }

      // Check TF-002: Missing Encryption on EBS / Storage
      if (currentResourceType === 'aws_ebs_volume' && /encrypted\s*=\s*false/i.test(trimmed)) {
        findings.push(createIaCFinding('TF-002', relPath, lineNum, line, currentResourceType, currentResourceName));
      }

      // Check TF-003: Permissive Ingress (0.0.0.0/0)
      if (/(?:cidr_blocks|cidr_block)\s*=\s*\[.*["']0\.0\.0\.0\/0["'].*\]/i.test(trimmed)) {
        findings.push(createIaCFinding('TF-003', relPath, lineNum, line, currentResourceType || 'aws_security_group', currentResourceName || 'security_group'));
      }

      // Check TF-004: Wildcard IAM Policy
      if (/(?:["']?Action["']?)\s*[:=]\s*(?:["']\*["']|\[.*["']\*["'].*\])/i.test(trimmed) || /(?:["']?Principal["']?)\s*[:=]\s*["']\*["']/i.test(trimmed)) {
        findings.push(createIaCFinding('TF-004', relPath, lineNum, line, currentResourceType || 'aws_iam_policy', currentResourceName || 'iam_policy'));
      }

      // Check TF-005: Hardcoded credentials/keys. Redact the secret value
      // (K8S-009 pattern): keep the attribute name and the first two
      // characters only — the value must never reach the finding snippet.
      if (/(?:access_key|secret_key|aws_secret_access_key|password)\s*=\s*["'][a-zA-Z0-9_\-!@#$%^&*()+=]{8,}["']/i.test(trimmed) && !/var\./i.test(trimmed)) {
        const credMatch = trimmed.match(/((?:access_key|secret_key|aws_secret_access_key|password)\s*=\s*["'])([a-zA-Z0-9_\-!@#$%^&*()+=]{8,})(["'])/i);
        const redacted = credMatch
          ? `${credMatch[1]}${credMatch[2].substring(0, 2)}****${credMatch[3]}`
          : `Hardcoded credential in ${currentResourceName || 'credentials'}`;
        findings.push(createIaCFinding('TF-005', relPath, lineNum, redacted, currentResourceType || 'provider', currentResourceName || 'credentials'));
      }
    }

    // Check TF-002 on S3 buckets lacking encryption blocks across entire file
    if (content.includes('aws_s3_bucket') && !content.includes('server_side_encryption_configuration')) {
      const match = content.match(/resource\s+["']aws_s3_bucket["']\s+["']([^"']+)["']/);
      const resName = match ? match[1] : 'unencrypted_bucket';
      const finding = createIaCFinding('TF-002', relPath, 1, `resource "aws_s3_bucket" "${resName}"`, 'aws_s3_bucket', resName);
      if (finding) findings.push(finding);
    }

  } catch (err) {
    // Malformed file handling: skip cleanly
  }

  return findings.filter(Boolean);
}

module.exports = { scanTerraformFile };
