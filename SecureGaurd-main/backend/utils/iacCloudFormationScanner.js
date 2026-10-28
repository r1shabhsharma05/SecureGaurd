const fs = require('fs');
const yaml = require('js-yaml');
const { IAC_RULES } = require('./rules/iacRules');

function createCfnFinding(ruleId, filePath, lineStart, codeSnippet, resourceType = 'AWS::Resource', resourceName = 'unknown') {
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

function findLine(content, needle) {
  const lines = content.split('\n');
  const idx = lines.findIndex(l => l.includes(needle));
  return idx >= 0 ? idx + 1 : 1;
}

function isWildcard(value) {
  if (value === '*') return true;
  if (Array.isArray(value)) return value.includes('*');
  return false;
}

function checkResource(logicalId, resource, content, filePath, findings) {
  const type = resource.Type || '';
  const props = resource.Properties || {};
  const line = findLine(content, logicalId);
  const push = (ruleId, snippet) => {
    const f = createCfnFinding(ruleId, filePath, line, snippet, type, logicalId);
    if (f) findings.push(f);
  };

  // CFN-001 / CFN-003: S3 bucket public ACL / missing encryption
  if (type === 'AWS::S3::Bucket') {
    const acl = props.AccessControl;
    if (acl === 'PublicRead' || acl === 'PublicReadWrite') {
      push('CFN-001', `AccessControl: ${acl}`);
    }
    if (!props.BucketEncryption) {
      push('CFN-003', `AWS::S3::Bucket ${logicalId} (no BucketEncryption)`);
    }
  }

  // CFN-002: open security group ingress (inline or standalone rule)
  const ingressLists = [];
  if (type === 'AWS::EC2::SecurityGroup' && Array.isArray(props.SecurityGroupIngress)) {
    ingressLists.push(props.SecurityGroupIngress);
  }
  if (type === 'AWS::EC2::SecurityGroupIngress') {
    ingressLists.push([props]);
  }
  for (const rules of ingressLists) {
    for (const rule of rules) {
      if (rule && (rule.CidrIp === '0.0.0.0/0' || rule.CidrIpv6 === '::/0')) {
        push('CFN-002', `CidrIp: ${rule.CidrIp || rule.CidrIpv6}`);
      }
    }
  }

  // CFN-003: EBS / RDS encryption flags
  if (type === 'AWS::EC2::Volume' && props.Encrypted === false) {
    push('CFN-003', 'Encrypted: false');
  }
  if (type === 'AWS::RDS::DBInstance' && props.StorageEncrypted === false) {
    push('CFN-003', 'StorageEncrypted: false');
  }

  // CFN-006: publicly accessible RDS
  if (type === 'AWS::RDS::DBInstance' && props.PubliclyAccessible === true) {
    push('CFN-006', 'PubliclyAccessible: true');
  }

  // CFN-004: wildcard IAM policy statements (Policy resource or Role inline policies)
  const policyDocs = [];
  if (type === 'AWS::IAM::Policy' && props.PolicyDocument) {
    policyDocs.push(props.PolicyDocument);
  }
  if (type === 'AWS::IAM::Role' && Array.isArray(props.Policies)) {
    for (const p of props.Policies) {
      if (p && p.PolicyDocument) policyDocs.push(p.PolicyDocument);
    }
  }
  for (const doc of policyDocs) {
    const statements = Array.isArray(doc.Statement) ? doc.Statement : [];
    for (const st of statements) {
      if (st && (isWildcard(st.Action) || isWildcard(st.Resource))) {
        push('CFN-004', 'Action/Resource: *');
        break;
      }
    }
  }

  // CFN-005: literal secret values in properties (Ref/Sub objects are not
  // literals, so they never match — only hardcoded strings fire).
  const propsJson = JSON.stringify(props);
  if (/(?:password|passwd|secret|api[_-]?key|access[_-]?key)"\s*:\s*"[^"]{8,}"/i.test(propsJson)) {
    push('CFN-005', `Hardcoded credential in ${logicalId}`);
  }
}

/**
 * CloudFormation template scanner (JSON or YAML).
 * Returns [] for any file that is not a template — the guard is the
 * AWSTemplateFormatVersion key or a Resources map with AWS::* types.
 */
function scanCloudFormationFile(fullPath, relPath) {
  const findings = [];
  try {
    const content = fs.readFileSync(fullPath, 'utf8');
    if (!content.trim()) return findings;

    let template = null;
    if (relPath.endsWith('.json')) {
      try { template = JSON.parse(content); } catch (e) { return findings; }
    } else {
      // js-yaml's safe schema rejects CloudFormation intrinsic tags (!Ref,
      // !Sub, !GetAtt, ...). Strip the tag, keeping the value: a scalar
      // intrinsic becomes the 7-char placeholder "__REF__" (deliberately
      // under the 8-char secret threshold, so it can never fire CFN-005),
      // while flow/block values keep their shape minus the tag.
      const scrubbed = content
        .replace(/![A-Za-z]+\s+(?=[|>])/g, '')
        .replace(/![A-Za-z]+\s+(?=[[{])/g, '')
        .replace(/![A-Za-z]+\s+(?:"[^"\n]*"|'[^'\n]*'|[^\s[{][^\n]*)/g, '"__REF__"');
      try {
        template = yaml.load(scrubbed, { schema: yaml.DEFAULT_SAFE_SCHEMA, json: true });
      } catch (e) {
        return findings;
      }
    }

    if (!template || typeof template !== 'object') return findings;
    const resources = template.Resources;
    if (!resources || typeof resources !== 'object') return findings;
    const isTemplate = template.AWSTemplateFormatVersion ||
      Object.values(resources).some(r => r && typeof r.Type === 'string' && r.Type.startsWith('AWS::'));
    if (!isTemplate) return findings;

    for (const [logicalId, resource] of Object.entries(resources)) {
      if (!resource || typeof resource !== 'object') continue;
      checkResource(logicalId, resource, content, relPath, findings);
    }
  } catch (err) {
    // Malformed file handling: skip cleanly
  }

  return findings.filter(Boolean);
}

module.exports = { scanCloudFormationFile };
