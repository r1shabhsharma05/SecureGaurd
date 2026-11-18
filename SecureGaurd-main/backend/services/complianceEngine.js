/**
 * SecureGuard Compliance Engine
 * 
 * Maps real vulnerability findings from SecureGuard scans to regulatory & compliance frameworks:
 * - SOC 2 (Trust Services Criteria)
 * - HIPAA (Security Rule)
 * - PCI-DSS (v4.0)
 * - GDPR (Articles 25, 32, 5)
 * 
 * Provides deterministic compliance scoring, control evaluation, evidence mapping,
 * and prioritized recommendations.
 */

const FRAMEWORK_CONTROLS = {
  SOC2: [
    {
      id: 'SOC2-CC6.1',
      name: 'Access Control & Identity Authentication',
      category: 'Logical Access',
      description: 'Controls requiring logical access security software, authentication mechanisms, and access privilege limitations.',
      cweMatches: ['CWE-287', 'CWE-306', 'CWE-798', 'CWE-269', 'CWE-639', 'CWE-285'],
      types: ['sast', 'secret', 'iac', 'api'],
      recommendation: 'Implement strict multi-factor authentication, remove hardcoded credentials, and enforce robust role-based access control (RBAC).'
    },
    {
      id: 'SOC2-CC6.3',
      name: 'Data Transmission & Encryption Security',
      category: 'Data Protection',
      description: 'Controls enforcing data encryption in transit and at rest using modern cryptographic protocols.',
      cweMatches: ['CWE-319', 'CWE-311', 'CWE-327', 'CWE-295'],
      types: ['sast', 'secret', 'iac', 'api'],
      recommendation: 'Enforce TLS 1.3 for all endpoints, replace deprecated cipher suites, and prevent cleartext transmission of sensitive data.'
    },
    {
      id: 'SOC2-CC6.6',
      name: 'Boundary Protection & Network Security',
      category: 'Infrastructure Security',
      description: 'Controls preventing unauthorized boundary penetration, malicious payloads, and external attack vector exposure.',
      cweMatches: ['CWE-918', 'CWE-94', 'CWE-434', 'CWE-78', 'CWE-88', 'CWE-284', 'CWE-200', 'CWE-250'],
      types: ['sast', 'iac', 'api'],
      recommendation: 'Deploy web application firewalls, sanitize outgoing server calls (SSRF protection), and restrict unneeded inbound ports.'
    },
    {
      id: 'SOC2-CC6.8',
      name: 'Vulnerability Management & Secure Development',
      category: 'Application Security',
      description: 'Controls ensuring software is protected against injection, cross-site scripting, and flaw exploitation.',
      cweMatches: ['CWE-89', 'CWE-79', 'CWE-22', 'CWE-502', 'CWE-95', 'CWE-601'],
      types: ['sast', 'dependency', 'iac', 'api'],
      recommendation: 'Use parameterized queries, encode output rendering, sanitize file path inputs, and enforce automated SAST CI/CD checks.'
    },
    {
      id: 'SOC2-CC7.1',
      name: 'Secrets Management & System Configuration',
      category: 'System Operations',
      description: 'Controls protecting system configuration parameters, API keys, passwords, and environment secrets.',
      cweMatches: ['CWE-798', 'CWE-200', 'CWE-538', 'CWE-540'],
      types: ['secret', 'iac'],
      recommendation: 'Store credentials in dedicated secrets vaults (e.g. AWS Secrets Manager/Vault) and audit codebase for committed tokens.'
    },
    {
      id: 'SOC2-CC7.2',
      name: 'Dependency & Vulnerability Patch Management',
      category: 'Change Management',
      description: 'Controls monitoring third-party libraries for known CVE vulnerabilities and requiring timely security updates.',
      cweMatches: ['CWE-1395', 'CWE-1104', 'CWE-937'],
      types: ['dependency'],
      recommendation: 'Upgrade vulnerable third-party packages to fixed versions and enable automated lockfile security alerts.'
    }
  ],

  HIPAA: [
    {
      id: 'HIPAA-164.312(a)(1)',
      name: 'Access Control & User Authentication',
      category: 'Technical Safeguards',
      description: 'Implement technical policies and procedures to allow access only to authorized persons or software programs.',
      cweMatches: ['CWE-287', 'CWE-306', 'CWE-269', 'CWE-639'],
      types: ['sast'],
      recommendation: 'Restrict access to ePHI endpoints, enforce session timeouts, and validate user authorization on every request.'
    },
    {
      id: 'HIPAA-164.312(b)',
      name: 'Audit Controls & Security Event Logging',
      category: 'Technical Safeguards',
      description: 'Implement hardware, software, and procedural mechanisms that record and examine activity in systems containing ePHI.',
      cweMatches: ['CWE-778', 'CWE-532', 'CWE-117'],
      types: ['sast', 'iac'],
      recommendation: 'Avoid logging sensitive personal data, centralize audit logs, and restrict log file modification permissions.'
    },
    {
      id: 'HIPAA-164.312(c)(1)',
      name: 'Data Integrity & Injection Prevention',
      category: 'Technical Safeguards',
      description: 'Implement policies and procedures to protect ePHI from improper alteration or destruction.',
      cweMatches: ['CWE-89', 'CWE-79', 'CWE-502', 'CWE-94'],
      types: ['sast'],
      recommendation: 'Enforce parameterized queries to prevent SQL injection and use cryptographic hashes to verify data integrity.'
    },
    {
      id: 'HIPAA-164.312(d)',
      name: 'Person or Entity Authentication',
      category: 'Technical Safeguards',
      description: 'Implement procedures to verify that a person or entity seeking access to ePHI is the one claimed.',
      cweMatches: ['CWE-798', 'CWE-287', 'CWE-384'],
      types: ['secret', 'sast'],
      recommendation: 'Enforce strong authentication mechanisms and remove embedded secret keys from source code files.'
    },
    {
      id: 'HIPAA-164.312(e)(1)',
      name: 'Transmission Security & Encryption',
      category: 'Technical Safeguards',
      description: 'Implement technical security measures to guard against unauthorized access to ePHI transmitted over network.',
      cweMatches: ['CWE-319', 'CWE-311', 'CWE-327'],
      types: ['sast', 'iac'],
      recommendation: 'Require HTTPS/TLS encryption across all network channels handling sensitive health information.'
    },
    {
      id: 'HIPAA-164.308(a)(1)',
      name: 'Security Management & Risk Analysis',
      category: 'Administrative Safeguards',
      description: 'Conduct an accurate and thorough assessment of potential risks and vulnerabilities to ePHI.',
      cweMatches: ['CWE-1395', 'CWE-200', 'CWE-22'],
      types: ['dependency', 'sast'],
      recommendation: 'Perform routine code vulnerability scans and remediate high-risk code flaws prior to production releases.'
    }
  ],

  'PCI-DSS': [
    {
      id: 'PCI-REQ-3',
      name: 'Protect Stored Account Data & Secrets',
      category: 'Data Protection',
      description: 'Protect stored cardholder data and ensure cryptographic keys and secrets are securely maintained.',
      cweMatches: ['CWE-798', 'CWE-311', 'CWE-312', 'CWE-319'],
      types: ['secret', 'sast'],
      recommendation: 'Remove hardcoded secrets, API tokens, and private keys from code repositories immediately.'
    },
    {
      id: 'PCI-REQ-4',
      name: 'Protect Cardholder Data in Transit',
      category: 'Network Security',
      description: 'Use strong cryptography and security protocols to safeguard sensitive cardholder data during transmission.',
      cweMatches: ['CWE-319', 'CWE-327', 'CWE-295'],
      types: ['sast', 'iac'],
      recommendation: 'Enforce TLS 1.2 or higher for all payment processing and external communications.'
    },
    {
      id: 'PCI-REQ-6',
      name: 'Develop & Maintain Secure Systems & Software',
      category: 'Application Security',
      description: 'Protect systems against software vulnerabilities, OWASP Top 10 flaws, and code injections.',
      cweMatches: ['CWE-89', 'CWE-79', 'CWE-22', 'CWE-78', 'CWE-502'],
      types: ['sast'],
      recommendation: 'Address all injection vulnerabilities, practice secure coding standards, and perform mandatory code reviews.'
    },
    {
      id: 'PCI-REQ-7',
      name: 'Restrict Access to System Components by Business Need',
      category: 'Access Control',
      description: 'Ensure access to system components and cardholder data is restricted to authorized personnel.',
      cweMatches: ['CWE-285', 'CWE-639', 'CWE-269'],
      types: ['sast'],
      recommendation: 'Enforce least privilege access rules and prevent insecure direct object references (IDOR).'
    },
    {
      id: 'PCI-REQ-10',
      name: 'Log and Monitor All Access to Systems',
      category: 'Logging & Auditing',
      description: 'Track and monitor all access to network resources and cardholder data.',
      cweMatches: ['CWE-778', 'CWE-532', 'CWE-117'],
      types: ['sast', 'iac'],
      recommendation: 'Implement centralized logging without recording sensitive primary account numbers (PAN) or passwords.'
    },
    {
      id: 'PCI-REQ-11',
      name: 'Test Security of Systems & Software Regularly',
      category: 'Vulnerability Management',
      description: 'Perform frequent vulnerability assessments and third-party component dependency audits.',
      cweMatches: ['CWE-1395', 'CWE-937', 'CWE-1104'],
      types: ['dependency', 'iac'],
      recommendation: 'Continuously scan software dependencies and infrastructure-as-code files for security compliance.'
    }
  ],

  GDPR: [
    {
      id: 'GDPR-ART-25',
      name: 'Data Protection by Design and Default',
      category: 'Privacy & Architecture',
      description: 'Implement appropriate technical measures designed to implement data-protection principles effectively.',
      cweMatches: ['CWE-200', 'CWE-538', 'CWE-359', 'CWE-798'],
      types: ['sast', 'secret'],
      recommendation: 'Incorporate privacy and security controls at design time and prevent accidental disclosure of user data.'
    },
    {
      id: 'GDPR-ART-32(1)(a)',
      name: 'Pseudonymization & Encryption of Personal Data',
      category: 'Security of Processing',
      description: 'Implement encryption and pseudonymization measures to protect personal data during storage and transit.',
      cweMatches: ['CWE-311', 'CWE-319', 'CWE-327'],
      types: ['sast', 'secret'],
      recommendation: 'Encrypt sensitive personal fields at rest and mandate HTTPS/TLS for all external network endpoints.'
    },
    {
      id: 'GDPR-ART-32(1)(b)',
      name: 'System Confidentiality, Integrity, and Resilience',
      category: 'Security of Processing',
      description: 'Ensure ongoing confidentiality, integrity, availability, and resilience of processing systems and services.',
      cweMatches: ['CWE-89', 'CWE-79', 'CWE-22', 'CWE-502', 'CWE-78'],
      types: ['sast'],
      recommendation: 'Eliminate code flaw injection points (SQLi, XSS, RCE) that could compromise system integrity.'
    },
    {
      id: 'GDPR-ART-32(1)(c)',
      name: 'Vulnerability Assessment & Timely Restoration',
      category: 'Security of Processing',
      description: 'Regularly test, assess, and evaluate technical measures for ensuring the security of processing.',
      cweMatches: ['CWE-1395', 'CWE-937', 'CWE-1104'],
      types: ['dependency', 'iac'],
      recommendation: 'Perform continuous security scanning and rapidly patch third-party dependencies.'
    },
    {
      id: 'GDPR-ART-32(2)',
      name: 'Risk Assessment & Breach Prevention',
      category: 'Risk Management',
      description: 'Evaluate risks arising from processing, such as accidental or unlawful destruction, loss, or unauthorized access.',
      cweMatches: ['CWE-287', 'CWE-306', 'CWE-918', 'CWE-434'],
      types: ['sast', 'secret', 'iac'],
      recommendation: 'Audit access privileges, protect against server-side request forgery, and enforce strict API authorization.'
    },
    {
      id: 'GDPR-ART-5(1)(f)',
      name: 'Integrity and Confidentiality Principles',
      category: 'Data Principles',
      description: 'Personal data shall be processed in a manner that ensures appropriate security including protection against unauthorized access.',
      cweMatches: ['CWE-798', 'CWE-200', 'CWE-639'],
      types: ['secret', 'sast'],
      recommendation: 'Prevent credential leaks and unauthorized data exposure through robust access control and automated scanning.'
    }
  ]
};

/**
 * Evaluates real vulnerability findings against a specified compliance framework.
 * 
 * @param {Object} options
 * @param {string} options.framework - 'SOC2' | 'HIPAA' | 'PCI-DSS' | 'GDPR'
 * @param {Array} options.vulnerabilities - List of Vulnerability records from DB
 * @param {Object} options.repository - Repository record from DB
 * @param {string} options.reportName - Custom or generated report name
 * @param {Date} options.fromDate - Start date of evaluation period
 * @param {Date} options.toDate - End date of evaluation period
 * @returns {Object} Complete structured compliance report object
 */
function evaluateCompliance({ framework, vulnerabilities = [], repository, reportName, fromDate, toDate, dateRangeOption }) {
  const normalizedFramework = (framework || 'SOC2').toUpperCase().replace('-', '_');
  const lookupKey = normalizedFramework === 'PCI_DSS' || normalizedFramework === 'PCI-DSS' ? 'PCI-DSS' : normalizedFramework;
  
  const controlsConfig = FRAMEWORK_CONTROLS[lookupKey] || FRAMEWORK_CONTROLS.SOC2;

  // Filter vulnerabilities: only open vulnerabilities count towards control degradation
  const openVulns = vulnerabilities.filter(v => v.status === 'open' || !v.status);
  const fixedOrIgnoredVulns = vulnerabilities.filter(v => v.status === 'fixed' || v.status === 'false_positive' || v.status === 'ignored');

  // Counts breakdown
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;

  openVulns.forEach(v => {
    const s = (v.severity || 'low').toLowerCase();
    if (s === 'critical') criticalCount++;
    else if (s === 'high') highCount++;
    else if (s === 'medium') mediumCount++;
    else lowCount++;
  });

  const totalFindings = openVulns.length;

  // Evaluate each control
  let passedControls = 0;
  let partialControls = 0;
  let failedControls = 0;
  let notAssessedControls = 0;

  const evaluatedControls = controlsConfig.map(ctrl => {
    // Find matching vulnerabilities for this control based on CWE or vulnerability type
    const mapped = openVulns.filter(v => {
      const cweMatch = v.cweId && ctrl.cweMatches.some(c => v.cweId.toUpperCase().includes(c.toUpperCase()));
      const typeMatch = v.type && ctrl.types.includes(v.type.toLowerCase());
      return cweMatch || typeMatch;
    });

    const mappedResolved = fixedOrIgnoredVulns.filter(v => {
      const cweMatch = v.cweId && ctrl.cweMatches.some(c => v.cweId.toUpperCase().includes(c.toUpperCase()));
      const typeMatch = v.type && ctrl.types.includes(v.type.toLowerCase());
      return cweMatch || typeMatch;
    });

    const critMapped = mapped.filter(v => (v.severity || '').toLowerCase() === 'critical').length;
    const highMapped = mapped.filter(v => (v.severity || '').toLowerCase() === 'high').length;
    const medMapped = mapped.filter(v => (v.severity || '').toLowerCase() === 'medium').length;
    const lowMapped = mapped.filter(v => (v.severity || '').toLowerCase() === 'low').length;

    let status = 'PASS';
    let severity = 'NONE';
    let evidence = '';

    if (critMapped > 0 || highMapped >= 2) {
      status = 'FAIL';
      severity = critMapped > 0 ? 'CRITICAL' : 'HIGH';
      failedControls++;
      evidence = `FAILED: Detected ${critMapped} Critical and ${highMapped} High severity open vulnerability finding(s) violating this control standard.`;
    } else if (highMapped === 1 || medMapped >= 2) {
      status = 'PARTIAL';
      severity = highMapped === 1 ? 'HIGH' : 'MEDIUM';
      partialControls++;
      evidence = `PARTIALLY SATISFIED: Detected ${highMapped} High and ${medMapped} Medium severity open vulnerability finding(s) requiring remediation.`;
    } else if (medMapped === 1 || lowMapped > 0) {
      status = 'PARTIAL';
      severity = medMapped === 1 ? 'MEDIUM' : 'LOW';
      partialControls++;
      evidence = `PARTIALLY SATISFIED: ${medMapped > 0 ? medMapped + ' Medium and ' : ''}${lowMapped} Low severity open finding(s) detected.`;
    } else {
      status = 'PASS';
      severity = 'NONE';
      passedControls++;
      if (mappedResolved.length > 0) {
        evidence = `PASSED: 0 open vulnerabilities active. (${mappedResolved.length} previously identified finding(s) have been successfully remediated or resolved).`;
      } else {
        evidence = `PASSED: No open security vulnerabilities mapped to this control during the evaluated assessment period.`;
      }
    }

    return {
      id: ctrl.id,
      name: ctrl.name,
      category: ctrl.category,
      description: ctrl.description,
      status,
      severity,
      findingsCount: mapped.length,
      evidence,
      recommendation: ctrl.recommendation,
      mappedFindings: mapped.slice(0, 10).map(v => ({
        id: v.id,
        title: v.title,
        severity: (v.severity || 'low').toLowerCase(),
        filePath: v.filePath,
        lineStart: v.lineStart,
        cweId: v.cweId || 'N/A',
        status: v.status || 'open'
      }))
    };
  });

  // Calculate Deterministic Compliance Score (0 to 100)
  // Finding score deduction: Critical (-15), High (-8), Medium (-4), Low (-1)
  const findingDeduction = (criticalCount * 15) + (highCount * 8) + (mediumCount * 4) + (lowCount * 1);
  const findingScore = Math.max(0, 100 - findingDeduction);

  const totalEvaluated = evaluatedControls.length;
  const controlScore = totalEvaluated > 0
    ? Math.round(((passedControls + (partialControls * 0.5)) / totalEvaluated) * 100)
    : 100;

  const complianceScore = Math.max(0, Math.min(100, Math.round((findingScore * 0.6) + (controlScore * 0.4))));

  // Generate prioritized recommendations
  const recommendations = [];
  if (criticalCount > 0) {
    recommendations.push({
      priority: 'CRITICAL',
      title: `Remediation of ${criticalCount} Critical Vulnerabilities`,
      action: 'Immediately address critical findings (e.g. hardcoded credentials, SQL injection, remote code execution) before deploying to production.'
    });
  }
  if (highCount > 0) {
    recommendations.push({
      priority: 'HIGH',
      title: `Remediation of ${highCount} High-Severity Vulnerabilities`,
      action: 'Fix high-severity findings such as unescaped input rendering (XSS), path traversals, and insecure Direct Object References.'
    });
  }
  if (mediumCount > 0 || lowCount > 0) {
    recommendations.push({
      priority: 'MEDIUM',
      title: `Schedule Resolution for ${mediumCount + lowCount} Moderate/Low Findings`,
      action: 'Incorporate low and medium severity findings into upcoming sprint engineering backlogs.'
    });
  }
  if (recommendations.length === 0) {
    recommendations.push({
      priority: 'LOW',
      title: 'Maintain Continuous CI/CD Security Scanning',
      action: 'No open vulnerabilities detected. Continue automated continuous integration scans on all pull requests.'
    });
  }

  // Limitations
  const limitations = [
    'Assessment is based strictly on static source code analysis (SAST), secrets detection, and dependency manifests evaluated by SecureGuard.',
    'Dynamic runtime penetration testing, infrastructure hardware, physical security, and operational policies were not in scope for this automated report.',
    'Third-party cloud infrastructure configurations outside of scanned IaC files are not evaluated.'
  ];

  // Disclaimer
  const disclaimer = 'DISCLAIMER: This document is an automated security assessment report generated by SecureGuard based on source code scanning data. It does NOT constitute an official regulatory audit, legal certification, or guarantee of regulatory compliance under SOC 2, HIPAA, PCI-DSS, or GDPR standards.';

  const formattedName = reportName || `${lookupKey} Compliance Report - ${repository?.name || 'Repository'}`;

  return {
    product: 'SecureGuard',
    report: {
      name: formattedName,
      framework: lookupKey,
      repositoryId: repository?.id,
      repositoryName: repository?.name || 'N/A',
      repositoryFullName: repository?.fullName || 'N/A',
      platform: repository?.platform || 'github',
      language: repository?.language || 'N/A',
      dateRangeOption: dateRangeOption || '30d',
      assessmentPeriod: {
        from: fromDate ? new Date(fromDate).toISOString() : new Date(Date.now() - 30 * 86400000).toISOString(),
        to: toDate ? new Date(toDate).toISOString() : new Date().toISOString()
      },
      generatedAt: new Date().toISOString()
    },
    summary: {
      score: complianceScore,
      totalFindings,
      critical: criticalCount,
      high: highCount,
      medium: mediumCount,
      low: lowCount,
      passedControls,
      partialControls,
      failedControls,
      notAssessedControls
    },
    controls: evaluatedControls,
    findings: openVulns.map(v => ({
      id: v.id,
      title: v.title,
      severity: (v.severity || 'low').toLowerCase(),
      cweId: v.cweId || 'N/A',
      ruleId: v.ruleId || 'N/A',
      filePath: v.filePath,
      lineStart: v.lineStart,
      lineEnd: v.lineEnd,
      codeSnippet: v.codeSnippet || '',
      status: v.status || 'open',
      type: v.type || 'sast',
      aiFix: v.aiFix || null
    })),
    recommendations,
    limitations,
    disclaimer
  };
}

module.exports = {
  FRAMEWORK_CONTROLS,
  evaluateCompliance
};
