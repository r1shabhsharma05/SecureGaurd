/**
 * AI Fix Engine — Intelligent rule-based vulnerability fix generator
 * Generates contextually correct, production-quality code fixes for each
 * vulnerability type detected by the SAST/Secret scanner.
 *
 * Uses optional Gemini API if GEMINI_API_KEY is set in .env,
 * otherwise falls back to the high-quality built-in rule engine.
 */

// ── Rule-Based Fix Templates ──────────────────────────────────────────────────
const FIX_RULES = {
  'Potential SQL Injection': {
    confidence: 97,
    explanation: 'SQL queries must use parameterized statements or an ORM query builder. String concatenation and template literals in SQL allow attackers to inject arbitrary commands.',
    fixTemplate: (snippet) => {
      // Replace raw string concat with parameterized query
      const fixed = snippet
        .replace(/`SELECT\s+(.*?)\s+WHERE\s+(\w+)\s*=\s*\$\{([^}]+)\}`/gi,
          'db.query(\'SELECT $1 WHERE $2 = ?\', [$3])')
        .replace(/`SELECT\s+(.*?)\s+FROM\s+(.*?)\s+WHERE\s+(.*?)\s*\+\s*([^`]+)`/gi,
          'db.query(\'SELECT $1 FROM $2 WHERE $3 = ?\', [userInput])')
        || `// FIXED: Use parameterized query instead\nconst result = await db.query(\n  'SELECT * FROM users WHERE id = ?',\n  [sanitizedId]\n);`;
      return fixed;
    },
    cweId: 'CWE-89',
    cvssScore: 9.8,
    references: ['https://owasp.org/www-community/attacks/SQL_Injection', 'https://cwe.mitre.org/data/definitions/89.html']
  },

  'Cross-Site Scripting (XSS)': {
    confidence: 94,
    explanation: 'User-controlled inputs must be sanitized before being reflected in HTTP responses. Use a library like DOMPurify or encode special characters to prevent script injection.',
    fixTemplate: (snippet) => {
      return snippet
        .replace(/res\.send\(`(.*)(\$\{req\.(query|body|params)\.[^}]+\})(.*)`\)/,
          `const sanitized = encodeURIComponent($2);\nres.send(\`$1\${sanitized}$4\`)`)
        || `// FIXED: Sanitize user input before rendering\nconst sanitized = encodeURIComponent(req.query.input || '');\nres.send(\`<h1>Hello \${sanitized}</h1>\`);`;
    },
    cweId: 'CWE-79',
    cvssScore: 7.4,
    references: ['https://owasp.org/www-community/attacks/xss/', 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html']
  },

  'Path Traversal Vulnerability': {
    confidence: 92,
    explanation: 'File paths derived from user input must be resolved and validated against an allowed base directory to prevent directory traversal attacks.',
    fixTemplate: (snippet) => {
      return `// FIXED: Validate and sanitize file path\nconst safeName = path.basename(req.body.filename);\nconst allowedDir = path.resolve('./uploads');\nconst fullPath = path.resolve(allowedDir, safeName);\n\nif (!fullPath.startsWith(allowedDir)) {\n  return res.status(400).json({ error: 'Invalid file path' });\n}\n\nfs.readFile(fullPath, 'utf8', callback);`;
    },
    cweId: 'CWE-22',
    cvssScore: 7.5,
    references: ['https://owasp.org/www-community/attacks/Path_Traversal', 'https://cwe.mitre.org/data/definitions/22.html']
  },

  'Weak JWT Signature Verification': {
    confidence: 99,
    explanation: 'JWT secrets must be loaded from environment variables, never hardcoded. Hardcoded secrets are trivially extractable from source code or compiled binaries.',
    fixTemplate: (snippet) => {
      return snippet
        .replace(/jwt\.verify\(([^,]+),\s*['"`][^'"`]+['"`]\)/,
          'jwt.verify($1, process.env.JWT_SECRET)')
        || `// FIXED: Load secret from environment variable\nconst decoded = jwt.verify(token, process.env.JWT_SECRET);\nif (!decoded) throw new Error('Invalid token');`;
    },
    cweId: 'CWE-798',
    cvssScore: 9.1,
    references: ['https://jwt.io/introduction', 'https://owasp.org/www-project-web-security-testing-guide/']
  },

  'Remote Command Execution': {
    confidence: 99,
    explanation: 'Never pass user-controlled data directly to shell commands. Use allowlists, argument arrays (not shell strings), or avoid shell execution entirely.',
    fixTemplate: (snippet) => {
      return `// FIXED: Use spawn with argument array, never exec with user input\nconst { spawn } = require('child_process');\nconst ALLOWED_CMDS = ['ls', 'cat'];\n\nif (!ALLOWED_CMDS.includes(req.body.cmd)) {\n  return res.status(400).json({ error: 'Command not allowed' });\n}\n\nconst child = spawn(req.body.cmd, [], { shell: false });\nchild.stdout.on('data', data => res.send(data.toString()));`;
    },
    cweId: 'CWE-78',
    cvssScore: 10.0,
    references: ['https://owasp.org/www-community/attacks/Command_Injection', 'https://cwe.mitre.org/data/definitions/78.html']
  },

  'Hardcoded Secret Key': {
    confidence: 99,
    explanation: 'Secrets, passwords, and API keys must never be stored in source code. Use environment variables loaded via dotenv or a secrets manager (AWS Secrets Manager, Vault).',
    fixTemplate: (snippet) => {
      const match = snippet.match(/(?:const|let|var)\s+(\w+)\s*=\s*['"`][^'"`]+['"`]/);
      const varName = match ? match[1].toUpperCase() : 'SECRET_KEY';
      return `// FIXED: Move to .env file and access via process.env\n// In .env: ${varName}=your_actual_secret_here\nconst secret = process.env.${varName};\nif (!secret) throw new Error('${varName} environment variable is not set');`;
    },
    cweId: 'CWE-798',
    cvssScore: 9.8,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html']
  },

  'Exposed AWS Access Key': {
    confidence: 100,
    explanation: 'AWS Access Keys detected in source code. Rotate this key immediately via AWS IAM console, then use IAM roles or environment variables for credential management.',
    fixTemplate: (snippet) => {
      return `// CRITICAL FIX REQUIRED:\n// 1. Go to AWS IAM Console → Users → Security credentials\n// 2. Deactivate and delete this exposed key immediately\n// 3. Check CloudTrail for unauthorized usage\n// 4. Use IAM roles for EC2/Lambda or environment variables:\n\n// In .env:\n// AWS_ACCESS_KEY_ID=your_key\n// AWS_SECRET_ACCESS_KEY=your_secret\n\n// In code:\nconst { S3Client } = require('@aws-sdk/client-s3');\nconst client = new S3Client({ region: process.env.AWS_REGION });`;
    },
    cweId: 'CWE-798',
    cvssScore: 10.0,
    references: ['https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html']
  },

  'Dockerfile Root Execution': {
    confidence: 95,
    explanation: 'Container processes should run as a non-root user to limit blast radius if the container is compromised.',
    fixTemplate: (snippet) => {
      return `# FIXED: Run container as non-root user\nRUN groupadd -r appuser && useradd -r -g appuser appuser\nWORKDIR /app\nCOPY --chown=appuser:appuser . .\nUSER appuser\nCMD ["node", "server.js"]`;
    },
    cweId: 'CWE-250',
    cvssScore: 5.5,
    references: ['https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user']
  },

  'Exposed Port in Dockerfile': {
    confidence: 90,
    explanation: 'Exposing SSH (port 22) in a container image is a security anti-pattern. Use container orchestration tools for remote access instead.',
    fixTemplate: (snippet) => {
      return `# FIXED: Remove SSH exposure; use docker exec or kubectl exec instead\n# EXPOSE 22  <-- REMOVED\n# For production debugging, use:\n# docker exec -it <container_id> /bin/sh\n# or kubectl exec -it <pod_name> -- /bin/sh`;
    },
    cweId: 'CWE-284',
    cvssScore: 5.3,
    references: ['https://docs.docker.com/engine/reference/builder/#expose']
  },

  // Dependency vulnerabilities
  'Prototype Pollution in Lodash': {
    confidence: 100,
    explanation: 'This version of Lodash contains a prototype pollution vulnerability. Upgrade to lodash >= 4.17.21 immediately.',
    fixTemplate: (snippet) => {
      return `// FIXED: Upgrade lodash to patched version\n// Run: npm install lodash@^4.17.21\n\n// In package.json:\n// "lodash": "^4.17.21"\n\n// Verify with: npm audit`;
    },
    cweId: 'CWE-1321',
    cvssScore: 7.4,
    references: ['https://github.com/advisories/GHSA-35jh-r3h4-6jhm']
  },

  'SSRF in Axios': {
    confidence: 100,
    explanation: 'Older versions of Axios are vulnerable to Server-Side Request Forgery. Upgrade to axios >= 0.21.1.',
    fixTemplate: (snippet) => {
      return `// FIXED: Upgrade axios to patched version\n// Run: npm install axios@latest\n\n// In package.json:\n// "axios": "^1.6.0"\n\n// Also validate all URLs before making requests:\nconst url = new URL(userProvidedUrl);\nif (!['https:'].includes(url.protocol)) {\n  throw new Error('Only HTTPS URLs allowed');\n}`;
    },
    cweId: 'CWE-918',
    cvssScore: 7.5,
    references: ['https://github.com/advisories/GHSA-42xw-2xvc-qx8m']
  },

  // IaC & API Specification Fix Rules
  'Publicly Accessible Storage Bucket': {
    confidence: 95,
    explanation: 'Storage buckets must block public ACLs and public bucket policies to prevent accidental data leaks.',
    fixTemplate: (snippet) => {
      return `# FIXED: Restrict public access on S3 Bucket\nresource "aws_s3_bucket" "private_bucket" {\n  bucket = "secure-data-bucket"\n}\n\nresource "aws_s3_bucket_public_access_block" "block_public" {\n  bucket                  = aws_s3_bucket.private_bucket.id\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}`;
    },
    cweId: 'CWE-200',
    cvssScore: 8.6,
    references: ['https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html']
  },

  'Missing Server-Side Storage Encryption': {
    confidence: 95,
    explanation: 'Storage resources should be encrypted at rest using KMS or AES256 server-side encryption.',
    fixTemplate: (snippet) => {
      return `# FIXED: Enable Server-Side Encryption\nresource "aws_s3_bucket_server_side_encryption_configuration" "encrypt" {\n  bucket = aws_s3_bucket.my_bucket.id\n  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm = "AES256"\n    }\n  }\n}`;
    },
    cweId: 'CWE-311',
    cvssScore: 7.5,
    references: ['https://cwe.mitre.org/data/definitions/311.html']
  },

  'Overly Permissive Ingress Rule (0.0.0.0/0)': {
    confidence: 95,
    explanation: 'Avoid 0.0.0.0/0 CIDR block ingress rules on sensitive ports. Restrict network access to trusted IP ranges.',
    fixTemplate: (snippet) => {
      return `# FIXED: Restrict ingress CIDR blocks\ningress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/16"] # Restricted internal subnet\n}`;
    },
    cweId: 'CWE-284',
    cvssScore: 9.1,
    references: ['https://cwe.mitre.org/data/definitions/284.html']
  },

  'Privileged Container Execution': {
    confidence: 98,
    explanation: 'Disable privileged execution on container securityContext to prevent host root breakout.',
    fixTemplate: (snippet) => {
      return `# FIXED: Disable container privileged mode\nsecurityContext:\n  privileged: false\n  allowPrivilegeEscalation: false\n  readOnlyRootFilesystem: true`;
    },
    cweId: 'CWE-250',
    cvssScore: 9.8,
    references: ['https://kubernetes.io/docs/concepts/security/pod-security-standards/']
  },

  'Container Running as Root User': {
    confidence: 95,
    explanation: 'Enforce non-root execution in Pod securityContext with runAsNonRoot: true.',
    fixTemplate: (snippet) => {
      return `# FIXED: Enforce non-root execution\nsecurityContext:\n  runAsNonRoot: true\n  runAsUser: 10001\n  runAsGroup: 10001`;
    },
    cweId: 'CWE-250',
    cvssScore: 7.8,
    references: ['https://kubernetes.io/docs/tasks/configure-pod-container/security-context/']
  },

  'Container Process Running as Root': {
    confidence: 95,
    explanation: 'Add a non-root USER instruction to Dockerfile to prevent running container processes as root.',
    fixTemplate: (snippet) => {
      return `# FIXED: Run as unprivileged user\nRUN groupadd -r appuser && useradd -r -g appuser appuser\nWORKDIR /app\nCOPY --chown=appuser:appuser . .\nUSER appuser\nCMD ["node", "server.js"]`;
    },
    cweId: 'CWE-250',
    cvssScore: 7.5,
    references: ['https://docs.docker.com/develop/develop-images/dockerfile_best-practices/']
  },

  'Missing Authentication Requirement on API Specification': {
    confidence: 95,
    explanation: 'Declare security schemes in OpenAPI components and enforce authentication on API operations.',
    fixTemplate: (snippet) => {
      return `# FIXED: Define security requirement in OpenAPI spec\ncomponents:\n  securitySchemes:\n    bearerAuth:\n      type: http\n      scheme: bearer\n      bearerFormat: JWT\nsecurity:\n  - bearerAuth: []`;
    },
    cweId: 'CWE-306',
    cvssScore: 8.5,
    references: ['https://swagger.io/docs/specification/authentication/']
  },
};

// Default fallback for unknown vulnerability types
const DEFAULT_FIX = {
  confidence: 70,
  explanation: 'This vulnerability should be reviewed by a security engineer. Apply the principle of least privilege, validate all inputs, and avoid trusting user-controlled data.',
  fixTemplate: (snippet) => {
    return `// AI FIX SUGGESTION:\n// 1. Validate and sanitize all user inputs before use\n// 2. Apply principle of least privilege\n// 3. Use established security libraries for the operation\n// 4. Add input validation middleware\n// 5. Consider adding rate limiting\n\n// Review this code carefully with your security team.`;
  },
  cweId: 'CWE-20',
  cvssScore: 5.0,
  references: ['https://owasp.org/www-project-top-ten/']
};

// ── Main AI Fix Generation Function ──────────────────────────────────────────
async function generateAiFix(vulnerability) {
  const { title, codeSnippet, type, severity } = vulnerability;

  // 1. Try local gemini-web2api proxy (1.5M Token Web Model)
  const web2apiUrl = process.env.GEMINI_WEB2API_URL || 'http://localhost:8081/v1';
  try {
    const web2apiResult = await callGeminiWeb2Api(vulnerability, web2apiUrl);
    if (web2apiResult) return web2apiResult;
  } catch {
    // web2api proxy not running, try official API key
  }

  // 2. Try official Gemini API key if available
  if (process.env.GEMINI_API_KEY) {
    try {
      const geminiResult = await callGeminiAPI(vulnerability);
      if (geminiResult) return geminiResult;
    } catch (err) {
      console.warn('[AI Engine] Gemini API failed, falling back to rule engine:', err.message);
    }
  }

  // 3. Built-in Rule Engine Fallback
  const rule = FIX_RULES[title] || DEFAULT_FIX;
  const fixedCode = rule.fixTemplate(codeSnippet || '');

  return {
    fixedCode,
    explanation: rule.explanation,
    confidence: rule.confidence,
    cweId: rule.cweId || 'CWE-20',
    cvssScore: rule.cvssScore || 5.0,
    references: rule.references || [],
    engine: 'rule-based'
  };
}

// ── Gemini Web2API Integration (1.5M Token Context Proxy) ────────────────────
async function callGeminiWeb2Api(vulnerability, baseUrl) {
  const { title, codeSnippet, filePath, severity } = vulnerability;

  const prompt = `You are a senior application security engineer. Analyze this ${severity.toUpperCase()} severity vulnerability and provide a production-ready fix.

Vulnerability: ${title}
File: ${filePath}
Vulnerable Code:
\`\`\`
${codeSnippet}
\`\`\`

Respond in valid JSON only (no markdown codeblock wrapper):
{
  "fixedCode": "the complete fixed code snippet",
  "explanation": "clear 1-2 sentence explanation of why this is vulnerable and what the fix does",
  "confidence": 95,
  "cweId": "CWE-XXX"
}`;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 8000);

  const apiResponse = await fetch(`${baseUrl}/chat/completions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${process.env.GEMINI_WEB2API_KEY || 'sk-gemini'}`
    },
    body: JSON.stringify({
      model: 'gemini-1.5-flash',
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.1
    }),
    signal: controller.signal
  });
  clearTimeout(timeoutId);

  if (!apiResponse.ok) throw new Error(`web2api error: ${apiResponse.status}`);

  const responseData = await apiResponse.json();
  const text = responseData.choices?.[0]?.message?.content || '';
  const jsonMatch = text.match(/\{[\s\S]*\}/);
  if (!jsonMatch) throw new Error('Could not parse web2api JSON response');

  const parsed = JSON.parse(jsonMatch[0]);
  return {
    fixedCode: parsed.fixedCode || '',
    explanation: parsed.explanation || '',
    confidence: parsed.confidence || 90,
    cweId: parsed.cweId || 'CWE-20',
    cvssScore: 7.5,
    references: [],
    engine: 'gemini-1.5-flash (web2api proxy - 1.5M Tokens)'
  };
}

// ── Official Gemini REST API Integration ──────────────────────────────────────
async function callGeminiAPI(vulnerability) {
  const { title, codeSnippet, filePath, severity } = vulnerability;

  const prompt = `You are a senior application security engineer. Analyze this ${severity.toUpperCase()} severity vulnerability and provide a production-ready fix.

Vulnerability: ${title}
File: ${filePath}
Vulnerable Code:
\`\`\`
${codeSnippet}
\`\`\`

Respond in valid JSON only (no markdown):
{
  "fixedCode": "the complete fixed code snippet",
  "explanation": "clear 1-2 sentence explanation of why this is vulnerable and what the fix does",
  "confidence": <integer 0-100>,
  "cweId": "CWE-XXX"
}`;

  const response = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${process.env.GEMINI_API_KEY}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.1, maxOutputTokens: 1024 }
      })
    }
  );

  if (!response.ok) throw new Error(`Gemini API error: ${response.status}`);

  const geminiData = await response.json();
  const text = geminiData.candidates?.[0]?.content?.parts?.[0]?.text || '';
  const jsonMatch = text.match(/\{[\s\S]*\}/);
  if (!jsonMatch) throw new Error('Could not parse Gemini response');

  const parsed = JSON.parse(jsonMatch[0]);
  return {
    fixedCode: parsed.fixedCode || '',
    explanation: parsed.explanation || '',
    confidence: parsed.confidence || 85,
    cweId: parsed.cweId || 'CWE-20',
    cvssScore: 7.0,
    references: [],
    engine: 'gemini-1.5-flash (official API)'
  };
}

module.exports = { generateAiFix };
