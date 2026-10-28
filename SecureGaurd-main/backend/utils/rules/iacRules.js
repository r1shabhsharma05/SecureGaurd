/**
 * IaC Security Rules Registry (Terraform, Kubernetes, Dockerfile)
 */

const IAC_RULES = {
  // ── TERRAFORM SECURITY RULES ────────────────────────────────────────────────
  'TF-001': {
    ruleId: 'TF-001',
    framework: 'Terraform',
    category: 'Storage',
    title: 'Publicly Accessible Storage Bucket',
    severity: 'critical',
    cweId: 'CWE-200',
    description: 'Storage bucket or object ACL is configured with public-read, public-read-write, or missing public access block settings.',
    remediation: 'Configure bucket ACL to private and enable aws_s3_bucket_public_access_block with block_public_acls = true.',
    references: ['https://cwe.mitre.org/data/definitions/200.html', 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html']
  },
  'TF-002': {
    ruleId: 'TF-002',
    framework: 'Terraform',
    category: 'Encryption',
    title: 'Missing Server-Side Storage Encryption',
    severity: 'high',
    cweId: 'CWE-311',
    description: 'Storage resource (S3 bucket, EBS volume, Azure Storage) is created without explicit server-side encryption enabled.',
    remediation: 'Add server-side encryption configuration using KMS or AES256 provider managed keys.',
    references: ['https://cwe.mitre.org/data/definitions/311.html']
  },
  'TF-003': {
    ruleId: 'TF-003',
    framework: 'Terraform',
    category: 'Network',
    title: 'Overly Permissive Ingress Rule (0.0.0.0/0)',
    severity: 'critical',
    cweId: 'CWE-284',
    description: 'Security group or firewall rule allows unrestricted network access (0.0.0.0/0) to sensitive ports (e.g. 22, 3389, 3306, 5432, 27017).',
    remediation: 'Restrict ingress cidr_blocks to trusted IP ranges or bastion hosts instead of global 0.0.0.0/0.',
    references: ['https://cwe.mitre.org/data/definitions/284.html']
  },
  'TF-004': {
    ruleId: 'TF-004',
    framework: 'Terraform',
    category: 'IAM',
    title: 'Overly Permissive IAM Policy (Wildcard Action/Principal)',
    severity: 'high',
    cweId: 'CWE-732',
    description: 'IAM policy document or statement grants wildcard ("*") permissions across all actions or resources.',
    remediation: 'Enforce the principle of least privilege by specifying exact actions (e.g. s3:GetObject) and target ARNs.',
    references: ['https://cwe.mitre.org/data/definitions/732.html']
  },
  'TF-005': {
    ruleId: 'TF-005',
    framework: 'Terraform',
    category: 'Secrets',
    title: 'Hardcoded Credentials in Terraform Manifest',
    severity: 'critical',
    cweId: 'CWE-798',
    description: 'Hardcoded access keys, secret keys, database passwords, or auth tokens detected in Terraform configuration.',
    remediation: 'Use Terraform variables marked with sensitive = true or inject credentials via AWS Secrets Manager / Vault.',
    references: ['https://cwe.mitre.org/data/definitions/798.html']
  },
  'TF-006': {
    ruleId: 'TF-006',
    framework: 'Terraform',
    category: 'Logging',
    title: 'Missing Security Audit Logging',
    severity: 'medium',
    cweId: 'CWE-778',
    description: 'Cloud resource lacks security access logging or VPC flow logging configuration.',
    remediation: 'Enable logging (e.g. aws_s3_bucket_logging, aws_flow_log) to maintain security audit trails.',
    references: ['https://cwe.mitre.org/data/definitions/778.html']
  },

  // ── KUBERNETES SECURITY RULES ───────────────────────────────────────────────
  'K8S-001': {
    ruleId: 'K8S-001',
    framework: 'Kubernetes',
    category: 'Privilege',
    title: 'Privileged Container Execution',
    severity: 'critical',
    cweId: 'CWE-250',
    description: 'Container securityContext is configured with privileged: true, allowing root access to host devices and kernel capabilities.',
    remediation: 'Set securityContext.privileged: false and grant only specific required Linux capabilities.',
    references: ['https://kubernetes.io/docs/concepts/security/pod-security-standards/']
  },
  'K8S-002': {
    ruleId: 'K8S-002',
    framework: 'Kubernetes',
    category: 'Privilege',
    title: 'Container Running as Root User',
    severity: 'high',
    cweId: 'CWE-250',
    description: 'Pod or container securityContext explicitly sets runAsUser: 0 or lacks runAsNonRoot: true.',
    remediation: 'Configure securityContext.runAsNonRoot: true and specify a non-zero runAsUser ID (e.g. 10001).',
    references: ['https://kubernetes.io/docs/tasks/configure-pod-container/security-context/']
  },
  'K8S-003': {
    ruleId: 'K8S-003',
    framework: 'Kubernetes',
    category: 'Network',
    title: 'Host Network Shared with Pod',
    severity: 'high',
    cweId: 'CWE-668',
    description: 'Pod specification uses hostNetwork: true, exposing host network interfaces and loopback services to container workloads.',
    remediation: 'Remove hostNetwork: true unless running network infrastructure daemonsets that strictly require it.',
    references: ['https://kubernetes.io/docs/concepts/security/pod-security-standards/']
  },
  'K8S-004': {
    ruleId: 'K8S-004',
    framework: 'Kubernetes',
    category: 'Process Isolation',
    title: 'Host PID Namespace Shared with Pod',
    severity: 'high',
    cweId: 'CWE-668',
    description: 'Pod uses hostPID: true, allowing container processes to inspect and interact with processes running on the host node.',
    remediation: 'Remove hostPID: true to enforce process namespace isolation between host and containers.',
    references: ['https://kubernetes.io/docs/concepts/security/pod-security-standards/']
  },
  'K8S-005': {
    ruleId: 'K8S-005',
    framework: 'Kubernetes',
    category: 'Storage',
    title: 'Dangerous Host Path Volume Mount',
    severity: 'high',
    cweId: 'CWE-22',
    description: 'Pod mounts host system files or directories (e.g. /, /etc, /var/run/docker.sock) via hostPath volume.',
    remediation: 'Avoid mounting sensitive host paths. Use persistentVolumeClaims or emptyDir volumes instead.',
    references: ['https://cwe.mitre.org/data/definitions/22.html']
  },
  'K8S-006': {
    ruleId: 'K8S-006',
    framework: 'Kubernetes',
    category: 'Resource Management',
    title: 'Missing Container Resource Limits',
    severity: 'medium',
    cweId: 'CWE-400',
    description: 'Container specification does not define CPU or memory limits, leaving cluster vulnerable to Denial of Service (DoS).',
    remediation: 'Define resources.limits.cpu and resources.limits.memory for all container specifications.',
    references: ['https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/']
  },
  'K8S-007': {
    ruleId: 'K8S-007',
    framework: 'Kubernetes',
    category: 'Capabilities',
    title: 'Insecure Linux Capabilities Added',
    severity: 'high',
    cweId: 'CWE-250',
    description: 'Container securityContext adds dangerous Linux capabilities such as SYS_ADMIN, NET_ADMIN, SYS_PTRACE, or ALL.',
    remediation: 'Drop all capabilities (capabilities.drop: ["ALL"]) and add back only minimal required capabilities.',
    references: ['https://kubernetes.io/docs/tasks/configure-pod-container/security-context/']
  },
  'K8S-008': {
    ruleId: 'K8S-008',
    framework: 'Kubernetes',
    category: 'Privilege',
    title: 'Allow Privilege Escalation Enabled',
    severity: 'medium',
    cweId: 'CWE-250',
    description: 'Container allows privilege escalation (allowPrivilegeEscalation: true or not set to false).',
    remediation: 'Explicitly set securityContext.allowPrivilegeEscalation: false in all container definitions.',
    references: ['https://kubernetes.io/docs/tasks/configure-pod-container/security-context/']
  },
  'K8S-009': {
    ruleId: 'K8S-009',
    framework: 'Kubernetes',
    category: 'Secrets',
    title: 'Hardcoded Secret in Kubernetes Manifest',
    severity: 'critical',
    cweId: 'CWE-798',
    description: 'Plaintext passwords, API keys, or private tokens hardcoded in manifest environment variables.',
    remediation: 'Use secretKeyRef to reference Kubernetes Secret objects or External Secrets Operator.',
    references: ['https://kubernetes.io/docs/concepts/configuration/secret/']
  },

  // ── DOCKERFILE SECURITY RULES ───────────────────────────────────────────────
  'DOCKER-001': {
    ruleId: 'DOCKER-001',
    framework: 'Docker',
    category: 'Privilege',
    title: 'Container Process Running as Root',
    severity: 'medium',
    cweId: 'CWE-250',
    description: 'Dockerfile is missing a USER instruction or explicitly specifies USER root.',
    remediation: 'Create an unprivileged user/group (e.g. RUN addgroup -S app && adduser -S app -G app) and set USER app.',
    references: ['https://docs.docker.com/develop/develop-images/dockerfile_best-practices/']
  },
  'DOCKER-002': {
    ruleId: 'DOCKER-002',
    framework: 'Docker',
    category: 'Network',
    title: 'Exposed Sensitive Port in Dockerfile',
    severity: 'medium',
    cweId: 'CWE-200',
    description: 'Dockerfile explicitly exposes sensitive administrative or remote access ports (e.g. EXPOSE 22, 2375, 3389).',
    remediation: 'Remove EXPOSE 22 or Docker daemon socket ports unless running a dedicated SSH image.',
    references: ['https://cwe.mitre.org/data/definitions/200.html']
  },
  'DOCKER-003': {
    ruleId: 'DOCKER-003',
    framework: 'Docker',
    category: 'Secrets',
    title: 'Hardcoded Credentials in ENV / ARG Instructions',
    severity: 'critical',
    cweId: 'CWE-798',
    description: 'Hardcoded secret key, API token, or password found in ENV or ARG instructions in Dockerfile.',
    remediation: 'Do not bake secrets into image layers via ENV/ARG. Pass secrets at runtime or use Docker BuildKit secrets.',
    references: ['https://docs.docker.com/develop/develop-images/build_enhancements/#using-ssh-to-access-private-data-in-builds']
  },
  'DOCKER-004': {
    ruleId: 'DOCKER-004',
    framework: 'Docker',
    category: 'File System',
    title: 'Risky ADD Instruction Used Instead of COPY',
    severity: 'low',
    cweId: 'CWE-829',
    description: 'Using ADD for local files or remote URLs can lead to unexpected tar extraction or remote file fetching vulnerabilities.',
    remediation: 'Use COPY instead of ADD for copying local files into the container image.',
    references: ['https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#add-or-copy']
  },
  'DOCKER-005': {
    ruleId: 'DOCKER-005',
    framework: 'Docker',
    category: 'Command Execution',
    title: 'Dangerous Remote Script Execution in RUN',
    severity: 'high',
    cweId: 'CWE-829',
    description: 'RUN instruction executes unverified remote shell scripts via curl | sh or wget | bash.',
    remediation: 'Download remote packages, verify SHA256 checksums, and execute verified install steps explicitly.',
    references: ['https://cwe.mitre.org/data/definitions/829.html']
  },

  // ── CLOUDFORMATION SECURITY RULES ──────────────────────────────────────────
  'CFN-001': {
    ruleId: 'CFN-001',
    framework: 'CloudFormation',
    category: 'Storage',
    title: 'Publicly Accessible S3 Bucket in Template',
    severity: 'critical',
    cweId: 'CWE-200',
    description: 'S3 bucket resource sets AccessControl to PublicRead or PublicReadWrite, exposing bucket contents to anyone on the internet.',
    remediation: 'Remove the public AccessControl and add a PublicAccessBlockConfiguration with BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls and RestrictPublicBuckets all true.',
    references: ['https://cwe.mitre.org/data/definitions/200.html']
  },
  'CFN-002': {
    ruleId: 'CFN-002',
    framework: 'CloudFormation',
    category: 'Network',
    title: 'Overly Permissive Security Group Ingress (0.0.0.0/0)',
    severity: 'critical',
    cweId: 'CWE-284',
    description: 'Security group ingress rule allows unrestricted access (0.0.0.0/0) to a sensitive port.',
    remediation: 'Restrict CidrIp to trusted ranges or reference a bastion/security group instead of 0.0.0.0/0.',
    references: ['https://cwe.mitre.org/data/definitions/284.html']
  },
  'CFN-003': {
    ruleId: 'CFN-003',
    framework: 'CloudFormation',
    category: 'Encryption',
    title: 'Missing Encryption at Rest',
    severity: 'high',
    cweId: 'CWE-311',
    description: 'Storage resource (S3 bucket without BucketEncryption, EBS volume with Encrypted false, RDS instance with StorageEncrypted false) is created without encryption at rest.',
    remediation: 'Enable BucketEncryption on S3 buckets, Encrypted: true on EBS volumes, and StorageEncrypted: true on RDS instances.',
    references: ['https://cwe.mitre.org/data/definitions/311.html']
  },
  'CFN-004': {
    ruleId: 'CFN-004',
    framework: 'CloudFormation',
    category: 'IAM',
    title: 'Overly Permissive IAM Policy (Wildcard Action/Resource)',
    severity: 'high',
    cweId: 'CWE-732',
    description: 'IAM policy statement grants wildcard ("*") actions or resources in a CloudFormation template.',
    remediation: 'Scope each statement to the exact actions and resource ARNs the workload needs.',
    references: ['https://cwe.mitre.org/data/definitions/732.html']
  },
  'CFN-005': {
    ruleId: 'CFN-005',
    framework: 'CloudFormation',
    category: 'Secrets',
    title: 'Hardcoded Secret in Template Properties',
    severity: 'critical',
    cweId: 'CWE-798',
    description: 'A literal password, secret or API key value is embedded in template resource properties instead of a parameter with NoEcho or a secrets reference.',
    remediation: 'Move the value to a NoEcho parameter, Secrets Manager dynamic reference, or SSM SecureString parameter.',
    references: ['https://cwe.mitre.org/data/definitions/798.html']
  },
  'CFN-006': {
    ruleId: 'CFN-006',
    framework: 'CloudFormation',
    category: 'Network',
    title: 'Publicly Accessible RDS Instance',
    severity: 'high',
    cweId: 'CWE-200',
    description: 'RDS DB instance sets PubliclyAccessible to true, exposing the database port to the internet.',
    remediation: 'Set PubliclyAccessible: false and reach the database only through private subnets or a bastion host.',
    references: ['https://cwe.mitre.org/data/definitions/200.html']
  }
};

module.exports = { IAC_RULES };
