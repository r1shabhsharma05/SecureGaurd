/**
 * Day 5 — CloudFormation scanner verification.
 * Verifies: CFN-001..CFN-006 on JSON + YAML templates (incl. !Ref/!Sub
 * intrinsic tags), the non-template guard, and the unified pipeline count.
 */

const fs = require('fs');
const path = require('path');
const { scanCloudFormationFile } = require('../utils/iacCloudFormationScanner');
const { runSecurityScan } = require('../utils/securityScanner');

let passed = 0;
let total = 0;
function assert(cond, msg) {
  total++;
  if (cond) { console.log(`  ✓ PASS: ${msg}`); passed++; }
  else { console.error(`  ✗ FAIL: ${msg}`); }
}

const DIR = path.join(__dirname, 'temp_cfn_fixtures');

function setup() {
  if (fs.existsSync(DIR)) fs.rmSync(DIR, { recursive: true, force: true });
  fs.mkdirSync(DIR, { recursive: true });

  // JSON template: every CFN rule fires exactly once per class.
  fs.writeFileSync(path.join(DIR, 'template.json'), JSON.stringify({
    AWSTemplateFormatVersion: '2010-09-09',
    Resources: {
      PublicBucket: {
        Type: 'AWS::S3::Bucket',
        Properties: { AccessControl: 'PublicRead' }
      },
      OpenSG: {
        Type: 'AWS::EC2::SecurityGroup',
        Properties: {
          SecurityGroupIngress: [{ IpProtocol: 'tcp', FromPort: 22, ToPort: 22, CidrIp: '0.0.0.0/0' }]
        }
      },
      WildcardPolicy: {
        Type: 'AWS::IAM::Policy',
        Properties: {
          PolicyDocument: { Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] }
        }
      },
      AppDB: {
        Type: 'AWS::RDS::DBInstance',
        Properties: {
          StorageEncrypted: false,
          PubliclyAccessible: true,
          MasterUserPassword: 'HardcodedSecret123!'
        }
      },
      DataVolume: {
        Type: 'AWS::EC2::Volume',
        Properties: { Encrypted: false }
      }
    }
  }, null, 2));

  // YAML template with intrinsic tags: !Ref must parse, must NOT fire
  // CFN-005 (it is a reference, not a literal), and the public ACL must fire.
  fs.writeFileSync(path.join(DIR, 'stack.yaml'), `
AWSTemplateFormatVersion: 2010-09-09
Resources:
  RefBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Ref BucketParam
      AccessControl: PublicReadWrite
  RefDB:
    Type: AWS::RDS::DBInstance
    Properties:
      MasterUserPassword: !Ref DBPassword
      StorageEncrypted: true
      PubliclyAccessible: false
`);

  // Non-templates: must yield no findings (guard).
  fs.writeFileSync(path.join(DIR, 'plain.json'), JSON.stringify({ name: 'app', version: '1.0.0' }));
  fs.writeFileSync(path.join(DIR, 'notes.yaml'), 'title: hello\nitems:\n  - one\n');
}

function cleanup() {
  if (fs.existsSync(DIR)) fs.rmSync(DIR, { recursive: true, force: true });
}

(function run() {
  console.log('\n=== Day 5 — CloudFormation Scanner Verification ===\n');
  setup();
  try {
    console.log('[Group 1] JSON template rules');
    const jsonFindings = scanCloudFormationFile(path.join(DIR, 'template.json'), 'template.json');
    const jids = jsonFindings.map(f => f.ruleId);
    assert(jids.includes('CFN-001'), 'CFN-001 public S3 bucket');
    assert(jids.includes('CFN-002'), 'CFN-002 open security group 0.0.0.0/0');
    assert(jids.includes('CFN-003'), 'CFN-003 missing encryption (S3 + EBS + RDS flags)');
    assert(jids.includes('CFN-004'), 'CFN-004 wildcard IAM policy');
    assert(jids.includes('CFN-005'), 'CFN-005 hardcoded DB password literal');
    assert(jids.includes('CFN-006'), 'CFN-006 publicly accessible RDS');
    assert(jsonFindings.every(f => f.type === 'iac' && f.cweId && f.mlFeatures.framework === 'CloudFormation'),
      'All findings carry type iac, CWE mapping, CloudFormation framework');

    console.log('\n[Group 2] YAML template with intrinsic tags');
    const yamlFindings = scanCloudFormationFile(path.join(DIR, 'stack.yaml'), 'stack.yaml');
    const yids = yamlFindings.map(f => f.ruleId);
    assert(yids.includes('CFN-001'), 'CFN-001 fires on YAML public ACL despite !Ref present');
    assert(!yids.includes('CFN-005'), 'CFN-005 does NOT fire on !Ref password reference');
    assert(yids.includes('CFN-003'), 'CFN-003 fires on the YAML S3 bucket with no BucketEncryption');
    assert(yids.filter(id => id === 'CFN-003').length === 1, 'Exactly one CFN-003 (RDS encryption is on, so it does not fire there)');
    assert(!yids.includes('CFN-006'), 'No CFN-006 when PubliclyAccessible is false');

    console.log('\n[Group 3] Non-template guard');
    assert(scanCloudFormationFile(path.join(DIR, 'plain.json'), 'plain.json').length === 0,
      'Plain JSON yields no findings');
    assert(scanCloudFormationFile(path.join(DIR, 'notes.yaml'), 'notes.yaml').length === 0,
      'Plain YAML yields no findings');

    console.log('\n[Group 4] Unified pipeline');
    const result = runSecurityScan(DIR);
    assert(result.summaryStats.cloudFormationCount > 0,
      `Unified scan counts CloudFormation findings (found: ${result.summaryStats.cloudFormationCount})`);
    assert(result.summaryStats.iacCount >= result.summaryStats.cloudFormationCount,
      'iacCount includes CloudFormation findings');

    console.log(`\n==================================================`);
    console.log(`Verification Summary: ${passed}/${total} tests passed.`);
    console.log(`==================================================\n`);
    cleanup();
    if (passed !== total) process.exit(1);
  } catch (err) {
    cleanup();
    console.error('Fatal error during CFN verification:', err);
    process.exit(1);
  }
})();
