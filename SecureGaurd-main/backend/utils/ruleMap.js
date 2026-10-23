// Shared scanner-rule → classifier-vocabulary mapping.
// The FP classifier was trained on these rule names (see
// backend/services/fp-classifier), while the scanner emits SAST-*/SEC-* IDs.
// Every code path that builds mlFeatures must map through here, otherwise
// webhook-created findings speak a vocabulary the classifier never saw.
const RULE_MAP = {
  'SAST-001': 'sqli-concat',
  'SAST-002': 'xss-unescaped',
  'SAST-003': 'path-traversal',
  'SAST-004': 'hardcoded-secret',
  'SAST-005': 'insecure-deserialize',
  'SEC-001': 'hardcoded-secret',
  'SEC-002': 'hardcoded-secret',
  'SEC-003': 'hardcoded-secret',
};

function mapRuleId(ruleId) {
  return RULE_MAP[ruleId] || ruleId;
}

module.exports = { RULE_MAP, mapRuleId };
