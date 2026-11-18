'use strict';

// API key management (19 Nov 2026). Keys are org-scoped, OWNER/ADMIN only.
// The full key is returned exactly once, in the create response — list and
// revoke responses never carry it (only the hash is stored).
const express = require('express');
const router = express.Router();
const prisma = require('../prismaClient');
const authMiddleware = require('../middleware/auth');
const { requireOrgContext, requireOrgRole, createAuditLog } = require('../middleware/rbac');
const { withRequestOrgContext } = require('../utils/rlsContext');
const { API_KEY_SCOPES, generateApiKey } = require('../utils/apiKeys');

router.use(authMiddleware);
router.use(requireOrgContext);

const KEY_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 _-]{0,49}$/;

// Fields safe to return: never keyHash, never the key itself.
const PUBLIC_FIELDS = {
  id: true, name: true, keyPrefix: true, scopes: true,
  lastUsedAt: true, expiresAt: true, revokedAt: true, createdAt: true,
};

// POST /api/api-keys — create a key, returned once with the secret.
router.post('/', requireOrgRole(['OWNER', 'ADMIN']), async (req, res) => {
  const { name, scopes, expiresAt } = req.body || {};
  if (typeof name !== 'string' || !KEY_NAME_RE.test(name.trim())) {
    return res.status(400).json({ message: 'Name must be 1-50 characters (letters, digits, space, _ or -).' });
  }
  const cleanScopes = [...new Set(Array.isArray(scopes) ? scopes : [])]
    .filter((s) => API_KEY_SCOPES.includes(s));
  if (cleanScopes.length === 0) {
    return res.status(400).json({ message: `Scopes must include at least one of: ${API_KEY_SCOPES.join(', ')}.` });
  }
  let expiry = null;
  if (expiresAt !== undefined && expiresAt !== null && expiresAt !== '') {
    expiry = new Date(expiresAt);
    if (Number.isNaN(expiry.getTime()) || expiry <= new Date()) {
      return res.status(400).json({ message: 'expiresAt must be a future date.' });
    }
  }
  const { key, keyPrefix, keyHash } = generateApiKey();
  try {
    const row = await withRequestOrgContext(req, (tx) => tx.apiKey.create({
      data: {
        organizationId: req.organizationId,
        userId: req.userId,
        name: name.trim(),
        keyPrefix,
        keyHash,
        scopes: cleanScopes,
        expiresAt: expiry,
      },
      select: PUBLIC_FIELDS,
    }));
    await createAuditLog(req.organizationId, req.userId, 'API_KEY_CREATED', 'ApiKey', row.id, { name: row.name, scopes: cleanScopes });
    return res.status(201).json({ ...row, key });
  } catch (err) {
    console.error('Error creating API key:', err);
    return res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/api-keys — list keys (revoked included, flagged by revokedAt).
router.get('/', requireOrgRole(['OWNER', 'ADMIN']), async (req, res) => {
  try {
    const rows = await withRequestOrgContext(req, (tx) => tx.apiKey.findMany({
      where: { organizationId: req.organizationId },
      select: PUBLIC_FIELDS,
      orderBy: { createdAt: 'desc' },
    }));
    return res.json(rows);
  } catch (err) {
    console.error('Error listing API keys:', err);
    return res.status(500).json({ message: 'Server error' });
  }
});

// DELETE /api/api-keys/:id — revoke (soft: revokedAt, kept for audit).
router.delete('/:id', requireOrgRole(['OWNER', 'ADMIN']), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (Number.isNaN(id)) return res.status(400).json({ message: 'Invalid key id.' });
  try {
    // update() needs a unique where; check org ownership first, then
    // revoke by id (a key from another org 404s instead of leaking).
    const existing = await withRequestOrgContext(req, (tx) => tx.apiKey.findFirst({
      where: { id, organizationId: req.organizationId },
      select: { id: true },
    }));
    if (!existing) return res.status(404).json({ message: 'API key not found.' });
    const row = await withRequestOrgContext(req, (tx) => tx.apiKey.update({
      where: { id },
      data: { revokedAt: new Date() },
      select: PUBLIC_FIELDS,
    }));
    await createAuditLog(req.organizationId, req.userId, 'API_KEY_REVOKED', 'ApiKey', row.id, { name: row.name });
    return res.json(row);
  } catch (err) {
    console.error('Error revoking API key:', err);
    return res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
