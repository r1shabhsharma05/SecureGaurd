'use strict';

// JWT-or-API-key auth for the read surface (vulns, scans, SBOMs).
// A request carrying X-Api-Key never falls through to JWT: the key is
// looked up by sha256 hash, and the scopes decide what it may do — GETs
// need 'read', POST /api/scans/trigger needs 'scan:trigger' (scans router
// only, via allowTrigger). Every other method/path with a key is a 403,
// so keys can never write findings, change settings, or manage orgs.
// req.userId is the key creator's id, so requireOrgContext still verifies
// a live membership and req.apiKeyOrgId pins the key's org (never the
// creator's default org).
const prisma = require('../prismaClient');
const authMiddleware = require('./auth');
const { hashApiKey } = require('../utils/apiKeys');

function authenticateRequest({ allowTrigger = false } = {}) {
  return async (req, res, next) => {
    const presented = req.headers['x-api-key'];
    if (!presented || typeof presented !== 'string') return authMiddleware(req, res, next);
    try {
      const record = await prisma.apiKey.findUnique({ where: { keyHash: hashApiKey(presented) } });
      if (!record || record.revokedAt || (record.expiresAt && record.expiresAt <= new Date())) {
        return res.status(401).json({ message: 'Invalid or expired API key' });
      }
      const isTrigger = allowTrigger && req.method === 'POST' && req.path === '/trigger';
      const needed = isTrigger ? 'scan:trigger' : req.method === 'GET' ? 'read' : null;
      if (!needed || !record.scopes.includes(needed)) {
        return res.status(403).json({ message: 'API key lacks the required scope' });
      }
      req.userId = record.userId;
      req.apiKeyOrgId = record.organizationId;
      req.apiKey = { id: record.id, scopes: record.scopes };
      // Last-used touch must never fail the request it measures.
      prisma.apiKey.update({ where: { id: record.id }, data: { lastUsedAt: new Date() } }).catch(() => {});
      return next();
    } catch {
      return res.status(401).json({ message: 'Invalid API key' });
    }
  };
}

module.exports = { authenticateRequest };
