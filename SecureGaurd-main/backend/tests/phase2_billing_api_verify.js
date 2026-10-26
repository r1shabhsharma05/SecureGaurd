const assert = require('assert');
const prisma = require('../prismaClient');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const http = require('http');

const JWT_SECRET = process.env.JWT_SECRET || 'secureguard_super_secret_jwt_key_2026';

function generateToken(userId, email) {
  return jwt.sign({ id: userId, email }, JWT_SECRET, { expiresIn: '1h' });
}

function makeRequest(options, postData) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const parsed = data ? JSON.parse(data) : {};
          resolve({ status: res.statusCode, headers: res.headers, body: parsed });
        } catch (e) {
          resolve({ status: res.statusCode, headers: res.headers, rawBody: data });
        }
      });
    });
    req.on('error', reject);
    if (postData) {
      req.write(typeof postData === 'string' ? postData : JSON.stringify(postData));
    }
    req.end();
  });
}

async function runBillingApiVerificationSuite() {
  console.log('\n================================================================');
  console.log(' SECUREGUARD PHASE 2: BILLING API & RBAC ENDPOINT VERIFY ');
  console.log('================================================================\n');

  let passed = 0;
  let failed = 0;

  async function test(name, fn) {
    try {
      await fn();
      console.log(`  ✓ ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ✕ ${name}`);
      console.error(`     Error: ${err.message}`);
      failed++;
    }
  }

  let owner, admin, dev, orgA, orgB;
  const timestamp = Date.now();

  try {
    const passwordHash = await bcrypt.hash('ApiPass123!', 10);

    owner = await prisma.user.create({
      data: { firstName: 'ApiOwner', lastName: 'Test', email: `api_owner_${timestamp}@test.com`, password: passwordHash }
    });
    admin = await prisma.user.create({
      data: { firstName: 'ApiAdmin', lastName: 'Test', email: `api_admin_${timestamp}@test.com`, password: passwordHash }
    });
    dev = await prisma.user.create({
      data: { firstName: 'ApiDev', lastName: 'Test', email: `api_dev_${timestamp}@test.com`, password: passwordHash }
    });

    orgA = await prisma.organization.create({
      data: {
        name: `Api Org A ${timestamp}`,
        slug: `api-org-a-${timestamp}`,
        memberships: {
          create: [
            { userId: owner.id, role: 'OWNER' },
            { userId: admin.id, role: 'ADMIN' },
            { userId: dev.id, role: 'DEVELOPER' }
          ]
        }
      }
    });

    orgB = await prisma.organization.create({
      data: {
        name: `Api Org B ${timestamp}`,
        slug: `api-org-b-${timestamp}`,
        memberships: { create: [{ userId: dev.id, role: 'OWNER' }] }
      }
    });

    const ownerToken = generateToken(owner.id, owner.email);
    const adminToken = generateToken(admin.id, admin.email);
    const devToken = generateToken(dev.id, dev.email);

    await test('GET /api/billing/usage — OWNER retrieves org usage (200)', async () => {
      const res = await makeRequest({
        hostname: '127.0.0.1',
        port: 5000,
        path: '/api/billing/usage',
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${ownerToken}`,
          'x-organization-id': String(orgA.id)
        }
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.plan, 'FREE');
      assert.notStrictEqual(res.body.usage, undefined);
    });

    await test('GET /api/billing/usage — ADMIN retrieves org usage (200)', async () => {
      const res = await makeRequest({
        hostname: '127.0.0.1',
        port: 5000,
        path: '/api/billing/usage',
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${adminToken}`,
          'x-organization-id': String(orgA.id)
        }
      });
      assert.strictEqual(res.status, 200);
    });

    await test('POST /api/billing/create-subscription — OWNER initiates upgrade (200 with keys, 503 fail-closed without)', async () => {
      const res = await makeRequest({
        hostname: '127.0.0.1',
        port: 5000,
        path: '/api/billing/create-subscription',
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${ownerToken}`,
          'x-organization-id': String(orgA.id),
          'Content-Type': 'application/json'
        }
      }, { plan: 'PRO' });
      // Razorpay keys/plan IDs may or may not be configured in the test env:
      // 200 + auth URL when configured, honest 503 when not. Anything else
      // (notably a 200 without a URL, or a 500) is a failure.
      assert.ok(res.status === 200 || res.status === 503, `unexpected status ${res.status}`);
      if (res.status === 200) {
        assert.notStrictEqual(res.body.url, undefined);
        assert.notStrictEqual(res.body.subscriptionId, undefined);
      } else {
        assert.match(res.body.message || '', /not configured/i);
      }
    });

    await test('POST /api/billing/create-subscription — ADMIN attempt returns 403 Forbidden', async () => {
      const res = await makeRequest({
        hostname: '127.0.0.1',
        port: 5000,
        path: '/api/billing/create-subscription',
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${adminToken}`,
          'x-organization-id': String(orgA.id),
          'Content-Type': 'application/json'
        }
      }, { plan: 'PRO' });
      assert.strictEqual(res.status, 403);
    });

    await test('POST /api/billing/create-subscription — DEVELOPER attempt returns 403 Forbidden', async () => {
      const res = await makeRequest({
        hostname: '127.0.0.1',
        port: 5000,
        path: '/api/billing/create-subscription',
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${devToken}`,
          'x-organization-id': String(orgA.id),
          'Content-Type': 'application/json'
        }
      }, { plan: 'PRO' });
      assert.strictEqual(res.status, 403);
    });

    await test('Removed Stripe endpoints return 404 (portal + checkout gone)', async () => {
      for (const path of ['/api/billing/create-portal-session', '/api/billing/create-checkout-session']) {
        const res = await makeRequest({
          hostname: '127.0.0.1',
          port: 5000,
          path,
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${ownerToken}`,
            'x-organization-id': String(orgA.id),
            'Content-Type': 'application/json'
          }
        }, { plan: 'PRO' });
        assert.strictEqual(res.status, 404, `${path} should be gone`);
      }
    });

    await test('IDOR Protection — User requesting unauthorized Org B billing returns 403', async () => {
      const res = await makeRequest({
        hostname: '127.0.0.1',
        port: 5000,
        path: '/api/billing/usage',
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${ownerToken}`, // owner is NOT a member of Org B
          'x-organization-id': String(orgB.id)
        }
      });
      assert.strictEqual(res.status, 403);
    });

    // Cleanup
    await prisma.organization.deleteMany({ where: { id: { in: [orgA.id, orgB.id] } } });
    await prisma.user.deleteMany({ where: { id: { in: [owner.id, admin.id, dev.id] } } });

  } catch (err) {
    console.error('API Verification Setup Error:', err);
    failed++;
  }

  console.log('\n================================================================');
  console.log(` RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log('================================================================\n');

  if (failed > 0) process.exit(1);
}

runBillingApiVerificationSuite();
