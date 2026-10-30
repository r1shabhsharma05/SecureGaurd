const express = require('express');
const router = express.Router();
const prisma = require('../prismaClient');
const authMiddleware = require('../middleware/auth');
const { requireOrgContext, requireOrgRole, createAuditLog } = require('../middleware/rbac');
const { runSecurityScan } = require('../utils/securityScanner');
const { mapRuleId } = require('../utils/ruleMap');
const { resolveScanTarget } = require('../utils/repoScanSource');
const crypto = require('crypto');
const { encrypt, decrypt } = require('../utils/cryptoUtils');
const rateLimit = require('express-rate-limit');

const webhookLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 30,
  message: { message: 'Too many webhook requests' },
});

// Helper: Verify GitHub/GitLab Webhook Signatures.
// Fails CLOSED: without a configured secret nothing is trusted, and GitHub's
// HMAC is computed over the exact raw request bytes (captured by the
// express.json verify hook in server.js) — never over re-serialized JSON,
// whose key order/whitespace need not match what GitHub signed.
function safeEqual(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function verifyWebhookSignature(platform, req) {
  const secret = process.env.WEBHOOK_SECRET;
  if (!secret) return false;

  if (platform === 'github') {
    const signature = req.headers['x-hub-signature-256'];
    if (!signature || !Buffer.isBuffer(req.rawBody)) return false;
    const digest = 'sha256=' + crypto.createHmac('sha256', secret).update(req.rawBody).digest('hex');
    return safeEqual(signature, digest);
  } else if (platform === 'gitlab') {
    const token = req.headers['x-gitlab-token'];
    if (!token) return false;
    return safeEqual(token, secret);
  }
  return false;
}

// Webhook endpoint does NOT require auth header since it's called by Github/Gitlab
router.post('/webhook/:platform', webhookLimiter, async (req, res) => {
  const { platform } = req.params;
  const payload = req.body;
  
  if (!verifyWebhookSignature(platform, req)) {
    return res.status(401).json({ message: 'Invalid webhook signature or secret token' });
  }

  console.log(`[Webhook Received] Platform: ${platform}`);

  let scanTarget = null;
  try {
    let repoFullName = '';
    let commitSha = '';
    let branch = 'main';

    if (platform === 'github') {
      repoFullName = payload.repository?.full_name || '';
      commitSha = payload.head_commit?.id || payload.after || '';
      branch = payload.ref ? payload.ref.replace('refs/heads/', '') : 'main';
    } else if (platform === 'gitlab') {
      repoFullName = payload.project?.path_with_namespace || '';
      commitSha = payload.checkout_sha || '';
      branch = payload.ref ? payload.ref.replace('refs/heads/', '') : 'main';
    }

    if (!repoFullName) {
      return res.status(400).json({ message: 'Could not extract repository full name from payload' });
    }

    // Find the repository in database
    const repo = await prisma.repository.findFirst({
      where: { fullName: repoFullName, platform },
    });

    if (!repo) {
      return res.status(404).json({ message: `Repository ${repoFullName} is not registered in SecureGuard` });
    }

    // Scan the pushed repository's own tree (clone of the registered repo),
    // never SecureGaurd's own checkout. No reachable source → honest failure.
    try {
      scanTarget = resolveScanTarget(repo, { branch });
    } catch (resolveErr) {
      await prisma.scan.create({
        data: {
          userId: repo.userId,
          organizationId: repo.organizationId,
          repositoryId: repo.id,
          status: 'failed',
          branch,
          commitSha: commitSha || 'push-event',
          completedAt: new Date(),
        },
      });
      return res.status(502).json({ message: `Scan failed: ${resolveErr.message}` });
    }
    const scanResult = runSecurityScan(scanTarget.scanPath);

    // Append ML Features
    for (let finding of scanResult.findings) {
      if (finding.mlFeatures) {
        const seenCount = await prisma.vulnerability.count({
          where: {
            ruleId: finding.ruleId,
            filePath: finding.filePath,
            scan: { repositoryId: repo.id }
          }
        });
        finding.mlFeatures.same_finding_seen_before_count = seenCount;

        const dismissedCount = await prisma.vulnerability.count({
          where: {
            ruleId: finding.ruleId,
            status: 'ignored',
            scan: { repositoryId: repo.id }
          }
        });
        // Classifier schema field is 0/1 — boolean, not the raw count.
        finding.mlFeatures.developer_dismissed_similar_before = dismissedCount > 0 ? 1 : 0;
        finding.mlFeatures.file_change_frequency = 0;

        finding.mlFeatures.rule_id = mapRuleId(finding.ruleId);
        finding.mlFeatures.cwe_id = finding.cweId;
      }
    }

    let finalFindings = scanResult.findings;
    const sastFindings = scanResult.findings.filter(f => f.mlFeatures);
    
    if (sastFindings.length > 0) {
      try {
        const payload = { findings: sastFindings.map(f => f.mlFeatures) };
        const CLASSIFIER_URL = process.env.FP_CLASSIFIER_URL || "http://localhost:8001";
        
        const response = await fetch(`${CLASSIFIER_URL}/classify/batch`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });

        if (response.ok) {
          const { results } = await response.json();
          const realSastFindings = sastFindings.filter((f, idx) => {
            // Never suppress IaC/API findings via the SAST-only classifier.
            if (f.mlFeatures.isIaC || f.mlFeatures.isApi) return true;
            const pred = results[idx]?.prediction;
            return pred === 'REAL' || !pred;
          });
          
          finalFindings = [
            ...scanResult.findings.filter(f => !f.mlFeatures),
            ...realSastFindings
          ];
        }
      } catch (err) {
        console.warn(`[ML Service Error] Error: ${err.message}`);
      }
    }

    const critCount = finalFindings.filter(f => f.severity === 'critical').length;
    const highCount = finalFindings.filter(f => f.severity === 'high').length;
    const medCount  = finalFindings.filter(f => f.severity === 'medium').length;
    const lowCount  = finalFindings.filter(f => f.severity === 'low').length;
    const secrets   = finalFindings.filter(f => f.type === 'secret').length;

    // Create scan with repository's organizationId
    const scan = await prisma.scan.create({
      data: {
        userId: repo.userId,
        organizationId: repo.organizationId,
        repositoryId: repo.id,
        status: 'completed',
        branch,
        commitSha: commitSha || 'push-event',
        totalFiles: scanResult.totalFiles,
        totalLines: scanResult.totalLines,
        criticalCount: critCount,
        highCount: highCount,
        mediumCount: medCount,
        lowCount: lowCount,
        secretsFound: secrets,
        durationMs: scanResult.durationMs,
        completedAt: new Date(),
      },
    });

    if (finalFindings.length > 0) {
      const dbFindings = finalFindings.map(f => ({
        scanId: scan.id,
        ruleId: f.ruleId,
        cweId: f.cweId,
        type: f.type,
        severity: f.severity,
        title: f.title,
        filePath: f.filePath,
        lineStart: f.lineStart,
        lineEnd: f.lineEnd,
        codeSnippet: f.codeSnippet,
        status: 'open'
      }));
      await prisma.vulnerability.createMany({ data: dbFindings });
    }

    const riskLevel = critCount > 0 ? 'critical' : highCount > 2 ? 'high' : medCount > 3 ? 'medium' : 'low';
    await prisma.repository.update({
      where: { id: repo.id },
      data: { riskLevel, updatedAt: new Date() },
    });

    if (repo.organizationId) {
      await createAuditLog(
        repo.organizationId,
        repo.userId,
        'WEBHOOK_SCAN_COMPLETED',
        'SCAN',
        String(scan.id),
        { repoName: repo.fullName, platform, commitSha }
      );
      // Day 7 — same opt-in alerts as the manual scan path (best-effort).
      try {
        const { dispatchScanAlerts } = require('../utils/scanAlerts');
        await dispatchScanAlerts({ organizationId: repo.organizationId, scan, repository: repo });
      } catch (alertErr) {
        console.error('Webhook scan alert dispatch failed (scan itself succeeded):', alertErr.message);
      }
    }

    if (scanTarget) scanTarget.cleanup();
    return res.status(200).json({
      message: 'Webhook processed, scan successfully completed',
      scanId: scan.id,
      issuesFound: scanResult.findings.length
    });
  } catch (err) {
    if (scanTarget) scanTarget.cleanup();
    console.error('[Webhook Error]', err);
    return res.status(500).json({ message: 'Internal Server Error' });
  }
});

// Protect all authenticated integration endpoints below
router.use(authMiddleware);

// GET /api/integration/tokens
router.get('/tokens', async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.userId },
      select: { githubToken: true, gitlabToken: true }
    });
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({
      hasGithub: !!user.githubToken,
      hasGitlab: !!user.gitlabToken
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/integration/tokens
router.post('/tokens', async (req, res) => {
  const { githubToken, gitlabToken } = req.body;
  try {
    const tokenUpdates = {};
    if (githubToken !== undefined) tokenUpdates.githubToken = encrypt(githubToken);
    if (gitlabToken !== undefined) tokenUpdates.gitlabToken = encrypt(gitlabToken);

    await prisma.user.update({
      where: { id: req.userId },
      data: tokenUpdates
    });
    res.json({ message: 'Integration tokens successfully updated' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/integration/repos
router.get('/repos', async (req, res) => {
  const { platform } = req.query;
  if (!platform || (platform !== 'github' && platform !== 'gitlab')) {
    return res.status(400).json({ message: 'Platform must be github or gitlab' });
  }

  try {
    const user = await prisma.user.findUnique({
      where: { id: req.userId },
      select: { githubToken: true, gitlabToken: true }
    });

    if (!user) return res.status(404).json({ message: 'User not found' });

    const rawToken = platform === 'github' ? user.githubToken : user.gitlabToken;
    const token = decrypt(rawToken);
    if (!token) {
      return res.status(200).json([]);
    }

    if (platform === 'github') {
      const response = await fetch('https://api.github.com/user/repos?per_page=50&sort=updated', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': 'SecureGuard-App'
        }
      });
      if (!response.ok) {
        return res.status(response.status).json({ message: 'Failed fetching repositories from GitHub API' });
      }
      const githubRepos = await response.json();
      const repos = githubRepos.map(r => ({
        name: r.name,
        fullName: r.full_name,
        url: r.html_url,
        platform: 'github',
        language: r.language || 'JavaScript'
      }));
      return res.json(repos);
    } else {
      const response = await fetch('https://gitlab.com/api/v4/projects?owned=true&per_page=50', {
        headers: {
          'PRIVATE-TOKEN': token
        }
      });
      if (!response.ok) {
        return res.status(response.status).json({ message: 'Failed fetching repositories from GitLab API' });
      }
      const gitlabRepos = await response.json();
      const repos = gitlabRepos.map(r => ({
        name: r.name,
        fullName: r.path_with_namespace,
        url: r.web_url,
        platform: 'gitlab',
        language: 'JavaScript'
      }));
      return res.json(repos);
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/integration/pr-bot: REAL PR bot (Day 7 — replaces the old
// simulation, which returned prNumber || 42 and a localhost report URL).
// With the user's connected GitHub PAT (stored encrypted, same helper as
// the repo-import tokens), this posts a real check run on the commit AND
// a real summary comment on the PR via the GitHub REST API, and returns
// only the ids/URLs GitHub itself returns. No PAT => honest 400. GitHub
// rejecting the call => its status surfaced, never a fabricated success.
// A repo with no scan yet posts a check noting that honestly instead of
// claiming a clean bill of health.
// Write operation: OWNER/ADMIN/DEVELOPER only (Auditor is read-only).
router.post('/pr-bot', requireOrgContext, requireOrgRole(['OWNER', 'ADMIN', 'DEVELOPER']), async (req, res) => {
  const { repositoryId, commitSha, prNumber } = req.body;
  if (!repositoryId || !commitSha || !prNumber) {
    return res.status(400).json({ message: 'repositoryId, commitSha and prNumber are required' });
  }

  try {
    const { parseRepoFullName, buildCheckRunPayload, buildPrCommentBody } = require('../utils/prBot');
    const repo = await prisma.repository.findFirst({
      where: { id: parseInt(repositoryId), organizationId: req.organizationId },
    });
    if (!repo) return res.status(404).json({ message: 'Repository not found in active organization' });
    if (repo.platform !== 'github') {
      return res.status(400).json({ message: 'PR bot currently supports GitHub repositories only' });
    }
    const parsed = parseRepoFullName(repo.fullName);
    if (!parsed) return res.status(400).json({ message: 'Repository fullName is not in owner/repo form' });

    const user = await prisma.user.findUnique({ where: { id: req.userId }, select: { githubToken: true } });
    const pat = decrypt(user ? user.githubToken : null);
    if (!pat) {
      return res.status(400).json({ message: 'No GitHub token connected — connect a PAT in onboarding or settings first' });
    }

    const scan = await prisma.scan.findFirst({
      where: { repositoryId: repo.id, organizationId: req.organizationId },
      orderBy: { createdAt: 'desc' },
    });
    const criticalCount = scan ? scan.criticalCount : 0;
    const highCount = scan ? scan.highCount : 0;
    const mediumCount = scan ? scan.mediumCount : 0;
    const lowCount = scan ? scan.lowCount : 0;
    const isClean = Boolean(scan) && (criticalCount + highCount === 0);
    const reportUrl = `${process.env.FRONTEND_URL || ''}/dashboard`.replace(/\/$/, '') || null;

    const ghHeaders = {
      'Authorization': `Bearer ${pat}`,
      'Accept': 'application/vnd.github+json',
      'User-Agent': 'SecureGuard-App',
      'Content-Type': 'application/json',
    };
    const checkPayload = buildCheckRunPayload({ commitSha, isClean, criticalCount, highCount, reportUrl });
    if (!scan) {
      checkPayload.output.title = 'SecureGuard: no scan yet for this repository';
      checkPayload.output.summary = 'No SecureGuard scan exists for this repository yet — run a scan first for a real verdict.';
      checkPayload.conclusion = 'neutral';
    }
    const checkRes = await fetch(`https://api.github.com/repos/${parsed.owner}/${parsed.repo}/check-runs`, {
      method: 'POST', headers: ghHeaders, body: JSON.stringify(checkPayload),
    });
    if (!checkRes.ok) {
      const body = (await checkRes.text()).slice(0, 300);
      return res.status(502).json({ message: `GitHub rejected the check run (${checkRes.status})`, githubError: body });
    }
    const checkRun = await checkRes.json();

    const commentBody = buildPrCommentBody({
      repoFullName: repo.fullName, commitSha, isClean,
      criticalCount, highCount, mediumCount, lowCount, reportUrl,
    });
    const commentRes = await fetch(`https://api.github.com/repos/${parsed.owner}/${parsed.repo}/issues/${prNumber}/comments`, {
      method: 'POST', headers: ghHeaders, body: JSON.stringify({ body: scan ? commentBody : `${commentBody}\n\n_Note: no SecureGuard scan exists for this repository yet — run a scan first for a real verdict._` }),
    });
    if (!commentRes.ok) {
      const body = (await commentRes.text()).slice(0, 300);
      // The check run is real and already posted; report the partial
      // outcome honestly instead of claiming full success or hiding it.
      return res.status(502).json({
        message: `Check run posted, but GitHub rejected the PR comment (${commentRes.status})`,
        githubError: body,
        checkRun: { id: checkRun.id, html_url: checkRun.html_url, conclusion: checkRun.conclusion },
      });
    }
    const comment = await commentRes.json();

    await createAuditLog(
      req.organizationId, req.userId, 'PR_BOT_POSTED', 'REPOSITORY', String(repo.id),
      { prNumber, commitSha, checkRunId: checkRun.id, commentId: comment.id, conclusion: checkRun.conclusion }
    );

    res.json({
      message: 'PR Bot check posted to GitHub',
      botReport: {
        repository: repo.fullName,
        commit: commitSha,
        prNumber,
        scanId: scan ? scan.id : null,
        checkRun: { id: checkRun.id, html_url: checkRun.html_url, conclusion: checkRun.conclusion },
        comment: { id: comment.id, html_url: comment.html_url },
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
