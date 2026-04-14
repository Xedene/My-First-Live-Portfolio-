const express = require('express');
const router = express.Router();
const {
  resolveIP,
  fetchHeaders,
  checkReachability,
  fetchSubdomains,
  checkSubdomainLiveness,
} = require('../services/curl');

// ── Security header checklist ──────────────────────────────────────
const SECURITY_HEADERS = [
  { name: 'content-security-policy', label: 'Content-Security-Policy', critical: true },
  { name: 'strict-transport-security', label: 'HSTS', critical: true },
  { name: 'x-frame-options', label: 'X-Frame-Options', critical: false },
  { name: 'x-content-type-options', label: 'X-Content-Type-Options', critical: false },
  { name: 'referrer-policy', label: 'Referrer-Policy', critical: false },
  { name: 'permissions-policy', label: 'Permissions-Policy', critical: false },
  { name: 'x-xss-protection', label: 'X-XSS-Protection', critical: false },
];

// ── Common paths to probe ──────────────────────────────────────────
const COMMON_PATHS = [
  '/admin', '/login', '/wp-admin', '/api', '/api/v1', '/api/v2',
  '/dashboard', '/console', '/panel', '/phpmyadmin', '/config',
  '/backup', '/.env', '/robots.txt', '/sitemap.xml', '/swagger',
  '/graphql', '/actuator', '/health', '/status', '/.git/config',
];

// Sanitize domain input
function sanitizeDomain(input) {
  return input
    .replace(/https?:\/\//, '')
    .replace(/\/.*$/, '')
    .trim()
    .toLowerCase();
}

// ── POST /api/recon/profile ────────────────────────────────────────
router.post('/profile', async (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'domain required' });

  const clean = sanitizeDomain(domain);
  const [ips, httpResult] = await Promise.all([
    resolveIP(clean),
    fetchHeaders(clean),
  ]);

  res.json({
    domain: clean,
    ips,
    reachable: !httpResult.error,
    responseTime: httpResult.responseTime ?? null,
    statusCode: httpResult.statusCode ?? null,
    protocol: httpResult.protocol ?? null,
    url: httpResult.url ?? null,
  });
});

// ── POST /api/recon/headers ───────────────────────────────────────
router.post('/headers', async (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'domain required' });

  const clean = sanitizeDomain(domain);
  const result = await fetchHeaders(clean);

  if (result.error) {
    return res.json({ error: result.error, domain: clean });
  }

  const headerAudit = SECURITY_HEADERS.map(h => ({
    ...h,
    present: h.name in (result.headers || {}),
    value: result.headers?.[h.name] ?? null,
  }));

  const missing = headerAudit.filter(h => !h.present);
  const present = headerAudit.filter(h => h.present);
  const server = result.headers?.['server'] || result.headers?.['x-powered-by'] || null;

  const findings = [];
  if (missing.some(h => h.critical)) {
    missing.filter(h => h.critical).forEach(h => {
      findings.push({ severity: 'high', title: `Missing ${h.label}`, detail: `Critical security header not set.` });
    });
  }
  missing.filter(h => !h.critical).forEach(h => {
    findings.push({ severity: 'medium', title: `Missing ${h.label}`, detail: `Recommended security header absent.` });
  });
  if (server) {
    findings.push({ severity: 'info', title: 'Server version exposed', detail: `Server: ${server}` });
  }

  res.json({
    domain: clean,
    url: result.url,
    statusCode: result.statusCode,
    statusMessage: result.statusMessage,
    responseTime: result.responseTime,
    server,
    headers: result.headers,
    securityAudit: { present, missing },
    findings,
    bodyPreview: result.bodyPreview,
  });
});

// ── POST /api/recon/subdomains ────────────────────────────────────
router.post('/subdomains', async (req, res) => {
  const { domain, checkLiveness } = req.body;
  if (!domain) return res.status(400).json({ error: 'domain required' });

  const clean = sanitizeDomain(domain);
  const subs = await fetchSubdomains(clean);

  let results = subs.map(s => ({ subdomain: s, alive: null }));
  if (checkLiveness && subs.length > 0) {
    results = await checkSubdomainLiveness(subs);
  }

  res.json({ domain: clean, total: subs.length, subdomains: results });
});

// ── POST /api/recon/endpoints ─────────────────────────────────────
router.post('/endpoints', async (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'domain required' });

  const clean = sanitizeDomain(domain);
  const base = `https://${clean}`;

  const checks = await Promise.all(
    COMMON_PATHS.map(async (path) => {
      const result = await fetchHeaders(`${base}${path}`, 'GET', 5000);
      return {
        path,
        url: `${base}${path}`,
        statusCode: result.statusCode ?? null,
        error: result.error ?? null,
        interesting: [200, 301, 302, 401, 403].includes(result.statusCode),
      };
    })
  );

  const interesting = checks.filter(c => c.interesting);
  const findings = interesting
    .filter(c => c.statusCode === 200)
    .map(c => ({
      severity: c.path.includes('admin') || c.path.includes('console') || c.path.includes('panel') ? 'high' : 'info',
      title: `Accessible: ${c.path}`,
      detail: `Returns HTTP ${c.statusCode}`,
    }));

  res.json({ domain: clean, paths: checks, interesting, findings });
});

// ── POST /api/recon/full ──────────────────────────────────────────
// Calls services directly — no localhost fetch (required for Vercel serverless)
router.post('/full', async (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'domain required' });

  const clean = sanitizeDomain(domain);

  const [ips, httpResult] = await Promise.all([
    resolveIP(clean),
    fetchHeaders(clean),
  ]);

  const profile = {
    domain: clean,
    ips,
    reachable: !httpResult.error,
    responseTime: httpResult.responseTime ?? null,
    statusCode: httpResult.statusCode ?? null,
    protocol: httpResult.protocol ?? null,
    url: httpResult.url ?? null,
  };

  let headersData = { error: httpResult.error, domain: clean };
  if (!httpResult.error) {
    const headerAudit = SECURITY_HEADERS.map(h => ({
      ...h,
      present: h.name in (httpResult.headers || {}),
      value: httpResult.headers?.[h.name] ?? null,
    }));
    const missing = headerAudit.filter(h => !h.present);
    const present = headerAudit.filter(h => h.present);
    const server = httpResult.headers?.['server'] || httpResult.headers?.['x-powered-by'] || null;
    const findings = [];
    missing.filter(h => h.critical).forEach(h =>
      findings.push({ severity: 'high', title: `Missing ${h.label}`, detail: 'Critical security header not set.' })
    );
    missing.filter(h => !h.critical).forEach(h =>
      findings.push({ severity: 'medium', title: `Missing ${h.label}`, detail: 'Recommended security header absent.' })
    );
    if (server) findings.push({ severity: 'info', title: 'Server version exposed', detail: `Server: ${server}` });

    headersData = {
      domain: clean,
      url: httpResult.url,
      statusCode: httpResult.statusCode,
      statusMessage: httpResult.statusMessage,
      responseTime: httpResult.responseTime,
      server,
      headers: httpResult.headers,
      securityAudit: { present, missing },
      findings,
      bodyPreview: httpResult.bodyPreview,
    };
  }

  res.json({ domain: clean, profile, headers: headersData });
});

module.exports = router;
