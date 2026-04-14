const https = require('https');
const http = require('http');
const dns = require('dns').promises;
const { URL } = require('url');

/**
 * Resolve a domain to its IP address(es)
 */
async function resolveIP(domain) {
  try {
    const result = await dns.lookup(domain, { all: true });
    return result.map(r => r.address);
  } catch (e) {
    return [];
  }
}

/**
 * Perform an HTTP/HTTPS HEAD/GET request and return timing + headers
 */
function fetchHeaders(targetUrl, method = 'GET', timeoutMs = 8000) {
  return new Promise((resolve) => {
    const start = Date.now();
    let parsed;
    try {
      parsed = new URL(targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`);
    } catch {
      return resolve({ error: 'Invalid URL' });
    }

    const lib = parsed.protocol === 'https:' ? https : http;
    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; xedene-recon/1.0)',
        'Accept': '*/*',
      },
      timeout: timeoutMs,
      rejectUnauthorized: false,
    };

    const req = lib.request(options, (res) => {
      const elapsed = Date.now() - start;
      let body = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { if (body.length < 4096) body += chunk; });
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          statusMessage: res.statusMessage,
          headers: res.headers,
          responseTime: elapsed,
          bodyPreview: body.slice(0, 2048),
          url: parsed.href,
          protocol: parsed.protocol,
        });
      });
    });

    req.on('timeout', () => { req.destroy(); resolve({ error: 'Request timed out' }); });
    req.on('error', (e) => resolve({ error: e.message }));
    req.end();
  });
}

/**
 * Check if a host is reachable (TCP ping via HTTP)
 */
async function checkReachability(domain) {
  const result = await fetchHeaders(`https://${domain}`, 'HEAD', 5000);
  if (result.error) {
    const fallback = await fetchHeaders(`http://${domain}`, 'HEAD', 5000);
    return !fallback.error;
  }
  return true;
}

/**
 * Fetch subdomains from crt.sh (certificate transparency)
 */
async function fetchSubdomains(domain) {
  return new Promise((resolve) => {
    const url = `https://crt.sh/?q=%25.${domain}&output=json`;
    const parsed = new URL(url);
    const options = {
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      method: 'GET',
      headers: { 'User-Agent': 'xedene-recon/1.0', 'Accept': 'application/json' },
      timeout: 10000,
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          const records = JSON.parse(data);
          const names = [...new Set(
            records
              .map(r => r.name_value)
              .join('\n')
              .split('\n')
              .map(s => s.trim().replace(/^\*\./, ''))
              .filter(s => s.endsWith(domain) && s !== domain && !s.includes('*'))
          )].sort();
          resolve(names);
        } catch {
          resolve([]);
        }
      });
    });

    req.on('timeout', () => { req.destroy(); resolve([]); });
    req.on('error', () => resolve([]));
    req.end();
  });
}

/**
 * Check liveness of a list of subdomains (concurrent, capped)
 */
async function checkSubdomainLiveness(subdomains, limit = 15) {
  const results = [];
  const queue = subdomains.slice(0, 30);

  const chunks = [];
  for (let i = 0; i < queue.length; i += limit) {
    chunks.push(queue.slice(i, i + limit));
  }

  for (const chunk of chunks) {
    const batch = await Promise.all(
      chunk.map(async (sub) => {
        const alive = await checkReachability(sub);
        return { subdomain: sub, alive };
      })
    );
    results.push(...batch);
  }

  return results;
}

module.exports = { resolveIP, fetchHeaders, checkReachability, fetchSubdomains, checkSubdomainLiveness };
