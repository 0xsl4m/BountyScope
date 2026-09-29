// BountyScope — background analyzer: fetches in-scope JS/source maps through the
// privileged context (D7 fix: content scripts were blocked by page CORS) and runs
// secret/endpoint/subdomain extraction over them.
import * as store from './store.js';
import * as scope from './scope.js';
import { classifyEndpoint } from '../lib/classify.js';
import { scanSecrets } from '../lib/secrets.js';

const MAX_TEXT = 2_000_000;
const MAX_SCRIPTS_PER_SCAN = 25;

const EP_RES = [
  /['"`](\/(?:api|v\d+|rest|graphql|gql|admin|auth|oauth|sso|socket|ws|webhook|service|internal|debug|actuator|swagger|openapi|api-docs|rpc|upload|export)[^\s'"`<>{}|\\^`\[\]]{0,200})['"`]/g,
  /(?:endpoint|apiUrl|API_URL|baseUrl|BASE_URL|apiBase|API_BASE|serverUrl|SERVER_URL)\s*[=:]\s*['"`]([^'"`\s]{5,200})['"`]/g,
  /fetch\s*\(\s*['"`]([^'"`\s]{5,200})['"`]/g,
  /axios\s*\.\s*\w+\s*\(\s*['"`]([^'"`\s]{5,200})['"`]/g,
  /\.open\s*\(\s*['"`][A-Z]+['"`]\s*,\s*['"`]([^'"`\s]{5,200})['"`]/g,
  /['"`](https?:\/\/[^\s'"`<>{}|\\^`\[\]]{8,200})['"`]/g,
];

export async function fetchText(url, tabId) {
  if (tabId != null && !(await scope.isInScope(url, tabId))) {
    return { ok: false, error: 'out of scope' };
  }
  try {
    const resp = await fetch(url, { cache: 'force-cache' });
    const text = await resp.text();
    return {
      ok: resp.ok,
      status: resp.status,
      contentType: resp.headers.get('content-type') || '',
      text: text.length > MAX_TEXT ? text.slice(0, MAX_TEXT) : text,
    };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

export function analyzeJS(code, scriptUrl, baseHost) {
  const endpoints = [];
  const secrets = [];
  const subdomains = [];
  if (!code || code.length < 10) return { endpoints, secrets, subdomains };

  for (const re of EP_RES) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(code)) !== null) {
      const ep = m[1];
      if (!ep || ep.length < 3 || ep.length > 300) continue;
      if (/^(?:on[A-Z]|data-|aria-|--[a-z])/.test(ep)) continue;
      endpoints.push(ep);
    }
  }

  for (const s of scanSecrets(code)) {
    s.source = scriptUrl || '';
    secrets.push(s);
  }

  if (baseHost) {
    const esc = String(baseHost).replace(/\./g, '\\.');
    const sre = new RegExp(`(?:https?://)?([a-zA-Z0-9][a-zA-Z0-9\\-]*\\.${esc})`, 'gi');
    let sm;
    while ((sm = sre.exec(code)) !== null) subdomains.push(sm[1].toLowerCase());
  }

  return { endpoints: [...new Set(endpoints)], secrets, subdomains: [...new Set(subdomains)] };
}

export async function ingestFindings(tabId, findings, sourceUrl) {
  for (const ep of findings.endpoints) {
    let path = ep;
    let host = '';
    let full = sourceUrl;
    if (/^https?:/i.test(ep)) {
      try {
        const u = new URL(ep);
        path = u.pathname;
        host = u.hostname;
        full = ep;
      } catch (_) {}
    }
    if (path.length < 3 || path.length > 300) continue;
    if (/^https?:/i.test(full) && !(await scope.isInScope(full, tabId))) continue;
    store.push(tabId, 'endpoints', {
      _key: (host || '') + path, path, method: 'DISCOVERED', url: full, host,
      type: classifyEndpoint(path),
    }, { match: (x, n) => x._key === n._key });
  }
  for (const s of findings.secrets) {
    if (s.source && /^https?:/i.test(s.source) && !(await scope.isInScope(s.source, tabId))) continue;
    store.push(tabId, 'secrets', {
      name: s.name, value: s.value, risk: s.risk, severity: s.risk, category: s.name,
      context: s.context || '', source: s.source || '', url: s.source || '', timestamp: Date.now(),
    }, { match: (x, n) => x.value === n.value });
  }
  for (const h of findings.subdomains) {
    store.push(tabId, 'subdomains', {
      host: h, source: sourceUrl, discovered: new Date().toISOString(),
    }, { match: (x, n) => x.host === n.host });
  }
  store.markDirty(tabId);
}

export async function handleScanScripts(tabId, urls) {
  const tab = await store.ensure(tabId);
  if (!tab) return;
  const t = tab.target;
  const baseHost = t && t.host ? String(t.host).toLowerCase().replace(/^\*\./, '') : '';
  for (const url of (urls || []).slice(0, MAX_SCRIPTS_PER_SCAN)) {
    if (!/^https?:/i.test(url)) continue;
    if (!(await scope.isInScope(url, tabId))) continue;
    const r = await fetchText(url, tabId);
    if (!r.ok || !r.text) continue;
    if (!r.contentType || r.contentType.includes('javascript') || r.contentType.includes('text/plain') || /\.js($|\?)/i.test(url)) {
      await ingestFindings(tabId, analyzeJS(r.text, url, baseHost), url);
    }
    await ingestSourceMap(tabId, r.text, url, baseHost);
  }
}

async function ingestSourceMap(tabId, code, scriptUrl, baseHost) {
  const m = code.match(/\/\/[#@]\s*sourceMappingURL=(\S+)/);
  if (!m) return;
  let mu = m[1].trim();
  if (mu.startsWith('data:')) return;
  try { mu = /^https?:/i.test(mu) ? mu : new URL(mu, scriptUrl).href; } catch (_) { return; }
  if (!(await scope.isInScope(mu, tabId))) return;
  const r = await fetchText(mu, tabId);
  if (!r.ok || !r.text) return;
  let map;
  try { map = JSON.parse(r.text); } catch (_) { return; }
  if (Array.isArray(map.sources)) {
    for (const src of map.sources) {
      if (!src) continue;
      const path = src.replace(/^webpack:\/\/\//, '').replace(/^\.\//, '');
      if (/\.(js|ts|jsx|tsx|vue)$/.test(path) && path.length < 200) {
        store.push(tabId, 'endpoints', {
          _key: path, path, method: 'SOURCEMAP', url: mu, type: 'SOURCEMAP', note: 'source map',
        }, { match: (x, n) => x._key === n._key || x.path === n.path });
      }
    }
  }
  if (Array.isArray(map.sourcesContent)) {
    for (const content of map.sourcesContent) {
      if (typeof content === 'string') {
        await ingestFindings(tabId, analyzeJS(content, mu, baseHost), mu);
      }
    }
  }
}
