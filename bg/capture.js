// BountyScope — passive capture pipeline (merged webRequest listeners).
// Fixes D5 (never auto-clears on navigation) and D6 (WebSocket upsert, not
// insert-once). URL params/bodies come from webRequest; JS analysis is in analyzer.js.
import * as store from './store.js';
import * as scope from './scope.js';
import { extractURL, parseBody, analyzeHeaders, buildParam, decodeBytes } from '../lib/classify.js';

// Only injection-relevant request headers are captured.
const INJECT_HEADERS = new Set([
  'referer', 'origin', 'host', 'x-forwarded-for', 'x-forwarded-host', 'x-real-ip',
  'x-client-ip', 'x-remote-addr', 'authorization', 'x-api-key', 'x-auth-token',
  'x-csrf-token', 'x-xsrf-token', 'x-access-token', 'x-requested-with',
]);

const PARAM_KEY = (x) => `${x.key}|${x.source}|${(x.url || '').split('?')[0]}`;

export function initCapture() {
  chrome.webRequest.onBeforeRequest.addListener(onBeforeRequest, { urls: ['<all_urls>'] }, ['requestBody']);
  chrome.webRequest.onSendHeaders.addListener(onSendHeaders, { urls: ['<all_urls>'] }, ['requestHeaders', 'extraHeaders']);
  chrome.webRequest.onHeadersReceived.addListener(onHeadersReceived, { urls: ['<all_urls>'] }, ['responseHeaders', 'extraHeaders']);
}

async function onBeforeRequest(d) {
  if (d.tabId < 0) return;
  if (!(await scope.isInScope(d.url, d.tabId))) return;
  const tab = await store.ensure(d.tabId);
  if (!tab) return;

  store.push(d.tabId, 'requests', {
    id: d.requestId, url: d.url, method: d.method, type: d.type, timestamp: Date.now(),
  });

  for (const p of extractURL(d.url, d.method)) {
    store.push(d.tabId, 'params', p, { match: (x, n) => PARAM_KEY(x) === PARAM_KEY(n) });
  }

  if (d.requestBody) {
    const rb = d.requestBody;
    if (rb.raw && rb.raw.length) {
      const s = decodeBytes(rb.raw[0].bytes);
      if (s) {
        for (const p of parseBody(s, '', d.url, d.method)) {
          store.push(d.tabId, 'params', p, { match: (x, n) => PARAM_KEY(x) === PARAM_KEY(n) });
        }
      }
    } else if (rb.formData) {
      for (const [k, vals] of Object.entries(rb.formData)) {
        const v = Array.isArray(vals) ? String(vals[0]) : String(vals);
        const p = buildParam(k, v, 'post_form', d.url, d.method);
        if (p) store.push(d.tabId, 'params', p, { match: (x, n) => PARAM_KEY(x) === PARAM_KEY(n) });
      }
    }
  }
  updateBadge(d.tabId);
}

async function onSendHeaders(d) {
  if (d.tabId < 0) return;
  if (!(await scope.isInScope(d.url, d.tabId))) return;
  const tab = await store.ensure(d.tabId);
  if (!tab) return;
  for (const h of d.requestHeaders || []) {
    const hl = h.name.toLowerCase();
    if (!INJECT_HEADERS.has(hl)) continue;
    // one entry per header name, ever (ReconSpider dedupe rule)
    if (tab.params.some((p) => p.source === 'request_header' && p.key.toLowerCase() === hl)) continue;
    const p = buildParam(h.name, h.value || '', 'request_header', d.url, d.method);
    if (p) store.push(d.tabId, 'params', p, {
      match: (x, n) => x.source === 'request_header' && x.key.toLowerCase() === String(n.key).toLowerCase(),
    });
  }
}

async function onHeadersReceived(d) {
  if (d.tabId < 0) return;
  if (!['main_frame', 'xmlhttprequest', 'sub_frame'].includes(d.type)) return;
  if (!(await scope.isInScope(d.url, d.tabId))) return;
  const tab = await store.ensure(d.tabId);
  if (!tab || !d.responseHeaders) return;
  let hostKey = '';
  try { hostKey = new URL(d.url).hostname; } catch (_) { return; }

  if (!tab.headers.some((h) => h._host === hostKey)) {
    for (const row of analyzeHeaders(d.responseHeaders, d.url, hostKey)) {
      store.push(d.tabId, 'headers', row, {
        match: (x, n) => x._host === n._host && x.header === n.header,
      });
    }
  }

  const map = {};
  d.responseHeaders.forEach((h) => { map[h.name.toLowerCase()] = h.value; });
  const acao = (map['access-control-allow-origin'] || '').trim();
  const acac = (map['access-control-allow-credentials'] || '').trim().toLowerCase();
  const base = d.url.split('?')[0];
  if (acao === '*') pushCorsSecret(d.tabId, 'CORS Wildcard', 'HIGH', '*', base, d.url);
  if (acao === 'null') pushCorsSecret(d.tabId, 'CORS Origin: null', 'MEDIUM', 'null', base, d.url);
  if (acac === 'true') pushCorsSecret(d.tabId, 'CORS Allow-Credentials: true', 'MEDIUM', 'true', base, d.url);

  // Passive CORS observations feed the CORS pane (D3 fix — active origin-forging
  // is impossible from a browser fetch, so misconfigs are flagged from real
  // responses instead).
  if (acao || acac) {
    store.push(d.tabId, 'corsResults', {
      url: d.url, origin: acao || '—', acao, acac: acac === 'true',
      vulnerable: acao === '*' || acao === 'null', passive: true, timestamp: Date.now(),
    }, { match: (x, n) => x.url === n.url && x.acao === n.acao });
  }
}

function pushCorsSecret(tabId, name, risk, value, base, url) {
  store.push(tabId, 'secrets', {
    name, value, risk, severity: risk, category: name + ' ★ check',
    context: name + ' on ' + base, source: 'response_header', url, timestamp: Date.now(),
  }, {
    match: (x, n) => x.name === name && (x.url || '').split('?')[0] === base,
  });
}

export function updateBadge(tabId) {
  if (tabId == null || tabId < 0 || !chrome.action) return;
  const tab = store.peek(tabId);
  if (!tab) return;
  const total = tab.params.length + tab.endpoints.length + tab.secrets.length + tab.scanResults.length;
  const hr = tab.secrets.some((s) => s.risk === 'CRITICAL' || s.risk === 'HIGH') ||
             tab.scanResults.some((r) => r.severity === 'CRITICAL' || r.severity === 'HIGH');
  try {
    chrome.action.setBadgeText({ text: total ? (total > 999 ? '999+' : String(total)) : '', tabId })
      .catch(() => {});
    chrome.action.setBadgeBackgroundColor({ color: hr ? '#f85149' : total ? '#388bfd' : '#6e7781', tabId })
      .catch(() => {});
  } catch (_) {}
}

// WebSocket upsert — D6 fix: later reports UPDATE status/counts/messages.
// Hardened: only in-scope ws(s):// URLs, status whitelisted, messages capped —
// a hostile page could otherwise spam oversized fake connections into storage.
const WS_STATUSES = new Set(['CONNECTING', 'OPEN', 'CLOSED', 'ERROR']);

export async function upsertWebSocket(tabId, conn) {
  if (!conn || !conn.url) return;
  const url = String(conn.url).slice(0, 500);
  if (!/^wss?:\/\//i.test(url)) return;
  if (!(await scope.isInScope(url, tabId))) return;
  const tab = await store.ensure(tabId);
  if (!tab) return;
  const messages = (Array.isArray(conn.messages) ? conn.messages : [])
    .slice(-50)
    .map((m) => ({
      direction: m && m.direction === 'OUT' ? 'OUT' : 'IN',
      data: String((m && m.data) || '').slice(0, 200),
      timestamp: Number(m && m.timestamp) || Date.now(),
    }));
  const status = WS_STATUSES.has(conn.status) ? conn.status : 'CONNECTING';
  const arr = tab.websocketConnections;
  const ex = arr.find((w) => w.url === url);
  if (ex) {
    ex.status = status;
    if (conn.protocol) ex.protocol = String(conn.protocol).slice(0, 100);
    if (typeof conn.messageCount === 'number') ex.messageCount = conn.messageCount;
    if (typeof conn.sentCount === 'number') ex.sentCount = conn.sentCount;
    if (typeof conn.receivedCount === 'number') ex.receivedCount = conn.receivedCount;
    if (messages.length) ex.messages = messages;
  } else {
    arr.push({
      url, protocol: String(conn.protocol || '').slice(0, 100), status,
      messageCount: conn.messageCount || 0, sentCount: conn.sentCount || 0,
      receivedCount: conn.receivedCount || 0,
      messages, timestamp: conn.timestamp || Date.now(),
    });
    if (arr.length > 100) arr.splice(0, arr.length - 100);
  }
  store.markDirty(tabId);
}
