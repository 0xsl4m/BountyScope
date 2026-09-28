// BountyScope — background service worker (module).
// Persistent per-tab store (D4), scope engine, merged capture pipeline,
// message router compatible with the ReconHawk popup API.
import * as store from './bg/store.js';
import * as scope from './bg/scope.js';
import * as sessions from './bg/sessions.js';
import { initCapture, updateBadge, upsertWebSocket } from './bg/capture.js';
import { fetchText, analyzeJS, handleScanScripts } from './bg/analyzer.js';
import { buildParam, classifyEndpoint } from './lib/classify.js';

initCapture();

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create('bs-snapshot', { periodInMinutes: 5 });
  store.initSettings().then((s) => scope.setExtraOOS(s.oosExtra || []));
});

// Restore settings cache + extra OOS list on every SW wake.
store.getSettings().then((s) => scope.setExtraOOS(s.oosExtra || []));

chrome.alarms.onAlarm.addListener((a) => {
  if (a.name !== 'bs-snapshot') return;
  (async () => {
    try {
      const activeTabs = await chrome.tabs.query({ active: true });
      for (const t of activeTabs) {
        const tab = await store.ensure(t.id);
        if (tab && (tab.target?.host || tab.target?.noFilter)) await sessions.saveSession(t.id);
      }
    } catch (_) {}
  })();
});

// Tab closed → snapshot a session if a target was set, then drop all data.
chrome.tabs.onRemoved.addListener((tabId) => {
  (async () => {
    try {
      const tab = await store.ensure(tabId);
      if (tab && (tab.target?.host || tab.target?.noFilter)) await sessions.saveSession(tabId);
    } catch (_) {}
    await store.dropTab(tabId);
  })();
});

// ─── Message router ──────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const tabId = (typeof msg?.tabId === 'number' && msg.tabId >= 0)
    ? msg.tabId
    : (sender.tab?.id ?? -1);
  route(msg || {}, tabId, sender)
    .then((r) => { try { sendResponse(r ?? { ok: true }); } catch (_) {} })
    .catch((e) => { try { sendResponse({ ok: false, error: e?.message || String(e) }); } catch (_) {} });
  return true; // every route() path responds, so the channel never hangs
});

async function route(msg, tabId, sender) {
  const type = msg.type || msg.action;

  if (tabId < 0) return { ok: false, error: 'Invalid tab ID' };

  switch (type) {

    case 'GET_DATA': {
      const tab = await store.ensure(tabId);
      const out = { ok: true, dataVersion: tab.dataVersion || 0, target: tab.target || null };
      for (const c of store.COLLECTIONS) out[c] = tab[c];
      return out;
    }

    case 'SET_TARGET': {
      const tab = await store.ensure(tabId);
      tab.target = msg.target || null;
      store.clearTab(tabId);
      return { ok: true };
    }

    case 'CLEAR_DATA': {
      await store.ensure(tabId);
      store.clearTab(tabId);
      updateBadge(tabId);
      return { ok: true };
    }

    case 'GET_SETTINGS':
      return { ok: true, settings: await store.getSettings() };

    case 'SET_SETTINGS': {
      const s = await store.setSettings(msg.settings || {});
      scope.setExtraOOS(s.oosExtra || []);
      return { ok: true };
    }

    case 'SAVE_SESSION':
      return { ok: await sessions.saveSession(tabId) };

    case 'GET_SESSIONS':
      return { ok: true, sessions: await sessions.list() };

    case 'LOAD_SESSION':
      return { ok: await sessions.load(tabId, msg.host) };

    case 'DELETE_SESSION':
      await sessions.remove(msg.host);
      return { ok: true };

    case 'IMPORT_SESSION':
      return { ok: await sessions.importSession(tabId, msg.host, msg.session) };

    case 'ADD_PARAMS': {
      const origin = sender.origin || sender.url || '';
      const list = Array.isArray(msg.params) ? msg.params : (Array.isArray(msg.data) ? msg.data : []);
      await store.ensure(tabId);
      for (const raw of list) {
        const name = raw?.key || raw?.name;
        if (!name) continue;
        let url = raw.url || '';
        if (url && !/^https?:/i.test(url) && /^https?:/i.test(origin)) {
          try { url = new URL(url, origin).href; } catch (_) {}
        }
        if (url && /^https?:/i.test(url) && !(await scope.isInScope(url, tabId))) continue;
        const p = buildParam(name, raw.value || '', raw.source || 'URL', url, raw.method || 'GET');
        if (!p) continue;
        store.push(tabId, 'params', p, {
          match: (x, n) => `${x.key}|${x.source}|${(x.url || '').split('?')[0]}` ===
                           `${n.key}|${n.source}|${(n.url || '').split('?')[0]}`,
        });
      }
      updateBadge(tabId);
      return { ok: true };
    }

    case 'ADD_ENDPOINTS': {
      const origin = sender.origin || sender.url || '';
      const list = Array.isArray(msg.endpoints) ? msg.endpoints : (Array.isArray(msg.data) ? msg.data : []);
      await store.ensure(tabId);
      for (const raw of list) {
        if (!raw) continue;
        let url = raw.url || raw.path || '';
        if (url && !/^https?:/i.test(url) && /^https?:/i.test(origin)) {
          try { url = new URL(url, origin).href; } catch (_) {}
        }
        let path = raw.path || '';
        let host = raw.host || '';
        if (!path && /^https?:/i.test(url)) {
          try { const u = new URL(url); path = u.pathname; host = u.hostname; } catch (_) { path = url; }
        }
        if (!path || path.length > 300) continue;
        if (/^https?:/i.test(url) && !(await scope.isInScope(url, tabId))) continue;
        const item = {
          _key: raw._key || ((host || '') + path),
          path, method: raw.method || 'GET', url: url || path, host,
          type: raw.type || classifyEndpoint(path),
        };
        store.push(tabId, 'endpoints', item, {
          match: (x, n) => x._key === n._key || x.path === n.path,
        });
      }
      updateBadge(tabId);
      return { ok: true };
    }

    case 'ADD_SECRETS': {
      const list = Array.isArray(msg.secrets) ? msg.secrets : (Array.isArray(msg.data) ? msg.data : []);
      await store.ensure(tabId);
      for (const s of list) {
        if (!s) continue;
        const source = s.source || s.url || '';
        if (source && /^https?:/i.test(source) && !(await scope.isInScope(source, tabId))) continue;
        const value = String(s.value || '').slice(0, 200);
        if (!value) continue;
        store.push(tabId, 'secrets', {
          name: s.name || s.category || 'Secret', value,
          risk: s.risk || s.severity || 'HIGH',
          severity: s.severity || s.risk || 'HIGH',
          category: s.category || s.name || 'Secret',
          context: String(s.context || '').slice(0, 250),
          source, url: source, timestamp: Date.now(),
        }, { match: (x, n) => x.value === n.value });
      }
      updateBadge(tabId);
      return { ok: true };
    }

    case 'ADD_SUBDOMAINS': {
      const list = Array.isArray(msg.subdomains) ? msg.subdomains : (Array.isArray(msg.data) ? msg.data : []);
      await store.ensure(tabId);
      for (const s of list) {
        if (!s?.host) continue;
        store.push(tabId, 'subdomains', {
          host: String(s.host).toLowerCase(),
          source: s.source || '',
          discovered: s.discovered || new Date().toISOString(),
        }, { match: (x, n) => x.host === n.host });
      }
      return { ok: true };
    }

    case 'ADD_WEBSOCKET': {
      const conn = msg.connection || msg.data?.connection;
      await upsertWebSocket(tabId, conn);
      return { ok: true };
    }

    case 'ADD_PAYLOAD_RESULT':
    case 'ADD_FUZZ_RESULT':
    case 'ADD_IDOR_RESULT':
    case 'ADD_CORS_RESULT':
    case 'ADD_GRAPHQL_RESULT':
    case 'ADD_SCAN_RESULT': {
      const map = {
        ADD_PAYLOAD_RESULT: 'payloadResults', ADD_FUZZ_RESULT: 'fuzzResults',
        ADD_IDOR_RESULT: 'idorResults', ADD_CORS_RESULT: 'corsResults',
        ADD_GRAPHQL_RESULT: 'graphqlResults', ADD_SCAN_RESULT: 'scanResults',
      };
      const result = msg.result || msg.data;
      if (!result) return { ok: true };
      await store.ensure(tabId);
      result.timestamp = result.timestamp || Date.now();
      const dedupe = {
        ADD_CORS_RESULT: (x, n) => x.url === n.url && x.origin === n.origin,
        ADD_GRAPHQL_RESULT: (x, n) => x.url === n.url && x.name === n.name,
        ADD_SCAN_RESULT: (x, n) => x.key === n.key,
      }[type];
      store.push(tabId, map[type], result, dedupe ? { match: dedupe } : {});
      updateBadge(tabId);
      return { ok: true };
    }

    case 'ADD_JWT_TOKEN': {
      const t = msg.token || msg.data;
      if (!t?.token) return { ok: true };
      await store.ensure(tabId);
      store.push(tabId, 'jwtTokens', t, { match: (x, n) => x.token === n.token });
      return { ok: true };
    }

    case 'ADD_API_DOC': {
      const d = msg.doc || msg.data;
      if (!d?.url) return { ok: true };
      await store.ensure(tabId);
      store.push(tabId, 'apiDocs', d, { match: (x, n) => x.url === n.url });
      return { ok: true };
    }

    case 'SAVE_CUSTOM_PAYLOADS': {
      const payloads = Array.isArray(msg.payloads) ? msg.payloads : [];
      await store.setSettings({ customPayloads: payloads });
      const tab = await store.ensure(tabId);
      tab.customPayloads = payloads;
      store.markDirty(tabId);
      return { ok: true };
    }

    case 'SCAN_SCRIPTS':
      await handleScanScripts(tabId, msg.urls || []);
      return { ok: true };

    case 'FETCH_TEXT':
      return fetchText(msg.url, tabId);

    case 'ANALYZE_JS':
      return { ok: true, findings: analyzeJS(msg.code || '', msg.scriptUrl || '', '') };

    default:
      return { ok: false, error: 'Unknown action: ' + type };
  }
}
