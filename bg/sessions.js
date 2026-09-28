// BountyScope — per-target session snapshots (save / load / import / delete).
// Sessions are trimmed harder than live tabs so 12 sessions stay well inside
// chrome.storage.local's default quota (unlimitedStorage intentionally not used).
import * as store from './store.js';

const KEY = 'bountyscope_sessions';
const MAX_SESSIONS = 12;
const TRIMS = {
  requests: 100, params: 1000, endpoints: 800, scanResults: 300,
  fuzzResults: 300, idorResults: 200, payloadResults: 200,
};

async function readAll() {
  try { const r = await chrome.storage.local.get(KEY); return r[KEY] || {}; }
  catch (_) { return {}; }
}

async function writeAll(all) {
  try { await chrome.storage.local.set({ [KEY]: all }); } catch (_) {}
}

export async function saveSession(tabId) {
  const tab = await store.ensure(tabId);
  const t = tab?.target;
  if (!t || (!t.host && !t.noFilter)) return false;
  const all = await readAll();
  const snap = { target: t, savedAt: Date.now() };
  for (const c of store.COLLECTIONS) {
    const arr = tab[c] || [];
    snap[c] = TRIMS[c] ? arr.slice(0, TRIMS[c]) : arr.slice();
  }
  all[t.noFilter ? '__all__' : t.host] = snap;
  const keys = Object.keys(all);
  if (keys.length > MAX_SESSIONS) {
    keys.sort((a, b) => (all[a].savedAt || 0) - (all[b].savedAt || 0));
    for (const k of keys.slice(0, keys.length - MAX_SESSIONS)) delete all[k];
  }
  await writeAll(all);
  return true;
}

export async function list() {
  const all = await readAll();
  return Object.entries(all)
    .map(([host, s]) => ({
      host,
      savedAt: s.savedAt,
      counts: {
        params: s.params?.length || 0,
        secrets: s.secrets?.length || 0,
        endpoints: s.endpoints?.length || 0,
      },
    }))
    .sort((a, b) => b.savedAt - a.savedAt);
}

export async function load(tabId, host) {
  const all = await readAll();
  const s = all[host];
  if (!s) return false;
  const tab = await store.ensure(tabId);
  if (!tab) return false;
  for (const c of store.COLLECTIONS) tab[c] = Array.isArray(s[c]) ? s[c] : [];
  tab.target = s.target || null;
  store.markDirty(tabId);
  return true;
}

export async function remove(host) {
  const all = await readAll();
  delete all[host];
  await writeAll(all);
}

export async function importSession(tabId, host, session) {
  if (!session || typeof session !== 'object') return false;
  if (!session.target && !Array.isArray(session.params) && !Array.isArray(session.endpoints)) return false;
  const snap = {
    target: session.target || { host: host || '', wildcard: false, noFilter: false, raw: host || '' },
    savedAt: session.savedAt || Date.now(),
  };
  for (const c of store.COLLECTIONS) snap[c] = Array.isArray(session[c]) ? session[c] : [];
  const all = await readAll();
  all[host || 'imported'] = snap;
  await writeAll(all);
  return load(tabId, host || 'imported');
}
