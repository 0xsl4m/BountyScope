// BountyScope — persistent per-tab store (fixes D4: MV3 service-worker death).
// Write-through with a 500 ms debounce; lazy reload from chrome.storage.local on wake.
const TAB_PREFIX = 'tab:';
export const SETTINGS_KEY = 'bountyscope_settings';

export const COLLECTIONS = [
  'params', 'endpoints', 'secrets', 'requests', 'headers', 'payloadResults',
  'fuzzResults', 'idorResults', 'corsResults', 'graphqlResults', 'subdomains',
  'customPayloads', 'websocketConnections', 'jwtTokens', 'apiDocs', 'scanResults',
];

const CAPS = {
  requests: 500, params: 2000, endpoints: 1500, secrets: 500, headers: 1000,
  payloadResults: 500, fuzzResults: 500, idorResults: 500, corsResults: 500,
  graphqlResults: 500, subdomains: 1000, customPayloads: 500,
  websocketConnections: 100, jwtTokens: 100, apiDocs: 100, scanResults: 500,
};

const tabs = new Map();        // tabId → in-memory tab data
const writeTimers = new Map(); // tabId → pending flush timer

function emptyTab() {
  const t = { target: null, dataVersion: 0 };
  for (const c of COLLECTIONS) t[c] = [];
  return t;
}

const pendingLoads = new Map(); // in-flight ensure() loads (concurrent wake-up dedupe)
const dropped = new Set();      // tabs removed — ensure() must not resurrect them

export async function ensure(tabId) {
  if (tabId == null || tabId < 0) return null;
  if (dropped.has(tabId)) return null;
  if (tabs.has(tabId)) return tabs.get(tabId);
  if (pendingLoads.has(tabId)) return pendingLoads.get(tabId);
  const p = (async () => {
    let saved = null;
    try {
      const res = await chrome.storage.local.get(TAB_PREFIX + tabId);
      saved = res[TAB_PREFIX + tabId];
    } catch (_) {}
    const tab = Object.assign(emptyTab(), saved || {});
    if (!tab.target) tab.target = null;
    for (const c of COLLECTIONS) if (!Array.isArray(tab[c])) tab[c] = [];
    tabs.set(tabId, tab);
    pendingLoads.delete(tabId);
    return tab;
  })();
  pendingLoads.set(tabId, p);
  return p;
}

export function peek(tabId) { return tabs.get(tabId) || null; }

export function markDirty(tabId) {
  const tab = tabs.get(tabId);
  if (!tab) return;
  tab.dataVersion = (tab.dataVersion || 0) + 1;
  if (writeTimers.has(tabId)) return;
  writeTimers.set(tabId, setTimeout(() => {
    writeTimers.delete(tabId);
    flush(tabId);
  }, 500));
}

export async function flush(tabId) {
  const tab = tabs.get(tabId);
  if (!tab) return;
  const out = {};
  for (const [k, v] of Object.entries(tab)) if (!k.startsWith('_')) out[k] = v;
  try { await chrome.storage.local.set({ [TAB_PREFIX + tabId]: out }); } catch (_) {}
}

// opts.match(existingItem, newItem) → true means duplicate, skip.
export function push(tabId, collection, item, opts = {}) {
  const tab = tabs.get(tabId);
  if (!tab || !Array.isArray(tab[collection]) || !item) return false;
  if (opts.match && tab[collection].some((x) => opts.match(x, item))) return false;
  tab[collection].push(item);
  const cap = CAPS[collection];
  if (cap && tab[collection].length > cap) tab[collection].splice(0, tab[collection].length - cap);
  markDirty(tabId);
  return true;
}

export function clearTab(tabId) {
  const tab = tabs.get(tabId);
  if (!tab) return;
  for (const c of COLLECTIONS) tab[c] = [];
  markDirty(tabId);
}

export async function dropTab(tabId) {
  dropped.add(tabId);
  if (writeTimers.has(tabId)) { clearTimeout(writeTimers.get(tabId)); writeTimers.delete(tabId); }
  tabs.delete(tabId);
  try { await chrome.storage.local.remove(TAB_PREFIX + tabId); } catch (_) {}
}

// ── Global settings ─────────────────────────────────────────────────────────
const DEFAULT_SETTINGS = {
  customPayloads: [],
  oosExtra: [],
  blindXssUrl: '',
  scanDefaults: { delay: 500, concurrency: 2, timeout: 8000 },
};
let settingsCache = null;

export async function initSettings() { await getSettings(); }

export async function getSettings() {
  if (settingsCache) return settingsCache;
  try {
    const r = await chrome.storage.local.get(SETTINGS_KEY);
    settingsCache = Object.assign({}, DEFAULT_SETTINGS, r[SETTINGS_KEY] || {});
  } catch (_) { settingsCache = JSON.parse(JSON.stringify(DEFAULT_SETTINGS)); }
  return settingsCache;
}

export async function setSettings(patch) {
  const cur = await getSettings();
  settingsCache = Object.assign({}, cur, patch);
  if (patch.scanDefaults) {
    settingsCache.scanDefaults = Object.assign({}, cur.scanDefaults, patch.scanDefaults);
  }
  try { await chrome.storage.local.set({ [SETTINGS_KEY]: settingsCache }); } catch (_) {}
  return settingsCache;
}
