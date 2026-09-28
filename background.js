// ============================================================
// ReconHawk Pro - Background Service Worker v4.1
// FIXED: Better scope/target filtering, request body capture,
//        WebSocket tracking, improved session management
// ============================================================

const store = {
  requests:{}, params:{}, endpoints:{}, secrets:{}, headers:{},
  target:{}, payloadResults:{}, fuzzResults:{}, idorResults:{},
  corsResults:{}, graphqlResults:{}, subdomains:{},
  customPayloads:{}, websocketConnections:{}, jwtTokens:{}, apiDocs:{}
};

// ─── Init tab data ───────────────────────────────────────────
function initTab(tabId) {
  if (!store.requests[tabId]) {
    store.requests[tabId]    = [];
    store.params[tabId]      = [];
    store.endpoints[tabId]   = [];
    store.secrets[tabId]     = [];
    store.headers[tabId]     = [];
    store.payloadResults[tabId] = [];
    store.fuzzResults[tabId] = [];
    store.idorResults[tabId] = [];
    store.corsResults[tabId] = [];
    store.graphqlResults[tabId] = [];
    store.subdomains[tabId]  = [];
    store.customPayloads[tabId] = [];
    store.websocketConnections[tabId] = [];
    store.jwtTokens[tabId] = [];
    store.apiDocs[tabId] = [];
  }
}

// ─── Scope check - IMPROVED ──────────────────────────────────
function isInScope(url, tabId) {
  const target = store.target[tabId];
  // No target set = capture nothing (require explicit scope)
  if (!target) return false;
  // noFilter = capture everything
  if (target.noFilter) return true;
  // No host set = capture nothing
  if (!target.host) return false;

  try {
    const reqHost = new URL(url).hostname.toLowerCase();
    const targetHost = target.host.toLowerCase();

    if (target.wildcard) {
      // Wildcard: *.example.com matches sub.example.com AND example.com
      const base = targetHost.replace(/^\*\./, "");
      return reqHost === base || reqHost.endsWith("." + base);
    }
    // Exact match only
    return reqHost === targetHost;
  } catch(e) { return false; }
}

// ─── Check if a stored item's URL is in scope ────────────────
function itemInScope(itemUrl, tabId) {
  if (!itemUrl) return false;
  return isInScope(itemUrl, tabId);
}

// ─── Request interception ────────────────────────────────────
chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    const tabId = details.tabId;
    if (tabId < 0) return;
    initTab(tabId);
    if (!isInScope(details.url, tabId)) return;
    try {
      const url = new URL(details.url);
      url.searchParams.forEach((value, key) => {
        if (!store.params[tabId].find(p => p.key===key && p.url===details.url))
          store.params[tabId].push({ key, value, source:"URL", url:details.url });
      });
      const epKey = url.hostname + url.pathname;
      if (url.pathname && url.pathname !== "/" && !store.endpoints[tabId].find(e => e._key===epKey)) {
        store.endpoints[tabId].push({
          _key:epKey, path:url.pathname, method:details.method,
          url:details.url, host:url.hostname, type:detectEndpointType(url.pathname)
        });
      }
      if (store.requests[tabId].length < 500)
        store.requests[tabId].push({
          id:details.requestId, url:details.url, method:details.method,
          timestamp:Date.now(), type:details.type,
          headers: details.requestHeaders ? headersToObj(details.requestHeaders) : {}
        });
    } catch(e) {}
  },
  { urls:["<all_urls>"] }, ["requestHeaders"]
);

// ─── Response headers ────────────────────────────────────────
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    const tabId = details.tabId;
    if (tabId < 0) return;
    initTab(tabId);
    if (!isInScope(details.url, tabId)) return;
    if (!["main_frame","xmlhttprequest","fetch","sub_frame"].includes(details.type)) return;
    try {
      const hostKey = new URL(details.url).hostname;
      if (!store.headers[tabId].find(h => h._host===hostKey))
        store.headers[tabId].push(...analyzeHeaders(details.responseHeaders, details.url, hostKey));
    } catch(e) {}
  },
  { urls:["<all_urls>"] }, ["responseHeaders"]
);

// ─── Helper: headers array to object ─────────────────────────
function headersToObj(headersArr) {
  if (!headersArr) return {};
  const obj = {};
  headersArr.forEach(h => { obj[h.name.toLowerCase()] = h.value; });
  return obj;
}

function detectEndpointType(path) {
  if (path.match(/\.(php|asp|aspx|jsp|py|rb|go|cfm)$/i)) return "SERVER-SIDE";
  if (path.match(/\/api\/|\/v\d+\//i)) return "API";
  if (path.match(/graphql/i)) return "GRAPHQL";
  if (path.match(/\.(json|xml|yaml)$/i)) return "DATA";
  if (path.match(/\.(js|ts|mjs)$/i)) return "JS";
  if (path.match(/admin|panel|dashboard|login|auth|manage|config|setup|phpmy|wp-admin/i)) return "SENSITIVE";
  if (path.match(/upload|file|import|export|download/i)) return "FILE";
  return "PAGE";
}

function analyzeHeaders(headers, url, hostKey) {
  if (!headers) return [];
  const checks = {
    "x-frame-options":           { risk:"MEDIUM", desc:"Clickjacking protection" },
    "content-security-policy":   { risk:"HIGH",   desc:"XSS protection policy" },
    "strict-transport-security": { risk:"HIGH",   desc:"HTTPS enforcement (HSTS)" },
    "x-content-type-options":    { risk:"LOW",    desc:"MIME sniffing protection" },
    "x-xss-protection":          { risk:"MEDIUM", desc:"Browser XSS filter" },
    "referrer-policy":           { risk:"LOW",    desc:"Referrer information control" },
    "permissions-policy":        { risk:"LOW",    desc:"Browser feature permissions" },
    "server":                    { risk:"INFO",   desc:"Server technology disclosure" },
    "x-powered-by":              { risk:"INFO",   desc:"Technology stack disclosure" },
    "access-control-allow-origin":{ risk:"HIGH",  desc:"CORS policy" },
    "set-cookie":                { risk:"MEDIUM", desc:"Cookie security flags" }
  };
  const map = {};
  headers.forEach(h => { map[h.name.toLowerCase()] = h.value; });
  return Object.entries(checks).map(([header, info]) => ({
    _host:hostKey, url, header,
    value: map[header] || "MISSING",
    present: !!map[header],
    risk: map[header] ? "OK" : info.risk,
    desc: info.desc
  }));
}

// ─── Storage helpers ─────────────────────────────────────────
const STORAGE_KEY = "reconhawk_sessions";

async function saveSession(tabId) {
  const target = store.target[tabId];
  if (!target || (!target.host && !target.noFilter)) return;
  const key = target.noFilter ? "__all__" : target.host;
  try {
    const existing = await chrome.storage.local.get(STORAGE_KEY);
    const sessions = existing[STORAGE_KEY] || {};
    sessions[key] = {
      target: store.target[tabId],
      params: store.params[tabId]      || [],
      endpoints: store.endpoints[tabId] || [],
      secrets: store.secrets[tabId]    || [],
      requests: (store.requests[tabId] || []).slice(-100),
      headers: store.headers[tabId]    || [],
      payloadResults: store.payloadResults[tabId] || [],
      fuzzResults: store.fuzzResults[tabId]       || [],
      idorResults: store.idorResults[tabId]       || [],
      corsResults: store.corsResults[tabId]       || [],
      graphqlResults: store.graphqlResults[tabId] || [],
      subdomains: store.subdomains[tabId]         || [],
      customPayloads: store.customPayloads[tabId]  || [],
      websocketConnections: store.websocketConnections[tabId] || [],
      jwtTokens: store.jwtTokens[tabId]            || [],
      apiDocs: store.apiDocs[tabId]                || [],
      savedAt: Date.now()
    };
    const keys = Object.keys(sessions);
    if (keys.length > 20) {
      const oldest = keys.sort((a,b) => (sessions[a].savedAt||0) - (sessions[b].savedAt||0))[0];
      delete sessions[oldest];
    }
    await chrome.storage.local.set({ [STORAGE_KEY]: sessions });
  } catch(e) {}
}

async function loadSession(tabId, host) {
  try {
    const existing = await chrome.storage.local.get(STORAGE_KEY);
    const sessions = existing[STORAGE_KEY] || {};
    const s = sessions[host];
    if (!s) return false;
    initTab(tabId);
    store.target[tabId]        = s.target;
    store.params[tabId]        = s.params        || [];
    store.endpoints[tabId]     = s.endpoints     || [];
    store.secrets[tabId]       = s.secrets       || [];
    store.requests[tabId]      = s.requests      || [];
    store.headers[tabId]       = s.headers       || [];
    store.payloadResults[tabId]= s.payloadResults|| [];
    store.fuzzResults[tabId]   = s.fuzzResults   || [];
    store.idorResults[tabId]   = s.idorResults   || [];
    store.corsResults[tabId]   = s.corsResults   || [];
    store.graphqlResults[tabId]= s.graphqlResults|| [];
    store.subdomains[tabId]    = s.subdomains    || [];
    store.customPayloads[tabId]= s.customPayloads|| [];
    store.websocketConnections[tabId] = s.websocketConnections || [];
    store.jwtTokens[tabId]     = s.jwtTokens     || [];
    store.apiDocs[tabId]       = s.apiDocs       || [];
    return true;
  } catch(e) { return false; }
}

// Auto-save every 10 seconds for active tabs
setInterval(async () => {
  const tabs = await chrome.tabs.query({ active:true });
  for (const tab of tabs) {
    if (store.target[tab.id]?.host || store.target[tab.id]?.noFilter) saveSession(tab.id);
  }
}, 10000);

// ─── Message handler ─────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const tabId = (msg.tabId >= 0) ? msg.tabId : (sender.tab?.id ?? -1);
  if (tabId < 0) {
    sendResponse({ ok: false, error: "Invalid tab ID" });
    return true;
  }
  switch (msg.type) {

    case "GET_DATA":
      initTab(tabId);
      sendResponse({
        params:         store.params[tabId]         || [],
        endpoints:      store.endpoints[tabId]      || [],
        secrets:        store.secrets[tabId]        || [],
        requests:       store.requests[tabId]       || [],
        headers:        store.headers[tabId]        || [],
        payloadResults: store.payloadResults[tabId] || [],
        fuzzResults:    store.fuzzResults[tabId]    || [],
        idorResults:    store.idorResults[tabId]    || [],
        corsResults:    store.corsResults[tabId]    || [],
        graphqlResults: store.graphqlResults[tabId] || [],
        subdomains:     store.subdomains[tabId]     || [],
        customPayloads: store.customPayloads[tabId] || [],
        websocketConnections: store.websocketConnections[tabId] || [],
        jwtTokens:      store.jwtTokens[tabId]      || [],
        apiDocs:        store.apiDocs[tabId]        || [],
        target:         store.target[tabId]         || null
      });
      break;

    case "GET_SESSIONS":
      chrome.storage.local.get(STORAGE_KEY).then(r => {
        const sessions = r[STORAGE_KEY] || {};
        const list = Object.entries(sessions).map(([host, s]) => ({
          host, savedAt: s.savedAt,
          counts: { params: s.params?.length||0, secrets: s.secrets?.length||0, endpoints: s.endpoints?.length||0 }
        })).sort((a,b)=>b.savedAt-a.savedAt);
        sendResponse({ sessions: list });
      });
      return true;

    case "LOAD_ALL_SESSIONS":
      chrome.storage.local.get(STORAGE_KEY).then(r => {
        const sessions = r[STORAGE_KEY] || {};
        const list = Object.entries(sessions).map(([host, s]) => ({
          host, savedAt: s.savedAt,
          counts: { params: s.params?.length||0, secrets: s.secrets?.length||0, endpoints: s.endpoints?.length||0 }
        })).sort((a,b)=>b.savedAt-a.savedAt);
        sendResponse({ sessions: list });
      });
      return true;

    case "IMPORT_SESSION":
      (async () => {
        try {
          const host = msg.host || "imported";
          const existing = await chrome.storage.local.get(STORAGE_KEY);
          const sessions = existing[STORAGE_KEY] || {};
          sessions[host] = msg.session;
          await chrome.storage.local.set({ [STORAGE_KEY]: sessions });
          const ok = await loadSession(tabId, host);
          sendResponse({ ok });
        } catch(e) {
          sendResponse({ ok: false, error: e.message });
        }
      })();
      return true;

    case "LOAD_SESSION":
      loadSession(tabId, msg.host).then(ok => sendResponse({ ok }));
      return true;

    case "DELETE_SESSION":
      chrome.storage.local.get(STORAGE_KEY).then(r => {
        const sessions = r[STORAGE_KEY] || {};
        delete sessions[msg.host];
        chrome.storage.local.set({ [STORAGE_KEY]: sessions }).then(() => sendResponse({ ok:true }));
      });
      return true;

    case "SET_TARGET":
      store.target[tabId] = msg.target;
      // Clear all data when target changes
      store.requests[tabId]=[]; store.params[tabId]=[];
      store.endpoints[tabId]=[]; store.secrets[tabId]=[];
      store.headers[tabId]=[]; store.payloadResults[tabId]=[];
      store.fuzzResults[tabId]=[]; store.idorResults[tabId]=[];
      store.corsResults[tabId]=[]; store.graphqlResults[tabId]=[];
      store.subdomains[tabId]=[]; store.customPayloads[tabId]=[];
      store.websocketConnections[tabId]=[]; store.jwtTokens[tabId]=[];
      store.apiDocs[tabId]=[];
      sendResponse({ ok:true });
      break;

    case "ADD_SECRETS":
      initTab(tabId);
      msg.secrets.forEach(s => {
        // Only add if in scope
        if (s.source && !itemInScope(s.source, tabId)) return;
        if (!store.secrets[tabId].find(x=>x.value===s.value)) store.secrets[tabId].push(s);
      });
      sendResponse({ ok:true });
      break;

    case "ADD_PARAMS":
      initTab(tabId);
      msg.params.forEach(p => {
        // Only add if URL is in scope
        if (p.url && !itemInScope(p.url, tabId)) return;
        if (!store.params[tabId].find(x=>x.key===p.key&&x.source===p.source&&x.url===p.url))
          store.params[tabId].push(p);
      });
      sendResponse({ ok:true });
      break;

    case "ADD_ENDPOINTS":
      initTab(tabId);
      msg.endpoints.forEach(e => {
        // Only add if URL is in scope
        if (e.url && e.url.startsWith("http") && !itemInScope(e.url, tabId)) return;
        if (!store.endpoints[tabId].find(x=>x._key===e._key||x.path===e.path))
          store.endpoints[tabId].push(e);
      });
      sendResponse({ ok:true });
      break;

    case "ADD_PAYLOAD_RESULT":
      initTab(tabId);
      store.payloadResults[tabId].push(msg.result);
      sendResponse({ ok:true });
      break;

    case "ADD_FUZZ_RESULT":
      initTab(tabId);
      store.fuzzResults[tabId].push(msg.result);
      sendResponse({ ok:true });
      break;

    case "ADD_IDOR_RESULT":
      initTab(tabId);
      store.idorResults[tabId].push(msg.result);
      sendResponse({ ok:true });
      break;

    case "ADD_CORS_RESULT":
      initTab(tabId);
      store.corsResults[tabId].push(msg.result);
      sendResponse({ ok:true });
      break;

    case "ADD_GRAPHQL_RESULT":
      initTab(tabId);
      store.graphqlResults[tabId].push(msg.result);
      sendResponse({ ok:true });
      break;

    case "ADD_SUBDOMAINS":
      initTab(tabId);
      msg.subdomains.forEach(s => {
        if (!store.subdomains[tabId].find(x=>x.host===s.host))
          store.subdomains[tabId].push(s);
      });
      sendResponse({ ok:true });
      break;

    case "SAVE_SESSION":
      saveSession(tabId).then(()=>sendResponse({ok:true}));
      return true;

    case "CLEAR_DATA":
      store.requests[tabId]=[]; store.params[tabId]=[];
      store.endpoints[tabId]=[]; store.secrets[tabId]=[];
      store.headers[tabId]=[]; store.payloadResults[tabId]=[];
      store.fuzzResults[tabId]=[]; store.idorResults[tabId]=[];
      store.corsResults[tabId]=[]; store.graphqlResults[tabId]=[];
      store.subdomains[tabId]=[]; store.customPayloads[tabId]=[];
      store.websocketConnections[tabId]=[]; store.jwtTokens[tabId]=[];
      store.apiDocs[tabId]=[];
      sendResponse({ ok:true });
      break;

    case "SAVE_CUSTOM_PAYLOADS":
      initTab(tabId);
      store.customPayloads[tabId] = msg.payloads || [];
      sendResponse({ ok:true });
      break;

    case "ADD_WEBSOCKET":
      initTab(tabId);
      if (!store.websocketConnections[tabId].find(ws => ws.url === msg.connection.url))
        store.websocketConnections[tabId].push(msg.connection);
      sendResponse({ ok:true });
      break;

    case "ADD_JWT_TOKEN":
      initTab(tabId);
      if (!store.jwtTokens[tabId].find(t => t.token === msg.token.token))
        store.jwtTokens[tabId].push(msg.token);
      sendResponse({ ok:true });
      break;

    case "ADD_API_DOC":
      initTab(tabId);
      if (!store.apiDocs[tabId].find(d => d.url === msg.doc.url))
        store.apiDocs[tabId].push(msg.doc);
      sendResponse({ ok:true });
      break;

    // NEW: Purge out-of-scope data after target change
    case "PURGE_OUT_OF_SCOPE":
      initTab(tabId);
      store.params[tabId]    = store.params[tabId].filter(p => !p.url || itemInScope(p.url, tabId));
      store.endpoints[tabId] = store.endpoints[tabId].filter(e => !e.url || !e.url.startsWith("http") || itemInScope(e.url, tabId));
      store.secrets[tabId]   = store.secrets[tabId].filter(s => !s.source || itemInScope(s.source, tabId));
      store.requests[tabId]  = store.requests[tabId].filter(r => itemInScope(r.url, tabId));
      store.headers[tabId]   = store.headers[tabId].filter(h => !h.url || itemInScope(h.url, tabId));
      store.subdomains[tabId]= store.subdomains[tabId].filter(s => {
        if (!s.source) return true;
        return itemInScope(s.source, tabId);
      });
      sendResponse({ ok:true });
      break;
  }
  return true;
});

// ─── Tab navigation ──────────────────────────────────────────
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "loading") {
    const target = store.target[tabId];
    if (target?.host && tab.url) {
      try {
        const newHost = new URL(tab.url).hostname.toLowerCase();
        const base = target.host.toLowerCase().replace(/^\*\./,"");
        if (newHost===base || newHost.endsWith("."+base)) return;
      } catch(e) {}
    }
    if (target?.noFilter) return; // Don't clear on navigation if no-filter scope
    store.requests[tabId]=[]; store.params[tabId]=[];
    store.endpoints[tabId]=[]; store.secrets[tabId]=[];
    store.headers[tabId]=[]; store.payloadResults[tabId]=[];
    store.fuzzResults[tabId]=[]; store.idorResults[tabId]=[];
    store.corsResults[tabId]=[]; store.graphqlResults[tabId]=[];
    store.subdomains[tabId]=[]; store.customPayloads[tabId]=[];
    store.websocketConnections[tabId]=[]; store.jwtTokens[tabId]=[];
    store.apiDocs[tabId]=[];
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  if (store.target[tabId]?.host || store.target[tabId]?.noFilter) saveSession(tabId);
  delete store.requests[tabId]; delete store.params[tabId];
  delete store.endpoints[tabId]; delete store.secrets[tabId];
  delete store.headers[tabId]; delete store.payloadResults[tabId];
  delete store.fuzzResults[tabId]; delete store.idorResults[tabId];
  delete store.corsResults[tabId]; delete store.graphqlResults[tabId];
  delete store.subdomains[tabId]; delete store.customPayloads[tabId];
  delete store.websocketConnections[tabId]; delete store.jwtTokens[tabId];
  delete store.apiDocs[tabId]; delete store.target[tabId];
});
