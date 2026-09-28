// ============================================================
// ReconHawk Pro - Content Script v4.1
// FIXED: WebSocket real monitoring, scope-aware scanning,
//        better source map handling, POST body capture
// ============================================================
(function() {
  if (window.__reconHawkInjected) return;
  window.__reconHawkInjected = true;

  const SECRET_PATTERNS = [
    { name:"AWS Access Key",   regex:/AKIA[0-9A-Z]{16}/g,                              risk:"CRITICAL" },
    { name:"AWS Secret Key",   regex:/aws.{0,20}['"\s=:][0-9a-zA-Z\/+]{40}/gi,        risk:"CRITICAL" },
    { name:"Google API Key",   regex:/AIza[0-9A-Za-z\-_]{35}/g,                       risk:"HIGH" },
    { name:"GitHub Token",     regex:/gh[pousr]_[0-9a-zA-Z]{36}/g,                    risk:"CRITICAL" },
    { name:"JWT Token",        regex:/eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g, risk:"HIGH" },
    { name:"Bearer Token",     regex:/bearer\s+[a-zA-Z0-9\-._~+\/]{20,}/gi,           risk:"HIGH" },
    { name:"Private Key",      regex:/-----BEGIN\s*(RSA|EC|DSA)?\s*PRIVATE KEY-----/g, risk:"CRITICAL" },
    { name:"Slack Token",      regex:/xox[baprs]-[0-9a-zA-Z]{10,}/g,                  risk:"HIGH" },
    { name:"Stripe Secret",    regex:/sk_(live|test)_[0-9a-zA-Z]{24,}/g,              risk:"CRITICAL" },
    { name:"Stripe Public",    regex:/pk_(live|test)_[0-9a-zA-Z]{24,}/g,              risk:"MEDIUM" },
    { name:"Firebase URL",     regex:/https:\/\/[a-z0-9-]+\.firebaseio\.com/g,        risk:"MEDIUM" },
    { name:"API Key Generic",  regex:/['"]api[_-]?key['"]\s*[:=]\s*['"][a-zA-Z0-9\-_]{16,}['"]/gi, risk:"HIGH" },
    { name:"Password in Code", regex:/['"]password['"]\s*[:=]\s*['"][^'"]{6,}['"]/gi, risk:"HIGH" },
    { name:"Secret in Code",   regex:/['"]secret['"]\s*[:=]\s*['"][^'"]{8,}['"]/gi,   risk:"HIGH" },
    { name:"Auth Token",       regex:/['"]auth[_-]?token['"]\s*[:=]\s*['"][a-zA-Z0-9\-_]{16,}['"]/gi, risk:"HIGH" },
    { name:"DB MongoDB",       regex:/mongodb(\+srv)?:\/\/[^\s'"<>]+/gi,               risk:"CRITICAL" },
    { name:"DB SQL",           regex:/(mysql|postgresql|postgres):\/\/[^\s'"<>]+/gi,   risk:"CRITICAL" },
    { name:"SendGrid Key",     regex:/SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,    risk:"HIGH" },
  ];

  const ENDPOINT_PATTERNS = [
    /['"`](\/[a-zA-Z0-9_\-\/\.]{2,100})['"`]/g,
    /['"`](https?:\/\/[^\s'"<>{}|\\^`\[\]]{5,200})['"`]/g,
    /fetch\s*\(\s*['"`]([^'"`]+)['"`]/g,
    /axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/g,
    /url\s*[:=]\s*['"`]([^'"`\s]{4,200})['"`]/gi,
    /endpoint\s*[:=]\s*['"`]([^'"`\s]{4,200})['"`]/gi,
  ];

  const foundSecrets = [], foundEndpoints = [], foundParams = [], foundSubdomains = [];

  // ── Get base domain ───────────────────────────────────────
  function getBaseDomain() {
    try {
      const parts = window.location.hostname.split(".");
      return parts.slice(-2).join(".");
    } catch(_) { return window.location.hostname; }
  }

  // ── Check if URL is same scope as current page ────────────
  function isSameScope(url) {
    try {
      const base = getBaseDomain();
      const host = new URL(url).hostname.toLowerCase();
      return host === base || host.endsWith("." + base);
    } catch(_) { return true; } // relative URLs are always in scope
  }

  function buildSubdomainRegex(base) {
    const escaped = base.replace(/\./g, "\\.");
    return new RegExp(`(?:https?://)?([a-zA-Z0-9][a-zA-Z0-9\\-]*\\.${escaped})`, "gi");
  }

  function scanSource(source, sourceUrl) {
    const base = getBaseDomain();
    const subRe = buildSubdomainRegex(base);

    // Secrets
    SECRET_PATTERNS.forEach(({ name, regex, risk }) => {
      let m; regex.lastIndex=0;
      while ((m=regex.exec(source))!==null) {
        const val = m[0].substring(0,150);
        if (!foundSecrets.find(s=>s.value===val))
          foundSecrets.push({ name, value:val, risk, source:sourceUrl });
      }
    });

    // Endpoints - only same-scope absolute URLs
    ENDPOINT_PATTERNS.forEach(regex => {
      let m; regex.lastIndex=0;
      while ((m=regex.exec(source))!==null) {
        const ep = m[1]||m[2];
        if (!ep || ep.length<=2 || ep.length>=300) continue;
        if (ep.startsWith("http") && !isSameScope(ep)) continue; // skip out-of-scope absolute URLs
        if (!foundEndpoints.find(e=>e.path===ep))
          foundEndpoints.push({ _key:ep, path:ep, method:"DISCOVERED", url:ep.startsWith("http")?ep:sourceUrl, type:ep.startsWith("http")?"EXTERNAL":"INTERNAL" });
      }
    });

    // Params from URL patterns
    const paramRe = /[?&]([a-zA-Z_][a-zA-Z0-9_\-]{0,50})=/g;
    let pm; paramRe.lastIndex=0;
    while ((pm=paramRe.exec(source))!==null) {
      const p = pm[1];
      if (p && p.length>1 && !foundParams.find(x=>x.key===p&&x.source==="JS"))
        foundParams.push({ key:p, value:"", source:"JS", url:sourceUrl });
    }

    // Subdomains
    let sm; subRe.lastIndex=0;
    while ((sm=subRe.exec(source))!==null) {
      const host = sm[1].toLowerCase();
      if (host !== window.location.hostname && !foundSubdomains.find(x=>x.host===host))
        foundSubdomains.push({ host, source:sourceUrl, discovered: new Date().toISOString() });
    }
  }

  function scanDOM() {
    document.querySelectorAll("form").forEach(form => {
      const action = form.getAttribute("action") || window.location.href;
      const method = (form.getAttribute("method")||"GET").toUpperCase();
      // Only include forms that submit to in-scope targets
      let actionUrl = action;
      try {
        actionUrl = new URL(action, window.location.href).href;
      } catch(_) {}
      form.querySelectorAll("input,select,textarea").forEach(inp => {
        const name = inp.getAttribute("name");
        if (name && !foundParams.find(p=>p.key===name&&p.source==="FORM"))
          foundParams.push({ key:name, value:inp.value||"", source:"FORM", url:actionUrl, method });
      });
    });

    document.querySelectorAll("a[href]").forEach(a => {
      try {
        const url = new URL(a.href, window.location.href);
        // Only index same-scope links
        if (!isSameScope(url.href) && url.hostname !== window.location.hostname) return;
        url.searchParams.forEach((value,key) => {
          if (!foundParams.find(p=>p.key===key&&p.source==="LINK"))
            foundParams.push({ key, value, source:"LINK", url:a.href });
        });
        if (url.pathname && url.pathname.length>1 && !foundEndpoints.find(e=>e.path===url.pathname))
          foundEndpoints.push({ _key:url.pathname, path:url.pathname, method:"GET", url:a.href, type:"LINK" });
      } catch(_) {}
    });

    document.querySelectorAll("script:not([src])").forEach(s => {
      if (s.textContent) scanSource(s.textContent, window.location.href+"[inline]");
    });
  }

  // ── Source Map Parser ─────────────────────────────────────
  async function parseSourceMaps(scriptUrl) {
    try {
      const resp = await fetch(scriptUrl, { cache:"force-cache" });
      if (!resp.ok) return;
      const text = await resp.text();

      const mapMatch = text.match(/\/\/[#@]\s*sourceMappingURL=(.+)$/m);
      if (!mapMatch) return;

      let mapUrl = mapMatch[1].trim();
      if (mapUrl.startsWith("data:")) return;
      if (!mapUrl.startsWith("http")) {
        mapUrl = new URL(mapUrl, scriptUrl).href;
      }

      const mapResp = await fetch(mapUrl, { cache:"force-cache" });
      if (!mapResp.ok) return;

      let mapData;
      try {
        mapData = await mapResp.json();
      } catch(e) {
        return; // Invalid JSON in source map
      }

      if (mapData.sources && Array.isArray(mapData.sources)) {
        mapData.sources.forEach(src => {
          if (!src) return;
          const path = src.replace(/^webpack:\/\/\/|^\.\//, "");
          if (path.match(/\.(js|ts|vue|jsx|tsx)$/) && path.length < 200) {
            if (!foundEndpoints.find(e=>e.path===path))
              foundEndpoints.push({ _key:path, path, method:"SOURCEMAP", url:mapUrl, type:"JS", note:"From source map" });
          }
        });
      }

      if (mapData.sourcesContent && Array.isArray(mapData.sourcesContent)) {
        mapData.sourcesContent.forEach((content, i) => {
          if (content && typeof content === "string") {
            scanSource(content, (mapData.sources&&mapData.sources[i]) || mapUrl);
          }
        });
      }
    } catch(e) {
      // Silently fail but don't block other scans
    }
  }

  async function scanExternalScripts() {
    const scripts = Array.from(document.querySelectorAll("script[src]")).slice(0,25);
    for (const script of scripts) {
      try {
        // Only scan same-scope scripts
        if (!isSameScope(script.src)) continue;

        const resp = await fetch(script.src, { cache:"force-cache" });
        if (resp.ok) {
          const ct = resp.headers.get("content-type")||"";
          if (ct.includes("javascript")||ct.includes("text/plain")||script.src.endsWith(".js")) {
            const text = await resp.text();
            scanSource(text, script.src);
          }
        }
        await parseSourceMaps(script.src);
      } catch(_) {}
    }
  }

  // ── WebSocket Real Monitoring ─────────────────────────────
  function hookWebSocket() {
    const OrigWebSocket = window.WebSocket;
    if (!OrigWebSocket || window.__reconHawkWSHooked) return;
    window.__reconHawkWSHooked = true;

    window.WebSocket = function(url, protocols) {
      const ws = protocols ? new OrigWebSocket(url, protocols) : new OrigWebSocket(url);
      const connInfo = {
        url: url,
        protocol: typeof protocols === "string" ? protocols : (Array.isArray(protocols) ? protocols.join(",") : ""),
        status: "CONNECTING",
        messageCount: 0,
        sentCount: 0,
        receivedCount: 0,
        messages: [],
        timestamp: Date.now()
      };

      ws.addEventListener("open", () => {
        connInfo.status = "OPEN";
        sendWSUpdate(connInfo);
      });

      ws.addEventListener("close", () => {
        connInfo.status = "CLOSED";
        sendWSUpdate(connInfo);
      });

      ws.addEventListener("error", () => {
        connInfo.status = "ERROR";
        sendWSUpdate(connInfo);
      });

      ws.addEventListener("message", (evt) => {
        connInfo.receivedCount++;
        connInfo.messageCount++;
        if (connInfo.messages.length < 20) {
          connInfo.messages.push({
            direction: "IN",
            data: typeof evt.data === "string" ? evt.data.substring(0, 200) : "[binary]",
            timestamp: Date.now()
          });
        }
        sendWSUpdate(connInfo);
      });

      // Intercept send
      const origSend = ws.send.bind(ws);
      ws.send = function(data) {
        connInfo.sentCount++;
        connInfo.messageCount++;
        if (connInfo.messages.length < 20) {
          connInfo.messages.push({
            direction: "OUT",
            data: typeof data === "string" ? data.substring(0, 200) : "[binary]",
            timestamp: Date.now()
          });
        }
        sendWSUpdate(connInfo);
        return origSend(data);
      };

      return ws;
    };

    // Copy static properties
    Object.keys(OrigWebSocket).forEach(k => {
      try { window.WebSocket[k] = OrigWebSocket[k]; } catch(_) {}
    });
    window.WebSocket.prototype = OrigWebSocket.prototype;
    window.WebSocket.CONNECTING = OrigWebSocket.CONNECTING;
    window.WebSocket.OPEN = OrigWebSocket.OPEN;
    window.WebSocket.CLOSING = OrigWebSocket.CLOSING;
    window.WebSocket.CLOSED = OrigWebSocket.CLOSED;
  }

  function sendWSUpdate(connInfo) {
    chrome.runtime.sendMessage({
      type: "ADD_WEBSOCKET",
      tabId: -1,
      connection: {
        url: connInfo.url,
        protocol: connInfo.protocol,
        status: connInfo.status,
        messageCount: connInfo.messageCount,
        sentCount: connInfo.sentCount,
        receivedCount: connInfo.receivedCount,
        messages: connInfo.messages,
        timestamp: connInfo.timestamp
      }
    }).catch(()=>{});
  }

  // ── Intercept fetch for POST body capture ─────────────────
  function hookFetch() {
    const origFetch = window.fetch;
    if (!origFetch || window.__reconHawkFetchHooked) return;
    window.__reconHawkFetchHooked = true;

    window.fetch = function(input, init) {
      try {
        const url = typeof input === "string" ? input : input?.url || "";
        const method = (init?.method || "GET").toUpperCase();
        if (method === "POST" || method === "PUT" || method === "PATCH") {
          const body = init?.body;
          if (body && typeof body === "string") {
            // Try to extract params from body
            try {
              // JSON body
              const json = JSON.parse(body);
              Object.entries(json).forEach(([key, value]) => {
                chrome.runtime.sendMessage({
                  type: "ADD_PARAMS", tabId: -1,
                  params: [{ key, value: String(value).substring(0,100), source: "POST-JSON", url }]
                }).catch(()=>{});
              });
            } catch(_) {
              // Form-encoded body
              try {
                const sp = new URLSearchParams(body);
                const params = [];
                sp.forEach((value, key) => {
                  params.push({ key, value: value.substring(0,100), source: "POST-FORM", url });
                });
                if (params.length) {
                  chrome.runtime.sendMessage({ type: "ADD_PARAMS", tabId: -1, params }).catch(()=>{});
                }
              } catch(_) {}
            }
          }
        }
      } catch(_) {}
      return origFetch.apply(this, arguments);
    };
  }

  // ── XMLHttpRequest body capture ───────────────────────────
  function hookXHR() {
    const origOpen = XMLHttpRequest.prototype.open;
    const origSend = XMLHttpRequest.prototype.send;
    if (window.__reconHawkXHRHooked) return;
    window.__reconHawkXHRHooked = true;

    XMLHttpRequest.prototype.open = function(method, url) {
      this._reconMethod = method;
      this._reconUrl = url;
      return origOpen.apply(this, arguments);
    };

    XMLHttpRequest.prototype.send = function(body) {
      if (body && (this._reconMethod === "POST" || this._reconMethod === "PUT")) {
        try {
          const url = this._reconUrl || "";
          if (typeof body === "string") {
            try {
              const json = JSON.parse(body);
              const params = Object.entries(json).map(([key, value]) => ({
                key, value: String(value).substring(0,100), source: "XHR-JSON", url
              }));
              if (params.length) chrome.runtime.sendMessage({ type:"ADD_PARAMS", tabId:-1, params }).catch(()=>{});
            } catch(_) {
              try {
                const sp = new URLSearchParams(body);
                const params = [];
                sp.forEach((v,k) => params.push({ key:k, value:v.substring(0,100), source:"XHR-FORM", url }));
                if (params.length) chrome.runtime.sendMessage({ type:"ADD_PARAMS", tabId:-1, params }).catch(()=>{});
              } catch(_) {}
            }
          }
        } catch(_) {}
      }
      return origSend.apply(this, arguments);
    };
  }

  async function runScan() {
    // Hook early
    hookWebSocket();
    hookFetch();
    hookXHR();

    scanDOM();
    await scanExternalScripts();

    if (foundSecrets.length)
      chrome.runtime.sendMessage({ type:"ADD_SECRETS", tabId:-1, secrets:foundSecrets }).catch(()=>{});
    if (foundParams.length)
      chrome.runtime.sendMessage({ type:"ADD_PARAMS", tabId:-1, params:foundParams }).catch(()=>{});
    if (foundEndpoints.length)
      chrome.runtime.sendMessage({ type:"ADD_ENDPOINTS", tabId:-1, endpoints:foundEndpoints }).catch(()=>{});
    if (foundSubdomains.length)
      chrome.runtime.sendMessage({ type:"ADD_SUBDOMAINS", tabId:-1, subdomains:foundSubdomains }).catch(()=>{});

    return {
      secrets:foundSecrets.length,
      params:foundParams.length,
      endpoints:foundEndpoints.length,
      subdomains:foundSubdomains.length
    };
  }

  // Hook WebSocket immediately (before page scripts run connections)
  hookWebSocket();
  hookFetch();
  hookXHR();

  if (document.readyState==="loading") document.addEventListener("DOMContentLoaded", runScan);
  else runScan();

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type==="SCAN_NOW") {
      runScan().then(counts => sendResponse({ ok:true, ...counts }));
      return true;
    }
  });
})();
