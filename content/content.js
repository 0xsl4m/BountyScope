// BountyScope — content script (ISOLATED world, document_start).
// 1) Relays MAIN-world page_spy events to the background (D1 fix — the old tools
//    lost all fetch/XHR/WS data here).
// 2) DOM recon: anchors, forms (+ shadow DOM), data attributes, HTML comments,
//    cookie names, window config objects, reflections, inline & external JS.
// All items are pre-filtered client-side (same-site only) and re-checked against
// the real target scope by the background.
(() => {
  if (window.__bountyScopeContent) return;
  window.__bountyScopeContent = true;

  const send = (type, extra) => {
    try { chrome.runtime.sendMessage(Object.assign({ type }, extra)).catch(() => {}); } catch (_) {}
  };

  // ── D1 relay: page_spy (MAIN world) → background ──────────────────────────
  // Strict type whitelist: a hostile page could otherwise abuse the relay to
  // inject arbitrary store mutations.
  window.addEventListener('message', (e) => {
    if (e.source !== window || !e.data || e.data.source !== 'bountyscope-spy' || !e.data.type) return;
    if (e.data.type !== 'ADD_PARAMS' && e.data.type !== 'ADD_WEBSOCKET') return;
    send(e.data.type, e.data.payload || {});
  });

  // ── Client-side pre-filter ────────────────────────────────────────────────
  function getBaseDomain() {
    try { const p = location.hostname.split('.'); return p.slice(-2).join('.'); }
    catch (_) { return location.hostname; }
  }
  function sameSite(url) {
    try {
      const h = new URL(url, location.href).hostname.toLowerCase();
      const b = getBaseDomain();
      return h === b || h.endsWith('.' + b);
    } catch (_) { return false; }
  }

  const INTERESTING_DATA = /^data-(?:id|src|url|token|key|auth|api|endpoint|path|redirect|user|player|team|game|season|league|config|json|payload)$/i;
  const INTERESTING_COOKIE = /^(?:session|token|auth|jwt|csrf|login|user|account|access|refresh|sid)/i;
  const WINDOW_TARGETS = [
    '__NEXT_DATA__', '__NEXT_PUBLIC__', '__INITIAL_STATE__', '__REDUX_STATE__',
    '__APOLLO_STATE__', '__RELAY_STORE__', '__APP_CONFIG__', '__ENV__',
    '__NUXT__', '__APP_DATA__', 'siteConfig', 'appConfig', '__data', '__state',
  ];

  // ── Scanners (raw items; background classifies + scopes + dedupes) ────────
  function scanAnchors(params, endpoints) {
    document.querySelectorAll('a[href]').forEach((a) => {
      try {
        const u = new URL(a.href, location.href);
        if (!sameSite(u.href)) return;
        u.searchParams.forEach((val, key) => {
          if (key) params.push({ key, value: val.slice(0, 300), source: 'LINK', url: u.href, method: 'GET' });
        });
        if (u.pathname && u.pathname.length > 1) {
          endpoints.push({ path: u.pathname, url: u.href, method: 'GET' });
        }
      } catch (_) {}
    });
  }

  function collectForms(root, params) {
    root.querySelectorAll('input, select, textarea').forEach((el) => {
      const name = el.name || el.id || el.getAttribute('data-name');
      if (!name || String(name).length < 2) return;
      let actionUrl = location.href;
      const form = el.closest('form');
      if (form) {
        try { actionUrl = new URL(form.getAttribute('action') || location.href, location.href).href; } catch (_) {}
      }
      const method = ((form && form.getAttribute('method')) || 'GET').toUpperCase();
      params.push({
        key: name,
        value: String(el.value || el.getAttribute('placeholder') || '').slice(0, 300),
        source: 'FORM', url: actionUrl, method,
      });
    });
  }

  function scanForms(params) {
    collectForms(document, params);
    document.querySelectorAll('*').forEach((el) => {
      if (el.shadowRoot) { try { collectForms(el.shadowRoot, params); } catch (_) {} }
    });
  }

  function scanDataAttrs(params) {
    document.querySelectorAll('[data-id],[data-src],[data-url],[data-token],[data-key],[data-auth],[data-api],[data-endpoint],[data-path],[data-redirect],[data-user],[data-player],[data-team],[data-game],[data-season],[data-league],[data-config]').forEach((el) => {
      [...el.attributes].forEach((attr) => {
        if (!INTERESTING_DATA.test(attr.name)) return;
        const val = attr.value;
        if (!val || val.length < 2 || val.length > 300) return;
        params.push({ key: attr.name.replace('data-', ''), value: val, source: 'data_attribute', url: location.href, method: 'GET' });
      });
    });
  }

  function scanComments(secrets) {
    const walker = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT);
    let node;
    const kvRe = /(?:api[_-]?key|token|secret|password|auth)\s*[=:]\s*([^\s"'<>]{8,100})/gi;
    while ((node = walker.nextNode())) {
      const text = node.textContent || '';
      if (text.length < 10) continue;
      kvRe.lastIndex = 0;
      let m;
      while ((m = kvRe.exec(text)) !== null) {
        secrets.push({
          name: 'Secret in HTML Comment', risk: 'MEDIUM',
          value: m[1].slice(0, 200), context: text.slice(0, 300),
          source: location.href,
        });
      }
    }
  }

  function scanCookieNames(secrets) {
    document.cookie.split(';').forEach((c) => {
      const name = c.split('=')[0].trim();
      if (!name || !INTERESTING_COOKIE.test(name)) return;
      secrets.push({
        name: 'Interesting Cookie Name', risk: 'MEDIUM',
        value: name, context: 'Cookie found: ' + name, source: location.href,
      });
    });
  }

  function scanWindowConfig(params) {
    WINDOW_TARGETS.forEach((key) => {
      try {
        let obj = window;
        key.split('.').forEach((k) => { obj = obj?.[k]; });
        if (!obj || typeof obj !== 'object') return;
        JSON.stringify(obj).match(/"([^"]+)"\s*:\s*"([^"]{4,200})"/g)?.slice(0, 40).forEach((kv) => {
          const [, k, v] = kv.match(/"([^"]+)"\s*:\s*"([^"]+)"/) || [];
          if (k && v) params.push({ key: k, value: v.slice(0, 300), source: 'window_config', url: location.href, method: 'GET' });
        });
      } catch (_) {}
    });
  }

  function testReflections() {
    const refs = [];
    try {
      const u = new URL(location.href);
      const body = document.body?.innerHTML || '';
      u.searchParams.forEach((val, name) => {
        if (!val || val.length < 6) return;
        if (body.includes(val)) {
          refs.push({
            param: name, url: location.href, payloadType: 'DOM-REFLECT', status: '—',
            reflected: true, timestamp: Date.now(),
          });
        }
      });
    } catch (_) {}
    return refs;
  }

  function collectScriptUrls() {
    const urls = [];
    document.querySelectorAll('script[src]').forEach((s) => {
      try {
        const abs = new URL(s.src, location.href).href;
        if (sameSite(abs) && !urls.includes(abs)) urls.push(abs);
      } catch (_) {}
    });
    return urls.slice(0, 25);
  }

  function runScan() {
    const params = [];
    const endpoints = [];
    const secrets = [];
    scanAnchors(params, endpoints);
    scanForms(params);
    scanDataAttrs(params);
    scanWindowConfig(params);
    scanComments(secrets);
    scanCookieNames(secrets);

    if (params.length) send('ADD_PARAMS', { params });
    if (endpoints.length) send('ADD_ENDPOINTS', { endpoints });
    if (secrets.length) send('ADD_SECRETS', { secrets });
    testReflections().forEach((r) => send('ADD_PAYLOAD_RESULT', { result: r }));

    // Inline scripts → background analysis (secret + endpoint extraction)
    let inline = 0;
    document.querySelectorAll('script:not([src])').forEach((s) => {
      const code = s.textContent || '';
      if (code.length > 20 && inline < 10) {
        inline++;
        send('ANALYZE_JS', { code: code.slice(0, 200000), scriptUrl: location.href + '[inline]' });
      }
    });

    // External in-scope scripts → background fetch + analyze + source maps (D7)
    const urls = collectScriptUrls();
    if (urls.length) send('SCAN_SCRIPTS', { urls });

    return { params: params.length, endpoints: endpoints.length, secrets: secrets.length };
  }

  chrome.runtime.onMessage.addListener((msg, _sender, respond) => {
    if (msg && msg.type === 'SCAN_NOW') {
      const counts = runScan();
      respond(Object.assign({ ok: true }, counts));
      return true;
    }
  });

  // ── SPA coverage: re-scan on route changes + DOM mutations (debounced) ─────
  // One-shot DOMContentLoaded misses everything a modern SPA renders later.
  let scanPending = false;
  function scheduleRescan() {
    if (scanPending) return;
    scanPending = true;
    setTimeout(() => { scanPending = false; try { runScan(); } catch (_) {} }, 1500);
  }
  try {
    const _push = history.pushState, _replace = history.replaceState;
    history.pushState = function () { const r = _push.apply(this, arguments); scheduleRescan(); return r; };
    history.replaceState = function () { const r = _replace.apply(this, arguments); scheduleRescan(); return r; };
    window.addEventListener('popstate', scheduleRescan);
  } catch (_) {}
  try {
    const mo = new MutationObserver(() => scheduleRescan());
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => mo.observe(document.documentElement, { childList: true, subtree: true }), { once: true });
    } else {
      mo.observe(document.documentElement, { childList: true, subtree: true });
    }
  } catch (_) {}

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => runScan(), { once: true });
  } else {
    runScan();
  }
})();
