// BountyScope — page spy (MAIN world, document_start).
// Hooks fetch / XHR / WebSocket from inside the page context. Events travel to the
// content script via window.postMessage (the relay the old tool was missing).
// URL params and request logs are NOT reported here — webRequest already covers
// those; the spy adds what only page context can see (bodies of edge-case types,
// WebSocket connections and their messages).
(() => {
  if (window.__bountyScopeSpy) return;
  window.__bountyScopeSpy = true;

  const send = (type, payload) => {
    try { window.postMessage({ source: 'bountyscope-spy', type, payload }, '*'); } catch (_) {}
  };

  function flatJS(obj, pfx, d) {
    const pairs = [];
    if (d > 6 || !obj || typeof obj !== 'object') return pairs;
    for (const [k, v] of Object.entries(obj)) {
      const key = pfx ? pfx + '.' + k : k;
      if (Array.isArray(v)) {
        if (v[0] && typeof v[0] === 'object') flatJS(v[0], key + '[0]', d + 1).forEach((p) => pairs.push(p));
        else if (v[0] != null) pairs.push([key, String(v[0])]);
      } else if (v !== null && typeof v === 'object') {
        flatJS(v, key, d + 1).forEach((p) => pairs.push(p));
      } else {
        pairs.push([key, v]);
      }
    }
    return pairs;
  }

  function extractFromBody(body, url, method, jsonTag, formTag) {
    if (!body || typeof body !== 'string' || body.length > 100000) return [];
    const out = [];
    try {
      const j = JSON.parse(body);
      if (j && typeof j === 'object') {
        flatJS(j, '', 0).forEach(([k, v]) => {
          if (k && v != null) out.push({ key: k, value: String(v).slice(0, 100), source: jsonTag, url, method });
        });
        return out;
      }
    } catch (_) {}
    if (body.includes('=') && !body.includes('<')) {
      try {
        new URLSearchParams(body).forEach((v, k) => {
          if (k) out.push({ key: k, value: String(v).slice(0, 100), source: formTag, url, method });
        });
      } catch (_) {}
    }
    return out;
  }

  // ── fetch hook ─────────────────────────────────────────────────────────────
  const _fetch = window.fetch;
  window.fetch = function (input, init) {
    try {
      const url = typeof input === 'string' ? input : (input instanceof Request ? input.url : String(input || ''));
      const method = ((init && init.method) || (input instanceof Request && input.method) || 'GET').toUpperCase();
      if (init && init.body) {
        let params = [];
        if (typeof init.body === 'string') {
          params = extractFromBody(init.body, url, method, 'POST-JSON', 'POST-FORM');
        } else if (typeof FormData !== 'undefined' && init.body instanceof FormData) {
          for (const [k, v] of init.body.entries()) {
            if (k && typeof v === 'string') params.push({ key: k, value: v.slice(0, 100), source: 'POST-FORM', url, method });
          }
        }
        if (params.length) send('ADD_PARAMS', { params });
      }
    } catch (_) {}
    return _fetch.apply(this, arguments);
  };

  // ── XHR hook ───────────────────────────────────────────────────────────────
  const _open = XMLHttpRequest.prototype.open;
  const _send = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (method, url) {
    try {
      this.__bsUrl = String(url);
      this.__bsMethod = String(method || 'GET').toUpperCase();
    } catch (_) {}
    return _open.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function (body) {
    try {
      if (body && typeof body === 'string' && this.__bsUrl) {
        const params = extractFromBody(body, this.__bsUrl, this.__bsMethod || 'POST', 'XHR-JSON', 'XHR-FORM');
        if (params.length) send('ADD_PARAMS', { params });
      }
    } catch (_) {}
    return _send.apply(this, arguments);
  };

  // ── WebSocket hook (connection monitor + message capture) ─────────────────
  const OrigWS = window.WebSocket;
  function WebSocketShim(url, protocols) {
    const ws = protocols !== undefined ? new OrigWS(url, protocols) : new OrigWS(url);
    // Resolve relative WS URLs ("/ws" is valid per spec) to absolute ws(s):// so
    // the background scope check can see the host.
    const wsUrl = (() => {
      try { return new URL(url, location.href).href.replace(/^http/i, 'ws'); }
      catch (_) { return String(url); }
    })();
    const info = {
      url: wsUrl,
      protocol: typeof protocols === 'string' ? protocols : (Array.isArray(protocols) ? protocols.join(',') : ''),
      status: 'CONNECTING', messageCount: 0, sentCount: 0, receivedCount: 0,
      messages: [], timestamp: Date.now(),
    };
    const report = () => send('ADD_WEBSOCKET', {
      connection: {
        url: info.url, protocol: info.protocol, status: info.status,
        messageCount: info.messageCount, sentCount: info.sentCount,
        receivedCount: info.receivedCount, messages: info.messages, timestamp: info.timestamp,
      },
    });
    ws.addEventListener('open', () => { info.status = 'OPEN'; report(); });
    ws.addEventListener('close', () => { info.status = 'CLOSED'; report(); });
    ws.addEventListener('error', () => { info.status = 'ERROR'; report(); });
    ws.addEventListener('message', (e) => {
      info.receivedCount++; info.messageCount++;
      if (info.messages.length >= 50) info.messages.shift(); // keep the LAST 50
      info.messages.push({
        direction: 'IN',
        data: typeof e.data === 'string' ? e.data.substring(0, 200) : '[binary]',
        timestamp: Date.now(),
      });
      report();
      if (typeof e.data === 'string') {
        const ps = extractFromBody(e.data, info.url, 'WS', 'WS', 'WS');
        if (ps.length) send('ADD_PARAMS', { params: ps });
      }
    });
    const origSend = ws.send.bind(ws);
    ws.send = function (data) {
      info.sentCount++; info.messageCount++;
      if (info.messages.length >= 50) info.messages.shift(); // keep the LAST 50
      info.messages.push({
        direction: 'OUT',
        data: typeof data === 'string' ? data.substring(0, 200) : '[binary]',
        timestamp: Date.now(),
      });
      report();
      if (typeof data === 'string') {
        const ps = extractFromBody(data, info.url, 'WS', 'WS', 'WS');
        if (ps.length) send('ADD_PARAMS', { params: ps });
      }
      return origSend(data);
    };
    report();
    return ws;
  }
  Object.setPrototypeOf(WebSocketShim, OrigWS); // inherit statics (CONNECTING, OPEN, …)
  WebSocketShim.prototype = OrigWS.prototype;   // instanceof keeps working
  window.WebSocket = WebSocketShim;
})();
