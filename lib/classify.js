// BountyScope — shared classification & param-building helpers (pure, no chrome.*).
// Param scoring/injection-type logic inherited from ReconSpider v8, generalized
// (defect D12: all NBA-specific bonuses removed).
import { isOOS } from './oos.js';

// ── Noise detectors ──────────────────────────────────────────────────────────
export const STATIC_EXT = /\.(jpg|jpeg|png|svg|webp|gif|ico|mp4|m3u8|mp3|woff2?|ttf|otf|eot|css|pdf)(\?|$)/i;
export const DATE_PATH = /\/(?:19|20)\d{2}\/(?:0[1-9]|1[0-2])\//;
const CSS_MODULE = /^[A-Za-z][A-Za-z0-9]*[-_][A-Za-z][A-Za-z0-9\-_]*[-_][A-Za-z0-9_+-]{4,12}$/;
const CSS_MODULE2 = /^[A-Za-z][A-Za-z0-9]*__[A-Za-z0-9_+-]{4,12}$/;

const NAME_BLOCK = new Set([
  'accept', 'accept-encoding', 'accept-language', 'connection', 'pragma',
  'cache-control', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform',
  'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'sec-fetch-user',
  'upgrade-insecure-requests', 'user-agent', 'te', 'dnt',
  'if-modified-since', 'if-none-match',
  'utv', 'wklz', 'gdpr_consent', 'gdpr', '_ga', '_gid', 'cb',
  'a', 'b', 'c', 'd', 'e', 'f', 'n', 'o', 'r', 's', 't', 'u', 'v', 'x', 'y', 'z',
]);
const NAME_NOISE_RE = [
  /^s\d{5,}$/, /^_\d+$/, /^\$\$\w+/, /^ng[A-Z]/, /^jQuery\d{5,}/i,
  /^__\w+__$/, /^AQ[BE]$/, /^ndh$/, /^pf$/, /^ce$/, /^mid$/,
];

export function isNoisyName(n) {
  if (!n || String(n).length < 2) return true;
  if (NAME_BLOCK.has(String(n).toLowerCase())) return true;
  return NAME_NOISE_RE.some((re) => re.test(n));
}

export function isNoisyValue(v) {
  if (!v) return false;
  const s = String(v);
  return s.length > 300 || /^[A-Za-z0-9+/=]{200,}$/.test(s) ||
    /^ut\d+\.\d+\.\d{10,}$/.test(s) || CSS_MODULE.test(s) || CSS_MODULE2.test(s);
}

// ── Injection-type classification ────────────────────────────────────────────
export function injTypes(name, value) {
  const n = String(name || '').toLowerCase();
  const v = String(value || '').toLowerCase();
  const t = new Set();
  if (/^(?:id|uid|pid|gid|cid|eid|tid|rid|oid|aid|vid|sid|.*_id|.*_num|limit|offset|page|sort|order|order_by|group_by|season)$/.test(n)) t.add('SQLi');
  if (/^(?:q|query|search|keyword|term|filter|name|title|slug|label|tag|category|locale|pagetype|platform|usertype|format|type|country|lang|language)$/.test(n)) { t.add('SQLi'); t.add('XSS'); }
  if (/^(?:msg|message|text|content|html|description|comment|feedback|note|body|display|caption|alt|output)$/.test(n)) t.add('XSS');
  if (/^(?:template|tpl|tmpl|render|engine|expression|expr|formula|layout|view)$/.test(n)) { t.add('SSTI'); t.add('XSS'); }
  if (/^(?:file|filename|filepath|path|dir|folder|load|include|require|import|doc|document|resource|module|plugin|skin|theme|component|src)$/.test(n)) { t.add('LFI'); t.add('RFI'); t.add('Path Traversal'); }
  if (v.includes('..') || v.includes('%2e%2e') || v.includes('%252e') || v.includes('%2f')) { t.add('LFI'); t.add('Path Traversal'); }
  if (/^(?:url|uri|src|source|dest|destination|redirect|return|returnurl|returnto|callback|next|goto|target|ref|referrer|origin|host|server|proxy|endpoint|webhook|ping|service|site|domain|base|baseurl|img|image|link|href|action|feed|rss|forward|to|from|location)$/.test(n)) { t.add('SSRF'); t.add('Open Redirect'); }
  if (/^https?:\/\//.test(v)) { t.add('SSRF'); t.add('Open Redirect'); }
  if (/^(?:cmd|command|exec|run|eval|execute|shell|bash|sh|powershell|system|popen|spawn|proc|pipe|subprocess|invoke)$/.test(n)) { t.add('OS CMD'); t.add('RCE'); }
  if (/^(?:xml|soap|wsdl|dtd|schema|xsl|xslt|entity)$/.test(n)) t.add('XXE');
  if (/^(?:token|auth|jwt|access_token|refresh_token|api_key|apikey|key|secret|hash|sig|signature|nonce|bearer|password|passwd|pwd|passphrase)$/.test(n)) { t.add('Auth Bypass'); t.add('Token Replay'); }
  if (/.*_id$/.test(n) || /^(?:user|account|customer|member|client|org|player|team|role)$/.test(n)) t.add('IDOR');
  if (/^(?:upload|attachment|photo|avatar|media|image|document|import)$/.test(n)) { t.add('File Upload RCE'); t.add('LFI'); }
  if (t.size === 0) { t.add('XSS'); t.add('SQLi'); }
  return [...t];
}

// ── Scoring ──────────────────────────────────────────────────────────────────
const SRC_SCORE = {
  graphql: 35, post_json: 30, 'POST-JSON': 30, post_form: 28, 'POST-FORM': 28,
  'XHR-JSON': 26, 'XHR-FORM': 26, xml_body: 28, hidden_input: 25, form_field: 22,
  FORM: 22, react_input: 22, ajax_call: 22, window_config: 22, request_header: 20,
  js_analysis: 18, data_attribute: 18, JS: 18, url_parameter: 15, URL: 15,
  hash_parameter: 12, path_segment: 10, html_comment: 10, cookie: 8,
  anchor_href: 8, LINK: 8, 'DOM-REFLECT': 30,
};

export function scoreParam(name, value, source, hostname) {
  let sc = 0;
  const n = String(name || '').toLowerCase();
  const v = String(value || '').toLowerCase();
  sc += SRC_SCORE[source] || 8;
  if (/^(?:cmd|command|exec|eval|shell|bash|system|run)$/.test(n)) sc += 60;
  if (/^(?:template|tpl|render|expression|engine|view)$/.test(n)) sc += 50;
  if (/^(?:file|path|dir|load|include|require|resource)$/.test(n)) sc += 45;
  if (/^(?:url|uri|redirect|callback|webhook|proxy|dest|next|src|source|forward|goto)$/.test(n)) sc += 45;
  if (/^(?:query|search|q|filter|where|season)$/.test(n)) sc += 35;
  if (/^(?:token|auth|jwt|key|secret|password|sig|api_key|apikey)$/.test(n)) sc += 35;
  if (/.*_id$/.test(n) || /^(?:id|uid)$/.test(n)) sc += 30;
  if (/^(?:upload|attachment|media)$/.test(n)) sc += 30;
  if (/^(?:platform|format|type|country|locale|pagetype|usertype|lang)$/.test(n)) sc += 20;
  if (/^(?:region|cid|stat)$/.test(n)) sc += 15;
  if (v && /^\d{2,15}$/.test(v)) sc += 8;
  if (v && /^https?:\/\//.test(v)) sc += 20;
  if (v && v.includes('..')) sc += 15;
  // Generic high-value-host heuristic (replaces the old NBA-specific bonuses)
  if (/(?:^|\.)(?:auth|account|api|admin|login|secure|portal)\./.test(hostname)) sc += 25;
  return sc;
}

export function buildParam(name, value, source, url, method) {
  if (!name || isNoisyName(name) || isNoisyValue(value)) return null;
  let hostname = '';
  try { hostname = new URL(url).hostname.toLowerCase(); } catch (_) {}
  if (hostname && isOOS(hostname)) return null;
  const sc = scoreParam(name, value, source, hostname);
  return {
    key: String(name),
    name: String(name),
    value: String(value || '').substring(0, 300),
    source,
    url: url || '',
    method: method || 'GET',
    injectionTypes: injTypes(name, value),
    score: sc,
    confidence: sc >= 55 ? 'HIGH' : sc >= 20 ? 'MEDIUM' : 'LOW',
    interesting: /^(?:id|uid|.*_id|q|query|search|url|redirect|file|path|token|auth|jwt|key|secret|cmd|template|platform|format|season|src|source|dest|callback|webhook)$/i.test(name),
    isCSRF: /csrf|xsrf|_token|authenticity_token|__RequestVerificationToken/i.test(name),
    timestamp: Date.now(),
  };
}

// ── URL extraction (params, hash params, path segments) ─────────────────────
export function extractURL(urlStr, method) {
  const out = [];
  try {
    const u = new URL(urlStr);
    const path = u.pathname;
    const isStatic = STATIC_EXT.test(urlStr);
    const isDatePath = DATE_PATH.test(path);
    if (/^\/akam\//.test(path)) return [];

    u.searchParams.forEach((val, key) => {
      if (isNoisyName(key) || isNoisyValue(val)) return;
      const p = buildParam(key, val, 'url_parameter', urlStr, method || 'GET');
      if (p) out.push(p);
    });

    if (u.hash && u.hash.includes('=')) {
      new URLSearchParams(u.hash.slice(1)).forEach((val, key) => {
        if (isNoisyName(key) || isNoisyValue(val)) return;
        const p = buildParam(key, val, 'hash_parameter', urlStr, method || 'GET');
        if (p) out.push(p);
      });
    }

    if (!isStatic && !isDatePath) {
      const segs = path.split('/').filter(Boolean);
      segs.forEach((seg, i) => {
        if (/^\d{2,15}$/.test(seg)) {
          if (/^20[12]\d$/.test(seg) || /^0[1-9]$|^1[0-2]$/.test(seg)) return;
          const pname = (segs[i - 1] ? segs[i - 1].replace(/s$/, '') + '_id' : 'path_id');
          const p = buildParam(pname, seg, 'path_segment', urlStr, method || 'GET');
          if (p) out.push(p);
        }
        if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg)) {
          const pname = (segs[i - 1] ? segs[i - 1].replace(/s$/, '') + '_uuid' : 'path_uuid');
          const p = buildParam(pname, seg, 'path_segment', urlStr, method || 'GET');
          if (p) out.push(p);
        }
      });
    }
  } catch (_) {}
  return out;
}

// ── Request-body parsing (GraphQL / JSON / XML / form / raw) ────────────────
export function decodeBytes(raw) {
  try { return new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(raw)); }
  catch (_) { return null; }
}

function flatten(obj, pfx, depth) {
  const pairs = [];
  if (depth > 8 || !obj || typeof obj !== 'object') return pairs;
  for (const [k, v] of Object.entries(obj)) {
    const key = pfx ? pfx + '.' + k : k;
    if (Array.isArray(v)) {
      if (v[0] && typeof v[0] === 'object') flatten(v[0], key + '[0]', depth + 1).forEach((p) => pairs.push(p));
      else if (v[0] !== undefined) pairs.push([key, String(v[0])]);
    } else if (v !== null && typeof v === 'object') {
      flatten(v, key, depth + 1).forEach((p) => pairs.push(p));
    } else {
      pairs.push([key, v]);
    }
  }
  return pairs;
}

export function parseBody(bodyStr, ct, url, method) {
  if (!bodyStr || !bodyStr.trim()) return [];
  const out = [];
  if (bodyStr.includes('"operationName"') || bodyStr.includes('"query"') || bodyStr.includes('"mutation"')) {
    try {
      const g = JSON.parse(bodyStr);
      const gout = [];
      if (g.operationName) gout.push(buildParam('gql_operation', String(g.operationName), 'graphql', url, method));
      if (g.query) gout.push(buildParam('gql_query', String(g.query).slice(0, 300), 'graphql', url, method));
      if (g.variables && typeof g.variables === 'object') {
        flatten(g.variables, 'var', 0).forEach(([k, v]) => {
          if (k && v != null) gout.push(buildParam(k, String(v).slice(0, 300), 'graphql', url, method));
        });
      }
      const valid = gout.filter(Boolean);
      if (valid.length) return valid;
    } catch (_) {}
  }
  try {
    const parsed = JSON.parse(bodyStr);
    if (parsed && typeof parsed === 'object') {
      flatten(parsed, '', 0).forEach(([k, v]) => {
        if (!k || isNoisyName(k) || v == null) return;
        const p = buildParam(k, String(v).slice(0, 300), 'post_json', url, method);
        if (p) out.push(p);
      });
      if (out.length) return out;
    }
  } catch (_) {}
  if ((ct && (ct.includes('xml') || ct.includes('soap'))) || bodyStr.trimStart().startsWith('<')) {
    const re = /<([a-zA-Z][\w:.-]{0,60})(?:\s[^>]*)?>([^<]{1,300})<\/\1>/g;
    let m;
    while ((m = re.exec(bodyStr)) !== null) {
      const name = m[1].replace(/^[^:]+:/, '');
      const val = m[2].trim();
      if (!name || isNoisyName(name) || !val) continue;
      const p = buildParam(name, val, 'xml_body', url, method);
      if (p) out.push(p);
    }
    if (out.length) return out;
  }
  if (bodyStr.includes('=')) {
    try {
      new URLSearchParams(bodyStr).forEach((v, k) => {
        if (isNoisyName(k) || isNoisyValue(v)) return;
        const p = buildParam(k, v.slice(0, 300), 'post_form', url, method);
        if (p) out.push(p);
      });
      if (out.length) return out;
    } catch (_) {}
  }
  if (bodyStr.length < 800 && !isNoisyValue(bodyStr)) {
    const p = buildParam('_raw_body', bodyStr.slice(0, 400), 'raw_body', url, method);
    return p ? [p] : [];
  }
  return [];
}

// ── Security-header audit (once per host) ───────────────────────────────────
export function analyzeHeaders(headers, url, hostKey) {
  if (!headers) return [];
  const checks = {
    'x-frame-options':            { risk: 'MEDIUM', desc: 'Clickjacking protection' },
    'content-security-policy':    { risk: 'HIGH',   desc: 'XSS protection policy' },
    'strict-transport-security':  { risk: 'HIGH',   desc: 'HTTPS enforcement (HSTS)' },
    'x-content-type-options':     { risk: 'LOW',    desc: 'MIME sniffing protection' },
    'x-xss-protection':           { risk: 'MEDIUM', desc: 'Browser XSS filter' },
    'referrer-policy':            { risk: 'LOW',    desc: 'Referrer information control' },
    'permissions-policy':         { risk: 'LOW',    desc: 'Browser feature permissions' },
    'server':                     { risk: 'INFO',   desc: 'Server technology disclosure' },
    'x-powered-by':               { risk: 'INFO',   desc: 'Technology stack disclosure' },
    'access-control-allow-origin':{ risk: 'HIGH',   desc: 'CORS policy' },
    'set-cookie':                 { risk: 'MEDIUM', desc: 'Cookie security flags' },
  };
  const map = {};
  headers.forEach((h) => { map[h.name.toLowerCase()] = h.value; });
  return Object.entries(checks).map(([header, info]) => ({
    _host: hostKey, url, header,
    value: map[header] || 'MISSING',
    present: !!map[header],
    risk: map[header] ? 'OK' : info.risk,
    desc: info.desc,
  }));
}

// ── Endpoint classification (superset; ReconHawk badge types) ────────────────
export function detectEndpointType(path) {
  const p = String(path || '');
  if (/graphql/i.test(p)) return 'GRAPHQL';
  if (p.match(/\.(php|asp|aspx|jsp|py|rb|go|cfm)$/i)) return 'SERVER-SIDE';
  if (p.match(/\/api\/|\/v\d+\//i)) return 'API';
  if (p.match(/\.(json|xml|yaml)$/i)) return 'DATA';
  if (p.match(/\.(js|ts|mjs)$/i)) return 'JS';
  if (p.match(/admin|panel|dashboard|login|auth|signin|sso|oauth|manage|config|setup|phpmy|wp-admin|actuator/i)) return 'SENSITIVE';
  if (p.match(/upload|file|import|export|download/i)) return 'FILE';
  if (p.match(/\.(js\.map|json\.map)$/i)) return 'SOURCEMAP';
  return 'PAGE';
}

export function classifyEndpoint(urlOrPath) {
  try {
    return detectEndpointType(new URL(urlOrPath).pathname);
  } catch (_) {
    return detectEndpointType(urlOrPath);
  }
}
