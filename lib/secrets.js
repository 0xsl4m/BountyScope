// BountyScope — unified secret detection patterns.
// Strict, context-required variants preferred (inherited from the ReconSpider v8
// false-positive overhaul); prefixed vendor tokens need no context.
export const SECRET_PATTERNS = [
  { name: 'JWT Token',          risk: 'CRITICAL', re: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
  { name: 'AWS Access Key',     risk: 'CRITICAL', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'AWS Secret Key',     risk: 'CRITICAL', re: /(?:aws_secret_access_key|aws_secret|secretAccessKey)\s*[=:"'\s]+([A-Za-z0-9/+]{40})\b/i },
  { name: 'Google API Key',     risk: 'CRITICAL', re: /\bAIza[0-9A-Za-z\-_]{35}\b/ },
  { name: 'Google OAuth Client',risk: 'HIGH',     re: /\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b/ },
  { name: 'Stripe Secret Key',  risk: 'CRITICAL', re: /\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{20,}\b/ },
  { name: 'Stripe Public Key',  risk: 'MEDIUM',   re: /\bpk_(?:live|test)_[0-9a-zA-Z]{20,}\b/ },
  { name: 'Slack Token',        risk: 'CRITICAL', re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/ },
  { name: 'GitHub Token',       risk: 'CRITICAL', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { name: 'Private Key',        risk: 'CRITICAL', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/ },
  { name: 'Auth Bearer Token',  risk: 'HIGH',     re: /(?:Authorization|Bearer|X-Auth-Token|X-API-Key)\s*[=:"':\s]+([A-Za-z0-9\-_.]{20,500})/i },
  { name: 'Akamai Edge Token',  risk: 'HIGH',     re: /hdnts=[a-z0-9%=&~]{10,}/ },
  { name: 'Internal IP Endpoint', risk: 'HIGH',   re: /https?:\/\/(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)[\d.]{3,15}/ },
  { name: 'App Secret',         risk: 'HIGH',     re: /(?:api[_-]?secret|client[_-]?secret|app[_-]?secret|consumer[_-]?secret)\s*[=:"':\s]+['"`]?([A-Za-z0-9\-_.]{10,100})['"`]?/i },
  { name: 'Hardcoded Password', risk: 'CRITICAL', re: /["'](?:password|passwd|pwd)["']\s*:\s*["']([^"']{6,100})["']/i },
  { name: 'API Token (context)',risk: 'HIGH',     re: /(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret[_-]?key|private[_-]?key|serviceAccountKey)\s*[=:"':\s]+['"`]([A-Za-z0-9\-_.+/]{32,})['"`]/i },
  { name: 'SMTP Credentials',   risk: 'HIGH',     re: /(?:smtp|mail)[._-]?(?:password|pass|secret)\s*[=:"':\s]+['"`]([^'"`]{8,100})['"`]/i },
  { name: 'MongoDB URI',        risk: 'CRITICAL', re: /mongodb(?:\+srv)?:\/\/[^\s'"<>]+/i },
  { name: 'SQL DB URI',         risk: 'CRITICAL', re: /(?:mysql|postgresql|postgres):\/\/[^\s'"<>]+/i },
  { name: 'SendGrid Key',       risk: 'HIGH',     re: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/ },
  { name: 'Firebase URL',       risk: 'MEDIUM',   re: /https:\/\/[a-z0-9-]+\.firebaseio\.com/ },
];

// Scan code/text; returns [{name, risk, value, context}]
export function scanSecrets(code) {
  const out = [];
  if (!code || code.length < 10) return out;
  for (const { name, risk, re } of SECRET_PATTERNS) {
    const gre = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
    let m;
    while ((m = gre.exec(code)) !== null) {
      const val = (m[1] || m[0]).trim();
      if (!val || val.length < 8) continue;
      if (/^[a-f0-9]{8,16}$/.test(val)) continue;              // build hashes
      if (/^(?:on[A-Z]|data-|swiper-|next-|css-)/.test(val)) continue; // HTML/CSS attrs
      out.push({
        name,
        risk,
        value: val.slice(0, 200),
        context: code.substring(Math.max(0, m.index - 40), m.index + 120).replace(/\n/g, ' ').slice(0, 250),
      });
    }
  }
  return out;
}
