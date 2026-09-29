# 🎯 BountyScope

> Scope-first web reconnaissance & vulnerability scanner — a Chrome extension for bug
> bounty hunters and authorized pentesters.

**⚠ Authorized use only.** BountyScope sends real requests (including your session
cookies) to targets you point it at. Only use it on assets you own or have explicit
permission to test.

## What it does

**Passive recon** (while you browse):
- Parameters from URLs, POST bodies (JSON / form / XML / GraphQL), request headers,
  path segments, forms, anchors, data attributes and `window` config objects
- Endpoints from requests, JS files, source maps and inline scripts
- Secrets (API keys, tokens, private keys, DB URIs) with context-required patterns
- Subdomains, security-header audit, WebSocket monitoring, JWT decoding

**Active testing** (explicit scope required, conservative defaults):
- Evidence-based vulnerability scanner: SQLi (error / boolean / time), XSS, Blind XSS,
  LFI, RFI, RCE/OS command, SSTI, SSRF, XXE, Open Redirect
- Every finding requires concrete evidence — baseline comparison, 3-round boolean
  confirmation, double-confirmed time-based SQLi, reflection gated to HTML responses
- Lightweight fuzzer, IDOR probe, GraphQL introspection, API-doc discovery

**Workflow**: per-tab sessions, save/restore/import, export to Burp / sqlmap / ffuf /
nuclei / curl / CSV / Markdown / JSON.

## Trust & privacy

- **All data stays local** — no telemetry; the only network traffic is to the targets
  you scan (and your Blind XSS collector, if you configure one).
- Data reported by **in-scope pages** (DOM/network observation) is trusted as in-scope
  observation. On wildcard scopes that include user-generated-content hosts, treat
  findings as leads, not ground truth.
- "Confirmed" means: reflection found in HTML responses only (verbatim echoes are
  reported as unconfirmed leads), boolean SQLi verified across 3 consecutive rounds,
  time-based SQLi double-confirmed, signature matches excluded against a per-request
  baseline. Always manually verify before reporting.
- Active scans run in an **offscreen document** — closing the popup does not stop
  them; reopen it to watch live progress.

## Install (load unpacked)

1. `git clone https://github.com/0xsl4m/BountyScope.git`
2. Open `chrome://extensions` → enable **Developer mode**
3. **Load unpacked** → select the cloned folder
4. Open the popup, set your target scope, browse the target, then scan.

## Status

v1.0.0-alpha — active development. See [CHANGELOG](CHANGELOG.md).

## License

[MIT](LICENSE)
