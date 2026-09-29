# 🎯 BountyScope

> **Scope-first web reconnaissance & vulnerability scanner** — a Chrome extension for
> bug bounty hunters and authorized pentesters. Map a target's attack surface while
> you browse, then run an evidence-based active scanner where **every finding must
> prove itself** — no noise, no "maybe", exploit hints included.

![Chrome](https://img.shields.io/badge/Chrome-111%2B-4285F4?logo=googlechrome&logoColor=white)
![Manifest](https://img.shields.io/badge/Manifest-V3-34A853)
![License](https://img.shields.io/badge/License-MIT-blue)
![Tests](https://img.shields.io/badge/Audits-5%20review%20rounds-8A2BE2)

---

## ⚠️ Authorized Use Only

BountyScope sends **real requests — including your session cookies** — to targets you
point it at. Use it **only** on assets you own or have explicit written permission to
test (your own labs, bug bounty programs in scope, authorized engagements).
The authors accept no liability for misuse.

---

## 📖 Table of Contents

- [What It Does](#-what-it-does)
- [Installation](#-installation)
- [Quick Start (First Scan in 5 Minutes)](#-quick-start-first-scan-in-5-minutes)
- [Setting Your Target Scope](#-setting-your-target-scope)
- [Passive Recon (While You Browse)](#-passive-recon-while-you-browse)
- [Active Scanner (Evidence-Based)](#-active-scanner-evidence-based)
- [Other Tools](#-other-tools)
- [Sessions & Export](#-sessions--export)
- [How "Confirmed" Works](#-how-confirmed-works)
- [Safety Gates & Privacy](#-safety-gates--privacy)
- [Troubleshooting & FAQ](#-troubleshooting--faq)
- [Architecture (For Contributors)](#-architecture-for-contributors)
- [Testing Legally (Local Labs)](#-testing-legally-local-labs)
- [Known Limitations](#-known-limitations)
- [Credits & License](#-credits--license)

---

## 🔍 What It Does

BountyScope works in two layers:

**1. Passive recon — collects while you browse.** A service worker watches all
in-scope traffic, a content script maps the DOM, and a MAIN-world spy hooks the
page's own `fetch` / `XHR` / `WebSocket`. You get, with zero effort:

| Pane | What it captures |
|---|---|
| **Params** | URL params, POST bodies (JSON / form / XML / GraphQL), path-segment IDs & UUIDs, injection-relevant request headers, form fields (incl. shadow DOM), anchor links, `data-*` attributes, JS `window` config objects |
| **Endpoints** | From requests, inline scripts, external JS files, **source maps** (`sourcesContent` is scanned too) |
| **Secrets** | 21 strict, context-required patterns: AWS / Google / GitHub / Slack / Stripe keys, JWTs, private keys, MongoDB & SQL URIs, SMTP creds, hardcoded passwords, internal IPs, Akamai edge tokens… |
| **Requests / Headers** | Live request log + a per-host security-header audit (CSP, HSTS, X-Frame-Options, CORS…) |
| **Subdomains** | Extracted from JS content against your target base |
| **WebSocket** | Every connection with live status and the **last 50 messages IN/OUT** |
| **Reflect** | Params whose values are reflected in the current DOM |

**2. Active scanner — probes with evidence.** One click runs SQLi (error / boolean /
time), XSS, Blind XSS, LFI, RFI, OS-command injection, SSTI, SSRF, XXE and
Open-Redirect tests against your captured params — and only reports a finding when
the response contains **concrete proof** (see
[How "Confirmed" Works](#-how-confirmed-works)). Scans run in a dedicated
**offscreen document**, so closing the popup does **not** stop them.

Plus a complete workflow: per-target **sessions**, **exports** to Burp / sqlmap /
ffuf / nuclei / curl, a **JWT decoder** with security checks, **GraphQL
introspection**, **API-doc discovery**, a heuristic **fuzzer**, an **IDOR probe**,
and **custom payloads** that feed both the fuzzer and the scanner.

---

## 📦 Installation

### Requirements

- **Google Chrome 111+** (uses Manifest V3 content scripts with `"world": "MAIN"`
  and the offscreen API). Edge 111+ generally works too.
- No build step, no dependencies, no external services — everything runs locally.

### Steps

1. **Get the code** — either:
   ```bash
   git clone https://github.com/0xsl4m/BountyScope.git
   ```
   …or download the repo as ZIP from GitHub and extract it.

2. **Open the extensions page** — navigate to:
   ```
   chrome://extensions
   ```

3. **Enable Developer mode** — toggle it in the top-right corner.

4. **Load the extension** — click **Load unpacked**, then select the cloned/extracted
   **`BountyScope` folder** (the one containing `manifest.json` — not a parent folder).

5. **Pin it** — click the puzzle-piece icon in the toolbar and pin 🎯 **BountyScope**.

6. That's it. The extension shows `BountyScope 1.0.0` with zero errors on the
   extensions page. Open any website, click the icon, and continue to
   [Quick Start](#-quick-start-first-scan-in-5-minutes).

### Updating

`git pull` inside the folder, then press the **↻ reload** icon on the extension's
card in `chrome://extensions`.

---

## 🚀 Quick Start (First Scan in 5 Minutes)

1. **Open the popup** and click the red **NO SCOPE** chip in the header.
2. **Set your target** — type `localhost` (or `*.example.com`), pick **Exact** (or
   **Wildcard**), press **✓ Apply**. The chip turns green.
3. **Browse the target** normally. Watch the sidebar counters fill: params,
   endpoints, secrets, requests, subdomains…
4. Optionally press **⚡ Scan** in the header — re-runs DOM/JS recon on demand.
5. Open the **💥 Scanner** tab, choose the vuln types (or leave *All Vuln Types*),
   confirm the dialog — the scan runs in the background even if you close the popup.
6. Confirmed findings appear in the **Scanner** pane with evidence and exploit hints.
7. **📤 Export** → Markdown report, Burp XML, sqlmap commands — go build your report.

> **Tip:** test it against a local lab first — see
> [Testing Legally](#-testing-legally-local-labs).

---

## 🎯 Setting Your Target Scope

Click the scope chip in the header (or the warning overlay) to open the modal:

| Mode | Example | Behavior |
|---|---|---|
| **Exact** | `example.com` | Captures + allows testing on `example.com` only |
| **Wildcard ✦** | `*.example.com` | `example.com` **and every subdomain** |
| **No Filter** | *(leave empty)* | **Passive capture on everything** — and **all active testing is disabled** (by design: never fire payloads at domains you didn't choose) |

The scope is **per tab** and persists across popup opens. An always-on
**out-of-scope blocklist** (ad networks, tag managers, social CDNs…) is applied on
top of your scope for both capture and scanning.

---

## 🕵️ Passive Recon (While You Browse)

Runs automatically the moment a target is set. Notes:

- **POST/GraphQL bodies** are parsed and flattened — `variables.user.email` shows up
  as its own param.
- **JS & source maps** are fetched through the privileged background (bypasses page
  CORS, so you see far more than DevTools-init scans) and scanned for secrets,
  endpoints and subdomains. Source-map `sourcesContent` is analyzed too — the
  original TS/Vue code often leaks more than the bundle.
- **SPA-friendly:** route changes (`pushState`/`replaceState`/`popstate`) and DOM
  mutations trigger automatic re-scans (budget-capped per page).
- Press **⚡ Scan** any time to force a full re-scan of the current page.

---

## 💥 Active Scanner (Evidence-Based)

Open the **💥 Scanner** tab:

- **Vuln types:** All, or individually — `SQLi (Error/Boolean/Time)`, `XSS`,
  `LFI / Path Traversal`, `RFI`, `SSRF`, `SSTI`, `OS Command Injection`, `XXE`,
  `Open Redirect`.
- **Param filter:** all in-scope / HIGH confidence only / URL params only / POST
  params only. Hard cap: **50 params per run**.
- **Delay & Threads:** conservative defaults (500 ms, 2 threads) — raise the delay
  on production targets.
- **🪤 Canary:** paste your Blind-XSS collector URL (e.g. `xss.report` / Burp
  Collaborator). **Blind XSS payloads fire only when a canary is configured** —
  they never touch third-party collectors by default.
- **Start Scan** → a confirmation dialog shows the target, request count and
  estimated duration. Accept → the scan runs in an **offscreen document**:
  - Close the popup freely — the scan continues.
  - Reopen the popup → live progress resumes.
  - **■ Stop** halts it mid-run; findings already made are saved.
- **Smart mode** (the default *All Vuln Types* option) maps each param to the
  injection types its name implies (`file=` → LFI/RFI, `url=` → SSRF/redirect,
  `cmd=` → OS CMD…), and always adds SQLi + XSS.

Every confirmed finding shows: severity, payload, **evidence** (the exact matched
response excerpt), detection method, URL, and a ready-made **exploit hint**
(sqlmap / dalfox / ffuf commands tailored to the param).

---

## 🧰 Other Tools

| Tool | What it does |
|---|---|
| **🔫 Fuzzer** | Heuristic quick-pass: injects payloads, flags status/size deltas. Query-string params only (body/path params belong to the scanner). Parallel workers, configurable delay. |
| **🔁 IDOR** | Swaps numeric `id`-style params with test values; flags same-status/similar-size responses for manual review. |
| **🌐 CORS** | **Passive** detection: flags `ACAO: *`, `ACAO: null`, and `ACAC: true` observed in real responses (browsers cannot forge the Origin header — claims of "active CORS testing" from an extension are fake). |
| **◈ GraphQL** | Probes common GraphQL paths + discovered endpoints with an introspection query; lists exposed types and field counts. |
| **🔐 JWT** | Decode any token pasted in — flags `alg:none`, weak HS256, missing `exp`, expired tokens, and tokens issued >30 days ago. |
| **📚 API Docs** | Probes 13 common paths (`/swagger.json`, `/openapi.json`, `/api-docs`…) and records versions + endpoint counts. |
| **📝 My Payloads** | Your own payload lists, saved globally — injected into the **fuzzer** and **mapped into the scanner** (SQLi→SQLi_ERROR, XSS→XSS, LFI→LFI, SSRF→SSRF, SSTI→SSTI, RCE→OS_CMD). |

---

## 💾 Sessions & Export

- **💾 Save** — snapshot the current tab's data, keyed by target host (max 12, LRU).
- **📂 History** — restore any saved session in one click.
- **📥 Import** — load a previously exported JSON (works across machines).
- **↓ / ✕** — export the full session as JSON, or clear the tab.

**📤 Export tab:**

| Group | Formats |
|---|---|
| Bug report | 📄 Markdown · 🗂 JSON · 📊 CSV |
| Tool integration | Burp Suite XML (imports directly) · sqlmap command list · FFUF wordlist · Nuclei targets · cURL commands · raw URL list |
| HIGH confidence only | sqlmap / FFUF / JSON / Markdown restricted to HIGH-confidence params |
| Confirmed vulns | Markdown / JSON / CSV of scanner findings, exploit hints included |

All downloads are generated locally in the popup — no data ever leaves your machine.

---

## ✅ How "Confirmed" Works

This tool's brand is **true positives only**. Each detector has hard evidence rules:

| Detector | Finding requires… |
|---|---|
| `SQLi_ERROR` | A DB-vendor error signature (MySQL/Oracle/MSSQL/PostgreSQL/SQLite…) **absent from the baseline** of the same request |
| `SQLi_BOOLEAN` | ≥20% response-length delta between true/false payloads **in 3 consecutive rounds** |
| `SQLi_TIME` | Delay above `baseline_max + expected_sleep − 500ms`, **confirmed by 2 consecutive delayed hits** |
| `SSTI` | The **evaluated result** (`{{8*9}}`→`72`, `{{7*7}}`→`49`) appearing in the response but not the baseline — the result digit never occurs in the payload, so plain reflection cannot fake it |
| `XSS` | An unescaped tag/attribute signature reflected in an **HTML** response (content-type checked) |
| `XSS` (verbatim echo) | Reported as `reflected_observed` — an **unconfirmed lead (LOW)**, explicitly labeled *"check context/encoding/CSP"* |
| `LFI` / `XXE` | Real file content (`root:x:0:0:`, `[boot loader]`…) or parser errors, baseline-excluded |
| `OS_CMD` | Actual command output (`uid=…gid=…`, `command not found`, `/tmp/foo` artifacts) |
| `SSRF` | Cloud metadata fields, internal-IP disclosure, or protocol banners in the response |
| `Open Redirect` | The final URL **actually left the origin** toward the payload host (redirect-following, not header guessing) |

Everything is measured **against a per-request baseline** — dynamic content,
timestamps and ad noise are automatically excluded.

---

## 🛡 Safety Gates & Privacy

- **No scope, no action.** With no target set, BountyScope captures nothing. With
  `No Filter`, all active testing is disabled.
- **Confirmation dialog** before every active run: target, request count, estimated
  duration, and the authorization reminder.
- **Scope enforced twice:** client-side before queueing, and again inside the
  background per relayed capture — absolute in-scope URLs only.
- **Anti-poisoning:** pages can only report about their own tab; fake
  `tabId`s are ignored; overflow eviction keeps the **highest-scored** params, so a
  hostile in-scope page can't flush your genuine captures with junk.
- **All data stays local.** No telemetry, no phone-home, no analytics. The only
  network traffic is to the targets you scan (plus your Blind-XSS collector, if you
  configure one).
- **Trust note:** data reported by in-scope pages is treated as in-scope observation.
  On wildcard scopes that include user-generated-content hosts, treat findings as
  leads, not ground truth.

---

## 🛠 Troubleshooting & FAQ

**The popup looks cramped / tables are cut off.**
The popup is fixed at Chrome's maximum popup size (800×600). Panes scroll
vertically — that's expected. Full-width work happens in the exported reports.

**I closed the popup mid-scan — did I lose it?**
No. Scans run in an offscreen document. Reopen the popup and the live progress is
still there. Only closing *Chrome* stops a scan.

**Nothing is being captured.**
You almost certainly have no target set (the red **NO SCOPE** chip is showing).
Also note the built-in out-of-scope blocklist — ad/analytics domains are never
captured, even under `No Filter`.

**The badge on the icon shows numbers — what are they?**
Total captured items for that tab. Red = at least one CRITICAL/HIGH finding.

**Why does the extension need `<all_urls>`?**
A recon tool must observe the pages you point it at. The scope engine is what keeps
that power contained — set a target and everything else is ignored.

**Where does my data live?**
In `chrome.storage.local`, keyed per tab, plus saved sessions. Clearing browser
site data for the extension or pressing ✕ removes it.

---

## 🏗 Architecture (For Contributors)

```
bountyscope/
├── manifest.json          # MV3, single source of truth for name/version
├── background.js          # SW entry (module): message router, alarms, offscreen mgmt
├── bg/
│   ├── store.js           # persistent per-tab store: write-through, lazy reload, caps
│   ├── scope.js           # exact/wildcard/noFilter engine + OOS blocklist
│   ├── capture.js         # webRequest listeners, body parsing, header audit, WS upsert
│   ├── analyzer.js        # privileged JS/source-map fetching + secret/endpoint scan
│   └── sessions.js        # session snapshots (save/load/import/delete)
├── lib/
│   ├── oos.js             # base out-of-scope domain list
│   ├── classify.js        # param scoring, injection types, body/URL extraction
│   └── secrets.js         # strict secret patterns
├── content/
│   ├── content.js         # ISOLATED world: DOM recon + whitelisted spy relay
│   └── page_spy.js        # MAIN world: fetch/XHR/WS hooks + SPA route signal
├── scanner/
│   ├── payloads.js        # payload sets (Blind XSS uses a CANARY placeholder)
│   ├── detect.js          # evidence signatures (vendor errors, file content…)
│   └── scan.js            # queue/workers engine: probe / boolean(3×) / time(2×)
├── offscreen.html/.js     # scanner runtime — scans survive popup close
└── popup/                 # UI: 16 panes, filters, sessions, exports
```

Data flow: `page_spy (MAIN) → postMessage → content.js (whitelisted relay) →
background (scope-checked, tab-pinned, deduped) → chrome.storage → popup (viewer)`.
The popup never talks to pages, and pages can never call the background directly.

Code style: plain ES2020+, no frameworks, no build step. Every JS file passes
`node --check`. Please keep it that way.

---

## 🧪 Testing Legally (Local Labs)

Never test on sites you don't own. Use local deliberately-vulnerable apps:

```bash
# OWASP Juice Shop — modern SPA (recon + XSS + secrets)
docker run -d -p 3000:3000 bkimminich/juice-shop

# DVWA — classic PHP (SQLi/LFI/command injection; set security to Low)
docker run -d -p 80:80 vulnerables/web-dvwa
```

Then: set target `localhost` → browse → ⚡ Scan → 💥 Scanner. The scope-gate test:
run a second service on another port, confirm its access log stays empty while
scanning.

---

## 🚧 Known Limitations

- **CORS testing is passive-only.** A browser cannot forge the `Origin` header on
  `fetch`; anyone claiming active origin-forging from an extension is selling snake
  oil. Misconfigurations are flagged from observed responses instead.
- **Forbidden headers** (`Host`, `Origin`, `Referer`) can't be injected by the
  header-injection tests; `X-Forwarded-For`, `Authorization`, `X-API-Key` etc. work.
- **Fuzzer / Auto-Test / IDOR are heuristic tools** — query-string params only, and
  their "interesting" flags are leads, not evidence. The 💥 Scanner is the
  evidence engine; prefer it.
- The built-in **out-of-scope list is not yet user-overridable** — if your target is
  on it, open an issue.
- Whole-blob storage writes are debounced but not per-collection — very busy tabs
  do redundant disk writes (functionally harmless).

---

## 🤝 Credits & License

BountyScope unifies the author's two earlier tools: **ReconHawk Pro** (UI, scope
system, sessions, JWT/API-docs/GraphQL tooling) and **ReconSpider Pro** (the
evidence-based scanner engine, param scoring, request-body parsing, page spy).

Built through 5 independent review rounds (3 blind code audits, 1 context-aware
design review, 1 independent Opus review) — every finding fixed and documented in
[CHANGELOG.md](CHANGELOG.md).

Licensed under [MIT](LICENSE). Bug bounty responsibly.
