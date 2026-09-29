# Changelog

All notable changes to BountyScope are documented here.

## 1.0.0-alpha.1 — 2026-09-29

Merge of the author's earlier tools (ReconHawk Pro v5.0 + ReconSpider Pro V10) into one
scope-first extension.

- P0: repo skeleton, branding, MIT license, seeded UI.
- P1: persistent per-tab store that survives MV3 service-worker death, scope engine
  (exact / wildcard / passive-only), unified message router, sessions, badge, 5-min
  snapshot alarm.
- P2: merged passive capture pipeline (webRequest + request-body parsing), MAIN-world
  page spy with a working relay (fetch/XHR/WebSocket), background JS / source-map /
  secret analysis, all NBA-specific hard-coding removed.
- P3: English UI, history-modal listener fix, refresh only on real data change.
- P4: active scanner engine (SQLi error/boolean/time, XSS, Blind XSS, LFI, RFI, RCE,
  SSTI, SSRF, XXE, open redirect) with evidence-based detection, redirect-following
  fixed, canary-gated blind XSS, safety gates + confirmation before any active run.
- P5: fuzzer runs with real parallel workers (threads input wired), CORS detection
  is passive (browser fetch cannot forge Origin), all active modules require an
  Exact/Wildcard target.
- P6: export suite — Markdown / JSON / CSV / Burp XML / sqlmap / ffuf / nuclei /
  cURL / URL list (+HIGH variants) and confirmed-vuln report, direct downloads.
- P7 (context-aware design review fixes): popup resized to Chrome's 800×600 limit,
  custom payloads served globally and injected into the scanner, SPA route-change
  recon (pushState/replaceState/MutationObserver), path-segment + GraphQL/JSON body
  reconstruction for injection tests, double-confirmed time-based SQLi, HTML-gated
  reflection findings, per-host endpoint dedupe, timestamped passive-session keys,
  unlimitedStorage for reliable persistence, scan-duration warning in the
  confirmation dialog, trust & privacy docs.
- Opus independent review fixes: SSTI detector made sound (8*9→72 asymmetric math —
  the old {{77}} check false-positived on plain reflection), scanner relocated to an
  offscreen document (scans survive popup close; progress persisted and resumable in
  the popup), onStartup sweep of stale tab:* keys after browser restart, score-based
  param eviction (hostile in-scope pages can no longer flush genuine captures),
  SPA route-change signal moved to the MAIN-world spy (isolated-world history patch
  was inert), rescans budget-capped, fuzzer/auto-test/IDOR restricted to query-string
  injectable params, per-host endpoint dedupe in the UI, verbatim XSS reflection
  downgraded to unconfirmed lead.
