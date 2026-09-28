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
