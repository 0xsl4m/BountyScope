// BountyScope — offscreen scanner runtime.
// The active scan engine lives here instead of the popup so a scan survives
// popup focus loss and tab switches (the popup becomes a pure viewer).
// Messages targeting this context are tagged target:'bountyscope-offscreen'.
'use strict';

chrome.runtime.onMessage.addListener((msg) => {
  if (!msg || msg.target !== 'bountyscope-offscreen') return;

  if (msg.type === 'SCAN_START') {
    try {
      runActiveScan(msg.params || [], msg.options || {}, {
        onProgress(info) {
          chrome.runtime.sendMessage({ type: 'SCAN_PROGRESS', tabId: msg.tabId, progress: info }).catch(() => {});
        },
        onResult(finding) {
          chrome.runtime.sendMessage({ type: 'ADD_SCAN_RESULT', tabId: msg.tabId, result: finding }).catch(() => {});
        },
        onDone(info) {
          chrome.runtime.sendMessage({ type: 'SCAN_DONE', tabId: msg.tabId, done: info.done, total: info.total, count: info.results.length }).catch(() => {});
        },
      });
    } catch (_) {}
  } else if (msg.type === 'SCAN_STOP') {
    try { stopActiveScan(); } catch (_) {}
  }
});
