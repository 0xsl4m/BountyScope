// BountyScope — scope engine: exact / wildcard / passive-only targets,
// plus an always-applied out-of-scope blocklist (capture AND scanner).
import * as store from './store.js';
import { BASE_OOS } from '../lib/oos.js';

let extraOOS = [];

export function setExtraOOS(list) {
  extraOOS = (Array.isArray(list) ? list : [])
    .map((s) => String(s).trim().toLowerCase())
    .filter(Boolean);
}

export function isOOS(hostname) {
  const hn = String(hostname || '').toLowerCase();
  if (!hn) return false;
  for (const d of BASE_OOS) if (hn === d || hn.endsWith('.' + d)) return true;
  for (const d of extraOOS) if (hn === d || hn.endsWith('.' + d)) return true;
  return false;
}

export async function isInScope(url, tabId) {
  let hn = '';
  try { hn = new URL(url).hostname.toLowerCase(); } catch (_) { return false; }
  if (isOOS(hn)) return false;
  const tab = await store.ensure(tabId);
  const t = tab?.target;
  if (!t) return false;                     // no target set → capture nothing
  if (t.noFilter) return true;              // passive-only "everything" mode
  if (!t.host) return false;
  const th = String(t.host).toLowerCase().replace(/^\*\./, '');
  if (t.wildcard) return hn === th || hn.endsWith('.' + th);
  return hn === th;
}
