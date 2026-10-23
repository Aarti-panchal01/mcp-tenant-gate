// Small DOM helpers. Server strings only ever go through textContent:
// tool descriptions and results are attacker-controlled text.

export function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
      else if (k === 'dataset') Object.assign(el.dataset, v);
      else el.setAttribute(k, v === true ? '' : String(v));
    }
  }
  append(el, kids);
  return el;
}

function append(el, kids) {
  for (const k of kids) {
    if (k === null || k === undefined || k === false) continue;
    if (Array.isArray(k)) append(el, k);
    else if (k instanceof Node) el.appendChild(k);
    else el.appendChild(document.createTextNode(String(k)));
  }
}

export const $ = (sel, root = document) => root.querySelector(sel);

export function chip(text, tone = 'neutral', extra = '') {
  return h('span', { class: `chip chip-${tone}${extra ? ' ' + extra : ''}`, text });
}

// "BLOCK · argguard": label in caps, layer as written in the code.
export function verdictChip(v, big = false) {
  return h('span', { class: `chip chip-${v.tone}${big ? ' chip-big' : ''}` }, v.label,
    v.layer && v.tone !== 'allow' ? h('span', { class: 'chip-layer', text: `· ${v.layer}` }) : null);
}

// Verdict for a call or scan result, per the site's colour rules.
export function verdictOf(r) {
  if (!r) return null;
  if (r.blocked) return { label: 'BLOCK', tone: 'block', layer: r.layer || '', reason: r.reason || '' };
  const acts = r.actions || [];
  const has = (p) => acts.some((a) => a.startsWith(p));
  if (has('injection_wrapped')) return { label: 'WRAP', tone: 'warn', layer: 'injection', reason: 'delivered inside untrusted-data markers' };
  if (has('pii_redacted')) return { label: 'REDACT', tone: 'warn', layer: 'pii', reason: 'personal data redacted before the model reads it' };
  if (has('cross_tenant_filtered')) return { label: 'FILTER', tone: 'warn', layer: 'isolation', reason: "rows owned by another tenant dropped from the result" };
  if (has('dropped_non_text')) return { label: 'FILTER', tone: 'warn', layer: 'non_text', reason: 'non-text content dropped' };
  return { label: 'ALLOW', tone: 'allow', layer: '', reason: 'passed every check' };
}

export function actionTone(a) {
  if (/^(pii_redacted|cross_tenant_filtered|injection_wrapped|dropped_non_text)/.test(a)) return 'warn';
  return 'neutral';
}

export function fmtMs(ms) {
  if (typeof ms !== 'number' || !isFinite(ms)) return '';
  if (ms < 10) return ms.toFixed(2);
  if (ms < 100) return ms.toFixed(1);
  return Math.round(ms).toString();
}

export function store(kind, key, value) {
  try {
    const s = kind === 'session' ? window.sessionStorage : window.localStorage;
    if (value === undefined) return s.getItem(key);
    if (value === null) s.removeItem(key);
    else s.setItem(key, value);
  } catch (e) { /* storage blocked: the page still works, it just forgets */ }
  return null;
}
