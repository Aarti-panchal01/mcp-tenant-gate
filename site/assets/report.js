// Attack suite, held-out eval and error analysis. Recorded data comes from
// /data/recorded.json; the live suite comes from POST /api/gate?action=suite.
import { h, $, chip, fmtMs } from './dom.js';

const CI = {
  'rules only': { withheld: '14.4 to 35.4', flagged: '18.5 to 40.8', chatW: '0.0 to 6.4', chatF: '0.0 to 6.4', stdW: '0.0 to 0.1', stdF: '0.0 to 0.2' },
  'rules + classifier': { withheld: '33.1 to 57.5', flagged: '64.6 to 85.6', chatW: '0.0 to 6.4', chatF: '0.3 to 9.4', stdW: '0.0 to 0.1', stdF: '0.1 to 0.5' },
};

const suiteState = { suite: null, filter: 'all', live: false, recordedAt: '' };

function pct(n, d) {
  if (!d) return '';
  const v = (100 * n) / d;
  return `${v > 0 && v < 1 ? v.toFixed(2) : v.toFixed(1)}%`;
}

/* ------------------------------------------------------------ suite */

function renderSuite(prevNames) {
  const s = suiteState.suite;
  if (!s) return;
  const lat = s.latency || {};
  const sum = $('#suite-summary');
  const ok = (t) => h('span', { class: s.blocked === s.attacks ? 'ok' : '', text: t });
  sum.replaceChildren(
    ok(`${s.blocked}/${s.attacks} blocked`), h('span', { class: 'sep', text: '·' }),
    `${s.logged}/${s.loggable} logged`, h('span', { class: 'sep', text: '·' }),
    h('span', { class: s.benign_passed === s.benign_total ? 'ok' : '', text: `${s.benign_passed}/${s.benign_total} benign passed` }), h('span', { class: 'sep', text: '·' }),
    `added latency p50 ${fmtMs(lat.added_p50)} ms, p95 ${fmtMs(lat.added_p95)} ms (${lat.n} calls)`);
  const label = $('#suite-label');
  if (suiteState.live) {
    label.textContent = `Live run, just now, in ${s.seconds} s on the server. In-process upstreams.`;
    label.classList.add('live');
  } else {
    label.textContent = `Recorded run, ${suiteState.recordedAt}. In-process upstreams.`;
    label.classList.remove('live');
  }

  const cats = {};
  for (const r of s.rows) cats[r.category] = (cats[r.category] || 0) + 1;
  const fbox = $('#suite-filters');
  const mk = (key, text, n) => h('button', {
    type: 'button', 'aria-pressed': suiteState.filter === key ? 'true' : 'false',
    onclick: () => { suiteState.filter = key; renderSuite(); },
  }, text, h('span', { class: 'n', text: String(n) }));
  fbox.replaceChildren(mk('all', 'all', s.rows.length), ...Object.entries(cats).map(([c, n]) => mk(c, c, n)));

  const rows = s.rows.map((r, i) => ({ ...r, i: i + 1 })).filter((r) => suiteState.filter === 'all' || r.category === suiteState.filter);
  $('#suite-rows').replaceChildren(...rows.map((r) => h('tr', { class: prevNames ? 'row-new' : '' },
    h('td', { class: 'num', text: String(r.i) }),
    h('td', null, r.name, h('span', { class: 'm-note', text: r.note })),
    h('td', { text: r.category }),
    h('td', null, r.blocked ? chip('BLOCK', 'block') : chip('MISSED', 'warn')),
    h('td', { text: r.layer || '' }),
    h('td', { text: r.logged }),
    h('td', { text: r.note }))));

  const hb = s.hard_benign || [];
  const pass = hb.filter((x) => x[1] === 'pass').length;
  const wrap = hb.filter((x) => x[1] === 'wrap').length;
  $('#hb-count').textContent = `pass ${pass} · wrap ${wrap} · blocked ${hb.length - pass - wrap} of ${hb.length}`;
  $('#hb-rows').replaceChildren(...hb.map(([text, out]) => h('tr', null,
    h('td', { text }),
    h('td', null, chip(out === 'pass' ? 'PASS' : out === 'wrap' ? 'WRAP' : out.toUpperCase(), out === 'pass' ? 'allow' : out === 'wrap' ? 'warn' : 'block')))));
}

async function runLiveSuite() {
  const btn = $('#suite-run');
  const msg = $('#suite-msg');
  btn.disabled = true;
  btn.setAttribute('aria-busy', 'true');
  btn.textContent = 'Running 20 attacks...';
  msg.textContent = 'Running the suite on the server. This takes a few seconds.';
  try {
    const r = await fetch('/api/gate?action=suite', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    let d = null;
    try { d = await r.json(); } catch (e) { d = null; }
    if (r.status === 429) {
      const e = (d && d.error) || 'the live suite is rate limited';
      msg.textContent = `${e.charAt(0).toUpperCase()}${e.slice(1)}. The table keeps the ${suiteState.live ? 'last live' : 'recorded'} run. Try again in about 30 seconds.`;
      return;
    }
    if (!r.ok || !d || !Array.isArray(d.rows)) {
      msg.textContent = `The live run failed: ${(d && d.error) || `HTTP ${r.status}`}. The table keeps the previous run.`;
      return;
    }
    suiteState.suite = d;
    suiteState.live = true;
    renderSuite(true);
    msg.textContent = d.blocked === d.attacks && d.benign_passed === d.benign_total
      ? 'Live result matches the recorded one.'
      : 'Live result differs from the recorded one. The table shows the live numbers.';
  } catch (e) {
    msg.textContent = 'Could not reach the API. The table keeps the previous run.';
  } finally {
    btn.disabled = false;
    btn.removeAttribute('aria-busy');
    btn.textContent = 'Run the suite live again';
  }
}

/* ------------------------------------------------------------ eval */

function renderEval(layers) {
  const a = layers.configs['rules only'];
  const b = layers.configs['rules + classifier'];
  const nI = layers.test_injections;
  const nB = layers.test_benign;
  const nS = layers.stdlib_eval_paragraphs;
  const cell = (n, d, ci, em) => h('td', null, h('span', { class: `frac${em ? ' em' : ''}`, text: `${n}/${d}` }), h('span', { class: 'eq', text: ' = ' }), h('span', { class: `pc${em ? ' em' : ''}`, text: pct(n, d) }), ci ? h('span', { class: 'ci', text: ci }) : null);
  const row = (label, ca, cb) => h('tr', null, h('td', { text: label }), ca, cb);
  const ra = CI['rules only'];
  const rb = CI['rules + classifier'];
  $('#eval-rows').replaceChildren(
    row('Injections withheld', cell(a.withheld, nI, ra.withheld), cell(b.withheld, nI, rb.withheld, true)),
    row('Withheld or wrapped', cell(a.flagged, nI, ra.flagged), cell(b.flagged, nI, rb.flagged)),
    row('Benign chat withheld', cell(a.benign_chat_withheld, nB, ra.chatW), cell(b.benign_chat_withheld, nB, rb.chatW)),
    row('Benign chat wrapped', cell(a.benign_chat_flagged, nB), cell(b.benign_chat_flagged, nB, rb.chatF)),
    row('Unseen stdlib docs withheld', cell(a.stdlib_withheld, nS, ra.stdW), cell(b.stdlib_withheld, nS, rb.stdW)),
    row('Unseen stdlib docs wrapped', cell(a.stdlib_flagged, nS), cell(b.stdlib_flagged, nS, rb.stdF)),
    row('Time per text', h('td', { text: `${a.ms_per_text_stdlib_paragraphs} to ${a.ms_per_text_injection_rows} ms` }), h('td', { text: `${b.ms_per_text_stdlib_paragraphs} to ${b.ms_per_text_injection_rows} ms` })),
  );
  const ci = layers.recall_gain_withheld_ci || [];
  $('#eval-source').textContent = `Withheld recall up ${((b.withheld - a.withheld) * 100 / nI).toFixed(1)} points (paired bootstrap 95% interval +${(ci[0] * 100).toFixed(1)} to +${(ci[1] * 100).toFixed(1)}). ${layers.newly_withheld} injections newly withheld, ${layers.no_longer_withheld} lost. Classifier thresholds: wrap at ${layers.model.t_low}, withhold at ${layers.model.t_high}. Source: ${layers.source}.`;

  const strip = (name, c) => {
    const w = c.withheld;
    const f = c.flagged - c.withheld;
    const m = nI - c.flagged;
    const cells = [];
    for (let i = 0; i < nI; i++) cells.push(h('span', { class: i < w ? 'c-block' : i < w + f ? 'c-warn' : 'c-miss' }));
    return h('div', null,
      h('div', { class: 'strip-h' }, h('b', { text: name }), h('span', { text: `${w} withheld · ${f} wrapped · ${m} passed` })),
      h('div', { class: 'strip', role: 'img', 'aria-label': `${name}: ${w} of ${nI} withheld, ${f} wrapped, ${m} passed with no flag` }, cells));
  };
  $('#eval-strips').replaceChildren(strip('Rules only', a), strip('Rules + classifier', b));
}

function renderErrors(ea) {
  $('#err-rows').replaceChildren(...ea.categories.map(([cat, n, w, p, fix]) => h('tr', null,
    h('td', { text: cat }), h('td', { class: 'num', text: String(n) }), h('td', { class: 'num', text: `${w} / ${p}` }), h('td', { text: fix }))));
  $('#err-cuts').replaceChildren(...ea.cross_cuts.map((c) => h('li', { text: c })));
  $('#err-sub').textContent = `The ${ea.misses} held-out injections that were not withheld: ${ea.wrapped} wrapped, ${ea.passed} passed with no flag. Grouped by hand by what the text asks for, so treat counts as approximate.`;
}

/* ------------------------------------------------------------ boot */

async function boot() {
  $('#suite-run').addEventListener('click', runLiveSuite);
  try {
    const r = await fetch('/data/recorded.json');
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const d = await r.json();
    suiteState.suite = d.suite;
    suiteState.recordedAt = d.recorded_at;
    renderSuite();
    renderEval(d.layers);
    renderErrors(d.error_analysis);
  } catch (e) {
    $('#suite-label').textContent = `Could not load the recorded results (${e.message}). The live suite button still works.`;
    $('#suite-summary').textContent = '';
  }
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
else boot();
