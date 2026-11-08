/* NetSentry TraceIQ dashboard. Vanilla JS, no external libraries or network assets. */
(() => {
'use strict';
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = x => String(x ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info'];
const SEV_VAR = { critical: 'var(--sev-critical)', high: 'var(--sev-high)', medium: 'var(--sev-medium)', low: 'var(--sev-low)', info: 'var(--sev-info)' };
const state = { result: null, filter: 'All', query: '', svcTable: false, fpTab: 'DNS', selected: [], busy: false };

/* ---------- helpers ---------- */
async function api(url, opts) {
  const r = await fetch(url, opts);
  let body = null;
  try { body = await r.json(); } catch { /* non-JSON error body */ }
  if (!r.ok) throw new Error((body && body.error) || `Request failed (${r.status}).`);
  return body;
}
let toastTimer;
function toast(msg) { const t = $('#toast'); t.textContent = msg; t.classList.add('show'); clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove('show'), 3200); }
function setMessage(msg, good = false) { const m = $('#scan-message'); m.textContent = msg; m.classList.toggle('good', good); }
const utc = s => (s && !/[zZ]|[+-]\d\d:?\d\d$/.test(s) ? new Date(s + 'Z') : new Date(s));
const fmtDate = s => s ? utc(s).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : '';
const sevClass = s => String(s || 'info').toLowerCase();
const sevBadge = s => `<span class="sev ${esc(sevClass(s))}">${esc(s)}</span>`;
function show(which) {
  for (const id of ['empty', 'loading', 'error']) $(`#state-${id}`).hidden = id !== which;
  $('#content').hidden = which !== 'content';
}

/* ---------- theme ---------- */
const root = document.documentElement;
const effectiveTheme = () => root.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
function syncThemeButton() { $('#theme').setAttribute('aria-label', `Switch to ${effectiveTheme() === 'dark' ? 'light' : 'dark'} theme`); }
try { const saved = localStorage.getItem('theme'); if (saved) root.dataset.theme = saved; } catch { /* storage unavailable */ }
$('#theme').addEventListener('click', () => {
  root.dataset.theme = effectiveTheme() === 'dark' ? 'light' : 'dark';
  try { localStorage.setItem('theme', root.dataset.theme); } catch { /* ignore */ }
  syncThemeButton();
});
syncThemeButton();

/* ---------- scan form ---------- */
const targetInput = $('#target');
targetInput.addEventListener('input', () => { $('#clear').hidden = !targetInput.value; });
$('#clear').addEventListener('click', () => { targetInput.value = ''; $('#clear').hidden = true; targetInput.focus(); });

$('#scan-form').addEventListener('submit', async e => {
  e.preventDefault();
  if (state.busy) return;
  const target = targetInput.value.trim();
  if (!target) { setMessage('Enter a domain name or IP address to scan.'); targetInput.focus(); return; }
  if (!$('#authorized').checked) { setMessage('Confirm you are allowed to scan this target before starting.'); $('#authorized').focus(); return; }
  setBusy(true); setMessage('Validating target and starting the scan.', true);
  try {
    const started = await api('/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target, profile: $('input[name="profile"]:checked').value, authorized: true }) });
    toast(`Scan #${started.id} started`);
    show('loading'); $('#loading-title').textContent = `Scanning ${target}`; updateSteps('Queued');
    jump('#assessment');
    await poll(started.id, target);
  } catch (err) {
    setMessage(err.message);
    if (!$('#state-loading').hidden) showError(err.message);
  } finally { setBusy(false); loadHistory(); }
});
function setBusy(b) { state.busy = b; $('#start').disabled = b; $('#start').textContent = b ? 'Scanning' : 'Start scan'; }

const STEP_ORDER = ['Collecting footprint', 'Scanning ports', 'Matching known vulnerabilities', 'Scoring exposure'];
function updateSteps(progress) {
  $('#loading-step').textContent = `${progress}…`;
  const idx = STEP_ORDER.findIndex(s => progress.startsWith(s));
  $$('#steps li').forEach((li, i) => { li.classList.toggle('done', idx > i || progress === 'Complete'); li.classList.toggle('active', i === idx); });
}
function showError(msg) { $('#error-text').textContent = msg; show('error'); }

async function poll(id, target) {
  for (let n = 0; n < 400; n++) {
    await new Promise(r => setTimeout(r, 1000));
    const s = await api(`/api/scan/${id}/status`);
    updateSteps(s.progress || 'Running');
    if (s.status === 'completed') {
      const full = await api(`/api/scan/${id}/results`);
      render(full.result, { kind: 'Live scan', id, target: full.target, profile: full.profile, when: full.completed_at });
      setMessage(`Scan #${id} complete.`, true); return;
    }
    if (s.status === 'failed') { showError(s.error || 'The scan failed.'); setMessage(s.error || 'The scan failed.'); return; }
  }
  showError('The scan is taking longer than expected. It keeps running; open it from history when it finishes.');
}

$('#demo').addEventListener('click', async () => {
  try {
    const d = await api('/api/demo');
    render(d.result, { kind: 'Sample data', id: 'demo', target: d.target, profile: 'demo', when: null });
    setMessage('Showing offline sample data. This is not a live scan.', true);
  } catch (err) { showError(err.message); }
});

function jump(sel) { const el = $(sel); el.scrollIntoView({ block: 'start' }); }

/* ---------- render assessment ---------- */
function render(result, meta) {
  state.result = result; state.meta = meta; state.filter = 'All'; state.query = ''; state.svcTable = false;
  $('#search').value = '';
  const risk = result.risk || {}, hosts = result.hosts || [], services = hosts.flatMap(h => (h.ports || []).map(p => ({ ...p, host: (h.addresses || [])[0] || meta.target })));
  show('content');
  $('#assess-kind').textContent = meta.kind === 'Sample data' ? 'Sample data, not a live scan' : meta.kind === 'Saved scan' ? `Saved scan #${meta.id}` : `Scan #${meta.id}`;
  $('#assess-target').textContent = meta.target;
  const engineName = { nmap: 'Nmap', builtin: 'Built-in scanner', demo: 'Sample data' }[result.engine] || result.engine || 'Unknown engine';
  $('#assess-meta').textContent = [meta.profile && meta.profile !== 'demo' ? `${meta.profile} depth` : null, engineName, meta.when ? fmtDate(meta.when) : null].filter(Boolean).join(' · ');
  const base = meta.id === 'demo' ? '/api/demo/report' : `/api/scan/${meta.id}/report`;
  $('#dl-pdf').href = `${base}?format=pdf`; $('#dl-html').href = `${base}?format=html`;
  const json = $('#dl-json'); json.hidden = meta.id === 'demo'; json.href = `${base}?format=json`;

  drawGauge(risk);
  drawBreakdown(risk.breakdown || {});
  const strong = (risk.findings || []).filter(f => ['critical', 'high'].includes(sevClass(f.severity))).length;
  $('#stats').innerHTML = [[hosts.length, 'Hosts found'], [services.length, 'Open ports'], [strong, 'High or critical findings'], [(result.cves || []).length, 'CVE matches']]
    .map(([n, l]) => `<div class="stat"><b>${n}</b><span>${l}</span></div>`).join('');
  drawServices(services);
  drawFindings();
  drawGraph(result.graph || { nodes: [], edges: [] });
  drawFootprint(result.footprint || {});
  jump('#assessment');
  $('#assessment').focus({ preventScroll: true });
}

/* ----- gauge ----- */
function drawGauge(risk) {
  const score = Math.max(0, Math.min(100, risk.score ?? 0)), label = risk.label || 'Low', f = score / 100;
  const pt = fr => [120 - 100 * Math.cos(Math.PI * fr), 120 - 100 * Math.sin(Math.PI * fr)];
  const [x, y] = pt(f);
  const ticks = [0.25, 0.5, 0.75].map(t => { const [x1, y1] = pt(t); const [x2, y2] = [120 - 82 * Math.cos(Math.PI * t), 120 - 82 * Math.sin(Math.PI * t)]; return `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="var(--color-surface)" stroke-width="3"/>`; }).join('');
  $('#gauge').setAttribute('aria-label', `Exposure score ${score} out of 100, ${label}`);
  $('#gauge').innerHTML = `<svg viewBox="0 0 240 150" aria-hidden="true"><path class="track" d="M20 120A100 100 0 0 1 220 120" fill="none" stroke-width="18" stroke-linecap="round"/>${score ? `<path d="M20 120A100 100 0 0 1 ${x.toFixed(2)} ${y.toFixed(2)}" fill="none" stroke="${SEV_VAR[sevClass(label)]}" stroke-width="18" stroke-linecap="round"/>` : ''}${ticks}<text class="num" x="120" y="112" text-anchor="middle">${score}</text><text class="den" x="120" y="138" text-anchor="middle">out of 100</text></svg>`;
  $('#score-note').innerHTML = `${sevBadge(label)} exposure`;
}
function drawBreakdown(b) {
  const entries = Object.entries(b).filter(([, v]) => v > 0).sort((a, c) => c[1] - a[1]);
  const max = Math.max(1, ...entries.map(e => e[1]));
  $('#breakdown').innerHTML = entries.map(([k, v]) => `<div class="bar-row"><span class="name">${esc(k)}</span><span class="bar-track" aria-hidden="true"><span class="bar-fill" style="display:block;width:${(v / max * 100).toFixed(1)}%"></span></span><span class="val">${v}</span></div>`).join('') || '<p class="help">No exposure rules were triggered.</p>';
}

/* ----- services ----- */
function drawServices(services) {
  const box = $('#services'), btn = $('#svc-toggle');
  btn.hidden = !services.length; btn.setAttribute('aria-pressed', state.svcTable); btn.textContent = state.svcTable ? 'Show as chart' : 'Show as table';
  if (!services.length) { box.innerHTML = '<p class="list-empty">No open ports were found in the scanned range.</p>'; return; }
  if (state.svcTable) {
    box.innerHTML = `<div class="table-wrap"><table><thead><tr><th scope="col">Host</th><th scope="col">Port</th><th scope="col">Service</th><th scope="col">Product and version</th></tr></thead><tbody>${services.map(s => `<tr><td class="mono">${esc(s.host)}</td><td class="mono">${esc(s.port)}/${esc(s.protocol)}</td><td>${esc(s.service)}</td><td>${esc([s.product, s.version].filter(Boolean).join(' ')) || '<span class="help">not identified</span>'}</td></tr>`).join('')}</tbody></table></div>`;
    return;
  }
  const counts = {}; services.forEach(s => { counts[s.service || 'unknown'] = (counts[s.service || 'unknown'] || 0) + 1; });
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])), max = entries[0][1];
  box.innerHTML = `<div class="bars" role="img" aria-label="Open ports by service: ${esc(entries.map(([k, v]) => `${k} ${v}`).join(', '))}">${entries.map(([k, v]) => `<div class="bar-row"><span class="name mono">${esc(k)}</span><span class="bar-track"><span class="bar-fill" style="display:block;width:${(v / max * 100).toFixed(1)}%"></span></span><span class="val">${v}</span></div>`).join('')}</div>`;
}
$('#svc-toggle').addEventListener('click', () => {
  state.svcTable = !state.svcTable;
  const r = state.result; drawServices((r.hosts || []).flatMap(h => (h.ports || []).map(p => ({ ...p, host: (h.addresses || [])[0] || state.meta.target }))));
});

/* ----- findings ----- */
function drawFindings() {
  const all = (state.result.risk || {}).findings || [];
  const counts = Object.fromEntries(SEVERITIES.map(s => [s, all.filter(f => f.severity === s).length]));
  $('#chips').innerHTML = ['All', ...SEVERITIES.filter(s => counts[s])].map(s => `<button type="button" class="chip" data-sev="${s}" aria-pressed="${state.filter === s}">${s}${s === 'All' ? ` ${all.length}` : ` ${counts[s]}`}</button>`).join('');
  const q = state.query.toLowerCase();
  const list = all.filter(f => (state.filter === 'All' || f.severity === state.filter) && (!q || `${f.title} ${f.detail} ${f.remediation} ${f.category}`.toLowerCase().includes(q)));
  $('#findings-count').textContent = `${list.length} of ${all.length}`;
  $('#findings').innerHTML = list.map(f => `<details class="finding"><summary>${sevBadge(f.severity)}<span class="ttl">${esc(f.title)}</span>${f.points ? `<span class="pts" title="Points added to the score">+${f.points}</span>` : ''}</summary><div class="body"><p>${esc(f.detail)}</p><p><b>What to do:</b> ${esc(f.remediation)}</p>${f.category ? `<p class="help">Category: ${esc(f.category)}</p>` : ''}</div></details>`).join('')
    || `<p class="list-empty">${all.length ? 'No findings match this filter.' : 'No exposure findings were generated for this target.'}</p>`;
}
$('#chips').addEventListener('click', e => { const b = e.target.closest('.chip'); if (!b) return; state.filter = b.dataset.sev; drawFindings(); $(`.chip[data-sev="${state.filter}"]`)?.focus(); });
$('#search').addEventListener('input', e => { state.query = e.target.value; drawFindings(); });

/* ----- exposure map (SVG) ----- */
const SVGNS = 'http://www.w3.org/2000/svg';
const KIND_LABEL = { target: 'Target', host: 'Host', service: 'Service', cve: 'Vulnerability', dns: 'DNS record' };
function shapeFor(kind) {
  switch (kind) {
    case 'target': return '<circle r="20" class="shape"/>';
    case 'host': return '<rect x="-11" y="-11" width="22" height="22" rx="3" class="shape"/>';
    case 'cve': return '<polygon points="0,-15 15,0 0,15 -15,0" class="shape"/>';
    case 'dns': return '<polygon points="0,-11 11,9 -11,9" class="shape"/>';
    default: return '<circle r="11" class="shape"/>';
  }
}
function layoutGraph(g) {
  const cx = 400, cy = 260, nodes = g.nodes.map(n => ({ ...n })), by = Object.fromEntries(nodes.map(n => [n.id, n]));
  const parents = {}; g.edges.forEach(e => { (parents[e.to] ||= []).push(e.from); });
  const kind = k => nodes.filter(n => n.kind === k);
  const orphanCves = kind('cve').filter(c => !(parents[c.id] || []).some(p => by[p] && by[p].kind === 'service'));
  const leaves = [...kind('service'), ...kind('dns'), ...orphanCves];
  const RING = { service: 150, dns: 190, cve: 228 };
  leaves.forEach((n, i) => { n.a = -Math.PI / 2 + 2 * Math.PI * (i + 0.5) / leaves.length; n.r = RING[n.kind]; });
  const hosts = kind('host');
  hosts.forEach((h, i) => {
    const kids = g.edges.filter(e => e.from === h.id).map(e => by[e.to]).filter(k => k && k.a !== undefined);
    const sx = kids.reduce((s, k) => s + Math.cos(k.a), 0), sy = kids.reduce((s, k) => s + Math.sin(k.a), 0);
    h.a = kids.length && Math.hypot(sx, sy) > 0.35 * kids.length ? Math.atan2(sy, sx) : -Math.PI / 2 + 2 * Math.PI * i / Math.max(1, hosts.length);
    h.r = hosts.length === 1 && h.a === -Math.PI / 2 ? 0 : 78;
  });
  if (hosts.length === 1) hosts[0].r = 78;
  const offsets = {};
  kind('cve').filter(c => !orphanCves.includes(c)).forEach(c => {
    const p = by[(parents[c.id] || []).find(x => by[x] && by[x].kind === 'service')], k = offsets[p.id] = (offsets[p.id] || 0) + 1;
    c.a = p.a + 0.16 * (k % 2 ? Math.ceil(k / 2) : -Math.ceil(k / 2)); c.r = RING.cve;
  });
  nodes.forEach(n => { if (n.kind === 'target') { n.x = cx; n.y = cy; } else { n.x = cx + n.r * Math.cos(n.a); n.y = cy + n.r * Math.sin(n.a); } });
  return nodes;
}
function drawGraph(g) {
  const svg = $('#graph'), legend = $('#legend');
  const sample = (kind, style = '') => `<svg viewBox="-16 -16 32 32" aria-hidden="true" style="${style}"><g class="k-${kind}" style="--s:var(--sev-info)">${shapeFor(kind).replace('class="shape"', `fill="currentColor"`)}</g></svg>`;
  legend.innerHTML = [['target', 'Target', 'color:var(--sev-high)'], ['host', 'Host', 'color:var(--chart-1)'], ['service', 'Service', 'color:var(--chart-6)'], ['service', 'Risky service', 'color:var(--sev-high)'], ['cve', 'Vulnerability', 'color:var(--sev-high)'], ['dns', 'DNS record', 'color:var(--chart-3)']]
    .map(([k, l, st]) => `<li>${sample(k, st)}${l}</li>`).join('');
  if (!g.nodes.length) { svg.innerHTML = '<text x="400" y="260" text-anchor="middle" fill="currentColor">No map data for this assessment.</text>'; return; }
  const nodes = layoutGraph(g), by = Object.fromEntries(nodes.map(n => [n.id, n]));
  const dense = nodes.length > 26;
  const rings = [78, 150, 190, 228].map(r => `<circle class="ring" cx="400" cy="260" r="${r}"/>`).join('');
  const edges = g.edges.map(e => { const a = by[e.from], b = by[e.to]; if (!a || !b) return ''; const hot = b.kind === 'cve' && ['critical', 'high'].includes(sevClass(b.severity)); return `<line class="edge${hot ? ' hot' : ''}" x1="${a.x.toFixed(1)}" y1="${a.y.toFixed(1)}" x2="${b.x.toFixed(1)}" y2="${b.y.toFixed(1)}"/>`; }).join('');
  const nodeSvg = nodes.map(n => {
    const sev = sevClass(n.severity), extra = n.kind === 'service' && sev === 'high' ? ' risky' : '';
    const showLabel = !dense || ['target', 'host', 'cve'].includes(n.kind);
    let label = '';
    if (showLabel) {
      const rad = n.kind === 'target' ? 28 : 18, dx = n.kind === 'target' ? 0 : Math.cos(n.a), dy = n.kind === 'target' ? 1 : Math.sin(n.a);
      const anchor = dx > 0.35 ? 'start' : dx < -0.35 ? 'end' : 'middle';
      label = `<text x="${(dx * rad).toFixed(1)}" y="${(dy * rad + 4).toFixed(1)}" text-anchor="${anchor}">${esc(n.label.length > 26 ? n.label.slice(0, 25) + '…' : n.label)}</text>`;
    }
    const aria = `${KIND_LABEL[n.kind] || 'Node'}: ${n.label}${n.kind === 'cve' || n.kind === 'target' ? `, ${n.severity}` : ''}`;
    return `<g class="node k-${n.kind}${extra}" data-id="${esc(n.id)}" transform="translate(${n.x.toFixed(1)} ${n.y.toFixed(1)})" style="--s:${SEV_VAR[sev] || SEV_VAR.info}" tabindex="0" role="button" aria-label="${esc(aria)}"><title>${esc(aria)}</title>${shapeFor(n.kind)}${label}</g>`;
  }).join('');
  svg.innerHTML = `<g aria-hidden="true">${rings}${edges}</g>${nodeSvg}`;
  const select = el => {
    $$('#graph .node.sel').forEach(x => x.classList.remove('sel')); el.classList.add('sel');
    const n = by[el.dataset.id], links = g.edges.filter(e => e.from === n.id || e.to === n.id).length;
    $('#node-detail').innerHTML = `<b>${esc(n.label)}</b> · ${KIND_LABEL[n.kind] || 'Node'}${n.kind === 'cve' || n.kind === 'target' ? ` · ${sevBadge(n.severity)}` : ''}<br>${esc(n.title || '')}${n.title ? '<br>' : ''}<span class="help">${links} connection${links === 1 ? '' : 's'}</span>`;
  };
  svg.onclick = e => { const el = e.target.closest('.node'); if (el) select(el); };
  svg.onkeydown = e => { if ((e.key === 'Enter' || e.key === ' ') && e.target.classList?.contains('node')) { e.preventDefault(); select(e.target); } };
  $('#node-detail').textContent = 'Target in the centre; hosts, services, vulnerabilities and DNS records spread outward. Select a node for details.';
}

/* ----- footprint ----- */
function kv(rows) { rows = rows.filter(([, v]) => v !== null && v !== undefined && v !== '' && !(Array.isArray(v) && !v.length)); return rows.length ? `<dl class="kv">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${Array.isArray(v) ? v.map(esc).join('<br>') : esc(v)}</dd>`).join('')}</dl>` : ''; }
const FP_TABS = {
  DNS: fp => { const d = fp.dns || {}; const body = kv([...['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'].map(k => [k, d[k]]), ['SPF record', 'spf_present' in d ? (d.spf_present ? 'Present' : 'Missing') : null], ['DMARC policy', 'dmarc_present' in d ? (d.dmarc_present ? 'Present' : 'Missing') : null], ['Reverse DNS', (fp.reverse_dns || []).map(r => `${r.ip} → ${r.name}`)]]); return body || ''; },
  WHOIS: fp => kv(Object.entries(fp.whois || {}).map(([k, v]) => [k.replace(/_/g, ' '), v])),
  Certificate: fp => { const t = fp.tls || {}; return t.available ? kv([['Trust', t.trusted ? 'Trusted by this system' : 'Not trusted'], ['Problem', t.error], ['Subject', t.subject], ['Issuer', t.issuer], ['Expires', t.not_after], ['Days left', t.days_left]]) : ''; },
  Subdomains: fp => kv((fp.subdomains || []).map(s => [s.name, s.addresses])),
  Web: fp => { const h = fp.http || {}; return h.status ? kv([['URL', h.url], ['Status', h.status], ['HTTPS', h.https ? 'Yes' : 'No'], ...Object.entries(h.tech_hints || {}), ...Object.entries(h.security_headers || {}).map(([k, v]) => [k, v ? 'Present' : 'Missing']), ['Admin paths', (h.admin_paths || []).map(p => `${p.path} (HTTP ${p.status})`)]]) : ''; },
};
const FP_EMPTY = { DNS: 'No DNS records were collected for this target.', WHOIS: 'No WHOIS data was collected for this target.', Certificate: 'No TLS certificate was reachable on port 443.', Subdomains: 'No common subdomains resolved.', Web: 'No web server answered on HTTP or HTTPS.' };
function drawFootprint(fp) {
  const names = Object.keys(FP_TABS);
  $('#fp-tabs').innerHTML = names.map(n => `<button class="tab" role="tab" type="button" id="tab-${n}" aria-selected="${state.fpTab === n}" aria-controls="fp-panel" tabindex="${state.fpTab === n ? 0 : -1}" data-tab="${n}">${n}</button>`).join('');
  const panel = $('#fp-panel'); panel.setAttribute('aria-labelledby', `tab-${state.fpTab}`);
  const notes = [...(fp.notes || []), ...(fp.errors || [])].map(n => `<p class="note">${esc(n)}</p>`).join('');
  panel.innerHTML = notes + (FP_TABS[state.fpTab](fp) || `<p class="list-empty">${FP_EMPTY[state.fpTab]}</p>`);
  $('#fp-tabs').onclick = e => { const b = e.target.closest('.tab'); if (b) { state.fpTab = b.dataset.tab; drawFootprint(fp); $(`#tab-${state.fpTab}`).focus(); } };
  $('#fp-tabs').onkeydown = e => { const i = names.indexOf(state.fpTab), d = { ArrowRight: 1, ArrowLeft: -1 }[e.key]; if (d) { e.preventDefault(); state.fpTab = names[(i + d + names.length) % names.length]; drawFootprint(fp); $(`#tab-${state.fpTab}`).focus(); } };
}

/* ---------- history and comparison ---------- */
async function loadHistory() {
  const rows = $('#history-rows');
  try {
    const items = await api('/api/history');
    state.selected = state.selected.filter(id => items.some(i => i.id === id && i.status === 'completed'));
    rows.innerHTML = items.map(x => {
      const done = x.status === 'completed', checked = state.selected.includes(x.id);
      return `<tr><td><input type="checkbox" class="pick" value="${x.id}" aria-label="Select scan ${x.id} for comparison" ${done ? '' : 'disabled'} ${checked ? 'checked' : ''}></td><td class="mono">#${x.id}</td><td class="mono">${esc(x.target)}</td><td>${esc(x.profile)}</td><td><span class="status ${esc(x.status)}">${esc(x.status)}</span></td><td>${done ? `${sevBadge(x.label)} <span class="mono">${x.score}</span>` : '<span class="help">n/a</span>'}</td><td>${esc(fmtDate(x.created_at))}</td><td><div class="row-actions"><button class="btn small" data-open="${x.id}" ${done ? '' : 'disabled'}>Open</button><button class="btn small ghost" data-del="${x.id}" aria-label="Delete scan ${x.id}" ${['queued', 'running'].includes(x.status) ? 'disabled' : ''}>Delete</button></div></td></tr>`;
    }).join('') || '<tr><td colspan="8" class="empty">No saved scans yet. Completed scans appear here so you can reopen and compare them.</td></tr>';
    syncCompare();
  } catch (err) { rows.innerHTML = `<tr><td colspan="8" class="empty">Could not load history: ${esc(err.message)}</td></tr>`; }
}
function syncCompare() {
  $('#compare-btn').disabled = state.selected.length !== 2;
  $('#compare-help').textContent = state.selected.length === 2 ? `Ready to compare scan #${state.selected[0]} with #${state.selected[1]}.` : 'Tick two completed scans to see what changed between them.';
}
$('#history-rows').addEventListener('change', e => {
  if (!e.target.matches('.pick')) return;
  const id = Number(e.target.value);
  state.selected = e.target.checked ? [...state.selected, id].slice(-2) : state.selected.filter(x => x !== id);
  $$('.pick').forEach(p => { p.checked = state.selected.includes(Number(p.value)); });
  syncCompare();
});
$('#history-rows').addEventListener('click', async e => {
  const open = e.target.closest('[data-open]'), del = e.target.closest('[data-del]');
  try {
    if (open) { const r = await api(`/api/scan/${open.dataset.open}/results`); render(r.result, { kind: 'Saved scan', id: r.id, target: r.target, profile: r.profile, when: r.completed_at }); }
    if (del && confirm(`Delete scan #${del.dataset.del}? This cannot be undone.`)) { await api(`/api/scan/${del.dataset.del}`, { method: 'DELETE' }); toast(`Scan #${del.dataset.del} deleted`); loadHistory(); }
  } catch (err) { toast(err.message); }
});
$('#refresh-history').addEventListener('click', loadHistory);
$('#compare-btn').addEventListener('click', async () => {
  const [a, b] = [...state.selected].sort((x, y) => x - y), out = $('#compare-result');
  try {
    const d = await api(`/api/compare?a=${a}&b=${b}`);
    const list = (items, fn) => items.length ? `<ul>${items.map(fn).join('')}</ul>` : '<p class="help">None</p>';
    const dir = d.score_change > 0 ? 'up' : d.score_change < 0 ? 'down' : '';
    out.innerHTML = `<div class="diff"><div><h4>Score change from #${a} to #${b}</h4><p class="delta ${dir}">${d.score_change > 0 ? '+' : ''}${d.score_change} <span class="help">(${d.score_a} to ${d.score_b})${d.target_a !== d.target_b ? ` · different targets: ${esc(d.target_a)} and ${esc(d.target_b)}` : ''}</span></p></div>
      <div><h4>New open ports (${d.new_ports.length})</h4>${list(d.new_ports, p => `<li class="mono">${esc(p[0])} ${esc(p[1])}/${esc(p[2])} ${esc(p[3] || '')}</li>`)}</div>
      <div><h4>Ports no longer open (${d.closed_ports.length})</h4>${list(d.closed_ports, p => `<li class="mono">${esc(p[0])} ${esc(p[1])}/${esc(p[2])} ${esc(p[3] || '')}</li>`)}</div>
      <div><h4>New findings (${d.new_findings.length})</h4>${list(d.new_findings, f => `<li>${sevBadge(f.severity)} ${esc(f.title)}</li>`)}</div>
      <div><h4>Resolved findings (${d.resolved_findings.length})</h4>${list(d.resolved_findings, f => `<li>${sevBadge(f.severity)} ${esc(f.title)}</li>`)}</div></div>`;
  } catch (err) { out.innerHTML = `<p class="message">${esc(err.message)}</p>`; }
});

/* ---------- boot ---------- */
show('empty');
loadHistory();
if (/[?&#]demo/.test(location.search + location.hash)) $('#demo').click();
})();
