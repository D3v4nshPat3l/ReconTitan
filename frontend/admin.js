/* SOC console client.
 *
 * The admin token lives in sessionStorage and is sent as a header on every
 * request. It is never placed in a cookie or a URL: a header carries no
 * ambient authority, so a cross-site request cannot drive this console, and a
 * token in a query string would end up in proxy and browser history.
 */
'use strict';

const TOKEN_KEY = 'recontitan_admin_token';
const REFRESH_MS = 15000;

const state = { view: 'overview', window: 24, timer: null, kind: '', ip: '' };

const $ = (id) => document.getElementById(id);
const token = () => sessionStorage.getItem(TOKEN_KEY) || '';

/* Escape before any interpolation. Every value below is attacker-controlled:
   user agents, paths, payload excerpts and targets all originate outside. */
function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

/* Every timestamp is stored UTC and rendered in IST.
   `toLocaleString()` follows whatever locale the viewing machine happens to
   have, so the same event read from two laptops showed two different times and
   neither said which zone it meant. The zone is pinned and labelled instead. */
const IST = 'Asia/Kolkata';

/** Parse a server timestamp as UTC.

    The API is the authority and now marks its datetimes UTC-aware, but any
    record written before that fix serializes as "2026-08-26T12:25:23" with no
    offset — and `new Date()` reads an offset-less string as *local* time,
    silently shifting it by the viewer's UTC offset. Treating an unmarked
    timestamp as UTC matches how it was actually stored. */
function parseUtc(value) {
  if (!value) return null;
  const text = String(value);
  const marked = /(Z|[+-]\d{2}:?\d{2})$/.test(text) ? text : `${text}Z`;
  const date = new Date(marked);
  return Number.isNaN(date.getTime()) ? null : date;
}

function fmtTime(value) {
  if (!value) return '—';
  const date = parseUtc(value);
  if (!date) return '—';
  return date.toLocaleString('en-IN', {
    timeZone: IST,
    day: '2-digit', month: 'short',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false,
  });
}

/** Hour-of-day in IST, for chart axes. */
function fmtHour(value) {
  if (!value) return '';
  const date = parseUtc(value.length <= 13 ? `${value}:00:00` : value);
  if (!date) return '';
  return date.toLocaleTimeString('en-IN', {
    timeZone: IST, hour: '2-digit', minute: '2-digit', hour12: false,
  });
}

function fmtAgo(value) {
  if (!value) return '—';
  const date = parseUtc(value);
  if (!date) return '—';
  const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

/* The console is served at the root when it runs as its own process behind an
   SSH tunnel, and under /admin when a serverless platform forces it onto the
   public origin. Deriving the base from the page URL keeps one build working
   in both places. */
const BASE = window.location.pathname.replace(/\/[^/]*$/, '');

async function api(path, params = {}) {
  const query = new URLSearchParams({ hours: state.window, ...params });
  const response = await fetch(`${BASE}/api/${path}?${query}`, {
    headers: { 'X-ReconTitan-Admin': token() },
    cache: 'no-store',
  });
  if (response.status === 401 || response.status === 429) {
    lock(response.status === 429 ? 'Locked out after repeated failures. Wait and retry.' : 'Session rejected.');
    throw new Error('unauthorized');
  }
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

/* ── Authentication ─────────────────────────────────────────────────────── */

function lock(message) {
  sessionStorage.removeItem(TOKEN_KEY);
  clearInterval(state.timer);
  $('app').hidden = true;
  $('lock').hidden = false;
  if (message) { $('lockErr').textContent = message; $('lockErr').hidden = false; }
}

async function unlock() {
  const supplied = $('token').value.trim();
  if (!supplied) return;
  sessionStorage.setItem(TOKEN_KEY, supplied);
  $('lockErr').hidden = true;
  try {
    await api('session');
    $('token').value = '';
    $('lock').hidden = true;
    $('app').hidden = false;
    start();
  } catch {
    lock('Authentication failed.');
  }
}

$('unlock').addEventListener('click', unlock);
$('token').addEventListener('keydown', (e) => { if (e.key === 'Enter') unlock(); });
$('logout').addEventListener('click', () => lock(''));

/* ── Rendering ──────────────────────────────────────────────────────────── */

function kpi(label, value, sub, tone) {
  return `<div class="kpi ${tone ? `is-${tone}` : ''}">
    <div class="kpi-label">${esc(label)}</div>
    <div class="kpi-value">${esc(value)}</div>
    <div class="kpi-sub">${esc(sub)}</div>
  </div>`;
}

function renderOverview(data) {
  if (!data.available) {
    $('kpis').innerHTML = `<div class="panel empty">MongoDB unavailable — no telemetry to show.</div>`;
    return;
  }
  $('kpis').innerHTML = [
    kpi('THREAT EVENTS', data.threat_events, `${data.unique_attackers} distinct sources`,
      data.threat_events > 0 ? 'hot' : ''),
    kpi('INJECTIONS BLOCKED', data.injections_blocked, 'payloads rejected at the edge',
      data.injections_blocked > 0 ? 'hot' : ''),
    kpi('AUTH FAILURES', data.auth_failures, 'bad or missing API key',
      data.auth_failures > 0 ? 'warn' : ''),
    kpi('RATE LIMITED', data.rate_limited, 'requests throttled',
      data.rate_limited > 0 ? 'warn' : ''),
    kpi('ADMIN ATTEMPTS', data.admin_attempts, 'failed console logins',
      data.admin_attempts > 0 ? 'hot' : ''),
    kpi('SCANS', data.scans_window, `${data.scans_total} all time · ${data.scans_running} running`, 'cool'),
    kpi('FAILED SCANS', data.scans_failed, 'in this window', data.scans_failed > 0 ? 'warn' : ''),
    kpi('UNIQUE SOURCES', data.unique_sources, 'distinct client addresses', 'cool'),
  ].join('');
}

function renderTimeline(data) {
  const buckets = data.buckets || [];
  const host = $('timeline');
  if (!buckets.length) {
    host.innerHTML = '<div class="empty">No traffic recorded in this window.</div>';
    return;
  }

  const peak = Math.max(...buckets.map((b) => b.hostile + b.normal), 1);
  const H = 150;

  // Label every Nth bucket so the axis stays readable at any window length.
  const step = Math.max(1, Math.ceil(buckets.length / 8));

  const cols = buckets.map((b, i) => {
    const total = b.hostile + b.normal;
    // A non-zero count must never round to an invisible bar; that is the
    // difference between "nothing happened" and "something small happened".
    const px = (n) => (n > 0 ? Math.max(2, Math.round((n / peak) * H)) : 0);
    const label = fmtHour(b.hour);
    return `<div class="tl-col" title="${esc(label)} — ${b.hostile} hostile, ${b.normal} normal">
        <div class="tl-stack" data-h="${H}">
          ${b.hostile ? `<div class="tl-bar hostile" data-h="${px(b.hostile)}"></div>` : ''}
          ${b.normal ? `<div class="tl-bar normal" data-h="${px(b.normal)}"></div>` : ''}
          ${total === 0 ? '<div class="tl-bar empty-bar"></div>' : ''}
        </div>
        <span class="tl-tick">${i % step === 0 ? esc(label) : ''}</span>
      </div>`;
  }).join('');

  host.innerHTML = `
    <div class="chart">
      <div class="chart-yaxis"><span>${peak}</span><span>${Math.round(peak / 2)}</span><span>0</span></div>
      <div class="chart-plot">${cols}</div>
    </div>
    <div class="legend">
      <span><i class="sw-hostile"></i>Hostile</span>
      <span><i class="sw-normal"></i>Normal</span>
      <span class="legend-zone">Times in IST</span>
    </div>`;

  applySizes(host);
}

/* The console runs under `style-src 'self'` with no 'unsafe-inline', so a
   `style="height:..."` attribute inside an innerHTML string is refused by the
   browser and the bar renders with no height at all — the chart looked empty
   and nothing in the network or the data explained why.

   CSP governs style *attributes parsed from markup*; assigning through the
   CSSOM is not restricted. So sizes travel as data-* and are applied here
   after insertion, which keeps the strict policy intact. */
function applySizes(root) {
  root.querySelectorAll('[data-h]').forEach((el) => {
    el.style.height = `${el.dataset.h}px`;
  });
  root.querySelectorAll('[data-w]').forEach((el) => {
    el.style.width = `${el.dataset.w}%`;
  });
  root.querySelectorAll('[data-bg]').forEach((el) => {
    el.style.background = el.dataset.bg;
  });
}

function renderClasses(data) {
  const classes = data.classes || [];
  if (!classes.length) {
    $('classes').innerHTML = '<div class="empty">No events recorded in this window.</div>';
    return;
  }
  const peak = Math.max(...classes.map((c) => c.events), 1);
  /* Reads the design tokens rather than repeating hex values, so the palette
     cannot drift out of step with the stylesheet — the old map still held a
     lime green from a previous theme and was painting it on every info bar. */
  const token = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const colour = {
    critical: token('--critical'), high: token('--high'), medium: token('--medium'),
    low: token('--low'), info: token('--dim'),
  };
  $('classes').innerHTML = classes.map((c) => `
    <div>
      <div class="cls-top">
        <span class="cls-name sev-${esc(c.severity)}">${esc(c.kind)}</span>
        <span class="cls-count">${esc(c.events)} · ${esc(c.sources)} src</span>
      </div>
      <div class="cls-track">
        <div class="cls-fill" data-w="${(c.events / peak) * 100}" data-bg="${colour[c.severity] || token('--dim')}"></div>
      </div>
    </div>`).join('');
  applySizes($('classes'));
}

function threatRows(sources) {
  if (!sources.length) return '<div class="empty">No hostile activity in this window.</div>';
  return `<table><thead><tr>
      <th>SOURCE IP</th><th>EVENTS</th><th>SEVERITY</th><th>ATTACK CLASSES</th>
      <th>USER AGENT</th><th>FIRST SEEN</th><th>LAST SEEN</th>
    </tr></thead><tbody>${sources.map((s) => `
    <tr>
      <td class="nowrap">${esc(s.ip)}</td>
      <td class="count-hot">${esc(s.events)}</td>
      <td><span class="pill sev-${esc(s.severity)}">${esc(s.severity.toUpperCase())}</span></td>
      <td>${s.kinds.map((k) => `<span class="pill mono-dim">${esc(k)}</span>`).join(' ')}</td>
      <td><span class="trunc mono-dim">${esc(s.user_agent || '—')}</span></td>
      <td class="nowrap mono-dim">${esc(fmtAgo(s.first_seen))}</td>
      <td class="nowrap mono-dim">${esc(fmtAgo(s.last_seen))}</td>
    </tr>`).join('')}</tbody></table>`;
}

function renderEvents(data) {
  const events = data.events || [];
  if (!events.length) {
    $('eventTable').innerHTML = '<div class="empty">No events match these filters.</div>';
    return;
  }
  $('eventTable').innerHTML = `<table><thead><tr>
      <th>TIME</th><th>KIND</th><th>SOURCE</th><th>COUNT</th>
      <th>METHOD</th><th>PATH</th><th>DETAIL</th><th>USER AGENT</th>
    </tr></thead><tbody>${events.map((e) => `
    <tr>
      <td class="nowrap mono-dim">${esc(fmtTime(e.at))}</td>
      <td><span class="pill sev-${esc(e.severity)}">${esc(e.kind)}</span></td>
      <td class="nowrap">${esc(e.ip)}</td>
      <td class="${e.hostile ? 'count-hot' : 'mono-dim'}">${esc(e.count ?? 1)}</td>
      <td class="mono-dim">${esc(e.method || '—')}</td>
      <td><span class="trunc mono-dim">${esc(e.path || '—')}</span></td>
      <td><span class="trunc">${esc(e.detail || e.target || e.reason || '—')}</span></td>
      <td><span class="trunc mono-dim">${esc(e.user_agent || '—')}</span></td>
    </tr>`).join('')}</tbody></table>`;
}

function renderScans(data) {
  const scans = data.scans || [];
  if (!scans.length) {
    $('scanTable').innerHTML = '<div class="empty">No scans in this window.</div>';
    return;
  }
  $('scanTable').innerHTML = `<table><thead><tr>
      <th>STARTED</th><th>TARGET</th><th>PROFILE</th><th>STATUS</th>
      <th>FINDINGS</th><th>CRIT</th><th>HIGH</th><th>SOURCE IP</th><th>KEY</th><th>USER AGENT</th>
    </tr></thead><tbody>${scans.map((s) => `
    <tr>
      <td class="nowrap mono-dim">${esc(fmtTime(s.created_at))}</td>
      <td>${esc(s.target)}</td>
      <td><span class="pill mono-dim">${esc((s.scan_type || '').toUpperCase())}</span></td>
      <td class="st-${esc(s.status)}">${esc(s.status)}${s.error ? ' ⚠' : ''}</td>
      <td>${esc(s.total_findings ?? 0)}</td>
      <td class="sev-critical">${esc(s.critical ?? 0)}</td>
      <td class="sev-high">${esc(s.high ?? 0)}</td>
      <td class="nowrap">${esc(s.client_ip || '—')}</td>
      <td class="mono-dim nowrap">${esc(s.api_key_id || '—')}</td>
      <td><span class="trunc mono-dim">${esc(s.user_agent || '—')}</span></td>
    </tr>`).join('')}</tbody></table>`;
}

function renderTargets(data) {
  const targets = data.targets || [];
  if (!targets.length) {
    $('targetTable').innerHTML = '<div class="empty">No targets scanned in this window.</div>';
    return;
  }
  $('targetTable').innerHTML = `<table><thead><tr>
      <th>TARGET</th><th>SCANS</th><th>DISTINCT SOURCES</th><th>PROFILES USED</th><th>LAST SCAN</th>
    </tr></thead><tbody>${targets.map((t) => `
    <tr>
      <td>${esc(t.target)}</td>
      <td class="${t.scans > 10 ? 'count-hot' : ''}">${esc(t.scans)}</td>
      <td>${t.sources.map((s) => `<span class="pill mono-dim">${esc(s)}</span>`).join(' ') || '—'}</td>
      <td>${t.profiles.map((p) => `<span class="pill mono-dim">${esc(p)}</span>`).join(' ')}</td>
      <td class="nowrap mono-dim">${esc(fmtAgo(t.last_scan))}</td>
    </tr>`).join('')}</tbody></table>`;
}

function renderDevices(data) {
  $('deviceCaveat').textContent = data.caveat || '';
  const rows = data.devices || [];
  if (!rows.length) {
    $('deviceTable').innerHTML = '<div class="empty">No client activity in this window.</div>';
    return;
  }
  $('deviceTable').innerHTML = `<table><thead><tr>
      <th>CLIENT</th><th>REQUESTS</th><th>ADDRESSES</th><th>USER AGENT</th>
      <th>PLATFORM</th><th>LANG</th><th>API KEY</th><th>PATHS</th><th>LAST SEEN</th>
    </tr></thead><tbody>${rows.map((d) => `
    <tr class="${d.hostile ? 'row-hostile' : ''}">
      <td class="mono-dim">${esc(d.client_id)}${d.hostile
        ? ` <span class="pill">${esc(d.hostile_kinds.join(', '))}</span>` : ''}</td>
      <td class="${d.requests > 100 ? 'count-hot' : ''}">${esc(d.requests)}</td>
      <td>${d.ips.map((ip) => `<span class="pill mono-dim">${esc(ip)}</span>`).join(' ') || '—'}</td>
      <td class="ua-cell" title="${esc(d.user_agent)}">${esc(d.user_agent) || '—'}${
        d.user_agent_count > 1 ? ` <span class="pill">+${d.user_agent_count - 1}</span>` : ''}</td>
      <td class="mono-dim">${esc(d.platform) || '—'}</td>
      <td class="mono-dim">${esc(d.language) || '—'}</td>
      <td>${d.api_callers.map((c) => `<span class="pill">${esc(c)}</span>`).join(' ') || '—'}</td>
      <td class="mono-dim">${esc(d.paths_touched)}</td>
      <td class="nowrap mono-dim">${esc(fmtAgo(d.last_seen))}</td>
    </tr>`).join('')}</tbody></table>`;
}

/* `api()` only does GET. Blocking is a state change, so it gets its own path
   with the same auth handling and a surfaced error — a silent failure here
   would leave an operator believing a source was blocked when it was not. */
async function apiSend(path, method, body) {
  const response = await fetch(`${BASE}/api/${path}`, {
    method,
    headers: { 'X-ReconTitan-Admin': token(), 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (response.status === 401) { lock('Session expired.'); throw new Error('unauthorized'); }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || data.detail || `Failed (${response.status})`);
  return data;
}

function flash(message, bad = false) {
  const el = $('flash');
  el.textContent = message;
  el.className = `flash${bad ? ' is-bad' : ''}`;
  el.hidden = false;
  clearTimeout(flash._t);
  flash._t = setTimeout(() => { el.hidden = true; }, 4000);
}

/* ── Detections ─────────────────────────────────────────────────────────── */

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function renderDetections(data) {
  $('detectNote').textContent = data.note || '';
  const rows = data.detections || [];
  if (!rows.length) {
    $('detectList').innerHTML =
      `<div class="empty">Nothing matched in this window. ${esc(String(data.events_examined || 0))} events across `
      + `${esc(String(data.sources_examined || 0))} sources examined.</div>`;
    return;
  }

  $('detectList').innerHTML = rows.map((d, i) => `
    <article class="detect sev-${esc(d.severity)}" data-i="${i}">
      <button class="detect-head" type="button" aria-expanded="false">
        <span class="sev-chip ${esc(d.severity)}">${esc(d.severity)}</span>
        <span class="detect-title">${esc(d.title)}</span>
        <span class="detect-count mono-dim">${esc(d.count)} events</span>
        <span class="detect-caret" aria-hidden="true">▾</span>
      </button>
      <div class="detect-body" hidden>
        <p class="detect-why">${esc(d.explanation)}</p>
        ${d.caveat ? `<p class="detect-caveat">${esc(d.caveat)}</p>` : ''}
        <dl class="detect-facts">
          <div><dt>Source</dt><dd class="mono-dim">${esc(d.source)}</dd></div>
          <div><dt>First seen</dt><dd class="mono-dim">${esc(fmtTime(d.first_seen))}</dd></div>
          <div><dt>Last seen</dt><dd class="mono-dim">${esc(fmtTime(d.last_seen))}</dd></div>
          <div><dt>Rule</dt><dd class="mono-dim">${esc(d.rule)}</dd></div>
        </dl>
        ${d.user_agents?.length ? `<div class="detect-sub"><span>User agents</span>${
          d.user_agents.map((a) => `<span class="pill">${esc(a)}</span>`).join('')}</div>` : ''}
        ${d.sample_paths?.length ? `<div class="detect-sub"><span>Evidence</span>${
          d.sample_paths.map((x) => `<span class="pill">${esc(x)}</span>`).join('')}</div>` : ''}
        <div class="detect-actions">
          <button class="block-btn danger" data-block-source="${esc(d.source)}"
                  data-reason="${esc(d.rule)}">Block this source</button>
          <button class="block-btn ghost" data-inspect="${esc(d.source)}">Full profile</button>
        </div>
      </div>
    </article>`).join('');
}

/* ── Source profile ─────────────────────────────────────────────────────── */

async function inspectSource(ip) {
  const d = await api(`source/${encodeURIComponent(ip)}`, { hours: 168 });
  if (!d.available) return;
  const list = (rows, key = 'value') => (rows || []).map((r) =>
    `<div class="prof-row"><span class="mono-dim trunc">${esc(r[key])}</span><b>${esc(r.count)}</b></div>`).join('')
    || '<div class="prof-none">none</div>';

  $('modalBody').innerHTML = `
    <div class="prof-grid">
      <div><span class="prof-k">Source</span><span class="prof-v mono-dim">${esc(d.source)}</span></div>
      <div><span class="prof-k">Events</span><span class="prof-v">${esc(d.events)}</span></div>
      <div><span class="prof-k">Hostile</span><span class="prof-v ${d.hostile_events ? 'sev-critical' : ''}">${esc(d.hostile_events)}</span></div>
      <div><span class="prof-k">First seen</span><span class="prof-v mono-dim">${esc(fmtTime(d.first_seen))}</span></div>
      <div><span class="prof-k">Last seen</span><span class="prof-v mono-dim">${esc(fmtTime(d.last_seen))}</span></div>
      <div><span class="prof-k">Blocked</span><span class="prof-v">${d.blocked ? 'yes' : 'no'}</span></div>
    </div>
    <p class="detect-caveat">${esc(d.caveat || '')}</p>
    <div class="prof-cols">
      <section><h4>Event kinds</h4>${list(d.kinds)}</section>
      <section><h4>Paths</h4>${list(d.paths)}</section>
      <section><h4>User agents</h4>${list(d.user_agents)}</section>
      <section><h4>Targets scanned</h4>${list(d.targets_scanned)}</section>
    </div>
    ${Object.keys(d.client_hints || {}).length ? `<div class="detect-sub"><span>Client hints</span>${
      Object.entries(d.client_hints).map(([k, v]) => `<span class="pill">${esc(k)}: ${esc(v)}</span>`).join('')}</div>` : ''}
    ${d.api_callers?.length ? `<div class="detect-sub"><span>API keys used</span>${
      d.api_callers.map((c) => `<span class="pill">${esc(c)}</span>`).join('')}</div>` : ''}
    <h4 class="prof-h">Recent activity</h4>
    <div class="table-wrap"><table><thead><tr><th>Time (IST)</th><th>Kind</th><th>Method</th><th>Path</th><th>Detail</th></tr></thead>
      <tbody>${(d.timeline || []).map((t) => `<tr>
        <td class="nowrap mono-dim">${esc(fmtTime(t.at))}</td>
        <td><span class="pill">${esc(t.kind)}</span></td>
        <td class="mono-dim">${esc(t.method || '')}</td>
        <td class="mono-dim trunc">${esc(t.path || t.target || '')}</td>
        <td class="trunc">${esc(t.detail || '')}</td></tr>`).join('')}</tbody></table></div>`;
  $('modalTitle').textContent = `Source ${ip}`;
  $('sourceModal').hidden = false;
}

/* ── Blocklist ──────────────────────────────────────────────────────────── */

function renderBlocklist(data) {
  const targets = data.targets || [];
  const sources = data.sources || [];

  $('targetBlockTable').innerHTML = targets.length ? `<table><thead><tr>
      <th>HOST</th><th>REASON</th><th>ADDED (IST)</th><th></th></tr></thead><tbody>${targets.map((t) => `
      <tr><td class="mono-dim">${esc(t.host)}</td><td>${esc(t.reason) || '—'}</td>
        <td class="nowrap mono-dim">${esc(fmtTime(t.added_at))}</td>
        <td><button class="block-btn ghost" data-unblock-target="${esc(t.host)}">Remove</button></td></tr>`).join('')}
    </tbody></table>` : '<div class="empty">No targets blocked.</div>';

  $('sourceBlockTable').innerHTML = sources.length ? `<table><thead><tr>
      <th>SOURCE</th><th>REASON</th><th>ADDED (IST)</th><th></th></tr></thead><tbody>${sources.map((t) => `
      <tr><td class="mono-dim">${esc(t.source)}</td><td>${esc(t.reason) || '—'}</td>
        <td class="nowrap mono-dim">${esc(fmtTime(t.added_at))}</td>
        <td><button class="block-btn ghost" data-unblock-source="${esc(t.source)}">Remove</button></td></tr>`).join('')}
    </tbody></table>` : '<div class="empty">No sources blocked.</div>';
}

/* ── Loading ────────────────────────────────────────────────────────────── */

async function refresh() {
  try {
    $('liveLabel').textContent = 'SYNC';
    if (state.view === 'overview') {
      const [ov, tl, cls, th] = await Promise.all([
        api('overview'), api('timeline'), api('classes'), api('threats', { limit: 10 }),
      ]);
      renderOverview(ov);
      renderTimeline(tl);
      renderClasses(cls);
      $('topThreats').innerHTML = threatRows(th.sources || []);
      populateKinds(cls.classes || []);
    } else if (state.view === 'threats') {
      $('threatTable').innerHTML = threatRows((await api('threats', { limit: 100 })).sources || []);
    } else if (state.view === 'events') {
      renderEvents(await api('events', { kind: state.kind, ip: state.ip, limit: 200 }));
    } else if (state.view === 'scans') {
      renderScans(await api('scans', { limit: 200 }));
    } else if (state.view === 'detections') {
      renderDetections(await api('detections'));
    } else if (state.view === 'blocklist') {
      renderBlocklist(await api('blocklist'));
    } else if (state.view === 'devices') {
      renderDevices(await api('devices', { limit: 200 }));
    } else if (state.view === 'targets') {
      renderTargets(await api('targets', { limit: 100 }));
    }
    $('liveLabel').textContent = 'LIVE';
  } catch (error) {
    if (error.message !== 'unauthorized') $('liveLabel').textContent = 'ERROR';
  }
}

function populateKinds(classes) {
  const select = $('kindFilter');
  if (select.options.length > 1) return;
  classes.forEach((c) => {
    const option = document.createElement('option');
    option.value = c.kind;
    option.textContent = c.kind;
    select.appendChild(option);
  });
}

function start() {
  clearInterval(state.timer);
  refresh();
  state.timer = setInterval(refresh, REFRESH_MS);
}

document.querySelectorAll('[data-view]').forEach((element) => {
  if (element.tagName !== 'BUTTON') return;
  element.addEventListener('click', () => {
    state.view = element.dataset.view;
    document.querySelectorAll('.nav-a').forEach((b) => b.classList.toggle('is-on', b === element));
    document.querySelectorAll('section.view').forEach((s) => { s.hidden = s.dataset.view !== state.view; });
    refresh();
  });
});

$('window').addEventListener('change', (e) => { state.window = Number(e.target.value); refresh(); });
$('kindFilter').addEventListener('change', (e) => { state.kind = e.target.value; refresh(); });
$('ipFilter').addEventListener('input', (e) => { state.ip = e.target.value.trim(); });
$('ipFilter').addEventListener('keydown', (e) => { if (e.key === 'Enter') refresh(); });

if (token()) {
  api('session').then(() => {
    $('lock').hidden = true;
    $('app').hidden = false;
    start();
  }).catch(() => lock(''));
}

/* ── Actions ────────────────────────────────────────────────────────────── */
/* Delegated: every panel is re-rendered on refresh, so listeners bound to
   individual buttons would be discarded on the next tick. */

document.addEventListener('click', async (event) => {
  const el = event.target.closest('[data-block-source],[data-unblock-source],[data-unblock-target],[data-inspect],.detect-head');
  if (!el) return;

  if (el.classList.contains('detect-head')) {
    const body = el.nextElementSibling;
    const open = !body.hidden;
    body.hidden = open;
    el.setAttribute('aria-expanded', String(!open));
    return;
  }

  try {
    if (el.dataset.inspect) {
      await inspectSource(el.dataset.inspect);
    } else if (el.dataset.blockSource) {
      const source = el.dataset.blockSource;
      if (!confirm(`Block ${source}? It will be refused before routing.`)) return;
      await apiSend('blocklist/sources', 'POST', { source, reason: el.dataset.reason || 'blocked from console' });
      flash(`${source} blocked.`);
      refresh();
    } else if (el.dataset.unblockSource) {
      await apiSend(`blocklist/sources/${encodeURIComponent(el.dataset.unblockSource)}`, 'DELETE');
      flash(`${el.dataset.unblockSource} unblocked.`);
      refresh();
    } else if (el.dataset.unblockTarget) {
      await apiSend(`blocklist/targets/${encodeURIComponent(el.dataset.unblockTarget)}`, 'DELETE');
      flash(`${el.dataset.unblockTarget} unblocked.`);
      refresh();
    }
  } catch (error) {
    if (error.message !== 'unauthorized') flash(error.message, true);
  }
});

document.addEventListener('submit', async (event) => {
  const form = event.target;
  if (form.id !== 'targetForm' && form.id !== 'sourceForm') return;
  event.preventDefault();
  try {
    if (form.id === 'targetForm') {
      await apiSend('blocklist/targets', 'POST', {
        host: $('targetHost').value.trim(), reason: $('targetReason').value.trim(),
      });
      flash(`${$('targetHost').value.trim()} will no longer be scanned.`);
      $('targetHost').value = ''; $('targetReason').value = '';
    } else {
      await apiSend('blocklist/sources', 'POST', {
        source: $('sourceValue').value.trim(), reason: $('sourceReason').value.trim(),
      });
      flash(`${$('sourceValue').value.trim()} blocked.`);
      $('sourceValue').value = ''; $('sourceReason').value = '';
    }
    refresh();
  } catch (error) {
    if (error.message !== 'unauthorized') flash(error.message, true);
  }
});

document.addEventListener('click', (event) => {
  if (event.target.id === 'modalClose' || event.target.id === 'sourceModal') {
    $('sourceModal').hidden = true;
  }
});
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') $('sourceModal').hidden = true;
});
