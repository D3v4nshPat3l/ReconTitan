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

function fmtTime(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString();
}

function fmtAgo(value) {
  if (!value) return '—';
  const seconds = Math.floor((Date.now() - new Date(value).getTime()) / 1000);
  if (Number.isNaN(seconds)) return '—';
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

async function api(path, params = {}) {
  const query = new URLSearchParams({ hours: state.window, ...params });
  const response = await fetch(`/admin/api/${path}?${query}`, {
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
  if (!buckets.length) {
    $('timeline').innerHTML = '<div class="empty">No traffic recorded in this window.</div>';
    return;
  }
  const peak = Math.max(...buckets.map((b) => b.hostile + b.normal), 1);
  $('timeline').innerHTML = buckets.map((b) => {
    const hostileH = Math.round((b.hostile / peak) * 165);
    const normalH = Math.round((b.normal / peak) * 165);
    const hour = b.hour.slice(11) || b.hour;
    return `<div class="tl-col" data-label="${esc(hour)} · ${b.hostile} hostile / ${b.normal} normal">
      ${b.hostile ? `<div class="tl-bar hostile" style="height:${hostileH}px"></div>` : ''}
      ${b.normal ? `<div class="tl-bar normal" style="height:${normalH}px"></div>` : ''}
    </div>`;
  }).join('') +
  `<div class="legend" style="width:100%">
     <span><i style="background:#f87171"></i>hostile</span>
     <span><i style="background:#a3e635"></i>normal</span>
   </div>`;
}

function renderClasses(data) {
  const classes = data.classes || [];
  if (!classes.length) {
    $('classes').innerHTML = '<div class="empty">No events recorded in this window.</div>';
    return;
  }
  const peak = Math.max(...classes.map((c) => c.events), 1);
  const colour = { critical: '#f87171', high: '#fb923c', medium: '#facc15', low: '#60a5fa', info: '#65a30d' };
  $('classes').innerHTML = classes.map((c) => `
    <div>
      <div class="cls-top">
        <span class="cls-name sev-${esc(c.severity)}">${esc(c.kind)}</span>
        <span class="cls-count">${esc(c.events)} · ${esc(c.sources)} src</span>
      </div>
      <div class="cls-track">
        <div class="cls-fill" style="width:${(c.events / peak) * 100}%;background:${colour[c.severity] || '#65a30d'}"></div>
      </div>
    </div>`).join('');
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
