'use strict';

function getReconTitanApiKey() {
  return sessionStorage.getItem('recontitan_api_key') || '';
}

async function apiFetch(url, options = {}, allowPrompt = true) {
  const headers = new Headers(options.headers || {});
  const key = getReconTitanApiKey();
  if (key) headers.set('X-ReconTitan-Key', key);
  const response = await fetch(url, { ...options, headers });
  if (response.status !== 401 || !allowPrompt) return response;
  const supplied = window.prompt('Enter your ReconTitan API access key:');
  if (!supplied) return response;
  sessionStorage.setItem('recontitan_api_key', supplied.trim());
  return apiFetch(url, options, false);
}

const PROFILE_STEPS = {
  full: [
    'WHOIS and DNS reconnaissance', 'Certificate Transparency discovery', 'Wayback history',
    'Infrastructure and HTTP probing', 'Technology stack detection', 'Favicon hash correlation',
    'JavaScript file analysis', 'Subdomain takeover checks', 'Security headers and TLS',
    'CORS, cookie, robots and WAF review', 'Port exposure and CVE candidates', 'AI summary and report',
  ],
  recon_only: [
    'WHOIS lookup', 'DNS enumeration', 'Certificate Transparency discovery', 'Wayback history',
    'IP intelligence', 'HTTP probing', 'Subfinder passive enumeration', 'Amass passive enumeration',
    'AI summary and report',
  ],
  osint_only: [
    'Technology stack detection', 'Favicon hash correlation', 'JavaScript file analysis',
    'Subdomain takeover checks', 'Security headers', 'SSL/TLS review', 'robots.txt and sitemap',
    'CORS configuration', 'Cookie security', 'WAF detection', 'AI summary and report',
  ],
  vuln_only: ['Port exposure scan', 'Technology-led NVD lookup', 'AI summary and report'],
  danger: [
    'WHOIS and DNS reconnaissance', 'Certificate Transparency discovery', 'Wayback history',
    'Infrastructure and HTTP probing', 'Technology stack detection', 'Favicon hash correlation',
    'JavaScript file analysis', 'Subdomain takeover checks', 'Security headers and TLS',
    'CORS, cookie, robots and WAF review', 'Port exposure and CVE candidates',
    'Danger recon and host fingerprinting', 'DNS zone-transfer (AXFR) attempts',
    'Attack surface inventory', 'SQL injection probes', 'Command injection probes',
    'HTML injection probes', 'JavaScript injection (XSS) probes', 'Template injection probes',
    'XXE probes', 'SSRF probes', 'NoSQL injection probes',
    'Reverse shell possibility assessment', 'Directory fuzzing', 'Path traversal probes',
    'IDOR identifier enumeration', 'OWASP Top 10 coverage matrix', 'AI summary and report',
  ],
};

const DANGER_PHRASE = 'I am authorized';
let dangerUnlocked = false;
let dangerEnabledOnServer = null;
let scanBusy = false;
let activeScanId = '';
let cancelRequestPending = false;
let runtimeCapabilities = null;

let scanCount = Number.parseInt(localStorage.getItem('rt_scan_count') || '0', 10) || 0;
let selectedProfile = localStorage.getItem('rt_scan_profile') || 'full';
// The danger gate is deliberately never restored from storage: the operator
// must re-acknowledge authorization in every session.
if (!PROFILE_STEPS[selectedProfile] || selectedProfile === 'danger') selectedProfile = 'full';

document.getElementById('hsScans').textContent = String(scanCount);

const dangerGate = document.getElementById('dangerGate');
const dangerConsent = document.getElementById('dangerConsent');
const dangerPhrase = document.getElementById('dangerPhrase');
const dangerFeedback = document.getElementById('dangerGateFeedback');
const dangerStatus = document.getElementById('dangerGateStatus');

function refreshDangerGate() {
  const consented = Boolean(dangerConsent && dangerConsent.checked);
  const typed = dangerPhrase ? dangerPhrase.value.trim() : '';
  dangerUnlocked = consented && typed === DANGER_PHRASE;

  if (!dangerFeedback) return;
  if (dangerEnabledOnServer === false) {
    dangerFeedback.textContent = 'Danger Mode is disabled on this server (ALLOW_DANGER_MODE=false). The scan will be rejected.';
    dangerFeedback.dataset.state = 'blocked';
  } else if (dangerUnlocked) {
    dangerFeedback.textContent = '✓ Danger Mode unlocked. Bounded simulation traffic will be sent to the target you enter above.';
    dangerFeedback.dataset.state = 'ready';
  } else if (!consented) {
    dangerFeedback.textContent = 'Confirm authorization with the checkbox above.';
    dangerFeedback.dataset.state = 'locked';
  } else {
    dangerFeedback.textContent = `Type the exact phrase "${DANGER_PHRASE}" to unlock.`;
    dangerFeedback.dataset.state = 'locked';
  }
  if (selectedProfile === 'danger') {
    scanBtn.disabled = scanBusy || !dangerUnlocked;
    scanBtn.classList.toggle('danger-armed', dangerUnlocked);
  }
}

function selectProfile(profile) {
  if (!PROFILE_STEPS[profile]) return;
  selectedProfile = profile;
  localStorage.setItem('rt_scan_profile', profile === 'danger' ? 'full' : profile);
  document.querySelectorAll('[data-profile]').forEach((button) => {
    const active = button.dataset.profile === profile;
    button.classList.toggle('active', active);
    button.setAttribute('aria-checked', String(active));
  });
  if (dangerGate) dangerGate.hidden = profile !== 'danger';
  document.body.classList.toggle('danger-selected', profile === 'danger');
  if (profile !== 'danger') {
    scanBtn.disabled = scanBusy;
    scanBtn.classList.remove('danger-armed');
  }
  refreshDangerGate();
}

document.querySelectorAll('[data-profile]').forEach((button) => {
  button.addEventListener('click', () => selectProfile(button.dataset.profile));
});
if (dangerConsent) dangerConsent.addEventListener('change', refreshDangerGate);
if (dangerPhrase) dangerPhrase.addEventListener('input', refreshDangerGate);

document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
  anchor.addEventListener('click', (event) => {
    const element = document.querySelector(anchor.getAttribute('href'));
    if (element) {
      event.preventDefault();
      element.scrollIntoView({ behavior: 'smooth' });
    }
  });
});

const scanBtn = document.getElementById('scanBtn');
const targetInput = document.getElementById('targetInput');
const cancelScanBtn = document.getElementById('cancelScanBtn');

// Applied after scanBtn exists because the gate toggles the scan button.
selectProfile(selectedProfile);

function setProgress(percent, phase) {
  document.getElementById('progressFill').style.width = `${percent}%`;
  document.getElementById('progressPct').textContent = `${percent}%`;
  document.getElementById('progressPhase').textContent = phase;
}

function addLog(message) {
  const log = document.getElementById('progressLog');
  const line = document.createElement('div');
  line.className = 'plog-line';
  line.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
  log.appendChild(line);
  log.scrollTop = log.scrollHeight;
}

function setScanBusy(busy) {
  scanBusy = busy;
  scanBtn.classList.toggle('loading', busy);
  scanBtn.disabled = busy || (selectedProfile === 'danger' && !dangerUnlocked);
  cancelScanBtn.hidden = !(busy && activeScanId);
  if (!busy) {
    cancelScanBtn.disabled = false;
    cancelScanBtn.textContent = 'Cancel scan';
  }
}

function wait(milliseconds) {
  return new Promise(resolve => window.setTimeout(resolve, milliseconds));
}

async function responseError(response) {
  let detail = `Server returned ${response.status}`;
  try {
    const payload = await response.json();
    detail = payload.detail || payload.error || payload.message || detail;
  } catch (_) {
    // Keep the status-based message when the server did not return JSON.
  }
  return String(detail);
}

function normalizeReportData(data) {
  const normalized = { ...data };
  normalized.severity_counts = normalized.severity_counts || {
    critical: normalized.critical_count || 0,
    high: normalized.high_count || 0,
    medium: normalized.medium_count || 0,
    low: normalized.low_count || 0,
    info: normalized.info_count || 0,
  };
  normalized.total_time_seconds = normalized.total_time_seconds ?? normalized.duration_seconds ?? 0;
  normalized.tools_run = normalized.tools_run ?? (normalized.tools_used || []).length;
  if (!normalized.ai_summary && normalized.summary) {
    normalized.ai_summary = { executive_summary: normalized.summary };
  }
  return normalized;
}

function phaseLabel(value) {
  const labels = {
    recon: 'Reconnaissance',
    osint: 'OSINT and web analysis',
    portscan: 'Port exposure scan',
    vulnscan: 'Vulnerability correlation',
    danger: 'Danger Mode probes',
    ai_analysis: 'AI summary and report',
  };
  return labels[value] || String(value || 'Queued').replaceAll('_', ' ');
}

async function runSynchronousFallback(target, profile, reason = '') {
  activeScanId = '';
  cancelScanBtn.hidden = true;
  if (reason) addLog(`Queue unavailable: ${reason}`);
  addLog('Running compatibility scan in this request; live per-tool status is unavailable.');
  const startedAt = Date.now();
  setProgress(5, 'Compatibility scan running...');
  const elapsedTicker = window.setInterval(() => {
    const elapsed = Math.round((Date.now() - startedAt) / 1000);
    setProgress(5, `Compatibility scan running... (${elapsed}s)`);
  }, 1000);

  let url = `/api/test-scan?target=${encodeURIComponent(target)}&scan_type=${encodeURIComponent(profile)}`;
  if (profile === 'danger') {
    url += `&danger_acknowledgement=${encodeURIComponent(DANGER_PHRASE)}`;
  }
  try {
    const response = await apiFetch(url);
    if (!response.ok) throw new Error(await responseError(response));
    return normalizeReportData(await response.json());
  } finally {
    window.clearInterval(elapsedTicker);
  }
}

async function pollQueuedScan(scanId, startedAt) {
  const seenCompleted = new Set();
  let runningSignature = '';

  while (activeScanId === scanId) {
    const response = await apiFetch(`/api/scan/${encodeURIComponent(scanId)}/status`);
    if (!response.ok) throw new Error(await responseError(response));
    const status = await response.json();
    const elapsed = Math.round((Date.now() - startedAt) / 1000);
    setProgress(status.progress || 0, `${phaseLabel(status.phase)} (${elapsed}s)`);

    for (const tool of status.tools_completed || []) {
      if (!seenCompleted.has(tool)) {
        seenCompleted.add(tool);
        addLog(`✓ ${tool} completed`);
      }
    }
    const running = (status.tools_running || []).join(', ');
    if (running && running !== runningSignature) {
      runningSignature = running;
      addLog(`→ Running: ${running}`);
    }

    if (status.status === 'completed') {
      const report = await apiFetch(`/api/scan/${encodeURIComponent(scanId)}/report`);
      if (!report.ok) throw new Error(await responseError(report));
      return normalizeReportData(await report.json());
    }
    if (status.status === 'failed') {
      throw new Error(status.error || 'The scan worker reported a failure.');
    }
    if (status.status === 'cancelled') {
      addLog('Scan cancelled. Findings completed before cancellation remain stored.');
      localStorage.removeItem('rt_active_scan');
      activeScanId = '';
      setProgress(status.progress || 0, 'Cancelled');
      setScanBusy(false);
      return null;
    }
    await wait(1500);
  }
  return null;
}

async function queueOrRunScan(target, profile) {
  if (runtimeCapabilities && runtimeCapabilities.async_scans === false) {
    return runSynchronousFallback(target, profile, 'this deployment does not run background workers');
  }

  const payload = { target, scan_type: profile };
  if (profile === 'danger') payload.danger_acknowledgement = DANGER_PHRASE;
  const response = await apiFetch('/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    const detail = await responseError(response);
    if (response.status === 503 && /\/api\/test-scan|synchronous scan/i.test(detail)) {
      return runSynchronousFallback(target, profile, detail);
    }
    throw new Error(detail);
  }

  const accepted = await response.json();
  activeScanId = accepted.scan_id;
  cancelScanBtn.hidden = false;
  localStorage.setItem('rt_active_scan', JSON.stringify({
    scan_id: activeScanId,
    target: accepted.target || target,
    scan_type: profile,
  }));
  addLog(`Queued as ${activeScanId}. Progress now comes from the worker.`);
  return pollQueuedScan(activeScanId, Date.now());
}

function openCompletedReport(data, fallbackTarget, fallbackProfile) {
  const normalized = normalizeReportData(data);
  const target = normalized.target || fallbackTarget;
  const profile = normalized.scan_type || fallbackProfile;
  setProgress(100, 'Assessment complete');
  addLog(`✓ ${normalized.tools_run} modules completed with ${normalized.total_findings} findings in ${normalized.total_time_seconds}s`);

  Object.entries(normalized.tool_results || {}).forEach(([tool, result]) => {
    const status = result.status === 'ok' ? '✓' : '✗';
    addLog(`${status} ${tool}: ${result.findings ?? '—'} finding(s), ${result.time_seconds ?? '—'}s`);
  });
  if (normalized.ai_summary?.risk_level) addLog(`AI risk level: ${normalized.ai_summary.risk_level}`);
  logDangerTelemetry(normalized.danger_summary);

  scanCount += 1;
  localStorage.setItem('rt_scan_count', String(scanCount));
  localStorage.removeItem('rt_active_scan');
  document.getElementById('hsScans').textContent = String(scanCount);
  try {
    sessionStorage.setItem('rt_scan_target', target);
    sessionStorage.setItem('rt_scan_profile', profile);
    sessionStorage.setItem('rt_scan_data', JSON.stringify(normalized));
  } catch (_) {
    addLog('Browser cache is full; the report will be loaded from persistent scan storage.');
  }
  activeScanId = '';
  cancelScanBtn.hidden = true;
  addLog('Opening the persisted interactive report...');
  window.setTimeout(() => {
    const query = new URLSearchParams({ target, scan_type: profile, cached: '1' });
    if (normalized.scan_id && normalized.scan_id.startsWith('scan_')) query.set('scan_id', normalized.scan_id);
    window.location.href = `/report.html?${query.toString()}`;
  }, 500);
}

scanBtn.addEventListener('click', startScan);
targetInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') startScan();
});

async function startScan() {
  if (scanBusy) return;
  const target = targetInput.value.trim();
  if (!target) {
    targetInput.focus();
    targetInput.setAttribute('aria-invalid', 'true');
    window.setTimeout(() => targetInput.removeAttribute('aria-invalid'), 1500);
    return;
  }

  if (selectedProfile === 'danger' && !dangerUnlocked) {
    refreshDangerGate();
    if (dangerPhrase) dangerPhrase.focus();
    return;
  }

  setScanBusy(true);
  const progress = document.getElementById('scanProgress');
  progress.hidden = false;
  document.getElementById('progressLog').replaceChildren();
  setProgress(1, 'Validating target...');
  addLog(`Profile selected: ${selectedProfile}`);

  try {
    if (selectedProfile === 'danger') {
      addLog('☣ Danger Mode armed — bounded simulation traffic only, all results are candidates');
    }
    const data = await queueOrRunScan(target, selectedProfile);
    if (data) openCompletedReport(data, target, selectedProfile);
  } catch (error) {
    localStorage.removeItem('rt_active_scan');
    activeScanId = '';
    setProgress(0, `Error: ${error.message}`);
    addLog(`✗ ${error.message}`);
    setScanBusy(false);
  }
}

cancelScanBtn.addEventListener('click', async () => {
  if (!activeScanId || cancelRequestPending) return;
  cancelRequestPending = true;
  cancelScanBtn.disabled = true;
  cancelScanBtn.textContent = 'Cancelling...';
  const scanId = activeScanId;
  try {
    const response = await apiFetch(`/api/scan/${encodeURIComponent(scanId)}/cancel`, { method: 'POST' });
    if (!response.ok) throw new Error(await responseError(response));
    const result = await response.json();
    if (result.status === 'completed') {
      addLog('The scan completed before cancellation reached the worker.');
      cancelScanBtn.textContent = 'Completed';
    } else if (result.status === 'failed') {
      addLog('The scan failed before cancellation reached the worker.');
      activeScanId = '';
      localStorage.removeItem('rt_active_scan');
      setProgress(0, 'Scan failed');
      setScanBusy(false);
    } else if (result.status === 'cancelled') {
      addLog(result.message || 'Cancellation requested.');
      activeScanId = '';
      localStorage.removeItem('rt_active_scan');
      setProgress(Number.parseInt(document.getElementById('progressPct').textContent, 10) || 0, 'Cancelled');
      setScanBusy(false);
    } else {
      throw new Error(`Unexpected cancellation state: ${result.status || 'unknown'}`);
    }
  } catch (error) {
    addLog(`✗ Could not cancel: ${error.message}`);
    cancelScanBtn.disabled = false;
    cancelScanBtn.textContent = 'Cancel scan';
  } finally {
    cancelRequestPending = false;
  }
});

async function resumeActiveScan() {
  let saved;
  try {
    saved = JSON.parse(localStorage.getItem('rt_active_scan') || 'null');
  } catch (_) {
    localStorage.removeItem('rt_active_scan');
    return;
  }
  if (!saved || !/^scan_[a-f0-9]{12}$/.test(saved.scan_id || '')) return;

  activeScanId = saved.scan_id;
  targetInput.value = saved.target || '';
  if (PROFILE_STEPS[saved.scan_type]) selectProfile(saved.scan_type);
  document.getElementById('scanProgress').hidden = false;
  document.getElementById('progressLog').replaceChildren();
  setScanBusy(true);
  cancelScanBtn.hidden = false;
  addLog(`Resuming live status for ${activeScanId}.`);
  try {
    const data = await pollQueuedScan(activeScanId, Date.now());
    if (data) openCompletedReport(data, saved.target || '', saved.scan_type || 'full');
  } catch (error) {
    localStorage.removeItem('rt_active_scan');
    activeScanId = '';
    setProgress(0, `Error: ${error.message}`);
    addLog(`✗ ${error.message}`);
    setScanBusy(false);
  }
}

function logDangerTelemetry(summary) {
  if (!summary) return;
  const completed = (summary.stages_completed || []).length;
  const failed = summary.stages_failed || [];
  const skipped = summary.stages_skipped || [];
  addLog(`☣ Danger stages: ${completed} completed, ${failed.length} failed, ${skipped.length} skipped`);
  addLog(`☣ Bounded traffic: ${summary.requests_sent ?? 0} request(s), ${summary.payloads_sent ?? 0} payload(s) in ${summary.elapsed_seconds ?? '?'}s`);
  if (summary.timed_out) addLog('☣ Time limit reached — remaining stages skipped, report built from completed work');
  if (summary.budget_exhausted && !summary.timed_out) addLog('☣ Request budget was exhausted — coverage is partial');
  if (failed.length) addLog(`☣ Failed stages: ${failed.join(', ')}`);
  if (skipped.length) addLog(`☣ Skipped stages: ${skipped.join(', ')}`);
  const surface = (summary.attack_surface || []).length;
  const probes = (summary.injection_matrix || []).length;
  addLog(`☣ Attack surface: ${surface} input point(s); injection probes: ${probes}`);
  const tested = (summary.owasp_coverage || []).filter((entry) => entry.tested).length;
  addLog(`☣ OWASP Top 10 coverage: ${tested}/10 categories exercised`);
  addLog('☣ All danger findings are candidates requiring manual validation');
}

function profileLabel(profile) {
  return ({ full: 'FULL', recon_only: 'RECON', osint_only: 'OSINT', vuln_only: 'VULN', danger: 'DANGER' })[profile] || 'FULL';
}


async function loadCapabilities() {
  try {
    const response = await fetch('/api/capabilities');
    if (!response.ok) return;
    const payload = await response.json();
    runtimeCapabilities = payload.runtime || null;
    if (payload.version) document.getElementById('versionPill').textContent = `v${payload.version}`;
    const full = (payload.profiles || []).find((profile) => profile.key === 'full');
    if (full?.tool_count) document.getElementById('moduleCount').textContent = `${full.tool_count}+`;

    const danger = payload.danger_mode;
    if (danger && dangerStatus) {
      dangerEnabledOnServer = Boolean(danger.enabled);
      const bounds = danger.bounds || {};
      dangerStatus.textContent = danger.enabled
        ? `Danger Mode is enabled on this server. Bounded per scan: ${bounds.max_scan_seconds ?? '?'}s time limit, `
          + `${bounds.max_requests_total ?? '?'} requests, ${bounds.max_payloads_per_scan ?? '?'} payloads, `
          + `${bounds.max_endpoints ?? '?'} endpoints, ${bounds.idor_max_ids ?? '?'} identifiers per object reference.`
        : (danger.disabled_reason || 'Danger Mode is disabled on this server.');
      refreshDangerGate();
    }
  } catch (_) {
    // Static copy remains a complete fallback.
  }
}
loadCapabilities().finally(resumeActiveScan);

let currentCat = 'all';
let newsCache = null;

async function loadNews(category = 'all') {
  currentCat = category;
  const grid = document.getElementById('newsGrid');
  grid.innerHTML = Array.from({ length: 6 }, () => `
    <div class="news-card news-skeleton"><div class="sk-line sk-short"></div><div class="sk-line sk-long"></div><div class="sk-line sk-med"></div></div>`).join('');
  try {
    if (!newsCache) {
      const response = await apiFetch('/api/news?limit=40');
      if (!response.ok) throw new Error(`News request failed (${response.status})`);
      const data = await response.json();
      newsCache = data.news || [];
    }
    const items = category === 'all' ? newsCache : newsCache.filter((item) => item.category === category);
    renderNewsItems(items, grid);
  } catch (_) {
    grid.innerHTML = '<div class="history-empty">The live feed is temporarily unavailable. The scanner remains usable.</div>';
  }
}

function renderNewsItems(items, grid) {
  if (!items.length) {
    grid.innerHTML = '<div class="history-empty">No items in this category.</div>';
    return;
  }
  grid.innerHTML = items.map((item, index) => {
    const url = safeUrl(item.url || '#');
    const hasLink = url !== '#';
    return `
      <article class="news-card" data-sev="${esc(item.severity)}" style="animation-delay:${index * 0.035}s">
        <div class="nc-hdr"><span class="nc-source">${esc(item.source)}</span><span class="nc-time">${esc(item.published_at || 'recently')}</span></div>
        <div class="nc-title">${esc(item.title)}</div>
        <div class="nc-summary">${esc(item.summary || '')}</div>
        <div class="nc-footer"><div class="nc-tags">${(item.tags || []).map((tag) => `<span class="nc-tag">${esc(tag)}</span>`).join('')}</div>${hasLink ? `<a class="nc-read-more" href="${esc(url)}" target="_blank" rel="noopener noreferrer">READ ↗</a>` : ''}</div>
      </article>`;
  }).join('');
}

document.querySelectorAll('.ncat').forEach((button) => {
  button.addEventListener('click', () => {
    document.querySelectorAll('.ncat').forEach((item) => item.classList.remove('active'));
    button.classList.add('active');
    loadNews(button.dataset.cat);
  });
});
loadNews(currentCat);

function esc(value) {
  return String(value ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function safeUrl(value) {
  try {
    const url = new URL(String(value || ''), window.location.origin);
    return ['http:', 'https:'].includes(url.protocol) ? url.href : '#';
  } catch (_) {
    return '#';
  }
}

(function initParticleNetwork() {
  const canvas = document.getElementById('heroCanvas');
  if (!canvas || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  const context = canvas.getContext('2d');
  if (!context) return;
  const count = window.innerWidth > 1600 ? 110 : 75;
  const linkDistance = 155;
  let width = 0;
  let height = 0;
  let particles = [];

  function resize() {
    const ratio = Math.min(window.devicePixelRatio || 1, 2);
    width = canvas.offsetWidth;
    height = canvas.offsetHeight;
    canvas.width = Math.round(width * ratio);
    canvas.height = Math.round(height * ratio);
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
  }

  function createParticle() {
    return {
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.32,
      vy: (Math.random() - 0.5) * 0.32,
      radius: Math.random() * 1.4 + 0.6,
    };
  }

  function reset() {
    resize();
    particles = Array.from({ length: count }, createParticle);
  }

  function draw() {
    context.clearRect(0, 0, width, height);
    for (let firstIndex = 0; firstIndex < particles.length; firstIndex += 1) {
      const first = particles[firstIndex];
      for (let secondIndex = firstIndex + 1; secondIndex < particles.length; secondIndex += 1) {
        const second = particles[secondIndex];
        const x = first.x - second.x;
        const y = first.y - second.y;
        const distance = Math.hypot(x, y);
        if (distance > linkDistance) continue;
        context.beginPath();
        context.moveTo(first.x, first.y);
        context.lineTo(second.x, second.y);
        context.strokeStyle = `rgba(163,230,53,${(1 - distance / linkDistance) * 0.18})`;
        context.lineWidth = 0.55;
        context.stroke();
      }
      context.beginPath();
      context.arc(first.x, first.y, first.radius, 0, Math.PI * 2);
      context.fillStyle = 'rgba(163,230,53,.46)';
      context.fill();
      first.x += first.vx;
      first.y += first.vy;
      if (first.x < 0 || first.x > width) first.vx *= -1;
      if (first.y < 0 || first.y > height) first.vy *= -1;
    }
    window.requestAnimationFrame(draw);
  }

  reset();
  draw();
  window.addEventListener('resize', reset);
}());
