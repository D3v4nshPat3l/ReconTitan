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
    scanBtn.disabled = !dangerUnlocked;
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
    scanBtn.disabled = false;
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

scanBtn.addEventListener('click', startScan);
targetInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') startScan();
});

async function startScan() {
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

  scanBtn.classList.add('loading');
  scanBtn.disabled = true;
  const progress = document.getElementById('scanProgress');
  progress.hidden = false;
  document.getElementById('progressLog').replaceChildren();
  setProgress(1, 'Validating target...');
  addLog(`Profile selected: ${selectedProfile}`);

  const steps = PROFILE_STEPS[selectedProfile];
  const startedAt = Date.now();
  const elapsed = () => Math.round((Date.now() - startedAt) / 1000);
  let stepIndex = 0;
  // Danger Mode runs many more modules, so its steps advance more slowly and the
  // ticker keeps reporting elapsed time after the named steps are exhausted.
  // Without that the bar froze at 92% and the scan looked hung.
  const stepInterval = selectedProfile === 'danger' ? 2600 : 950;
  const timer = window.setInterval(() => {
    if (stepIndex < steps.length) {
      const percent = Math.min(92, Math.round(((stepIndex + 1) / (steps.length + 1)) * 92));
      const label = steps[stepIndex];
      setProgress(percent, `${label}... (${elapsed()}s)`);
      addLog(`→ ${label}`);
      stepIndex += 1;
      return;
    }
    setProgress(92, `Finalizing findings and report... (${elapsed()}s)`);
  }, stepInterval);

  try {
    let requestUrl = `/api/test-scan?target=${encodeURIComponent(target)}&scan_type=${encodeURIComponent(selectedProfile)}`;
    if (selectedProfile === 'danger') {
      requestUrl += `&danger_acknowledgement=${encodeURIComponent(DANGER_PHRASE)}`;
      addLog('☣ Danger Mode armed — bounded simulation traffic only, all results are candidates');
    }
    const response = await apiFetch(requestUrl);
    window.clearInterval(timer);
    if (!response.ok) {
      let detail = `Server returned ${response.status}`;
      try {
        const payload = await response.json();
        detail = payload.detail || payload.error || detail;
      } catch (_) {
        // Keep status-based message.
      }
      throw new Error(detail);
    }
    const data = await response.json();
    setProgress(100, 'Assessment complete');
    addLog(`✓ ${data.tools_run} modules completed with ${data.total_findings} findings in ${data.total_time_seconds}s`);

    Object.entries(data.tool_results || {}).forEach(([tool, result]) => {
      const status = result.status === 'ok' ? '✓' : '✗';
      addLog(`${status} ${tool}: ${result.findings ?? 0} finding(s), ${result.time_seconds ?? '—'}s`);
    });
    if (data.ai_summary?.risk_level) addLog(`AI risk level: ${data.ai_summary.risk_level}`);
    logDangerTelemetry(data.danger_summary);

    scanCount += 1;
    localStorage.setItem('rt_scan_count', String(scanCount));
    document.getElementById('hsScans').textContent = String(scanCount);

    sessionStorage.setItem('rt_scan_target', data.target || target);
    sessionStorage.setItem('rt_scan_profile', data.scan_type || selectedProfile);
    sessionStorage.setItem('rt_scan_data', JSON.stringify(data));
    addLog('Opening the interactive report...');
    window.setTimeout(() => {
      window.location.href = `/report.html?target=${encodeURIComponent(data.target || target)}&scan_type=${encodeURIComponent(data.scan_type || selectedProfile)}&cached=1`;
    }, 500);
  } catch (error) {
    window.clearInterval(timer);
    setProgress(0, `Error: ${error.message}`);
    addLog(`✗ ${error.message}`);
    scanBtn.classList.remove('loading');
    scanBtn.disabled = false;
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
loadCapabilities();

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
