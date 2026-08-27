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

/* ── RECONTITAN report.js — web-check.xyz style renderer ── */

const $ = id => document.getElementById(id);
// Use ?? rather than || so a legitimate 0 renders as "0" instead of vanishing.
const esc = s => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
const safeUrl = value => { try { const u = new URL(String(value||''), window.location.origin); return ['http:','https:'].includes(u.protocol) ? u.href : '#'; } catch (_) { return '#'; } };
let findingRegistry = [];
const findingRef = finding => { const index = findingRegistry.push(finding) - 1; return `data-finding-index="${index}"`; };

// ── UTILS ──────────────────────────────────────────────────
const SEV = { critical:0, high:1, medium:2, low:3, info:4 };

function sevClass(s) {
  return { critical:'red', high:'orange', medium:'yellow', low:'cyan', info:'dim' }[s] || 'dim';
}

// ── VULNERABILITY EXPLANATIONS — human-readable, sourced from OWASP/CWE ──
const VULN_EXPLAIN = {
  'security_headers': {
    'Strict-Transport-Security': {
      what: 'HSTS tells browsers to ONLY use HTTPS. Without it, attackers can intercept your connection using a "man-in-the-middle" attack — they sit between you and the website and read everything.',
      fix: 'Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains',
      ref: 'https://owasp.org/www-project-secure-headers/#strict-transport-security',
      cwe: 'CWE-319',
    },
    'Content-Security-Policy': {
      what: 'CSP prevents Cross-Site Scripting (XSS) attacks by telling the browser which scripts are allowed to run. Without it, an attacker can inject malicious JavaScript that steals user data, hijacks sessions, or redirects users to phishing sites.',
      fix: "Add a strict CSP header. Start with: Content-Security-Policy: default-src 'self'",
      ref: 'https://owasp.org/www-project-secure-headers/#content-security-policy',
      cwe: 'CWE-79',
    },
    'X-Frame-Options': {
      what: 'This header prevents your site from being loaded inside a hidden iframe. Without it, attackers can overlay invisible frames on top of legitimate pages to trick users into clicking — this is called "Clickjacking".',
      fix: 'Add: X-Frame-Options: DENY (or SAMEORIGIN if you use iframes internally)',
      ref: 'https://owasp.org/www-project-secure-headers/#x-frame-options',
      cwe: 'CWE-1021',
    },
    'X-Content-Type-Options': {
      what: 'Without this header, browsers may "guess" the content type of files, which attackers exploit to make the browser execute a disguised script as if it were a normal file.',
      fix: 'Add: X-Content-Type-Options: nosniff',
      ref: 'https://owasp.org/www-project-secure-headers/#x-content-type-options',
      cwe: 'CWE-16',
    },
    'Referrer-Policy': {
      what: 'Controls how much URL information is shared when users click links. Without it, sensitive data in URLs (tokens, IDs) may leak to third-party sites.',
      fix: 'Add: Referrer-Policy: strict-origin-when-cross-origin',
      ref: 'https://owasp.org/www-project-secure-headers/#referrer-policy',
      cwe: 'CWE-200',
    },
    'Permissions-Policy': {
      what: 'Controls which browser features (camera, microphone, geolocation) your site can access. Without it, injected scripts could silently access the user\'s camera or location.',
      fix: 'Add: Permissions-Policy: camera=(), microphone=(), geolocation=()',
      ref: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy',
      cwe: 'CWE-250',
    },
    'X-XSS-Protection': {
      what: 'Legacy browser XSS filters are obsolete and can introduce security issues. Modern applications should disable this header and rely on a strict Content Security Policy plus contextual output encoding.',
      fix: 'Use X-XSS-Protection: 0 and rely on a strict Content Security Policy.',
      ref: 'https://owasp.org/www-project-secure-headers/#x-xss-protection',
      cwe: 'CWE-79',
    },
  },
  'ssl_certificate': {
    what: 'SSL/TLS encrypts the connection between the user and the server. An expired or misconfigured certificate means data travels in plain text — passwords, cookies, and personal data are exposed.',
    ref: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security',
    cwe: 'CWE-295',
  },
  'cors_misconfiguration': {
    what: 'CORS controls which other websites can make requests to your API. A misconfiguration means any website can read your users\' private data, steal tokens, or perform actions on their behalf.',
    ref: 'https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny',
    cwe: 'CWE-346',
  },
  'cookie_security': {
    what: 'Cookies without security flags can be stolen via XSS attacks (HttpOnly), sent over unencrypted connections (Secure), or used in cross-site request forgery attacks (SameSite).',
    ref: 'https://owasp.org/www-community/controls/SecureCookieAttribute',
    cwe: 'CWE-614',
  },
  'information_disclosure': {
    what: 'When the server reveals its version (e.g., "Apache 2.4.51"), attackers know exactly which vulnerabilities to exploit. It\'s like putting your house key under the doormat and announcing it.',
    ref: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server',
    cwe: 'CWE-200',
  },
  'waf_detection': {
    what: 'A Web Application Firewall (WAF) acts as a shield between users and your server, blocking common attacks like SQL injection and XSS before they reach your application.',
    ref: 'https://owasp.org/www-community/Web_Application_Firewall',
  },
};

function getExplanation(category, headerName) {
  if (category === 'security_headers' && headerName) {
    return VULN_EXPLAIN.security_headers?.[headerName] || null;
  }
  return VULN_EXPLAIN[category] || null;
}

function explainBlock(category, headerName) {
  const e = getExplanation(category, headerName);
  if (!e) return '';
  return `<div class="vuln-explain">
    <div class="vuln-explain-title">💡 WHAT THIS MEANS</div>
    <div class="vuln-explain-text">${esc(e.what)}</div>
    ${e.fix ? `<div class="vuln-explain-text" style="margin-top:.3rem;color:var(--green)">✓ Fix: ${esc(e.fix)}</div>` : ''}
    ${e.ref ? `<a class="vuln-explain-ref" href="${safeUrl(e.ref)}" target="_blank" rel="noopener noreferrer">📖 Learn more (OWASP) ↗</a>` : ''}
    ${e.cwe ? `<span class="owasp-badge">${e.cwe}</span>` : ''}
  </div>`;
}

function card(title, bodyHtml, colorClass='', id='') {
  return `<div class="wc-card"${id ? ` id="${id}"` : ''}>
  <div class="wc-card-head">
    <span class="wc-card-title ${colorClass}">${title}</span>
    <div class="wc-card-icons"><button title="info">ⓘ</button><button title="refresh">↺</button></div>
  </div>
  <div class="wc-card-body">${bodyHtml}</div>
</div>`;
}

function kv(key, val, cls='') {
  return `<div class="kv-row"><span class="kv-key">${esc(key)}</span><span class="kv-val ${cls}">${val}</span></div>`;
}

function checkRow(label, pass, note='') {
  const icon = pass === true ? '<span class="check-pass">✔ Yes</span>'
             : pass === false ? '<span class="check-fail">✘ No</span>'
             : `<span class="check-warn">${esc(pass)}</span>`;
  return `<div class="check-row"><span class="check-label">${esc(label)}</span>${icon}</div>`;
}

function li(items) {
  return '<ul class="inline-list">' + items.map(i => `<li>${i}</li>`).join('') + '</ul>';
}

// ── RENDER FUNCTIONS PER TOOL ──────────────────────────────

function renderWhois(findings) {
  const f = findings[0];
  if (!f) return '';
  const lines = (f.evidence||'').split('\n').filter(l=>l.trim());
  const rows = lines.map(l => {
    const [k,...rest] = l.split(':');
    return kv(k.trim(), esc(rest.join(':').trim()));
  }).join('');
  const sev = f.severity;
  const title = sev === 'info' ? 'WHOIS' : `WHOIS <span class="sev-pill ${sev}">${sev.toUpperCase()}</span>`;
  return card(title, rows || '<div class="card-empty">No WHOIS data</div>', 'green', 'card-whois');
}

function renderDns(findings) {
  const main = findings.find(f=>f.category==='dns_records');
  if (!main) return '';
  const lines = (main.evidence||'').split('\n').filter(l=>l.trim());
  let body = '';
  lines.forEach(l => {
    const parts = l.trim().split(/\s+/);
    if (parts[0] && ['A','AAAA','MX','NS','TXT','CNAME','SOA'].includes(parts[0])) {
      body += `<span class="record-type">${parts[0]}</span>`;
      body += `<div class="kv-val" style="font-size:.75rem;margin-bottom:.2rem">${esc(parts.slice(1).join(' '))}</div>`;
    } else {
      body += `<div style="color:var(--dim);font-size:.72rem;padding:.1rem 0;padding-left:.5rem">${esc(l.trim())}</div>`;
    }
  });

  const spf   = findings.find(f=>f.title&&f.title.includes('SPF'));
  const dmarc = findings.find(f=>f.title&&f.title.includes('DMARC'));
  const emailBody = checkRow('SPF Record', !spf) + checkRow('DMARC Policy', !dmarc);

  // DNS card spans 2 columns for readability
  const dnsCard = `<div class="wc-card span-2" id="card-dns">
    <div class="wc-card-head"><span class="wc-card-title yellow">DNS Records</span><div class="wc-card-icons"><button>ⓘ</button><button>↺</button></div></div>
    <div class="wc-card-body">${body||'<div class="card-empty">No records</div>'}</div>
  </div>`;
  return dnsCard + card('Email Security', emailBody, 'yellow', 'card-email');
}

function renderSsl(findings) {
  const main = findings.find(f=>f.category==='ssl_certificate');
  if (!main) return card('TLS / SSL', '<div class="card-empty">Could not connect on port 443</div>', 'orange', 'card-ssl');
  const lines = (main.evidence||'').split('\n');
  const get = key => (lines.find(l=>l.includes(key))||'').split(':').slice(1).join(':').trim();
  const body = kv('Issuer', esc(get('Issuer')))
    + kv('Valid From', esc(get('Valid From')))
    + kv('Valid Until', esc(get('Valid Until')))
    + kv('Protocol', esc(get('Protocol')), 'green')
    + kv('Cipher Suite', esc(get('Cipher Suite')));

  const weakTls = findings.find(f=>f.category==='weak_tls');
  const weakRow = checkRow('TLS 1.3', !weakTls);
  const expiry  = main.severity;
  const cls = expiry === 'critical' ? 'red' : expiry === 'medium' ? 'yellow' : 'green';

  return card(`TLS / SSL <span class="sev-pill ${expiry}">${expiry.toUpperCase()}</span>`,
              body + weakRow, cls, 'card-ssl');
}

function renderHeaders(findings) {
  const missing = findings.filter(f=>f.category==='security_headers');
  const HDRS = ['Strict-Transport-Security','Content-Security-Policy','X-Frame-Options',
                'X-Content-Type-Options','Referrer-Policy','Permissions-Policy','X-XSS-Protection'];
  const missingNames = missing.map(f => (f.title||'').replace('Missing Security Header: ',''));

  // Make each missing header row clickable → opens modal with AI button
  let body = HDRS.map(h => {
    const isMissing = missingNames.includes(h);
    const finding = missing.find(f => (f.title||'').includes(h));
    if (isMissing && finding) {
      return `<div class="check-row clickable-finding" ${findingRef(finding)} style="cursor:pointer;border-radius:3px;transition:.1s">
        <span class="check-label">${esc(h)}</span>
        <span class="check-fail">✘ Missing <span style="font-size:.6rem;color:var(--dim);margin-left:.3rem">click to analyze →</span></span>
      </div>`;
    }
    return checkRow(h, true);
  }).join('');

  const leak = findings.find(f=>f.category==='information_disclosure');
  body += leak ? checkRow('Server version hidden', false) : checkRow('Server version hidden', true);
  const critical = ['Content-Security-Policy','Strict-Transport-Security','X-Frame-Options'];
  const firstMissing = critical.find(h => missingNames.includes(h));
  if (firstMissing) body += explainBlock('security_headers', firstMissing);
  if (leak) body += explainBlock('information_disclosure');
  return card('HTTP Security', body, 'yellow', 'card-headers');
}

function renderPorts(findings) {
  const main = findings.find(f=>f.category==='port_scan');
  const dangerous = findings.filter(f=>f.category==='dangerous_port');

  if (main) {
    const lines = (main.evidence||'').split('\n').filter(l=>l.includes('/tcp'));
    if (lines.length) {
      let body = '<table class="port-table"><thead><tr><th>PORT</th><th>SERVICE</th><th>RISK</th></tr></thead><tbody>';
      lines.forEach(l => {
        const m = l.match(/(\d+)\/tcp\s+open\s+(\S+)/);
        if (m) {
          const isDangerous = dangerous.find(df => df.evidence && df.evidence.includes(m[1]+'/tcp'));
          const risk = isDangerous ? `<span class="port-danger">⚠ HIGH</span>` : `<span class="port-open">✔ OK</span>`;
          body += `<tr><td>${m[1]}</td><td>${esc(m[2])}</td><td>${risk}</td></tr>`;
        }
      });
      body += '</tbody></table>';
      return card('Open Ports', body, 'green', 'card-ports');
    }
  }

  // No binary — show informational well-known ports card instead of blank
  const body = kv('Scan status', '<span class="kv-val yellow">Binary not installed</span>')
    + kv('Fallback', '<span class="kv-val dim">HackerTarget API</span>')
    + '<div class="port-info-grid" style="margin-top:.5rem">'
    + '<div class="port-info-item">Port <strong>80</strong> — HTTP</div>'
    + '<div class="port-info-item">Port <strong>443</strong> — HTTPS</div>'
    + '<div class="port-info-item">Port <strong>22</strong> — SSH</div>'
    + '<div class="port-info-item">Port <strong>25</strong> — SMTP</div>'
    + '<div class="port-info-item">Port <strong>3306</strong> — MySQL</div>'
    + '<div class="port-info-item">Port <strong>8080</strong> — HTTP-Alt</div>'
    + '</div>'
    + '<div class="kv-row" style="margin-top:.4rem"><span class="kv-key">Install Nmap for full results</span><a href="https://nmap.org" target="_blank" class="kv-val cyan" style="font-size:.7rem">nmap.org ↗</a></div>';
  return card('Open Ports', body, 'orange', 'card-ports');
}

function renderSubdomains(findings) {
  const crtsh = findings.filter(f=>f.tool==='crt.sh'||f.tool==='subfinder'||f.tool==='amass');
  if (!crtsh.length) return '';
  const main = crtsh.find(f=>f.category==='subdomain_enumeration');
  if (!main) return '';
  const lines = (main.evidence||'').split('\n').filter(l=>l.includes('•'));
  const subs  = lines.map(l=>l.replace('•','').trim()).filter(Boolean);
  const sensitiveF = crtsh.find(f=>f.category==='sensitive_subdomains');
  const sensNames  = sensitiveF ? (sensitiveF.evidence||'').split('\n').map(l=>l.replace('•','').trim()) : [];

  const tags = subs.map(s =>
    `<span class="subdomain-tag${sensNames.includes(s)?' sensitive':''}">${esc(s)}</span>`
  ).join('');

  const body = `${kv('Total found', subs.length)}
    ${sensNames.length ? kv('Sensitive','<span class="kv-val orange">'+sensNames.length+'</span>','') : ''}
    <div class="tag-cloud">${tags}</div>`;
  return card(`Subdomains <span class="sev-pill ${sensitiveF?'medium':'info'}">${subs.length}</span>`,
              body, 'cyan', 'card-subdomains');
}

function renderWaf(findings) {
  const f = findings.find(f=>f.category==='waf_detection');
  if (!f) return '';
  const detected = !(f.title||'').toLowerCase().includes('no waf');
  const body = checkRow('WAF Detected', detected)
    + kv('Status', esc(f.title||''), detected ? 'green' : 'red');
  return card('Firewall / WAF', body, detected ? 'green' : 'orange', 'card-waf');
}

function renderIpInfo(findings) {
  const f = findings.find(f=>f.category==='ip_geolocation');
  if (!f) return '';
  const lines = (f.evidence||'').split('\n');
  const get = k => (lines.find(l=>l.includes(k))||'').split(':').slice(1).join(':').trim();
  const body = kv('IP Address', esc(get('IP Address')))
    + kv('Organization', esc(get('Organization')))
    + kv('Location', esc(get('Location')))
    + kv('Timezone', esc(get('Timezone')));

  const revIp = findings.find(f=>f.category==='reverse_ip');
  const revRow = revIp ? kv('Shared Hosts', esc((revIp.title||'').match(/\d+/)?.[0]||'?'), 'orange') : '';

  return card('IP / Geolocation', body + revRow, 'cyan', 'card-ip');
}

function renderCors(findings) {
  const f = findings.find(f=>f.category==='cors_misconfiguration');
  if (!f) return '';
  const vuln = !(f.title||'').includes('No Obvious');
  const body = checkRow('CORS Secure', !vuln) + (vuln ? `<div class="kv-val red" style="margin-top:.4rem">${esc(f.title)}</div>` : '');
  return card('CORS Policy', body, vuln ? 'red' : 'green', 'card-cors');
}

function renderCookies(findings) {
  const f = findings.find(f=>f.category==='cookie_security');
  if (!f) return '';
  const ok = f.severity === 'info';
  const body = checkRow('HttpOnly', ok)
    + checkRow('Secure Flag', ok)
    + checkRow('SameSite', ok);
  return card('Cookie Flags', body, ok ? 'green' : 'yellow', 'card-cookies');
}

function renderWhois2(findings) {
  const wayback = findings.find(f=>f.tool==='wayback_machine'&&f.category==='archive_history');
  if (!wayback) return '';
  const lines = (wayback.evidence||'').split('\n');
  const get = k => (lines.find(l=>l.includes(k))||'').split(':').slice(1).join(':').trim();
  const body = kv('Latest Snapshot', esc(get('Latest snapshot')))
    + kv('Total URLs', esc(get('Total archived URLs')));
  const interesting = findings.find(f=>f.category==='sensitive_historical_urls');
  const intRow = interesting ? kv('Sensitive paths', '<span class="kv-val orange">'+((interesting.evidence||'').split('\n').filter(l=>l.includes('•')).length)+'</span>') : '';
  return card('Wayback Machine', body + intRow, 'cyan', 'card-wayback');
}

function renderThreatIntel(findings) {
  const vt = findings.find(f=>f.tool==='virustotal');
  const gn = findings.find(f=>f.tool==='greynoise');
  if (!vt && !gn) return '';
  let body = '';
  if (vt) {
    const m = (vt.title||'').match(/(\d+) Malicious/);
    const mal = m ? parseInt(m[1]) : 0;
    body += checkRow('VirusTotal Clean', mal === 0) + kv('Detections', mal, mal>0?'red':'green');
  }
  if (gn) {
    const cls = (gn.title||'').includes('MALICIOUS') ? 'red' : 'green';
    body += kv('GreyNoise', esc((gn.title||'').replace('GreyNoise — IP','').replace(/\w+\s+Classification:/,'').trim()), cls);
  }
  return card('Threats', body, 'red', 'card-threats');
}

function renderVulns(findings) {
  const vulns = findings.filter(f=>['vulnerability','cve_finding','injection','secret_leak','subdomain_takeover','javascript_secret','javascript_risky_sink'].includes(f.category));
  if (!vulns.length) return '';
  const sorted = [...vulns].sort((a,b) => SEV[a.severity]-SEV[b.severity]);
  const body = sorted.map(f => `
    <div class="finding-item" ${findingRef(f)}>
      <div class="finding-item-title">
        <span class="sev-pill ${esc(f.severity)}">${esc(String(f.severity||'info').toUpperCase())}</span>
        ${esc(f.title)}
      </div>
      <div class="finding-item-meta">${esc(f.tool)} · ${esc(f.category)}</div>
      ${f.remediation?'<div class="finding-has-fix">✓ Fix available</div>':''}
    </div>`).join('');
  return card(`Vulnerabilities <span class="sev-pill ${sorted[0]?.severity||'info'}">${vulns.length}</span>`,
              body, 'red', 'card-vulns');
}

function renderRobots(findings) {
  const f = findings.find(f=>f.category==='robots_txt');
  if (!f) return '';
  const sensitive = findings.find(f=>f.category==='sensitive_paths_disclosed'&&f.tool==='robots_txt');
  const body = kv('robots.txt', 'Present', 'green')
    + kv('Disallow entries', (f.title||'').match(/\d+/)?.[0]||'?')
    + (sensitive ? kv('Sensitive paths', '<span class="kv-val orange">'+(sensitive.evidence||'').split('\n').length+'</span>') : '');
  return card('Robots / Sitemap', body, 'yellow', 'card-robots');
}

function renderHttpProbe(findings) {
  const f = findings.find(f=>f.tool==='httpx_probe'&&f.category==='http_probe');
  if (!f) return '';
  const lines = (f.evidence||'').split('\n');
  const get = k => (lines.find(l=>l.includes(k))||'').split(':').slice(1).join(':').trim();
  const tech = findings.find(f=>f.category==='tech_fingerprint');
  const techList = tech ? (tech.evidence||'').split('\n').filter(l=>l.includes('•')).map(l=>l.replace('•','').trim()) : [];
  const body = kv('Status', esc(get('Status Code')), parseInt(get('Status Code'))>=400?'red':'green')
    + kv('Title', esc(get('Page Title')))
    + kv('Server', esc(get('Server')))
    + (techList.length ? kv('Technologies', esc(techList.join(', '))) : '');
  return card('HTTP Probe', body, 'green', 'card-http');
}


function renderTechStack(findings) {
  const f = findings.find(item=>item.category==='tech_stack') || findings.find(item=>item.category==='tech_fingerprint');
  if (!f) return '';
  const items = (f.evidence||'').split('\n').filter(line=>line.trim()).slice(0,30);
  const body = items.length
    ? li(items.map(item=>esc(item.replace(/^\s*•\s*/,''))))
    : `<div class="kv-val">${esc(f.description||'Technology fingerprint available')}</div>`;
  return card('Technology Stack', body, 'cyan', 'card-tech');
}

function renderFavicon(findings) {
  const f = findings.find(item=>item.category==='favicon_hash');
  if (!f) return '';
  const lines = (f.evidence||'').split('\n').filter(Boolean);
  const get = key => (lines.find(line=>line.startsWith(key))||'').split(':').slice(1).join(':').trim();
  const body = kv('MurmurHash3', esc(get('Shodan MurmurHash3')))
    + kv('MD5', esc(get('MD5')))
    + kv('Asset matches', esc(get('Shodan indexed matches')||'API key not configured'));
  return card('Favicon Hash Lookup', body, 'cyan', 'card-favicon');
}

function renderJsAnalysis(findings) {
  const js = findings.filter(item=>String(item.category||'').startsWith('javascript_'));
  if (!js.length) return '';
  const order = {critical:0,high:1,medium:2,low:3,info:4};
  const body = [...js].sort((a,b)=>(order[a.severity]??9)-(order[b.severity]??9)).map(f=>`
    <div class="finding-item" ${findingRef(f)}>
      <div class="finding-item-title"><span class="sev-pill ${esc(f.severity)}">${esc(String(f.severity||'info').toUpperCase())}</span>${esc(f.title)}</div>
      <div class="finding-item-meta">${esc(f.category)}</div>
    </div>`).join('');
  return card(`JavaScript Analysis <span class="sev-pill info">${js.length}</span>`, body, 'yellow', 'card-js');
}

function renderTakeover(findings) {
  const summary = findings.find(item=>item.category==='subdomain_takeover_summary');
  const issues = findings.filter(item=>item.category==='subdomain_takeover');
  if (!summary && !issues.length) return '';
  let body = summary ? `<div class="kv-val" style="margin-bottom:.5rem">${esc(summary.description)}</div>` : '';
  body += issues.length ? issues.map(f=>`
    <div class="finding-item" ${findingRef(f)}>
      <div class="finding-item-title"><span class="sev-pill high">HIGH</span>${esc(f.title)}</div>
      <div class="finding-item-meta">Manual verification required</div>
    </div>`).join('') : checkRow('Dangling SaaS delegation', true);
  return card(`Subdomain Takeover <span class="sev-pill ${issues.length?'high':'info'}">${issues.length}</span>`, body, issues.length?'red':'green', 'card-takeover');
}

// ── DANGER MODE ─────────────────────────────────────────────
const DANGER_CATEGORIES = [
  'danger_attack_surface', 'danger_dangerous_feature', 'danger_host_discovery', 'danger_fingerprint',
  'danger_dns_enumeration', 'danger_zone_transfer', 'danger_injection_sql', 'danger_injection_command',
  'danger_injection_html', 'danger_injection_xss', 'danger_injection_ssti', 'danger_injection_xxe',
  'danger_injection_nosql', 'danger_ssrf', 'danger_injection_matrix', 'danger_reverse_shell',
  'danger_directory_fuzzing', 'danger_sensitive_path', 'danger_directory_listing', 'danger_verbose_error',
  'danger_path_traversal', 'danger_idor', 'danger_idor_summary', 'danger_missing_auth',
  'danger_weak_tls', 'danger_plaintext_http', 'danger_tls_review', 'danger_insecure_design',
  'danger_missing_rate_limit', 'danger_misconfiguration', 'danger_outdated_components',
  'danger_auth_weakness', 'danger_session_cookie', 'danger_integrity', 'danger_deserialization',
  'danger_monitoring', 'danger_owasp_matrix',
  'danger_dom_xss', 'danger_prototype_pollution', 'danger_dom_clobbering', 'danger_postmessage',
  'danger_dom_summary', 'danger_business_logic', 'danger_business_logic_summary',
  'danger_mass_assignment', 'danger_data_exposure', 'danger_data_exposure_summary',
  'danger_cors', 'danger_open_redirect', 'danger_graphql', 'danger_jwt', 'danger_crlf',
  'danger_host_injection', 'danger_advanced_summary', 'danger_coverage',
];

function isDangerFinding(finding) {
  return DANGER_CATEGORIES.includes(finding.category) || finding.requires_manual_validation === true;
}

function renderDangerBanner(summary) {
  const slot = $('dangerBannerSlot');
  if (!slot) return;
  const failed = summary.stages_failed || [];
  const skipped = summary.stages_skipped || [];
  const confirmed = summary.exploits_confirmed || 0;

  // "Budget exhausted" and "time limit reached" need different fixes, so name
  // the ceiling that actually stopped the scan rather than lumping them together.
  let limitNotice = '';
  if (summary.timed_out) {
    limitNotice = `<span class="danger-banner-warn">stopped at the ${esc(summary.elapsed_seconds ?? '?')}s time limit`
      + `${skipped.length ? ` — ${esc(skipped.length)} stage(s) skipped` : ''} — raise DANGER_MAX_SCAN_SECONDS</span>`;
  } else if (summary.budget_exhausted) {
    limitNotice = '<span class="danger-banner-warn">request budget spent — coverage is partial'
      + ' — raise DANGER_MAX_REQUESTS_TOTAL / DANGER_MAX_PAYLOADS_PER_SCAN</span>';
  }

  const exploitLine = confirmed
    ? `<strong>${esc(confirmed)} finding(s) below were confirmed by exploitation</strong> — the scanner reproduced
       the issue and captured proof (a version banner, an arithmetic result, or a reflection context). No records,
       credentials, or personal data were extracted. Everything else is a detection candidate requiring manual
       validation.`
    : `Every result below is a <strong>detection candidate requiring manual validation</strong>. Nothing was
       confirmed by exploitation in this scan.`;

  slot.innerHTML = `
    <div class="danger-banner">
      <div class="danger-banner-head">
        <span class="danger-banner-tag">☣ DANGER MODE — PENETRATION TEST SIMULATION</span>
        ${confirmed ? `<span class="exploited-badge">${esc(confirmed)} EXPLOITED</span>` : ''}
      </div>
      <p class="danger-banner-text">
        ${exploitLine}
        No data was created, modified, or deleted, no credentials were used against live accounts, and no reverse
        shell was connected.
      </p>
      <div class="danger-banner-stats">
        <span><b>${esc(summary.requests_sent ?? 0)}</b> requests</span>
        <span><b>${esc(summary.payloads_sent ?? 0)}</b> payloads</span>
        <span><b>${esc(summary.elapsed_seconds ?? 0)}s</b> elapsed</span>
        <span><b>${esc((summary.stages_completed || []).length)}</b> stages completed</span>
        <span><b>${esc(failed.length)}</b> failed</span>
        <span><b>${esc(skipped.length)}</b> skipped</span>
        <span><b>${esc((summary.attack_surface || []).length)}</b> input points</span>
        ${limitNotice}
      </div>
    </div>`;
  slot.style.display = 'block';
}

function renderOwaspMatrix(summary) {
  const coverage = summary.owasp_coverage || [];
  if (!coverage.length) return '';
  const rows = coverage.map((entry) => `
    <tr>
      <td>${esc(entry.category)}</td>
      <td class="${entry.tested ? 'owasp-tested' : 'owasp-untested'}">${entry.tested ? 'TESTED' : 'NOT TESTED'}</td>
      <td>${esc(entry.findings ?? 0)}</td>
    </tr>`).join('');
  const tested = coverage.filter((entry) => entry.tested).length;
  const body = `<table class="danger-table">
      <thead><tr><th>OWASP TOP 10 (2021)</th><th>COVERAGE</th><th>FINDINGS</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    <div class="danger-note">NOT TESTED means unassessed, not clean.</div>`;
  return card(`OWASP Coverage <span class="sev-pill info">${tested}/10</span>`, body, 'orange', 'card-owasp');
}

function renderAttackSurface(summary) {
  const items = summary.attack_surface || [];
  if (!items.length) return '';
  const counts = {};
  items.forEach((item) => { counts[item.input_type] = (counts[item.input_type] || 0) + 1; });
  const summaryRows = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .map(([type, count]) => kv(type.replace(/_/g, ' '), esc(count)))
    .join('');
  const list = items.slice(0, 40).map((item) => `
    <div class="danger-endpoint">
      <span class="danger-method">${esc(item.method)}</span>
      <span class="danger-url">${esc(item.url)}</span>
      <span class="danger-params">${esc((item.parameters || []).join(', ') || 'no parameters')}</span>
    </div>`).join('');
  return card(`Attack Surface <span class="sev-pill info">${items.length}</span>`,
    summaryRows + `<div class="danger-endpoints">${list}</div>`, 'cyan', 'card-attack-surface');
}

function renderInjectionMatrix(summary) {
  const matrix = summary.injection_matrix || [];
  if (!matrix.length) return '';
  const grouped = new Map();
  matrix.forEach((entry) => {
    const key = `${entry.endpoint}||${entry.injection_type}`;
    const bucket = grouped.get(key) || { endpoint: entry.endpoint, type: entry.injection_type, probes: 0, signals: 0 };
    bucket.probes += 1;
    if (entry.signal && entry.signal !== 'none') bucket.signals += 1;
    grouped.set(key, bucket);
  });
  const rows = [...grouped.values()].slice(0, 60).map((bucket) => `
    <tr>
      <td class="danger-url">${esc(bucket.endpoint)}</td>
      <td>${esc(bucket.type)}</td>
      <td>${esc(bucket.probes)}</td>
      <td class="${bucket.signals ? 'owasp-untested' : 'owasp-tested'}">${bucket.signals ? `${esc(bucket.signals)} signal(s)` : 'no signal'}</td>
    </tr>`).join('');
  const body = `<table class="danger-table">
      <thead><tr><th>ENDPOINT</th><th>TYPE</th><th>PROBES</th><th>RESULT</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    <div class="danger-note">No signal is not evidence the endpoint is safe.</div>`;
  return card(`Injection Matrix <span class="sev-pill info">${matrix.length}</span>`, body, 'yellow', 'card-injection-matrix');
}

function renderExploited(findings) {
  const exploited = findings.filter((f) => f.exploited);
  if (!exploited.length) return '';
  const sorted = [...exploited].sort((a, b) => (SEV[a.severity] ?? 9) - (SEV[b.severity] ?? 9));
  const body = sorted.map((f) => `
    <div class="finding-item exploited-item" ${findingRef(f)}>
      <div class="finding-item-title">
        <span class="sev-pill ${esc(f.severity)}">${esc(String(f.severity || 'info').toUpperCase())}</span>
        <span class="exploited-badge">EXPLOITED</span>
        ${esc(String(f.title || '').replace('[EXPLOITED] ', ''))}
      </div>
      <div class="exploit-row"><span class="exploit-key">Technique</span><span class="exploit-val">${esc(f.exploit_technique || '—')}</span></div>
      <div class="exploit-row"><span class="exploit-key">Proof</span><span class="exploit-val">${esc(f.exploit_proof || '—')}</span></div>
      <div class="exploit-row"><span class="exploit-key">Impact</span><span class="exploit-val">${esc(f.exploit_impact || '—')}</span></div>
      <div class="danger-validate">✓ Fix included — click for the full remediation</div>
    </div>`).join('');
  return card(`⚡ Exploited &amp; Confirmed <span class="sev-pill critical">${exploited.length}</span>`,
    body, 'red', 'card-exploited');
}

function renderDangerFindings(findings) {
  const danger = findings
    .filter(isDangerFinding)
    .filter((f) => f.category !== 'danger_owasp_matrix' && !f.exploited);
  if (!danger.length) return '';
  const sorted = [...danger].sort((a, b) => (SEV[a.severity] ?? 9) - (SEV[b.severity] ?? 9));
  const actionable = sorted.filter((f) => f.severity !== 'info');
  const shown = (actionable.length ? actionable : sorted).slice(0, 60);
  const body = shown.map((f) => `
    <div class="finding-item" ${findingRef(f)}>
      <div class="finding-item-title">
        <span class="sev-pill ${esc(f.severity)}">${esc(String(f.severity || 'info').toUpperCase())}</span>
        ${esc(f.title)}
      </div>
      <div class="finding-item-meta">${esc(f.tool)} · ${esc(f.owasp_category || f.category)}</div>
      <div class="danger-validate">⚠ Candidate — manual validation required</div>
    </div>`).join('');
  return card(`Danger Findings <span class="sev-pill ${shown[0]?.severity || 'info'}">${danger.length}</span>`,
    body, 'red', 'card-danger-findings');
}

// ── AI SUMMARY BANNER ───────────────────────────────────────
function renderAiSummary(ai, target) {
  if (!ai) return;
  const risk = ai.risk_level || 'INFO';
  const riskColors = {
    CRITICAL:'#ef5350', HIGH:'#ffa726', MEDIUM:'#cddc39', LOW:'#8bc34a', CLEAN:'#4dd0e1'
  };
  const riskBg = {
    CRITICAL:'rgba(239,83,80,.08)', HIGH:'rgba(255,167,38,.08)',
    MEDIUM:'rgba(205,220,57,.06)', LOW:'rgba(139,195,74,.06)', CLEAN:'rgba(77,208,225,.06)'
  };
  const color = riskColors[risk] || '#8bc34a';
  const bg    = riskBg[risk] || 'rgba(139,195,74,.06)';

  const recs = (ai.top_recommendations || []).map(r =>
    `<li style="margin:.25rem 0;color:var(--text)">${esc(r)}</li>`
  ).join('');

  const banner = document.createElement('div');
  banner.id = 'aiBanner';
  banner.style.cssText = `
    background:${bg}; border:1px solid ${color}40;
    border-left:3px solid ${color}; border-radius:6px;
    padding:1.1rem 1.4rem; margin-bottom:1rem;
    font-family:var(--mono);
  `;
  banner.innerHTML = `
    <div style="display:flex;align-items:center;gap:.75rem;margin-bottom:.65rem">
      <span style="font-size:.62rem;letter-spacing:.15em;color:var(--dim)">🤖 AI ANALYSIS</span>
      <span style="
        font-size:.72rem;font-weight:700;letter-spacing:.12em;
        color:${color};background:${bg};border:1px solid ${color}40;
        padding:.15rem .55rem;border-radius:3px"
      >${esc(risk)}</span>
    </div>
    <p style="font-size:.82rem;color:var(--text);line-height:1.7;margin-bottom:.65rem">
      ${esc(ai.executive_summary || '')}
    </p>
    ${recs ? `
      <div style="font-size:.68rem;color:var(--dim);letter-spacing:.1em;margin-bottom:.35rem">TOP RECOMMENDATIONS</div>
      <ul style="margin:0;padding-left:1.1rem;font-size:.78rem">${recs}</ul>
    ` : ''}
  `;

  const slot = $('aiBannerSlot');
  slot.innerHTML = '';
  slot.appendChild(banner);
  slot.style.display = 'block';
}

// ── MAIN RENDER ────────────────────────────────────────────
function renderReport(data) {
  const findings = data.findings || [];
  findingRegistry = [];
  const sc = data.severity_counts || {};

  // Update meta bar
  $('topbarTarget').textContent = data.target || '—';
  $('metaTarget').textContent   = data.target || '—';
  $('metaScanId').textContent   = (data.scan_id||'—').substring(0,16);
  const scanProfile = data.scan_type || sessionStorage.getItem('rt_scan_profile') || 'full';
  const profileNames = {full:'FULL', recon_only:'RECON', osint_only:'OSINT', vuln_only:'VULN', danger:'DANGER'};
  if ($('metaProfile')) $('metaProfile').textContent = profileNames[scanProfile] || String(scanProfile).toUpperCase();
  $('metaFindings').textContent = data.total_findings || 0;
  $('metaCritical').textContent = sc.critical || 0;
  $('metaHigh').textContent     = sc.high || 0;
  $('metaMedium').textContent   = sc.medium || 0;
  $('metaTime').textContent     = `${data.total_time_seconds||'?'}s`;

  // Update severity bar. data-count lets the stylesheet mute a zero: a bright
  // red "0 CRITICAL" trains people to ignore the colour, so severity colour is
  // earned by a non-zero value and a clean scan reads calm.
  const counts = {
    sbTotal: data.total_findings || 0,
    sbCritical: sc.critical || 0,
    sbHigh: sc.high || 0,
    sbMedium: sc.medium || 0,
    sbLow: sc.low || 0,
    sbInfo: sc.info || 0,
  };
  Object.entries(counts).forEach(([id, value]) => {
    const el = $(id);
    el.textContent = value;
    el.closest('.sev-bar-item')?.setAttribute('data-count', String(value));
  });
  $('sevBar').style.display   = 'flex';

  const danger = data.danger_summary || null;
  if (danger) {
    renderDangerBanner(danger);
    document.body.classList.add('danger-report');
  }

  // Build cards
  const cards = [
    renderExploited(findings),
    danger ? renderDangerFindings(findings) : '',
    danger ? renderOwaspMatrix(danger) : '',
    danger ? renderAttackSurface(danger) : '',
    danger ? renderInjectionMatrix(danger) : '',
    renderHttpProbe(findings),
    renderTechStack(findings),
    renderFavicon(findings),
    renderJsAnalysis(findings),
    renderTakeover(findings),
    renderSsl(findings),
    renderHeaders(findings),
    renderDns(findings),
    renderPorts(findings),
    renderSubdomains(findings),
    renderWaf(findings),
    renderCors(findings),
    renderCookies(findings),
    renderRobots(findings),
    renderIpInfo(findings),
    renderWhois(findings.filter ? findings.filter(f=>f.tool==='whois') : []),
    renderWhois2(findings),
    renderThreatIntel(findings),
    renderVulns(findings),
  ].filter(Boolean).join('');

  if (!cards.trim()) {
    $('emptyReport').style.display = 'flex';
    return;
  }
  $('reportGrid').innerHTML = cards;
  $('reportGrid').style.display = 'block';

  // Inject AI summary banner above cards
  if (data.ai_summary) renderAiSummary(data.ai_summary, data.target);

  requestAnimationFrame(() => masonryLayout());
  window.addEventListener('resize', debounce(masonryLayout, 150));

  // Card positions come from measured heights, and heights depend on the font
  // actually in use. The first pass runs while the webfonts are still loading,
  // so it measures fallback metrics and the columns end up overlapping once
  // the real faces swap in. Re-run when the fonts are ready.
  if (document.fonts && document.fonts.ready) {
    document.fonts.ready.then(() => masonryLayout());
  }
}

// ── JS MASONRY ENGINE — zero gaps, auto-adjusts to content ──
function getColumnCount() {
  const w = window.innerWidth;
  if (w <= 580) return 1;
  if (w <= 960) return 2;
  if (w <= 1300) return 3;
  return 4;
}

function masonryLayout() {
  const grid = $('reportGrid');
  if (!grid || grid.style.display === 'none') return;

  const cards = Array.from(grid.querySelectorAll('.wc-card:not(.hidden)'));
  if (!cards.length) return;

  const cols = getColumnCount();
  const gap = 16;
  const containerWidth = grid.clientWidth;
  const colWidth = (containerWidth - gap * (cols - 1)) / cols;

  // Reset cards to measure natural height
  cards.forEach(c => {
    c.style.position = 'absolute';
    c.style.width = colWidth + 'px';
    c.style.top = '0px';
    c.style.left = '-9999px';
    c.classList.remove('placed');
  });

  // Force reflow to get measured heights
  grid.offsetHeight;

  // Track the height of each column
  const colHeights = new Array(cols).fill(0);

  cards.forEach((card, i) => {
    // Find the shortest column
    let shortest = 0;
    for (let c = 1; c < cols; c++) {
      if (colHeights[c] < colHeights[shortest]) shortest = c;
    }

    // Position the card
    const x = shortest * (colWidth + gap);
    const y = colHeights[shortest];
    card.style.width = colWidth + 'px';
    card.style.left = x + 'px';
    card.style.top = y + 'px';

    // Update column height
    colHeights[shortest] += card.offsetHeight + gap;

    // Stagger fade-in
    setTimeout(() => card.classList.add('placed'), i * 30);
  });

  // Set container height to tallest column
  grid.style.height = Math.max(...colHeights) + 'px';
}

function debounce(fn, ms) {
  let t;
  return function(...args) { clearTimeout(t); t = setTimeout(() => fn.apply(this, args), ms); };
}

$('reportGrid').addEventListener('click', event => {
  const item = event.target.closest('[data-finding-index]');
  if (!item || !$('reportGrid').contains(item)) return;
  const finding = findingRegistry[Number(item.dataset.findingIndex)];
  if (finding) window.openModal(finding);
});

// ── MODAL ──────────────────────────────────────────────────
window.openModal = function(f) {
  if (typeof f === 'string') f = JSON.parse(f);
  window._modalFinding = f;

  $('modalSev').textContent   = (f.severity||'info').toUpperCase();
  $('modalSev').className     = `modal-sev sev-pill ${f.severity}`;
  $('modalTitle').textContent  = f.title||'';
  $('modalDesc').textContent   = f.description||'';
  $('modalEvidence').textContent = f.evidence||'No evidence.';
  $('modalTool').textContent   = f.tool||'';
  $('modalCat').textContent    = f.category||'';
  $('modalRemBlock').style.display = f.remediation ? 'block' : 'none';
  if (f.remediation) $('modalRem').textContent = f.remediation;

  // Exploitation proof panel, shown only when the scanner actually proved it.
  const exploitBlock = $('modalExploitBlock');
  if (exploitBlock) {
    if (f.exploited) {
      exploitBlock.style.display = 'block';
      $('modalExploit').innerHTML = `
        <div class="exploit-row"><span class="exploit-key">Technique</span><span class="exploit-val">${esc(f.exploit_technique || '—')}</span></div>
        <div class="exploit-row"><span class="exploit-key">Proof captured</span><span class="exploit-val">${esc(f.exploit_proof || '—')}</span></div>
        <div class="exploit-row"><span class="exploit-key">Impact</span><span class="exploit-val">${esc(f.exploit_impact || '—')}</span></div>
        <div class="exploit-note">Proof is limited to a version banner, arithmetic result, platform name, or reflection context. No records, credentials, or personal data were extracted.</div>`;
    } else {
      exploitBlock.style.display = 'none';
    }
  }
  $('modalCveBlock').style.display = f.cve_id ? 'block' : 'none';
  if (f.cve_id) { $('modalCve').textContent = f.cve_id; $('modalCve').href = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(f.cve_id)}`; }
  $('modalCvssWrap').style.display = f.cvss_score ? 'inline' : 'none';
  if (f.cvss_score) $('modalCvss').textContent = f.cvss_score;

  // Static explanation from local DB
  const headerName = (f.title||'').replace('Missing Security Header: ','');
  const explain = getExplanation(f.category, headerName);
  const explainEl = $('modalExplainBlock');

  // AI explanation from scan data (if present)
  const aiText = f.explanation || null;

  if (explain || aiText) {
    explainEl.style.display = 'block';
    $('modalExplain').innerHTML = aiText
      ? `<h4>🤖 AI EXPLANATION</h4><p>${esc(aiText)}</p>
         ${explain?.fix ? `<p style="color:var(--green);margin-top:.4rem">✓ <strong>Fix:</strong> ${esc(explain.fix)}</p>` : ''}
         ${explain?.ref ? `<a href="${safeUrl(explain.ref)}" target="_blank" rel="noopener noreferrer" style="display:block;margin-top:.4rem">📖 Read more on OWASP ↗</a>` : ''}`
      : `<h4>💡 WHAT THIS MEANS IN PLAIN ENGLISH</h4>
         <p>${esc(explain.what)}</p>
         ${explain.fix ? `<p style="color:var(--green);margin-top:.4rem">✓ <strong>How to fix:</strong> ${esc(explain.fix)}</p>` : ''}
         ${explain.ref ? `<a href="${safeUrl(explain.ref)}" target="_blank" rel="noopener noreferrer" style="display:block;margin-top:.4rem">📖 Read more on OWASP ↗</a>` : ''}
         ${explain.cwe ? `<span class="owasp-badge" style="margin-top:.4rem">${explain.cwe}</span>` : ''}`;
  } else {
    explainEl.style.display = 'none';
  }

  // Reset the AI action buttons
  resetAiButton($('modalAiBtn'), '🤖 VERIFY WITH AI');
  resetAiButton($('modalTopicBtn'), '🧠 EXPLAIN THIS TOPIC');
  $('modalAiResult').style.display = 'none';
  $('modalAiResult').innerHTML = '';
  $('modalTopicResult').style.display = 'none';
  $('modalTopicResult').innerHTML = '';
  renderAiBadge();

  $('modal').style.display = 'flex';
};

// ── AI BACKEND STATUS ──────────────────────────
// The AI endpoints always answer — with a model when one is reachable, with
// built-in static text otherwise. The badge tells the user which they got, so
// a generic-looking answer is never mistaken for a model's judgement.
window._aiStatus = null;

async function loadAiStatus() {
  try {
    const res = await apiFetch('/api/ai/status', {}, false);
    if (res.ok) window._aiStatus = await res.json();
  } catch (_) { /* status is advisory only; the buttons still work without it */ }
  renderAiBadge();
}

function renderAiBadge() {
  const badge = $('modalAiBadge');
  if (!badge) return;
  const st = window._aiStatus;
  const live = st && st.active_backend && st.active_backend !== 'fallback';
  badge.classList.toggle('live', !!live);
  badge.textContent = live
    ? `${String(st.active_backend).toUpperCase()} · ${st.model || ''}`.trim()
    : 'NO MODEL · STATIC ANSWERS';
  badge.title = live
    ? `Answers generated by ${st.active_backend} (${st.model})`
    : (st && st.ollama && st.ollama.error)
      ? `Ollama unreachable: ${st.ollama.error}`
      : 'No AI backend reachable — showing built-in explanations';
}

function resetAiButton(btn, label) {
  if (!btn) return;
  btn.textContent = label;
  btn.disabled = false;
  btn.style.opacity = '1';
}

function aiPanelStyle(rgb) {
  return `display:block;margin-top:.8rem;padding:.8rem;background:rgba(${rgb},.06);`
       + `border:1px solid rgba(${rgb},.2);border-radius:4px;font-size:.78rem`;
}

loadAiStatus();

// AI verify button handler

$('modalAiBtn').addEventListener('click', async () => {
  const f = window._modalFinding;
  if (!f) return;
  const btn = $('modalAiBtn');
  btn.textContent = '⏳ Analyzing...';
  btn.disabled = true;
  btn.style.opacity = '.6';

  try {
    const res  = await apiFetch('/api/verify', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        scan_id:     window._scanData?.scan_id || 'manual',
        finding_id:  f.id || f.title || 'unknown',
        finding_text: f.title || f.description || '',
        target:      window._scanData?.target || '',
        severity:    f.severity || 'info',
        description: f.description || f.evidence || '',
      }),
    });
    if (!res.ok) throw new Error(`Verification failed (${res.status})`);
    const data = await res.json();
    const result = $('modalAiResult');
    result.style.display = 'block';
    result.style.cssText = 'display:block;margin-top:.8rem;padding:.8rem;background:rgba(139,195,74,.06);border:1px solid rgba(139,195,74,.2);border-radius:4px;font-size:.78rem';
    const rems = Array.isArray(data.remediation)
      ? data.remediation.map(r => `<li>${esc(r)}</li>`).join('')
      : '';
    result.innerHTML = `
      <div style="font-size:.65rem;color:var(--green);letter-spacing:.12em;margin-bottom:.5rem">🤖 AI VERIFICATION RESULT${data.ai_backend ? ` · ${esc(String(data.ai_backend).toUpperCase())}` : ''}</div>
      ${data.assessment ? `<div style="font-size:.68rem;color:var(--dim);margin-bottom:.5rem">TRIAGE: <strong style="color:var(--text)">${esc(String(data.assessment).replace(/_/g,' '))}</strong>${data.confidence ? ` · confidence ${esc(data.confidence)}` : ''}</div>` : ''}
      <p style="color:var(--text);line-height:1.65;margin-bottom:.5rem">${esc(data.explanation || '')}</p>
      ${data.impact ? `<p style="color:#ffa726;margin-bottom:.5rem">⚠ Impact: ${esc(data.impact)}</p>` : ''}
      ${rems ? `<div style="color:var(--dim);font-size:.68rem;margin-bottom:.3rem">REMEDIATION</div><ul style="margin:0;padding-left:1rem;color:var(--text)">${rems}</ul>` : ''}
      ${(data.references||[]).length ? `<div style="margin-top:.5rem">${data.references.map(r=>`<a href="${safeUrl(r)}" target="_blank" rel="noopener noreferrer" style="color:var(--cyan);font-size:.7rem">${esc(r)}</a>`).join(' ')}</div>` : ''}
    `;
    btn.textContent = '✓ VERIFIED';
    btn.style.opacity = '1';
  } catch(e) {
    btn.textContent = '🤖 VERIFY WITH AI';
    btn.disabled = false;
    btn.style.opacity = '1';
  }
});

// Topic explanation handler — teaches the concept behind the finding rather
// than restating the finding. Uses the finding's category when it has one, so
// "Missing Security Header: CSP" asks about security headers as a subject.
$('modalTopicBtn').addEventListener('click', async () => {
  const f = window._modalFinding;
  if (!f) return;
  const btn = $('modalTopicBtn');
  const topic = f.category || (f.title || '').replace(/:.*$/, '') || 'web security';
  btn.textContent = '⏳ Explaining...';
  btn.disabled = true;
  btn.style.opacity = '.6';

  try {
    const res = await apiFetch('/api/ai/explain', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        topic,
        context: [f.title, f.description, f.evidence].filter(Boolean).join(' — ').slice(0, 4000),
        audience: 'developer',
      }),
    });
    if (!res.ok) throw new Error(`Explanation failed (${res.status})`);
    const data = await res.json();
    const box = $('modalTopicResult');
    box.style.cssText = aiPanelStyle('0,229,255');
    box.innerHTML = `
      <div style="font-size:.65rem;color:var(--cyan);letter-spacing:.12em;margin-bottom:.5rem">🧠 TOPIC: ${esc(data.topic || topic)}${data.ai_backend ? ` · ${esc(String(data.ai_backend).toUpperCase())}` : ''}</div>
      <p style="color:var(--text);line-height:1.65">${esc(data.explanation || '')}</p>
      ${data.ai_generated === false ? `<div style="color:var(--dim);font-size:.65rem;margin-top:.5rem">Built-in explanation — no AI model reachable.</div>` : ''}
    `;
    box.style.display = 'block';
    btn.textContent = '✓ EXPLAINED';
    btn.style.opacity = '1';
  } catch (e) {
    resetAiButton(btn, '🧠 EXPLAIN THIS TOPIC');
  }
});

$('modalClose').addEventListener('click', () => $('modal').style.display = 'none');
$('modal').addEventListener('click', e => { if (e.target === $('modal')) $('modal').style.display = 'none'; });
document.addEventListener('keydown', e => { if (e.key === 'Escape') $('modal').style.display = 'none'; });

// ── SCAN EXECUTION ─────────────────────────────────────────
const PHASES = [
  [8,'WHOIS lookup'],[14,'DNS enumeration'],[20,'Certificate Transparency'],
  [24,'IP Geolocation'],[30,'HTTP probe'],[36,'Technology detection'],
  [42,'Favicon hash lookup'],[48,'JavaScript analysis'],[54,'Subdomain takeover'],
  [60,'Security headers analysis'],[66,'SSL/TLS check'],[71,'robots.txt scan'],
  [76,'CORS test'],[81,'Cookie flags'],[86,'WAF detection'],[92,'Building report'],
];
const TOOLS = ['whois','dns_lookup','crt.sh','ipinfo','httpx_probe','tech_stack','favicon_hash',
               'js_analysis','subdomain_takeover','security_headers','ssl_check','robots_sitemap',
               'cors_check','cookie_check','waf_detect'];

function setProgress(pct, label) {
  $('progressInner').style.width = pct + '%';
  $('progressPct').textContent   = pct + '%';
  $('loadingText').textContent   = label;
}

function updateToolPill(name, state) {
  let pill = document.querySelector(`.tool-pill[data-tool="${name}"]`);
  if (!pill) {
    pill = document.createElement('div');
    pill.className = 'tool-pill';
    pill.dataset.tool = name;
    pill.textContent = name;
    $('toolPills').appendChild(pill);
  }
  pill.className = `tool-pill ${state}`;
}

async function runScan(target, scanType = 'full') {
  $('loadingState').style.display = 'flex';
  $('reportGrid').style.display   = 'none';
  $('emptyReport').style.display  = 'none';

  setProgress(0, 'Initializing...');
  TOOLS.forEach(t => updateToolPill(t, ''));
  const loadingSub = $('loadingSub');
  if (loadingSub) loadingSub.textContent = `Running ${scanType.replaceAll('_', ' ')} modules with bounded network access`;

  let pi = 0;
  const timer = setInterval(() => {
    if (pi < PHASES.length) {
      const [pct, label] = PHASES[pi++];
      setProgress(pct, label + '...');
      if (pi <= TOOLS.length) updateToolPill(TOOLS[pi-1], 'running');
      if (pi > 1 && pi-2 < TOOLS.length) updateToolPill(TOOLS[pi-2], 'done');
    } else clearInterval(timer);
  }, 700);

  try {
    let url = `/api/test-scan?target=${encodeURIComponent(target)}&scan_type=${encodeURIComponent(scanType)}`;
    if (scanType === 'danger') {
      // Re-running a danger scan from a report link still requires the typed
      // acknowledgement; without it the API returns 403 by design.
      const supplied = window.prompt('Danger Mode requires authorization. Type: I am authorized');
      if (supplied === null) { clearInterval(timer); $('loadingText').textContent = 'Danger scan cancelled.'; return; }
      url += `&danger_acknowledgement=${encodeURIComponent(supplied.trim())}`;
    }
    const res = await apiFetch(url);
    clearInterval(timer);
    TOOLS.forEach(t => updateToolPill(t, 'done'));
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    setProgress(100, 'Complete!');
    await new Promise(r => setTimeout(r, 400));
    $('loadingState').style.display = 'none';
    renderReport(data);
    // Store for export
    window._scanData = data;
  } catch(err) {
    clearInterval(timer);
    $('loadingText').textContent = `Error: ${err.message}`;
    console.error('[ReconTitan]', err);
  }
}

// ── EXPORT ─────────────────────────────────────────────────
function safeFilename(value) {
  return String(value || 'target').replace(/[^a-zA-Z0-9._-]+/g, '_').replace(/\.{2,}/g, '_').replace(/^[._]+|[._]+$/g, '').slice(0, 120) || 'target';
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = Object.assign(document.createElement('a'), {href:url, download:filename});
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function buildPdfExportPayload(data) {
  // Send only fields consumed by the PDF service. This avoids serializing large
  // UI-only state and makes export noticeably faster on large scan results.
  const keys = [
    'scan_id', 'target', 'scan_type', 'status', 'started_at', 'completed_at',
    'total_time_seconds', 'tools_run', 'tools_used', 'total_findings',
    'severity_counts', 'summary', 'ai_summary', 'tool_results', 'findings',
    'danger_summary',
  ];
  const payload = {version: '0.5.0'};
  keys.forEach(key => {
    if (data[key] !== undefined && data[key] !== null) payload[key] = data[key];
  });
  return payload;
}

$('btnExportJson').addEventListener('click', () => {
  if (!window._scanData) return;
  downloadBlob(new Blob([JSON.stringify(window._scanData, null, 2)], {type:'application/json'}), `recontitan_${safeFilename(window._scanData.target)}.json`);
});

$('btnExportHtml').addEventListener('click', () => {
  downloadBlob(new Blob([document.documentElement.outerHTML], {type:'text/html'}), 'recontitan_report.html');
});

$('btnExportPdf').addEventListener('click', async () => {
  if (!window._scanData) return;
  const btn = $('btnExportPdf');
  const original = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'BUILDING PDF...';
  try {
    const response = await apiFetch('/api/report/pdf', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(buildPdfExportPayload(window._scanData)),
    });
    if (!response.ok) throw new Error(`PDF export failed (${response.status})`);
    const blob = await response.blob();
    downloadBlob(blob, `recontitan_${safeFilename(window._scanData.target)}.pdf`);
  } catch (error) {
    alert(error.message);
  } finally {
    btn.disabled = false;
    btn.textContent = original;
  }
});

// ── ENTRY POINT ────────────────────────────────────────────
(function init() {
  const params = new URLSearchParams(window.location.search);
  const target = params.get('target');
  const scanType = params.get('scan_type') || sessionStorage.getItem('rt_scan_profile') || 'full';
  const cachedRequested = params.get('cached') === '1';
  const storedTarget = sessionStorage.getItem('rt_scan_target');
  const storedData = sessionStorage.getItem('rt_scan_data');

  if (storedData && (!target || storedTarget === target) && (cachedRequested || storedTarget === target)) {
    try {
      const data = JSON.parse(storedData);
      $('loadingState').style.display = 'none';
      renderReport(data);
      window._scanData = data;
      return;
    } catch (_) {
      sessionStorage.removeItem('rt_scan_data');
    }
  }

  if (target) {
    runScan(target, scanType);
    return;
  }

  $('loadingState').style.display = 'none';
  $('emptyReport').style.display = 'flex';
}());
