'use strict';

const ATTACK_SURFACE_LIMITS = Object.freeze({
  subdomains: 200,
  addresses: 100,
  services: 200,
  technologies: 100,
  findings: 50,
  inputPoints: 200,
});

const SEVERITY_RANK = Object.freeze({ critical: 0, high: 1, medium: 2, low: 3, info: 4 });

function cleanHost(value) {
  let text = String(value || '').trim().toLowerCase();
  if (!text) return '';
  const bareAddress = text.replace(/^\[|\]$/g, '');
  if (isAddress(bareAddress)) return bareAddress;
  try {
    const parsed = new URL(text.includes('://') ? text : `https://${text}`);
    return parsed.hostname.replace(/^\[|\]$/g, '').replace(/^\*\./, '').replace(/\.$/, '');
  } catch (_) {
    return text.replace(/^\*\./, '').replace(/\.$/, '').split(/[/?#]/)[0].split(':')[0];
  }
}

function isIpv4(value) {
  const parts = String(value).split('.');
  return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

function isIpv6(value) {
  const text = String(value).replace(/^\[|\]$/g, '');
  return text.includes(':') && /^[0-9a-f:]+$/i.test(text) && text.length >= 3 && text.length <= 45;
}

function isAddress(value) {
  return isIpv4(value) || isIpv6(value);
}

function inTargetScope(host, targetHost) {
  if (!host || !targetHost || isAddress(host)) return false;
  return host === targetHost || host.endsWith(`.${targetHost}`);
}

function evidenceText(finding) {
  return String(finding && finding.evidence || '');
}

function hostsFromText(text, targetHost) {
  const result = new Set();
  const pattern = /(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}/gi;
  for (const match of String(text || '').matchAll(pattern)) {
    const host = cleanHost(match[0]);
    if (inTargetScope(host, targetHost)) result.add(host);
  }
  return result;
}

function addressesFromFindings(findings) {
  const result = new Set();
  for (const finding of findings) {
    const category = String(finding.category || '');
    if (!['dns_records', 'ip_geolocation', 'port_scan'].includes(category)) continue;
    for (const line of evidenceText(finding).split(/\r?\n/)) {
      const dns = line.match(/^\s*(?:A|AAAA)\s+([^\s]+)/i);
      const labelled = line.match(/^\s*(?:IP Address|Pinned address)\s*:\s*([^\s]+)/i);
      const candidate = (dns || labelled || [])[1];
      if (candidate && isAddress(candidate)) result.add(candidate.replace(/^\[|\]$/g, ''));
    }
  }
  return [...result].sort();
}

function servicesFromFindings(findings) {
  const services = new Map();
  for (const finding of findings) {
    if (!['port_scan', 'dangerous_port'].includes(String(finding.category || ''))) continue;
    const text = `${finding.title || ''}\n${evidenceText(finding)}`;
    const pattern = /\b(\d{1,5})\/tcp\s+(?:open\s+)?([a-z0-9_.?\/-]+)/gi;
    for (const match of text.matchAll(pattern)) {
      const port = Number(match[1]);
      if (port > 0 && port <= 65535) services.set(`${port}/tcp`, { port, service: match[2] });
    }
  }
  return [...services.values()].sort((a, b) => a.port - b.port);
}

function technologiesFromFindings(findings) {
  const technologies = new Map();
  const add = (name, version = '') => {
    const cleanName = String(name || '').trim();
    const cleanVersion = String(version || '').trim();
    if (!cleanName || cleanName.length > 120) return;
    const key = `${cleanName} ${cleanVersion}`.trim().toLowerCase();
    technologies.set(key, { name: cleanName, version: cleanVersion });
  };

  for (const finding of findings) {
    if (Array.isArray(finding.technologies)) {
      for (const item of finding.technologies) {
        if (typeof item === 'string') add(item);
        else if (item && typeof item === 'object') add(item.name, item.version);
      }
    }
    if (finding.category === 'tech_stack') {
      for (const line of evidenceText(finding).split(/\r?\n/)) {
        const match = line.match(/^\s*[•*-]\s*(.+?)(?:\s+\[[^\]]+\])?(?:\s+—.*)?$/);
        if (match) add(match[1]);
      }
    }
    if (finding.category === 'http_probe') {
      const match = evidenceText(finding).match(/^Technologies:\s*(.+)$/im);
      if (match) match[1].split(',').forEach(item => add(item));
    }
  }
  return [...technologies.values()].sort((a, b) => a.name.localeCompare(b.name));
}

function severityOf(findings) {
  return findings.reduce((best, finding) => {
    const severity = String(finding.severity || 'info').toLowerCase();
    return (SEVERITY_RANK[severity] ?? 5) < (SEVERITY_RANK[best] ?? 5) ? severity : best;
  }, 'info');
}

function buildAttackSurfaceTree(report = {}) {
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const targetHost = cleanHost(report.target || report.danger_summary?.target) || 'Unknown target';
  let nextId = 0;
  const node = (kind, label, options = {}) => ({
    id: `surface-${nextId++}`,
    kind,
    label: String(label),
    detail: options.detail ? String(options.detail) : '',
    severity: options.severity || '',
    children: options.children || [],
    finding: options.finding,
  });
  const capped = (items, limit, kind) => {
    const shown = items.slice(0, limit);
    if (items.length > limit) shown.push(node('more', `${items.length - limit} more ${kind} not shown`));
    return shown;
  };

  const subdomains = new Set();
  for (const finding of findings) {
    if (['subdomain_enumeration', 'sensitive_subdomains', 'subdomain_takeover', 'subdomain_takeover_summary'].includes(String(finding.category || ''))) {
      hostsFromText(evidenceText(finding), targetHost).forEach(host => subdomains.add(host));
    }
    const affected = cleanHost(finding.affected_asset);
    if (affected !== targetHost && inTargetScope(affected, targetHost)) subdomains.add(affected);
  }
  const danger = report.danger_summary && typeof report.danger_summary === 'object' ? report.danger_summary : {};
  const inputPoints = Array.isArray(danger.attack_surface) ? danger.attack_surface : [];
  for (const item of inputPoints) {
    const host = cleanHost(item && item.url);
    if (host !== targetHost && inTargetScope(host, targetHost)) subdomains.add(host);
  }

  const relatedFindings = host => findings.filter(finding => cleanHost(finding.affected_asset) === host);
  const subdomainNodes = [...subdomains].sort().map(host => {
    const related = relatedFindings(host);
    return node('domain', host, {
      severity: related.length ? severityOf(related) : '',
      detail: related.length ? `${related.length} related finding${related.length === 1 ? '' : 's'}` : 'Discovered hostname',
      children: related.slice(0, 20).map(finding => node('finding', finding.title || 'Untitled finding', {
        severity: finding.severity || 'info', detail: finding.tool || 'unknown scanner', finding,
      })),
    });
  });

  const addresses = addressesFromFindings(findings);
  const services = servicesFromFindings(findings);
  const infrastructureChildren = [];
  if (addresses.length) infrastructureChildren.push(node('group', `IP addresses (${addresses.length})`, {
    children: capped(addresses.map(address => node('address', address)), ATTACK_SURFACE_LIMITS.addresses, 'addresses'),
  }));
  if (services.length) infrastructureChildren.push(node('group', `Open services (${services.length})`, {
    children: capped(services.map(item => node('service', `${item.port}/tcp`, { detail: item.service })), ATTACK_SURFACE_LIMITS.services, 'services'),
  }));

  const technologies = technologiesFromFindings(findings);
  const technologyNodes = technologies.map(item => node('technology', item.name, { detail: item.version || '' }));

  const pointNodes = inputPoints.map(item => {
    let path = String(item?.url || 'Unknown endpoint');
    try {
      const parsed = new URL(path);
      path = `${parsed.pathname}${parsed.search}`;
    } catch (_) { /* Preserve the original text for incomplete local URLs. */ }
    const parameters = Array.isArray(item?.parameters) ? item.parameters.filter(Boolean) : [];
    return node('input', `${String(item?.method || 'GET').toUpperCase()} ${path}`, {
      detail: [item?.input_type, parameters.length ? `parameters: ${parameters.join(', ')}` : ''].filter(Boolean).join(' · '),
    });
  });

  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
  const findingGroups = severityOrder.map(severity => {
    const matching = findings.filter(finding => String(finding.severity || 'info').toLowerCase() === severity);
    if (!matching.length) return null;
    const leaves = matching.slice(0, ATTACK_SURFACE_LIMITS.findings).map(finding => node('finding', finding.title || 'Untitled finding', {
      detail: [finding.tool || 'unknown scanner', finding.affected_asset || ''].filter(Boolean).join(' · '),
      severity,
      finding,
    }));
    if (matching.length > ATTACK_SURFACE_LIMITS.findings) leaves.push(node('more', `${matching.length - ATTACK_SURFACE_LIMITS.findings} more findings not shown`));
    return node('severity', `${severity[0].toUpperCase()}${severity.slice(1)} (${matching.length})`, { severity, children: leaves });
  }).filter(Boolean);

  const toolResults = report.tool_results && typeof report.tool_results === 'object' ? report.tool_results : {};
  const toolNames = new Set([
    ...(Array.isArray(report.tools_used) ? report.tools_used : []),
    ...Object.keys(toolResults),
    ...findings.map(finding => finding.tool).filter(Boolean),
  ]);
  const toolNodes = [...toolNames].sort().map(name => {
    const result = toolResults[name];
    const count = findings.filter(finding => finding.tool === name).length;
    const failed = result && typeof result === 'object' && (result.error || result.status === 'error' || result.status === 'failed');
    return node('scanner', name, {
      severity: failed ? 'high' : '',
      detail: failed ? 'Failed' : `${count} finding${count === 1 ? '' : 's'}`,
    });
  });

  const rootChildren = [];
  if (subdomainNodes.length) rootChildren.push(node('group', `Subdomains (${subdomainNodes.length})`, {
    children: capped(subdomainNodes, ATTACK_SURFACE_LIMITS.subdomains, 'subdomains'),
  }));
  if (infrastructureChildren.length) rootChildren.push(node('group', 'Infrastructure', { children: infrastructureChildren }));
  if (technologyNodes.length) rootChildren.push(node('group', `Technologies (${technologyNodes.length})`, {
    children: capped(technologyNodes, ATTACK_SURFACE_LIMITS.technologies, 'technologies'),
  }));
  if (pointNodes.length) rootChildren.push(node('group', `Web input points (${pointNodes.length})`, {
    children: capped(pointNodes, ATTACK_SURFACE_LIMITS.inputPoints, 'input points'),
  }));
  if (findingGroups.length) rootChildren.push(node('group', `Findings (${findings.length})`, { children: findingGroups }));
  if (toolNodes.length) rootChildren.push(node('group', `Scanner coverage (${toolNodes.length})`, { children: toolNodes }));

  return {
    root: node('target', targetHost, {
      severity: findings.length ? severityOf(findings) : '',
      detail: `${findings.length} finding${findings.length === 1 ? '' : 's'} · ${rootChildren.length} branches`,
      children: rootChildren,
    }),
    stats: {
      subdomains: subdomainNodes.length,
      addresses: addresses.length,
      services: services.length,
      technologies: technologyNodes.length,
      inputPoints: pointNodes.length,
      findings: findings.length,
      scanners: toolNodes.length,
    },
  };
}

function createAttackSurfaceTree(root, onOpenFinding) {
  const doc = root.ownerDocument;
  const tree = root.querySelector('[data-tree]');
  const summary = root.querySelector('[data-summary]');
  const expandAll = root.querySelector('[data-expand-all]');
  const collapseAll = root.querySelector('[data-collapse-all]');
  let branches = [];

  function renderNode(item, depth, parentButton) {
    const row = doc.createElement('li');
    row.className = `surface-tree-node surface-tree-${item.kind}`;
    row.setAttribute('role', 'treeitem');
    row.setAttribute('aria-level', String(depth + 1));

    const button = doc.createElement('button');
    button.type = 'button';
    button.className = 'surface-tree-button';
    button.setAttribute('data-kind', item.kind);

    const marker = doc.createElement('span');
    marker.className = 'surface-tree-marker';
    marker.setAttribute('aria-hidden', 'true');
    const label = doc.createElement('span');
    label.className = 'surface-tree-label';
    label.textContent = item.label;
    button.appendChild(marker);
    button.appendChild(label);

    if (item.detail) {
      const detail = doc.createElement('span');
      detail.className = 'surface-tree-detail';
      detail.textContent = item.detail;
      button.appendChild(detail);
    }
    if (item.severity) {
      const severity = doc.createElement('span');
      severity.className = `surface-tree-badge is-${item.severity}`;
      severity.textContent = item.severity.toUpperCase();
      button.appendChild(severity);
    }
    row.appendChild(button);

    let childList = null;
    let childClip = null;
    let childButtons = [];
    if (item.children.length) {
      childClip = doc.createElement('div');
      childClip.className = 'surface-tree-clip';
      childList = doc.createElement('ul');
      childList.className = 'surface-tree-children';
      childList.setAttribute('role', 'group');
      const openByDefault = depth === 0;
      let openState = openByDefault;
      childClip.className = openByDefault ? 'surface-tree-clip' : 'surface-tree-clip is-collapsed';
      childClip.setAttribute('aria-hidden', String(!openByDefault));
      row.setAttribute('aria-expanded', String(openByDefault));
      button.setAttribute('aria-expanded', String(openByDefault));
      for (const child of item.children) {
        const rendered = renderNode(child, depth + 1, button);
        childButtons.push(rendered.button);
        childList.appendChild(rendered.row);
      }
      childClip.appendChild(childList);
      row.appendChild(childClip);
      const branch = {
        depth,
        setOpen(open) {
          openState = Boolean(open);
          childClip.className = openState ? 'surface-tree-clip' : 'surface-tree-clip is-collapsed';
          childClip.setAttribute('aria-hidden', String(!openState));
          row.setAttribute('aria-expanded', String(openState));
          button.setAttribute('aria-expanded', String(openState));
        },
        isOpen() { return openState; },
      };
      branches.push(branch);
      button.addEventListener('click', () => branch.setOpen(!branch.isOpen()));
      button.addEventListener('keydown', event => {
        if (event.key === 'ArrowDown' || event.key === 'ArrowRight') {
          event.preventDefault();
          if (!branch.isOpen()) branch.setOpen(true);
          else if (childButtons[0] && childButtons[0].focus) childButtons[0].focus();
        } else if (event.key === 'ArrowUp' || event.key === 'ArrowLeft') {
          event.preventDefault();
          if (branch.isOpen()) branch.setOpen(false);
          else if (parentButton && parentButton.focus) parentButton.focus();
        }
      });
    } else if (item.finding) {
      button.className += ' is-action';
      button.addEventListener('click', () => onOpenFinding(item.finding));
    } else {
      button.disabled = true;
    }
    return { row, button };
  }

  expandAll.addEventListener('click', () => branches.forEach(branch => branch.setOpen(true)));
  collapseAll.addEventListener('click', () => branches.forEach(branch => branch.setOpen(branch.depth === 0)));

  return {
    update(report) {
      const model = buildAttackSurfaceTree(report);
      branches = [];
      tree.replaceChildren();
      tree.appendChild(renderNode(model.root, 0, null).row);
      const stats = model.stats;
      summary.textContent = `${stats.subdomains} subdomains · ${stats.addresses} addresses · ${stats.services} services · ${stats.technologies} technologies · ${stats.findings} findings`;
      root.hidden = false;
      return model;
    },
  };
}

function createReportViewTabs(root, views) {
  // Driven by whatever buttons the markup declares, rather than a fixed pair.
  // Adding a tab is then a markup change plus a view element, which is how the
  // attack-paths view was added without touching the switching logic.
  const buttons = {};
  for (const button of root.querySelectorAll('[data-report-view]')) {
    const name = button.dataset.reportView;
    if (views[name]) buttons[name] = button;
  }
  const order = Object.keys(buttons);
  const fallback = order[0];

  function show(view, focus = false) {
    const selected = buttons[view] ? view : fallback;
    for (const [name, element] of Object.entries(views)) {
      if (element) element.hidden = name !== selected;
    }
    for (const [name, button] of Object.entries(buttons)) {
      button.setAttribute('aria-selected', String(name === selected));
      button.setAttribute('tabindex', name === selected ? '0' : '-1');
    }
    root.hidden = false;
    if (focus && buttons[selected] && buttons[selected].focus) buttons[selected].focus();
  }

  order.forEach((name, index) => {
    const button = buttons[name];
    button.addEventListener('click', () => show(name));
    button.addEventListener('keydown', event => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
      event.preventDefault();
      const next = event.key === 'Home' ? 0
        : event.key === 'End' ? order.length - 1
        : event.key === 'ArrowLeft' ? (index - 1 + order.length) % order.length
        : (index + 1) % order.length;
      show(order[next], true);
    });
    button.setAttribute('role', 'tab');
    button.setAttribute('data-view-name', name);
  });
  root.setAttribute('role', 'tablist');

  // A tab whose view has no content is hidden rather than shown empty: a scan
  // with no correlated paths should not advertise a tab that leads nowhere.
  function setAvailable(name, available) {
    if (!buttons[name]) return;
    buttons[name].hidden = !available;
    if (!available && buttons[name].getAttribute('aria-selected') === 'true') show(fallback);
  }

  return { show, setAvailable };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    buildAttackSurfaceTree,
    createAttackSurfaceTree,
    createReportViewTabs,
    cleanHost,
    isAddress,
  };
}
