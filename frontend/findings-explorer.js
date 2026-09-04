'use strict';

// The query is pure: filtering never mutates the report or exported findings.
function selectFindings(findings, { query = '', severity = '', tool = '' } = {}) {
  const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const words = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  return findings.filter(finding => {
    if (severity && finding.severity !== severity) return false;
    if (tool && finding.tool !== tool) return false;
    const text = ['title', 'description', 'evidence', 'category', 'tool', 'cve_id', 'affected_asset', 'remediation']
      .map(key => String(finding[key] ?? '')).join(' ').toLowerCase();
    return words.every(word => text.includes(word));
  }).sort((a, b) => (rank[a.severity] ?? 5) - (rank[b.severity] ?? 5));
}

function createFindingsExplorer(root, onOpen) {
  const doc = root.ownerDocument;
  let findings = [];
  let page = 0;
  const pageSize = 25;
  const query = root.querySelector('[data-query]');
  const severity = root.querySelector('[data-severity]');
  const tool = root.querySelector('[data-tool]');
  const results = root.querySelector('[data-results]');
  const count = root.querySelector('[data-count]');
  const previous = root.querySelector('[data-previous]');
  const next = root.querySelector('[data-next]');

  function render() {
    const matches = selectFindings(findings, { query: query.value, severity: severity.value, tool: tool.value });
    page = Math.min(page, Math.max(0, Math.ceil(matches.length / pageSize) - 1));
    const start = page * pageSize;
    count.textContent = matches.length
      ? `${matches.length} of ${findings.length} findings match · Showing ${start + 1}–${Math.min(start + pageSize, matches.length)}`
      : `No matching findings (${findings.length} total). Clear filters to see all findings.`;
    results.replaceChildren();
    matches.slice(start, start + pageSize).forEach(finding => {
      const row = doc.createElement('li');
      const button = doc.createElement('button');
      button.type = 'button';
      // Scanner output is untrusted; render as text, never HTML.
      button.textContent = `[${String(finding.severity || 'info').toUpperCase()}] ${finding.title || 'Untitled finding'} — ${finding.tool || 'unknown'}`;
      button.addEventListener('click', () => onOpen(finding));
      row.appendChild(button);
      results.appendChild(row);
    });
    previous.disabled = page === 0;
    next.disabled = start + pageSize >= matches.length;
  }

  function resetPage() { page = 0; render(); }
  query.addEventListener('input', resetPage);
  severity.addEventListener('change', resetPage);
  tool.addEventListener('change', resetPage);
  previous.addEventListener('click', () => { page = Math.max(0, page - 1); render(); });
  next.addEventListener('click', () => { page += 1; render(); });
  root.querySelector('[data-clear]').addEventListener('click', () => {
    query.value = ''; severity.value = ''; tool.value = ''; resetPage();
  });

  return {
    update(items) {
      findings = items;
      const selected = tool.value;
      tool.replaceChildren();
      const names = [...new Set(items.map(f => f.tool).filter(Boolean))].sort();
      for (const name of ['', ...names]) {
        const option = doc.createElement('option');
        option.value = name;
        option.textContent = name || 'All scanners';
        tool.appendChild(option);
      }
      tool.value = names.includes(selected) ? selected : '';
      root.hidden = false;
      resetPage();
    },
  };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { selectFindings, createFindingsExplorer };
}
