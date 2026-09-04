const { test } = require('node:test');
const assert = require('node:assert/strict');
const { selectFindings, createFindingsExplorer } = require('../findings-explorer.js');

const findings = [
  { title: 'TLS expiry', severity: 'low', tool: 'tls', evidence: 'example.com' },
  { title: 'Header missing', severity: 'high', tool: 'headers', cve_id: 'CVE-2025-1234' },
  { title: '<img src=x onerror=alert(1)>', severity: 'critical', tool: 'tls', affected_asset: 'example.com' },
];

test('search matches all words across evidence fields and combines filters', () => {
  assert.equal(selectFindings(findings, { query: 'EXAMPLE tls', tool: 'tls', severity: 'low' }).length, 1);
  assert.equal(selectFindings(findings, { query: 'cve-2025' })[0], findings[1]);
  assert.equal(selectFindings(findings, { query: 'missing', tool: 'tls' }).length, 0);
});

test('severity sorting preserves original objects and input order', () => {
  const before = JSON.stringify(findings);
  assert.deepEqual(selectFindings(findings), [findings[2], findings[1], findings[0]]);
  assert.equal(JSON.stringify(findings), before);
  assert.deepEqual(selectFindings([], { query: '  ' }), []);
  assert.equal(selectFindings([{ title: 'Unknown' }]).length, 1);
});

// Minimal DOM harness executes the real controller and its event handlers.
class Element {
  constructor() { this.value = ''; this.children = []; this.events = {}; this.hidden = true; }
  set innerHTML(_) { throw new Error('Untrusted HTML rendering is forbidden'); }
  replaceChildren() { this.children = []; }
  appendChild(child) { this.children.push(child); }
  addEventListener(name, handler) { this.events[name] = handler; }
  fire(name) { this.events[name](); }
}
function setup() {
  const elements = Object.fromEntries(['query', 'severity', 'tool', 'results', 'count', 'previous', 'next', 'clear'].map(name => [name, new Element()]));
  const root = new Element();
  root.ownerDocument = { createElement: () => new Element() };
  root.querySelector = selector => elements[selector.slice(6, -1)];
  let opened;
  const controller = createFindingsExplorer(root, finding => { opened = finding; });
  return { root, elements, controller, opened: () => opened };
}

test('controller safely renders text and opens the original finding', () => {
  const ui = setup();
  ui.controller.update(findings);
  assert.equal(ui.root.hidden, false);
  const button = ui.elements.results.children[0].children[0];
  assert.ok(button.textContent.includes('<img src=x onerror=alert(1)>'));
  button.fire('click');
  assert.equal(ui.opened(), findings[2]);
});

test('pagination, filtering, empty state, and clear work together', () => {
  const ui = setup();
  ui.controller.update(Array.from({ length: 26 }, (_, index) => ({ title: `Finding ${index}`, tool: 'tls' })));
  assert.equal(ui.elements.results.children.length, 25);
  assert.equal(ui.elements.previous.disabled, true);
  ui.elements.next.fire('click');
  assert.equal(ui.elements.results.children.length, 1);
  assert.equal(ui.elements.next.disabled, true);
  ui.elements.query.value = 'no match';
  ui.elements.query.fire('input');
  assert.equal(ui.elements.results.children.length, 0);
  assert.match(ui.elements.count.textContent, /No matching findings/);
  ui.elements.clear.fire('click');
  assert.equal(ui.elements.results.children.length, 25);
  assert.equal(ui.elements.previous.disabled, true);
});

test('rescan refresh removes stale scanners and preserves valid filters', () => {
  const ui = setup();
  ui.controller.update(findings);
  ui.elements.tool.value = 'tls';
  ui.controller.update(findings.slice(0, 1));
  assert.equal(ui.elements.tool.value, 'tls');
  ui.controller.update([]);
  assert.equal(ui.elements.tool.value, '');
  assert.equal(ui.elements.results.children.length, 0);
  assert.equal(ui.elements.tool.children.length, 1);
});
