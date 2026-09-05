const { test } = require('node:test');
const assert = require('node:assert/strict');
const {
  buildAttackSurfaceTree,
  createAttackSurfaceTree,
  cleanHost,
  isAddress,
} = require('../attack-surface-tree.js');

const report = {
  target: 'https://example.com/path',
  tools_used: ['dns_lookup', 'nmap'],
  tool_results: { dns_lookup: { status: 'ok' }, nmap: { status: 'failed', error: 'missing binary' } },
  danger_summary: {
    attack_surface: [
      { url: 'https://admin.example.com/login?next=/', method: 'POST', input_type: 'login_form', parameters: ['username'] },
    ],
  },
  findings: [
    {
      tool: 'crt.sh', category: 'subdomain_enumeration', severity: 'info', title: 'Domains',
      evidence: '• api.example.com\n• admin.example.com\n• evil-example.com',
    },
    {
      tool: 'dns_lookup', category: 'dns_records', severity: 'info', title: 'DNS',
      evidence: 'A       93.184.216.34\nAAAA    2606:2800:220:1:248:1893:25c8:1946',
    },
    {
      tool: 'nmap', category: 'port_scan', severity: 'info', title: 'Ports',
      evidence: '• 443/tcp open https\n• 22/tcp open ssh',
    },
    {
      tool: 'tech_stack', category: 'tech_stack', severity: 'info', title: 'Stack',
      evidence: '• React 18 [JavaScript] — matched asset\n• nginx [Web server] — matched header',
      technologies: [{ name: 'React', version: '18' }],
    },
    {
      tool: 'headers', category: 'security_headers', severity: 'high',
      title: '<img src=x onerror=alert(1)>', affected_asset: 'https://admin.example.com/login',
    },
  ],
};

function descendants(item) {
  return [item, ...item.children.flatMap(descendants)];
}

test('normalizes targets and validates addresses', () => {
  assert.equal(cleanHost('https://WWW.Example.com:443/a'), 'www.example.com');
  assert.equal(cleanHost('2606:2800:220:1:248:1893:25c8:1946'), '2606:2800:220:1:248:1893:25c8:1946');
  assert.equal(isAddress('93.184.216.34'), true);
  assert.equal(isAddress('999.184.216.34'), false);
  assert.equal(isAddress('2606:2800:220:1:248:1893:25c8:1946'), true);
});

test('builds a scoped and deduplicated attack-surface hierarchy', () => {
  const model = buildAttackSurfaceTree(report);
  const all = descendants(model.root);
  assert.equal(model.root.label, 'example.com');
  assert.equal(model.stats.subdomains, 2);
  assert.equal(model.stats.addresses, 2);
  assert.equal(model.stats.services, 2);
  assert.equal(model.stats.inputPoints, 1);
  assert.ok(model.stats.technologies >= 2);
  assert.ok(all.some(item => item.label === 'api.example.com'));
  assert.ok(all.some(item => item.label === 'admin.example.com'));
  assert.ok(!all.some(item => item.label === 'evil-example.com'));
  assert.ok(all.some(item => item.label === '22/tcp' && item.detail === 'ssh'));
  assert.ok(all.some(item => item.label === 'POST /login?next=/'));
  assert.ok(all.some(item => item.label === '<img src=x onerror=alert(1)>' && item.finding === report.findings[4]));
});

class Element {
  constructor() {
    this.children = [];
    this.events = {};
    this.attributes = {};
    this.hidden = true;
    this.disabled = false;
    this.className = '';
    this.textContent = '';
  }
  set innerHTML(_) { throw new Error('Untrusted HTML rendering is forbidden'); }
  replaceChildren() { this.children = []; }
  appendChild(child) { this.children.push(child); }
  addEventListener(name, handler) { this.events[name] = handler; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  getAttribute(name) { return this.attributes[name]; }
  fire(name, event = {}) { this.events[name]({ preventDefault() {}, ...event }); }
  focus() { this.focused = true; }
}

function flattenElements(element) {
  return [element, ...element.children.flatMap(flattenElements)];
}

function setup() {
  const elements = { tree: new Element(), summary: new Element(), expandAll: new Element(), collapseAll: new Element() };
  const root = new Element();
  root.ownerDocument = { createElement: () => new Element() };
  root.querySelector = selector => ({
    '[data-tree]': elements.tree,
    '[data-summary]': elements.summary,
    '[data-expand-all]': elements.expandAll,
    '[data-collapse-all]': elements.collapseAll,
  })[selector];
  let opened;
  const controller = createAttackSurfaceTree(root, finding => { opened = finding; });
  return { root, elements, controller, opened: () => opened };
}

test('controller expands downward, collapses branches, and opens finding evidence', () => {
  const ui = setup();
  ui.controller.update(report);
  assert.equal(ui.root.hidden, false);
  assert.match(ui.elements.summary.textContent, /2 subdomains/);

  const nodes = flattenElements(ui.elements.tree);
  const rootRow = nodes.find(item => item.className.includes('surface-tree-target'));
  const groupRow = nodes.find(item => item.className.includes('surface-tree-group'));
  assert.equal(rootRow.getAttribute('aria-expanded'), 'true');
  assert.equal(groupRow.getAttribute('aria-expanded'), 'false');
  groupRow.children[0].fire('click');
  assert.equal(groupRow.getAttribute('aria-expanded'), 'true');
  ui.elements.collapseAll.fire('click');
  assert.equal(rootRow.getAttribute('aria-expanded'), 'true');
  assert.equal(groupRow.getAttribute('aria-expanded'), 'false');
  ui.elements.expandAll.fire('click');
  assert.equal(groupRow.getAttribute('aria-expanded'), 'true');

  const action = nodes.find(item => item.className.includes('is-action') && item.children.some(child => child.textContent.includes('<img')));
  action.fire('click');
  assert.equal(ui.opened(), report.findings[4]);
});

test('keyboard arrows open a branch and move to its first child', () => {
  const ui = setup();
  ui.controller.update(report);
  const nodes = flattenElements(ui.elements.tree);
  const groupRow = nodes.find(item => item.className.includes('surface-tree-group'));
  const button = groupRow.children[0];
  button.fire('keydown', { key: 'ArrowRight' });
  assert.equal(groupRow.getAttribute('aria-expanded'), 'true');
  button.fire('keydown', { key: 'ArrowRight' });
  const childList = groupRow.children[1];
  assert.equal(childList.children[0].children[0].focused, true);
});
