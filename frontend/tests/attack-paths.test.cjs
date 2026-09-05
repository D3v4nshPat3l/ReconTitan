const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createAttackPathsView, PATH_STATUS, STEP_ROLE } = require('../attack-paths.js');

/* This view renders scan-derived strings: server banners, endpoints, payload
 * descriptions. A banner is fully attacker-controlled, so the escaping is a
 * security property and is tested as one rather than assumed.
 *
 * The stub captures innerHTML instead of forbidding it, because the assertion
 * worth making is about what ends up in the string. */
class Element {
  constructor() {
    this.events = {};
    this.attributes = {};
    this.hidden = true;
    this.textContent = '';
    this.html = '';
  }
  set innerHTML(value) { this.html = String(value); }
  get innerHTML() { return this.html; }
  addEventListener(name, handler) { this.events[name] = handler; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  getAttribute(name) { return this.attributes[name]; }
  fire(name, event = {}) { this.events[name]({ preventDefault() {}, ...event }); }
}

function setup(onOpenFinding) {
  const list = new Element();
  const summary = new Element();
  const legend = new Element();
  const root = new Element();
  root.querySelector = selector => ({
    '[data-paths-list]': list,
    '[data-paths-summary]': summary,
    '[data-paths-legend]': legend,
  })[selector];
  return { root, list, summary, legend, view: createAttackPathsView(root, { onOpenFinding }) };
}

function step(kind, label, level, extra = {}) {
  return { kind, label, detail: '', evidence_level: level, source_finding_id: null, ...extra };
}

const CONFIRMED = {
  id: 'attack_path_001',
  title: 'Confirmed SQL injection at https://shop.example.com/item?id=7',
  status: 'exploited',
  severity: 'high',
  attack_confirmed: true,
  attack_type: 'SQL injection',
  source_finding_ids: ['f_sqli'],
  steps: [
    step('target', 'shop.example.com', 'confirmed'),
    step('proof', 'Target-side execution proof', 'confirmed', { source_finding_id: 'f_sqli' }),
  ],
  possible_impacts: ['Read database rows accessible to the application user'],
  remediation: 'Use parameterised queries.',
};

const KEV_CVE = {
  id: 'attack_path_002',
  title: 'CVE-2021-41773 through Apache httpd 2.4.49',
  status: 'version_confirmed',
  severity: 'critical',
  attack_confirmed: false,
  attack_type: 'Remote command execution',
  source_finding_ids: ['f_cve'],
  steps: [
    step('target', 'shop.example.com', 'confirmed'),
    step('threat', 'CISA KEV: exploited in the wild', 'supported', { source_finding_id: 'f_cve' }),
    step('technique', 'Possible technique: Remote command execution', 'possible', { source_finding_id: 'f_cve' }),
  ],
  possible_impacts: ['Potential host takeover'],
  remediation: 'Upgrade Apache httpd beyond the affected range.',
};

test('a scan with nothing to correlate hides the view rather than showing it empty', () => {
  const { view, root } = setup();
  assert.deepEqual(view.update({}), { count: 0 });
  assert.equal(root.hidden, true);
  assert.equal(view.update({ attack_paths: [] }).count, 0);
  assert.equal(view.update({ attack_paths: 'not an array' }).count, 0);
});

test('the summary counts each status by the name a reader would use', () => {
  const { view, summary } = setup();
  view.update({ attack_paths: [CONFIRMED, KEV_CVE] });
  assert.match(summary.textContent, /^2 paths/);
  assert.match(summary.textContent, /1 confirmed on this target/);
  assert.match(summary.textContent, /1 version-confirmed/);
});

test('every step renders its evidence level as text, not only as colour', () => {
  const { view, list } = setup();
  view.update({ attack_paths: [KEV_CVE] });
  // Three steps, three visible level labels.
  assert.equal((list.html.match(/class="path-level level-/g) || []).length, 3);
  assert.match(list.html, /level-confirmed">confirmed</);
  assert.match(list.html, /level-supported">supported</);
  assert.match(list.html, /level-possible">possible</);
});

test('a chain ending in an unexecuted step says so in words', () => {
  const { view, list } = setup();
  view.update({ attack_paths: [KEV_CVE] });
  assert.match(list.html, /ends in a step that was never executed/);
  assert.match(list.html, /Treat the outcome as unproven/);
  // And it must not be described the way a proven chain is.
  assert.doesNotMatch(list.html, /Every step in this chain was observed or proven[\s\S]*CVE-2021-41773/);
});

test('a version-confirmed path never claims the target was exploited', () => {
  const { view, list } = setup();
  view.update({ attack_paths: [KEV_CVE] });
  assert.match(list.html, /Version-confirmed/);
  assert.match(list.html, /No exploit was run/);
  assert.match(list.html, /Possible impact if exploited/);
  assert.doesNotMatch(list.html, /Confirmed on this target/);
});

test('only a proven path claims demonstrated impact', () => {
  const { view, list } = setup();
  view.update({ attack_paths: [CONFIRMED] });
  assert.match(list.html, /Confirmed on this target/);
  assert.match(list.html, /Demonstrated impact/);
  assert.match(list.html, /Every step in this chain was observed or proven/);
});

test('scan-derived text is escaped before it reaches the page', () => {
  // A server banner is attacker-controlled. So is an endpoint, a payload
  // description, and a CVE title copied from an upstream feed.
  const attack = '<img src=x onerror=alert(1)>';
  const hostile = {
    ...CONFIRMED,
    title: attack,
    attack_type: attack,
    remediation: attack,
    possible_impacts: [attack],
    steps: [step('service', `443/tcp ${attack}`, 'confirmed', { detail: attack })],
  };
  const { view, list } = setup();
  view.update({ attack_paths: [hostile] });

  // The payload's text survives; its angle brackets and quotes do not, so no
  // tag is ever formed. That is the property worth asserting -- searching for
  // the word "onerror" would fail on correctly escaped output.
  assert.doesNotMatch(list.html, /<img/, 'an img tag was formed from scan data');
  assert.match(list.html, /&lt;img src=x onerror=alert\(1\)&gt;/);
  // Six hostile fields went in -- title, attack_type, remediation, one impact,
  // and the step's label and detail. Every one comes back entity-encoded.
  assert.equal((list.html.match(/&lt;img src=x/g) || []).length, 6);
});

test('an attacker cannot break out of the finding-id attribute', () => {
  const { view, list } = setup(() => {});
  view.update({
    attack_paths: [{
      ...CONFIRMED,
      steps: [step('proof', 'p', 'confirmed', { source_finding_id: '" onmouseover="alert(1)' })],
    }],
  });
  // The payload text survives inside the attribute, which is harmless. What
  // matters is that both quotes are entities, so it cannot close the attribute
  // and start a new one.
  assert.match(list.html, /data-finding-id="&quot; onmouseover=&quot;alert\(1\)"/);
  assert.doesNotMatch(list.html, /data-finding-id="" onmouseover/);
});

test('a step opens the finding it came from, by mouse and by keyboard', () => {
  const opened = [];
  const { view, root } = setup(id => opened.push(id));
  view.update({ attack_paths: [CONFIRMED] });

  const target = { closest: selector => (selector === '[data-finding-id]' ? { dataset: { findingId: 'f_sqli' } } : null) };
  root.fire('click', { target });
  assert.deepEqual(opened, ['f_sqli']);

  root.fire('keydown', { key: 'Enter', target });
  assert.deepEqual(opened, ['f_sqli', 'f_sqli']);

  // A key that is not an activation must not open anything.
  root.fire('keydown', { key: 'Tab', target });
  assert.equal(opened.length, 2);
});

test('every status and step kind the correlator emits has a label here', () => {
  // Otherwise a path renders with a blank badge or an unnamed step, which is
  // exactly the case a reader would misread.
  const source = fs.readFileSync(
    path.join(__dirname, '..', '..', 'backend', 'app', 'services', 'attack_paths.py'), 'utf8');

  const statuses = [...source.matchAll(/^\s{4}"(\w+)": \d,$/gm)]
    .map(match => match[1])
    .filter(name => name in { exploited: 1, version_confirmed: 1, supported: 1, candidate: 1, blocked: 1 });
  assert.ok(statuses.length >= 5, `expected the status order table, found ${statuses}`);
  for (const status of statuses) {
    assert.ok(PATH_STATUS[status], `status ${status} has no label in the view`);
  }

  for (const kind of [...source.matchAll(/_step\(\s*"(\w+)"/g)].map(m => m[1])) {
    assert.ok(STEP_ROLE[kind], `step kind ${kind} has no role label in the view`);
  }
});
