const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {
  TRIAGE_STATES,
  SUPPRESSING_STATES,
  triageStateOf,
  isSuppressed,
  createTriageControl,
  createTriageSummary,
} = require('../triage.js');

/* The interface has one job beyond collecting a decision: it must not let
 * suppression feel frictionless. These tests hold that line from the UI side,
 * the way the Python tests hold it from the server side. */

class Element {
  constructor(tag = 'div') {
    this.tag = tag;
    this.events = {};
    this.attributes = {};
    this.dataset = {};
    this.classes = new Set();
    this.hidden = false;
    this.disabled = false;
    this.value = '';
    this.textContent = '';
    this.focused = false;
    this.classList = {
      add: (...names) => names.forEach(n => this.classes.add(n)),
      remove: (...names) => names.forEach(n => this.classes.delete(n)),
      toggle: (name, force) => (force ? this.classes.add(name) : this.classes.delete(name)),
      contains: name => this.classes.has(name),
    };
  }
  addEventListener(name, handler) { this.events[name] = handler; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  getAttribute(name) { return this.attributes[name]; }
  focus() { this.focused = true; }
  async fire(name, event = {}) { return this.events[name]({ preventDefault() {}, ...event }); }
}

function setupControl(onSave) {
  const buttons = Object.keys(TRIAGE_STATES).map(state => {
    const button = new Element('button');
    button.dataset.triageState = state;
    return button;
  });
  const elements = {
    block: new Element(),
    buttons,
    reasonWrap: new Element(),
    reasonInput: new Element('textarea'),
    saveButton: new Element('button'),
    status: new Element(),
    current: new Element(),
  };
  const control = createTriageControl(elements, { onSave });
  const pick = state => buttons.find(b => b.dataset.triageState === state);
  return { ...elements, control, pick };
}

const FINDING = {
  id: 'f_1',
  title: 'Apache httpd 2.4.49 is affected by CVE-2021-41773',
  severity: 'critical',
  triage_fingerprint: 'a'.repeat(32),
  triage: { state: 'open', reason: '', author: '', decided_at: '' },
};

// ── State helpers ────────────────────────────────────────────────────────────

test('exactly two states suppress, and both of them are the reviewed-away ones', () => {
  assert.deepEqual(SUPPRESSING_STATES.sort(), ['accepted_risk', 'false_positive']);
  assert.equal(TRIAGE_STATES.confirmed.suppresses, false, 'confirming must not hide a finding');
  assert.equal(TRIAGE_STATES.open.suppresses, false);
});

test('an unknown or missing state reads as open rather than throwing', () => {
  assert.equal(triageStateOf(undefined), 'open');
  assert.equal(triageStateOf({}), 'open');
  assert.equal(triageStateOf({ triage: { state: 'deleted' } }), 'open');
  assert.equal(isSuppressed({ triage: { state: 'deleted' } }), false);
});

// ── The friction that has to stay ────────────────────────────────────────────

test('a suppressing state cannot be saved without a written reason', async () => {
  let called = false;
  const ui = setupControl(async () => { called = true; });
  ui.control.open(FINDING);

  await ui.pick('false_positive').fire('click');
  ui.reasonInput.value = '   ';
  await ui.saveButton.fire('click');

  assert.equal(called, false, 'an unjustified suppression reached the server');
  assert.match(ui.status.textContent, /written reason is required/);
  assert.ok(ui.status.classes.has('is-error'));
  assert.equal(ui.reasonInput.focused, true, 'the user is not told where to fix it');
});

test('the reason field is only demanded by the states that hide something', async () => {
  const ui = setupControl(async () => {});
  ui.control.open(FINDING);

  await ui.pick('confirmed').fire('click');
  assert.equal(ui.reasonWrap.hidden, true);

  await ui.pick('accepted_risk').fire('click');
  assert.equal(ui.reasonWrap.hidden, false);

  await ui.pick('open').fire('click');
  assert.equal(ui.reasonWrap.hidden, true);
});

test('confirming needs no reason and saves straight through', async () => {
  const sent = [];
  const ui = setupControl(async payload => { sent.push(payload); });
  ui.control.open(FINDING);

  await ui.pick('confirmed').fire('click');
  await ui.saveButton.fire('click');

  assert.deepEqual(sent, [{ fingerprint: 'a'.repeat(32), state: 'confirmed', reason: '' }]);
  assert.match(ui.status.textContent, /Saved/);
});

test('a justified suppression saves, carrying its reason', async () => {
  const sent = [];
  const ui = setupControl(async payload => { sent.push(payload); });
  ui.control.open(FINDING);

  await ui.pick('false_positive').fire('click');
  ui.reasonInput.value = '  Backported patch in 2.4.49-1ubuntu1.4  ';
  await ui.saveButton.fire('click');

  assert.equal(sent.length, 1);
  assert.equal(sent[0].state, 'false_positive');
  assert.equal(sent[0].reason, 'Backported patch in 2.4.49-1ubuntu1.4');
});

test('a failed save says so and does not claim success', async () => {
  const ui = setupControl(async () => { throw new Error('The triage store could not be written.'); });
  ui.control.open(FINDING);
  await ui.pick('confirmed').fire('click');
  await ui.saveButton.fire('click');

  assert.match(ui.status.textContent, /could not be written/);
  assert.ok(ui.status.classes.has('is-error'));
  assert.equal(ui.saveButton.disabled, false, 'the button stayed disabled after a failure');
});

test('a finding with no fingerprint hides the control instead of offering a dead button', () => {
  const ui = setupControl(async () => {});
  ui.control.open({ id: 'old', title: 'From an older export' });
  assert.equal(ui.block.hidden, true);
});

test('an existing decision is shown when the finding is reopened', () => {
  const ui = setupControl(async () => {});
  ui.control.open({
    ...FINDING,
    triage: { state: 'accepted_risk', reason: 'Owner accepted', decided_at: '2026-09-05T10:00:00+00:00' },
  });
  assert.match(ui.current.textContent, /Accepted risk/);
  assert.match(ui.current.textContent, /Owner accepted/);
  assert.match(ui.current.textContent, /2026-09-05/);
  assert.equal(ui.reasonInput.value, 'Owner accepted');
});

// ── Suppression is never silent ──────────────────────────────────────────────

function setupSummary() {
  const elements = {
    root: new Element(), count: new Element(), detail: new Element(), toggle: new Element('button'),
  };
  return { ...elements, summary: createTriageSummary(elements) };
}

test('the banner stays hidden only while nothing has been reviewed', () => {
  const ui = setupSummary();
  ui.summary.update({ triage_summary: { counts: {}, suppressed_total: 0 } });
  assert.equal(ui.root.hidden, true);
  ui.summary.update({});
  assert.equal(ui.root.hidden, true);
});

test('the banner appears whenever anything is suppressed, and says what and why', () => {
  const ui = setupSummary();
  ui.summary.update({
    triage_summary: {
      counts: { open: 4, confirmed: 1, false_positive: 2, accepted_risk: 1 },
      suppressed_total: 3,
    },
  });
  assert.equal(ui.root.hidden, false);
  assert.match(ui.count.textContent, /3 findings suppressed by triage/);
  assert.match(ui.detail.textContent, /2 marked false positive/);
  assert.match(ui.detail.textContent, /1 accepted as risk/);
  assert.match(ui.detail.textContent, /remain in the report and every export/);
});

test('the toggle reveals suppressed findings rather than un-suppressing them', async () => {
  const ui = setupSummary();
  const seen = [];
  ui.summary.update({ triage_summary: { counts: { false_positive: 1 }, suppressed_total: 1 } },
    revealed => seen.push(revealed));

  await ui.toggle.fire('click');
  assert.deepEqual(seen, [true]);
  assert.match(ui.toggle.textContent, /Hide suppressed/);
  assert.equal(ui.toggle.getAttribute('aria-expanded'), 'true');

  await ui.toggle.fire('click');
  assert.deepEqual(seen, [true, false]);
  assert.match(ui.toggle.textContent, /Show suppressed/);
});

test('a report with only confirmations shows the banner without a reveal toggle', () => {
  const ui = setupSummary();
  ui.summary.update({ triage_summary: { counts: { confirmed: 2 }, suppressed_total: 0 } });
  assert.equal(ui.root.hidden, false);
  assert.match(ui.count.textContent, /2 findings confirmed by review/);
  assert.equal(ui.toggle.hidden, true, 'nothing is hidden, so there is nothing to reveal');
});

// ── Agreement with the server ────────────────────────────────────────────────

test('the states here are exactly the states the server accepts', () => {
  const source = fs.readFileSync(
    path.join(__dirname, '..', '..', 'backend', 'app', 'services', 'triage.py'), 'utf8');
  const declared = (source.match(/^STATES = \(([^)]+)\)/m) || [])[1] || '';
  const serverStates = [...declared.matchAll(/(\w+)/g)]
    .map(m => m[1])
    .map(name => (source.match(new RegExp(`^${name} = "(\\w+)"`, 'm')) || [])[1])
    .filter(Boolean);

  assert.deepEqual(serverStates.sort(), Object.keys(TRIAGE_STATES).sort(),
    'the UI offers a state the server would reject, or hides one it accepts');

  const suppressing = ((source.match(/^SUPPRESSING = \(([^)]+)\)/m) || [])[1] || '');
  const serverSuppressing = [...suppressing.matchAll(/(\w+)/g)]
    .map(m => (source.match(new RegExp(`^${m[1]} = "(\\w+)"`, 'm')) || [])[1])
    .filter(Boolean);
  assert.deepEqual(serverSuppressing.sort(), SUPPRESSING_STATES.slice().sort(),
    'the UI and the server disagree about which states hide a finding');
});
