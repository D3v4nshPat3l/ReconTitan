const { test, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

class Storage {
  constructor() { this.values = new Map(); }
  getItem(key) { return this.values.get(key) ?? null; }
  setItem(key, value) { this.values.set(key, String(value)); }
  removeItem(key) { this.values.delete(key); }
  clear() { this.values.clear(); }
}
global.localStorage = new Storage();
global.sessionStorage = new Storage();
const notices = [];
class Notification {
  static permission = 'default';
  static async requestPermission() { return Notification.permission; }
  constructor(title, options) { notices.push({ title, options }); }
}
global.Notification = Notification;
const alerts = require('../alerts.js');

beforeEach(() => { localStorage.clear(); sessionStorage.clear(); notices.length = 0; Notification.permission = 'default'; });

test('requires an explicit permission grant before enabling desktop alerts', async () => {
  assert.deepEqual(await alerts.setEnabled(true), { enabled: false, reason: 'Browser notification permission was not granted.' });
  Notification.permission = 'granted';
  assert.deepEqual(await alerts.setEnabled(true), { enabled: true });
  assert.equal(alerts.enabled(), true);
  assert.deepEqual(await alerts.setEnabled(false), { enabled: false });
});

test('only high and critical findings show one notification per scan', async () => {
  Notification.permission = 'granted';
  await alerts.setEnabled(true);
  const report = { scan_id: 'scan_1', target: 'example.com', severity_counts: { critical: 1, high: 2, medium: 10 } };
  assert.equal(alerts.notify(report), true);
  assert.equal(alerts.notify(report), false);
  assert.equal(notices.length, 1);
  assert.match(notices[0].options.body, /1 critical, 2 high/);
  assert.equal(alerts.notify({ scan_id: 'scan_2', target: 'example.com', severity_counts: { medium: 2 } }), false);
});

test('unsupported notification APIs cannot be enabled', async () => {
  const saved = global.Notification;
  delete global.Notification;
  assert.equal(alerts.supported(), false);
  assert.match((await alerts.setEnabled(true)).reason, /unavailable/);
  global.Notification = saved;
});
