const { test } = require('node:test');
const assert = require('node:assert/strict');
const { read } = require('../scan-progress.js');

const progress = (n, phase = 'Running check') => ({ type: 'progress', progress: n, phase });
const complete = { type: 'complete', progress: 100, report: { target: 'example.com', findings: [] } };
const encode = events => new TextEncoder().encode(events.map(e => JSON.stringify(e)).join('\n') + '\n');
function response(chunks) {
  return new Response(new ReadableStream({
    start(controller) { chunks.forEach(chunk => controller.enqueue(chunk)); controller.close(); }
  }), { headers: { 'Content-Type': 'application/x-ndjson' } });
}

test('renders updates before the report arrives, not after buffering the entire response', async () => {
  let controller;
  const events = [];
  let notify;
  const updated = new Promise(resolve => { notify = resolve; });
  const res = new Response(new ReadableStream({ start(c) { controller = c; } }), {
    headers: { 'Content-Type': 'application/x-ndjson' }
  });
  const result = read(res, event => { events.push(event); notify(); });
  controller.enqueue(encode([progress(25)]));
  await updated;
  assert.equal(events[0].progress, 25);
  controller.enqueue(encode([progress(75), complete]));
  controller.close();
  assert.deepEqual(await result, complete.report);
  assert.deepEqual(events.map(e => e.progress), [25, 75]);
});

test('handles split JSON, split Unicode, and multiple events per chunk', async () => {
  const bytes = encode([progress(10, 'Résultats 🔎'), progress(60), complete]);
  const events = [];
  const report = await read(response(Array.from(bytes, b => Uint8Array.of(b))), e => events.push(e));
  assert.equal(events[0].phase, 'Résultats 🔎');
  assert.deepEqual(events.map(e => e.progress), [10, 60]);
  assert.deepEqual(report, complete.report);
});

test('progress is monotonic and never claims completion early', async () => {
  const values = [];
  await read(response([encode([progress(20), progress(10), progress(100), complete])]), e => values.push(e.progress));
  assert.deepEqual(values, [20, 20, 99]);
});

test('accepts an older backend JSON report without starting another scan', async () => {
  const result = await read(Response.json(complete.report), () => assert.fail('No invented progress'));
  assert.deepEqual(result, complete.report);
});

test('accepts a last line without a newline', async () => {
  const result = await read(response([new TextEncoder().encode(JSON.stringify(complete))]), () => {});
  assert.deepEqual(result, complete.report);
});

test('rejects a disconnected stream without a final report', async () => {
  await assert.rejects(read(response([encode([progress(25)])]), () => {}), /before the report arrived/);
});

test('propagates server errors and cancels the reader', async () => {
  let cancelled = false;
  const res = new Response(new ReadableStream({
    start(c) { c.enqueue(encode([{ type: 'error', message: 'Report failed' }])); },
    cancel() { cancelled = true; }
  }), { headers: { 'Content-Type': 'application/x-ndjson' } });
  await assert.rejects(read(res, () => {}), /Report failed/);
  assert.equal(cancelled, true);
  assert.equal(res.body.locked, false);
});

test('rejects malformed progress data and missing reports', async () => {
  await assert.rejects(read(response([encode([progress('bad')])]), () => {}), /Invalid scan progress/);
  await assert.rejects(read(response([encode([{ type: 'complete' }])]), () => {}), /Missing scan report/);
  await assert.rejects(read(response([new TextEncoder().encode('not json\n')]), () => {}), SyntaxError);
});
