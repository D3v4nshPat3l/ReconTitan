/* Shared local-scan stream reader. No polling, second scan, or invented progress. */
(function (root) {
  'use strict';

  async function read(response, onProgress) {
    if (!(response.headers.get('content-type') || '').includes('application/x-ndjson')) {
      // Keep compatibility with older API deployments during a rolling update.
      return response.json();
    }
    if (!response.body || !response.body.getReader) {
      throw new Error('This browser cannot read live scan updates. Please use a current browser.');
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let pending = '';
    let percent = 0;
    let report;
    function accept(line) {
      if (!line.trim()) return;
      const event = JSON.parse(line);
      if (event.type === 'error') throw new Error(event.message || 'Scan failed.');
      if (event.type === 'complete') {
        if (!event.report || typeof event.report !== 'object') throw new Error('Missing scan report.');
        report = event.report;
      } else if (event.type === 'progress') {
        const value = Number(event.progress);
        if (!Number.isFinite(value)) throw new Error('Invalid scan progress.');
        // Completion belongs to the final report, never an intermediate event.
        percent = Math.max(percent, Math.min(99, Math.max(0, Math.floor(value))));
        onProgress({ ...event, progress: percent });
      }
    }
    try {
      while (true) {
        const { value, done } = await reader.read();
        pending += done ? decoder.decode() : decoder.decode(value, { stream: true });
        let end;
        while ((end = pending.indexOf('\n')) !== -1) {
          accept(pending.slice(0, end));
          pending = pending.slice(end + 1);
        }
        if (done) {
          if (pending.trim()) accept(pending);
          break;
        }
      }
      if (!report) throw new Error('Scan connection ended before the report arrived. Check the server logs before retrying.');
      return report;
    } finally {
      try { await reader.cancel(); } catch (_) { /* Connection may already be closed. */ }
      reader.releaseLock();
    }
  }

  const api = { read };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.ScanProgress = api;
})(typeof window !== 'undefined' ? window : globalThis);
