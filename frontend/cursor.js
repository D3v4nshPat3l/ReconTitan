/* Cursor glyph trail for the hero.
 *
 * Characters are emitted along the pointer's path and fade out, so moving the
 * mouse leaves a stroke of text behind it. Emission is distance-based rather
 * than time-based: a stationary pointer produces nothing, and a fast one
 * produces an evenly spaced trail instead of a clump.
 *
 * The alphabet is hex digits and the punctuation of addresses and hashes,
 * because this sits on a recon tool — the trail reads as fragments of the
 * things a scan actually pulls back, not as decorative noise.
 *
 * Scoped to the dark hero on purpose. A full-page trail would have to fight
 * the white scanner section below, where faint glyphs either vanish or turn
 * into smudges over the form the page exists to serve.
 */
(function () {
  'use strict';

  const host = document.querySelector('.hero');
  const canvas = document.getElementById('cursorCanvas');
  if (!host || !canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  // Pointer trails are meaningless without a pointer, and on touch the
  // canvas would only ever be dead weight.
  const finePointer = window.matchMedia('(pointer: fine)');
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

  const GLYPHS = '0123456789abcdef/:.-_?&=<>#$%'.split('');
  const MAX = 140;              // hard ceiling; oldest are dropped first
  const SPACING = 14;           // px of pointer travel between emissions
  const LIFE = 1500;            // ms from full opacity to gone

  let W = 0, H = 0, dpr = 1;
  let glyphs = [];
  let lastX = null, lastY = null;
  let running = false, raf = 0, lastFrame = 0;

  function resize() {
    const r = host.getBoundingClientRect();
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = r.width;
    H = r.height;
    if (!W || !H) return;
    canvas.width = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function emit(x, y) {
    if (glyphs.length >= MAX) glyphs.shift();
    glyphs.push({
      char: GLYPHS[(Math.random() * GLYPHS.length) | 0],
      x: x + (Math.random() - 0.5) * 18,
      y: y + (Math.random() - 0.5) * 18,
      // A slow drift upward reads as the trail dissipating rather than
      // simply switching off.
      vx: (Math.random() - 0.5) * 0.22,
      vy: -0.10 - Math.random() * 0.20,
      rot: (Math.random() - 0.5) * 0.7,
      size: 10 + Math.random() * 9,
      born: performance.now(),
      // A minority in accent, so the trail has punctuation rather than being
      // one flat colour.
      accent: Math.random() < 0.18,
    });
  }

  function onMove(event) {
    if (!finePointer.matches || reduceMotion.matches) return;
    const r = host.getBoundingClientRect();
    const x = event.clientX - r.left;
    const y = event.clientY - r.top;
    if (x < 0 || y < 0 || x > W || y > H) { lastX = lastY = null; return; }

    if (lastX === null) { lastX = x; lastY = y; emit(x, y); start(); return; }

    // Walk the segment since the last event and drop a glyph every SPACING
    // pixels, so a fast flick still leaves an even stroke rather than a gap.
    let dx = x - lastX, dy = y - lastY;
    let dist = Math.hypot(dx, dy);
    while (dist >= SPACING) {
      const t = SPACING / dist;
      lastX += dx * t;
      lastY += dy * t;
      emit(lastX, lastY);
      dx = x - lastX; dy = y - lastY;
      dist = Math.hypot(dx, dy);
    }
    start();
  }

  function draw(now) {
    ctx.clearRect(0, 0, W, H);
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';

    for (let i = glyphs.length - 1; i >= 0; i--) {
      const g = glyphs[i];
      const age = (now - g.born) / LIFE;
      if (age >= 1) { glyphs.splice(i, 1); continue; }

      g.x += g.vx;
      g.y += g.vy;

      // Quick fade in, long fade out — the glyph should register instantly
      // under the cursor and then linger.
      const alpha = age < 0.12 ? age / 0.12 : 1 - (age - 0.12) / 0.88;
      ctx.save();
      ctx.translate(g.x, g.y);
      ctx.rotate(g.rot * age);
      ctx.font = g.size + 'px "JetBrains Mono", ui-monospace, monospace';
      ctx.fillStyle = g.accent
        ? 'rgba(238,117,1,' + (alpha * 0.75).toFixed(3) + ')'
        : 'rgba(255,255,255,' + (alpha * 0.42).toFixed(3) + ')';
      ctx.fillText(g.char, 0, 0);
      ctx.restore();
    }
  }

  function frame(now) {
    lastFrame = now;
    draw(now);
    if (glyphs.length) {
      raf = requestAnimationFrame(frame);
    } else {
      running = false;               // idle costs nothing once the trail clears
    }
  }

  function start() {
    if (running || reduceMotion.matches) return;
    running = true;
    raf = requestAnimationFrame(frame);
  }
  function stop() {
    running = false;
    cancelAnimationFrame(raf);
  }

  resize();
  window.addEventListener('resize', resize);
  window.addEventListener('pointermove', onMove, { passive: true });
  window.addEventListener('pointerleave', () => { lastX = lastY = null; });
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) { stop(); glyphs = []; ctx.clearRect(0, 0, W, H); }
  });

  reduceMotion.addEventListener('change', (e) => {
    if (e.matches) { stop(); glyphs = []; ctx.clearRect(0, 0, W, H); }
  });
})();
