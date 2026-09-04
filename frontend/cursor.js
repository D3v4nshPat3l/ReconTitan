/* Cursor glyph trail — page-wide.
 *
 * Characters are emitted along the pointer's path and fade out, so moving the
 * mouse leaves a stroke of text behind it anywhere on the page.
 *
 * Emission is distance-based rather than time-based: a stationary pointer
 * produces nothing, and a fast one produces an evenly spaced trail instead of
 * a gap followed by a clump.
 *
 * The alphabet is hex digits and the punctuation of addresses and hashes,
 * because this sits on a recon tool — the trail reads as fragments of the
 * things a scan pulls back, not as decorative noise.
 *
 * The page alternates dark and light bands, so a single ink colour would be
 * invisible on half of it. Each band declares data-surface, and the glyph
 * takes its colour from whichever one the pointer is over at the moment it is
 * emitted. It keeps that colour for its whole life, which is correct: the
 * glyph belongs to the surface it was drawn on, even after the page scrolls.
 */
(function () {
  'use strict';

  const canvas = document.getElementById('cursorCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  // A trail is meaningless without a pointer, and on touch the canvas would
  // only ever be dead weight.
  const finePointer = window.matchMedia('(pointer: fine)');
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

  const GLYPHS = '0123456789abcdef/:.-_?&=<>#'.split('');
  const MAX = 160;
  const SPACING = 16;           // px of pointer travel between emissions
  const LIFE = 1300;            // ms from emission to gone

  let W = 0, H = 0, dpr = 1;
  let glyphs = [];
  let lastX = null, lastY = null;
  let running = false, raf = 0;

  function resize() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = window.innerWidth;
    H = window.innerHeight;
    if (!W || !H) return;
    canvas.width = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  // Which band is under this point? The canvas is pointer-events:none, so
  // elementFromPoint returns the real content beneath it.
  function surfaceAt(x, y) {
    const el = document.elementFromPoint(x, y);
    if (!el) return 'light';
    const band = el.closest('[data-surface]');
    return band ? band.getAttribute('data-surface') : 'light';
  }

  function emit(x, y, surface) {
    if (glyphs.length >= MAX) glyphs.shift();
    glyphs.push({
      char: GLYPHS[(Math.random() * GLYPHS.length) | 0],
      x: x + (Math.random() - 0.5) * 12,
      y: y + (Math.random() - 0.5) * 12,
      // A slow drift upward reads as the trail dissipating rather than
      // simply switching off.
      vx: (Math.random() - 0.5) * 0.18,
      vy: -0.08 - Math.random() * 0.16,
      rot: (Math.random() - 0.5) * 0.6,
      size: 7 + Math.random() * 4,
      born: performance.now(),
      dark: surface === 'dark',
      // A minority in accent, so the stroke has punctuation rather than
      // being one flat tone.
      accent: Math.random() < 0.18,
    });
  }

  function onMove(event) {
    if (!finePointer.matches || reduceMotion.matches) return;
    const x = event.clientX;
    const y = event.clientY;
    const surface = surfaceAt(x, y);

    if (lastX === null) { lastX = x; lastY = y; emit(x, y, surface); start(); return; }

    // Walk the segment since the last event and drop a glyph every SPACING
    // pixels, so a fast flick still leaves an even stroke rather than a gap.
    let dx = x - lastX, dy = y - lastY;
    let dist = Math.hypot(dx, dy);
    let budget = 24;                       // guard against a huge jump
    while (dist >= SPACING && budget-- > 0) {
      const t = SPACING / dist;
      lastX += dx * t;
      lastY += dy * t;
      emit(lastX, lastY, surface);
      dx = x - lastX; dy = y - lastY;
      dist = Math.hypot(dx, dy);
    }
    if (budget <= 0) { lastX = x; lastY = y; }
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
      ctx.font = g.size.toFixed(1) + 'px "JetBrains Mono", ui-monospace, monospace';
      if (g.accent) {
        ctx.fillStyle = 'rgba(238,117,1,' + (alpha * 0.8).toFixed(3) + ')';
      } else if (g.dark) {
        ctx.fillStyle = 'rgba(255,255,255,' + (alpha * 0.40).toFixed(3) + ')';
      } else {
        ctx.fillStyle = 'rgba(13,13,13,' + (alpha * 0.34).toFixed(3) + ')';
      }
      ctx.fillText(g.char, 0, 0);
      ctx.restore();
    }
  }

  function frame(now) {
    draw(now);
    if (glyphs.length) {
      raf = requestAnimationFrame(frame);
    } else {
      running = false;             // idle costs nothing once the trail clears
    }
  }

  function start() {
    if (running || reduceMotion.matches) return;
    running = true;
    raf = requestAnimationFrame(frame);
  }
  function clear() {
    running = false;
    cancelAnimationFrame(raf);
    glyphs = [];
    if (W && H) ctx.clearRect(0, 0, W, H);
  }

  resize();
  window.addEventListener('resize', resize);
  window.addEventListener('pointermove', onMove, { passive: true });
  window.addEventListener('pointerdown', onMove, { passive: true });
  // A gap in pointer data should break the stroke, not draw a line across it.
  window.addEventListener('pointerleave', () => { lastX = lastY = null; });
  window.addEventListener('blur', () => { lastX = lastY = null; });
  document.addEventListener('visibilitychange', () => { if (document.hidden) clear(); });

  reduceMotion.addEventListener('change', (e) => { if (e.matches) clear(); });
})();
