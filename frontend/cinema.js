/* ═══════════════════════════════════════════════════════════════════════
   ReconTitan — cinematic scroll engine

   The stage is sticky, so scrolling the section scrubs a timeline rather than
   moving the page. This file owns only numbers: it reads scroll position,
   smooths it, and writes CSS custom properties. Nothing here touches layout,
   which is why the whole choreography can be retuned by editing the constants
   in ACTS without hunting through style rules.

   Smoothing matters more than it sounds. Raw scroll offsets arrive in coarse
   jumps — a wheel notch is dozens of pixels — so driving transforms directly
   from them looks stepped. Interpolating toward the target each frame turns
   that into continuous motion, and the loop parks itself once it converges so
   an idle page costs nothing.
   ═══════════════════════════════════════════════════════════════════════ */

(function cinema() {
  'use strict';

  const section = document.querySelector('.cinema');
  if (!section) return;

  const root = section;
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

  const railTrack = section.querySelector('.rail-track');
  const railControls = section.querySelector('.rail-controls');
  const railPrev = section.querySelector('.rail-prev');
  const railNext = section.querySelector('.rail-next');

  /* Timeline, in pixels scrolled through the sticky section. Each act names
     four points: fade-in start/end, then fade-out start/end. */
  const ACTS = {
    split: [560, 900, 1300, 1620],
    depth: [1760, 2140, 2540, 2700],
    total: 2700,
    introFade: [90, 650],
    railIn: [2760, 3560],
    railControls: [3360, 3660],
  };

  let targetScroll = 0;
  let smoothScroll = 0;
  let targetMouseX = 0;
  let targetMouseY = 0;
  let mouseX = 0;
  let mouseY = 0;
  let started = false;
  let framePending = false;

  let cards = [];
  let originalCount = 0;
  let active = 0;

  const clamp = (v, min = 0, max = 1) => Math.min(max, Math.max(min, v));

  /** Hermite ease between two edges — smooth first derivative at both ends,
      so layers do not visibly "start" or "stop" moving. */
  function smoothstep(edge0, edge1, value) {
    const x = clamp((value - edge0) / (edge1 - edge0));
    return x * x * (3 - 2 * x);
  }

  const lerp = (a, b, t) => a + (b - a) * t;

  /** An act's enter/exit envelope. `active` peaks at 1 between b and c. */
  function envelope(s, a, b, c, d) {
    const enter = smoothstep(a, b, s);
    const exit = smoothstep(c, d, s);
    return { enter, exit, active: enter * (1 - exit) };
  }

  function scrolled() {
    const top = -section.getBoundingClientRect().top;
    return clamp(top, 0, section.offsetHeight - window.innerHeight);
  }

  const set = (name, value) => root.style.setProperty(name, value);

  function update() {
    framePending = false;

    targetScroll = scrolled();
    if (!started || reduceMotion.matches) {
      smoothScroll = targetScroll;
      started = true;
    } else {
      smoothScroll = lerp(smoothScroll, targetScroll, 0.14);
    }
    if (Math.abs(smoothScroll - targetScroll) < 0.08) smoothScroll = targetScroll;

    mouseX = lerp(mouseX, targetMouseX, 0.12);
    mouseY = lerp(mouseY, targetMouseY, 0.12);

    const s = smoothScroll;
    const split = envelope(s, ...ACTS.split);
    const depth = envelope(s, ...ACTS.depth);
    const progress = clamp(s / ACTS.total);
    const introExit = smoothstep(ACTS.introFade[0], ACTS.introFade[1], s);

    const railRaw = smoothstep(ACTS.railIn[0], ACTS.railIn[1], s);
    const railEnter = Math.pow(railRaw, 1.55);
    const railCtl = smoothstep(ACTS.railControls[0], ACTS.railControls[1], s);

    const veil = clamp(split.active + depth.active);
    /* Eased separately from `enter` so the halves accelerate apart rather than
       drifting linearly — the difference between a machine opening and a
       crossfade. */
    const partDrift = Math.pow(split.enter, 1.5);

    const gridScale = 1 + progress * 0.22 + split.enter * 0.18 + depth.enter * 0.16;
    const heroY = progress * -74;
    const heroScale = progress * 0.23;

    const px = reduceMotion.matches ? 0 : mouseX;
    const py = reduceMotion.matches ? 0 : mouseY;

    set('--mx', px.toFixed(4));
    set('--my', py.toFixed(4));

    /* Depth layers. Parallax amount is the depth cue: the backdrop barely
       moves, the pylons move most, and everything else sits between. */
    set('--backdrop-y', `${py * -3 + progress * 18}px`);
    set('--backdrop-scale', (1.08 + progress * 0.06).toFixed(4));
    set('--backdrop-opacity', (1 - veil * 0.18).toFixed(4));

    set('--grid-y', `${py * -6 + progress * 40}px`);
    set('--grid-scale', gridScale.toFixed(4));
    set('--grid-opacity', (1 - split.active * 0.25).toFixed(4));
    set('--rings-scale', (0.82 + progress * 0.3 + split.enter * 0.2).toFixed(4));
    set('--rings-opacity', (0.55 - veil * 0.3).toFixed(4));
    set('--rings-spin', `${progress * 26}deg`);

    /* Skyline sits between the rings and the core, drifting up slightly as the
       camera pushes in, and dimming once the wash takes over. */
    set('--skyline-y', `${py * -4 + progress * -30}px`);
    set('--skyline-scale', (1.02 + progress * 0.12).toFixed(4));
    set('--skyline-opacity', (0.9 - veil * 0.55).toFixed(4));

    /* The operations floor is scenery for the whole second half, not a beat
       that ends. It rises during the evidence act and then stays: the rail
       cards sit above it on a higher layer, so it reads as the room the work
       happens in rather than something competing with the cards. It only dims
       — never disappears — once the rail is fully in. */
    const floorIn = smoothstep(1700, 2200, s);
    const floorSettle = smoothstep(2700, 3400, s);
    set('--analyst-opacity', (floorIn * (1 - floorSettle * 0.34)).toFixed(4));
    set('--analyst-y', `${(1 - floorIn) * 70}px`);
    set('--analyst-scale', (1.04 + floorIn * 0.06 + floorSettle * 0.05).toFixed(4));

    /* Pylons arrive slightly after the floor so the frame closes in rather
       than everything appearing at once. */
    const pylonIn = smoothstep(1950, 2500, s);
    set('--pylon-opacity', (pylonIn * (1 - floorSettle * 0.22)).toFixed(4));
    set('--pylon-y', `${(1 - pylonIn) * 90}px`);
    set('--pylon-scale', (1.04 + pylonIn * 0.1).toFixed(4));

    set('--scan-opacity', (split.active * 0.9).toFixed(4));
    set('--scan-y', `${-50 + split.enter * 120}vh`);

    set('--blur-px', `${veil * 12}px`);
    set('--dim', (1 - veil * 0.26).toFixed(4));
    set('--wash-top', (veil * 0.42).toFixed(4));
    set('--wash-mid', (veil * 0.34).toFixed(4));
    set('--wash-bottom', (veil * 0.5).toFixed(4));

    /* Title and lede */
    set('--title-y', `${introExit * -210}px`);
    set('--title-scale', (1 - introExit * 0.08).toFixed(4));
    set('--title-opacity', (1 - introExit).toFixed(4));
    set('--lede-y', `${introExit * 90}px`);
    set('--lede-opacity', (1 - introExit).toFixed(4));

    /* Core: intact until the split act, then handed to the two halves. */
    set('--core-opacity', (1 - split.enter).toFixed(4));
    set('--core-x', `calc(-50% + ${px * 18}px)`);
    set('--core-y', `${py * 8 + heroY}px`);
    set('--core-scale', (1 + heroScale).toFixed(4));

    set('--half-l-x', `calc(-50% + ${-partDrift * 44}vw + ${px * 22}px)`);
    set('--half-l-y', `${py * 10 + heroY - partDrift * 170}px`);
    set('--half-l-scale', (1 + heroScale + split.enter * 0.7).toFixed(4));
    set('--half-r-x', `calc(-50% + ${partDrift * 44}vw + ${px * 22}px)`);
    set('--half-r-y', `${py * 10 + heroY - partDrift * 170}px`);
    set('--half-r-scale', (1 + heroScale + split.enter * 0.7).toFixed(4));

    /* What the split reveals. Fades back out as the next act takes over. */
    set('--deep-opacity', (split.active * (1 - depth.enter)).toFixed(4));
    set('--deep-scale', (1.06 + split.enter * 0.08 + split.exit * 0.08).toFixed(4));

    /* Story panels */
    set('--panel1-opacity', (split.active * (1 - split.exit)).toFixed(4));
    set('--panel1-y', `calc(-50% + ${-split.exit * 86 + (1 - split.enter) * 58}px)`);
    set('--panel2-opacity', (depth.active * (1 - depth.exit)).toFixed(4));
    set('--panel2-y', `calc(-50% + ${-depth.exit * 86 + (1 - depth.enter) * 58}px)`);

    /* Capability rail. Counter-scaled by the grid zoom so the cards hold a
       constant on-screen size while the world behind them keeps pushing in,
       and the parent top is solved back through that scale so they land where
       the design says regardless of viewport height. */
    const screenTop = Math.min(220, Math.max(112, window.innerHeight * 0.19)) - 40;
    const parentTop = window.innerHeight - (window.innerHeight - screenTop) / gridScale;

    set('--rail-visibility', railEnter > 0.01 ? 'visible' : 'hidden');
    set('--rail-enter-x', `${(1 - railEnter) * 420}vw`);
    set('--rail-scale', (1 / gridScale).toFixed(4));
    set('--rail-top', `${parentTop}px`);
    set('--rail-controls-opacity', railCtl.toFixed(4));
    if (railControls) railControls.classList.toggle('is-ready', railCtl > 0.98);

    const settling =
      Math.abs(smoothScroll - targetScroll) > 0.08 ||
      Math.abs(mouseX - targetMouseX) > 0.001 ||
      Math.abs(mouseY - targetMouseY) > 0.001;
    if (settling) requestTick();
  }

  function requestTick() {
    if (framePending) return;
    framePending = true;
    requestAnimationFrame(update);
  }

  /* ── Infinite rail ─────────────────────────────────────────────────── */
  /* Three identical sets of cards. The viewer sits in the middle set, and once
     a transition carries them into an outer set they are jumped back by one
     set with transitions suppressed. The move is invisible because the sets
     are identical, and it means next/prev never run out in either direction
     without cloning on every interaction. */

  function buildRail() {
    if (!railTrack) return;
    const originals = Array.from(railTrack.querySelectorAll('.rail-card'));
    originalCount = originals.length;
    if (!originalCount) return;

    const all = [];
    for (let set_ = 0; set_ < 3; set_ += 1) {
      originals.forEach((card, index) => {
        const clone = card.cloneNode(true);
        clone.dataset.railIndex = String(set_ * originalCount + index);
        all.push(clone);
      });
    }
    railTrack.replaceChildren(...all);
    cards = all;
    active = originalCount;

    cards.forEach((card) => {
      card.addEventListener('click', () => { if (!wasDragged()) select(card); });
      card.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          select(card);
        }
      });
    });

    railTrack.addEventListener('transitionend', normalize);
    layout();
  }

  function layout() {
    if (!cards.length || !railTrack) return;
    const width = cards[0].offsetWidth;
    const gap = parseFloat(getComputedStyle(railTrack).columnGap || '0') || 0;
    set('--rail-shift', `${-(width + gap) * active}px`);
    cards.forEach((card, index) => card.classList.toggle('is-active', index === active));
  }

  function move(direction) { active += direction; layout(); }

  /* ── Dragging ──────────────────────────────────────────────────────── */
  /* The arrows alone hid most of the deck: nothing signalled that more cards
     existed off-screen. Direct manipulation fixes that — grab and throw, or
     swipe on touch — with the arrows kept for keyboard and precision. */

  const rail = section.querySelector('.rail');
  let dragging = false;
  let dragStartX = 0;
  let dragDX = 0;
  let pointerId = null;

  function cardStride() {
    if (!cards.length || !railTrack) return 1;
    const gap = parseFloat(getComputedStyle(railTrack).columnGap || '0') || 0;
    return cards[0].offsetWidth + gap;
  }

  function dragStart(event) {
    if (!rail || event.button > 0) return;
    dragging = true;
    pointerId = event.pointerId;
    dragStartX = event.clientX;
    dragDX = 0;
    rail.classList.add('is-dragging');
    railTrack.classList.add('is-jumping');
    rail.setPointerCapture?.(pointerId);
  }

  function dragMove(event) {
    if (!dragging) return;
    dragDX = event.clientX - dragStartX;
    /* Divided by the counter-scale so a pixel of pointer travel is a pixel of
       card travel on screen, whatever the stage is currently zoomed to. */
    const scale = parseFloat(getComputedStyle(root).getPropertyValue('--rail-scale')) || 1;
    set('--rail-drag', `${dragDX / scale}px`);
  }

  function dragEnd() {
    if (!dragging) return;
    dragging = false;
    rail.classList.remove('is-dragging');
    if (pointerId !== null) rail.releasePointerCapture?.(pointerId);
    pointerId = null;

    /* Snap to whichever card the throw landed nearest. */
    const steps = Math.round(-dragDX / cardStride());
    set('--rail-drag', '0px');
    railTrack.classList.remove('is-jumping');
    if (steps !== 0) { active += steps; layout(); }
    dragDX = 0;
  }

  /* A click that followed a real drag is a throw, not a selection. */
  function wasDragged() { return Math.abs(dragDX) > 6; }

  function wheel(event) {
    /* Only claim clearly horizontal intent. Vertical wheel drives the entire
       timeline and must never be swallowed here. */
    if (Math.abs(event.deltaX) <= Math.abs(event.deltaY)) return;
    event.preventDefault();
    wheelAccum += event.deltaX;
    const stride = cardStride();
    while (Math.abs(wheelAccum) >= stride) {
      move(wheelAccum > 0 ? 1 : -1);
      wheelAccum -= Math.sign(wheelAccum) * stride;
    }
  }
  let wheelAccum = 0;

  function select(card) {
    const index = Number(card.dataset.railIndex);
    if (Number.isFinite(index)) { active = index; layout(); }
  }

  function jump(index) {
    if (!railTrack) return;
    railTrack.classList.add('is-jumping');
    active = index;
    layout();
    requestAnimationFrame(() => requestAnimationFrame(() => {
      railTrack.classList.remove('is-jumping');
    }));
  }

  function normalize() {
    if (!originalCount) return;
    if (active >= originalCount * 2) jump(active - originalCount);
    else if (active < originalCount) jump(active + originalCount);
  }

  /* ── Wiring ────────────────────────────────────────────────────────── */

  window.addEventListener('scroll', requestTick, { passive: true });
  window.addEventListener('resize', () => { layout(); requestTick(); });
  window.addEventListener('pointermove', (event) => {
    targetMouseX = event.clientX / window.innerWidth - 0.5;
    targetMouseY = event.clientY / window.innerHeight - 0.5;
    requestTick();
  }, { passive: true });

  if (rail) {
    rail.addEventListener('pointerdown', dragStart);
    rail.addEventListener('pointermove', dragMove);
    rail.addEventListener('pointerup', dragEnd);
    rail.addEventListener('pointercancel', dragEnd);
    rail.addEventListener('lostpointercapture', dragEnd);
    rail.addEventListener('wheel', wheel, { passive: false });
    rail.addEventListener('dragstart', (event) => event.preventDefault());
  }

  if (railPrev) railPrev.addEventListener('click', () => move(-1));
  if (railNext) railNext.addEventListener('click', () => move(1));

  buildRail();
  requestTick();
})();
