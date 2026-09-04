/* Hero globe — a rotating wireframe sphere with hosts and the links between
 * them. Hand-rolled 3D rather than a library: the page's CSP is script-src
 * 'self', so a CDN build of Three.js would be blocked, and vendoring one to
 * draw a few hundred lines is not a trade worth making.
 *
 * Everything is projected by hand and drawn to a 2D canvas. That keeps it
 * small, dependency-free, and fast enough to sit behind a hero without
 * costing anything noticeable.
 */
function mountGlobe(canvas) {
  'use strict';

  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

  // The wireframe has to read against whatever it sits on. Dark ground gets
  // white lines; paper gets ink. Declared per canvas rather than assumed.
  const onPaper  = canvas.dataset.globe === 'light';
  const INK_LINE = onPaper ? '13,13,13' : '255,255,255';
  const ACCENT   = '238,117,1';

  // ── Geometry ────────────────────────────────────────────────────────────
  // A point on the unit sphere from latitude/longitude, in radians.
  function onSphere(lat, lon) {
    const cl = Math.cos(lat);
    return { x: cl * Math.cos(lon), y: Math.sin(lat), z: cl * Math.sin(lon) };
  }

  // Wireframe: parallels and meridians, each a ring of sampled points.
  const RINGS = [];
  for (let i = 1; i < 7; i++) {                    // parallels
    const lat = -Math.PI / 2 + (i * Math.PI) / 7;
    const ring = [];
    for (let s = 0; s <= 64; s++) ring.push(onSphere(lat, (s / 64) * Math.PI * 2));
    RINGS.push(ring);
  }
  for (let m = 0; m < 12; m++) {                   // meridians
    const lon = (m / 12) * Math.PI * 2;
    const ring = [];
    for (let s = 0; s <= 48; s++) {
      ring.push(onSphere(-Math.PI / 2 + (s / 48) * Math.PI, lon));
    }
    RINGS.push(ring);
  }

  // Hosts scattered over the surface. A few are "found" and drawn in accent.
  const HOSTS = [];
  for (let i = 0; i < 46; i++) {
    const lat = Math.asin(Math.random() * 2 - 1);   // uniform over the sphere
    const lon = Math.random() * Math.PI * 2;
    HOSTS.push({
      base: onSphere(lat, lon),
      found: i % 5 === 0,
      phase: Math.random() * Math.PI * 2,
    });
  }

  // Links between nearby hosts, drawn as arcs lifted off the surface so they
  // read as connections rather than chords cutting through the globe.
  const LINKS = [];
  const degree = new Array(HOSTS.length).fill(0);
  for (let i = 0; i < HOSTS.length; i++) {
    for (let j = i + 1; j < HOSTS.length; j++) {
      if (degree[i] >= 2 || degree[j] >= 2) continue;   // spread, don't clump
      const a = HOSTS[i].base, b = HOSTS[j].base;
      const d = Math.hypot(a.x - b.x, a.y - b.y, a.z - b.z);
      if (d < 0.70) {
        LINKS.push({ a, b });
        degree[i]++; degree[j]++;
      }
    }
  }

  function rotateY(p, angle) {
    const s = Math.sin(angle), c = Math.cos(angle);
    return { x: p.x * c - p.z * s, y: p.y, z: p.x * s + p.z * c };
  }

  // Base tilt, so the poles are never dead-on and the sphere reads as 3D.
  // The pointer nudges it a little either side of that, which is what makes
  // the globe feel like an object in the page rather than a looping GIF.
  const TILT = -0.42;
  const TILT_RANGE = 0.30;      // radians of pointer influence, kept small
  const YAW_RANGE = 0.34;
  let tiltNow = TILT, tiltWant = TILT;
  let yawNow = 0, yawWant = 0;

  function tilt(p) {
    const s = Math.sin(tiltNow), c = Math.cos(tiltNow);
    return { x: p.x, y: p.y * c - p.z * s, z: p.y * s + p.z * c };
  }

  // Pointer position drives the target; `draw` eases toward it, so the globe
  // follows with weight instead of snapping to the cursor.
  window.addEventListener('pointermove', (event) => {
    const r = canvas.getBoundingClientRect();
    if (!r.width) return;
    const nx = (event.clientX - (r.left + r.width / 2)) / (window.innerWidth / 2);
    const ny = (event.clientY - (r.top + r.height / 2)) / (window.innerHeight / 2);
    yawWant = Math.max(-1, Math.min(1, nx)) * YAW_RANGE;
    tiltWant = TILT + Math.max(-1, Math.min(1, ny)) * TILT_RANGE;
  }, { passive: true });

  // ── Sizing ──────────────────────────────────────────────────────────────
  let W = 0, H = 0, R = 0, cx = 0, cy = 0, dpr = 1;

  function resize() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = canvas.offsetWidth;
    H = canvas.offsetHeight;
    if (!W || !H) return;
    canvas.width = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    R = Math.min(W, H) * 0.38;
    cx = W / 2;
    cy = H / 2;
  }

  // Perspective projection. `depth` is the rotated z in [-1, 1]; the caller
  // uses it to fade whatever is on the far side of the sphere.
  const CAMERA = 2.6;
  function project(p) {
    const scale = CAMERA / (CAMERA - p.z);
    return { x: cx + p.x * R * scale, y: cy - p.y * R * scale, depth: p.z, scale };
  }

  // ── Rendering ───────────────────────────────────────────────────────────
  let spin = 0;
  let sweep = 0;

  function draw(dt) {
    if (!W || !H) return;
    ctx.clearRect(0, 0, W, H);

    // Soft core so the wireframe has something to sit against.
    const glow = ctx.createRadialGradient(cx, cy, 0, cx, cy, R * 1.5);
    glow.addColorStop(0, 'rgba(' + ACCENT + ',0.14)');
    glow.addColorStop(0.55, 'rgba(' + ACCENT + ',0.03)');
    glow.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.fillStyle = glow;
    ctx.fillRect(0, 0, W, H);

    // Wireframe. Segments are stroked individually so each can fade with its
    // own depth — a single path would force one opacity for the whole ring.
    ctx.lineWidth = 1;
    for (const ring of RINGS) {
      for (let i = 0; i < ring.length - 1; i++) {
        const p1 = project(tilt(rotateY(ring[i], spin + yawNow)));
        const p2 = project(tilt(rotateY(ring[i + 1], spin + yawNow)));
        const d = (p1.depth + p2.depth) / 2;
        const base = onPaper ? 0.10 : 0.07, span = onPaper ? 0.30 : 0.23;
        const alpha = base + span * ((d + 1) / 2);   // far side stays visible, faintly
        ctx.strokeStyle = 'rgba(' + INK_LINE + ',' + alpha.toFixed(3) + ')';
        ctx.beginPath();
        ctx.moveTo(p1.x, p1.y);
        ctx.lineTo(p2.x, p2.y);
        ctx.stroke();
      }
    }

    // Links, lifted above the surface along the midpoint normal.
    for (const link of LINKS) {
      const a = tilt(rotateY(link.a, spin + yawNow));
      const b = tilt(rotateY(link.b, spin + yawNow));
      const mid = { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2, z: (a.z + b.z) / 2 };
      const len = Math.hypot(mid.x, mid.y, mid.z) || 1;
      const lift = 1.22;
      const control = { x: (mid.x / len) * lift, y: (mid.y / len) * lift, z: (mid.z / len) * lift };

      const pa = project(a), pb = project(b), pc = project(control);
      const depth = (a.z + b.z) / 2;
      if (depth < -0.35) continue;                  // hide links behind the globe
      const alpha = 0.10 + 0.28 * ((depth + 1) / 2);
      ctx.strokeStyle = 'rgba(' + ACCENT + ',' + alpha.toFixed(3) + ')';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(pa.x, pa.y);
      ctx.quadraticCurveTo(pc.x, pc.y, pb.x, pb.y);
      ctx.stroke();
    }

    // Hosts. Ones on the near side get a pulse; the sweep brightens whatever
    // it is currently passing over, which is the scan reading the surface.
    for (const host of HOSTS) {
      const p3 = tilt(rotateY(host.base, spin + yawNow));
      const p = project(p3);
      if (p3.z < -0.55) continue;
      const near = (p3.z + 1) / 2;
      const pulse = 0.5 + 0.5 * Math.sin(sweep * 2 + host.phase);
      const lit = Math.max(0, 1 - Math.abs(p3.x - Math.sin(sweep) * 0.9) * 2.2);

      const radius = (host.found ? 2.4 : 1.6) * p.scale * (1 + lit * 0.5);
      const alpha = (host.found ? 0.55 : 0.3) * near + lit * 0.4 + pulse * 0.12;
      ctx.fillStyle = host.found
        ? 'rgba(' + ACCENT + ',' + Math.min(1, alpha).toFixed(3) + ')'
        : 'rgba(' + INK_LINE + ',' + Math.min(1, alpha).toFixed(3) + ')';
      ctx.beginPath();
      ctx.arc(p.x, p.y, Math.max(0.6, radius), 0, Math.PI * 2);
      ctx.fill();

      if (host.found && near > 0.55) {              // halo on found hosts
        ctx.strokeStyle = 'rgba(' + ACCENT + ',' + (0.22 * near).toFixed(3) + ')';
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.arc(p.x, p.y, radius + 4 + pulse * 3, 0, Math.PI * 2);
        ctx.stroke();
      }
    }

    // Equatorial scan ring, drawn last so it reads as passing in front.
    const ringPts = [];
    for (let s = 0; s <= 72; s++) {
      const lon = (s / 72) * Math.PI * 2;
      ringPts.push(project(tilt(rotateY(onSphere(0, lon), spin + yawNow))));
    }
    for (let i = 0; i < ringPts.length - 1; i++) {
      const p1 = ringPts[i], p2 = ringPts[i + 1];
      if (p1.depth < -0.1) continue;
      ctx.strokeStyle = 'rgba(' + ACCENT + ',' + (0.30 * ((p1.depth + 1) / 2)).toFixed(3) + ')';
      ctx.lineWidth = 1.4;
      ctx.beginPath();
      ctx.moveTo(p1.x, p1.y);
      ctx.lineTo(p2.x, p2.y);
      ctx.stroke();
    }

    // Ease toward the pointer target. The 0.06 factor is the weight: high
    // enough to feel responsive, low enough that the globe never snaps.
    tiltNow += (tiltWant - tiltNow) * 0.06;
    yawNow  += (yawWant - yawNow) * 0.06;

    spin += dt * 0.00016;
    sweep += dt * 0.0009;
  }

  // ── Loop ────────────────────────────────────────────────────────────────
  let raf = 0;
  let last = 0;
  let running = false;

  function frame(now) {
    const dt = Math.min(48, now - (last || now));   // clamp after a tab switch
    last = now;
    draw(dt);
    raf = requestAnimationFrame(frame);
  }

  function start() {
    if (running || reduceMotion.matches) return;
    running = true;
    last = 0;
    raf = requestAnimationFrame(frame);
  }
  function stop() {
    running = false;
    cancelAnimationFrame(raf);
  }

  resize();
  // Paint once up front. The observer below only starts the loop when the hero
  // scrolls into view, so without this the canvas sits empty until then --
  // and stays empty entirely in a tab that is never brought to the front.
  draw(0);
  window.addEventListener('resize', () => { resize(); if (!running) draw(0); });

  if (reduceMotion.matches) {
    // Static frame only; the one above is all this mode ever needs.
  } else {
    // Only animate while the hero is actually on screen.
    if ('IntersectionObserver' in window) {
      new IntersectionObserver((entries) => {
        entries[0].isIntersecting ? start() : stop();
      }, { threshold: 0.01 }).observe(canvas);
    } else {
      start();
    }
    document.addEventListener('visibilitychange', () => {
      document.hidden ? stop() : start();
    });
  }

  reduceMotion.addEventListener('change', (e) => {
    if (e.matches) { stop(); draw(0); } else { start(); }
  });
}

// Every canvas that asks for one gets its own instance.
document.querySelectorAll('[data-globe]').forEach(mountGlobe);
