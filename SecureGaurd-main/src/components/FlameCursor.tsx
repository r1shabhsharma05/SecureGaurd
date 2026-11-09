import { useEffect, useRef, useState } from 'react';
import './FlameCursor.css';

// Flame Fire Cursor — ported from the user's "Flame Fire Cursor" demo
// (flame trail + living flame cursor tip + click burst: the "Flame
// Breathing Burst" with spinning fire rings, blades, sparks, embers).
// The demo's dressing was NOT ported: the Rengoku bg.png image and its
// parallax/dim behaviour belong to the demo page, not to the cursor —
// SecureGuard keeps its own pages and backgrounds.
// Two adaptations for a working app (not a demo page):
//  - `cursor: none` hides the native pointer everywhere, EXCEPT text
//    fields, where the I-beam stays (see FlameCursor.css) so typing
//    stays usable. The flame tip IS the cursor everywhere else.
//  - Respects `prefers-reduced-motion`: the effect does not mount at
//    all, and the native cursor stays.
// The canvases are fixed overlays with pointer-events: none, so they
// never intercept clicks; they only draw. Mounted once in App, so the
// flame follows the cursor on every page.

const TAU = Math.PI * 2;

const lerp = (a: number, b: number, t: number) => a + (b - a) * t;
const rand = (a: number, b: number) => a + Math.random() * (b - a);
const randi = (a: number, b: number) => (a + Math.random() * (b - a)) | 0;
const clamp = (v: number, a: number, b: number) => Math.max(a, Math.min(b, v));

interface Ember { alive: boolean; x: number; y: number; vx: number; vy: number; age: number; life: number; sz: number; hot: number; sway: number; phase: number; grav: number; deep: boolean; }
interface Smoke { alive: boolean; x: number; y: number; vx: number; vy: number; age: number; life: number; r: number; dark: boolean; }
interface Flame { alive: boolean; x: number; y: number; vx: number; vy: number; age: number; life: number; r: number; hot: number; deep: boolean; }
interface Spark { alive: boolean; x: number; y: number; px: number; py: number; vx: number; vy: number; age: number; life: number; bright: number; deep: boolean; }
interface Blade { alive: boolean; x: number; y: number; vx: number; vy: number; angle: number; len: number; width: number; age: number; life: number; hot: number; deep: boolean; spin: number; }
interface FireRing { x: number; y: number; age: number; life: number; maxR: number; segs: number; rotSpeed: number; baseAngle: number; deep: boolean; }
interface Wave { x: number; y: number; r: number; maxR: number; age: number; life: number; delay?: number; }
interface Flash { x: number; y: number; r: number; maxR: number; age: number; life: number; }
interface HDCell { alive: boolean; x: number; y: number; str: number; age: number; life: number; }
interface TrailPoint { x: number; y: number; t: number; }

export default function FlameCursor() {
  const mainRef = useRef<HTMLCanvasElement>(null);
  const hdRef = useRef<HTMLCanvasElement>(null);
  const [enabled] = useState(
    () => typeof window !== 'undefined' && !window.matchMedia('(prefers-reduced-motion: reduce)').matches,
  );

  useEffect(() => {
    if (!enabled) return;
    const C = mainRef.current;
    const HD = hdRef.current;
    if (!C || !HD) return;
    const ctx = C.getContext('2d');
    const hctx = HD.getContext('2d');
    if (!ctx || !hctx) return;

    document.body.classList.add('flame-cursor-on');

    /* ── Canvas & DPR ── */
    let W = 0;
    let H = 0;
    let dpr = 1;

    function resize() {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      W = window.innerWidth;
      H = window.innerHeight;
      C.width = W * dpr;
      C.height = H * dpr;
      C.style.width = W + 'px';
      C.style.height = H + 'px';
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      HD.width = W * dpr;
      HD.height = H * dpr;
      HD.style.width = W + 'px';
      HD.style.height = H + 'px';
      hctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }
    resize();

    /* ══════════════════════════════════════════════════
       FLAME BREATHING COLOR SYSTEM
       Black → deep ember → fiery orange → golden amber → white-hot
       ══════════════════════════════════════════════════ */
    const LUT_R = new Uint8Array(256);
    const LUT_G = new Uint8Array(256);
    const LUT_B = new Uint8Array(256);
    (function () {
      const stops: [number, [number, number, number]][] = [
        [0, [0, 0, 0]],
        [24, [38, 4, 0]],
        [58, [120, 22, 0]],
        [98, [205, 62, 0]],
        [138, [255, 112, 8]],
        [178, [255, 172, 38]],
        [215, [255, 216, 92]],
        [255, [255, 250, 222]],
      ];
      for (let i = 0; i < 256; i++) {
        for (let s = 0; s < stops.length - 1; s++) {
          const [t0, c0] = stops[s];
          const [t1, c1] = stops[s + 1];
          if (i >= t0 && i <= t1) {
            const f = (i - t0) / (t1 - t0);
            LUT_R[i] = (c0[0] + (c1[0] - c0[0]) * f) | 0;
            LUT_G[i] = (c0[1] + (c1[1] - c0[1]) * f) | 0;
            LUT_B[i] = (c0[2] + (c1[2] - c0[2]) * f) | 0;
            break;
          }
        }
      }
    })();

    /* Deeper copper-ember accent LUT — for ~25% of particles */
    const CLUT_R = new Uint8Array(256);
    const CLUT_G = new Uint8Array(256);
    const CLUT_B = new Uint8Array(256);
    (function () {
      const stops: [number, [number, number, number]][] = [
        [0, [0, 0, 0]],
        [42, [32, 2, 0]],
        [95, [105, 12, 0]],
        [150, [185, 40, 0]],
        [200, [235, 88, 8]],
        [255, [255, 150, 45]],
      ];
      for (let i = 0; i < 256; i++) {
        for (let s = 0; s < stops.length - 1; s++) {
          const [t0, c0] = stops[s];
          const [t1, c1] = stops[s + 1];
          if (i >= t0 && i <= t1) {
            const f = (i - t0) / (t1 - t0);
            CLUT_R[i] = (c0[0] + (c1[0] - c0[0]) * f) | 0;
            CLUT_G[i] = (c0[1] + (c1[1] - c0[1]) * f) | 0;
            CLUT_B[i] = (c0[2] + (c1[2] - c0[2]) * f) | 0;
            break;
          }
        }
      }
    })();

    function flameColor(t: number, a: number) {
      const i = clamp(t * 255, 0, 255) | 0;
      return `rgba(${LUT_R[i]},${LUT_G[i]},${LUT_B[i]},${a})`;
    }
    function copperColor(t: number, a: number) {
      const i = clamp(t * 255, 0, 255) | 0;
      return `rgba(${CLUT_R[i]},${CLUT_G[i]},${CLUT_B[i]},${a})`;
    }

    /* ── Pointer state ── */
    const P = {
      x: W / 2,
      y: H / 2,
      tx: W / 2,
      ty: H / 2,
      px: W / 2,
      py: H / 2,
      vx: 0,
      vy: 0,
      speed: 0,
      lastMove: 0,
    };
    function setTarget(x: number, y: number) {
      P.tx = x;
      P.ty = y;
      P.lastMove = performance.now();
    }

    /* True while the pointer is over a text field — the flame steps aside
       there (no new embers, puffs, blades or tip) so the native I-beam is
       the only pointer and typed text stays readable. Existing particles
       fade out on their own; the flame resumes when the pointer leaves. */
    let overTextField = false;
    const onMouseOver = (e: MouseEvent) => {
      const t = e.target as HTMLElement | null;
      overTextField = !!t?.closest?.('input, textarea, [contenteditable="true"]');
    };

    /* ══════════════════════════════════════════
       PARTICLE POOLS
       ══════════════════════════════════════════ */

    /* — Embers — */
    const EMAX = 600;
    const embers: Ember[] = [];
    for (let i = 0; i < EMAX; i++) embers.push({ alive: false, x: 0, y: 0, vx: 0, vy: 0, age: 0, life: 0, sz: 0, hot: 0, sway: 0, phase: 0, grav: 0, deep: false });
    let eHead = 0;
    function spawnEmber(x: number, y: number, vx: number, vy: number, life: number, sz: number, hot: number, deep?: boolean) {
      const e = embers[eHead % EMAX];
      eHead++;
      e.alive = true;
      e.x = x;
      e.y = y;
      e.vx = vx;
      e.vy = vy;
      e.age = 0;
      e.life = life;
      e.sz = sz;
      e.hot = hot;
      e.sway = rand(0.4, 1.4);
      e.phase = rand(0, TAU);
      e.grav = rand(35, 85);
      e.deep = deep || false;
    }

    /* — Smoke wisps — */
    const SMAX = 300;
    const smoke: Smoke[] = [];
    for (let i = 0; i < SMAX; i++) smoke.push({ alive: false, x: 0, y: 0, vx: 0, vy: 0, age: 0, life: 0, r: 0, dark: false });
    let sHead = 0;
    function spawnSmoke(x: number, y: number, vx: number, vy: number, r: number, life: number, dark?: boolean) {
      const s = smoke[sHead % SMAX];
      sHead++;
      s.alive = true;
      s.x = x;
      s.y = y;
      s.vx = vx;
      s.vy = vy;
      s.age = 0;
      s.life = life;
      s.r = r;
      s.dark = dark || false;
    }

    /* — Flame puffs (flickering tongues of fire) — */
    const FMAX = 360;
    const flames: Flame[] = [];
    for (let i = 0; i < FMAX; i++) flames.push({ alive: false, x: 0, y: 0, vx: 0, vy: 0, age: 0, life: 0, r: 0, hot: 0, deep: false });
    let fHead = 0;
    function spawnFlame(x: number, y: number, vx: number, vy: number, r: number, life: number, hot: number, deep?: boolean) {
      const f = flames[fHead % FMAX];
      fHead++;
      f.alive = true;
      f.x = x;
      f.y = y;
      f.vx = vx;
      f.vy = vy;
      f.age = 0;
      f.life = life;
      f.r = r;
      f.hot = hot;
      f.deep = deep || false;
    }

    /* — Sparks — */
    const SPKMAX = 420;
    const sparks: Spark[] = [];
    for (let i = 0; i < SPKMAX; i++) sparks.push({ alive: false, px: 0, py: 0, x: 0, y: 0, vx: 0, vy: 0, age: 0, life: 0, bright: 0, deep: false });
    let spkHead = 0;
    function spawnSpark(x: number, y: number, vx: number, vy: number, life: number, bright: number, deep?: boolean) {
      const s = sparks[spkHead % SPKMAX];
      spkHead++;
      s.alive = true;
      s.x = x;
      s.y = y;
      s.px = x;
      s.py = y;
      s.vx = vx;
      s.vy = vy;
      s.age = 0;
      s.life = life;
      s.bright = bright;
      s.deep = deep || false;
    }

    /* — Flame blades (sword-slash streaks, Rengoku's signature) — */
    const BMAX = 150;
    const blades: Blade[] = [];
    for (let i = 0; i < BMAX; i++) blades.push({ alive: false, x: 0, y: 0, vx: 0, vy: 0, angle: 0, len: 0, width: 0, age: 0, life: 0, hot: 0, deep: false, spin: 0 });
    let bHead = 0;
    function spawnBlade(x: number, y: number, angle: number, speed: number, len: number, width: number, life: number, hot: number, deep?: boolean, spin?: number) {
      const b = blades[bHead % BMAX];
      bHead++;
      b.alive = true;
      b.x = x;
      b.y = y;
      b.vx = Math.cos(angle) * speed;
      b.vy = Math.sin(angle) * speed;
      b.angle = angle;
      b.len = len;
      b.width = width;
      b.age = 0;
      b.life = life;
      b.hot = hot;
      b.deep = deep || false;
      b.spin = spin || 0;
    }

    /* — Spinning fire rings (the circular flame-slash signature) — */
    const RMAX = 8;
    const fireRings: FireRing[] = [];
    function spawnFireRing(x: number, y: number, maxR: number, life: number, segs: number, rotSpeed: number, deep?: boolean) {
      fireRings.push({
        x, y, age: 0, life, maxR, segs,
        rotSpeed, baseAngle: rand(0, TAU), deep: deep || false,
      });
      if (fireRings.length > RMAX) fireRings.shift();
    }

    /* — Shockwaves & flashes — */
    const waves: Wave[] = [];
    const flashes: Flash[] = [];

    /* — Heat shimmer cells — */
    const HDMAX = 220;
    const hdCells: HDCell[] = [];
    for (let i = 0; i < HDMAX; i++) hdCells.push({ alive: false, x: 0, y: 0, str: 0, age: 0, life: 0 });
    let hdHead = 0;
    function spawnHD(x: number, y: number, str: number, life: number) {
      const h = hdCells[hdHead % HDMAX];
      hdHead++;
      h.alive = true;
      h.x = x;
      h.y = y;
      h.str = str;
      h.age = 0;
      h.life = life;
    }

    /* — Trail points — */
    const TMAX = 65;
    const trail: TrailPoint[] = [];
    function addTrail(x: number, y: number, t: number) {
      if (trail.length >= TMAX) trail.shift();
      trail.push({ x, y, t });
    }

    /* ══════════════════════════════════════════
       DRAW PRIMITIVES
       ══════════════════════════════════════════ */

    /* Flame blade — tapered curved sword-slash shape, hilt at origin, tip along +x */
    function drawBlade(cx: number, cy: number, len: number, width: number, angle: number, hot: number, deep: boolean, alpha: number) {
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(angle);
      ctx.beginPath();
      ctx.moveTo(0, -width * 0.5);
      ctx.quadraticCurveTo(len * 0.45, -width * 0.65, len * 0.92, -width * 0.06);
      ctx.quadraticCurveTo(len * 1.04, 0, len * 0.92, width * 0.06);
      ctx.quadraticCurveTo(len * 0.45, width * 0.65, 0, width * 0.5);
      ctx.closePath();
      const col = deep ? copperColor : flameColor;
      const g = ctx.createLinearGradient(0, 0, len, 0);
      g.addColorStop(0, col(0.18, alpha * 0.7));
      g.addColorStop(0.45, col(0.55, alpha * 0.92));
      g.addColorStop(0.78, col(0.82, alpha));
      g.addColorStop(1, col(0.98, alpha));
      ctx.fillStyle = g;
      ctx.fill();
      /* bright leading edge */
      ctx.lineWidth = Math.max(0.5, width * 0.1);
      ctx.strokeStyle = flameColor(1.0, alpha * 0.6);
      ctx.beginPath();
      ctx.moveTo(len * 0.4, -width * 0.5 * 0.55);
      ctx.lineTo(len * 0.96, 0);
      ctx.stroke();
      ctx.restore();
    }

    /* ── Flame Breathing Burst — Ultimate: Flame Tiger (circular flame slash) ── */
    function burst(x: number, y: number) {
      waves.push({ x, y, r: 0, maxR: rand(170, 260), age: 0, life: 620 });
      waves.push({ x, y, r: 0, maxR: rand(100, 150), age: 0, life: 460, delay: 70 });
      flashes.push({ x, y, r: 0, maxR: rand(260, 400), age: 0, life: 520 });

      /* spinning fire rings — the rotating circular flame slash */
      spawnFireRing(x, y, rand(220, 300), rand(900, 1250), 12, rand(3.2, 4.4), false);
      spawnFireRing(x, y, rand(120, 170), rand(700, 1000), 9, rand(-5.2, -3.8), true);

      /* radiating flame blades, staggered to read as a spinning sweep */
      const BLADES = 16;
      for (let i = 0; i < BLADES; i++) {
        const a = (i / BLADES) * TAU + rand(-0.08, 0.08);
        const spd = rand(160, 420);
        const isDeep = i % 3 === 0;
        spawnBlade(
          x, y, a, spd,
          rand(34, 62), rand(7, 13),
          rand(380, 720), rand(0.75, 1.0), isDeep,
          rand(1.5, 3.5) * (i % 2 === 0 ? 1 : -1),
        );
        spawnFlame(
          x, y,
          Math.cos(a) * spd * 0.45, Math.sin(a) * spd * 0.45,
          rand(22, 48), rand(340, 680), rand(0.6, 1.0), isDeep,
        );
        if (i % 2 === 0)
          spawnSmoke(
            x + rand(-8, 8), y + rand(-8, 8),
            Math.cos(a) * spd * 0.18, Math.sin(a) * spd * 0.18 - rand(25, 55),
            rand(20, 38), rand(550, 850), true,
          );
      }

      /* heavy sparks */
      for (let i = 0; i < 150; i++) {
        const a = rand(0, TAU), spd = rand(90, 540);
        spawnSpark(x, y, Math.cos(a) * spd, Math.sin(a) * spd, rand(300, 950), rand(0.7, 1.0), Math.random() < 0.3);
      }

      /* embers */
      for (let i = 0; i < 100; i++) {
        const a = rand(0, TAU) - Math.PI / 2, spd = rand(35, 220);
        spawnEmber(
          x, y, Math.cos(a) * spd, Math.sin(a) * spd - rand(40, 110),
          rand(500, 1300), rand(1.5, 3.6), rand(0.5, 1.0), Math.random() < 0.25,
        );
      }

      /* heat-wave distortion pulse */
      spawnHD(x, y, rand(13, 19), rand(750, 1150));
      for (let i = 0; i < 4; i++)
        spawnHD(x + rand(-20, 20), y + rand(-20, 20), rand(8, 13), rand(500, 850));
    }

    /* ══════════════════════════════════════════
       MAIN LOOP
       ══════════════════════════════════════════ */
    let last = performance.now();
    let ambE = 0, ambF = 0, ambHD = 0, ambB = 0;
    let raf = 0;

    function frame(now: number) {
      raf = requestAnimationFrame(frame);
      const dt = Math.min(now - last, 33);
      last = now;
      const dtS = dt * 0.001;

      /* Pointer tracking */
      P.px = P.x;
      P.py = P.y;
      const ease = 1 - Math.pow(0.001, dtS * 5);
      P.x = lerp(P.x, P.tx, ease);
      P.y = lerp(P.y, P.ty, ease);
      P.vx = (P.x - P.px) / Math.max(dtS, 0.001);
      P.vy = (P.y - P.py) / Math.max(dtS, 0.001);
      P.speed = Math.hypot(P.vx, P.vy);

      /* Trail */
      addTrail(P.x, P.y, now);
      while (trail.length && now - trail[0].t > 320) trail.shift();

      const idle = now - P.lastMove;
      const moving = idle < 120;
      const speedFactor = clamp(P.speed / 300, 0, 1);

      if (!overTextField) {
      /* ── Ambient ember emission ── */
      ambE -= dt;
      if (ambE <= 0) {
        ambE = moving ? rand(8, 20) : rand(25, 50);
        const n = moving ? randi(2, 5) : 1;
        for (let i = 0; i < n; i++) {
          const a = -Math.PI / 2 + rand(-0.8, 0.8);
          const spd = rand(20, 80) * (1 + speedFactor * 2);
          spawnEmber(
            P.x + rand(-5, 5), P.y + rand(-5, 5),
            Math.cos(a) * spd, Math.sin(a) * spd - rand(20, 50),
            rand(600, 1400), rand(1.2, 3.0), rand(0.3, 0.8), Math.random() < 0.18,
          );
        }
      }

      /* ── Ambient flowing flame puffs ── */
      ambF -= dt;
      if (ambF <= 0) {
        ambF = moving ? rand(12, 28) : rand(35, 70);
        const n = moving ? randi(2, 6) : randi(1, 3);
        for (let i = 0; i < n; i++) {
          const a = -Math.PI / 2 + rand(-1.0, 1.0);
          const spd = rand(15, 70) * (1 + speedFactor * 1.5);
          spawnFlame(
            P.x + rand(-6, 6), P.y + rand(-6, 6),
            Math.cos(a) * spd * 0.5, Math.sin(a) * spd - rand(10, 40),
            rand(10, 28) * (1 + speedFactor * 0.8),
            rand(180, 400), rand(0.4, 1.0), Math.random() < 0.15,
          );
        }
        if (Math.random() < (moving ? 0.4 : 0.1))
          spawnSmoke(
            P.x + rand(-8, 8), P.y - 10,
            rand(-15, 15), rand(-40, -15),
            rand(14, 26), rand(400, 700), false,
          );
      }

      /* ── Ambient sword-slash flame streaks on fast movement ── */
      ambB -= dt;
      if (ambB <= 0) {
        ambB = moving ? rand(70, 150) : rand(260, 520);
        if (moving && P.speed > 90) {
          const a = Math.atan2(P.vy, P.vx) + rand(-0.25, 0.25);
          spawnBlade(
            P.x, P.y, a, rand(20, 60) + speedFactor * 30,
            rand(16, 30) * (0.6 + speedFactor), rand(4, 7),
            rand(260, 520), rand(0.6, 0.95), Math.random() < 0.2,
            rand(-1, 1),
          );
        }
      }

      ambHD -= dt;
      if (ambHD <= 0) {
        ambHD = rand(80, 150);
        spawnHD(P.x + rand(-15, 15), P.y + rand(-15, 15), rand(3, 6), rand(200, 400));
      }

      /* ── Movement-triggered emission ── */
      if (moving && P.speed > 20) {
        const n = clamp((P.speed / 100) | 0, 1, 6);
        for (let i = 0; i < n; i++) {
          const t = Math.random();
          const sx = lerp(P.px, P.x, t), sy = lerp(P.py, P.y, t);
          const a = -Math.PI / 2 + rand(-1.1, 1.1);
          const spd = rand(30, 110) + speedFactor * 60;
          spawnFlame(
            sx + rand(-4, 4), sy + rand(-4, 4),
            P.vx * 0.1 + Math.cos(a) * spd * 0.4,
            -Math.abs(Math.sin(a) * spd) - rand(20, 55),
            rand(8, 22), rand(150, 350), rand(0.6, 1.0),
          );
          if (Math.random() < 0.5)
            spawnEmber(
              sx, sy,
              P.vx * 0.08 + rand(-40, 40), -rand(40, 130),
              rand(500, 1100), rand(1, 2.5), rand(0.5, 1.0),
            );
          if (P.speed > 150 && Math.random() < 0.22)
            spawnSpark(
              sx, sy,
              P.vx * 0.2 + rand(-80, 80), P.vy * 0.2 + rand(-80, 80),
              rand(200, 500), 0.8,
            );
          if (P.speed > 200 && Math.random() < 0.16) {
            const ba = Math.atan2(P.vy, P.vx) + rand(-0.3, 0.3);
            spawnBlade(
              sx, sy, ba, rand(60, 150),
              rand(20, 36), rand(5, 8),
              rand(220, 460), rand(0.7, 1.0), Math.random() < 0.2, rand(-1.5, 1.5),
            );
          }
        }
      }
      } // end if (!overTextField) — no new flame over text fields

      /* ═══════════ DRAW ═══════════ */
      ctx.clearRect(0, 0, W, H);
      ctx.globalCompositeOperation = 'lighter';

      /* ── Flashes — fiery white-gold bloom ── */
      for (let i = flashes.length - 1; i >= 0; i--) {
        const f = flashes[i];
        f.age += dt;
        if (f.age >= f.life) { flashes.splice(i, 1); continue; }
        const tp = f.age / f.life;
        const r = lerp(0, f.maxR, Math.pow(tp, 0.3));
        const a = (1 - tp) * (1 - tp) * 0.35;
        const g = ctx.createRadialGradient(f.x, f.y, 0, f.x, f.y, r);
        g.addColorStop(0, `rgba(255,250,225,${a})`);
        g.addColorStop(0.22, `rgba(255,170,40,${a * 0.82})`);
        g.addColorStop(0.55, `rgba(220,70,0,${a * 0.48})`);
        g.addColorStop(0.8, `rgba(80,15,0,${a * 0.22})`);
        g.addColorStop(1, 'rgba(0,0,0,0)');
        ctx.fillStyle = g;
        ctx.beginPath();
        ctx.arc(f.x, f.y, r, 0, TAU);
        ctx.fill();
      }

      /* ── Shockwaves — amber rings ── */
      for (let i = waves.length - 1; i >= 0; i--) {
        const w = waves[i];
        if (w.delay && w.delay > 0) { w.delay -= dt; continue; }
        w.age += dt;
        if (w.age >= w.life) { waves.splice(i, 1); continue; }
        const tp = w.age / w.life;
        const r = lerp(0, w.maxR, Math.pow(tp, 0.5));
        const a = (1 - tp) * (1 - tp) * 0.75;
        const lw = lerp(7, 0.4, tp);
        ctx.beginPath();
        ctx.arc(w.x, w.y, r, 0, TAU);
        ctx.lineWidth = lw;
        ctx.strokeStyle = `rgba(255,150,30,${a})`;
        ctx.stroke();
        ctx.lineWidth = lw * 3;
        ctx.strokeStyle = `rgba(180,50,0,${a * 0.32})`;
        ctx.stroke();
        if (tp < 0.42) {
          const r2 = lerp(0, w.maxR * 0.42, tp / 0.42);
          ctx.beginPath();
          ctx.arc(w.x, w.y, r2, 0, TAU);
          ctx.lineWidth = lw * 0.55;
          ctx.strokeStyle = `rgba(255,240,200,${a * 0.6})`;
          ctx.stroke();
        }
      }

      /* ── Spinning fire rings ── */
      for (let i = fireRings.length - 1; i >= 0; i--) {
        const r = fireRings[i];
        r.age += dt;
        if (r.age >= r.life) { fireRings.splice(i, 1); continue; }
        const tp = r.age / r.life;
        const radius = lerp(0, r.maxR, Math.pow(tp, 0.42));
        const ringAlpha = Math.sin(tp * Math.PI) * 0.85;
        r.baseAngle += r.rotSpeed * dtS;
        const col = r.deep ? copperColor : flameColor;

        /* thin connecting ring */
        ctx.beginPath();
        ctx.arc(r.x, r.y, radius, 0, TAU);
        ctx.lineWidth = lerp(2.4, 0.4, tp);
        ctx.strokeStyle = col(0.6, ringAlpha * 0.35);
        ctx.stroke();

        /* flame blades evenly spaced around the ring, rotating */
        for (let s = 0; s < r.segs; s++) {
          const segAngle = r.baseAngle + (s / r.segs) * TAU;
          const bx = r.x + Math.cos(segAngle) * radius;
          const by = r.y + Math.sin(segAngle) * radius;
          const tangent = segAngle + Math.PI / 2 * (r.rotSpeed > 0 ? 1 : -1);
          const segLen = lerp(8, 36, Math.sin(tp * Math.PI)) * (0.7 + 0.3 * Math.sin(s * 1.7 + tp * 6));
          drawBlade(bx, by, segLen, segLen * 0.4, tangent, r.deep ? 0.6 : 0.85, r.deep, ringAlpha);
        }
      }

      /* ── Smoke (drawn under flame) ── */
      ctx.globalCompositeOperation = 'source-over';
      for (let i = 0; i < SMAX; i++) {
        const s = smoke[i];
        if (!s.alive) continue;
        s.age += dt;
        if (s.age >= s.life) { s.alive = false; continue; }
        s.x += s.vx * dtS;
        s.y += s.vy * dtS;
        s.vy -= dtS * 8;
        s.vx += rand(-4, 4) * dtS;
        const tp = s.age / s.life;
        const r = s.r * (1 + tp * 1.2);
        const a = s.dark
          ? (1 - tp) * 0.18 * Math.sin(tp * Math.PI)
          : (1 - tp) * 0.1 * Math.sin(tp * Math.PI);
        const col = s.dark ? `rgba(14,4,2,${a})` : `rgba(70,25,5,${a})`;
        const g = ctx.createRadialGradient(s.x, s.y, 0, s.x, s.y, Math.max(1, r));
        g.addColorStop(0, col);
        g.addColorStop(1, 'rgba(0,0,0,0)');
        ctx.fillStyle = g;
        ctx.beginPath();
        ctx.arc(s.x, s.y, Math.max(1, r), 0, TAU);
        ctx.fill();
      }

      /* ── Flame puffs ── */
      ctx.globalCompositeOperation = 'lighter';
      for (let i = 0; i < FMAX; i++) {
        const f = flames[i];
        if (!f.alive) continue;
        f.age += dt;
        if (f.age >= f.life) { f.alive = false; continue; }
        f.x += f.vx * dtS;
        f.y += f.vy * dtS;
        f.vy -= dtS * 55;
        f.vx *= Math.pow(0.95, dtS * 60);
        f.vx += Math.sin(now * 0.007 + f.age * 0.01) * dtS * 40;
        const tp = f.age / f.life;
        const hotness = f.hot * (1 - tp);
        const r = f.r * (1 + tp * 0.3);
        const a = Math.sin(tp * Math.PI) * 0.7 * f.hot;
        const g = ctx.createRadialGradient(f.x, f.y, 0, f.x, f.y, Math.max(1, r));
        const col = f.deep ? copperColor : flameColor;
        g.addColorStop(0, col(hotness, a));
        g.addColorStop(0.45, col(hotness * 0.6, a * 0.7));
        g.addColorStop(0.8, col(hotness * 0.3, a * 0.3));
        g.addColorStop(1, 'rgba(0,0,0,0)');
        ctx.fillStyle = g;
        ctx.beginPath();
        ctx.arc(f.x, f.y, Math.max(1, r), 0, TAU);
        ctx.fill();
      }

      /* ── Flame blades (ambient + burst radiating) ── */
      for (let i = 0; i < BMAX; i++) {
        const b = blades[i];
        if (!b.alive) continue;
        b.age += dt;
        if (b.age >= b.life) { b.alive = false; continue; }
        b.x += b.vx * dtS;
        b.y += b.vy * dtS;
        b.vy -= dtS * 18;
        b.vx *= Math.pow(0.96, dtS * 60);
        b.angle += b.spin * dtS;
        const tp = b.age / b.life;
        const hotness = b.hot * (1 - tp);
        const len = b.len * (1 - tp * 0.25);
        const a = Math.sin(tp * Math.PI) * 0.85 * b.hot;
        if (a < 0.02) continue;
        drawBlade(b.x, b.y, len, b.width * (1 - tp * 0.3), b.angle, hotness, b.deep, a);
      }

      /* ── Trail — flowing flame ribbon ── */
      if (trail.length >= 3) {
        for (let i = 1; i < trail.length; i++) {
          const age = (now - trail[i].t) / 320;
          const alpha = clamp(1 - age, 0, 1);
          if (alpha < 0.01) continue;
          const w = lerp(2, 10, 1 - age);
          ctx.beginPath();
          ctx.moveTo(trail[i - 1].x, trail[i - 1].y);
          ctx.lineTo(trail[i].x, trail[i].y);
          ctx.lineWidth = w * 4;
          ctx.strokeStyle = `rgba(120,30,0,${alpha * 0.15})`;
          ctx.stroke();
          ctx.lineWidth = w * 2.5;
          ctx.strokeStyle = `rgba(225,70,0,${alpha * 0.32})`;
          ctx.stroke();
          ctx.lineWidth = w * 1.4;
          ctx.strokeStyle = `rgba(255,140,20,${alpha * 0.55})`;
          ctx.stroke();
          ctx.lineWidth = w * 0.8;
          ctx.strokeStyle = `rgba(255,200,80,${alpha * 0.72})`;
          ctx.stroke();
          ctx.lineWidth = Math.max(1, w * 0.42);
          ctx.strokeStyle = `rgba(255,250,220,${alpha * 0.9})`;
          ctx.stroke();
        }
      }

      /* ── Sparks ── */
      for (let i = 0; i < SPKMAX; i++) {
        const s = sparks[i];
        if (!s.alive) continue;
        s.age += dt;
        if (s.age >= s.life) { s.alive = false; continue; }
        s.px = s.x;
        s.py = s.y;
        s.x += s.vx * dtS;
        s.y += s.vy * dtS;
        s.vy += 180 * dtS;
        s.vx *= Math.pow(0.88, dtS * 60);
        const tp = s.age / s.life;
        const a = clamp((1 - tp) * (1 - tp) * s.bright * 1.2, 0, 1);
        const hotness = 1 - tp * 0.6;
        const tlen = Math.hypot(s.x - s.px, s.y - s.py);
        const slen = clamp(tlen, 2, 18);
        const ang = Math.atan2(s.y - s.py, s.x - s.px);

        ctx.setTransform(dpr, 0, 0, dpr, s.x, s.y);
        ctx.rotate(ang + Math.PI);
        ctx.beginPath();
        ctx.moveTo(0, 0);
        ctx.lineTo(slen, 0);
        const gc = ctx.createLinearGradient(0, 0, slen, 0);
        const col = s.deep ? copperColor : flameColor;
        gc.addColorStop(0, col(hotness, a));
        gc.addColorStop(1, col(hotness * 0.4, 0));
        ctx.strokeStyle = gc;
        ctx.lineWidth = clamp(2 - tp * 1.5, 0.5, 2);
        ctx.stroke();
        ctx.strokeStyle = col(hotness, a * 0.25);
        ctx.lineWidth = clamp(2 - tp * 1.5, 0.5, 2) * 2;
        ctx.stroke();
      }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      /* ── Embers ── */
      for (let i = 0; i < EMAX; i++) {
        const e = embers[i];
        if (!e.alive) continue;
        e.age += dt;
        if (e.age >= e.life) { e.alive = false; continue; }
        e.x += e.vx * dtS + Math.sin(now * 0.004 + e.phase) * e.sway * dtS;
        e.y += e.vy * dtS;
        e.vy += e.grav * dtS;
        e.vx *= Math.pow(0.97, dtS * 60);
        const tp = e.age / e.life;
        const hotness = e.hot * (1 - tp * 0.7);
        const a = (1 - tp) * (1 - tp) * 0.95;
        const r = e.sz * (1 - tp * 0.3);
        const col = e.deep ? copperColor : flameColor;

        ctx.fillStyle = col(hotness, a);
        ctx.beginPath();
        ctx.arc(e.x, e.y, Math.max(0.5, r), 0, TAU);
        ctx.fill();

        ctx.fillStyle = col(clamp(hotness, 0, 1), a * 0.3);
        ctx.beginPath();
        ctx.arc(e.x, e.y, Math.max(0.5, r * 2.2), 0, TAU);
        ctx.fill();
      }

      /* ── Cursor tip — Flame Breathing living flame core ── */
      // Hidden over text fields (see overTextField above) — the I-beam
      // is the only pointer there.
      if (!overTextField) {
        const flicker =
          0.88 +
          0.08 * Math.sin(now * 0.013) +
          0.06 * Math.sin(now * 0.031 + 1.3) +
          0.04 * Math.sin(now * 0.05 + 2.7);
        const jx = Math.sin(now * 0.022) * 1.2;
        const jy = Math.sin(now * 0.019 + 1.5) * 1.2;
        const cx = P.x + jx, cy = P.y + jy - 2 * flicker;

        /* far outer amber aura */
        const og = ctx.createRadialGradient(cx, cy, 0, cx, cy, 62 * flicker);
        og.addColorStop(0, 'rgba(255,120,20,0.22)');
        og.addColorStop(0.45, 'rgba(180,50,0,0.09)');
        og.addColorStop(1, 'rgba(0,0,0,0)');
        ctx.fillStyle = og;
        ctx.beginPath();
        ctx.arc(cx, cy, 62 * flicker, 0, TAU);
        ctx.fill();

        /* corona ring — golden haze at mid radius */
        const cg2 = ctx.createRadialGradient(cx, cy, 18 * flicker, cx, cy, 44 * flicker);
        cg2.addColorStop(0, 'rgba(0,0,0,0)');
        cg2.addColorStop(0.5, 'rgba(255,160,30,0.11)');
        cg2.addColorStop(1, 'rgba(0,0,0,0)');
        ctx.fillStyle = cg2;
        ctx.beginPath();
        ctx.arc(cx, cy, 44 * flicker, 0, TAU);
        ctx.fill();

        /* rising flame tongue shape */
        ctx.save();
        ctx.translate(cx, cy);
        const wobble = Math.sin(now * 0.012) * 0.12;
        ctx.rotate(wobble);
        ctx.beginPath();
        ctx.moveTo(0, 10 * flicker);
        ctx.quadraticCurveTo(9 * flicker, 2 * flicker, 4 * flicker, -12 * flicker);
        ctx.quadraticCurveTo(1 * flicker, -20 * flicker, 0, -30 * flicker);
        ctx.quadraticCurveTo(-1 * flicker, -20 * flicker, -4 * flicker, -12 * flicker);
        ctx.quadraticCurveTo(-9 * flicker, 2 * flicker, 0, 10 * flicker);
        ctx.closePath();
        const tongueG = ctx.createLinearGradient(0, 10 * flicker, 0, -30 * flicker);
        tongueG.addColorStop(0, 'rgba(200,40,0,0.85)');
        tongueG.addColorStop(0.4, 'rgba(255,120,10,0.9)');
        tongueG.addColorStop(0.72, 'rgba(255,200,60,0.92)');
        tongueG.addColorStop(1, 'rgba(255,250,225,0.96)');
        ctx.fillStyle = tongueG;
        ctx.fill();
        ctx.restore();

        /* mid flame bloom */
        const mg = ctx.createRadialGradient(cx, cy - 2, 0, cx, cy, 26 * flicker);
        mg.addColorStop(0, 'rgba(255,210,90,0.7)');
        mg.addColorStop(0.32, 'rgba(255,120,15,0.62)');
        mg.addColorStop(0.68, 'rgba(200,40,0,0.3)');
        mg.addColorStop(1, 'rgba(0,0,0,0)');
        ctx.fillStyle = mg;
        ctx.beginPath();
        ctx.arc(cx, cy - 2, 26 * flicker, 0, TAU);
        ctx.fill();

        /* inner white-hot core */
        const hg = ctx.createRadialGradient(cx, cy, 0, cx, cy, 8 * flicker);
        hg.addColorStop(0, 'rgba(255,253,240,1)');
        hg.addColorStop(0.32, 'rgba(255,200,90,0.95)');
        hg.addColorStop(0.68, 'rgba(255,110,10,0.55)');
        hg.addColorStop(1, 'rgba(120,10,0,0)');
        ctx.fillStyle = hg;
        ctx.beginPath();
        ctx.arc(cx, cy, 8 * flicker, 0, TAU);
        ctx.fill();

        /* orbiting micro flame-blade fragments */
        const orbitA = now * 0.0026;
        for (let k = 0; k < 2; k++) {
          const oa = orbitA + (k / 2) * TAU;
          const or = (15 + k * 4) * flicker;
          const ox = cx + Math.cos(oa) * or;
          const oy = cy + Math.sin(oa) * or;
          ctx.save();
          ctx.globalAlpha = 0.55 - k * 0.15;
          drawBlade(ox, oy, 7 * flicker, 2.6 * flicker, oa + Math.PI / 2, 0.85, k === 1, 0.8);
          ctx.globalAlpha = 1;
          ctx.restore();
        }

        /* tiny bright center point */
        ctx.fillStyle = `rgba(255,255,245,${flicker * 0.97})`;
        ctx.beginPath();
        ctx.arc(cx, cy, 2.1 * flicker, 0, TAU);
        ctx.fill();
      }

      ctx.globalCompositeOperation = 'source-over';

      /* ── Heat shimmer layer on HD canvas ── */
      hctx.clearRect(0, 0, W, H);
      for (let i = 0; i < HDMAX; i++) {
        const h = hdCells[i];
        if (!h.alive) continue;
        h.age += dt;
        if (h.age >= h.life) { h.alive = false; continue; }
        const tp = h.age / h.life;
        const r = h.str * 20 * (1 - tp * 0.4);
        const a = (1 - tp) * 0.11;
        const g = hctx.createRadialGradient(h.x, h.y, 0, h.x, h.y, r);
        g.addColorStop(0, `rgba(255,140,30,${a})`);
        g.addColorStop(0.5, `rgba(170,40,0,${a * 0.4})`);
        g.addColorStop(1, 'rgba(0,0,0,0)');
        hctx.fillStyle = g;
        hctx.beginPath();
        hctx.arc(h.x, h.y, r, 0, TAU);
        hctx.fill();
      }
    }

    /* ── Listeners ── */
    const onMouseMove = (e: MouseEvent) => setTarget(e.clientX, e.clientY);
    const onTouchMove = (e: TouchEvent) => {
      if (e.touches.length) setTarget(e.touches[0].clientX, e.touches[0].clientY);
    };
    const onMouseDown = (e: MouseEvent) => burst(e.clientX, e.clientY);
    const onTouchStart = (e: TouchEvent) => {
      if (e.touches.length) {
        setTarget(e.touches[0].clientX, e.touches[0].clientY);
        burst(P.tx, P.ty);
      }
    };
    window.addEventListener('resize', resize);
    window.addEventListener('mousemove', onMouseMove);
    window.addEventListener('mouseover', onMouseOver);
    window.addEventListener('touchmove', onTouchMove, { passive: true });
    window.addEventListener('mousedown', onMouseDown);
    window.addEventListener('touchstart', onTouchStart, { passive: true });

    raf = requestAnimationFrame(frame);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('resize', resize);
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('mouseover', onMouseOver);
      window.removeEventListener('touchmove', onTouchMove);
      window.removeEventListener('mousedown', onMouseDown);
      window.removeEventListener('touchstart', onTouchStart);
      document.body.classList.remove('flame-cursor-on');
    };
  }, [enabled]);

  if (!enabled) return null;

  return (
    <>
      <canvas id="flame-cursor-hd" ref={hdRef} aria-hidden="true" />
      <canvas id="flame-cursor-main" ref={mainRef} aria-hidden="true" />
    </>
  );
}
