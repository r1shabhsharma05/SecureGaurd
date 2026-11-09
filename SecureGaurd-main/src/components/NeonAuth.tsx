import React, { useEffect, useRef, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { apiUrl } from '../config/api';
import { trackEvent } from '../utils/analytics';
import TurnstileWidget, { isTurnstileEnabled } from './TurnstileWidget';
import './NeonAuth.css';

// Neon Lamp login / signup for SecureGuard — ported from LocalKart's
// NeonAuth (same lamp, cord, colours, sounds, particles, glass card).
// REAL wiring only: the form submits to SecureGuard's real auth —
// AuthContext login()/register() (POST /api/auth/login and
// /api/auth/register, HTTP-only refresh cookie + /me session restore).
// SecureGuard pieces that LocalKart did not have, all kept real:
//  - First + Last Name on signup (the backend requires both)
//  - Cloudflare Turnstile on signup when the site key is configured
//    (the widget renders nothing when it is not; the backend enforces
//    the token when its secret is set, so it cannot be skipped)
//  - Terms of Service agreement checkbox on signup (backend requires it)
//  - SSO buttons, only for providers the backend reports configured
//  - Forgot-password goes to AuthPage's forgot form (there is no
//    /forgot-password route in this app)
// Deliberately NOT ported from the demo:
//  - "Remember me" — sessions are HTTP-only cookies, there is no such flag
//  - fake "Signed In Successfully" overlay — real navigation happens instead
//  - lamp starts OFF in the demo (form hidden until you pull the cord).
//    Here it starts ON: hiding a real login form behind a hidden gesture
//    would block real logins. The cord still toggles it for fun.

const ANCHOR = { x: 245, y: 212 };
const REST = { x: 245, y: 300 };
const MAX_STRETCH = 120;
const TRIGGER_PULL = 32;

const COLOR_OPTIONS = [
  { id: 'amber', label: 'Amber (Warm)', dot: '#ffab3d' },
  { id: 'cyan', label: 'Cyan (Cyber)', dot: '#00f0ff' },
  { id: 'rose', label: 'Rose (Sunset)', dot: '#ff3385' },
  { id: 'mint', label: 'Mint (Emerald)', dot: '#00e676' },
  { id: 'moonlight', label: 'Moonlight (Cool White)', dot: '#d8e5ff' },
];

const PARTICLE_THEMES: Record<string, { fill: string; glow: string }> = {
  amber: { fill: '255, 205, 120', glow: '255, 185, 80' },
  cyan: { fill: '140, 245, 255', glow: '0, 240, 255' },
  rose: { fill: '255, 160, 200', glow: '255, 51, 133' },
  mint: { fill: '160, 255, 200', glow: '0, 230, 118' },
  moonlight: { fill: '220, 235, 255', glow: '200, 220, 255' },
};

interface NeonAuthProps {
  mode: 'login' | 'signup';
  oauthErrorText?: string;
  onModeChange: (mode: 'login' | 'signup') => void;
  onForgot: () => void;
}

export default function NeonAuth({ mode, oauthErrorText, onModeChange, onForgot }: NeonAuthProps) {
  const isRegister = mode === 'signup';
  const [lampOn, setLampOn] = useState(true);
  const [color, setColor] = useState('amber');
  const [soundOn, setSoundOn] = useState(true);
  const [showPassword, setShowPassword] = useState(false);

  // Form fields (real SecureGuard auth: first + last name on signup)
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [agreed, setAgreed] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // Turnstile token, tagged with the form mode that minted it: a token
  // minted for one mode must not leak into another (single-use, and the
  // widget remounts on mode change). Derived, not an effect.
  const [captcha, setCaptcha] = useState<{ mode: string; token: string } | null>(null);
  const captchaToken = captcha && captcha.mode === mode ? captcha.token : null;
  const [captchaKey, setCaptchaKey] = useState(0);
  const captchaEnabled = isTurnstileEnabled();

  // SSO providers configured on the server. The list comes from the
  // backend, so a button only ever renders for a provider that is
  // actually configured (no dead buttons). Empty list = no SSO section.
  const [ssoProviders, setSsoProviders] = useState<{ provider: string; label: string }[]>([]);

  const location = useLocation();
  const navigate = useNavigate();
  const { login, register, user } = useAuth();

  const lampOnRef = useRef(true);
  const colorRef = useRef('amber');
  const soundRef = useRef(true);
  const audioCtxRef = useRef<AudioContext | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const beadRef = useRef<SVGGElement>(null);
  const cordRef = useRef<SVGPathElement>(null);
  const shadeRef = useRef<SVGGElement>(null);
  const cardRef = useRef<HTMLDivElement>(null);
  const formStageRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const beadPos = useRef({ ...REST });
  const velRef = useRef({ x: 0, y: 0 });
  const twangRef = useRef({ amp: 0, start: 0 });
  const animRef = useRef({ raf: 0, spring: false, tx: REST.x, ty: REST.y });
  const dragRef = useRef<{ pointerId: number; moved: number } | null>(null);
  const simulatingRef = useRef(false);

  useEffect(() => { lampOnRef.current = lampOn; }, [lampOn]);
  useEffect(() => { colorRef.current = color; }, [color]);
  useEffect(() => { soundRef.current = soundOn; }, [soundOn]);

  // Clear messages when the tab changes (same as the old AuthPage).
  useEffect(() => { setError(''); setSuccess(''); }, [mode]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch(apiUrl('/api/auth/oauth/providers'));
        if (res.ok && !cancelled) {
          const data = await res.json();
          setSsoProviders(Array.isArray(data.providers) ? data.providers : []);
        }
      } catch { /* SSO stays hidden when the list cannot load */ }
    })();
    return () => { cancelled = true; };
  }, []);

  // Redirect after successful login based on onboarding status.
  // Honors a ?redirect= param (e.g. from an invite link) when it is a safe
  // same-origin path — protocol-relative or absolute URLs are never followed.
  useEffect(() => {
    if (user && success.includes('Login successful')) {
      const timer = setTimeout(() => {
        if (user.onboardingCompleted) {
          const redirect = new URLSearchParams(location.search).get('redirect');
          if (redirect && redirect.startsWith('/') && !redirect.startsWith('//')) {
            navigate(redirect);
          } else {
            navigate('/dashboard');
          }
        } else {
          navigate('/onboarding');
        }
      }, 800);
      return () => clearTimeout(timer);
    }
  }, [user, success, navigate, location.search]);

  // ---------- audio (generated tones, no assets) ----------
  const initAudio = () => {
    try {
      if (!audioCtxRef.current) {
        const AC = window.AudioContext
          || (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
        if (AC) audioCtxRef.current = new AC();
      }
      if (audioCtxRef.current && audioCtxRef.current.state === 'suspended') {
        audioCtxRef.current.resume();
      }
    } catch {
      // audio unavailable — silent mode
    }
  };

  const playPluck = (pullDist: number, turningOn: boolean) => {
    if (!soundRef.current) return;
    try {
      initAudio();
      const ctx = audioCtxRef.current;
      if (!ctx) return;
      const now = ctx.currentTime;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(480 + Math.min(260, pullDist * 3), now);
      osc.frequency.exponentialRampToValueAtTime(140, now + 0.12);
      gain.gain.setValueAtTime(0.4, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.14);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(now);
      osc.stop(now + 0.15);
      if (pullDist >= TRIGGER_PULL) {
        const snap = ctx.createOscillator();
        const snapGain = ctx.createGain();
        snap.type = 'sine';
        snap.frequency.setValueAtTime(turningOn ? 1800 : 1500, now + 0.02);
        snap.frequency.exponentialRampToValueAtTime(320, now + 0.06);
        snapGain.gain.setValueAtTime(0.35, now + 0.02);
        snapGain.gain.exponentialRampToValueAtTime(0.001, now + 0.065);
        snap.connect(snapGain);
        snapGain.connect(ctx.destination);
        snap.start(now + 0.02);
        snap.stop(now + 0.07);
        if (turningOn) {
          const hum = ctx.createOscillator();
          const humGain = ctx.createGain();
          hum.type = 'sine';
          hum.frequency.setValueAtTime(120, now + 0.05);
          humGain.gain.setValueAtTime(0.001, now);
          humGain.gain.linearRampToValueAtTime(0.06, now + 0.08);
          humGain.gain.exponentialRampToValueAtTime(0.001, now + 0.35);
          hum.connect(humGain);
          humGain.connect(ctx.destination);
          hum.start(now + 0.05);
          hum.stop(now + 0.38);
        }
      }
    } catch {
      // ignore audio errors
    }
  };

  const playColorSound = () => {
    if (!soundRef.current) return;
    try {
      initAudio();
      const ctx = audioCtxRef.current;
      if (!ctx) return;
      const now = ctx.currentTime;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(880, now);
      osc.frequency.exponentialRampToValueAtTime(1320, now + 0.05);
      gain.gain.setValueAtTime(0.12, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.06);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(now);
      osc.stop(now + 0.07);
    } catch {
      // ignore
    }
  };

  // ---------- elastic cord ----------
  const renderCord = (curX: number, curY: number) => {
    const cord = cordRef.current;
    if (!cord) return;
    let twangOffset = 0;
    const tw = twangRef.current;
    if (tw.amp > 0.05) {
      twangOffset = Math.sin((performance.now() - tw.start) * 0.05) * tw.amp;
    }
    const midX = (ANCHOR.x + curX) / 2 + twangOffset;
    const midY = (ANCHOR.y + curY) / 2;
    const stretchRatio = Math.max(1, (curY - ANCHOR.y) / (REST.y - ANCHOR.y));
    const strokeWidth = Math.max(1.6, 2.6 / Math.sqrt(stretchRatio));
    cord.setAttribute('d', `M ${ANCHOR.x} ${ANCHOR.y} Q ${midX} ${midY} ${curX} ${curY}`);
    cord.setAttribute('stroke-width', strokeWidth.toFixed(2));
  };

  const applyBead = () => {
    const bead = beadRef.current;
    if (!bead) return;
    const { x, y } = beadPos.current;
    bead.style.transform = `translate(${x}px, ${y}px)`;
    renderCord(x, y);
  };

  const ensureCordLoop = () => {
    if (animRef.current.raf) return;
    const step = () => {
      const a = animRef.current;
      if (a.spring) {
        const p = beadPos.current;
        const v = velRef.current;
        v.x += (a.tx - p.x) * 0.14;
        v.y += (a.ty - p.y) * 0.14;
        v.x *= 0.78;
        v.y *= 0.78;
        p.x += v.x;
        p.y += v.y;
        if (Math.abs(v.x) < 0.08 && Math.abs(v.y) < 0.08 && Math.abs(a.tx - p.x) < 0.4 && Math.abs(a.ty - p.y) < 0.4) {
          beadPos.current = { x: a.tx, y: a.ty };
          a.spring = false;
        }
      }
      twangRef.current.amp *= 0.93;
      applyBead();
      if (a.spring || Math.abs(twangRef.current.amp) > 0.05) {
        a.raf = requestAnimationFrame(step);
      } else {
        a.raf = 0;
        applyBead();
      }
    };
    animRef.current.raf = requestAnimationFrame(step);
  };

  const startSpring = (tx: number, ty: number) => {
    animRef.current.spring = true;
    animRef.current.tx = tx;
    animRef.current.ty = ty;
    ensureCordLoop();
  };

  const stopSpring = () => {
    animRef.current.spring = false;
    velRef.current = { x: 0, y: 0 };
  };

  const setLamp = (next: boolean) => {
    lampOnRef.current = next;
    setLampOn(next);
    if (cardRef.current) cardRef.current.style.transform = '';
  };

  const bounceShadeBack = () => {
    const shade = shadeRef.current;
    if (!shade) return;
    shade.style.transition = 'transform .7s cubic-bezier(.2,1.5,.3,1)';
    shade.style.transform = 'rotate(0deg)';
    setTimeout(() => {
      if (shadeRef.current) shadeRef.current.style.transition = '';
    }, 700);
  };

  const performSimulatedPull = () => {
    if (simulatingRef.current) return;
    simulatingRef.current = true;
    initAudio();
    const t0 = performance.now();
    const fromY = beadPos.current.y;
    const step = (now: number) => {
      const k = Math.min(1, (now - t0) / 220);
      const eased = k * k;
      beadPos.current = { x: REST.x, y: fromY + (REST.y + 50 - fromY) * eased };
      applyBead();
      if (shadeRef.current) shadeRef.current.style.transform = `rotate(${(1.8 * eased).toFixed(2)}deg)`;
      if (k < 1) {
        requestAnimationFrame(step);
        return;
      }
      const turningOn = !lampOnRef.current;
      setLamp(turningOn);
      playPluck(50, turningOn);
      twangRef.current = { amp: 15, start: performance.now() };
      bounceShadeBack();
      startSpring(REST.x, REST.y);
      setTimeout(() => { simulatingRef.current = false; }, 500);
    };
    requestAnimationFrame(step);
  };

  const toSvgPoint = (clientX: number, clientY: number) => {
    const svg = svgRef.current;
    if (!svg) return { x: REST.x, y: REST.y };
    const rect = svg.getBoundingClientRect();
    return {
      x: (clientX - rect.left) * (400 / rect.width),
      y: (clientY - rect.top) * (500 / rect.height),
    };
  };

  const onBeadPointerDown = (e: React.PointerEvent<SVGGElement>) => {
    e.preventDefault();
    initAudio();
    stopSpring();
    dragRef.current = { pointerId: e.pointerId, moved: 0 };
    e.currentTarget.setPointerCapture(e.pointerId);
  };

  const onBeadPointerMove = (e: React.PointerEvent<SVGGElement>) => {
    const drag = dragRef.current;
    if (!drag || e.pointerId !== drag.pointerId) return;
    const pt = toSvgPoint(e.clientX, e.clientY);
    const x = Math.max(REST.x - 45, Math.min(REST.x + 45, pt.x));
    const y = Math.max(REST.y, Math.min(REST.y + MAX_STRETCH, pt.y));
    drag.moved += Math.abs(e.movementX || 0) + Math.abs(e.movementY || 0);
    beadPos.current = { x, y };
    applyBead();
    const pullDist = y - REST.y;
    if (shadeRef.current) {
      shadeRef.current.style.transform = `rotate(${((pullDist / MAX_STRETCH) * 1.8).toFixed(2)}deg)`;
    }
  };

  const onBeadPointerUp = (e: React.PointerEvent<SVGGElement>) => {
    const drag = dragRef.current;
    if (!drag || e.pointerId !== drag.pointerId) return;
    dragRef.current = null;
    if (drag.moved < 6) {
      // a tap, not a drag — pull the cord for the user
      beadPos.current = { ...REST };
      applyBead();
      performSimulatedPull();
      return;
    }
    const pullDist = beadPos.current.y - REST.y;
    const triggered = pullDist >= TRIGGER_PULL;
    const turningOn = triggered ? !lampOnRef.current : lampOnRef.current;
    if (triggered) setLamp(turningOn);
    playPluck(pullDist, turningOn);
    twangRef.current = {
      amp: (beadPos.current.x - REST.x) * 0.4 + pullDist * 0.3,
      start: performance.now(),
    };
    bounceShadeBack();
    startSpring(REST.x, REST.y);
  };

  // ---------- dust particles ----------
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    let width = 0;
    let height = 0;
    let raf = 0;
    const resize = () => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };
    resize();
    window.addEventListener('resize', resize);

    class Particle {
      x = 0; y = 0; radius = 0; vx = 0; vy = 0;
      alpha = 0; pulseSpeed = 0; pulse = 0;
      constructor() { this.reset(); }
      reset() {
        this.x = Math.random() * width;
        this.y = Math.random() * height;
        this.radius = Math.random() * 2 + 0.6;
        this.vx = (Math.random() - 0.4) * 0.35;
        this.vy = -Math.random() * 0.4 - 0.15;
        this.alpha = Math.random() * 0.6 + 0.2;
        this.pulseSpeed = Math.random() * 0.03 + 0.01;
        this.pulse = Math.random() * Math.PI;
      }
      update() {
        this.x += this.vx;
        this.y += this.vy;
        this.pulse += this.pulseSpeed;
        if (this.y < 0) this.y = height;
        if (this.x < 0) this.x = width;
        if (this.x > width) this.x = 0;
      }
      draw() {
        const theme = PARTICLE_THEMES[colorRef.current] || PARTICLE_THEMES.amber;
        const currentAlpha = (Math.sin(this.pulse) * 0.3 + 0.7) * this.alpha;
        const factor = lampOnRef.current ? 1 : 0.08;
        ctx.save();
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${theme.fill}, ${currentAlpha * factor})`;
        if (lampOnRef.current) {
          ctx.shadowBlur = 7;
          ctx.shadowColor = `rgba(${theme.glow}, 0.5)`;
        }
        ctx.fill();
        ctx.restore();
      }
    }

    const particles = Array.from({ length: 60 }, () => new Particle());
    const render = () => {
      ctx.clearRect(0, 0, width, height);
      particles.forEach((p) => { p.update(); p.draw(); });
      raf = requestAnimationFrame(render);
    };
    render();
    renderCord(REST.x, REST.y);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('resize', resize);
    };
  }, []);

  // stop any spring when unmounting
  useEffect(() => () => {
    if (animRef.current.raf) cancelAnimationFrame(animRef.current.raf);
  }, []);

  // ---------- card tilt ----------
  const handleStageMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!lampOnRef.current) return;
    if (!window.matchMedia('(hover:hover) and (pointer:fine)').matches) return;
    const stage = formStageRef.current;
    const card = cardRef.current;
    if (!stage || !card) return;
    const rect = stage.getBoundingClientRect();
    const x = e.clientX - rect.left - rect.width / 2;
    const y = e.clientY - rect.top - rect.height / 2;
    card.style.transform = `perspective(900px) rotateX(${(-(y / rect.height) * 9).toFixed(2)}deg) rotateY(${((x / rect.width) * 9).toFixed(2)}deg)`;
  };

  const handleStageMouseLeave = () => {
    if (cardRef.current) cardRef.current.style.transform = '';
  };

  const changeColor = (id: string) => {
    if (id === colorRef.current) return;
    setColor(id);
    colorRef.current = id;
    playColorSound();
  };

  // ── Login / Register (real SecureGuard auth) ──────────────────────────
  const handleAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (isRegister && !agreed) {
      setError('You must agree to the Terms of Service to continue.');
      return;
    }

    if (isRegister && captchaEnabled && !captchaToken) {
      setError('Please complete the security check before continuing.');
      return;
    }

    setLoading(true);
    try {
      if (!isRegister) {
        await login(email, password);
        setSuccess('Login successful! Redirecting…');
        // After login, user state is updated — navigation happens in the
        // redirect effect above, based on updated user state.
      } else {
        await register(firstName, lastName, email, password, captchaToken ?? undefined);
        setSuccess('Account created! Redirecting to setup…');
        trackEvent('signup_completed');
        // New users always go to onboarding
        setTimeout(() => navigate('/onboarding'), 1000);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Something went wrong.');
      // The captcha token is single-use: mint a fresh one for the retry.
      setCaptcha(null);
      setCaptchaKey((k) => k + 1);
    } finally {
      setLoading(false);
    }
  };

  // ── Titles ────────────────────────────────────────────────────────────
  const titles = {
    login: { h: 'Welcome back', sub: 'Enter your details to access your dashboard.' },
    signup: { h: 'Create an account', sub: 'Start your 14-day free trial. No credit card required.' },
  };
  const { h, sub } = titles[mode];

  return (
    <div className="neon-auth" data-on={lampOn ? 'true' : 'false'} data-color={color}>
      <div className="ambient-glow" aria-hidden="true" />
      <canvas className="dust-canvas" ref={canvasRef} aria-hidden="true" />

      <Link className="neon-brand" to="/" aria-label="SecureGuard home">
        <span className="neon-brand-badge">S</span>
        <span>SecureGuard</span>
      </Link>

      <div className="quick-controls">
        <div className="color-palette" title="Choose lamp color">
          {COLOR_OPTIONS.map((opt) => (
            <button
              key={opt.id}
              type="button"
              className={`color-dot-btn${color === opt.id ? ' active' : ''}`}
              data-color={opt.id}
              style={{ '--dot-color': opt.dot } as React.CSSProperties}
              aria-label={`${opt.label} light`}
              title={opt.label}
              onClick={() => changeColor(opt.id)}
            />
          ))}
        </div>
        <button
          type="button"
          className="sound-toggle"
          title="Toggle sound"
          aria-label="Toggle sound"
          aria-pressed={soundOn}
          onClick={() => { setSoundOn((v) => !v); soundRef.current = !soundRef.current; if (!soundRef.current) initAudio(); }}
        >
          {soundOn ? (
            <svg className="sound-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5" />
              <path d="M15.54 8.46a5 5 0 0 1 0 7.07" />
              <path d="M19.07 4.93a10 10 0 0 1 0 14.14" />
            </svg>
          ) : (
            <svg className="sound-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5" />
              <line x1="23" y1="9" x2="17" y2="15" />
              <line x1="17" y1="9" x2="23" y2="15" />
            </svg>
          )}
        </button>
      </div>

      <main className="neon-scene">
        <div className="lamp-stage">
          <div className="lamp-wrapper">
            <svg className="lamp-svg" ref={svgRef} viewBox="0 0 400 500" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
              <defs>
                <linearGradient id="metalArm" x1="0" y1="0" x2="1" y2="0">
                  <stop offset="0%" stopColor="#3e434a" />
                  <stop offset="50%" stopColor="#7a828e" />
                  <stop offset="100%" stopColor="#24272c" />
                </linearGradient>
                <linearGradient id="brassJoint" x1="0" y1="0" x2="1" y2="1">
                  <stop offset="0%" stopColor="#ffe299" />
                  <stop offset="45%" stopColor="#c99738" />
                  <stop offset="85%" stopColor="#805915" />
                  <stop offset="100%" stopColor="#f5d38a" />
                </linearGradient>
                <linearGradient id="shadeExterior" x1="0" y1="0" x2="1" y2="1">
                  <stop offset="0%" stopColor="#343840" />
                  <stop offset="40%" stopColor="#21252a" />
                  <stop offset="100%" stopColor="#121417" />
                </linearGradient>
                <linearGradient id="shadeHighlight" x1="0" y1="0" x2="1" y2="0">
                  <stop offset="0%" stopColor="#ffffff" stopOpacity="0" />
                  <stop offset="42%" stopColor="#ffffff" stopOpacity="0.16" />
                  <stop offset="72%" stopColor="#ffffff" stopOpacity="0.025" />
                  <stop offset="100%" stopColor="#ffffff" stopOpacity="0" />
                </linearGradient>
                <linearGradient id="shadeRim" x1="0" y1="0" x2="1" y2="0">
                  <stop offset="0%" stopColor="#ffd584" />
                  <stop offset="50%" stopColor="#e2ab46" />
                  <stop offset="100%" stopColor="#996a1a" />
                </linearGradient>
                <radialGradient id="reflectorOff" cx="50%" cy="40%" r="70%">
                  <stop offset="0%" stopColor="#2c3036" />
                  <stop offset="55%" stopColor="#1a1d22" />
                  <stop offset="100%" stopColor="#0e1012" />
                </radialGradient>
                <radialGradient id="reflectorOn" cx="50%" cy="40%" r="70%">
                  <stop offset="0%" stopColor="#ffffff" stopOpacity="0.95" />
                  <stop offset="35%" stopColor="var(--lamp-glow, #ffe194)" stopOpacity="0.85" />
                  <stop offset="70%" stopColor="var(--lamp-accent, #ffab3d)" stopOpacity="0.6" />
                  <stop offset="100%" stopColor="#2a2015" stopOpacity="0.85" />
                </radialGradient>
                <linearGradient id="volumetricBeam" x1="0%" y1="0%" x2="90%" y2="70%">
                  <stop offset="0%" stopColor="var(--beam-start, rgba(255, 220, 130, 0.45))" />
                  <stop offset="25%" stopColor="var(--beam-mid, rgba(255, 195, 90, 0.22))" />
                  <stop offset="65%" stopColor="var(--beam-far, rgba(255, 175, 60, 0.08))" />
                  <stop offset="100%" stopColor="rgba(0, 0, 0, 0)" />
                </linearGradient>
                <filter id="bulbGlowFilter" x="-60%" y="-60%" width="220%" height="220%">
                  <feGaussianBlur in="SourceGraphic" stdDeviation="5" result="blur1" />
                  <feGaussianBlur in="SourceGraphic" stdDeviation="14" result="blur2" />
                  <feMerge>
                    <feMergeNode in="blur2" />
                    <feMergeNode in="blur1" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>
                <filter id="beamSoftFilter" x="-10%" y="-10%" width="120%" height="120%">
                  <feGaussianBlur stdDeviation="8" />
                </filter>
              </defs>

              <ellipse className="desk-shadow" cx="190" cy="460" rx="90" ry="16" fill="rgba(0, 0, 0, 0.55)" />

              <g className="light-beam-group">
                <polygon className="svg-light-beam" points="182,185 308,225 820,480 340,510" fill="url(#volumetricBeam)" filter="url(#beamSoftFilter)" />
              </g>

              <g className="lamp-base-group">
                <ellipse cx="190" cy="445" rx="72" ry="14" fill="#15171a" />
                <ellipse cx="190" cy="443" rx="70" ry="12" fill="url(#metalArm)" />
                <ellipse cx="190" cy="441" rx="66" ry="10" fill="#1c1f24" />
                <ellipse cx="190" cy="439" rx="60" ry="7" fill="none" stroke="#8e949f" strokeOpacity=".22" strokeWidth=".8" />
                <circle cx="190" cy="439" r="15" fill="url(#brassJoint)" />
                <circle cx="190" cy="439" r="7" fill="#15171a" />
                <circle cx="190" cy="439" r="3.2" fill="#747b86" />
              </g>

              <g className="lamp-arm-lower">
                <line x1="186" y1="439" x2="156" y2="295" stroke="url(#metalArm)" strokeWidth="4.5" strokeLinecap="round" />
                <line x1="194" y1="439" x2="164" y2="295" stroke="url(#metalArm)" strokeWidth="4.5" strokeLinecap="round" />
                <path d="M 188 420 Q 175 360 163 305" stroke="#606670" strokeWidth="2" strokeDasharray="3,3" fill="none" opacity="0.6" />
              </g>

              <g className="lamp-elbow-joint">
                <circle cx="160" cy="295" r="13" fill="url(#brassJoint)" />
                <circle cx="160" cy="295" r="6" fill="#1c1f24" />
                <circle cx="160" cy="295" r="3.3" fill="#858b94" />
                <line x1="155" y1="295" x2="165" y2="295" stroke="url(#brassJoint)" strokeWidth="2" />
              </g>

              <g className="lamp-arm-upper">
                <line x1="160" y1="295" x2="215" y2="175" stroke="url(#metalArm)" strokeWidth="5" strokeLinecap="round" />
                <path d="M 190 439 Q 168 360 160 295 Q 190 230 215 175" stroke="#101114" strokeWidth="3" fill="none" strokeLinecap="round" />
              </g>

              <g className="lamp-neck">
                <circle cx="215" cy="175" r="11" fill="url(#brassJoint)" />
                <rect x="209" y="162" width="16" height="15" rx="3" fill="url(#metalArm)" transform="rotate(25, 217, 169)" />
              </g>

              <g className="lamp-shade-assembly" id="shadeAssembly" ref={shadeRef}>
                <path className="lamp-shade-body" d="M 182.3 184.6 C 188 135, 220 112, 248 115 C 275 118, 298 155, 307.7 225.4 A 66 22 18 0 1 182.3 184.6 Z" fill="url(#shadeExterior)" stroke="#16181b" strokeWidth="1.8" />
                <path className="shade-enamel-highlight" d="M 187 181 C 193 139, 221 119, 247 120 C 267 122, 286 144, 297 178 C 271 163, 224 153, 187 181 Z" fill="url(#shadeHighlight)" />
                <path d="M 204 148 C 216 125, 235 119, 251 122" fill="none" stroke="#aeb5c2" strokeOpacity=".17" strokeWidth="1.2" strokeLinecap="round" />
                <ellipse className="shade-reflector-off" cx="245" cy="205" rx="66" ry="22" transform="rotate(18, 245, 205)" fill="url(#reflectorOff)" />
                <ellipse className="shade-reflector-on" cx="245" cy="205" rx="66" ry="22" transform="rotate(18, 245, 205)" fill="url(#reflectorOn)" />
                <ellipse className="reflector-detail" cx="245" cy="205" rx="49" ry="14" transform="rotate(18, 245, 205)" fill="none" stroke="#fff3ce" strokeOpacity=".16" strokeWidth=".8" />
                <ellipse cx="245" cy="205" rx="66" ry="22" transform="rotate(18, 245, 205)" fill="none" stroke="rgba(255, 213, 132, 0.25)" strokeWidth="1" />
                <path className="shade-rim-trim" d="M 182.3 184.6 A 66 22 18 0 0 307.7 225.4" stroke="url(#shadeRim)" strokeWidth="4" fill="none" strokeLinecap="round" />
                <g className="bulb-unit" id="bulbUnit">
                  <ellipse className="bulb-glass" cx="245" cy="195" rx="14" ry="17" transform="rotate(18, 245, 195)" fill="rgba(255, 255, 255, 0.08)" stroke="rgba(255, 255, 255, 0.25)" strokeWidth="1" />
                  <path d="M 239 190 Q 242 181 247 183" fill="none" stroke="#fff" strokeOpacity=".55" strokeWidth="1.2" strokeLinecap="round" />
                  <path className="bulb-filament" d="M 241 189 Q 245 183 249 189" stroke="#555" strokeWidth="1.8" fill="none" />
                  <circle className="bulb-glow-core" cx="245" cy="188" r="11" fill="var(--lamp-glow, #ffe194)" filter="url(#bulbGlowFilter)" opacity="0" />
                </g>
                <g className="cord-socket-grommet">
                  <rect x="242" y="206" width="6" height="6" rx="1.5" fill="url(#brassJoint)" stroke="#68420e" strokeWidth="0.8" />
                  <circle cx="245" cy="212" r="3" fill="#ffe299" stroke="#7a5513" strokeWidth="0.8" />
                  <circle cx="245" cy="212" r="1.3" fill="#181105" />
                </g>
              </g>

              <g className="pull-cord-system">
                <path className="elastic-cord-path" ref={cordRef} d="M 245 212 L 245 300" stroke="#e8bb54" strokeWidth="2.6" strokeLinecap="round" />
                <g
                  className="cord-bead-group"
                  ref={beadRef}
                  style={{ transform: 'translate(245px, 300px)' }}
                  onPointerDown={onBeadPointerDown}
                  onPointerMove={onBeadPointerMove}
                  onPointerUp={onBeadPointerUp}
                  onPointerCancel={onBeadPointerUp}
                >
                  <circle className="bead-aura" cx="0" cy="0" r="16" fill="var(--lamp-accent)" opacity="0" />
                  <path className="bead-shape" d="M -4 -8 L 4 -8 L 7 6 C 7 10, -7 10, -7 6 Z" fill="url(#brassJoint)" stroke="#7a5513" strokeWidth="0.8" />
                  <ellipse cx="2" cy="0" rx="2" ry="4" fill="#fff" opacity="0.5" />
                  <circle className="cord-hit-area" cx="0" cy="0" r="32" fill="transparent" />
                </g>
              </g>
            </svg>

            <div className="cord-tooltip">
              <span>Pull string to turn {lampOn ? 'off' : 'on'}</span>
              <div className="tooltip-arrow" />
            </div>
          </div>
        </div>

        <div className="form-stage" ref={formStageRef} onMouseMove={handleStageMouseMove} onMouseLeave={handleStageMouseLeave}>
          <div className="login-card" ref={cardRef}>
            <div className="card-header">
              <h1 className="card-title">{h}</h1>
              <p className="card-subtitle">{sub}</p>
            </div>

            <div className="auth-tabs" data-active={isRegister ? 'register' : 'signin'}>
              <button type="button" className={`auth-tab${!isRegister ? ' active' : ''}`} onClick={() => { if (isRegister) onModeChange('login'); }}>Sign In</button>
              <button type="button" className={`auth-tab${isRegister ? ' active' : ''}`} onClick={() => { if (!isRegister) onModeChange('signup'); }}>Sign Up</button>
              <div className="tab-slider" />
            </div>

            {error && <p className="neon-form-message" role="alert">{error}</p>}
            {success && <p className="neon-form-message neon-form-message--success" role="status">{success}</p>}
            {!error && oauthErrorText && <p className="neon-form-message" role="alert">{oauthErrorText}</p>}

            <form className="auth-form" onSubmit={handleAuthSubmit} autoComplete="off">
              {isRegister && (
                <div className="neon-form-row">
                  <div className="form-group">
                    <label htmlFor="neonFirstName">First Name</label>
                    <div className="input-wrapper">
                      <svg className="field-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                        <circle cx="12" cy="7" r="4" />
                      </svg>
                      <input type="text" id="neonFirstName" name="firstName" autoComplete="given-name" value={firstName}
                        onChange={(e) => setFirstName(e.target.value)} placeholder="Jane" required />
                    </div>
                  </div>

                  <div className="form-group">
                    <label htmlFor="neonLastName">Last Name</label>
                    <div className="input-wrapper">
                      <svg className="field-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                        <circle cx="12" cy="7" r="4" />
                      </svg>
                      <input type="text" id="neonLastName" name="lastName" autoComplete="family-name" value={lastName}
                        onChange={(e) => setLastName(e.target.value)} placeholder="Doe" required />
                    </div>
                  </div>
                </div>
              )}

              <div className="form-group">
                <label htmlFor="neonEmail">Work Email</label>
                <div className="input-wrapper">
                  <svg className="field-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <rect x="2" y="4" width="20" height="16" rx="2" />
                    <path d="m22 7-10 6L2 7" />
                  </svg>
                  <input type="email" id="neonEmail" name="email" autoComplete="email" value={email}
                    onChange={(e) => setEmail(e.target.value)} placeholder="jane@company.com" required />
                </div>
              </div>

              <div className="form-group">
                <div className="label-row">
                  <label htmlFor="neonPassword">Password</label>
                  {!isRegister && (
                    <button type="button" className="forgot-link" onClick={onForgot}>
                      Forgot password?
                    </button>
                  )}
                </div>
                <div className="input-wrapper">
                  <svg className="field-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                  </svg>
                  <input
                    type={showPassword ? 'text' : 'password'}
                    id="neonPassword"
                    name="password"
                    autoComplete={isRegister ? 'new-password' : 'current-password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder={isRegister ? 'Min 8 characters' : '••••••••'}
                    minLength={8}
                    required
                  />
                  <button
                    type="button"
                    className="eye-toggle"
                    onClick={() => setShowPassword((v) => !v)}
                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                    aria-pressed={showPassword}
                    tabIndex={-1}
                  >
                    {showPassword ? (
                      <svg className="eye-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M9.88 9.88a3 3 0 1 0 4.24 4.24" />
                        <path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68" />
                        <path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.59 9.59 0 0 0 5.39-1.61" />
                        <line x1="2" y1="2" x2="22" y2="22" />
                      </svg>
                    ) : (
                      <svg className="eye-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                        <circle cx="12" cy="12" r="3" />
                      </svg>
                    )}
                  </button>
                </div>
                {isRegister && (
                  <small className="field-hint">
                    At least 8 characters.
                  </small>
                )}
              </div>

              {isRegister && (
                <>
                  <div className="neon-captcha">
                    <TurnstileWidget
                      key={`captcha-${mode}-${captchaKey}`}
                      onVerify={(token) => setCaptcha({ mode, token })}
                      onExpire={() => setCaptcha(null)}
                      onError={() => setCaptcha(null)}
                    />
                  </div>
                  <div className="neon-terms" onClick={() => setAgreed(!agreed)}>
                    <div className={`neon-terms-box${agreed ? ' checked' : ''}`}>
                      {agreed && (
                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3.5">
                          <polyline points="20 6 9 17 4 12" />
                        </svg>
                      )}
                    </div>
                    <span className="neon-terms-label">
                      I agree to the{' '}
                      <Link to="/terms" target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()}>Terms of Service</Link>
                      {' & '}
                      <Link to="/privacy" target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()}>Privacy Policy</Link>
                    </span>
                  </div>
                </>
              )}

              <button type="submit" className="submit-btn" disabled={loading}>
                <span className="btn-glow-layer" />
                {loading ? (
                  <span className="btn-content">
                    <span className="btn-spinner" />
                    <span className="btn-text">Please wait…</span>
                  </span>
                ) : (
                  <span className="btn-content">
                    <span className="btn-text">{isRegister ? 'Start Free Trial' : 'Sign In'}</span>
                    <svg className="btn-arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                      <line x1="5" y1="12" x2="19" y2="12" />
                      <polyline points="12 5 19 12 12 19" />
                    </svg>
                  </span>
                )}
              </button>
            </form>

            {ssoProviders.length > 0 && (
              <div className="neon-sso">
                <div className="neon-sso-divider"><span>or continue with</span></div>
                <div className="neon-sso-buttons">
                  {ssoProviders.map((p) => (
                    <a key={p.provider} className="neon-sso-btn" href={apiUrl(`/api/auth/oauth/${p.provider}`)}>
                      Continue with {p.label}
                    </a>
                  ))}
                </div>
              </div>
            )}

            <Link className="neon-back-link" to="/">← Back to home</Link>
          </div>
        </div>
      </main>
    </div>
  );
}
