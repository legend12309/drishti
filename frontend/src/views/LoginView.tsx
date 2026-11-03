import React, { useState, useEffect, useRef, useCallback } from 'react';
import { OperatorProfile } from '../types';

interface LoginViewProps {
  onLoginSuccess: (operator: OperatorProfile, token: string) => void;
  showToast?: (type: 'success' | 'warning' | 'error' | 'info', title: string, detail?: string) => void;
}

export const LoginView: React.FC<LoginViewProps> = ({ onLoginSuccess, showToast }) => {
  // Input & Mode States
  const [tokenInput, setTokenInput] = useState('ED25519-948A-AUTH-BIO-09');
  const [mode, setMode] = useState<'passive' | 'active'>('passive');
  const [isAuthenticating, setIsAuthenticating] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const [flashOpacity, setFlashOpacity] = useState(0);

  // Live Telemetry States
  const [depth, setDepth] = useState('54.0 cm');
  const [pupilDil, setPupilDil] = useState('4.80mm');
  const [irisScan, setIrisScan] = useState('99.5%');
  const [telemetryCycle, setTelemetryCycle] = useState('0.47ms');
  const [gazeVector, setGazeVector] = useState('[-0.38, -0.24]');
  const [scanMode, setScanMode] = useState<'IDLE_SCAN' | 'HIGH_FREQ_ACQUISITION'>('IDLE_SCAN');
  const [biolockStatus, setBiolockStatus] = useState('ENGAGED');

  // Stages & Diagnostic Progress Bar States
  const [stages, setStages] = useState({
    step1: true,
    step2: true,
    step3: true,
    step4: false,
  });
  const [bootProgress, setBootProgress] = useState(78.4);
  const [bootDiagLabel, setBootDiagLabel] = useState('CIPHER_SUITE: CHACHA20-POLY1305 // NEURAL_TAP: SYNCED');
  const [engineBadge, setEngineBadge] = useState({
    text: 'DEFCON-1: [RECON_ACTIVE]',
    className: 'text-[9px] px-1.5 py-0.5 bg-[#E62E25]/20 text-[#EF4444] border border-[#E62E25]/50 font-bold',
  });
  const [buttonText, setButtonText] = useState('[ EXECUTE COCKPIT LOGIN ⌘↵ ]');
  const [authStatus, setAuthStatus] = useState<{
    custom: boolean;
    text: string;
    className: string;
  }>({
    custom: false,
    text: '',
    className: '',
  });

  // Color Morphing State: 0.0 = Red Eye (Visible Circular Eye), 1.0 = Blue Eye (Circular Eye)
  const [eyeColorProgress, setEyeColorProgress] = useState(0);

  // DOM Refs
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const arenaRef = useRef<HTMLDivElement | null>(null);
  const eyelidTopRef = useRef<HTMLDivElement | null>(null);
  const eyelidBottomRef = useRef<HTMLDivElement | null>(null);
  const animFrameRef = useRef<number | null>(null);
  const typingTimeoutRef = useRef<any>(null);
  const rebootTimersRef = useRef<any[]>([]);
  const authTimersRef = useRef<any[]>([]);
  const morphAnimRef = useRef<number | null>(null);

  // Eye Physics Parameters (Unified 280x280 Cyber-Portal Geometry)
  const SIZE = 280;
  const CENTER = SIZE / 2; // 140
  const IRIS_RADIUS = 68;

  const physicsRef = useRef({
    mouseX: typeof window !== 'undefined' ? window.innerWidth / 2 : 700,
    mouseY: typeof window !== 'undefined' ? window.innerHeight / 2 : 400,
    currentEyeX: 0,
    currentEyeY: 0,
    targetEyeX: 0,
    targetEyeY: 0,
    saccadeX: 0,
    saccadeY: 0,
    currentPupilR: 21,
    targetPupilR: 21,
    colorMorph: 0, // 0 = Red Eye, 1 = Blue Eye
  });

  // Vascular Seeds for Sclera
  const vesselSeedsRef = useRef<Array<{
    points: Array<{ x: number; y: number }>;
    width: number;
    alpha: number;
  }>>([]);

  // Iris Fibers (interpolated between Red Design and Blue Design)
  const irisFibersRef = useRef<Array<{
    angle: number;
    innerRel: number;
    outerRel: number;
    width: number;
    redCol: [number, number, number, number];
    blueCol: [number, number, number, number];
  }>>([]);

  // Precompute realistic organic micro-vessels
  const generateVessels = useCallback(() => {
    const vessels: typeof vesselSeedsRef.current = [];
    const branches = 18;

    for (let i = 0; i < branches; i++) {
      const angle = (i / branches) * Math.PI * 2 + (Math.random() * 0.2 - 0.1);
      const startDist = SIZE * 0.49;
      const endDist = SIZE * 0.24 + Math.random() * 15;
      const points: Array<{ x: number; y: number }> = [];
      let r = startDist;
      let a = angle;

      while (r > endDist) {
        points.push({
          x: CENTER + Math.cos(a) * r,
          y: CENTER + Math.sin(a) * r,
        });
        r -= 6 + Math.random() * 4;
        a += (Math.random() - 0.5) * 0.18;
      }

      vessels.push({
        points,
        width: 0.5 + Math.random() * 0.6,
        alpha: 0.25 + Math.random() * 0.35,
      });
    }

    vesselSeedsRef.current = vessels;
  }, [CENTER, SIZE]);

  // Precompute 400 iris fibers with dual color definitions (Red <-> Blue)
  const generateIrisFibers = useCallback(() => {
    const fibers: typeof irisFibersRef.current = [];
    const FIBER_COUNT = 400;

    for (let i = 0; i < FIBER_COUNT; i++) {
      const angle = (i / FIBER_COUNT) * Math.PI * 2 + (Math.random() * 0.015);
      const innerRel = 0.22 + Math.random() * 0.08;
      const outerRel = 0.97 - Math.random() * 0.04;
      const width = 0.6 + Math.random() * 0.8;

      // Red Tone (Design 1: Glowing Scarlet / White Filaments / Crimson)
      const redChoice = Math.random();
      let redCol: [number, number, number, number];
      if (redChoice > 0.72) {
        redCol = [255, 255, 255, 0.75 + Math.random() * 0.25]; // Stark white filament rays
      } else if (redChoice > 0.45) {
        redCol = [239, 68, 68, 0.65 + Math.random() * 0.3];   // Vivid scarlet
      } else if (redChoice > 0.22) {
        redCol = [220, 38, 38, 0.55 + Math.random() * 0.35];  // Glowing crimson
      } else if (redChoice > 0.08) {
        redCol = [254, 205, 211, 0.5 + Math.random() * 0.35]; // Pale rose-white
      } else {
        redCol = [185, 28, 28, 0.5 + Math.random() * 0.3];   // Blood ruby
      }

      // Blue Tone (Design 2: Electric Cyan / Rich Cobalt / Ice Blue / Violet)
      const blueChoice = Math.random();
      let blueCol: [number, number, number, number];
      if (blueChoice > 0.65) {
        blueCol = [56, 189, 248, 0.65 + Math.random() * 0.3];  // Bright cyan/electric blue
      } else if (blueChoice > 0.3) {
        blueCol = [37, 99, 235, 0.6 + Math.random() * 0.35];   // Rich cobalt
      } else if (blueChoice > 0.12) {
        blueCol = [147, 197, 253, 0.5 + Math.random() * 0.35]; // Ice blue highlight
      } else {
        blueCol = [216, 180, 254, 0.4 + Math.random() * 0.3];  // Subtle ethereal violet
      }

      fibers.push({
        angle,
        innerRel,
        outerRel,
        width,
        redCol,
        blueCol,
      });
    }

    irisFibersRef.current = fibers;
  }, []);

  // Blinking reflex for circular portal eyelids
  const triggerBlink = useCallback((duration = 140) => {
    const top = eyelidTopRef.current;
    const bottom = eyelidBottomRef.current;
    if (!top || !bottom) return;

    top.style.transform = 'translateY(0%)';
    bottom.style.transform = 'translateY(0%)';

    setTimeout(() => {
      top.style.transform = 'translateY(-100%)';
      bottom.style.transform = 'translateY(100%)';
    }, duration);
  }, []);

  // Smooth color morph animation from Red to Blue (or vice-versa)
  const animateEyeColor = useCallback((from: number, to: number, duration = 1400) => {
    if (morphAnimRef.current) cancelAnimationFrame(morphAnimRef.current);
    const startTime = performance.now();

    const step = (now: number) => {
      const elapsed = now - startTime;
      const progress = Math.min(1, elapsed / duration);
      // Smooth cubic ease-in-out
      const eased = progress < 0.5
        ? 4 * progress * progress * progress
        : 1 - Math.pow(-2 * progress + 2, 3) / 2;

      const current = from + (to - from) * eased;
      physicsRef.current.colorMorph = current;
      setEyeColorProgress(current);

      if (progress < 1) {
        morphAnimRef.current = requestAnimationFrame(step);
      }
    };

    morphAnimRef.current = requestAnimationFrame(step);
  }, []);

  // Main canvas animation and loop setup
  useEffect(() => {
    generateVessels();
    generateIrisFibers();

    const handleMouseMove = (e: MouseEvent) => {
      physicsRef.current.mouseX = e.clientX;
      physicsRef.current.mouseY = e.clientY;
    };
    window.addEventListener('mousemove', handleMouseMove);

    // Blinking schedule: 2.8s to 7.0s
    let blinkTimer: any;
    const scheduleNextBlink = () => {
      const nextBlink = 2800 + Math.random() * 4200;
      blinkTimer = setTimeout(() => {
        triggerBlink(130 + Math.random() * 30);
        scheduleNextBlink();
      }, nextBlink);
    };
    scheduleNextBlink();

    // Natural micro-saccades
    let saccadeTimer: any;
    let saccadeResetTimer: any;
    const scheduleNextSaccade = () => {
      const delay = 1000 + Math.random() * 2400;
      saccadeTimer = setTimeout(() => {
        physicsRef.current.saccadeX = (Math.random() - 0.5) * 5.5;
        physicsRef.current.saccadeY = (Math.random() - 0.5) * 4.2;
        saccadeResetTimer = setTimeout(() => {
          physicsRef.current.saccadeX = 0;
          physicsRef.current.saccadeY = 0;
        }, 100);
        scheduleNextSaccade();
      }, delay);
    };
    scheduleNextSaccade();

    // Live Jitter Metrics Interval (440ms)
    const jitterInterval = setInterval(() => {
      const base = 53.8 + (Math.random() * 0.6 - 0.3);
      setDepth(`${base.toFixed(1)} cm`);
      const mm = (3.4 + (physicsRef.current.currentPupilR / 21) * 1.4 + (Math.random() * 0.08)).toFixed(2);
      setPupilDil(`${mm}mm`);
      const scan = (99.3 + (Math.random() * 0.4)).toFixed(1);
      setIrisScan(`${scan}%`);
      setTelemetryCycle(`${(0.44 + (Math.random() * 0.12)).toFixed(2)}ms`);
    }, 440);

    // Master Render Routine
    const renderEye = () => {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      if (!ctx) return;

      const p = physicsRef.current;
      const t = p.colorMorph; // 0.0 = Red Eye, 1.0 = Blue Eye

      // 1. Calculate gaze offset relative to center viewport
      const arena = arenaRef.current;
      if (arena) {
        const rect = arena.getBoundingClientRect();
        const ax = rect.left + rect.width / 2;
        const ay = rect.top + rect.height / 2;
        const maxDisplacement = 34;

        const normX = Math.max(-1, Math.min(1, (p.mouseX - ax) / (window.innerWidth / 2)));
        const normY = Math.max(-1, Math.min(1, (p.mouseY - ay) / (window.innerHeight / 2)));

        p.targetEyeX = normX * maxDisplacement;
        p.targetEyeY = normY * maxDisplacement;

        const dist = Math.sqrt(p.targetEyeX * p.targetEyeX + p.targetEyeY * p.targetEyeY);
        if (dist > maxDisplacement) {
          p.targetEyeX = (p.targetEyeX / dist) * maxDisplacement;
          p.targetEyeY = (p.targetEyeY / dist) * maxDisplacement;
        }
      }

      p.currentEyeX += (p.targetEyeX + p.saccadeX - p.currentEyeX) * 0.12;
      p.currentEyeY += (p.targetEyeY + p.saccadeY - p.currentEyeY) * 0.12;
      p.currentPupilR += (p.targetPupilR - p.currentPupilR) * 0.08;

      ctx.clearRect(0, 0, SIZE, SIZE);

      ctx.save();
      ctx.beginPath();
      ctx.arc(CENTER, CENTER, CENTER - 2, 0, Math.PI * 2);
      ctx.clip();

      // --- STEP 1: SCLERA (Pale Ivory with 3D Depth) ---
      const scleraGrad = ctx.createRadialGradient(CENTER, CENTER, 20, CENTER, CENTER, CENTER);
      scleraGrad.addColorStop(0, '#fdfbf7');
      scleraGrad.addColorStop(0.55, '#f5efe6');
      scleraGrad.addColorStop(0.8, '#e7ddd0');
      scleraGrad.addColorStop(0.95, '#b9aa9b');
      scleraGrad.addColorStop(1.0, '#5f5446');
      ctx.fillStyle = scleraGrad;
      ctx.fillRect(0, 0, SIZE, SIZE);

      // Vascular corner flushes (Red tone shifts smoothly to softer vascular tone)
      const flushAlphaL = 0.45 - t * 0.12;
      const flushAlphaR = 0.42 - t * 0.10;

      const flushLeft = ctx.createRadialGradient(16, CENTER, 4, 30, CENTER, 85);
      flushLeft.addColorStop(0, `rgba(239, 68, 68, ${flushAlphaL})`);
      flushLeft.addColorStop(0.65, `rgba(220, 38, 38, ${flushAlphaL * 0.35})`);
      flushLeft.addColorStop(1, 'transparent');
      ctx.fillStyle = flushLeft;
      ctx.fillRect(0, 0, SIZE, SIZE);

      const flushRight = ctx.createRadialGradient(SIZE - 16, CENTER, 4, SIZE - 30, CENTER, 85);
      flushRight.addColorStop(0, `rgba(239, 68, 68, ${flushAlphaR})`);
      flushRight.addColorStop(0.65, `rgba(220, 38, 38, ${flushAlphaR * 0.35})`);
      flushRight.addColorStop(1, 'transparent');
      ctx.fillStyle = flushRight;
      ctx.fillRect(0, 0, SIZE, SIZE);

      // Capillary veins (blended from vivid crimson to subtle organic ruby)
      const veinR = Math.round(220 - t * 35);
      const veinG = Math.round(38 + t * 7);
      const veinB = Math.round(38 + t * 7);

      vesselSeedsRef.current.forEach((v) => {
        if (v.points.length < 2) return;
        ctx.beginPath();
        ctx.moveTo(v.points[0].x, v.points[0].y);
        for (let i = 1; i < v.points.length; i++) {
          ctx.lineTo(v.points[i].x, v.points[i].y);
        }
        ctx.strokeStyle = `rgba(${veinR}, ${veinG}, ${veinB}, ${v.alpha})`;
        ctx.lineWidth = v.width;
        ctx.lineCap = 'round';
        ctx.lineJoin = 'round';
        ctx.stroke();
      });

      // --- STEP 2: IRIS & CORNEA (Dynamic Color Morph: Red -> Blue) ---
      const irisX = CENTER + p.currentEyeX;
      const irisY = CENTER + p.currentEyeY;

      // Interpolate Iris Radial Base Gradient
      const irisGrad = ctx.createRadialGradient(irisX, irisY, p.currentPupilR * 0.7, irisX, irisY, IRIS_RADIUS);

      // Helper function to interpolate RGB stops
      const lerpRGB = (r1: number, g1: number, b1: number, r2: number, g2: number, b2: number) => {
        const r = Math.round(r1 + (r2 - r1) * t);
        const g = Math.round(g1 + (g2 - g1) * t);
        const b = Math.round(b1 + (b2 - b1) * t);
        return `rgb(${r}, ${g}, ${b})`;
      };

      // Stop 0: [28, 3, 3] (#1c0303) -> [2, 11, 24] (#020b18)
      irisGrad.addColorStop(0, lerpRGB(28, 3, 3, 2, 11, 24));
      // Stop 0.2: [91, 6, 6] (#5b0606) -> [3, 35, 77] (#03234d)
      irisGrad.addColorStop(0.2, lerpRGB(91, 6, 6, 3, 35, 77));
      // Stop 0.5: [153, 27, 27] (#991b1b) -> [12, 74, 138] (#0c4a8a)
      irisGrad.addColorStop(0.5, lerpRGB(153, 27, 27, 12, 74, 138));
      // Stop 0.78: [220, 38, 38] (#dc2626) -> [24, 107, 181] (#186bb5)
      irisGrad.addColorStop(0.78, lerpRGB(220, 38, 38, 24, 107, 181));
      // Stop 0.92: [239, 68, 68] (#ef4444) -> [14, 61, 105] (#0e3d69)
      irisGrad.addColorStop(0.92, lerpRGB(239, 68, 68, 14, 61, 105));
      // Stop 1.0: [21, 2, 2] (#150202) -> [2, 6, 15] (#02060f)
      irisGrad.addColorStop(1.0, lerpRGB(21, 2, 2, 2, 6, 15));

      ctx.fillStyle = irisGrad;
      ctx.beginPath();
      ctx.arc(irisX, irisY, IRIS_RADIUS, 0, Math.PI * 2);
      ctx.fill();

      // Dark Prominent Limbal Ring
      const limbalR = Math.round(34 - t * 32);
      const limbalG = Math.round(4 + t * 2);
      const limbalB = Math.round(4 + t * 13);
      ctx.strokeStyle = `rgb(${limbalR}, ${limbalG}, ${limbalB})`;
      ctx.lineWidth = 3.5;
      ctx.stroke();

      // Iris Radial Striations / Fibers
      irisFibersRef.current.forEach((f) => {
        const inR = p.currentPupilR + (IRIS_RADIUS - p.currentPupilR) * f.innerRel;
        const outR = p.currentPupilR + (IRIS_RADIUS - p.currentPupilR) * f.outerRel;
        const x1 = irisX + Math.cos(f.angle) * inR;
        const y1 = irisY + Math.sin(f.angle) * inR;
        const x2 = irisX + Math.cos(f.angle) * outR;
        const y2 = irisY + Math.sin(f.angle) * outR;

        // Interpolate fiber color between Red design and Blue design
        const fr = Math.round(f.redCol[0] + (f.blueCol[0] - f.redCol[0]) * t);
        const fg = Math.round(f.redCol[1] + (f.blueCol[1] - f.redCol[1]) * t);
        const fb = Math.round(f.redCol[2] + (f.blueCol[2] - f.redCol[2]) * t);
        const fa = (f.redCol[3] + (f.blueCol[3] - f.redCol[3]) * t).toFixed(3);

        ctx.beginPath();
        ctx.moveTo(x1, y1);
        ctx.lineTo(x2, y2);
        ctx.strokeStyle = `rgba(${fr}, ${fg}, ${fb}, ${fa})`;
        ctx.lineWidth = f.width;
        ctx.stroke();
      });

      // Collarette Crypt Ring (Morphs from Pure White/Silver to Electric Cyan Glow)
      ctx.beginPath();
      const collaretteR = p.currentPupilR + (IRIS_RADIUS - p.currentPupilR) * (0.42 + t * 0.03);
      const wobbleFreq = 18 - t * 2;
      const wobbleAmp = 2.0 - t * 0.2;

      for (let a = 0; a <= Math.PI * 2; a += 0.08) {
        const wobble = Math.sin(a * wobbleFreq) * wobbleAmp;
        const cr = collaretteR + wobble;
        const cx = irisX + Math.cos(a) * cr;
        const cy = irisY + Math.sin(a) * cr;
        if (a === 0) ctx.moveTo(cx, cy);
        else ctx.lineTo(cx, cy);
      }
      ctx.closePath();

      const colR = Math.round(255 - t * 199);
      const colG = Math.round(255 - t * 66);
      const colB = Math.round(255 - t * 7);
      const colA = (0.75 - t * 0.3).toFixed(2);
      ctx.strokeStyle = `rgba(${colR}, ${colG}, ${colB}, ${colA})`;
      ctx.lineWidth = 1.4 - t * 0.2;
      ctx.stroke();

      // --- STEP 3: PUPIL ---
      ctx.fillStyle = '#010204';
      ctx.beginPath();
      ctx.arc(irisX, irisY, p.currentPupilR, 0, Math.PI * 2);
      ctx.fill();

      // Sphincter Muscle Ring (Ruby glow -> Ocean blue glow)
      const pupilRing = ctx.createRadialGradient(
        irisX,
        irisY,
        p.currentPupilR * 0.78,
        irisX,
        irisY,
        p.currentPupilR * (1.3 - t * 0.05)
      );
      pupilRing.addColorStop(0, 'rgba(0, 0, 0, 0.98)');
      const sphR = Math.round(153 - t * 150);
      const sphG = Math.round(27 + t * 8);
      const sphB = Math.round(27 + t * 50);
      pupilRing.addColorStop(0.55, `rgba(${sphR}, ${sphG}, ${sphB}, 0.40)`);
      pupilRing.addColorStop(1, 'transparent');
      ctx.fillStyle = pupilRing;
      ctx.beginPath();
      ctx.arc(irisX, irisY, p.currentPupilR * 1.3, 0, Math.PI * 2);
      ctx.fill();

      // --- STEP 4: CORNEAL SPECULAR HIGHLIGHTS (Studio Glints) ---
      // Primary glossy cornea glint (top-left)
      const glint1X = irisX - IRIS_RADIUS * 0.32;
      const glint1Y = irisY - IRIS_RADIUS * 0.34;
      ctx.save();
      ctx.translate(glint1X, glint1Y);
      ctx.rotate(-0.35);
      ctx.fillStyle = '#ffffff';

      const shadowR = Math.round(255 - t * 199);
      const shadowG = Math.round(255 - t * 66);
      const shadowB = Math.round(255 - t * 7);
      ctx.shadowColor = `rgba(${shadowR}, ${shadowG}, ${shadowB}, 0.8)`;
      ctx.shadowBlur = 6;
      ctx.beginPath();
      ctx.ellipse(0, 0, 8.0 - t * 0.5, 4.8 - t * 0.6, 0, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();

      // Secondary pinpoint catchlight
      ctx.fillStyle = '#ffffff';
      ctx.shadowColor = `rgba(${shadowR}, ${shadowG}, ${shadowB}, 0.9)`;
      ctx.shadowBlur = 4;
      ctx.beginPath();
      ctx.arc(irisX - IRIS_RADIUS * 0.18, irisY - IRIS_RADIUS * 0.16, 2.8 - t * 0.3, 0, Math.PI * 2);
      ctx.fill();

      // Sharp white micro-sparkle (fades subtly into blue reflex)
      if (t < 0.8) {
        ctx.fillStyle = `rgba(255, 255, 255, ${0.95 * (1 - t)})`;
        ctx.beginPath();
        ctx.arc(irisX - IRIS_RADIUS * 0.08, irisY - IRIS_RADIUS * 0.4, 1.4, 0, Math.PI * 2);
        ctx.fill();
      }

      // Ambient bounce reflex on bottom-right edge
      ctx.save();
      ctx.translate(irisX + IRIS_RADIUS * 0.38, irisY + IRIS_RADIUS * 0.36);
      ctx.rotate(0.5);
      const bounceR = Math.round(255 - t * 199);
      const bounceG = Math.round(240 - t * 51);
      const bounceB = Math.round(240 + t * 8);
      ctx.fillStyle = `rgba(${bounceR}, ${bounceG}, ${bounceB}, 0.40)`;
      ctx.shadowColor = 'transparent';
      ctx.shadowBlur = 0;
      ctx.beginPath();
      ctx.ellipse(0, 0, 5.2 - t * 0.4, 2.8 - t * 0.4, 0, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();

      ctx.restore(); // end clip

      // Update Gaze Vector readout smoothly
      const vx = (p.currentEyeX / 34).toFixed(2);
      const vy = (p.currentEyeY / 34).toFixed(2);
      const sx = Number(vx) >= 0 ? '+' : '';
      const sy = Number(vy) >= 0 ? '+' : '';
      setGazeVector(`[${sx}${vx}, ${sy}${vy}]`);

      animFrameRef.current = requestAnimationFrame(renderEye);
    };

    animFrameRef.current = requestAnimationFrame(renderEye);

    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      if (blinkTimer) clearTimeout(blinkTimer);
      if (saccadeTimer) clearTimeout(saccadeTimer);
      if (saccadeResetTimer) clearTimeout(saccadeResetTimer);
      clearInterval(jitterInterval);
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
      if (morphAnimRef.current) cancelAnimationFrame(morphAnimRef.current);
    };
  }, [CENTER, IRIS_RADIUS, SIZE, generateIrisFibers, generateVessels, triggerBlink]);

  // Key input typing reactive behavior
  const handleKeyInput = (val: string) => {
    setTokenInput(val);
    setScanMode('HIGH_FREQ_ACQUISITION');
    physicsRef.current.targetPupilR = 14;
    physicsRef.current.saccadeX = (Math.random() - 0.5) * 5.5;
    physicsRef.current.saccadeY = (Math.random() - 0.5) * 4.5;

    if (typingTimeoutRef.current) clearTimeout(typingTimeoutRef.current);
    typingTimeoutRef.current = setTimeout(() => {
      setScanMode('IDLE_SCAN');
      physicsRef.current.targetPupilR = 21;
    }, 750);
  };

  const appendFlag = (flag: string) => {
    if (!tokenInput.includes(flag)) {
      const next = `${tokenInput.trim()} ${flag}`;
      handleKeyInput(next);
    }
  };

  const handleInputFocus = (isFocused: boolean) => {
    if (isFocused) {
      setAuthStatus({
        custom: true,
        text: 'CLINICAL_INTERCEPT_ACTIVE // ESCALATING_PRIVILEGES // INGESTING_BIOMETRIC_SEED',
        className: 'text-center text-[9px] tracking-[0.14em] text-[#EF4444] bg-[#E62E25]/15 border border-[#E62E25]/40 font-bold py-0.5 min-h-[14px]',
      });
      triggerBlink(90);
    } else {
      setAuthStatus({
        custom: true,
        text: 'AWAITING_BIOMETRIC_TOKEN_VALIDATION // AUTH_CHALLENGE_ID: 981-FC7',
        className: 'text-center text-[9px] tracking-[0.14em] text-[#94A3B8] bg-[#070B14] border border-[#1E293B] py-0.5 min-h-[14px]',
      });
    }
  };

  const handleSetMode = (newMode: 'passive' | 'active') => {
    setMode(newMode);
    if (newMode === 'passive') {
      setBiolockStatus('ENGAGED');
      physicsRef.current.targetPupilR = 21;
    } else {
      setBiolockStatus('INTRUSION_ALERT');
      physicsRef.current.targetPupilR = 28;
      triggerBlink(110);
    }
  };

  // Tactical Reboot Sequence (resets back to Red Eye scanning baseline)
  const rebootSequence = () => {
    rebootTimersRef.current.forEach(clearTimeout);
    rebootTimersRef.current = [];

    // Smoothly transition back to Red Eye (0.0)
    animateEyeColor(physicsRef.current.colorMorph, 0.0, 800);
    setIsSuccess(false);

    triggerBlink(160);
    generateVessels();
    setBootProgress(10);
    setEngineBadge({
      text: 'COLD_REBOOT_TRIGGERED',
      className: 'text-[9px] px-1.5 py-0.5 bg-[#E62E25]/25 text-[#EF4444] border border-[#E62E25]/60 font-bold',
    });
    setBootDiagLabel('PURGING CRYPTOGRAPHIC SENSORS & FLUSHING BUFFER...');
    setButtonText('[ EXECUTE COCKPIT LOGIN ⌘↵ ]');
    setAuthStatus({
      custom: true,
      text: 'SYS_REBOOT_TRIGGERED // RETESTING OPTO-ELECTRONIC MATRIX',
      className: 'text-center text-[9px] tracking-[0.14em] text-[#EF4444] bg-[#E62E25]/15 border border-[#E62E25]/40 font-bold py-0.5 min-h-[14px]',
    });

    setStages({ step1: false, step2: false, step3: false, step4: false });

    const t1 = setTimeout(() => {
      setBootProgress(35);
      setStages((prev) => ({ ...prev, step1: true }));
      setBootDiagLabel('STAGE 01 ATTESTATION CONFIRMED: AES-256-GCM READY...');
    }, 400);

    const t2 = setTimeout(() => {
      setBootProgress(60);
      setStages((prev) => ({ ...prev, step2: true }));
      setBootDiagLabel('STAGE 02 OPTIC NEURAL SENSORS CALIBRATED: SACCADE SYNCED...');
    }, 900);

    const t3 = setTimeout(() => {
      setBootProgress(78.4);
      setStages({ step1: true, step2: true, step3: true, step4: false });
      setEngineBadge({
        text: 'DEFCON-1: [RECON_ACTIVE]',
        className: 'text-[9px] px-1.5 py-0.5 bg-[#E62E25]/20 text-[#EF4444] border border-[#E62E25]/50 font-bold',
      });
      setBootDiagLabel('CIPHER_SUITE: CHACHA20-POLY1305 // NEURAL_TAP: SYNCED');
      setAuthStatus({
        custom: true,
        text: 'CALIBRATION COMPLETE // SUBJECT LOCKED // READY FOR JWT INGESTION',
        className: 'text-center text-[9px] tracking-[0.14em] text-[#94A3B8] bg-[#070B14] border border-[#1E293B] py-0.5 min-h-[14px]',
      });
      triggerBlink(120);
    }, 1500);

    rebootTimersRef.current.push(t1, t2, t3);
  };

  // Auth Protocol Execution: Morphs from Red Eye into Blue Eye upon credential submission
  const simulateAuth = useCallback(() => {
    if (isAuthenticating) return;
    setIsAuthenticating(true);

    // Camera flash overlay
    setFlashOpacity(0.45);
    setTimeout(() => setFlashOpacity(0), 180);

    setButtonText('[ LOCKING IRIS & DERIVING ENCLAVE KEY... ]');
    physicsRef.current.targetPupilR = 14;
    triggerBlink(110);

    setAuthStatus({
      custom: true,
      text: 'ACTIVE_PERSON_SCAN: PHOTOMETRIC STEREO MATCHING // EXTRACTING 4096-BIT RETINA HASH...',
      className: 'text-center text-[9px] tracking-[0.14em] text-[#EF4444] font-bold min-h-[14px]',
    });
    setBootProgress(90);

    // Begin dynamic eye color transformation: morph from Red (0.0) -> Blue (1.0)
    animateEyeColor(0.0, 1.0, 1600);

    const t1 = setTimeout(() => {
      setAuthStatus({
        custom: true,
        text: 'DERIVING ZERO-KNOWLEDGE PROOF FROM SUBJECT BIOMETRIC ENTROPY...',
        className: 'text-center text-[9px] tracking-[0.14em] text-[#FCA5A5] font-mono min-h-[14px]',
      });
      physicsRef.current.targetPupilR = 19;
    }, 900);

    const t2 = setTimeout(() => {
      setBootProgress(100);
      setStages({ step1: true, step2: true, step3: true, step4: true });
      setEngineBadge({
        text: 'DEFCON-5: [ONLINE_ROOT]',
        className: 'text-[9px] px-1.5 py-0.5 bg-[#10B981]/20 text-[#10B981] border border-[#10B981]/50 font-bold',
      });
      setAuthStatus({
        custom: true,
        text: 'ACCESS GRANTED // BIOMETRIC SIGNATURE VERIFIED // ROOT SHELL UNLOCKED',
        className: 'text-center text-[9px] tracking-[0.15em] text-[#10B981] bg-[#10B981]/15 py-0.5 border border-[#10B981]/40 font-bold min-h-[14px]',
      });
      setButtonText('[ COCKPIT RUNNING // SESSION ESTABLISHED ✓ ]');
      setIsSuccess(true);
      physicsRef.current.targetPupilR = 22;
      triggerBlink(150);

      const op: OperatorProfile = {
        id: 'local-operator-dev',
        name: 'Alex Morgan',
        email: 'root@drishti.sec',
        role: 'SecOps Lead // Principal Cyber Analyst',
        clearance: 'LEVEL 5 // TOP SECRET // AIR-GAP ENCLAVE',
        organization: 'DRISHTI Cyber Intelligence Division',
        avatar_text: 'AM',
        permissions: [
          'FULL_PASSIVE_RECON',
          'ATTACK_GRAPH_PATHFINDING',
          'PROMPT_GUARD_EVAL',
          'STIX_BUNDLE_EXPORT',
          'WAL_AUDIT_INSPECTION',
          'SCOPE_CHALLENGE_ISSUER',
        ],
        client_ip: '127.0.0.1 (Local Cockpit)',
        mfa_enabled: true,
        hardware_key_bound: true,
        default_scope: mode === 'passive' ? 'FULL_PASSIVE' : 'FULL_ACTIVE',
        token_fingerprint: 'SHA256: 8f43...27aa4',
      };

      localStorage.setItem('drishti_auth_token', tokenInput.trim() || 'ED25519-948A-AUTH-BIO-09');
      localStorage.setItem('drishti_operator', JSON.stringify(op));

      if (showToast) {
        showToast('success', 'Biometric Signature Verified', 'Access granted to DRISHTI Cockpit.');
      }

      setTimeout(() => {
        setIsAuthenticating(false);
        onLoginSuccess(op, tokenInput.trim());
      }, 700);
    }, 2100);

    authTimersRef.current.push(t1, t2);
  }, [animateEyeColor, isAuthenticating, mode, onLoginSuccess, showToast, tokenInput, triggerBlink]);

  // Keyboard shortcut Ctrl+Enter or Cmd+Enter
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
        simulateAuth();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [simulateAuth]);

  // Computed styles based on morph progress (t: 0 = Red, 1 = Blue/Emerald)
  const t = eyeColorProgress;
  const bracketBorderColor = t > 0.5 ? '#10B981' : '#E62E25';
  const portalGlow = t > 0.5
    ? 'shadow-[0_0_40px_rgba(37,99,235,0.45),inset_0_0_45px_rgba(0,0,0,0.95)] border-blue-500/60'
    : 'shadow-[0_0_40px_rgba(230,46,37,0.45),inset_0_0_45px_rgba(0,0,0,0.95)] border-rose-500/60';

  return (
    <div className="relative flex flex-col justify-between w-screen h-screen bg-[#030407] text-[#E5E7EB] select-none overflow-hidden p-3 md:p-4 font-mono">
      {/* CRT Scanlines, Analog Noise, Vignette Screen Layer */}
      <div className="crt-overlay"></div>

      {/* Fullscreen flash overlay on biometric capture / unlock */}
      <div
        className="pointer-events-none fixed inset-0 z-50 bg-[#E62E25] transition-opacity duration-300"
        id="flashOverlay"
        style={{ opacity: flashOpacity }}
      ></div>

      {/* Local Scoped Keyframe & Technical Styles */}
      <style>{`
        /* CRT Vignette, Scanlines & Phosphor Bloom */
        .crt-overlay {
          position: fixed;
          inset: 0;
          pointer-events: none;
          z-index: 45;
          background: radial-gradient(circle at center, transparent 60%, rgba(0, 0, 0, 0.72) 98%),
                      linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.35) 50%),
                      linear-gradient(90deg, rgba(255, 0, 0, 0.015), rgba(0, 255, 0, 0.005), rgba(0, 255, 0, 0.015));
          background-size: 100% 100%, 100% 3px, 6px 100%;
          box-shadow: inset 0 0 80px rgba(0, 0, 0, 0.85);
          opacity: 0.75;
        }

        /* Chromatic Aberration & Glitch Text */
        @keyframes chromaticTwitch {
          0%, 100% { text-shadow: -1px 0 rgba(230, 46, 37, 0.7), 1px 0 rgba(37, 99, 235, 0.7); }
          20% { text-shadow: -2px 0 rgba(230, 46, 37, 0.9), 2px 0 rgba(37, 99, 235, 0.9); }
          40% { text-shadow: 1px -1px rgba(230, 46, 37, 0.5), -1px 1px rgba(16, 185, 129, 0.6); }
          80% { text-shadow: -0.5px 0 rgba(230, 46, 37, 0.6), 0.5px 0 rgba(37, 99, 235, 0.6); }
        }
        .glitch-chroma {
          animation: chromaticTwitch 2.6s infinite ease-in-out;
        }

        /* Hacker Terminal Feeds Auto-Scroll Effect */
        @keyframes streamUp {
          0% { transform: translateY(0); }
          100% { transform: translateY(-50%); }
        }
        .stream-scroll {
          animation: streamUp 18s linear infinite;
        }
        .stream-scroll-fast {
          animation: streamUp 12s linear infinite;
        }

        /* Brutalist Buttons */
        .btn-brutal {
          transition: all 0.15s cubic-bezier(0.16, 1, 0.3, 1);
        }
        .btn-brutal:hover {
          background-color: #E62E25 !important;
          color: #030407 !important;
          border-color: #ff4d4d !important;
          box-shadow: 0 0 24px rgba(230, 46, 37, 0.6);
        }

        /* Blinking Block Cursor */
        @keyframes cursorPulse {
          0%, 49% { opacity: 1; }
          50%, 100% { opacity: 0; }
        }
        .cli-cursor {
          animation: cursorPulse 0.8s infinite;
        }

        /* Eyelids physics for circular portal */
        .eyelid {
          position: absolute;
          left: -10%;
          width: 120%;
          height: 52%;
          background: #030407;
          z-index: 26;
          transition: transform 0.08s ease-out;
          pointer-events: none;
        }
        .eyelid-top {
          top: 0;
          transform-origin: top;
          border-bottom: 2px solid rgba(230, 46, 37, 0.45);
          box-shadow: 0 6px 20px rgba(0, 0, 0, 0.98);
        }
        .eyelid-bottom {
          bottom: 0;
          transform-origin: bottom;
          border-top: 2px solid rgba(230, 46, 37, 0.45);
          box-shadow: 0 -6px 20px rgba(0, 0, 0, 0.98);
        }

        /* Circular Portal Decorative HUD Rings */
        @keyframes ringPulse {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        .hud-dial-spin {
          animation: ringPulse 40s linear infinite;
        }
        @keyframes ringCounterSpin {
          0% { transform: rotate(360deg); }
          100% { transform: rotate(0deg); }
        }
        .hud-dial-counter {
          animation: ringCounterSpin 30s linear infinite;
        }

        /* Barcode styling */
        .barcode-strip {
          letter-spacing: -1.5px;
          font-family: monospace;
          font-size: 14px;
          transform: scaleY(1.3);
          display: inline-block;
        }
      `}</style>

      {/* ========================================== */}
      {/* 1. TOP HEADER // HARDCORE CYBER-HUD & DEFCON TELEMETRY */}
      {/* ========================================== */}
      <header className="relative z-30 w-full mb-1">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 items-center bg-[#060911]/90 border border-[#1E293B]/80 px-4 py-2 shadow-[0_4px_30px_rgba(0,0,0,0.9)] backdrop-blur-md">
          {/* Left Section (4 cols): System ID, Kernel & Enclave Diagnostics */}
          <div className="lg:col-span-4 flex flex-col gap-1 text-[11px] tracking-[0.08em]">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="inline-block w-2.5 h-2.5 bg-[#E62E25] animate-ping" id="sysStatusBeacon"></span>
              <span className="text-white font-black tracking-[0.14em] glitch-chroma">
                SYS_ID // DRISHTI_SEC_ENGINE_V2.0
              </span>
              <span className={engineBadge.className} id="engineBadge">
                {engineBadge.text}
              </span>
            </div>
            <div className="flex items-center gap-2.5 text-[9.5px] text-[#64748B]">
              <span>KERNEL: <span className="text-[#CBD5E1] font-semibold">SEC-ARCH-09.r4</span></span>
              <span className="text-[#10B981] font-mono px-1 bg-[#10B981]/10 border border-[#10B981]/30">[SELINUX_ENFORCING]</span>
              <span className="text-[#38BDF8] font-mono px-1 bg-[#2563EB]/15 border border-[#2563EB]/40">[RPC_TLS1.3]</span>
              <span className="text-[#475569]">CYCLE: <span className="text-[#E5E7EB]" id="telemetryCycle">{telemetryCycle}</span></span>
            </div>
          </div>

          {/* Center Section (5 cols): Boot Stage Cards & Hacker Diagnostics Bar */}
          <div className="lg:col-span-5 flex flex-col gap-1 items-center justify-center">
            <div className="grid grid-cols-4 w-full gap-1.5 text-[9px] tracking-[0.05em] font-mono">
              {/* Stage 1 */}
              <div
                className={`px-1 py-1 text-center flex items-center justify-center gap-1 ${
                  stages.step1
                    ? 'bg-[#08101C] border border-[#10B981]/40'
                    : 'bg-[#080B12] border border-[#1E293B] text-[#475569]'
                }`}
                id="step1"
              >
                <span className={stages.step1 ? 'text-[#10B981] font-bold' : 'text-[#475569]'}>01:CRYPTO</span>
                {stages.step1 && <span className="text-[#10B981]">✓</span>}
              </div>

              {/* Stage 2 */}
              <div
                className={`px-1 py-1 text-center flex items-center justify-center gap-1 ${
                  stages.step2
                    ? 'bg-[#08101C] border border-[#10B981]/40'
                    : 'bg-[#080B12] border border-[#1E293B] text-[#475569]'
                }`}
                id="step2"
              >
                <span className={stages.step2 ? 'text-[#10B981] font-bold' : 'text-[#475569]'}>02:NEURAL</span>
                {stages.step2 && <span className="text-[#10B981]">✓</span>}
              </div>

              {/* Stage 3 */}
              <div
                className={`px-1 py-1 text-center flex items-center justify-center gap-1 ${
                  stages.step4
                    ? 'bg-[#08101C] border border-[#10B981]/40'
                    : stages.step3
                    ? 'bg-[#1C0A0D] border border-[#E62E25]/80 shadow-[0_0_12px_rgba(230,46,37,0.3)]'
                    : 'bg-[#080B12] border border-[#1E293B]'
                }`}
                id="step3"
              >
                <span className={stages.step4 ? 'text-[#10B981] font-bold' : stages.step3 ? 'text-[#F87171] font-bold' : 'text-[#475569]'}>
                  03:BIOMETRIC
                </span>
                {stages.step4 ? (
                  <span className="text-[#10B981]">✓</span>
                ) : stages.step3 ? (
                  <span className="text-[#E62E25] animate-ping inline-block w-1.5 h-1.5 rounded-full"></span>
                ) : null}
              </div>

              {/* Stage 4 */}
              <div
                className={`px-1 py-1 text-center flex items-center justify-center gap-1 ${
                  stages.step4
                    ? 'bg-[#08101C] border border-[#10B981]/70 shadow-[0_0_12px_rgba(16,185,129,0.3)]'
                    : 'bg-[#080B12] border border-[#1E293B] text-[#475569]'
                }`}
                id="step4"
              >
                <span className={stages.step4 ? 'text-[#10B981] font-bold' : 'text-[#475569]'}>
                  04:COCKPIT {stages.step4 && '✓'}
                </span>
              </div>
            </div>

            {/* Progress track & Micro diagnostic readouts */}
            <div className="w-full flex flex-col gap-0.5">
              <div className="w-full h-1.5 bg-[#090D18] border border-[#1E293B] relative overflow-hidden flex">
                <div
                  className={`h-full ${stages.step4 ? 'bg-[#10B981]' : 'bg-[#10B981]'} transition-all duration-300`}
                  id="bootProgressBar"
                  style={{ width: `${bootProgress}%` }}
                ></div>
              </div>
              <div className="flex items-center justify-between text-[8px] tracking-wider w-full text-[#64748B]">
                <span className="text-[#94A3B8] font-mono truncate max-w-[280px]" id="bootDiagLabel">
                  {bootDiagLabel}
                </span>
                <span className="text-[#EF4444] font-bold font-mono">
                  {bootProgress.toFixed(1)}% CAPTURE
                </span>
              </div>
            </div>
          </div>

          {/* Right Section (3 cols): Exploits, Live Distance, Re-Calibrate Trigger */}
          <div className="lg:col-span-3 flex flex-col items-end gap-1 text-[10px]">
            <div className="flex items-center gap-2">
              <span className="text-[8.5px] px-1.5 py-0.2 bg-[#10B981]/15 text-[#10B981] border border-[#10B981]/40 font-bold">
                PAYLOADS: 0
              </span>
              <span className="text-[#64748B]">
                DIST: <span className="text-[#E5E7EB] font-bold font-mono" id="subjectDistance">{depth}</span>
              </span>
              <span className="text-[9px] px-1.5 py-0.5 bg-[#E62E25]/25 text-[#EF4444] border border-[#E62E25]/60 font-bold tracking-wider animate-pulse" id="lockStatusBadge">
                [TARGET_LOCKED]
              </span>
            </div>
            <div>
              <button
                type="button"
                className="flex items-center gap-1.5 text-[9px] text-[#94A3B8] hover:text-white px-2 py-0.5 border border-[#334155]/80 hover:border-[#EF4444] bg-[#0A0E18] hover:bg-[#E62E25]/20 transition-all cursor-pointer shadow-sm font-mono"
                onClick={rebootSequence}
                title="Re-run engine self-test and camera sweep"
              >
                <span className="text-[#EF4444]">⚡</span>
                <span>REBOOT_OPTO_MATRIX</span>
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* ========================================== */}
      {/* 2. CENTER STAGE: PURE CIRCULAR BIOMETRIC PORTAL WITH LIVE CONSOLE FLANKS */}
      {/* ========================================== */}
      <main className="relative z-30 flex flex-col items-center justify-center flex-1 w-full my-auto overflow-hidden">
        {/* Status Bar Pill above eye */}
        <div className="flex items-center gap-4 text-[9px] tracking-[0.14em] text-[#64748B] pointer-events-none bg-[#070B14]/90 px-3 py-1 border border-[#1E293B] mb-1.5 shadow-[0_2px_15px_rgba(0,0,0,0.8)] backdrop-blur-sm">
          <span>SUBJECT: <span className="text-[#60A5FA] font-bold" id="subjectStatusText">HUMAN_HOST_ACTIVE</span></span>
          <span className="text-[#334155]">|</span>
          <span>CONFIDENCE: <span className="text-white font-bold font-mono" id="confVal">99.14%</span></span>
          <span className="text-[#334155]">|</span>
          <span>FIREWALL: <span className="text-[#EF4444] font-bold">L5_OVERRIDE</span></span>
          <span className="text-[#334155]">|</span>
          <span>LIVENESS: <span className="text-[#10B981] font-bold font-mono" id="livenessVal">0.998</span></span>
        </div>

        {/* Main Biometric Stage with Lateral Hacker Data Streams */}
        <div className="relative w-full max-w-6xl flex items-center justify-center px-2 gap-3 lg:gap-6">
          {/* LEFT FLANK: Scrolling Memory Hex Dump & Interrupt Stream */}
          <aside className="hidden xl:flex flex-col w-[210px] h-[270px] border border-[#1E293B]/70 bg-[#04060C]/90 p-2 overflow-hidden shadow-[inset_0_0_20px_rgba(0,0,0,0.85)] text-[8px] font-mono leading-relaxed relative">
            <div className="flex items-center justify-between border-b border-[#1E293B]/80 pb-1 mb-1 text-[8.5px] font-bold tracking-wider">
              <div className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-[#EF4444] animate-ping"></span>
                <span className="text-[#EF4444]">// MEM_DUMP_0x7FFF</span>
              </div>
              <span className="text-[7.5px] px-1 bg-[#E62E25]/20 text-[#EF4444] border border-[#E62E25]/40">L1_CACHE</span>
            </div>
            <div className="relative flex-1 overflow-hidden">
              <div className="stream-scroll space-y-1 text-[#475569]">
                <div className="flex justify-between"><span className="text-[#94A3B8]">0x7FFF89A2:</span> <span className="text-[#CBD5E1]">48 89 E5 48</span></div>
                <div className="flex justify-between"><span className="text-[#94A3B8]">0x7FFF89AA:</span> <span className="text-[#CBD5E1]">E8 24 FF FF</span></div>
                <div className="flex justify-between"><span className="text-[#EF4444]">OVERFLOW_GUARD:</span> <span className="text-[#10B981] font-bold">ACTIVE</span></div>
                <div className="flex justify-between"><span className="text-[#94A3B8]">0x7FFF89B2:</span> <span className="text-[#CBD5E1]">55 48 89 E5</span></div>
                <div className="flex justify-between"><span className="text-[#94A3B8]">0x7FFF89BA:</span> <span className="text-[#CBD5E1]">41 56 41 55</span></div>
                <div className="flex justify-between"><span className="text-[#60A5FA]">ROOT_INJECT:</span> <span className="text-[#EF4444] font-bold">BLOCKED</span></div>
                <div className="flex justify-between"><span className="text-[#94A3B8]">0x7FFF89C2:</span> <span className="text-[#CBD5E1]">B8 01 00 00</span></div>
                <div className="flex justify-between"><span className="text-[#94A3B8]">0x7FFF89CA:</span> <span className="text-[#CBD5E1]">05 48 3D 00</span></div>
                <div className="flex justify-between"><span className="text-[#94A3B8]">0x7FFF89D2:</span> <span className="text-[#CBD5E1]">77 1B 48 89</span></div>
                <div className="flex justify-between"><span className="text-[#F87171]">INTERRUPT:</span> <span className="text-white">SIGSEGV</span></div>
                <div className="flex justify-between"><span className="text-[#94A3B8]">0x7FFF89DA:</span> <span className="text-[#CBD5E1]">31 C0 C9 C3</span></div>
                <div className="flex justify-between"><span className="text-[#10B981]">CRYPTO_NONCE:</span> <span className="text-[#10B981]">0xFA49E2D</span></div>
                <div className="flex justify-between"><span className="text-[#94A3B8]">0x7FFF89EA:</span> <span className="text-[#CBD5E1]">48 83 EC 08</span></div>
                <div className="flex justify-between"><span className="text-[#94A3B8]">0x7FFF89A2:</span> <span className="text-[#CBD5E1]">48 89 E5 48</span></div>
                <div className="flex justify-between"><span className="text-[#94A3B8]">0x7FFF89AA:</span> <span className="text-[#CBD5E1]">E8 24 FF FF</span></div>
                <div className="flex justify-between"><span className="text-[#EF4444]">OVERFLOW_GUARD:</span> <span className="text-[#10B981] font-bold">ACTIVE</span></div>
                <div className="flex justify-between"><span className="text-[#94A3B8]">0x7FFF89B2:</span> <span className="text-[#CBD5E1]">55 48 89 E5</span></div>
              </div>
            </div>
            <div className="mt-1 pt-1 border-t border-[#1E293B]/80 text-[7.5px] text-[#64748B] flex justify-between items-center">
              <span>HEAP: <span className="text-white font-bold">42.1MB</span></span>
              <span className="text-[#10B981] font-bold">CANARY: SECURE</span>
            </div>
          </aside>

          {/* CENTER: Viewport Container for the Optic Array & Reticle Matrix */}
          <div className="relative w-[500px] max-w-full h-[320px] flex items-center justify-center mx-auto" id="scanArena" ref={arenaRef}>
            {/* Cybernetic Targeting HUD Corner Brackets */}
            <div
              className="absolute -top-1 -left-1 w-6 h-6 border-t-2 border-l-2 pointer-events-none transition-colors duration-500"
              style={{ borderColor: bracketBorderColor }}
            ></div>
            <div
              className="absolute -top-1 -right-1 w-6 h-6 border-t-2 border-r-2 pointer-events-none transition-colors duration-500"
              style={{ borderColor: bracketBorderColor }}
            ></div>
            <div
              className="absolute -bottom-1 -left-1 w-6 h-6 border-b-2 border-l-2 pointer-events-none transition-colors duration-500"
              style={{ borderColor: bracketBorderColor }}
            ></div>
            <div
              className="absolute -bottom-1 -right-1 w-6 h-6 border-b-2 border-r-2 pointer-events-none transition-colors duration-500"
              style={{ borderColor: bracketBorderColor }}
            ></div>

            {/* Precision Azimuth Degree Radial Marks */}
            <div className="absolute -top-5 text-[7.5px] font-mono tracking-widest text-[#EF4444]/90 pointer-events-none">
              AZM 000° // APERTURE_NORTH
            </div>
            <div className="absolute -bottom-5 text-[7.5px] font-mono tracking-widest text-[#475569] pointer-events-none">
              AZM 180° // APERTURE_SOUTH
            </div>

            {/* Outer HUD Concentric Framing Rings */}
            <div className="absolute w-[330px] h-[330px] rounded-full border border-dashed border-[#2563EB]/40 pointer-events-none hud-dial-spin"></div>
            <div className="absolute w-[310px] h-[310px] rounded-full border border-[#E62E25]/30 pointer-events-none hud-dial-counter"></div>
            <div className="absolute w-[292px] h-[292px] rounded-full border border-[#10B981]/25 pointer-events-none shadow-[0_0_25px_rgba(16,185,129,0.15)]"></div>

            {/* PURE CIRCULAR BIOMETRIC LENS / IRIS PORTAL VIEWPORT */}
            <div
              className={`relative w-[280px] h-[280px] rounded-full overflow-hidden bg-[#070b14] border-2 transition-all duration-700 flex items-center justify-center z-20 ${portalGlow}`}
              id="eyeOrbit"
            >
              {/* Unified Eye Rendering HTML5 Canvas */}
              <canvas
                className="absolute inset-0 w-full h-full block"
                height={280}
                id="eyeCanvas"
                ref={canvasRef}
                width={280}
              ></canvas>

              {/* Optical Glass Antireflective Depth Layer */}
              <div className="absolute inset-0 rounded-full shadow-[inset_0_0_50px_rgba(0,0,0,0.9),inset_0_15px_30px_rgba(0,0,0,0.7),inset_0_-15px_30px_rgba(0,0,0,0.7)] pointer-events-none z-25"></div>

              {/* Organic Circular Eyelids for natural physiological blinking */}
              <div
                className="eyelid eyelid-top"
                id="eyelidTop"
                ref={eyelidTopRef}
                style={{ transform: 'translateY(-100%)' }}
              ></div>
              <div
                className="eyelid eyelid-bottom"
                id="eyelidBottom"
                ref={eyelidBottomRef}
                style={{ transform: 'translateY(100%)' }}
              ></div>
            </div>

            {/* Precision Telemetry Overlay around Eye (Left Flank) */}
            <div className="absolute -left-12 top-1/2 -translate-y-1/2 text-[8.5px] text-[#475569] font-mono leading-relaxed tracking-wider text-left pointer-events-none hidden md:block">
              <div className="text-[#94A3B8]">FACIAL_DEPTH // <span className="text-white font-bold" id="depthVal">{depth}</span></div>
              <div className="text-[#EF4444] font-bold">IRIS_SCAN: <span id="irisScanVal">{irisScan}</span> MATCH</div>
              <div>PUPIL_DIL: <span className="text-[#CBD5E1]" id="pupilDilVal">{pupilDil}</span></div>
              <div>IPD_METRIC: <span className="text-[#94A3B8]" id="ipdVal">63.8mm</span></div>
              <div className="text-[#64748B]">VESSEL_HASH: <span className="text-[#F87171] font-mono">0x9E4B..7A</span></div>
              <div className="text-[#2563EB]">SACCADE_FRQ: <span className="text-white font-bold">3.4Hz</span></div>
            </div>

            {/* Precision Telemetry Overlay around Eye (Right Flank) */}
            <div className="absolute -right-12 top-1/2 -translate-y-1/2 text-[8.5px] text-[#475569] font-mono leading-relaxed tracking-wider text-right pointer-events-none hidden md:block">
              <div>CORNEA_REFRACT // <span className="text-[#10B981] font-bold">OK</span></div>
              <div className="text-[#E62E25] font-bold">BIOMETRIC_LOCK: <span id="biolockStatus">{biolockStatus}</span></div>
              <div>GAZE_VECTOR: <span className="text-white font-mono" id="gazeVectorVal">{gazeVector}</span></div>
              <div>SPECTRAL_IR: <span className="text-[#EF4444] font-bold">COHERENT</span></div>
              <div className="text-[#64748B]">TRIANGULATION: <span className="text-[#10B981] font-semibold">LOCKED</span></div>
              <div className="text-[#60A5FA]">ENTROPY_POOL: <span className="text-white font-mono">0x88F1</span></div>
            </div>
          </div>

          {/* RIGHT FLANK: Live Packet Sniffer & Security Hash Stream */}
          <aside className="hidden xl:flex flex-col w-[210px] h-[270px] border border-[#1E293B]/70 bg-[#04060C]/90 p-2 overflow-hidden shadow-[inset_0_0_20px_rgba(0,0,0,0.85)] text-[8px] font-mono leading-relaxed relative">
            <div className="flex items-center justify-between border-b border-[#1E293B]/80 pb-1 mb-1 text-[8.5px] font-bold tracking-wider">
              <div className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-[#38BDF8] animate-ping"></span>
                <span className="text-[#38BDF8]">// PKT_SNIFFER_ETH0</span>
              </div>
              <span className="text-[7.5px] px-1 bg-[#2563EB]/20 text-[#38BDF8] border border-[#2563EB]/40">PROMISC</span>
            </div>
            <div className="relative flex-1 overflow-hidden">
              <div className="stream-scroll-fast space-y-1 text-[#475569]">
                <div className="flex justify-between"><span className="text-[#38BDF8]">TCP/SYN</span> <span className="text-[#CBD5E1]">192.168.1.10:443</span></div>
                <div className="flex justify-between"><span className="text-[#10B981]">SHA256:</span> <span className="text-[#94A3B8]">a94a8fe5..ba6</span></div>
                <div className="flex justify-between"><span className="text-[#EF4444]">ECDSA:</span> <span className="text-[#10B981] font-bold">SIGN_VERIFIED</span></div>
                <div className="flex justify-between"><span className="text-[#94A3B8]">AEAD_TAG:</span> <span className="text-white">c029f635</span></div>
                <div className="flex justify-between"><span className="text-[#60A5FA]">DNS_TUNNEL:</span> <span className="text-[#10B981]">ZERO_LEAKS</span></div>
                <div className="flex justify-between"><span className="text-[#CBD5E1]">PORT_80:</span> <span className="text-[#EF4444] font-bold">REJECT_ALL</span></div>
                <div className="flex justify-between"><span className="text-[#EF4444]">MITM_CHECK:</span> <span className="text-[#10B981]">PIN_VALID</span></div>
                <div className="flex justify-between"><span className="text-[#10B981]">DIFFIE_HELLMAN:</span> <span className="text-white">X25519</span></div>
                <div className="flex justify-between"><span className="text-[#94A3B8]">PKT_DROP_RATE:</span> <span className="text-[#10B981]">0.0000%</span></div>
                <div className="flex justify-between"><span className="text-[#F87171]">PAYLOAD_LEN:</span> <span className="text-white">512_BYTES</span></div>
                <div className="flex justify-between"><span className="text-[#38BDF8]">ENCLAVE_TOKEN:</span> <span className="text-[#38BDF8]">0x89FC</span></div>
                <div className="flex justify-between"><span className="text-[#38BDF8]">TCP/SYN</span> <span className="text-[#CBD5E1]">192.168.1.10:443</span></div>
                <div className="flex justify-between"><span className="text-[#10B981]">SHA256:</span> <span className="text-[#94A3B8]">a94a8fe5..ba6</span></div>
                <div className="flex justify-between"><span className="text-[#EF4444]">ECDSA:</span> <span className="text-[#10B981] font-bold">SIGN_VERIFIED</span></div>
              </div>
            </div>
            <div className="mt-1 pt-1 border-t border-[#1E293B]/80 text-[7.5px] text-[#64748B] flex justify-between items-center">
              <span>THROUGHPUT: <span className="text-white font-bold">2.8 MB/s</span></span>
              <span className="text-[#38BDF8] font-bold">MTU: 1500</span>
            </div>
          </aside>
        </div>

        {/* ========================================== */}
        {/* 3. HACKER CLI AUTHENTICATION TERMINAL PROMPT */}
        {/* ========================================== */}
        <div className="relative z-30 w-[490px] max-w-full mt-2 flex flex-col gap-2">
          {/* Recon Scope Selector Buttons */}
          <div className="flex items-center justify-between px-1 text-[10px] tracking-[0.1em] text-[#64748B] font-medium">
            <button
              type="button"
              className={`flex items-center gap-1.5 cursor-pointer transition-colors ${
                mode === 'passive' ? 'text-white' : 'text-[#64748B] hover:text-[#94A3B8]'
              }`}
              id="togglePassive"
              onClick={() => handleSetMode('passive')}
            >
              <span className="text-[#2563EB] font-bold">[</span>
              <span className={mode === 'passive' ? 'text-[#2563EB]' : 'text-[#475569]'} id="dotPassive">
                {mode === 'passive' ? '●' : '○'}
              </span>
              <span>FULL_PASSIVE_RECON</span>
              <span className="text-[#2563EB] font-bold">]</span>
            </button>
            <button
              type="button"
              className={`flex items-center gap-1.5 cursor-pointer transition-colors ${
                mode === 'active' ? 'text-white' : 'text-[#64748B] hover:text-[#94A3B8]'
              }`}
              id="toggleActive"
              onClick={() => handleSetMode('active')}
            >
              <span className="text-[#475569]">[</span>
              <span className={mode === 'active' ? 'text-[#EF4444]' : 'text-[#475569]'} id="dotActive">
                {mode === 'active' ? '●' : '○'}
              </span>
              <span>ACTIVE_INTRUSION_GUARD</span>
              <span className="text-[#475569]">]</span>
            </button>
          </div>

          {/* Real Hacker CLI Console Input Terminal Box */}
          <div className="relative w-full bg-[#060912]/95 border border-[#1E293B] shadow-[0_4px_25px_rgba(0,0,0,0.85)] p-2.5 flex flex-col gap-1.5">
            {/* Terminal Titlebar & Command Path */}
            <div className="flex items-center justify-between text-[9px] text-[#64748B] border-b border-[#1E293B]/60 pb-1">
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-[#E62E25]/80"></span>
                <span className="w-2 h-2 rounded-full bg-[#F59E0B]/80"></span>
                <span className="w-2 h-2 rounded-full bg-[#10B981]/80"></span>
                <span className="text-[#94A3B8] font-bold ml-1 font-mono">root@drishti-core:~#</span>
              </div>
              <div className="flex items-center gap-1 text-[8.5px]">
                <span className="text-[#475569]">STATUS:</span>
                <span
                  className={
                    scanMode === 'HIGH_FREQ_ACQUISITION'
                      ? 'text-[#EF4444] font-bold tracking-tight animate-pulse'
                      : 'text-[#94A3B8] font-bold tracking-wider'
                  }
                  id="scanModeIndicator"
                >
                  {scanMode}
                </span>
              </div>
            </div>

            {/* Prompt & Input Field with Real Blinking Block Cursor */}
            <div className="flex items-center gap-2 text-[11px] font-mono pt-0.5">
              <span className="text-[#10B981] font-bold whitespace-nowrap select-none">
                ./authenticate_operator --token
              </span>
              <input
                autoComplete="off"
                className="w-full bg-transparent text-[#E5E7EB] font-mono tracking-wider outline-none border-none p-0 text-[11px] placeholder-[#475569] focus:ring-0"
                id="operatorInput"
                onBlur={() => handleInputFocus(false)}
                onFocus={() => handleInputFocus(true)}
                onInput={(e: any) => handleKeyInput(e.target.value)}
                placeholder="INPUT_JWT_SIGNATURE..."
                spellCheck={false}
                type="text"
                value={tokenInput}
              />
              <span className="text-[#E62E25] cli-cursor font-bold select-none text-[13px]">█</span>
            </div>

            {/* Quick Hacker Flag / Suggestion Chips */}
            <div className="flex items-center gap-1.5 pt-1 overflow-x-auto text-[8px] text-[#64748B]">
              <span className="text-[#475569] select-none font-bold">FLAGS:</span>
              <button
                type="button"
                className="px-1.5 py-0.5 bg-[#0B101D] border border-[#1E293B] hover:border-[#EF4444] hover:text-white transition-colors cursor-pointer"
                onClick={() => appendFlag('--bypass-sandbox')}
              >
                [--bypass-sandbox]
              </button>
              <button
                type="button"
                className="px-1.5 py-0.5 bg-[#0B101D] border border-[#1E293B] hover:border-[#EF4444] hover:text-white transition-colors cursor-pointer"
                onClick={() => appendFlag('--force-recon')}
              >
                [--force-recon]
              </button>
              <button
                type="button"
                className="px-1.5 py-0.5 bg-[#0B101D] border border-[#1E293B] hover:border-[#EF4444] hover:text-white transition-colors cursor-pointer"
                onClick={() => appendFlag('--debug-dump')}
              >
                [--debug-dump]
              </button>
            </div>
          </div>

          {/* Primary Tactical Authorization Trigger */}
          <button
            type="button"
            className={`w-full h-[38px] font-mono text-[11px] font-bold tracking-[0.16em] flex items-center justify-center gap-2 rounded-none transition-all cursor-pointer ${
              isSuccess
                ? 'bg-[#10B981]/20 border border-[#10B981] text-[#10B981] shadow-[0_0_24px_rgba(16,185,129,0.5)] hover:bg-[#10B981]/30'
                : 'bg-[#E62E25]/15 border border-[#E62E25] text-[#EF4444] shadow-[0_0_20px_rgba(230,46,37,0.35)] hover:bg-[#E62E25]/25 hover:text-white'
            }`}
            disabled={isAuthenticating}
            id="authBtn"
            onClick={simulateAuth}
          >
            <span id="authButtonText">{buttonText}</span>
            <span
              className={`w-2 h-2 bg-[#E62E25] animate-ping ${
                isAuthenticating && !isSuccess ? '' : 'hidden'
              }`}
              id="authSpinner"
            ></span>
          </button>

          {/* Live Terminal Feedback Log */}
          {authStatus.custom ? (
            <div className={authStatus.className} id="authStatus">
              {authStatus.text}
            </div>
          ) : (
            <div
              className="text-center text-[9px] tracking-[0.14em] text-[#94A3B8] bg-[#070B14] py-0.5 border border-[#1E293B] font-medium min-h-[14px]"
              id="authStatus"
            >
              <span className="text-[#60A5FA] font-bold">BIOMETRIC_CORE // SECURE_ENCLAVE_READY</span>
              <span className="text-[#64748B] ml-2">PRESS ⌘+ENTER TO AUTHENTICATE</span>
            </div>
          )}
        </div>
      </main>

      {/* ========================================== */}
      {/* 4. BOTTOM EDITORIAL FOOTER & HARDWARE SPECS WITH ACTIVE STATUS LEDS */}
      {/* ========================================== */}
      <footer className="relative z-30 flex flex-col items-center justify-end w-full pb-1">
        {/* Active Status LED Triad Bar */}
        <div className="flex items-center gap-6 mb-2 text-[8px] font-mono tracking-widest text-[#64748B]">
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-[#EF4444] animate-pulse"></span>
            <span className="text-[#EF4444] font-bold">RED: RECON_ACTIVE</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-[#F59E0B]"></span>
            <span className="text-[#F59E0B]">AMBER: BUFFER_LOCK</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-[#10B981]"></span>
            <span className="text-[#10B981]">GREEN: CRYPTO_VALID</span>
          </div>
        </div>

        {/* Brand Typography with Chromatic Twitch */}
        <div className="mb-2 text-center">
          <div className="glitch-chroma text-[15px] md:text-[17px] font-black text-[#E5E7EB] tracking-[0.35em]">
            D R I S H T I &nbsp;&nbsp;//&nbsp;&nbsp; V I S I O N &nbsp;&nbsp; C 2
          </div>
          <div className="text-[8.5px] tracking-[0.25em] text-[#475569] mt-0.5">
            SEC-OPS ZERO TRUST COMMAND ARCHITECTURE // SOVEREIGN CYBER INTELLIGENCE
          </div>
        </div>

        {/* Technical Spec Barcode and Hardware Hashes */}
        <div className="w-full max-w-5xl border-t border-[#1E293B]/70 pt-2 px-3 flex flex-wrap items-center justify-between text-[8px] tracking-[0.08em] font-mono text-[#64748B] gap-2">
          <div className="flex flex-col">
            <span className="text-[#475569]">SHA-256 ENCLAVE FINGERPRINT</span>
            <span className="text-[#94A3B8]">e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</span>
          </div>
          <div className="flex flex-col">
            <span className="text-[#475569]">DNS CHALLENGE STATUS</span>
            <span className="text-[#2563EB]" id="dnsChallengeStatus">ACME_V02 [RESOLVED // SECURE]</span>
          </div>
          <div className="flex flex-col">
            <span className="text-[#475569]">HSM ENCLAVE ATTESTATION</span>
            <span className="text-[#94A3B8]" id="enclaveAttest">NITRO_ENCLAVE_V4 // VERIFIED</span>
          </div>
          <div className="flex items-center gap-2 pl-3 border-l border-[#1E293B]">
            <div className="barcode-strip text-white">|||| || ||| | ||||</div>
            <span className="text-[7.5px] text-[#475569]">SEC-09</span>
          </div>
        </div>
      </footer>
    </div>
  );
};
