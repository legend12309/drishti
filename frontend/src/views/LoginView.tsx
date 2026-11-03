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
  const [depth, setDepth] = useState('54.2 cm');
  const [pupilDil, setPupilDil] = useState('4.82mm');
  const [irisScan, setIrisScan] = useState('99.4%');
  const [telemetryCycle, setTelemetryCycle] = useState('0.39ms');
  const [gazeVector, setGazeVector] = useState('[+0.12, -0.04]');
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
    text: 'DEFCON-5: [ONLINE_ROOT]',
    className: 'text-[9px] px-1.5 py-0.5 bg-[#059669]/15 text-[#047857] border border-[#059669]/40 font-bold',
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

  // DOM Refs
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const arenaRef = useRef<HTMLDivElement | null>(null);
  const animFrameRef = useRef<number | null>(null);
  const typingTimeoutRef = useRef<any>(null);
  const rebootTimersRef = useRef<any[]>([]);
  const authTimersRef = useRef<any[]>([]);

  // Eye Physics Parameters (Sterile Clinical Laboratory Dimensions)
  const SIZE = 314;
  const CENTER = SIZE / 2; // 157
  const IRIS_RADIUS = 64;
  const MAX_IRIS_OFFSET = 44;

  const physicsRef = useRef({
    mouseX: typeof window !== 'undefined' ? window.innerWidth / 2 : 700,
    mouseY: typeof window !== 'undefined' ? window.innerHeight / 2 : 400,
    curX: 0,
    curY: 0,
    targetX: 0,
    targetY: 0,
    saccadeOffsetX: 0,
    saccadeOffsetY: 0,
    pupilRadius: 20,
    targetPupilRadius: 20,
    pupilTwitch: 0,
    blinkProgress: 0, // 0: open, 1: closed
    isBlinking: false,
    blinkStartTime: 0,
    blinkDurationClose: 95,
    blinkDurationOpen: 185,
  });

  const primaryVesselsRef = useRef<Array<{
    points: Array<{ x: number; y: number }>;
    width: number;
    color: string;
    alpha: number;
  }>>([]);

  const irisFibersRef = useRef<Array<{
    angle: number;
    innerRel: number;
    outerRel: number;
    col: string;
    width: number;
  }>>([]);

  // Generate Vascular Network (42 primary tortuous vessels + 30 fine secondary capillaries)
  const generateBloodVessels = useCallback(() => {
    const vessels: typeof primaryVesselsRef.current = [];
    const vesselCount = 42;

    for (let i = 0; i < vesselCount; i++) {
      const angle = (i / vesselCount) * Math.PI * 2 + (Math.random() * 0.15 - 0.075);
      const outerR = CENTER * 0.98;
      const innerR = IRIS_RADIUS * 1.05 + Math.random() * 18;
      const points: Array<{ x: number; y: number }> = [];
      let r = outerR;
      let a = angle;

      while (r > innerR) {
        points.push({
          x: CENTER + Math.cos(a) * r,
          y: CENTER + Math.sin(a) * r,
        });
        r -= 3.5 + Math.random() * 3.5;
        a += (Math.random() - 0.5) * 0.28;
      }

      vessels.push({
        points,
        width: 0.6 + Math.random() * 1.3,
        color: Math.random() > 0.35 ? '#B91C1C' : '#991B1B',
        alpha: 0.65 + Math.random() * 0.35,
      });
    }

    // Secondary fine capillary network
    for (let j = 0; j < 30; j++) {
      const angle = Math.random() * Math.PI * 2;
      const outerR = CENTER * 0.96;
      const innerR = IRIS_RADIUS * 1.25;
      const points: Array<{ x: number; y: number }> = [];
      let r = outerR;
      let a = angle;

      while (r > innerR) {
        points.push({
          x: CENTER + Math.cos(a) * r,
          y: CENTER + Math.sin(a) * r,
        });
        r -= 3;
        a += (Math.random() - 0.5) * 0.35;
      }

      vessels.push({
        points,
        width: 0.4 + Math.random() * 0.35,
        color: '#DC2626',
        alpha: 0.45 + Math.random() * 0.35,
      });
    }

    primaryVesselsRef.current = vessels;
  }, [CENTER, IRIS_RADIUS]);

  // Pre-generate hyper-detailed piercing iris radial fibers
  const generateIrisFibers = useCallback(() => {
    const fibers: typeof irisFibersRef.current = [];
    const FIBER_COUNT = 480;

    for (let f = 0; f < FIBER_COUNT; f++) {
      const angle = (f / FIBER_COUNT) * Math.PI * 2 + (Math.random() * 0.008);
      const innerRel = 0.22 + Math.random() * 0.12;
      const outerRel = 0.98 - Math.random() * 0.03;
      const roll = Math.random();
      let col: string;

      if (roll > 0.84) {
        col = 'rgba(220, 38, 38, 0.85)'; // blood red nerve fiber
      } else if (roll > 0.52) {
        col = 'rgba(2, 132, 199, 0.8)';  // electric cobalt
      } else if (roll > 0.25) {
        col = 'rgba(224, 242, 254, 0.9)'; // cold pale ice steel
      } else {
        col = 'rgba(15, 23, 42, 0.85)';  // deep obsidian
      }

      fibers.push({
        angle,
        innerRel,
        outerRel,
        col,
        width: 0.65 + Math.random() * 1.0,
      });
    }

    irisFibersRef.current = fibers;
  }, []);

  // Realistic Organic Blink Function
  const triggerBlink = useCallback((forcedCloseDur = 95, forcedOpenDur = 185) => {
    const p = physicsRef.current;
    if (p.isBlinking) return;
    p.isBlinking = true;
    p.blinkStartTime = performance.now();
    p.blinkDurationClose = forcedCloseDur;
    p.blinkDurationOpen = forcedOpenDur;
  }, []);

  // Draw natural curved eyelids with anatomical palpebral fissure curves & tear meniscus
  const drawOrganicEyelids = useCallback((ctx: CanvasRenderingContext2D, progress: number, curX: number, curY: number) => {
    const marginY = CENTER + (curY * 0.15);
    const lateralCanthusX = 14;
    const medialCanthusX = SIZE - 14;
    const canthusY = CENTER + (curY * 0.08);

    const upperPeakX = SIZE * 0.44 + (curX * 0.08);
    const lowerTroughX = SIZE * 0.52 + (curX * 0.08);

    const upperRestY = -8;
    const upperPeakY = upperRestY + progress * (marginY - upperRestY + 6);

    const lowerRestY = SIZE + 8;
    const lowerTroughY = lowerRestY - progress * (lowerRestY - marginY + 6);

    ctx.save();

    // 1. UPPER EYELID
    ctx.beginPath();
    ctx.moveTo(0, 0);
    ctx.lineTo(SIZE, 0);
    ctx.lineTo(medialCanthusX + 16, 0);
    ctx.lineTo(medialCanthusX, canthusY - 6 + progress * 6);
    ctx.bezierCurveTo(
      SIZE * 0.74, upperPeakY - 8 * (1 - progress * 0.4),
      upperPeakX + 24, upperPeakY + 12 * progress,
      upperPeakX, upperPeakY + 14 * progress
    );
    ctx.bezierCurveTo(
      upperPeakX - 32, upperPeakY + 12 * progress,
      SIZE * 0.22, canthusY - 4 + progress * 4,
      lateralCanthusX, canthusY + 2 + progress * 2
    );
    ctx.lineTo(0, canthusY);
    ctx.closePath();

    const upperGrad = ctx.createLinearGradient(CENTER, 0, CENTER, Math.max(20, upperPeakY + 16 * progress));
    upperGrad.addColorStop(0, '#0F172A');
    upperGrad.addColorStop(0.68, '#1E293B');
    upperGrad.addColorStop(0.92, '#334155');
    upperGrad.addColorStop(0.98, '#475569');
    upperGrad.addColorStop(1, '#DC2626');
    ctx.fillStyle = upperGrad;
    ctx.fill();

    ctx.strokeStyle = '#DC2626';
    ctx.lineWidth = 2.2;
    ctx.stroke();

    // 2. LOWER EYELID
    ctx.beginPath();
    ctx.moveTo(0, SIZE);
    ctx.lineTo(SIZE, SIZE);
    ctx.lineTo(medialCanthusX + 16, SIZE);
    ctx.lineTo(medialCanthusX, canthusY - 3 - progress * 3);
    ctx.bezierCurveTo(
      SIZE * 0.72, lowerTroughY + 6 * (1 - progress * 0.3),
      lowerTroughX + 28, lowerTroughY - 10 * progress,
      lowerTroughX, lowerTroughY - 11 * progress
    );
    ctx.bezierCurveTo(
      lowerTroughX - 36, lowerTroughY - 10 * progress,
      SIZE * 0.22, canthusY + 2 - progress * 2,
      lateralCanthusX, canthusY + 4 - progress * 4
    );
    ctx.lineTo(0, canthusY);
    ctx.closePath();

    const lowerGrad = ctx.createLinearGradient(CENTER, SIZE, CENTER, Math.min(SIZE - 20, lowerTroughY - 12 * progress));
    lowerGrad.addColorStop(0, '#0F172A');
    lowerGrad.addColorStop(0.7, '#1E293B');
    lowerGrad.addColorStop(0.93, '#334155');
    lowerGrad.addColorStop(1, '#DC2626');
    ctx.fillStyle = lowerGrad;
    ctx.fill();

    ctx.strokeStyle = '#DC2626';
    ctx.lineWidth = 1.8;
    ctx.stroke();

    // 3. REALISTIC LOWER LID MARGIN
    const lowerRimY = Math.min(SIZE - 12, lowerTroughY - 10 * progress);
    ctx.beginPath();
    ctx.moveTo(lateralCanthusX + 8, canthusY + 4 - progress * 3);
    ctx.bezierCurveTo(
      SIZE * 0.24, lowerRimY + 4,
      lowerTroughX - 25, lowerRimY - 1,
      lowerTroughX, lowerRimY
    );
    ctx.bezierCurveTo(
      lowerTroughX + 25, lowerRimY + 1,
      SIZE * 0.72, lowerRimY + 6,
      medialCanthusX - 8, canthusY - 2 - progress * 2
    );
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.65)';
    ctx.lineWidth = 1.4;
    ctx.stroke();

    ctx.strokeStyle = 'rgba(2, 132, 199, 0.45)';
    ctx.lineWidth = 0.8;
    ctx.stroke();

    // 4. PALPEBRAL FISSURE SEAM when closed
    if (progress > 0.82) {
      const seamAlpha = (progress - 0.82) / 0.18;
      ctx.beginPath();
      ctx.moveTo(lateralCanthusX + 4, canthusY + 2);
      ctx.bezierCurveTo(
        SIZE * 0.35, marginY + 3,
        SIZE * 0.65, marginY + 2,
        medialCanthusX - 4, canthusY - 1
      );
      ctx.strokeStyle = `rgba(220, 38, 38, ${seamAlpha * 0.95})`;
      ctx.lineWidth = 2.8;
      ctx.stroke();
    }

    ctx.restore();
  }, [CENTER, SIZE]);

  // Draw realistic upper eyelid depth shadow
  const drawUpperEyelidDepthShadow = useCallback((ctx: CanvasRenderingContext2D, curYOffset: number) => {
    const shadowCenterY = 46 + (curYOffset * 0.12);
    const grad = ctx.createLinearGradient(CENTER, 0, CENTER, shadowCenterY + 42);
    grad.addColorStop(0, 'rgba(15, 23, 42, 0.48)');
    grad.addColorStop(0.35, 'rgba(15, 23, 42, 0.28)');
    grad.addColorStop(0.72, 'rgba(220, 38, 38, 0.09)');
    grad.addColorStop(1, 'rgba(15, 23, 42, 0)');

    ctx.save();
    ctx.beginPath();
    ctx.ellipse(CENTER, shadowCenterY, CENTER * 0.95, 48, 0, 0, Math.PI * 2);
    ctx.fillStyle = grad;
    ctx.fill();
    ctx.restore();
  }, [CENTER]);

  // Main canvas animation and loop setup
  useEffect(() => {
    generateBloodVessels();
    generateIrisFibers();

    const handleMouseMove = (e: MouseEvent) => {
      physicsRef.current.mouseX = e.clientX;
      physicsRef.current.mouseY = e.clientY;
    };
    window.addEventListener('mousemove', handleMouseMove);

    // Blinking schedule: 2.8s to 4.2s with ~28% realistic double-blink occurrence
    let blinkTimer: any;
    let doubleBlinkTimer: any;
    const scheduleNextBlink = () => {
      const delay = 2800 + Math.random() * 1400;
      blinkTimer = setTimeout(() => {
        const isDouble = Math.random() < 0.28;
        if (isDouble) {
          triggerBlink(75, 120);
          doubleBlinkTimer = setTimeout(() => {
            triggerBlink(95 + Math.random() * 15, 175 + Math.random() * 25);
          }, 250);
        } else {
          triggerBlink(90 + Math.random() * 20, 170 + Math.random() * 30);
        }
        scheduleNextBlink();
      }, delay);
    };
    scheduleNextBlink();

    // Saccades schedule (predatory sudden saccades & pupil micro-dilations)
    let saccadeTimer: any;
    let saccadeResetTimer: any;
    const scheduleNextSaccade = () => {
      const delay = 600 + Math.random() * 1400;
      saccadeTimer = setTimeout(() => {
        if (Math.random() > 0.6) {
          physicsRef.current.saccadeOffsetX = (Math.random() - 0.5) * 5.0;
          physicsRef.current.saccadeOffsetY = (Math.random() - 0.5) * 4.0;
          physicsRef.current.pupilTwitch = (Math.random() - 0.5) * 4.5;
        } else {
          physicsRef.current.saccadeOffsetX = (Math.random() - 0.5) * 2.2;
          physicsRef.current.saccadeOffsetY = (Math.random() - 0.5) * 1.8;
          physicsRef.current.pupilTwitch = (Math.random() - 0.5) * 1.5;
        }
        saccadeResetTimer = setTimeout(() => {
          physicsRef.current.saccadeOffsetX = 0;
          physicsRef.current.saccadeOffsetY = 0;
        }, 75);
        scheduleNextSaccade();
      }, delay);
    };
    scheduleNextSaccade();

    // Live Jitter Metrics Interval (420ms)
    const jitterInterval = setInterval(() => {
      const base = 54.0 + (Math.random() * 0.6 - 0.3);
      setDepth(`${base.toFixed(1)} cm`);
      const mm = (3.5 + (physicsRef.current.pupilRadius / 20) * 1.4 + (Math.random() * 0.12)).toFixed(2);
      setPupilDil(`${mm}mm`);
      const scan = (99.3 + (Math.random() * 0.5)).toFixed(1);
      setIrisScan(`${scan}%`);
      setTelemetryCycle(`${(0.34 + (Math.random() * 0.16)).toFixed(2)}ms`);
    }, 420);

    // Master Render Routine
    const drawEyeFrame = (now: number) => {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      if (!ctx) return;

      const p = physicsRef.current;

      // Update Blinking Progress with biological acceleration/deceleration
      if (p.isBlinking) {
        const elapsed = now - p.blinkStartTime;
        if (elapsed < p.blinkDurationClose) {
          const t = elapsed / p.blinkDurationClose;
          p.blinkProgress = Math.pow(t, 2.2);
        } else if (elapsed < p.blinkDurationClose + p.blinkDurationOpen) {
          const t = (elapsed - p.blinkDurationClose) / p.blinkDurationOpen;
          p.blinkProgress = 1 - (1 - Math.pow(1 - t, 3));
        } else {
          p.blinkProgress = 0;
          p.isBlinking = false;
        }
      } else {
        p.blinkProgress = 0;
      }

      // Calculate target ocular offsets normalized from eye canvas center
      let eyeCenterX = window.innerWidth / 2;
      let eyeCenterY = window.innerHeight / 2;

      const rect = canvas.getBoundingClientRect();
      if (rect.width > 0) {
        eyeCenterX = rect.left + rect.width / 2;
        eyeCenterY = rect.top + rect.height / 2;
      }

      const deltaX = p.mouseX - eyeCenterX;
      const deltaY = p.mouseY - eyeCenterY;

      const maxReachX = Math.max(window.innerWidth * 0.48, 300);
      const maxReachY = Math.max(window.innerHeight * 0.48, 300);

      let normX = deltaX / maxReachX;
      let normY = deltaY / maxReachY;

      const normDist = Math.sqrt(normX * normX + normY * normY);
      if (normDist > 1.0) {
        normX /= normDist;
        normY /= normDist;
      }

      p.targetX = normX * MAX_IRIS_OFFSET;
      p.targetY = normY * MAX_IRIS_OFFSET;

      // Smooth ocular physics interpolation (fluid gaze inertia + micro-saccades)
      const effectiveTargetX = p.targetX + p.saccadeOffsetX;
      const effectiveTargetY = p.targetY + p.saccadeOffsetY;
      p.curX += (effectiveTargetX - p.curX) * 0.085;
      p.curY += (effectiveTargetY - p.curY) * 0.085;
      p.pupilRadius += (p.targetPupilRadius + p.pupilTwitch - p.pupilRadius) * 0.14;

      ctx.clearRect(0, 0, SIZE, SIZE);

      ctx.save();
      ctx.beginPath();
      ctx.arc(CENTER, CENTER, CENTER - 2, 0, Math.PI * 2);
      ctx.clip();

      // 1. SCLERA
      const scleraGrad = ctx.createRadialGradient(CENTER, CENTER, 16, CENTER, CENTER, CENTER);
      scleraGrad.addColorStop(0, '#FFFFFF');
      scleraGrad.addColorStop(0.5, '#F8FAFC');
      scleraGrad.addColorStop(0.75, '#FEE2E2');
      scleraGrad.addColorStop(0.92, '#E2E8F0');
      scleraGrad.addColorStop(1.0, '#CBD5E1');
      ctx.fillStyle = scleraGrad;
      ctx.fillRect(0, 0, SIZE, SIZE);

      // Hemorrhagic corner flushes
      const flushLeft = ctx.createRadialGradient(14, CENTER, 2, 30, CENTER, 90);
      flushLeft.addColorStop(0, 'rgba(220, 38, 38, 0.65)');
      flushLeft.addColorStop(0.6, 'rgba(185, 28, 28, 0.25)');
      flushLeft.addColorStop(1, 'transparent');
      ctx.fillStyle = flushLeft;
      ctx.fillRect(0, 0, SIZE, SIZE);

      const flushRight = ctx.createRadialGradient(SIZE - 14, CENTER, 2, SIZE - 30, CENTER, 90);
      flushRight.addColorStop(0, 'rgba(220, 38, 38, 0.65)');
      flushRight.addColorStop(0.6, 'rgba(185, 28, 28, 0.25)');
      flushRight.addColorStop(1, 'transparent');
      ctx.fillStyle = flushRight;
      ctx.fillRect(0, 0, SIZE, SIZE);

      // Blood capillaries
      primaryVesselsRef.current.forEach((v) => {
        if (v.points.length < 2) return;
        ctx.beginPath();
        ctx.moveTo(v.points[0].x, v.points[0].y);
        for (let i = 1; i < v.points.length; i++) {
          ctx.lineTo(v.points[i].x, v.points[i].y);
        }
        ctx.strokeStyle = v.color;
        ctx.globalAlpha = v.alpha;
        ctx.lineWidth = v.width;
        ctx.lineCap = 'round';
        ctx.lineJoin = 'round';
        ctx.stroke();
      });
      ctx.globalAlpha = 1.0;

      // 2. IRIS & CORNEA POSITION
      const irisX = CENTER + p.curX;
      const irisY = CENTER + p.curY;

      // Glowing limbal ring shadow
      const limbalGlow = ctx.createRadialGradient(irisX, irisY, IRIS_RADIUS - 3, irisX, irisY, IRIS_RADIUS + 6);
      limbalGlow.addColorStop(0, 'transparent');
      limbalGlow.addColorStop(0.6, 'rgba(220, 38, 38, 0.85)');
      limbalGlow.addColorStop(1.0, 'transparent');
      ctx.fillStyle = limbalGlow;
      ctx.beginPath();
      ctx.arc(irisX, irisY, IRIS_RADIUS + 6, 0, Math.PI * 2);
      ctx.fill();

      // Iris base radial gradient
      const irisGrad = ctx.createRadialGradient(irisX, irisY, p.pupilRadius * 0.7, irisX, irisY, IRIS_RADIUS);
      irisGrad.addColorStop(0, '#0F172A');
      irisGrad.addColorStop(0.2, '#0369A1');
      irisGrad.addColorStop(0.55, '#0284C7');
      irisGrad.addColorStop(0.78, '#38BDF8');
      irisGrad.addColorStop(0.92, '#DC2626');
      irisGrad.addColorStop(1.0, '#090D16');
      ctx.fillStyle = irisGrad;
      ctx.beginPath();
      ctx.arc(irisX, irisY, IRIS_RADIUS, 0, Math.PI * 2);
      ctx.fill();

      // Limbal ring stroke
      ctx.strokeStyle = '#020617';
      ctx.lineWidth = 3.5;
      ctx.stroke();

      // Iris muscle fibers
      irisFibersRef.current.forEach((f) => {
        const inR = p.pupilRadius + (IRIS_RADIUS - p.pupilRadius) * f.innerRel;
        const outR = p.pupilRadius + (IRIS_RADIUS - p.pupilRadius) * f.outerRel;
        const x1 = irisX + Math.cos(f.angle) * inR;
        const y1 = irisY + Math.sin(f.angle) * inR;
        const x2 = irisX + Math.cos(f.angle) * outR;
        const y2 = irisY + Math.sin(f.angle) * outR;

        ctx.beginPath();
        ctx.moveTo(x1, y1);
        ctx.lineTo(x2, y2);
        ctx.strokeStyle = f.col;
        ctx.lineWidth = f.width;
        ctx.stroke();
      });

      // Collarette Ring
      ctx.beginPath();
      const collaretteR = p.pupilRadius + (IRIS_RADIUS - p.pupilRadius) * 0.48;
      for (let a = 0; a <= Math.PI * 2; a += 0.08) {
        const wobble = Math.sin(a * 24) * 2.4 + Math.cos(a * 12) * 1.2;
        const cr = collaretteR + wobble;
        const cx = irisX + Math.cos(a) * cr;
        const cy = irisY + Math.sin(a) * cr;
        if (a === 0) ctx.moveTo(cx, cy);
        else ctx.lineTo(cx, cy);
      }
      ctx.closePath();
      ctx.strokeStyle = 'rgba(239, 68, 68, 0.9)';
      ctx.lineWidth = 1.6;
      ctx.stroke();

      // 3. PUPIL
      ctx.fillStyle = '#000000';
      ctx.beginPath();
      ctx.arc(irisX, irisY, Math.max(8, p.pupilRadius), 0, Math.PI * 2);
      ctx.fill();

      const sphincter = ctx.createRadialGradient(irisX, irisY, p.pupilRadius * 0.75, irisX, irisY, p.pupilRadius * 1.25);
      sphincter.addColorStop(0, 'rgba(0,0,0,1)');
      sphincter.addColorStop(0.65, 'rgba(185, 28, 28, 0.45)');
      sphincter.addColorStop(1, 'transparent');
      ctx.fillStyle = sphincter;
      ctx.beginPath();
      ctx.arc(irisX, irisY, p.pupilRadius * 1.25, 0, Math.PI * 2);
      ctx.fill();

      // 4. CORNEAL SPECULAR HIGHLIGHTS
      const glintX = irisX - IRIS_RADIUS * 0.28;
      const glintY = irisY - IRIS_RADIUS * 0.32;
      ctx.save();
      ctx.translate(glintX, glintY);
      ctx.rotate(-0.35);
      ctx.fillStyle = 'rgba(255, 255, 255, 0.96)';
      ctx.beginPath();
      ctx.ellipse(0, 0, 6.5, 3.2, 0, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();

      ctx.fillStyle = 'rgba(255, 255, 255, 0.8)';
      ctx.beginPath();
      ctx.arc(irisX - IRIS_RADIUS * 0.14, irisY - IRIS_RADIUS * 0.12, 1.8, 0, Math.PI * 2);
      ctx.fill();

      ctx.save();
      ctx.translate(irisX + IRIS_RADIUS * 0.32, irisY + IRIS_RADIUS * 0.35);
      ctx.rotate(0.5);
      ctx.fillStyle = 'rgba(220, 38, 38, 0.4)';
      ctx.beginPath();
      ctx.ellipse(0, 0, 5, 2.4, 0, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();

      // 5. ANATOMICAL UPPER EYELID DEPTH SHADOW CAST DOWNWARD
      drawUpperEyelidDepthShadow(ctx, p.curY);

      // 6. DRAW REALISTIC EYELIDS OVER GLOBE
      drawOrganicEyelids(ctx, p.blinkProgress, p.curX, p.curY);

      ctx.restore();

      // Update GAZE_VECTOR readout
      const liveNormX = p.curX / MAX_IRIS_OFFSET;
      const liveNormY = p.curY / MAX_IRIS_OFFSET;
      const vx = liveNormX.toFixed(2);
      const vy = liveNormY.toFixed(2);
      const sx = liveNormX >= 0 ? '+' : '';
      const sy = liveNormY >= 0 ? '+' : '';
      setGazeVector(`[${sx}${vx}, ${sy}${vy}]`);

      animFrameRef.current = requestAnimationFrame(drawEyeFrame);
    };

    animFrameRef.current = requestAnimationFrame(drawEyeFrame);

    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      if (blinkTimer) clearTimeout(blinkTimer);
      if (doubleBlinkTimer) clearTimeout(doubleBlinkTimer);
      if (saccadeTimer) clearTimeout(saccadeTimer);
      if (saccadeResetTimer) clearTimeout(saccadeResetTimer);
      clearInterval(jitterInterval);
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
    };
  }, [CENTER, IRIS_RADIUS, MAX_IRIS_OFFSET, drawOrganicEyelids, drawUpperEyelidDepthShadow, generateBloodVessels, generateIrisFibers, triggerBlink]);

  // Key input typing reactive behavior
  const handleKeyInput = (val: string) => {
    setTokenInput(val);
    setScanMode('HIGH_FREQ_ACQUISITION');
    physicsRef.current.targetPupilRadius = 14;
    physicsRef.current.saccadeOffsetX = (Math.random() - 0.5) * 5;
    physicsRef.current.saccadeOffsetY = (Math.random() - 0.5) * 4;

    if (typingTimeoutRef.current) clearTimeout(typingTimeoutRef.current);
    typingTimeoutRef.current = setTimeout(() => {
      setScanMode('IDLE_SCAN');
      physicsRef.current.targetPupilRadius = 20;
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
        className: 'text-center text-[9px] tracking-[0.14em] text-[#DC2626] bg-[#FEF2F2] border border-[#DC2626]/40 font-bold py-1 min-h-[16px]',
      });
      triggerBlink(80, 140);
    } else {
      setAuthStatus({
        custom: true,
        text: 'AWAITING_BIOMETRIC_TOKEN_VALIDATION // AUTH_CHALLENGE_ID: 981-FC7',
        className: 'text-center text-[9px] tracking-[0.14em] text-[#475569] bg-[#F1F5F9] border border-[#CBD5E1] py-1 font-semibold min-h-[16px]',
      });
    }
  };

  const handleSetMode = (newMode: 'passive' | 'active') => {
    setMode(newMode);
    if (newMode === 'passive') {
      setBiolockStatus('ENGAGED');
      physicsRef.current.targetPupilRadius = 20;
    } else {
      setBiolockStatus('INTRUSION_ALERT');
      physicsRef.current.targetPupilRadius = 28;
      triggerBlink(85, 145);
    }
  };

  // Tactical Reboot Sequence
  const rebootSequence = () => {
    rebootTimersRef.current.forEach(clearTimeout);
    rebootTimersRef.current = [];

    triggerBlink(130, 220);
    generateBloodVessels();
    setBootProgress(10);
    setEngineBadge({
      text: 'COLD_REBOOT_TRIGGERED',
      className: 'text-[9px] px-1.5 py-0.5 bg-[#DC2626]/15 text-[#DC2626] border border-[#DC2626]/50 font-bold',
    });
    setBootDiagLabel('PURGING CRYPTOGRAPHIC SENSORS & FLUSHING BUFFER...');
    setAuthStatus({
      custom: true,
      text: 'SYS_REBOOT_TRIGGERED // RETESTING OPTO-ELECTRONIC MATRIX',
      className: 'text-center text-[9px] tracking-[0.14em] text-[#DC2626] bg-[#FEF2F2] border border-[#DC2626]/40 font-bold py-1 min-h-[16px]',
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
        className: 'text-[9px] px-1.5 py-0.5 bg-[#DC2626]/20 text-[#DC2626] border border-[#DC2626]/60 font-bold',
      });
      setBootDiagLabel('CIPHER_SUITE: CHACHA20-POLY1305 // NEURAL_TAP: SYNCED');
      setAuthStatus({
        custom: true,
        text: 'CALIBRATION COMPLETE // SUBJECT LOCKED // READY FOR JWT INGESTION',
        className: 'text-center text-[9px] tracking-[0.14em] text-[#475569] bg-[#F1F5F9] border border-[#CBD5E1] py-1 font-semibold min-h-[16px]',
      });
      triggerBlink(95, 160);
    }, 1500);

    rebootTimersRef.current.push(t1, t2, t3);
  };

  // Auth Protocol Simulation
  const simulateAuth = useCallback(() => {
    if (isAuthenticating) return;
    setIsAuthenticating(true);

    setFlashOpacity(0.35);
    setTimeout(() => setFlashOpacity(0), 160);

    setButtonText('[ LOCKING IRIS & DERIVING ENCLAVE KEY... ]');
    physicsRef.current.targetPupilRadius = 10;
    triggerBlink(80, 130);

    setAuthStatus({
      custom: true,
      text: 'ACTIVE_PERSON_SCAN: PHOTOMETRIC STEREO MATCHING // EXTRACTING 4096-BIT RETINA HASH...',
      className: 'text-center text-[9px] tracking-[0.14em] text-[#DC2626] bg-[#FEF2F2] border border-[#DC2626]/50 font-bold py-1 min-h-[16px]',
    });
    setBootProgress(90);

    const t1 = setTimeout(() => {
      setAuthStatus({
        custom: true,
        text: 'DERIVING ZERO-KNOWLEDGE PROOF FROM SUBJECT BIOMETRIC ENTROPY...',
        className: 'text-center text-[9px] tracking-[0.14em] text-[#B91C1C] bg-[#FEF2F2] font-mono py-1 min-h-[16px]',
      });
      physicsRef.current.targetPupilRadius = 16;
    }, 900);

    const t2 = setTimeout(() => {
      setBootProgress(100);
      setStages({ step1: true, step2: true, step3: true, step4: true });
      setEngineBadge({
        text: 'DEFCON-5: [ONLINE_ROOT]',
        className: 'text-[9px] px-1.5 py-0.5 bg-[#059669]/15 text-[#047857] border border-[#059669]/40 font-bold',
      });
      setAuthStatus({
        custom: true,
        text: 'ACCESS GRANTED // BIOMETRIC SIGNATURE VERIFIED // ROOT SHELL UNLOCKED',
        className: 'text-center text-[9px] tracking-[0.15em] text-[#047857] bg-[#ECFDF5] py-1 border border-[#059669]/40 font-bold min-h-[16px]',
      });
      setButtonText('[ COCKPIT RUNNING // SESSION ESTABLISHED ✓ ]');
      setIsSuccess(true);
      physicsRef.current.targetPupilRadius = 20;
      triggerBlink(95, 170);

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
      }, 500);
    }, 2100);

    authTimersRef.current.push(t1, t2);
  }, [isAuthenticating, mode, onLoginSuccess, showToast, tokenInput, triggerBlink]);

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

  return (
    <div className="relative flex flex-col justify-between w-full min-h-screen bg-[#FAF8FF] lab-grid-bg text-[#0F172A] select-none p-3 lg:p-4 font-mono overflow-x-hidden">
      {/* Local Scoped Keyframe & Technical Styles */}
      <style>{`
        /* Clinical Millimeter Grid Background */
        .lab-grid-bg {
          background-image: 
            linear-gradient(to right, rgba(15, 23, 42, 0.04) 1px, transparent 1px),
            linear-gradient(to bottom, rgba(15, 23, 42, 0.04) 1px, transparent 1px),
            linear-gradient(to right, rgba(220, 38, 38, 0.03) 1px, transparent 1px),
            linear-gradient(to bottom, rgba(220, 38, 38, 0.03) 1px, transparent 1px);
          background-size: 20px 20px, 20px 20px, 100px 100px, 100px 100px;
        }

        /* Subtle Technical Reticle Vignette */
        .clinical-overlay {
          position: fixed;
          inset: 0;
          pointer-events: none;
          z-index: 45;
          background: radial-gradient(circle at center, transparent 65%, rgba(203, 213, 225, 0.18) 92%, rgba(148, 163, 184, 0.28) 100%),
                      linear-gradient(rgba(15, 23, 42, 0.01) 50%, rgba(255, 255, 255, 0.01) 50%);
          background-size: 100% 100%, 100% 4px;
        }

        /* High-contrast Chromatic Jitter */
        @keyframes chromaticAlert {
          0%, 100% { text-shadow: -1px 0 rgba(220, 38, 38, 0.45), 1px 0 rgba(2, 132, 199, 0.45); }
          20% { text-shadow: -1.5px 0 rgba(220, 38, 38, 0.75), 1.5px 0 rgba(2, 132, 199, 0.75); }
          40% { text-shadow: 1px -0.5px rgba(220, 38, 38, 0.35), -1px 0.5px rgba(5, 150, 105, 0.45); }
          80% { text-shadow: -0.5px 0 rgba(220, 38, 38, 0.5), 0.5px 0 rgba(2, 132, 199, 0.5); }
        }
        .glitch-chroma {
          animation: chromaticAlert 3.5s infinite ease-in-out;
        }

        /* Telemetry stream loops */
        @keyframes streamUp {
          0% { transform: translateY(0); }
          100% { transform: translateY(-50%); }
        }
        .stream-scroll {
          animation: streamUp 16s linear infinite;
        }
        .stream-scroll-fast {
          animation: streamUp 11s linear infinite;
        }

        /* Reticle dial rotations */
        @keyframes ringPulse {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        .hud-dial-spin {
          animation: ringPulse 55s linear infinite;
        }
        @keyframes ringCounterSpin {
          0% { transform: rotate(360deg); }
          100% { transform: rotate(0deg); }
        }
        .hud-dial-counter {
          animation: ringCounterSpin 42s linear infinite;
        }

        /* Terminal Cursor */
        @keyframes cursorPulse {
          0%, 49% { opacity: 1; }
          50%, 100% { opacity: 0; }
        }
        .cli-cursor {
          animation: cursorPulse 0.75s infinite;
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

      {/* Subtle Clinical Optical Vignette */}
      <div className="clinical-overlay"></div>

      {/* Fullscreen flash overlay on biometric capture / unlock */}
      <div
        className="pointer-events-none fixed inset-0 z-50 bg-[#DC2626] transition-opacity duration-300"
        id="flashOverlay"
        style={{ opacity: flashOpacity }}
      ></div>

      {/* ========================================== */}
      {/* 1. TOP HEADER // STERILE CLINICAL DEFENSE LAB HUD */}
      {/* ========================================== */}
      <header className="relative z-30 w-full mb-3">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 items-center bg-white/95 border-2 border-[#CBD5E1] px-4 py-2.5 shadow-[0_4px_20px_rgba(15,23,42,0.06)] backdrop-blur-md">
          {/* Left Section (4 cols): System ID, Kernel & Enclave Diagnostics */}
          <div className="lg:col-span-4 flex flex-col gap-1 text-[11px] tracking-[0.06em]">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="inline-block w-2.5 h-2.5 bg-[#DC2626] animate-ping" id="sysStatusBeacon"></span>
              <span className="text-[#0F172A] font-extrabold tracking-[0.12em] glitch-chroma">
                LAB_ID // DRISHTI_CLINICAL_SYS_V3.1
              </span>
              <span className={engineBadge.className} id="engineBadge">
                {engineBadge.text}
              </span>
            </div>
            <div className="flex items-center gap-2 text-[9.5px] text-[#475569]">
              <span>KERNEL: <span className="text-[#0F172A] font-bold">SEC-ARCH-09.r4</span></span>
              <span className="text-[#059669] font-mono px-1 bg-[#059669]/10 border border-[#059669]/30 font-semibold">[SELINUX_ENFORCING]</span>
              <span className="text-[#0284C7] font-mono px-1 bg-[#0284C7]/10 border border-[#0284C7]/30 font-semibold">[RPC_TLS1.3]</span>
              <span className="text-[#64748B]">CYCLE: <span className="text-[#0F172A] font-bold" id="telemetryCycle">{telemetryCycle}</span></span>
            </div>
          </div>

          {/* Center Section (5 cols): Boot Stage Cards & Hacker Diagnostics Bar */}
          <div className="lg:col-span-5 flex flex-col gap-1.5 items-center justify-center">
            <div className="grid grid-cols-4 w-full gap-2 text-[9px] tracking-[0.05em] font-mono">
              {/* Stage 1 */}
              <div
                className={`px-1 py-1 text-center flex items-center justify-center gap-1 shadow-sm ${
                  stages.step1
                    ? 'bg-[#F1F5F9] border border-[#059669]/50'
                    : 'bg-[#F1F5F9] border border-[#CBD5E1] text-[#64748B]'
                }`}
                id="step1"
              >
                <span className={stages.step1 ? 'text-[#047857] font-bold' : 'text-[#64748B] font-bold'}>01:CRYPTO</span>
                {stages.step1 && <span className="text-[#059669] font-bold">✓</span>}
              </div>

              {/* Stage 2 */}
              <div
                className={`px-1 py-1 text-center flex items-center justify-center gap-1 shadow-sm ${
                  stages.step2
                    ? 'bg-[#F1F5F9] border border-[#059669]/50'
                    : 'bg-[#F1F5F9] border border-[#CBD5E1] text-[#64748B]'
                }`}
                id="step2"
              >
                <span className={stages.step2 ? 'text-[#047857] font-bold' : 'text-[#64748B] font-bold'}>02:NEURAL</span>
                {stages.step2 && <span className="text-[#059669] font-bold">✓</span>}
              </div>

              {/* Stage 3 (Active or Verified) */}
              <div
                className={`px-1 py-1 text-center flex items-center justify-center gap-1 ${
                  stages.step4
                    ? 'bg-[#F1F5F9] border border-[#059669]/50 shadow-sm'
                    : stages.step3
                    ? 'bg-[#FEF2F2] border-2 border-[#DC2626] shadow-[0_0_10px_rgba(220,38,38,0.2)]'
                    : 'bg-[#F1F5F9] border border-[#CBD5E1]'
                }`}
                id="step3"
              >
                <span className={stages.step4 ? 'text-[#047857] font-bold' : stages.step3 ? 'text-[#DC2626] font-bold' : 'text-[#64748B] font-bold'}>
                  03:BIOMETRIC
                </span>
                {stages.step4 ? (
                  <span className="text-[#059669] font-bold">✓</span>
                ) : stages.step3 ? (
                  <span className="text-[#DC2626] font-bold animate-pulse">●</span>
                ) : null}
              </div>

              {/* Stage 4 */}
              <div
                className={`px-1 py-1 text-center flex items-center justify-center gap-1 ${
                  stages.step4
                    ? 'bg-[#ECFDF5] border-2 border-[#059669] shadow-[0_0_12px_rgba(5,150,105,0.25)]'
                    : 'bg-[#F1F5F9] border border-[#CBD5E1] shadow-sm'
                }`}
                id="step4"
              >
                <span className={stages.step4 ? 'text-[#047857] font-bold' : 'text-[#64748B] font-bold'}>
                  04:COCKPIT {stages.step4 && '✓'}
                </span>
              </div>
            </div>

            {/* Progress track & Micro diagnostic readouts */}
            <div className="w-full flex flex-col gap-0.5">
              <div className="w-full h-1.5 bg-[#E2E8F0] border border-[#CBD5E1] relative overflow-hidden flex">
                <div
                  className="h-full bg-[#059669] transition-all duration-300"
                  id="bootProgressBar"
                  style={{ width: `${bootProgress}%` }}
                ></div>
              </div>
              <div className="flex items-center justify-between text-[8px] tracking-wider w-full text-[#475569]">
                <span className="text-[#334155] font-mono font-medium truncate max-w-[280px]" id="bootDiagLabel">
                  {bootDiagLabel}
                </span>
                <span className="text-[#DC2626] font-bold font-mono">
                  {bootProgress.toFixed(1)}% CAPTURE
                </span>
              </div>
            </div>
          </div>

          {/* Right Section (3 cols): Exploits, Live Distance, Re-Calibrate Trigger */}
          <div className="lg:col-span-3 flex flex-col items-end gap-1.5 text-[10px]">
            <div className="flex items-center gap-2">
              <span className="text-[8.5px] px-1.5 py-0.5 bg-[#059669]/10 text-[#047857] border border-[#059669]/40 font-bold">
                PAYLOADS: 0
              </span>
              <span className="text-[#475569]">
                DIST: <span className="text-[#0F172A] font-bold font-mono" id="subjectDistance">{depth}</span>
              </span>
              <span className="text-[9px] px-1.5 py-0.5 bg-[#DC2626]/15 text-[#DC2626] border border-[#DC2626]/60 font-bold tracking-wider animate-pulse" id="lockStatusBadge">
                [TARGET_LOCKED]
              </span>
            </div>
            <div>
              <button
                type="button"
                className="flex items-center gap-1.5 text-[9px] text-[#334155] hover:text-[#DC2626] px-2.5 py-1 border border-[#CBD5E1] hover:border-[#DC2626] bg-white hover:bg-[#FEF2F2] transition-all cursor-pointer shadow-sm font-mono font-semibold"
                onClick={rebootSequence}
                title="Re-run engine self-test and camera sweep"
              >
                <span className="text-[#DC2626]">⚡</span>
                <span>REBOOT_OPTO_MATRIX</span>
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* ========================================== */}
      {/* 2. CENTER STAGE: OCULAR APERTURE + CLINICAL FLANKS */}
      {/* ========================================== */}
      <main className="relative z-30 flex flex-col items-center justify-center flex-1 w-full my-auto overflow-hidden py-1">
        {/* Status Bar Pill above eye */}
        <div className="flex items-center gap-4 text-[9px] tracking-[0.14em] text-[#475569] pointer-events-none bg-white/95 px-5 py-1.5 border border-[#CBD5E1] mb-2 shadow-[0_2px_12px_rgba(15,23,42,0.06)] backdrop-blur-sm">
          <span>SUBJECT: <span className="text-[#0284C7] font-bold" id="subjectStatusText">HUMAN_HOST_ACTIVE</span></span>
          <span className="text-[#CBD5E1]">|</span>
          <span>CONFIDENCE: <span className="text-[#0F172A] font-bold font-mono" id="confVal">99.14%</span></span>
          <span className="text-[#CBD5E1]">|</span>
          <span>FIREWALL: <span className="text-[#DC2626] font-bold">L5_OVERRIDE</span></span>
          <span className="text-[#CBD5E1]">|</span>
          <span>LIVENESS: <span className="text-[#059669] font-bold font-mono" id="livenessVal">0.998</span></span>
        </div>

        {/* Main Biometric Stage with Lateral Data Streams & Spaced Metrics */}
        <div className="relative w-full max-w-7xl flex items-center justify-center px-4 gap-6 xl:gap-8">
          {/* LEFT FLANK: Clinical Scrolling Memory Hex Dump */}
          <aside className="hidden xl:flex flex-col w-[210px] h-[330px] border-2 border-[#CBD5E1] bg-white/95 p-2.5 overflow-hidden shadow-[0_4px_16px_rgba(15,23,42,0.05)] text-[8px] font-mono leading-relaxed relative shrink-0">
            <div className="flex items-center justify-between border-b border-[#E2E8F0] pb-1.5 mb-1.5 text-[8.5px] font-bold tracking-wider">
              <div className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-[#DC2626] animate-ping"></span>
                <span className="text-[#DC2626]">// MEM_DUMP_0x7FFF</span>
              </div>
              <span className="text-[7.5px] px-1 bg-[#DC2626]/10 text-[#DC2626] border border-[#DC2626]/30">L1_CACHE</span>
            </div>
            <div className="relative flex-1 overflow-hidden">
              <div className="stream-scroll space-y-1 text-[#475569]">
                <div className="flex justify-between"><span className="text-[#64748B]">0x7FFF89A2:</span> <span className="text-[#0F172A] font-medium">48 89 E5 48</span></div>
                <div className="flex justify-between"><span className="text-[#64748B]">0x7FFF89AA:</span> <span className="text-[#0F172A] font-medium">E8 24 FF FF</span></div>
                <div className="flex justify-between"><span className="text-[#DC2626] font-semibold">OVERFLOW_GUARD:</span> <span className="text-[#059669] font-bold">ACTIVE</span></div>
                <div className="flex justify-between"><span className="text-[#64748B]">0x7FFF89B2:</span> <span className="text-[#0F172A] font-medium">55 48 89 E5</span></div>
                <div className="flex justify-between"><span className="text-[#64748B]">0x7FFF89BA:</span> <span className="text-[#0F172A] font-medium">41 56 41 55</span></div>
                <div className="flex justify-between"><span className="text-[#0284C7] font-semibold">ROOT_INJECT:</span> <span className="text-[#DC2626] font-bold">BLOCKED</span></div>
                <div className="flex justify-between"><span className="text-[#64748B]">0x7FFF89C2:</span> <span className="text-[#0F172A] font-medium">B8 01 00 00</span></div>
                <div className="flex justify-between"><span className="text-[#64748B]">0x7FFF89CA:</span> <span className="text-[#0F172A] font-medium">05 48 3D 00</span></div>
                <div className="flex justify-between"><span className="text-[#64748B]">0x7FFF89D2:</span> <span className="text-[#0F172A] font-medium">77 1B 48 89</span></div>
                <div className="flex justify-between"><span className="text-[#DC2626]">INTERRUPT:</span> <span className="text-[#991B1B] font-bold">SIGSEGV</span></div>
                <div className="flex justify-between"><span className="text-[#64748B]">0x7FFF89DA:</span> <span className="text-[#0F172A] font-medium">31 C0 C9 C3</span></div>
                <div className="flex justify-between"><span className="text-[#059669]">CRYPTO_NONCE:</span> <span className="text-[#059669] font-bold">0xFA49E2D</span></div>
                <div className="flex justify-between"><span className="text-[#64748B]">0x7FFF89EA:</span> <span className="text-[#0F172A] font-medium">48 83 EC 08</span></div>
                <div className="flex justify-between"><span className="text-[#64748B]">0x7FFF89A2:</span> <span className="text-[#0F172A] font-medium">48 89 E5 48</span></div>
                <div className="flex justify-between"><span className="text-[#64748B]">0x7FFF89AA:</span> <span className="text-[#0F172A] font-medium">E8 24 FF FF</span></div>
                <div className="flex justify-between"><span className="text-[#DC2626] font-semibold">OVERFLOW_GUARD:</span> <span className="text-[#059669] font-bold">ACTIVE</span></div>
                <div className="flex justify-between"><span className="text-[#64748B]">0x7FFF89B2:</span> <span className="text-[#0F172A] font-medium">55 48 89 E5</span></div>
              </div>
            </div>
            <div className="mt-1.5 pt-1.5 border-t border-[#E2E8F0] text-[7.5px] text-[#475569] flex justify-between items-center font-semibold">
              <span>HEAP: <span className="text-[#0F172A]">42.1MB</span></span>
              <span className="text-[#059669]">CANARY: SECURE</span>
            </div>
          </aside>

          {/* LEFT BIOMETRIC READOUT PANEL */}
          <div className="hidden lg:flex flex-col justify-center w-[165px] gap-2.5 text-[9px] text-[#475569] font-mono tracking-wider text-left bg-white/80 p-3 border border-[#CBD5E1] shadow-sm shrink-0">
            <div className="border-b border-[#E2E8F0] pb-1 text-[8px] font-bold text-[#DC2626] tracking-widest">// OPTO_ACQUISITION</div>
            <div>
              <span className="text-[#64748B] block text-[8px]">FACIAL_DEPTH</span>
              <span className="text-[#0F172A] font-bold" id="depthVal">{depth}</span>
            </div>
            <div>
              <span className="text-[#64748B] block text-[8px]">IRIS_SCAN</span>
              <span className="text-[#DC2626] font-bold" id="irisScanVal">{irisScan} MATCH</span>
            </div>
            <div>
              <span className="text-[#64748B] block text-[8px]">PUPIL_DILATION</span>
              <span className="text-[#0F172A] font-bold" id="pupilDilVal">{pupilDil}</span>
            </div>
            <div>
              <span className="text-[#64748B] block text-[8px]">IPD_METRIC</span>
              <span className="text-[#334155] font-semibold" id="ipdVal">63.8mm</span>
            </div>
            <div>
              <span className="text-[#64748B] block text-[8px]">VESSEL_HASH</span>
              <span className="text-[#DC2626] font-mono font-bold">0x9E4B..7A</span>
            </div>
            <div>
              <span className="text-[#64748B] block text-[8px]">SACCADE_FRQ</span>
              <span className="text-[#0284C7] font-bold">3.4Hz</span>
            </div>
          </div>

          {/* CENTER: ULTRA-SHARP CLINICAL OCULAR ARENA */}
          <div className="relative w-[380px] sm:w-[410px] h-[390px] flex items-center justify-center shrink-0" id="scanArena" ref={arenaRef}>
            {/* Reticle Orientation Tags */}
            <div className="absolute -top-3 text-[8px] font-mono tracking-widest text-[#DC2626] font-bold pointer-events-none select-none bg-white/90 px-2 py-0.5 border border-[#DC2626]/30">
              AZM 000° // NORTH [PREDATOR_ACQ]
            </div>
            <div className="absolute -bottom-3 text-[8px] font-mono tracking-widest text-[#475569] font-medium pointer-events-none select-none bg-white/90 px-2 py-0.5 border border-[#CBD5E1]">
              AZM 180° // SOUTH [LOCKED]
            </div>

            {/* Subtle Rotating Calibration Circles */}
            <div className="absolute w-[390px] h-[390px] rounded-full border border-dashed border-[#0284C7]/30 pointer-events-none hud-dial-spin"></div>
            <div className="absolute w-[370px] h-[370px] rounded-full border border-[#DC2626]/25 pointer-events-none hud-dial-counter"></div>
            <div className="absolute w-[350px] h-[350px] rounded-full border border-[#CBD5E1] pointer-events-none"></div>

            {/* Outer Clinical Lens Bezel with Tick Marks */}
            <div className="relative w-[330px] h-[330px] rounded-full p-2 bg-[#F1F5F9] border-2 border-[#CBD5E1] shadow-[0_12px_35px_rgba(15,23,42,0.12),0_0_0_1px_rgba(255,255,255,0.8)_inset] flex items-center justify-center z-20">
              {/* Precision Millimeter Reticle SVG Overlay */}
              <svg className="absolute inset-0 w-full h-full pointer-events-none z-30" viewBox="0 0 330 330">
                <circle cx="165" cy="165" fill="none" opacity="0.65" r="158" stroke="#DC2626" strokeDasharray="3 6" strokeWidth="1.5"></circle>
                <circle cx="165" cy="165" fill="none" opacity="0.4" r="150" stroke="#0284C7" strokeWidth="0.8"></circle>
                <line stroke="#DC2626" strokeWidth="2" x1="165" x2="165" y1="4" y2="16"></line>
                <line stroke="#DC2626" strokeWidth="2" x1="165" x2="165" y1="314" y2="326"></line>
                <line stroke="#DC2626" strokeWidth="2" x1="4" x2="16" y1="165" y2="165"></line>
                <line stroke="#DC2626" strokeWidth="2" x1="314" x2="326" y1="165" y2="165"></line>
                <circle cx="165" cy="165" fill="none" opacity="0.5" r="154" stroke="#64748B" strokeDasharray="1 11" strokeWidth="1.5"></circle>
              </svg>

              {/* The Eyeball Housing */}
              <div className="relative w-[314px] h-[314px] rounded-full overflow-hidden bg-[#FAF8FF] border-2 border-[#DC2626] shadow-[0_0_35px_rgba(220,38,38,0.25),inset_0_0_40px_rgba(15,23,42,0.3)] flex items-center justify-center" id="eyeOrbit">
                <canvas
                  className="absolute inset-0 w-full h-full block z-20"
                  height={314}
                  id="eyeCanvas"
                  ref={canvasRef}
                  width={314}
                ></canvas>
                {/* Corneal Glass Gloss Vignette Overlay */}
                <div className="absolute inset-0 rounded-full shadow-[inset_0_0_25px_rgba(0,0,0,0.4),inset_0_18px_20px_rgba(255,255,255,0.45)] pointer-events-none z-26"></div>
              </div>
            </div>
          </div>

          {/* RIGHT BIOMETRIC READOUT PANEL */}
          <div className="hidden lg:flex flex-col justify-center w-[165px] gap-2.5 text-[9px] text-[#475569] font-mono tracking-wider text-right bg-white/80 p-3 border border-[#CBD5E1] shadow-sm shrink-0">
            <div className="border-b border-[#E2E8F0] pb-1 text-[8px] font-bold text-[#0284C7] tracking-widest">// ENCLAVE_CORRELATION</div>
            <div>
              <span className="text-[#64748B] block text-[8px]">CORNEA_REFRACT</span>
              <span className="text-[#059669] font-bold">PASS // NOMINAL</span>
            </div>
            <div>
              <span className="text-[#64748B] block text-[8px]">BIOMETRIC_LOCK</span>
              <span className="text-[#DC2626] font-bold" id="biolockStatus">{biolockStatus}</span>
            </div>
            <div>
              <span className="text-[#64748B] block text-[8px]">GAZE_VECTOR</span>
              <span className="text-[#0F172A] font-mono font-bold" id="gazeVectorVal">{gazeVector}</span>
            </div>
            <div>
              <span className="text-[#64748B] block text-[8px]">SPECTRAL_IR</span>
              <span className="text-[#DC2626] font-bold">COHERENT</span>
            </div>
            <div>
              <span className="text-[#64748B] block text-[8px]">TRIANGULATION</span>
              <span className="text-[#059669] font-bold">LOCKED</span>
            </div>
            <div>
              <span className="text-[#64748B] block text-[8px]">ENTROPY_POOL</span>
              <span className="text-[#0F172A] font-mono font-bold">0x88F1</span>
            </div>
          </div>

          {/* RIGHT FLANK: Clinical Ethernet Packet Sniffer */}
          <aside className="hidden xl:flex flex-col w-[210px] h-[330px] border-2 border-[#CBD5E1] bg-white/95 p-2.5 overflow-hidden shadow-[0_4px_16px_rgba(15,23,42,0.05)] text-[8px] font-mono leading-relaxed relative shrink-0">
            <div className="flex items-center justify-between border-b border-[#E2E8F0] pb-1.5 mb-1.5 text-[8.5px] font-bold tracking-wider">
              <div className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-[#0284C7] animate-ping"></span>
                <span className="text-[#0284C7]">// PKT_SNIFFER_ETH0</span>
              </div>
              <span className="text-[7.5px] px-1 bg-[#0284C7]/10 text-[#0284C7] border border-[#0284C7]/30">PROMISC</span>
            </div>
            <div className="relative flex-1 overflow-hidden">
              <div className="stream-scroll-fast space-y-1 text-[#475569]">
                <div className="flex justify-between"><span className="text-[#0284C7] font-medium">TCP/SYN</span> <span className="text-[#0F172A]">192.168.1.10:443</span></div>
                <div className="flex justify-between"><span className="text-[#059669]">SHA256:</span> <span className="text-[#334155] font-mono">a94a8fe5..ba6</span></div>
                <div className="flex justify-between"><span className="text-[#DC2626]">ECDSA:</span> <span className="text-[#059669] font-bold">SIGN_VERIFIED</span></div>
                <div className="flex justify-between"><span className="text-[#64748B]">AEAD_TAG:</span> <span className="text-[#0F172A] font-bold">c029f635</span></div>
                <div className="flex justify-between"><span className="text-[#0284C7]">DNS_TUNNEL:</span> <span className="text-[#059669] font-bold">ZERO_LEAKS</span></div>
                <div className="flex justify-between"><span className="text-[#64748B]">PORT_80:</span> <span className="text-[#DC2626] font-bold">REJECT_ALL</span></div>
                <div className="flex justify-between"><span className="text-[#DC2626]">MITM_CHECK:</span> <span className="text-[#059669] font-bold">PIN_VALID</span></div>
                <div className="flex justify-between"><span className="text-[#059669]">DIFFIE_HELLMAN:</span> <span className="text-[#0F172A] font-bold">X25519</span></div>
                <div className="flex justify-between"><span className="text-[#64748B]">PKT_DROP_RATE:</span> <span className="text-[#059669] font-bold">0.0000%</span></div>
                <div className="flex justify-between"><span className="text-[#DC2626]">PAYLOAD_LEN:</span> <span className="text-[#0F172A]">512_BYTES</span></div>
                <div className="flex justify-between"><span className="text-[#0284C7]">ENCLAVE_TOKEN:</span> <span className="text-[#0284C7] font-bold">0x89FC</span></div>
                <div className="flex justify-between"><span className="text-[#0284C7] font-medium">TCP/SYN</span> <span className="text-[#0F172A]">192.168.1.10:443</span></div>
                <div className="flex justify-between"><span className="text-[#059669]">SHA256:</span> <span className="text-[#334155] font-mono">a94a8fe5..ba6</span></div>
                <div className="flex justify-between"><span className="text-[#DC2626]">ECDSA:</span> <span className="text-[#059669] font-bold">SIGN_VERIFIED</span></div>
              </div>
            </div>
            <div className="mt-1.5 pt-1.5 border-t border-[#E2E8F0] text-[7.5px] text-[#475569] flex justify-between items-center font-semibold">
              <span>THROUGHPUT: <span className="text-[#0F172A]">2.8 MB/s</span></span>
              <span className="text-[#0284C7]">MTU: 1500</span>
            </div>
          </aside>
        </div>

        {/* ========================================== */}
        {/* 3. CLINICAL CLI AUTHENTICATION TERMINAL PROMPT */}
        {/* ========================================== */}
        <div className="relative z-30 w-full max-w-[560px] mt-3 flex flex-col gap-2 px-3">
          {/* Mode Switchers */}
          <div className="flex items-center justify-between px-1 text-[9.5px] tracking-[0.08em] font-semibold">
            <button
              type="button"
              className={`flex items-center gap-1.5 cursor-pointer transition-colors ${
                mode === 'passive' ? 'text-[#0F172A]' : 'text-[#64748B] hover:text-[#0284C7]'
              }`}
              id="togglePassive"
              onClick={() => handleSetMode('passive')}
            >
              <span className="text-[#0284C7] font-bold">[</span>
              <span className={mode === 'passive' ? 'text-[#0284C7]' : 'text-[#94A3B8]'} id="dotPassive">
                {mode === 'passive' ? '●' : '○'}
              </span>
              <span>FULL_PASSIVE_RECON</span>
              <span className="text-[#0284C7] font-bold">]</span>
            </button>
            <button
              type="button"
              className={`flex items-center gap-1.5 cursor-pointer transition-colors ${
                mode === 'active' ? 'text-[#0F172A]' : 'text-[#64748B] hover:text-[#DC2626]'
              }`}
              id="toggleActive"
              onClick={() => handleSetMode('active')}
            >
              <span className="text-[#94A3B8]">[</span>
              <span className={mode === 'active' ? 'text-[#DC2626]' : 'text-[#94A3B8]'} id="dotActive">
                {mode === 'active' ? '●' : '○'}
              </span>
              <span>ACTIVE_INTRUSION_GUARD</span>
              <span className="text-[#94A3B8]">]</span>
            </button>
          </div>

          {/* Terminal Command Frame */}
          <div className="relative w-full bg-[#0F172A] border-2 border-[#1E293B] shadow-[0_6px_25px_rgba(15,23,42,0.18)] p-3 flex flex-col gap-2 text-white">
            <div className="flex items-center justify-between text-[9px] text-[#94A3B8] border-b border-[#334155] pb-1.5">
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-[#DC2626]"></span>
                <span className="w-2 h-2 rounded-full bg-[#F59E0B]"></span>
                <span className="w-2 h-2 rounded-full bg-[#059669]"></span>
                <span className="text-white font-bold ml-1 font-mono">OPERATOR_AUTH // SECURE_ENCLAVE</span>
              </div>
              <div className="flex items-center gap-1 text-[8.5px]">
                <span className="text-[#94A3B8]">STATUS:</span>
                <span
                  className={
                    scanMode === 'HIGH_FREQ_ACQUISITION'
                      ? 'text-[#DC2626] font-extrabold tracking-tighter animate-pulse'
                      : 'text-[#94A3B8] font-bold tracking-wider'
                  }
                  id="scanModeIndicator"
                >
                  {scanMode}
                </span>
              </div>
            </div>

            <div className="flex items-center gap-2 text-[11px] font-mono pt-0.5">
              <span className="text-[#34D399] font-bold whitespace-nowrap select-none">root@drishti-core:~# ./auth_operator --token</span>
              <input
                autoComplete="off"
                className="w-full bg-transparent text-[#F8FAFC] font-mono font-medium tracking-wider outline-none border-none p-0 text-[11px] placeholder-[#64748B] focus:ring-0"
                id="operatorInput"
                onBlur={() => handleInputFocus(false)}
                onFocus={() => handleInputFocus(true)}
                onInput={(e: any) => handleKeyInput(e.target.value)}
                placeholder="INPUT_JWT_SIGNATURE..."
                spellCheck={false}
                type="text"
                value={tokenInput}
              />
              <span className="text-[#DC2626] cli-cursor font-bold select-none text-[13px]">█</span>
            </div>

            <div className="flex items-center justify-between pt-1 text-[8px] text-[#94A3B8] border-t border-[#1E293B]">
              <div className="flex items-center gap-1.5 overflow-x-auto">
                <span className="text-[#64748B] select-none font-bold">FLAGS:</span>
                <button
                  type="button"
                  className="px-1.5 py-0.5 bg-[#1E293B] border border-[#334155] hover:border-[#DC2626] hover:text-white transition-colors cursor-pointer"
                  onClick={() => appendFlag('--bypass-sandbox')}
                >
                  [--bypass-sandbox]
                </button>
                <button
                  type="button"
                  className="px-1.5 py-0.5 bg-[#1E293B] border border-[#334155] hover:border-[#DC2626] hover:text-white transition-colors cursor-pointer"
                  onClick={() => appendFlag('--force-recon')}
                >
                  [--force-recon]
                </button>
                <button
                  type="button"
                  className="px-1.5 py-0.5 bg-[#1E293B] border border-[#334155] hover:border-[#DC2626] hover:text-white transition-colors cursor-pointer"
                  onClick={() => appendFlag('--debug-dump')}
                >
                  [--debug-dump]
                </button>
              </div>
              <span className="text-[#64748B] font-mono text-[7.5px] select-none">AUTH_CHALLENGE // 981-FC7</span>
            </div>
          </div>

          {/* Execute Button */}
          <button
            type="button"
            className={`w-full h-[40px] font-mono text-[11.5px] font-bold tracking-[0.16em] flex items-center justify-center gap-2 transition-all cursor-pointer ${
              isSuccess
                ? 'bg-[#059669] hover:bg-[#047857] border-2 border-[#047857] text-white shadow-[0_4px_14px_rgba(5,150,105,0.35)]'
                : 'bg-[#DC2626] hover:bg-[#B91C1C] active:bg-[#991B1B] border-2 border-[#991B1B] text-white shadow-[0_4px_14px_rgba(220,38,38,0.35)] hover:shadow-[0_6px_20px_rgba(220,38,38,0.5)]'
            }`}
            disabled={isAuthenticating}
            id="authBtn"
            onClick={simulateAuth}
          >
            <span className="text-white font-black">▶</span>
            <span id="authButtonText">{buttonText}</span>
            <span className={`w-2 h-2 bg-white animate-ping ${isAuthenticating && !isSuccess ? '' : 'hidden'}`} id="authSpinner"></span>
          </button>

          {authStatus.custom ? (
            <div className={authStatus.className} id="authStatus">
              {authStatus.text}
            </div>
          ) : (
            <div className="flex items-center justify-between px-1 text-[8.5px] tracking-[0.12em] font-mono text-[#64748B] min-h-[16px]" id="authStatus">
              <span className="text-[#059669] font-bold">BIOMETRIC_CORE // SECURE_ENCLAVE_READY</span>
              <span className="text-[#475569]">PRESS ⌘+ENTER TO AUTHENTICATE</span>
            </div>
          )}
        </div>
      </main>

      {/* ========================================== */}
      {/* 4. BOTTOM CLINICAL FOOTER & HARDWARE SPECS */}
      {/* ========================================== */}
      <footer className="relative z-30 flex flex-col items-center justify-end w-full pb-1 pt-3">
        {/* Active Status LED Triad Bar */}
        <div className="flex items-center gap-6 mb-1 text-[8.5px] font-mono tracking-widest text-[#475569]">
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#DC2626] animate-pulse"></span>
            <span className="text-[#DC2626] font-bold">RED: RECON_ACTIVE</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#D97706]"></span>
            <span className="text-[#B45309] font-bold">AMBER: BUFFER_LOCK</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#059669]"></span>
            <span className="text-[#047857] font-bold">GREEN: CRYPTO_VALID</span>
          </div>
        </div>

        {/* Brand Typography with Clinical Red Contrast */}
        <div className="mb-1 text-center">
          <div className="glitch-chroma text-[15px] md:text-[17px] font-black text-[#0F172A] tracking-[0.35em]">
            D R I S H T I &nbsp;&nbsp;//&nbsp;&nbsp; V I S I O N &nbsp;&nbsp; C 2
          </div>
          <div className="text-[8.5px] tracking-[0.25em] text-[#64748B] font-semibold mt-0.5">
            HIGH-CONTAINMENT ZERO TRUST CLINICAL OCULAR DEFENSE MATRIX // PROTOCOL 09
          </div>
        </div>

        {/* Technical Spec Barcode and Hardware Hashes */}
        <div className="w-full max-w-6xl border-t-2 border-[#CBD5E1] pt-2 pb-1 px-4 flex flex-wrap items-center justify-between text-[8px] tracking-[0.08em] font-mono text-[#475569] gap-2 bg-white/70">
          <div className="flex flex-col">
            <span className="text-[#64748B] font-semibold">SHA-256 ENCLAVE FINGERPRINT</span>
            <span className="text-[#0F172A] font-bold">e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</span>
          </div>
          <div className="flex flex-col">
            <span className="text-[#64748B] font-semibold">DNS CHALLENGE STATUS</span>
            <span className="text-[#0284C7] font-bold" id="dnsChallengeStatus">ACME_V02 [RESOLVED // SECURE]</span>
          </div>
          <div className="flex flex-col">
            <span className="text-[#64748B] font-semibold">HSM ENCLAVE ATTESTATION</span>
            <span className="text-[#0F172A] font-bold" id="enclaveAttest">NITRO_ENCLAVE_V4 // VERIFIED</span>
          </div>
          <div className="flex items-center gap-2 pl-3 border-l-2 border-[#CBD5E1]">
            <div className="barcode-strip text-[#0F172A] font-bold">|||| || ||| | ||||</div>
            <span className="text-[7.5px] text-[#DC2626] font-extrabold">SEC-09</span>
          </div>
        </div>
      </footer>
    </div>
  );
};
