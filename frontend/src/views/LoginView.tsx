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
  const eyelidUpperRef = useRef<HTMLDivElement | null>(null);
  const eyelidLowerRef = useRef<HTMLDivElement | null>(null);
  const arenaRef = useRef<HTMLDivElement | null>(null);
  const animFrameRef = useRef<number | null>(null);
  const typingTimeoutRef = useRef<any>(null);
  const rebootTimersRef = useRef<any[]>([]);
  const authTimersRef = useRef<any[]>([]);

  // Eye Physics Parameters (Exact match to code.html)
  const SIZE = 380;
  const CENTER = SIZE / 2; // 190
  const IRIS_RADIUS = 76;

  const physicsRef = useRef({
    mouseX: typeof window !== 'undefined' ? window.innerWidth / 2 : 700,
    mouseY: typeof window !== 'undefined' ? window.innerHeight / 2 : 400,
    curX: 0,
    curY: 0,
    targetX: 0,
    targetY: 0,
    saccadeOffsetX: 0,
    saccadeOffsetY: 0,
    pupilRadius: 24,
    targetPupilRadius: 24,
    pupilTwitch: 0,
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

  // Generate refined, minimal vascular network (delicate clinical eye capillaries)
  const generateBloodVessels = useCallback(() => {
    const list: typeof primaryVesselsRef.current = [];
    const vesselCount = 10;
    for (let i = 0; i < vesselCount; i++) {
      const angle = (i / vesselCount) * Math.PI * 2 + (Math.random() * 0.15 - 0.075);
      const outerR = CENTER * 0.98;
      const innerR = IRIS_RADIUS * 1.15 + Math.random() * 20;
      const points = [];
      let r = outerR;
      let a = angle;
      while (r > innerR) {
        points.push({
          x: CENTER + Math.cos(a) * r,
          y: CENTER + Math.sin(a) * r,
        });
        r -= 6 + Math.random() * 4;
        a += (Math.random() - 0.5) * 0.22;
      }
      list.push({
        points,
        width: 0.5 + Math.random() * 0.4,
        color: Math.random() > 0.4 ? '#BA2415' : '#E63926',
        alpha: 0.35 + Math.random() * 0.20,
      });
    }

    // Secondary fine capillary accents (very few, subtle)
    for (let j = 0; j < 5; j++) {
      const angle = Math.random() * Math.PI * 2;
      const outerR = CENTER * 0.95;
      const innerR = IRIS_RADIUS * 1.30;
      const points = [];
      let r = outerR;
      let a = angle;
      while (r > innerR) {
        points.push({
          x: CENTER + Math.cos(a) * r,
          y: CENTER + Math.sin(a) * r,
        });
        r -= 5;
        a += (Math.random() - 0.5) * 0.25;
      }
      list.push({
        points,
        width: 0.35 + Math.random() * 0.25,
        color: '#E63926',
        alpha: 0.25 + Math.random() * 0.15,
      });
    }
    primaryVesselsRef.current = list;
  }, [CENTER, IRIS_RADIUS]);

  // Pre-generate hyper-detailed iris fibers (520 radial fibers)
  const generateIrisFibers = useCallback(() => {
    const list: typeof irisFibersRef.current = [];
    const FIBER_COUNT = 520;
    for (let f = 0; f < FIBER_COUNT; f++) {
      const angle = (f / FIBER_COUNT) * Math.PI * 2 + (Math.random() * 0.008);
      const innerRel = 0.22 + Math.random() * 0.12;
      const outerRel = 0.98 - Math.random() * 0.03;
      const roll = Math.random();
      let col: string;
      if (roll > 0.84) {
        col = 'rgba(230, 57, 38, 0.88)'; // screenprint vermilion
      } else if (roll > 0.52) {
        col = 'rgba(2, 132, 199, 0.8)';  // piercing cobalt
      } else if (roll > 0.25) {
        col = 'rgba(245, 242, 235, 0.9)'; // warm eggshell
      } else {
        col = 'rgba(17, 18, 22, 0.88)';  // deep carbon ink
      }
      list.push({
        angle,
        innerRel,
        outerRel,
        col,
        width: 0.65 + Math.random() * 1.1,
      });
    }
    irisFibersRef.current = list;
  }, []);

  // Blinking reflex trigger
  const triggerBlink = useCallback((duration = 90) => {
    const upper = eyelidUpperRef.current;
    const lower = eyelidLowerRef.current;
    if (!upper || !lower) return;
    upper.style.transform = 'translateY(0%)';
    lower.style.transform = 'translateY(0%)';
    setTimeout(() => {
      if (upper && lower) {
        upper.style.transform = 'translateY(-101%)';
        lower.style.transform = 'translateY(101%)';
      }
    }, duration);
  }, []);

  // Main canvas animation and loop setup
  useEffect(() => {
    generateBloodVessels();
    generateIrisFibers();

    const handleMouseMove = (e: MouseEvent) => {
      physicsRef.current.mouseX = e.clientX;
      physicsRef.current.mouseY = e.clientY;
    };
    window.addEventListener('mousemove', handleMouseMove);

    // Blinking schedule
    let blinkTimer: any;
    const scheduleNextBlink = () => {
      const delay = 3500 + Math.random() * 5500;
      blinkTimer = setTimeout(() => {
        triggerBlink(75 + Math.random() * 35);
        scheduleNextBlink();
      }, delay);
    };
    scheduleNextBlink();

    // Saccades schedule
    let saccadeTimer: any;
    let saccadeResetTimer: any;
    const scheduleNextSaccade = () => {
      const delay = 500 + Math.random() * 1400;
      saccadeTimer = setTimeout(() => {
        if (Math.random() > 0.65) {
          physicsRef.current.saccadeOffsetX = (Math.random() - 0.5) * 8.0;
          physicsRef.current.saccadeOffsetY = (Math.random() - 0.5) * 6.0;
          physicsRef.current.pupilTwitch = (Math.random() - 0.5) * 6.0;
        } else {
          physicsRef.current.saccadeOffsetX = (Math.random() - 0.5) * 3.0;
          physicsRef.current.saccadeOffsetY = (Math.random() - 0.5) * 2.5;
          physicsRef.current.pupilTwitch = 0;
        }
        saccadeResetTimer = setTimeout(() => {
          physicsRef.current.saccadeOffsetX = 0;
          physicsRef.current.saccadeOffsetY = 0;
        }, 80);
        scheduleNextSaccade();
      }, delay);
    };
    scheduleNextSaccade();

    // Live Jitter Metrics
    const jitterInterval = setInterval(() => {
      const base = 54.0 + (Math.random() * 0.6 - 0.3);
      setDepth(`${base.toFixed(1)} cm`);
      const mm = (3.5 + (physicsRef.current.pupilRadius / 24) * 1.5 + (Math.random() * 0.12)).toFixed(2);
      setPupilDil(`${mm}mm`);
      const scan = (99.3 + (Math.random() * 0.5)).toFixed(1);
      setIrisScan(`${scan}%`);
      setTelemetryCycle(`${(0.34 + (Math.random() * 0.16)).toFixed(2)}ms`);
    }, 420);

    // High-Detail Render Loop
    const drawEyeFrame = () => {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      if (!ctx) return;

      const p = physicsRef.current;
      const arena = arenaRef.current;
      if (arena) {
        const rect = arena.getBoundingClientRect();
        const ax = rect.left + rect.width / 2;
        const ay = rect.top + rect.height / 2;
        const maxDisplacement = 34;

        const normX = Math.max(-1, Math.min(1, (p.mouseX - ax) / (window.innerWidth / 2)));
        const normY = Math.max(-1, Math.min(1, (p.mouseY - ay) / (window.innerHeight / 2)));

        p.targetX = normX * maxDisplacement;
        p.targetY = normY * maxDisplacement;

        const dist = Math.sqrt(p.targetX * p.targetX + p.targetY * p.targetY);
        if (dist > maxDisplacement) {
          p.targetX = (p.targetX / dist) * maxDisplacement;
          p.targetY = (p.targetY / dist) * maxDisplacement;
        }
      }

      p.curX += (p.targetX + p.saccadeOffsetX - p.curX) * 0.16;
      p.curY += (p.targetY + p.saccadeOffsetY - p.curY) * 0.16;
      p.pupilRadius += (p.targetPupilRadius + p.pupilTwitch - p.pupilRadius) * 0.14;

      ctx.clearRect(0, 0, SIZE, SIZE);

      ctx.save();
      ctx.beginPath();
      ctx.arc(CENTER, CENTER, CENTER - 2, 0, Math.PI * 2);
      ctx.clip();

      // 1. Sclera with clean, elegant warm paper ivory tone
      const scleraGrad = ctx.createRadialGradient(CENTER, CENTER, 20, CENTER, CENTER, CENTER);
      scleraGrad.addColorStop(0, '#FFFFFC');
      scleraGrad.addColorStop(0.55, '#FAF8F3');
      scleraGrad.addColorStop(0.82, '#F2EDE4');
      scleraGrad.addColorStop(0.95, '#E8E2D5');
      scleraGrad.addColorStop(1.0, '#D8D1C3');
      ctx.fillStyle = scleraGrad;
      ctx.fillRect(0, 0, SIZE, SIZE);

      // Subtle lateral lighting tints (minimal, clean)
      const flushLeft = ctx.createRadialGradient(16, CENTER, 2, 36, CENTER, 110);
      flushLeft.addColorStop(0, 'rgba(230, 57, 38, 0.16)');
      flushLeft.addColorStop(0.6, 'rgba(186, 36, 21, 0.05)');
      flushLeft.addColorStop(1, 'transparent');
      ctx.fillStyle = flushLeft;
      ctx.fillRect(0, 0, SIZE, SIZE);

      const flushRight = ctx.createRadialGradient(SIZE - 16, CENTER, 2, SIZE - 36, CENTER, 110);
      flushRight.addColorStop(0, 'rgba(230, 57, 38, 0.16)');
      flushRight.addColorStop(0.6, 'rgba(186, 36, 21, 0.05)');
      flushRight.addColorStop(1, 'transparent');
      ctx.fillStyle = flushRight;
      ctx.fillRect(0, 0, SIZE, SIZE);

      // Draw blood vessels on sclera
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

      // 2. Iris & Cornea
      const irisX = CENTER + p.curX;
      const irisY = CENTER + p.curY;

      // Glowing limbal ring shadow
      const limbalGlow = ctx.createRadialGradient(irisX, irisY, IRIS_RADIUS - 4, irisX, irisY, IRIS_RADIUS + 7);
      limbalGlow.addColorStop(0, 'transparent');
      limbalGlow.addColorStop(0.6, 'rgba(220, 38, 38, 0.85)');
      limbalGlow.addColorStop(1.0, 'transparent');
      ctx.fillStyle = limbalGlow;
      ctx.beginPath();
      ctx.arc(irisX, irisY, IRIS_RADIUS + 8, 0, Math.PI * 2);
      ctx.fill();

      // Iris base radial gradient
      const irisGrad = ctx.createRadialGradient(irisX, irisY, p.pupilRadius * 0.7, irisX, irisY, IRIS_RADIUS);
      irisGrad.addColorStop(0, '#111216');
      irisGrad.addColorStop(0.2, '#0369A1');
      irisGrad.addColorStop(0.55, '#0284C7');
      irisGrad.addColorStop(0.78, '#38BDF8');
      irisGrad.addColorStop(0.92, '#E63926');
      irisGrad.addColorStop(1.0, '#090D16');
      ctx.fillStyle = irisGrad;
      ctx.beginPath();
      ctx.arc(irisX, irisY, IRIS_RADIUS, 0, Math.PI * 2);
      ctx.fill();

      // Limbal ring stroke
      ctx.strokeStyle = '#020617';
      ctx.lineWidth = 4;
      ctx.stroke();

      // Radial muscle fibers
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

      // Jagged Collarette Ring
      ctx.beginPath();
      const collaretteR = p.pupilRadius + (IRIS_RADIUS - p.pupilRadius) * 0.48;
      for (let a = 0; a <= Math.PI * 2; a += 0.08) {
        const wobble = Math.sin(a * 24) * 2.8 + Math.cos(a * 12) * 1.5;
        const cr = collaretteR + wobble;
        const cx = irisX + Math.cos(a) * cr;
        const cy = irisY + Math.sin(a) * cr;
        if (a === 0) ctx.moveTo(cx, cy);
        else ctx.lineTo(cx, cy);
      }
      ctx.closePath();
      ctx.strokeStyle = 'rgba(239, 68, 68, 0.9)';
      ctx.lineWidth = 1.8;
      ctx.stroke();

      // 3. Pupil
      ctx.fillStyle = '#000000';
      ctx.beginPath();
      ctx.arc(irisX, irisY, Math.max(9, p.pupilRadius), 0, Math.PI * 2);
      ctx.fill();

      const sphincter = ctx.createRadialGradient(irisX, irisY, p.pupilRadius * 0.75, irisX, irisY, p.pupilRadius * 1.25);
      sphincter.addColorStop(0, 'rgba(0,0,0,1)');
      sphincter.addColorStop(0.65, 'rgba(185, 28, 28, 0.45)');
      sphincter.addColorStop(1, 'transparent');
      ctx.fillStyle = sphincter;
      ctx.beginPath();
      ctx.arc(irisX, irisY, p.pupilRadius * 1.25, 0, Math.PI * 2);
      ctx.fill();

      // 4. Specular Highlights
      const glintX = irisX - IRIS_RADIUS * 0.28;
      const glintY = irisY - IRIS_RADIUS * 0.32;
      ctx.save();
      ctx.translate(glintX, glintY);
      ctx.rotate(-0.35);
      ctx.fillStyle = 'rgba(255, 255, 255, 0.96)';
      ctx.beginPath();
      ctx.ellipse(0, 0, 7.5, 3.8, 0, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();

      ctx.fillStyle = 'rgba(255, 255, 255, 0.8)';
      ctx.beginPath();
      ctx.arc(irisX - IRIS_RADIUS * 0.14, irisY - IRIS_RADIUS * 0.12, 2.2, 0, Math.PI * 2);
      ctx.fill();

      ctx.save();
      ctx.translate(irisX + IRIS_RADIUS * 0.32, irisY + IRIS_RADIUS * 0.35);
      ctx.rotate(0.5);
      ctx.fillStyle = 'rgba(220, 38, 38, 0.4)';
      ctx.beginPath();
      ctx.ellipse(0, 0, 6, 2.8, 0, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();

      ctx.restore();

      // Update Gaze Vector readout
      const vx = (p.curX / 34).toFixed(2);
      const vy = (p.curY / 34).toFixed(2);
      const sx = Number(vx) >= 0 ? '+' : '';
      const sy = Number(vy) >= 0 ? '+' : '';
      setGazeVector(`[${sx}${vx}, ${sy}${vy}]`);

      animFrameRef.current = requestAnimationFrame(drawEyeFrame);
    };

    drawEyeFrame();

    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      if (blinkTimer) clearTimeout(blinkTimer);
      if (saccadeTimer) clearTimeout(saccadeTimer);
      if (saccadeResetTimer) clearTimeout(saccadeResetTimer);
      clearInterval(jitterInterval);
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
    };
  }, [CENTER, IRIS_RADIUS, generateBloodVessels, generateIrisFibers, triggerBlink]);

  // Key input typing reactive behavior
  const handleKeyInput = (val: string) => {
    setTokenInput(val);
    setScanMode('HIGH_FREQ_ACQUISITION');
    physicsRef.current.targetPupilRadius = 16;
    physicsRef.current.saccadeOffsetX = (Math.random() - 0.5) * 6;
    physicsRef.current.saccadeOffsetY = (Math.random() - 0.5) * 5;

    if (typingTimeoutRef.current) clearTimeout(typingTimeoutRef.current);
    typingTimeoutRef.current = setTimeout(() => {
      setScanMode('IDLE_SCAN');
      physicsRef.current.targetPupilRadius = 24;
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
        className: 'text-center text-[9px] tracking-[0.14em] text-[#E63926] bg-[#FDF2F0] border border-[#E63926]/40 font-bold py-1 min-h-[16px]',
      });
      triggerBlink(80);
    } else {
      setAuthStatus({
        custom: true,
        text: 'AWAITING_BIOMETRIC_TOKEN_VALIDATION // AUTH_CHALLENGE_ID: 981-FC7',
        className: 'text-center text-[9px] tracking-[0.14em] text-[#484B53] bg-[#FAF8F3] border border-[#D8D2C5] py-1 font-semibold min-h-[16px]',
      });
    }
  };

  const handleSetMode = (newMode: 'passive' | 'active') => {
    setMode(newMode);
    if (newMode === 'passive') {
      setBiolockStatus('ENGAGED');
      physicsRef.current.targetPupilRadius = 24;
    } else {
      setBiolockStatus('INTRUSION_ALERT');
      physicsRef.current.targetPupilRadius = 32;
      triggerBlink(90);
    }
  };

  // Tactical Reboot Sequence
  const rebootSequence = () => {
    // Clear any previous running timers
    rebootTimersRef.current.forEach(clearTimeout);
    rebootTimersRef.current = [];

    triggerBlink(220);
    generateBloodVessels();
    setBootProgress(10);
    setEngineBadge({
      text: 'COLD_REBOOT_TRIGGERED',
      className: 'text-[9px] px-1.5 py-0.5 bg-[#E63926]/15 text-[#E63926] border border-[#E63926]/50 font-bold',
    });
    setBootDiagLabel('PURGING CRYPTOGRAPHIC SENSORS & FLUSHING BUFFER...');
    setAuthStatus({
      custom: true,
      text: 'SYS_REBOOT_TRIGGERED // RETESTING OPTO-ELECTRONIC MATRIX',
      className: 'text-center text-[9px] tracking-[0.14em] text-[#E63926] bg-[#FDF2F0] border border-[#E63926]/40 font-bold py-1 min-h-[16px]',
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
        className: 'text-[9px] px-1.5 py-0.5 bg-[#E63926]/20 text-[#E63926] border border-[#E63926]/60 font-bold',
      });
      setBootDiagLabel('CIPHER_SUITE: CHACHA20-POLY1305 // NEURAL_TAP: SYNCED');
      setAuthStatus({
        custom: true,
        text: 'CALIBRATION COMPLETE // SUBJECT LOCKED // READY FOR JWT INGESTION',
        className: 'text-center text-[9px] tracking-[0.14em] text-[#484B53] bg-[#FAF8F3] border border-[#D8D2C5] py-1 font-semibold min-h-[16px]',
      });
      triggerBlink(110);
    }, 1500);

    rebootTimersRef.current.push(t1, t2, t3);
  };

  // Auth Protocol Execution
  const simulateAuth = useCallback(() => {
    if (isAuthenticating) return;
    setIsAuthenticating(true);

    // Fullscreen crimson flash
    setFlashOpacity(0.35);
    setTimeout(() => setFlashOpacity(0), 160);

    setButtonText('[ LOCKING IRIS & DERIVING ENCLAVE KEY... ]');
    physicsRef.current.targetPupilRadius = 12;
    triggerBlink(80);

    setAuthStatus({
      custom: true,
      text: 'ACTIVE_PERSON_SCAN: PHOTOMETRIC STEREO MATCHING // EXTRACTING 4096-BIT RETINA HASH...',
      className: 'text-center text-[9px] tracking-[0.14em] text-[#E63926] bg-[#FDF2F0] border border-[#E63926]/50 font-bold py-1 min-h-[16px]',
    });
    setBootProgress(90);

    const t1 = setTimeout(() => {
      setAuthStatus({
        custom: true,
        text: 'DERIVING ZERO-KNOWLEDGE PROOF FROM SUBJECT BIOMETRIC ENTROPY...',
        className: 'text-center text-[9px] tracking-[0.14em] text-[#BA2415] bg-[#FDF2F0] font-mono py-1 min-h-[16px]',
      });
      physicsRef.current.targetPupilRadius = 18;
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
      physicsRef.current.targetPupilRadius = 24;
      triggerBlink(110);

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
    <div className="relative flex flex-col justify-between w-full min-h-screen bg-[#F5F2EB] text-[#111216] select-none p-2 md:p-3 font-mono overflow-x-hidden">
      {/* Local Scoped Keyframe & Technical Styles */}
      <style>{`
        /* Smooth Archival Print Vignette (No Grid) */
        .clinical-overlay {
          position: fixed;
          inset: 0;
          pointer-events: none;
          z-index: 45;
          background: radial-gradient(circle at center, transparent 65%, rgba(216, 210, 197, 0.18) 90%, rgba(180, 172, 158, 0.28) 100%);
        }

        /* High-contrast Chromatic Jitter */
        @keyframes chromaticAlert {
          0%, 100% { text-shadow: -1px 0 rgba(230, 57, 38, 0.5), 1px 0 rgba(2, 132, 199, 0.5); }
          20% { text-shadow: -2px 0 rgba(230, 57, 38, 0.8), 2px 0 rgba(2, 132, 199, 0.8); }
          40% { text-shadow: 1px -1px rgba(230, 57, 38, 0.4), -1px 1px rgba(16, 132, 62, 0.5); }
          80% { text-shadow: -0.5px 0 rgba(230, 57, 38, 0.6), 0.5px 0 rgba(2, 132, 199, 0.6); }
        }
        .glitch-chroma {
          animation: chromaticAlert 3s infinite ease-in-out;
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

        /* Smooth anatomical eyelids */
        .eyelid-slice {
          position: absolute;
          left: 0;
          width: 100%;
          height: 50%;
          background: #111216;
          z-index: 28;
          pointer-events: none;
          transition: transform 0.08s cubic-bezier(0.2, 0.9, 0.3, 1);
        }
        .eyelid-upper {
          top: 0;
          transform-origin: top;
          border-bottom: 2px solid rgba(230, 57, 38, 0.9);
          box-shadow: 0 4px 20px rgba(0, 0, 0, 0.9);
          transform: translateY(-101%);
        }
        .eyelid-lower {
          bottom: 0;
          transform-origin: bottom;
          border-top: 2px solid rgba(230, 57, 38, 0.9);
          box-shadow: 0 -4px 20px rgba(0, 0, 0, 0.9);
          transform: translateY(101%);
        }

        /* Terminal Cursor */
        @keyframes cursorPulse {
          0%, 49% { opacity: 1; }
          50%, 100% { opacity: 0; }
        }
        .cli-cursor {
          animation: cursorPulse 0.75s infinite;
        }

        /* Barcode text styling */
        .barcode-strip-login {
          letter-spacing: -1.5px;
          font-family: monospace;
          font-size: 14px;
          transform: scaleY(1.3);
          display: inline-block;
          background: transparent !important;
        }

        /* CLI Terminal Input override */
        .cli-terminal-input {
          background-color: transparent !important;
          color: #F8FAFC !important;
          border: none !important;
          box-shadow: none !important;
          outline: none !important;
        }
        .cli-terminal-input:focus {
          background-color: transparent !important;
          color: #F8FAFC !important;
          border: none !important;
          box-shadow: none !important;
          outline: none !important;
        }
      `}</style>

      {/* Subtle Clinical Optical Vignette */}
      <div className="clinical-overlay"></div>

      {/* Fullscreen flash overlay on biometric capture / unlock */}
      <div
        className="pointer-events-none fixed inset-0 z-50 bg-[#E63926] transition-opacity duration-300"
        id="flashOverlay"
        style={{ opacity: flashOpacity }}
      ></div>

      {/* ========================================== */}
      {/* 1. TOP HEADER // STERILE CLINICAL DEFENSE LAB HUD */}
      {/* ========================================== */}
      <header className="relative z-30 w-full mb-2">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 items-center bg-[#FAF8F3]/95 border-2 border-[#D8D2C5] px-4 py-2.5 shadow-[0_4px_20px_rgba(18,19,22,0.06)] backdrop-blur-md">
          {/* Left Section (4 cols): System ID, Kernel & Enclave Diagnostics */}
          <div className="lg:col-span-4 flex flex-col gap-0.5 text-[11px] tracking-[0.06em]">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="inline-block w-2.5 h-2.5 bg-[#E63926] animate-ping" id="sysStatusBeacon"></span>
              <span className="text-[#111216] font-extrabold tracking-[0.12em] glitch-chroma">
                LAB_ID // DRISHTI_CLINICAL_SYS_V3.1
              </span>
              <span className={engineBadge.className} id="engineBadge">
                {engineBadge.text}
              </span>
            </div>
            <div className="flex items-center gap-2 text-[9.5px] text-[#484B53]">
              <span>KERNEL: <span className="text-[#111216] font-bold">SEC-ARCH-09.r4</span></span>
              <span className="text-[#10843E] font-mono px-1 bg-[#10843E]/10 border border-[#10843E]/30 font-semibold">[SELINUX_ENFORCING]</span>
              <span className="text-[#0284C7] font-mono px-1 bg-[#0284C7]/10 border border-[#0284C7]/30 font-semibold">[RPC_TLS1.3]</span>
              <span className="text-[#6B6F78]">CYCLE: <span className="text-[#111216] font-bold" id="telemetryCycle">{telemetryCycle}</span></span>
            </div>
          </div>

          {/* Center Section (5 cols): Boot Stage Cards & Hacker Diagnostics Bar */}
          <div className="lg:col-span-5 flex flex-col gap-1 items-center justify-center">
            <div className="grid grid-cols-4 w-full gap-1.5 text-[9px] tracking-[0.05em] font-mono">
              {/* Stage 1 */}
              <div
                className={`px-1 py-1 text-center flex items-center justify-center gap-1 shadow-sm ${
                  stages.step1
                    ? 'bg-[#F5F2EB] border border-[#10843E]/50'
                    : 'bg-[#F5F2EB] border border-[#D8D2C5]'
                }`}
                id="step1"
              >
                <span className={stages.step1 ? 'text-[#10843E] font-bold' : 'text-[#6B6F78] font-bold'}>01:CRYPTO</span>
                {stages.step1 && <span className="text-[#10843E] font-bold">✓</span>}
              </div>

              {/* Stage 2 */}
              <div
                className={`px-1 py-1 text-center flex items-center justify-center gap-1 shadow-sm ${
                  stages.step2
                    ? 'bg-[#F5F2EB] border border-[#10843E]/50'
                    : 'bg-[#F5F2EB] border border-[#D8D2C5]'
                }`}
                id="step2"
              >
                <span className={stages.step2 ? 'text-[#10843E] font-bold' : 'text-[#6B6F78] font-bold'}>02:NEURAL</span>
                {stages.step2 && <span className="text-[#10843E] font-bold">✓</span>}
              </div>

              {/* Stage 3 (Active or Verified) */}
              <div
                className={`px-1 py-1 text-center flex items-center justify-center gap-1 ${
                  stages.step4
                    ? 'bg-[#F5F2EB] border border-[#10843E]/50 shadow-sm'
                    : stages.step3
                    ? 'bg-[#FDF2F0] border-2 border-[#E63926] shadow-[0_0_10px_rgba(230,57,38,0.2)]'
                    : 'bg-[#F5F2EB] border border-[#D8D2C5]'
                }`}
                id="step3"
              >
                <span className={stages.step4 ? 'text-[#10843E] font-bold' : stages.step3 ? 'text-[#E63926] font-bold' : 'text-[#6B6F78] font-bold'}>
                  03:BIOMETRIC
                </span>
                {stages.step4 ? (
                  <span className="text-[#10843E] font-bold">✓</span>
                ) : stages.step3 ? (
                  <span className="text-[#E63926] font-bold animate-pulse">●</span>
                ) : null}
              </div>

              {/* Stage 4 */}
              <div
                className={`px-1 py-1 text-center flex items-center justify-center gap-1 ${
                  stages.step4
                    ? 'bg-[#EBF5EE] border-2 border-[#10843E] shadow-[0_0_12px_rgba(16,132,62,0.25)]'
                    : 'bg-[#F5F2EB] border border-[#D8D2C5] shadow-sm'
                }`}
                id="step4"
              >
                <span className={stages.step4 ? 'text-[#10843E] font-bold' : 'text-[#6B6F78] font-bold'}>
                  04:COCKPIT {stages.step4 && '✓'}
                </span>
              </div>
            </div>

            {/* Progress track & Micro diagnostic readouts */}
            <div className="w-full flex flex-col gap-0.5">
              <div className="w-full h-1.5 bg-[#ECE8DF] border border-[#D8D2C5] relative overflow-hidden flex">
                <div
                  className={`h-full ${stages.step4 ? 'bg-[#10843E]' : 'bg-[#10843E]'} transition-all duration-300`}
                  id="bootProgressBar"
                  style={{ width: `${bootProgress}%` }}
                ></div>
              </div>
              <div className="flex items-center justify-between text-[8px] tracking-wider w-full text-[#484B53]">
                <span className="text-[#24272E] font-mono font-medium truncate max-w-[280px]" id="bootDiagLabel">
                  {bootDiagLabel}
                </span>
                <span className="text-[#E63926] font-bold font-mono">
                  {bootProgress.toFixed(1)}% CAPTURE
                </span>
              </div>
            </div>
          </div>

          {/* Right Section (3 cols): Exploits, Live Distance, Re-Calibrate Trigger */}
          <div className="lg:col-span-3 flex flex-col items-end gap-1 text-[10px]">
            <div className="flex items-center gap-2">
              <span className="text-[8.5px] px-1.5 py-0.5 bg-[#10843E]/10 text-[#10843E] border border-[#10843E]/40 font-bold">
                PAYLOADS: 0
              </span>
              <span className="text-[#484B53]">
                DIST: <span className="text-[#111216] font-bold font-mono" id="subjectDistance">{depth}</span>
              </span>
              <span className="text-[9px] px-1.5 py-0.5 bg-[#E63926]/15 text-[#E63926] border border-[#E63926]/60 font-bold tracking-wider animate-pulse" id="lockStatusBadge">
                [TARGET_LOCKED]
              </span>
            </div>
            <div>
              <button
                type="button"
                className="flex items-center gap-1.5 text-[9px] text-[#24272E] hover:text-[#E63926] px-2 py-0.5 border border-[#D8D2C5] hover:border-[#E63926] bg-[#FAF8F3] hover:bg-[#FDF2F0] transition-all cursor-pointer shadow-sm font-mono font-semibold"
                onClick={rebootSequence}
                title="Re-run engine self-test and camera sweep"
              >
                <span className="text-[#E63926]">⚡</span>
                <span>REBOOT_OPTO_MATRIX</span>
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* ========================================== */}
      {/* 2. CENTER STAGE: SCARY / UNSETTLING OCULAR APERTURE + CLINICAL FLANKS */}
      {/* ========================================== */}
      <main className="relative z-30 flex flex-col items-center justify-center flex-1 w-full my-auto overflow-hidden py-1">
        {/* Status Bar Pill above eye */}
        <div className="flex items-center gap-4 text-[9px] tracking-[0.14em] text-[#484B53] pointer-events-none bg-[#FAF8F3]/95 px-4 py-1.5 border border-[#D8D2C5] mb-2 shadow-[0_2px_12px_rgba(18,19,22,0.06)] backdrop-blur-sm">
          <span>SUBJECT: <span className="text-[#111216] font-bold" id="subjectStatusText">HUMAN_HOST_ACTIVE</span></span>
          <span className="text-[#D8D2C5]">|</span>
          <span>CONFIDENCE: <span className="text-[#111216] font-bold font-mono" id="confVal">99.14%</span></span>
          <span className="text-[#D8D2C5]">|</span>
          <span>FIREWALL: <span className="text-[#E63926] font-bold">L5_OVERRIDE</span></span>
          <span className="text-[#D8D2C5]">|</span>
          <span>LIVENESS: <span className="text-[#10843E] font-bold font-mono" id="livenessVal">0.998</span></span>
        </div>

        {/* Main Biometric Stage with Lateral Data Streams */}
        <div className="relative w-full max-w-6xl flex items-center justify-center px-2 gap-3 lg:gap-6">
          {/* LEFT FLANK: Clinical Scrolling Memory Hex Dump */}
          <aside className="hidden xl:flex flex-col w-[210px] h-[330px] border-2 border-[#D8D2C5] bg-[#FAF8F3]/95 p-2 overflow-hidden shadow-[0_4px_16px_rgba(18,19,22,0.05)] text-[8px] font-mono leading-relaxed relative shrink-0">
            <div className="flex items-center justify-between border-b border-[#D8D2C5] pb-1 mb-1 text-[8.5px] font-bold tracking-wider">
              <div className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-[#E63926] animate-ping"></span>
                <span className="text-[#E63926]">// MEM_DUMP_0x7FFF</span>
              </div>
              <span className="text-[7.5px] px-1 bg-[#E63926]/10 text-[#E63926] border border-[#E63926]/30">L1_CACHE</span>
            </div>
            <div className="relative flex-1 overflow-hidden">
              <div className="stream-scroll space-y-1 text-[#484B53]">
                <div className="flex justify-between"><span className="text-[#6B6F78]">0x7FFF89A2:</span> <span className="text-[#111216] font-medium">48 89 E5 48</span></div>
                <div className="flex justify-between"><span className="text-[#6B6F78]">0x7FFF89AA:</span> <span className="text-[#111216] font-medium">E8 24 FF FF</span></div>
                <div className="flex justify-between"><span className="text-[#E63926] font-semibold">OVERFLOW_GUARD:</span> <span className="text-[#10843E] font-bold">ACTIVE</span></div>
                <div className="flex justify-between"><span className="text-[#6B6F78]">0x7FFF89B2:</span> <span className="text-[#111216] font-medium">55 48 89 E5</span></div>
                <div className="flex justify-between"><span className="text-[#6B6F78]">0x7FFF89BA:</span> <span className="text-[#111216] font-medium">41 56 41 55</span></div>
                <div className="flex justify-between"><span className="text-[#111216] font-semibold">ROOT_INJECT:</span> <span className="text-[#E63926] font-bold">BLOCKED</span></div>
                <div className="flex justify-between"><span className="text-[#6B6F78]">0x7FFF89C2:</span> <span className="text-[#111216] font-medium">B8 01 00 00</span></div>
                <div className="flex justify-between"><span className="text-[#6B6F78]">0x7FFF89CA:</span> <span className="text-[#111216] font-medium">05 48 3D 00</span></div>
                <div className="flex justify-between"><span className="text-[#6B6F78]">0x7FFF89D2:</span> <span className="text-[#111216] font-medium">77 1B 48 89</span></div>
                <div className="flex justify-between"><span className="text-[#E63926]">INTERRUPT:</span> <span className="text-[#BA2415] font-bold">SIGSEGV</span></div>
                <div className="flex justify-between"><span className="text-[#6B6F78]">0x7FFF89DA:</span> <span className="text-[#111216] font-medium">31 C0 C9 C3</span></div>
                <div className="flex justify-between"><span className="text-[#10843E]">CRYPTO_NONCE:</span> <span className="text-[#10843E] font-bold">0xFA49E2D</span></div>
                <div className="flex justify-between"><span className="text-[#6B6F78]">0x7FFF89EA:</span> <span className="text-[#111216] font-medium">48 83 EC 08</span></div>
                {/* Duplicated loop block */}
                <div className="flex justify-between"><span className="text-[#6B6F78]">0x7FFF89A2:</span> <span className="text-[#111216] font-medium">48 89 E5 48</span></div>
                <div className="flex justify-between"><span className="text-[#6B6F78]">0x7FFF89AA:</span> <span className="text-[#111216] font-medium">E8 24 FF FF</span></div>
                <div className="flex justify-between"><span className="text-[#E63926] font-semibold">OVERFLOW_GUARD:</span> <span className="text-[#10843E] font-bold">ACTIVE</span></div>
                <div className="flex justify-between"><span className="text-[#6B6F78]">0x7FFF89B2:</span> <span className="text-[#111216] font-medium">55 48 89 E5</span></div>
              </div>
            </div>
            <div className="mt-1 pt-1 border-t border-[#D8D2C5] text-[7.5px] text-[#484B53] flex justify-between items-center font-semibold">
              <span>HEAP: <span className="text-[#111216]">42.1MB</span></span>
              <span className="text-[#10843E]">CANARY: SECURE</span>
            </div>
          </aside>

          {/* CENTER ARENA CLUSTER */}
          <div className="flex items-center justify-center gap-2 md:gap-4 shrink-0">
            {/* Left Telemetry Wing */}
            <div className="hidden md:flex flex-col items-end gap-1.5 text-[9px] text-[#484B53] font-mono leading-tight tracking-wider text-right w-[125px] shrink-0 border-r border-[#D8D2C5] pr-3 select-none">
              <span className="text-[7.5px] text-[#E63926] font-extrabold uppercase tracking-widest">// OPTO_METRICS</span>
              <div className="text-[#22252B] font-semibold">DEPTH // <span className="text-[#111216] font-bold font-mono" id="depthVal">{depth}</span></div>
              <div className="text-[#E63926] font-bold">IRIS: <span id="irisScanVal">{irisScan}</span></div>
              <div>PUPIL: <span className="text-[#111216] font-bold font-mono" id="pupilDilVal">{pupilDil}</span></div>
              <div>IPD: <span className="text-[#22252B] font-semibold font-mono" id="ipdVal">63.8mm</span></div>
              <div className="text-[#6B6F78]">HASH: <span className="text-[#E63926] font-mono font-bold">0x9E4B..7A</span></div>
              <div>SACCADE: <span className="text-[#111216] font-bold font-mono">3.4Hz</span></div>
            </div>

            {/* Ocular Arena Canvas & Bezel */}
            <div className="relative w-[400px] h-[400px] flex items-center justify-center shrink-0" id="scanArena" ref={arenaRef}>
              {/* Concentric HUD rings with technical markings */}
              <div className="absolute -top-3.5 text-[8px] font-mono tracking-widest text-[#E63926] font-bold pointer-events-none select-none">
                AZM 000° // APERTURE_NORTH [PREDATOR_ACQ]
              </div>
              <div className="absolute -bottom-3.5 text-[8px] font-mono tracking-widest text-[#484B53] font-medium pointer-events-none select-none">
                AZM 180° // APERTURE_SOUTH [LOCKED]
              </div>

              {/* Rotating Calibration Circles */}
              <div className="absolute w-[416px] h-[416px] rounded-full border border-dashed border-[#111216]/20 pointer-events-none hud-dial-spin"></div>
              <div className="absolute w-[404px] h-[404px] rounded-full border border-[#E63926]/20 pointer-events-none hud-dial-counter"></div>

              {/* Outer Clinical Lens Bezel */}
              <div className="relative w-[390px] h-[390px] rounded-full p-1.5 bg-[#ECE8DF] border-2 border-[#D8D2C5] shadow-[0_10px_30px_rgba(18,19,22,0.10),0_0_0_1px_rgba(255,255,255,0.8)_inset] flex items-center justify-center z-20">
                {/* Precision Reticle SVG Overlay */}
                <svg className="absolute inset-0 w-full h-full pointer-events-none z-30" viewBox="0 0 390 390">
                  <circle cx="195" cy="195" fill="none" opacity="0.65" r="186" stroke="#E63926" strokeDasharray="3 6" strokeWidth="1.5"></circle>
                  <circle cx="195" cy="195" fill="none" opacity="0.35" r="180" stroke="#111216" strokeWidth="0.8"></circle>
                  <line stroke="#E63926" strokeWidth="2" x1="195" x2="195" y1="4" y2="18"></line>
                  <line stroke="#E63926" strokeWidth="2" x1="195" x2="195" y1="372" y2="386"></line>
                  <line stroke="#E63926" strokeWidth="2" x1="4" x2="18" y1="195" y2="195"></line>
                  <line stroke="#E63926" strokeWidth="2" x1="372" x2="386" y1="195" y2="195"></line>
                  <circle cx="195" cy="195" fill="none" opacity="0.45" r="183" stroke="#6B6F78" strokeDasharray="1 12.5" strokeWidth="2"></circle>
                </svg>

                {/* The Eyeball Housing */}
                <div className="relative w-[380px] h-[380px] rounded-full overflow-hidden bg-[#FAF8F3] border-2 border-[#E63926] shadow-[0_0_35px_rgba(230,57,38,0.22),inset_0_0_40px_rgba(18,19,22,0.3)] flex items-center justify-center" id="eyeOrbit">
                  {/* Sharp Canvas Layer */}
                  <canvas
                    className="absolute inset-0 w-full h-full block z-20"
                    height={380}
                    id="eyeCanvas"
                    ref={canvasRef}
                    width={380}
                  ></canvas>

                  {/* Anatomical Eyelids (Blinking Reflex) */}
                  <div className="eyelid-slice eyelid-upper" id="eyelidUpper" ref={eyelidUpperRef}></div>
                  <div className="eyelid-slice eyelid-lower" id="eyelidLower" ref={eyelidLowerRef}></div>

                  {/* Corneal Glass Gloss Vignette Overlay */}
                  <div className="absolute inset-0 rounded-full shadow-[inset_0_0_30px_rgba(0,0,0,0.45),inset_0_20px_25px_rgba(255,255,255,0.4)] pointer-events-none z-26"></div>
                </div>
              </div>
            </div>

            {/* Right Telemetry Wing */}
            <div className="hidden md:flex flex-col items-start gap-1.5 text-[9px] text-[#484B53] font-mono leading-tight tracking-wider text-left w-[125px] shrink-0 border-l border-[#D8D2C5] pl-3 select-none">
              <span className="text-[7.5px] text-[#10843E] font-extrabold uppercase tracking-widest">// ENCLAVE_LOCK</span>
              <div>CORNEA // <span className="text-[#10843E] font-bold font-mono">OK [1.37]</span></div>
              <div className="text-[#E63926] font-bold">LOCK: <span id="biolockStatus">{biolockStatus}</span></div>
              <div>GAZE: <span className="text-[#111216] font-mono font-bold" id="gazeVectorVal">{gazeVector}</span></div>
              <div className="text-[#E63926] font-bold">IR: COHERENT</div>
              <div className="text-[#6B6F78]">TRIANG: <span className="text-[#10843E] font-bold font-mono">LOCKED</span></div>
              <div>POOL: <span className="text-[#111216] font-mono font-bold">0x88F1</span></div>
            </div>
          </div>

          {/* RIGHT FLANK: Clinical Ethernet Packet Sniffer */}
          <aside className="hidden xl:flex flex-col w-[210px] h-[330px] border-2 border-[#D8D2C5] bg-[#FAF8F3]/95 p-2 overflow-hidden shadow-[0_4px_16px_rgba(18,19,22,0.05)] text-[8px] font-mono leading-relaxed relative shrink-0">
            <div className="flex items-center justify-between border-b border-[#D8D2C5] pb-1 mb-1 text-[8.5px] font-bold tracking-wider">
              <div className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-[#E63926] animate-ping"></span>
                <span className="text-[#E63926]">// PKT_SNIFFER_ETH0</span>
              </div>
              <span className="text-[7.5px] px-1 bg-[#E63926]/10 text-[#E63926] border border-[#E63926]/30">PROMISC</span>
            </div>
            <div className="relative flex-1 overflow-hidden">
              <div className="stream-scroll-fast space-y-1 text-[#484B53]">
                <div className="flex justify-between"><span className="text-[#111216] font-medium">TCP/SYN</span> <span className="text-[#111216]">192.168.1.10:443</span></div>
                <div className="flex justify-between"><span className="text-[#10843E]">SHA256:</span> <span className="text-[#22252B] font-mono">a94a8fe5..ba6</span></div>
                <div className="flex justify-between"><span className="text-[#E63926]">ECDSA:</span> <span className="text-[#10843E] font-bold">SIGN_VERIFIED</span></div>
                <div className="flex justify-between"><span className="text-[#6B6F78]">AEAD_TAG:</span> <span className="text-[#111216] font-bold">c029f635</span></div>
                <div className="flex justify-between"><span className="text-[#111216]">DNS_TUNNEL:</span> <span className="text-[#10843E] font-bold">ZERO_LEAKS</span></div>
                <div className="flex justify-between"><span className="text-[#6B6F78]">PORT_80:</span> <span className="text-[#E63926] font-bold">REJECT_ALL</span></div>
                <div className="flex justify-between"><span className="text-[#E63926]">MITM_CHECK:</span> <span className="text-[#10843E] font-bold">PIN_VALID</span></div>
                <div className="flex justify-between"><span className="text-[#10843E]">DIFFIE_HELLMAN:</span> <span className="text-[#111216] font-bold">X25519</span></div>
                <div className="flex justify-between"><span className="text-[#6B6F78]">PKT_DROP_RATE:</span> <span className="text-[#10843E] font-bold">0.0000%</span></div>
                <div className="flex justify-between"><span className="text-[#E63926]">PAYLOAD_LEN:</span> <span className="text-[#111216]">512_BYTES</span></div>
                <div className="flex justify-between"><span className="text-[#111216]">ENCLAVE_TOKEN:</span> <span className="text-[#111216] font-bold">0x89FC</span></div>
                {/* Duplicated loop block */}
                <div className="flex justify-between"><span className="text-[#111216] font-medium">TCP/SYN</span> <span className="text-[#111216]">192.168.1.10:443</span></div>
                <div className="flex justify-between"><span className="text-[#10843E]">SHA256:</span> <span className="text-[#22252B] font-mono">a94a8fe5..ba6</span></div>
                <div className="flex justify-between"><span className="text-[#E63926]">ECDSA:</span> <span className="text-[#10843E] font-bold">SIGN_VERIFIED</span></div>
              </div>
            </div>
            <div className="mt-1 pt-1 border-t border-[#D8D2C5] text-[7.5px] text-[#484B53] flex justify-between items-center font-semibold">
              <span>THROUGHPUT: <span className="text-[#111216]">2.8 MB/s</span></span>
              <span className="text-[#111216]">MTU: 1500</span>
            </div>
          </aside>
        </div>

        {/* ========================================== */}
        {/* 3. CLINICAL CLI AUTHENTICATION TERMINAL PROMPT */}
        {/* ========================================== */}
        <div className="relative z-30 w-[520px] max-w-full mt-3 flex flex-col gap-1.5 mx-auto">
          <div className="flex items-center justify-between px-1 text-[9.5px] tracking-[0.08em] text-[#6B6F78] font-semibold">
            <button
              type="button"
              className={`flex items-center gap-1.5 cursor-pointer transition-colors ${
                mode === 'passive' ? 'text-[#111216]' : 'text-[#6B6F78] hover:text-[#111216]'
              }`}
              id="togglePassive"
              onClick={() => handleSetMode('passive')}
            >
              <span className="text-[#111216] font-bold">[</span>
              <span className={mode === 'passive' ? 'text-[#E63926]' : 'text-[#A8A398]'} id="dotPassive">
                {mode === 'passive' ? '●' : '○'}
              </span>
              <span className="hover:text-[#111216]">FULL_PASSIVE_RECON</span>
              <span className="text-[#111216] font-bold">]</span>
            </button>
            <button
              type="button"
              className={`flex items-center gap-1.5 cursor-pointer transition-colors ${
                mode === 'active' ? 'text-[#111216]' : 'text-[#6B6F78] hover:text-[#E63926]'
              }`}
              id="toggleActive"
              onClick={() => handleSetMode('active')}
            >
              <span className="text-[#A8A398]">[</span>
              <span className={mode === 'active' ? 'text-[#E63926]' : 'text-[#A8A398]'} id="dotActive">
                {mode === 'active' ? '●' : '○'}
              </span>
              <span>ACTIVE_INTRUSION_GUARD</span>
              <span className="text-[#A8A398]">]</span>
            </button>
          </div>

          <div className="relative w-full bg-[#111216] border-2 border-[#1E2024] shadow-[0_6px_25px_rgba(18,19,22,0.25)] p-2.5 flex flex-col gap-1.5 text-white">
            <div className="flex items-center justify-between text-[9px] text-[#A8A398] border-b border-[#2A2E35] pb-1">
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-[#E63926]"></span>
                <span className="w-2 h-2 rounded-full bg-[#F59E0B]"></span>
                <span className="w-2 h-2 rounded-full bg-[#10843E]"></span>
                <span className="text-[#FAF8F3] font-bold ml-1 font-mono">root@drishti-clinical-core:~#</span>
              </div>
              <div className="flex items-center gap-1 text-[8.5px]">
                <span className="text-[#A8A398]">STATUS:</span>
                <span
                  className={
                    scanMode === 'HIGH_FREQ_ACQUISITION'
                      ? 'text-[#E63926] font-extrabold tracking-tighter animate-pulse'
                      : 'text-[#A8A398] font-bold tracking-wider'
                  }
                  id="scanModeIndicator"
                >
                  {scanMode}
                </span>
              </div>
            </div>

            <div className="flex items-center gap-2 text-[11px] font-mono pt-0.5">
              <span className="text-[#E63926] font-bold whitespace-nowrap select-none">./auth_operator --token</span>
              <input
                autoComplete="off"
                className="cli-terminal-input w-full bg-transparent text-[#FAF8F3] font-mono font-medium tracking-wider outline-none border-none p-0 text-[11px] placeholder-[#6B6F78] focus:ring-0"
                id="operatorInput"
                onBlur={() => handleInputFocus(false)}
                onFocus={() => handleInputFocus(true)}
                onInput={(e: any) => handleKeyInput(e.target.value)}
                placeholder="INPUT_JWT_SIGNATURE..."
                spellCheck={false}
                type="text"
                value={tokenInput}
              />
              <span className="text-[#E63926] cli-cursor font-bold select-none text-[13px]">█</span>
            </div>

            <div className="flex items-center justify-between pt-1 text-[8px] text-[#A8A398] border-t border-[#1E2024]">
              <div className="flex items-center gap-1.5 overflow-x-auto">
                <span className="text-[#6B6F78] select-none font-bold">FLAGS:</span>
                <button
                  type="button"
                  className="px-1.5 py-0.5 bg-[#1E2024] border border-[#2A2E35] hover:border-[#E63926] hover:text-[#FAF8F3] transition-colors cursor-pointer"
                  onClick={() => appendFlag('--bypass-sandbox')}
                >
                  [--bypass-sandbox]
                </button>
                <button
                  type="button"
                  className="px-1.5 py-0.5 bg-[#1E2024] border border-[#2A2E35] hover:border-[#E63926] hover:text-[#FAF8F3] transition-colors cursor-pointer"
                  onClick={() => appendFlag('--force-recon')}
                >
                  [--force-recon]
                </button>
                <button
                  type="button"
                  className="px-1.5 py-0.5 bg-[#1E2024] border border-[#2A2E35] hover:border-[#E63926] hover:text-[#FAF8F3] transition-colors cursor-pointer"
                  onClick={() => appendFlag('--debug-dump')}
                >
                  [--debug-dump]
                </button>
              </div>
              <span className="text-[#6B6F78] font-mono text-[7.5px] select-none">AUTH_CHALLENGE // 981-FC7</span>
            </div>
          </div>

          <button
            type="button"
            className={`w-full h-[38px] font-mono text-[11px] font-bold tracking-[0.16em] flex items-center justify-center gap-2 rounded-none transition-all cursor-pointer ${
              isSuccess
                ? 'bg-[#10843E] hover:bg-[#0D6D33] border-2 border-[#0D6D33] text-[#FAF8F3] shadow-[0_4px_14px_rgba(16,132,62,0.35)]'
                : 'bg-[#E63926] hover:bg-[#BA2415] border-2 border-[#BA2415] text-[#FAF8F3] shadow-[0_4px_14px_rgba(230,57,38,0.35)]'
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
            <div className="flex items-center justify-between px-1 text-[8.5px] tracking-[0.12em] font-mono text-[#6B6F78] min-h-[16px]" id="authStatus">
              <span className="text-[#10843E] font-bold">BIOMETRIC_CORE // SECURE_ENCLAVE_READY</span>
              <span className="text-[#484B53]">PRESS ⌘+ENTER TO AUTHENTICATE</span>
            </div>
          )}
        </div>
      </main>

      {/* ========================================== */}
      {/* 4. BOTTOM CLINICAL FOOTER & HARDWARE SPECS */}
      {/* ========================================== */}
      <footer className="relative z-30 flex flex-col items-center justify-end w-full pb-1 pt-2">
        {/* Active Status LED Triad Bar */}
        <div className="flex items-center gap-6 mb-1 text-[8.5px] font-mono tracking-widest text-[#484B53]">
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#E63926] animate-pulse"></span>
            <span className="text-[#E63926] font-bold">RED: RECON_ACTIVE</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#D97706]"></span>
            <span className="text-[#B45309] font-bold">AMBER: BUFFER_LOCK</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#10843E]"></span>
            <span className="text-[#10843E] font-bold">GREEN: CRYPTO_VALID</span>
          </div>
        </div>

        {/* Brand Typography with Clinical Red Contrast */}
        <div className="mb-1 text-center">
          <div className="glitch-chroma text-[15px] md:text-[17px] font-black text-[#111216] tracking-[0.35em]">
            D R I S H T I &nbsp;&nbsp;//&nbsp;&nbsp; V I S I O N &nbsp;&nbsp; C 2
          </div>
          <div className="text-[8.5px] tracking-[0.25em] text-[#6B6F78] font-semibold mt-0.5">
            HIGH-CONTAINMENT ZERO TRUST CLINICAL OCULAR DEFENSE MATRIX // PROTOCOL 09
          </div>
        </div>

        {/* Technical Spec Barcode and Hardware Hashes */}
        <div className="w-full max-w-5xl border-t-2 border-[#D8D2C5] pt-1.5 px-3 flex flex-wrap items-center justify-between text-[8px] tracking-[0.08em] font-mono text-[#484B53] gap-2 bg-[#FAF8F3]/80">
          <div className="flex flex-col">
            <span className="text-[#6B6F78] font-semibold">SHA-256 ENCLAVE FINGERPRINT</span>
            <span className="text-[#111216] font-bold">e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</span>
          </div>
          <div className="flex flex-col">
            <span className="text-[#6B6F78] font-semibold">DNS CHALLENGE STATUS</span>
            <span className="text-[#111216] font-bold" id="dnsChallengeStatus">ACME_V02 [RESOLVED // SECURE]</span>
          </div>
          <div className="flex flex-col">
            <span className="text-[#6B6F78] font-semibold">HSM ENCLAVE ATTESTATION</span>
            <span className="text-[#111216] font-bold" id="enclaveAttest">NITRO_ENCLAVE_V4 // VERIFIED</span>
          </div>
          <div className="flex items-center gap-2 pl-3 border-l-2 border-[#D8D2C5]">
            <div className="barcode-strip-login text-[#111216] font-bold">|||| || ||| | ||||</div>
            <span className="text-[7.5px] text-[#E63926] font-extrabold">SEC-09</span>
          </div>
        </div>
      </footer>
    </div>
  );
};
