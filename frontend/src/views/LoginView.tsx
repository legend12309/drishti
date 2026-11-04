import React, { useState, useEffect, useRef, useCallback } from 'react';
import { OperatorProfile } from '../types';
import { DoodleIcon } from '../components/DoodleIcon';

interface LoginViewProps {
  onLoginSuccess: (operator: OperatorProfile, token: string) => void;
  showToast?: (type: 'success' | 'warning' | 'error' | 'info', title: string, detail?: string) => void;
  onReplayIntro?: () => void;
  startFadeIn?: boolean;
}

export const LoginView: React.FC<LoginViewProps> = ({
  onLoginSuccess,
  showToast,
  onReplayIntro,
  startFadeIn = true,
}) => {
  // Input & Mode States
  const [tokenInput, setTokenInput] = useState('ED25519-948A-AUTH-BIO-09');
  const [mode, setMode] = useState<'passive' | 'active'>('passive');
  const [isAuthenticating, setIsAuthenticating] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const [isEntering, setIsEntering] = useState(false);
  const [isScanningActive, setIsScanningActive] = useState(false);
  const [flashOpacity, setFlashOpacity] = useState(0);

  // Live Telemetry States
  const [depth, setDepth] = useState('54.0 cm');
  const [pupilDil, setPupilDil] = useState('4.80mm');
  const [irisScan, setIrisScan] = useState('99.5%');
  const [telemetryCycle, setTelemetryCycle] = useState('0.47ms');
  const [gazeVector, setGazeVector] = useState('[-0.38, -0.24]');
  const [scanMode, setScanMode] = useState<'IDLE_SCAN' | 'HIGH_FREQ_ACQUISITION'>('IDLE_SCAN');
  const [biolockStatus, setBiolockStatus] = useState('INITIALIZING...');
  const [corneaRefract, setCorneaRefract] = useState('ACQUIRING_OPTICS...');
  const [eyeAwakened, setEyeAwakened] = useState(false);
  const hasTriggeredAwakenRef = useRef(false);

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
    className: 'text-[9px] px-1.5 py-0.5 bg-[#E62E25]/20 text-[#EF4444] border border-[#E62E25]/50 font-bold rounded-sm',
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
  const isAuthenticatingRef = useRef(false);
  const isEnteringRef = useRef(false);
  const eyeAwakenedRef = useRef(false);
  const isBlinkingRef = useRef(false);
  const blinkTimerRef = useRef<any>(null);
  const blinkTimeoutRef = useRef<any>(null);

  // Eye Physics Parameters (Unified 280x280 Cyber-Portal Geometry)
  const SIZE = 280;
  const CENTER = SIZE / 2; // 140
  const IRIS_RADIUS = 68;

  const physicsRef = useRef({
    mouseX: typeof window !== 'undefined' ? window.innerWidth / 2 : 700,
    mouseY: typeof window !== 'undefined' ? window.innerHeight / 2 : 400,
    lastMouseX: typeof window !== 'undefined' ? window.innerWidth / 2 : 700,
    lastMouseY: typeof window !== 'undefined' ? window.innerHeight / 2 : 400,
    currentEyeX: 0,
    currentEyeY: 0,
    targetEyeX: 0,
    targetEyeY: 0,
    saccadeStartX: 0,
    saccadeStartY: 0,
    saccadeStartTime: 0,
    saccadeDuration: 65,
    isSaccading: false,
    gazeMode: 'CURSOR' as 'CURSOR' | 'LOOK_AWAY',
    tremorSeed: Math.random() * 100,
    currentPupilR: 12,
    targetPupilR: 12,
    colorMorph: 0, // 0 = Crimson Red, 1 = Electric Cobalt #00E5FF
    scanBeamProgress: -1, // -1 = inactive, 0.0 -> 1.0 active vertical laser scan sweep
    scanBeamActive: false,
    lockGazeToCenter: true,
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

  // Blinking reflex for circular portal eyelids (natural human blink: 75ms downstroke, 130ms upstroke)
  const triggerBlink = useCallback((duration = 140) => {
    if (
      isAuthenticatingRef.current ||
      isEnteringRef.current ||
      !eyeAwakenedRef.current ||
      isBlinkingRef.current ||
      physicsRef.current.lockGazeToCenter
    ) {
      return;
    }
    const top = eyelidTopRef.current;
    const bottom = eyelidBottomRef.current;
    if (!top || !bottom) return;

    isBlinkingRef.current = true;
    top.style.transition = 'transform 0.075s cubic-bezier(0.4, 0.0, 1, 1)';
    bottom.style.transition = 'transform 0.075s cubic-bezier(0.4, 0.0, 1, 1)';
    top.style.transform = 'translateY(0%)';
    bottom.style.transform = 'translateY(0%)';

    if (blinkTimeoutRef.current) clearTimeout(blinkTimeoutRef.current);
    blinkTimeoutRef.current = setTimeout(() => {
      // If authentication sequence took over while eyelids were down, DO NOT reopen!
      if (isAuthenticatingRef.current || isEnteringRef.current) {
        isBlinkingRef.current = false;
        return;
      }
      top.style.transition = 'transform 0.13s cubic-bezier(0.0, 0.0, 0.2, 1)';
      bottom.style.transition = 'transform 0.13s cubic-bezier(0.0, 0.0, 0.2, 1)';
      top.style.transform = 'translateY(-100%)';
      bottom.style.transform = 'translateY(100%)';

      setTimeout(() => {
        isBlinkingRef.current = false;
      }, 130);
    }, duration);
  }, []);

  // Handle cinematic fade-in and slow physiological eye opening
  useEffect(() => {
    if (!startFadeIn) {
      hasTriggeredAwakenRef.current = false;
      setEyeAwakened(false);
      eyeAwakenedRef.current = false;
      const top = eyelidTopRef.current;
      const bottom = eyelidBottomRef.current;
      if (top && bottom) {
        top.style.transition = 'transform 0.3s ease-out';
        bottom.style.transition = 'transform 0.3s ease-out';
        top.style.transform = 'translateY(0%)';
        bottom.style.transform = 'translateY(0%)';
      }
      physicsRef.current.lockGazeToCenter = true;
      physicsRef.current.currentPupilR = 12;
      physicsRef.current.targetPupilR = 12;
      return;
    }

    if (hasTriggeredAwakenRef.current) return;
    hasTriggeredAwakenRef.current = true;

    // Start with gaze locked centered and pupil constricted (resting dormancy)
    physicsRef.current.lockGazeToCenter = true;
    physicsRef.current.currentPupilR = 12;
    physicsRef.current.targetPupilR = 12;
    setCorneaRefract('ACQUIRING_OPTICS...');
    setBiolockStatus('INITIALIZING...');

    // Wait 700ms into the login page fade-in (as the UI emerges), then slowly open eyelids over 2100ms
    const openDelay = 700;
    const openDuration = 2100;

    const tOpen = setTimeout(() => {
      const top = eyelidTopRef.current;
      const bottom = eyelidBottomRef.current;
      if (top && bottom) {
        top.style.transition = `transform ${openDuration}ms cubic-bezier(0.16, 1, 0.3, 1)`;
        bottom.style.transition = `transform ${openDuration}ms cubic-bezier(0.16, 1, 0.3, 1)`;
        top.style.transform = 'translateY(-100%)';
        bottom.style.transform = 'translateY(100%)';
      }
      setEyeAwakened(true);
      eyeAwakenedRef.current = true;

      // Smoothly dilate pupil from 12px to 21px as eye adapts to light
      const pupilStartTime = performance.now();
      const dilateStep = (now: number) => {
        const elapsed = now - pupilStartTime;
        const p = Math.min(1, elapsed / openDuration);
        const eased = 1 - Math.pow(1 - p, 3);
        physicsRef.current.targetPupilR = 12 + eased * 9;
        physicsRef.current.currentPupilR = 12 + eased * 9;
        setPupilDil(`${(3.2 + eased * 1.6).toFixed(2)}mm`);

        if (p < 0.4) {
          setCorneaRefract('CORNEA_REFRACT_ACQUIRING...');
          setBiolockStatus('SYNCHRONIZING...');
        } else if (p < 0.9) {
          setCorneaRefract('OCULAR_ALIGNMENT_NOMINAL');
          setBiolockStatus('LOCK_CONFIRMED');
        }

        if (p < 1) {
          requestAnimationFrame(dilateStep);
        } else {
          setCorneaRefract('OK [NOMINAL]');
          setBiolockStatus('ENGAGED');
          physicsRef.current.lockGazeToCenter = false;
        }
      };
      requestAnimationFrame(dilateStep);
    }, openDelay);

    return () => clearTimeout(tOpen);
  }, [startFadeIn]);

  // Cinematic biometric laser scan & smooth color morph animation from Red to Blue (or vice-versa)
  const animateEyeColor = useCallback((from: number, to: number, duration = 1800) => {
    if (morphAnimRef.current) cancelAnimationFrame(morphAnimRef.current);
    const startTime = performance.now();
    const isAuthenticatingScan = to > from;

    if (isAuthenticatingScan) {
      physicsRef.current.scanBeamActive = true;
      physicsRef.current.scanBeamProgress = 0;
      setIsScanningActive(true);
    } else {
      physicsRef.current.scanBeamActive = false;
      physicsRef.current.scanBeamProgress = -1;
      setIsScanningActive(false);
    }

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

      if (isAuthenticatingScan) {
        physicsRef.current.scanBeamProgress = eased;
        // Natural Pupillary Light Reflex: constrict sharply as laser sweeps through center, then relax to normal
        if (progress < 0.25) {
          physicsRef.current.targetPupilR = 21 - progress * 40; // down to ~11px
        } else if (progress < 0.7) {
          physicsRef.current.targetPupilR = 11 + Math.sin(progress * Math.PI * 4) * 0.8; // subtle micro-flutter
        } else {
          physicsRef.current.targetPupilR = 11 + (progress - 0.7) * (1 / 0.3) * 10; // back up to ~21px
        }
      }

      if (progress < 1) {
        morphAnimRef.current = requestAnimationFrame(step);
      } else {
        if (isAuthenticatingScan) {
          physicsRef.current.scanBeamActive = false;
          physicsRef.current.scanBeamProgress = -1;
          physicsRef.current.targetPupilR = 21;
          setIsScanningActive(false);
        }
      }
    };

    morphAnimRef.current = requestAnimationFrame(step);
  }, []);

  // Main canvas animation and loop setup
  useEffect(() => {
    generateVessels();
    generateIrisFibers();

    // -------------------------------------------------------------
    // REALISTIC BIOLOGICAL SACCADE & FIXATION ENGINE
    // In human ocular physiology, eye movements are NOT continuous drifts:
    // 1. Saccades: Rapid ballistic snaps (40ms - 80ms)
    // 2. Fixations: Steady holds on focal points (250ms - 900ms) with micro-tremor
    // 3. Foveation: Alternating between following the cursor and darting to inspect UI targets
    // -------------------------------------------------------------
    let saccadeTimer: any;

    const triggerSaccadeTo = (targetX: number, targetY: number, durationMs = 60) => {
      const p = physicsRef.current;
      p.saccadeStartX = p.currentEyeX;
      p.saccadeStartY = p.currentEyeY;
      p.targetEyeX = targetX;
      p.targetEyeY = targetY;
      p.saccadeStartTime = performance.now();
      p.saccadeDuration = Math.max(35, durationMs);
      p.isSaccading = true;

      // Saccadic pupil reflex (slight dilation during eye snap)
      p.targetPupilR = 22.8;
    };

    const scheduleNextGazeShift = () => {
      // Natural human fixation duration: 250ms - 900ms
      const fixationDuration = 280 + Math.random() * 750;

      saccadeTimer = setTimeout(() => {
        const p = physicsRef.current;
        if (p.lockGazeToCenter) {
          scheduleNextGazeShift();
          return;
        }

        const arena = arenaRef.current;
        let cursorNormX = 0;
        let cursorNormY = 0;
        if (arena) {
          const rect = arena.getBoundingClientRect();
          const ax = rect.left + rect.width / 2;
          const ay = rect.top + rect.height / 2;
          cursorNormX = Math.max(-1, Math.min(1, (p.mouseX - ax) / (window.innerWidth / 2)));
          cursorNormY = Math.max(-1, Math.min(1, (p.mouseY - ay) / (window.innerHeight / 2)));
        }

        const cursorX = cursorNormX * 13;
        const cursorY = cursorNormY * 13;

        // Probabilities for next fixation target:
        // 50% -> Dart to an exploratory target (curiously inspecting telemetry, terminal, header, corners)
        // 38% -> Dart back to operator's cursor (focused interaction)
        // 12% -> Sequential micro-scan (small jump nearby, e.g. reading line of data)
        const roll = Math.random();

        if (roll < 0.50) {
          // EXPLORATORY SACCADE: Look around spontaneously
          p.gazeMode = 'LOOK_AWAY';

          const quadrant = Math.random();
          let targetX = 0;
          let targetY = 0;

          if (quadrant < 0.28) {
            // Glance left towards memory hex dump
            targetX = -10.0 - Math.random() * 5.0; // -10px to -15px
            targetY = (Math.random() - 0.5) * 8.0;
          } else if (quadrant < 0.56) {
            // Glance right towards packet sniffer
            targetX = 10.0 + Math.random() * 5.0;  // +10px to +15px
            targetY = (Math.random() - 0.5) * 8.0;
          } else if (quadrant < 0.78) {
            // Glance down towards CLI prompt and login execute button
            targetX = (Math.random() - 0.5) * 8.0;
            targetY = 9.0 + Math.random() * 5.5;   // +9px to +14.5px
          } else {
            // Glance up towards azimuth degrees & security status
            targetX = (Math.random() - 0.5) * 8.0;
            targetY = -9.0 - Math.random() * 5.5;  // -9px to -14.5px
          }

          // Real saccades take 45ms to 75ms
          const jumpDuration = 45 + Math.random() * 30;
          triggerSaccadeTo(targetX, targetY, jumpDuration);

          // Occasional organic blink on wide glances
          if (Math.abs(targetX) > 11 && Math.random() < 0.35) {
            setTimeout(() => triggerBlink(110), 30);
          }
        } else if (roll < 0.88) {
          // ATTENTION TO CURSOR: Dart back to user's cursor
          p.gazeMode = 'CURSOR';
          const jumpDuration = 40 + Math.random() * 30;
          triggerSaccadeTo(cursorX, cursorY, jumpDuration);
        } else {
          // MICRO-SCAN: Quick reading jump (±3px to ±6px)
          const angle = Math.random() * Math.PI * 2;
          const dist = 3.5 + Math.random() * 3.5;
          const targetX = Math.max(-15, Math.min(15, p.currentEyeX + Math.cos(angle) * dist));
          const targetY = Math.max(-15, Math.min(15, p.currentEyeY + Math.sin(angle) * dist));
          const jumpDuration = 35 + Math.random() * 25;
          triggerSaccadeTo(targetX, targetY, jumpDuration);
        }

        scheduleNextGazeShift();
      }, fixationDuration);
    };

    scheduleNextGazeShift();

    const handleMouseMove = (e: MouseEvent) => {
      const p = physicsRef.current;
      const dx = e.clientX - p.lastMouseX;
      const dy = e.clientY - p.lastMouseY;
      p.lastMouseX = e.clientX;
      p.lastMouseY = e.clientY;
      p.mouseX = e.clientX;
      p.mouseY = e.clientY;

      // If user moves mouse vigorously while eye is looking away, eye snaps attention back to cursor!
      if (Math.hypot(dx, dy) > 28 && p.gazeMode === 'LOOK_AWAY' && Math.random() < 0.45) {
        p.gazeMode = 'CURSOR';
        const arena = arenaRef.current;
        if (arena) {
          const rect = arena.getBoundingClientRect();
          const ax = rect.left + rect.width / 2;
          const ay = rect.top + rect.height / 2;
          const normX = Math.max(-1, Math.min(1, (e.clientX - ax) / (window.innerWidth / 2)));
          const normY = Math.max(-1, Math.min(1, (e.clientY - ay) / (window.innerHeight / 2)));
          triggerSaccadeTo(normX * 13, normY * 13, 50);
        }
      }
    };
    window.addEventListener('mousemove', handleMouseMove);

    // Blinking schedule: starts 4.8s after mount to let the slow awakening sequence complete undisturbed
    const scheduleNextBlink = (initialDelay = 4800) => {
      const nextBlink = initialDelay + Math.random() * 3200;
      blinkTimerRef.current = setTimeout(() => {
        if (!physicsRef.current.lockGazeToCenter && !isAuthenticatingRef.current && !isEnteringRef.current && eyeAwakenedRef.current) {
          triggerBlink(125 + Math.random() * 30);
        }
        if (!isAuthenticatingRef.current && !isEnteringRef.current) {
          scheduleNextBlink(3200 + Math.random() * 2400);
        }
      }, nextBlink);
    };
    scheduleNextBlink(4800);

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
      const t = p.colorMorph; // 0.0 = Red Eye, 1.0 = Electric Cobalt #00E5FF
      const now = performance.now();
      const arena = arenaRef.current;

      // 1. Biological Ocular Dynamics (Saccadic Flight vs Fixation Pursuit)
      if (p.lockGazeToCenter) {
        p.currentEyeX += (0 - p.currentEyeX) * 0.20;
        p.currentEyeY += (0 - p.currentEyeY) * 0.20;
      } else if (arena) {
        if (p.isSaccading) {
          // Ballistic Saccade: Steep acceleration & sharp mechanical landing
          const elapsed = now - p.saccadeStartTime;
          const progress = Math.min(1.0, elapsed / p.saccadeDuration);

          // Quartic ease-out: explosive instantaneous jump, decelerating sharply at destination
          const eased = 1 - Math.pow(1 - progress, 4);

          p.currentEyeX = p.saccadeStartX + (p.targetEyeX - p.saccadeStartX) * eased;
          p.currentEyeY = p.saccadeStartY + (p.targetEyeY - p.saccadeStartY) * eased;

          if (progress >= 1.0) {
            p.isSaccading = false;
            p.currentEyeX = p.targetEyeX;
            p.currentEyeY = p.targetEyeY;
            p.targetPupilR = 21; // Pupil settles on fixation target
          }
        } else {
          // Fixation Hold & Smooth Pursuit
          if (p.gazeMode === 'CURSOR') {
            // Smooth pursuit following mouse pointer
            const rect = arena.getBoundingClientRect();
            const ax = rect.left + rect.width / 2;
            const ay = rect.top + rect.height / 2;
            const normX = Math.max(-1, Math.min(1, (p.mouseX - ax) / (window.innerWidth / 2)));
            const normY = Math.max(-1, Math.min(1, (p.mouseY - ay) / (window.innerHeight / 2)));
            const cursorX = normX * 13;
            const cursorY = normY * 13;

            p.targetEyeX += (cursorX - p.targetEyeX) * 0.18;
            p.targetEyeY += (cursorY - p.targetEyeY) * 0.18;
            p.currentEyeX += (p.targetEyeX - p.currentEyeX) * 0.28;
            p.currentEyeY += (p.targetEyeY - p.currentEyeY) * 0.28;
          }

          // Physiological micro-tremor (micro-nystagmus drift < 0.4px)
          const tremorX = Math.sin(now * 0.04 + p.tremorSeed) * 0.35;
          const tremorY = Math.cos(now * 0.048 + p.tremorSeed) * 0.35;
          p.currentEyeX += tremorX * 0.12;
          p.currentEyeY += tremorY * 0.12;
        }

        // Clamp inside orbital sclera boundary
        const dist = Math.hypot(p.currentEyeX, p.currentEyeY);
        const maxDisplacement = 16.5;
        if (dist > maxDisplacement) {
          p.currentEyeX = (p.currentEyeX / dist) * maxDisplacement;
          p.currentEyeY = (p.currentEyeY / dist) * maxDisplacement;
        }
      }

      // Smooth pupil response
      p.currentPupilR += (p.targetPupilR - p.currentPupilR) * 0.14;

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
      scleraGrad.addColorStop(1.0, '#605045');
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

      // --- STEP 2: IRIS & CORNEA (Dynamic Color Morph: Crimson -> Electric Cobalt) ---
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

      // Stop 0: [28, 3, 3] (#1c0303) -> [1, 8, 20] (#010814)
      irisGrad.addColorStop(0, lerpRGB(28, 3, 3, 1, 8, 20));
      // Stop 0.2: [91, 6, 6] (#5b0606) -> [0, 48, 96]
      irisGrad.addColorStop(0.2, lerpRGB(91, 6, 6, 0, 48, 96));
      // Stop 0.5: [153, 27, 27] (#991b1b) -> [0, 110, 196]
      irisGrad.addColorStop(0.5, lerpRGB(153, 27, 27, 0, 110, 196));
      // Stop 0.78: [220, 38, 38] (#dc2626) -> [0, 160, 235]
      irisGrad.addColorStop(0.78, lerpRGB(220, 38, 38, 0, 160, 235));
      // Stop 0.92: [239, 68, 68] (#ef4444) -> [0, 229, 255] (#00E5FF Electric Cobalt)
      irisGrad.addColorStop(0.92, lerpRGB(239, 68, 68, 0, 229, 255));
      // Stop 1.0: [21, 2, 2] (#150202) -> [1, 6, 16]
      irisGrad.addColorStop(1.0, lerpRGB(21, 2, 2, 1, 6, 16));

      ctx.fillStyle = irisGrad;
      ctx.beginPath();
      ctx.arc(irisX, irisY, IRIS_RADIUS, 0, Math.PI * 2);
      ctx.fill();

      // Dark Prominent Limbal Ring
      const limbalR = Math.round(34 - t * 32);
      const limbalG = Math.round(4 + t * 40);
      const limbalB = Math.round(4 + t * 90);
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

        // Interpolate fiber color between Red design and Cobalt Blue design
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

      // Collarette Crypt Ring (Morphs from Pure White/Silver to Electric Cobalt Glow #00E5FF)
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

      const colR = Math.round(255 - t * 255);
      const colG = Math.round(255 - t * 26);
      const colB = 255;
      const colA = (0.75 + t * 0.2).toFixed(2);
      ctx.strokeStyle = `rgba(${colR}, ${colG}, ${colB}, ${colA})`;
      ctx.lineWidth = 1.4 - t * 0.2;
      ctx.stroke();

      // --- STEP 3: PUPIL ---
      ctx.fillStyle = '#010204';
      ctx.beginPath();
      ctx.arc(irisX, irisY, p.currentPupilR, 0, Math.PI * 2);
      ctx.fill();

      // Sphincter Muscle Ring (Ruby glow -> Electric Cobalt glow)
      const pupilRing = ctx.createRadialGradient(
        irisX,
        irisY,
        p.currentPupilR * 0.78,
        irisX,
        irisY,
        p.currentPupilR * (1.3 - t * 0.05)
      );
      pupilRing.addColorStop(0, 'rgba(0, 0, 0, 0.98)');
      const sphR = Math.round(153 - t * 153);
      const sphG = Math.round(27 + t * 153);
      const sphB = Math.round(27 + t * 228);
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

      const shadowR = Math.round(255 - t * 255);
      const shadowG = Math.round(255 - t * 26);
      const shadowB = 255;
      ctx.shadowColor = `rgba(${shadowR}, ${shadowG}, ${shadowB}, 0.85)`;
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
      const bounceR = Math.round(255 - t * 255);
      const bounceG = Math.round(240 - t * 11);
      const bounceB = 255;
      ctx.fillStyle = `rgba(${bounceR}, ${bounceG}, ${bounceB}, 0.40)`;
      ctx.shadowColor = 'transparent';
      ctx.shadowBlur = 0;
      ctx.beginPath();
      ctx.ellipse(0, 0, 5.2 - t * 0.4, 2.8 - t * 0.4, 0, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();

      // --- STEP 5: CINEMATIC BIOMETRIC LASER SCAN SWEEP & RETINAL MAPPING ---
      if (p.scanBeamActive && p.scanBeamProgress >= 0 && p.scanBeamProgress <= 1.05) {
        const beamY = (irisY - IRIS_RADIUS - 16) + p.scanBeamProgress * (2 * IRIS_RADIUS + 32);

        // 1. Broad Cyan Photometric Energy Wash across the scanned iris
        const beamGlow = ctx.createLinearGradient(0, beamY - 26, 0, beamY + 26);
        beamGlow.addColorStop(0, 'rgba(56, 189, 248, 0)');
        beamGlow.addColorStop(0.35, 'rgba(56, 189, 248, 0.42)');
        beamGlow.addColorStop(0.5, 'rgba(255, 255, 255, 0.96)');
        beamGlow.addColorStop(0.65, 'rgba(56, 189, 248, 0.42)');
        beamGlow.addColorStop(1, 'rgba(56, 189, 248, 0)');

        ctx.save();
        ctx.fillStyle = beamGlow;
        ctx.fillRect(CENTER - CENTER + 4, beamY - 26, SIZE - 8, 52);

        // 2. High-Energy Laser Beam Line across the eye diameter
        ctx.beginPath();
        ctx.moveTo(CENTER - CENTER + 10, beamY);
        ctx.lineTo(CENTER + CENTER - 10, beamY);
        ctx.strokeStyle = '#FFFFFF';
        ctx.shadowColor = '#38BDF8';
        ctx.shadowBlur = 20;
        ctx.lineWidth = 2.4;
        ctx.stroke();

        // 3. Secondary Cyan Optical Flare Halo
        ctx.beginPath();
        ctx.moveTo(CENTER - CENTER + 6, beamY);
        ctx.lineTo(CENTER + CENTER - 6, beamY);
        ctx.strokeStyle = 'rgba(56, 189, 248, 0.85)';
        ctx.shadowColor = '#0284C7';
        ctx.shadowBlur = 10;
        ctx.lineWidth = 5.0;
        ctx.stroke();

        // 4. Precision Biometric Micro-Tick Alignment Grid along the Laser Beam
        for (let gx = irisX - IRIS_RADIUS - 10; gx <= irisX + IRIS_RADIUS + 10; gx += 12) {
          ctx.beginPath();
          ctx.moveTo(gx, beamY - 3.5);
          ctx.lineTo(gx, beamY + 3.5);
          ctx.strokeStyle = 'rgba(255, 255, 255, 0.9)';
          ctx.shadowColor = '#38BDF8';
          ctx.shadowBlur = 6;
          ctx.lineWidth = 1.2;
          ctx.stroke();
        }

        // 5. Digital Tomography Coordinate Badge floating next to the beam
        const badgeY = Math.max(30, Math.min(SIZE - 30, beamY - 8));
        ctx.font = 'bold 7.5px monospace';
        ctx.fillStyle = '#38BDF8';
        ctx.shadowColor = '#000000';
        ctx.shadowBlur = 4;
        ctx.fillText(`TOMOGRAPHY: [Y: ${(p.scanBeamProgress * 100).toFixed(0)}%]`, CENTER + 38, badgeY);

        ctx.restore();
      }

      ctx.restore(); // end clip

      // Update Gaze Vector readout smoothly
      const vx = (p.currentEyeX / 16.5).toFixed(2);
      const vy = (p.currentEyeY / 16.5).toFixed(2);
      const sx = Number(vx) >= 0 ? '+' : '';
      const sy = Number(vy) >= 0 ? '+' : '';
      setGazeVector(`[${sx}${vx}, ${sy}${vy}]`);

      animFrameRef.current = requestAnimationFrame(renderEye);
    };

    animFrameRef.current = requestAnimationFrame(renderEye);

    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      if (saccadeTimer) clearTimeout(saccadeTimer);
      if (blinkTimerRef.current) clearTimeout(blinkTimerRef.current);
      if (blinkTimeoutRef.current) clearTimeout(blinkTimeoutRef.current);
      authTimersRef.current.forEach(clearTimeout);
      clearInterval(jitterInterval);
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
      if (morphAnimRef.current) cancelAnimationFrame(morphAnimRef.current);
    };
  }, [CENTER, IRIS_RADIUS, SIZE, generateIrisFibers, generateVessels, triggerBlink]);

  // Key input typing reactive behavior
  const handleKeyInput = (val: string) => {
    setTokenInput(val);
    setScanMode('HIGH_FREQ_ACQUISITION');
    physicsRef.current.targetPupilR = 15;

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
        className: 'text-center text-[9px] tracking-[0.14em] text-[#EF4444] bg-[#E62E25]/15 border border-[#E62E25]/40 font-bold py-0.5 min-h-[14px] rounded-sm',
      });
      triggerBlink(90);
    } else {
      setAuthStatus({
        custom: true,
        text: 'AWAITING_BIOMETRIC_TOKEN_VALIDATION // AUTH_CHALLENGE_ID: 981-FC7',
        className: 'text-center text-[9px] tracking-[0.14em] text-[#94A3B8] bg-[#070B14] border border-[#1E293B] py-0.5 min-h-[14px] rounded-sm',
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
    authTimersRef.current.forEach(clearTimeout);
    authTimersRef.current = [];

    // Reset eyelids to open
    const top = eyelidTopRef.current;
    const bottom = eyelidBottomRef.current;
    if (top && bottom) {
      top.style.transition = 'transform 0.22s ease-out';
      bottom.style.transition = 'transform 0.22s ease-out';
      top.style.transform = 'translateY(-100%)';
      bottom.style.transform = 'translateY(100%)';
    }

    // Smoothly transition back to Red Eye (0.0)
    physicsRef.current.lockGazeToCenter = false;
    physicsRef.current.scanBeamActive = false;
    physicsRef.current.scanBeamProgress = -1;
    physicsRef.current.colorMorph = 0.0;
    physicsRef.current.targetPupilR = 21;
    physicsRef.current.currentEyeX = 0;
    physicsRef.current.currentEyeY = 0;
    physicsRef.current.targetEyeX = 0;
    physicsRef.current.targetEyeY = 0;
    physicsRef.current.isSaccading = false;
    setEyeColorProgress(0.0);
    setIsScanningActive(false);
    setIsSuccess(false);
    setIsAuthenticating(false);
    isAuthenticatingRef.current = false;
    setIsEntering(false);
    isEnteringRef.current = false;
    eyeAwakenedRef.current = true;
    setFlashOpacity(0);

    triggerBlink(160);
    generateVessels();
    setBootProgress(10);
    setEngineBadge({
      text: 'COLD_REBOOT_TRIGGERED',
      className: 'text-[9px] px-1.5 py-0.5 bg-[#E62E25]/25 text-[#EF4444] border border-[#E62E25]/60 font-bold rounded-sm',
    });
    setBootDiagLabel('PURGING CRYPTOGRAPHIC SENSORS & FLUSHING BUFFER...');
    setButtonText('[ EXECUTE COCKPIT LOGIN ⌘↵ ]');
    setAuthStatus({
      custom: true,
      text: 'SYS_REBOOT_TRIGGERED // RETESTING OPTO-ELECTRONIC MATRIX',
      className: 'text-center text-[9px] tracking-[0.14em] text-[#EF4444] bg-[#E62E25]/15 border border-[#E62E25]/40 font-bold py-0.5 min-h-[14px] rounded-sm',
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
        className: 'text-[9px] px-1.5 py-0.5 bg-[#E62E25]/20 text-[#EF4444] border border-[#E62E25]/50 font-bold rounded-sm',
      });
      setBootDiagLabel('CIPHER_SUITE: CHACHA20-POLY1305 // NEURAL_TAP: SYNCED');
      setAuthStatus({
        custom: true,
        text: 'CALIBRATION COMPLETE // SUBJECT LOCKED // READY FOR JWT INGESTION',
        className: 'text-center text-[9px] tracking-[0.14em] text-[#94A3B8] bg-[#070B14] border border-[#1E293B] py-0.5 min-h-[14px] rounded-sm',
      });
      triggerBlink(120);
    }, 1500);

    rebootTimersRef.current.push(t1, t2, t3);
  };

  // Auth Protocol Execution:
  // 1. Operator clicks Auth -> Eyelids smoothly close shut (0.85s)
  // 2. While shut in darkness, morph to glowing Cobalt Blue Eye (at 950ms)
  // 3. Eyelids slowly, dramatically part over 2000ms (at 1400ms) revealing the Blue Eye looking around
  // 4. Operator observes the Blue Eye alive and conscious
  // 5. White optical flash transition blooming into main software cockpit (at 4400ms)
  const simulateAuth = useCallback(() => {
    if (isAuthenticating || isEntering) return;
    setIsAuthenticating(true);
    isAuthenticatingRef.current = true;

    // Immediately cancel any ambient blink timers & blinks
    if (blinkTimerRef.current) clearTimeout(blinkTimerRef.current);
    if (blinkTimeoutRef.current) clearTimeout(blinkTimeoutRef.current);
    isBlinkingRef.current = false;

    // Center eye and lock gaze forward calmly
    physicsRef.current.lockGazeToCenter = true;
    physicsRef.current.targetEyeX = 0;
    physicsRef.current.targetEyeY = 0;
    physicsRef.current.currentEyeX = 0;
    physicsRef.current.currentEyeY = 0;
    physicsRef.current.isSaccading = false;

    // 1. Immediately update button text & status
    setButtonText('[ INGESTING BIOMETRIC KEY... ]');
    setAuthStatus({
      custom: true,
      text: 'AUTHENTICATING OPERATOR IDENTITY // COMMENCING OCULAR CONVERGENCE...',
      className: 'text-center text-[9px] tracking-[0.14em] text-[#EF4444] font-bold min-h-[14px] rounded-sm',
    });
    setBootProgress(50);

    // 2. Smooth, cinematic eyelid closure (0.85s duration)
    const top = eyelidTopRef.current;
    const bottom = eyelidBottomRef.current;
    if (top && bottom) {
      top.style.transition = 'transform 0.85s cubic-bezier(0.4, 0.0, 0.2, 1)';
      bottom.style.transition = 'transform 0.85s cubic-bezier(0.4, 0.0, 0.2, 1)';
      top.style.transform = 'translateY(0%)';
      bottom.style.transform = 'translateY(0%)';
    }

    // Pupil constricts gently to 14px as eyelids close
    physicsRef.current.targetPupilR = 14;
    physicsRef.current.currentPupilR = 14;

    // 3. While the eye is fully shut in darkness (at 950ms), transform to glowing BLUE EYE
    const tClose = setTimeout(() => {
      physicsRef.current.colorMorph = 1.0;
      setEyeColorProgress(1.0);
      physicsRef.current.targetPupilR = 23;

      setBootProgress(100);
      setStages({ step1: true, step2: true, step3: true, step4: true });
      setEngineBadge({
        text: 'DEFCON-5: [ONLINE_ROOT]',
        className: 'text-[9px] px-1.5 py-0.5 bg-[#10B981]/20 text-[#10B981] border border-[#10B981]/50 font-bold rounded-sm animate-pulse',
      });
      setButtonText('[ BIOMETRICS CONFIRMED // UNVEILING COBALT CORE... ]');
      setAuthStatus({
        custom: true,
        text: 'ACCESS GRANTED // BIOMETRIC SIGNATURE VERIFIED // UNVEILING COBALT CORE',
        className: 'text-center text-[9px] tracking-[0.15em] text-[#00E5FF] bg-[#00E5FF]/10 py-0.5 border border-[#00E5FF]/40 font-bold min-h-[14px] rounded-sm',
      });
      setIsSuccess(true);
    }, 950);

    // 4. Slow-motion cinematic eyelid opening (2000ms duration) dramatically revealing the Blue Eye
    const tOpen = setTimeout(() => {
      if (top && bottom) {
        top.style.transition = 'transform 2000ms cubic-bezier(0.16, 1, 0.3, 1)';
        bottom.style.transition = 'transform 2000ms cubic-bezier(0.16, 1, 0.3, 1)';
        top.style.transform = 'translateY(-100%)';
        bottom.style.transform = 'translateY(100%)';
      }
      setButtonText('[ COCKPIT RUNNING // SESSION ESTABLISHED ]');
      setAuthStatus({
        custom: true,
        text: 'SESSION ACTIVE // COBALT OCULAR LINK ESTABLISHED // COMMENCING COCKPIT LAUNCH',
        className: 'text-center text-[9px] tracking-[0.15em] text-[#10B981] bg-[#10B981]/15 py-0.5 border border-[#10B981]/40 font-bold min-h-[14px] rounded-sm animate-pulse',
      });

      // Smooth pupil dilation as light enters the Blue Eye
      const pupilStartTime = performance.now();
      const dilateStep = (now: number) => {
        const elapsed = now - pupilStartTime;
        const p = Math.min(1, elapsed / 2000);
        const eased = 1 - Math.pow(1 - p, 3);
        physicsRef.current.targetPupilR = 14 + eased * 9; // up to 23px
        physicsRef.current.currentPupilR = 14 + eased * 9;
        setPupilDil(`${(3.4 + eased * 1.6).toFixed(2)}mm`);
        if (p < 1) {
          requestAnimationFrame(dilateStep);
        }
      };
      requestAnimationFrame(dilateStep);
    }, 1400);

    // 5. At 3100ms (eyelids fully parted), unlock gaze so Blue Eye dynamically looks around
    const tLookAround = setTimeout(() => {
      physicsRef.current.lockGazeToCenter = false;
      const p = physicsRef.current;
      p.saccadeStartX = p.currentEyeX;
      p.saccadeStartY = p.currentEyeY;
      p.targetEyeX = (Math.random() - 0.5) * 12;
      p.targetEyeY = (Math.random() - 0.5) * 9;
      p.saccadeStartTime = performance.now();
      p.saccadeDuration = 60;
      p.isSaccading = true;
    }, 3100);

    // 6. At 4400ms: Blinding white optic flash initiates as Blue Eye shines
    const tFlash = setTimeout(() => {
      setIsEntering(true);
      isEnteringRef.current = true;
      setFlashOpacity(1); // Blinding Optic White (#F8FAFC)
    }, 4400);

    // 7. At 4950ms: Complete transition into the main cockpit software as the flash blooms
    const tComplete = setTimeout(() => {
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
        showToast('success', 'Biometric Enclave Verified', 'Access granted. Entering DRISHTI Cockpit...');
      }

      setIsAuthenticating(false);
      isAuthenticatingRef.current = false;
      onLoginSuccess(op, tokenInput.trim());
    }, 4950);

    authTimersRef.current.push(tClose, tOpen, tLookAround, tFlash, tComplete);
  }, [isAuthenticating, isEntering, mode, onLoginSuccess, showToast, tokenInput]);

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
  const portalGlow = t > 0.5
    ? 'shadow-[0_0_40px_rgba(37,99,235,0.45),inset_0_0_45px_rgba(0,0,0,0.95)] border-blue-500/60'
    : 'shadow-[0_0_40px_rgba(230,46,37,0.45),inset_0_0_45px_rgba(0,0,0,0.95)] border-rose-500/60';

  return (
    <div
      className={`relative flex flex-col justify-between w-screen h-screen bg-[#030407] text-[#E5E7EB] select-none overflow-hidden p-3 md:p-4 font-mono transition-all duration-[1400ms] ease-out ${
        startFadeIn
          ? 'opacity-100 filter brightness-100 scale-100 pointer-events-auto'
          : 'opacity-0 filter brightness-50 scale-[0.99] pointer-events-none'
      }`}
      style={{
        transitionTimingFunction: 'cubic-bezier(0.16, 1, 0.3, 1)',
      }}
    >
      {/* CRT Scanlines, Analog Noise, Vignette Screen Layer */}
      <div className="crt-overlay"></div>

      {/* Fullscreen blinding white optic flash overlay that smoothly saturates the viewport before entering the app */}
      <div
        className="pointer-events-none fixed inset-0 z-[60] bg-[#F8FAFC] transition-opacity duration-500 ease-in-out"
        id="flashOverlay"
        style={{
          opacity: flashOpacity,
        }}
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

        /* Reticle SVG Rotations */
        @keyframes reticleRotateCounter {
          0% { transform: rotate(360deg); }
          100% { transform: rotate(0deg); }
        }
        .reticle-inner-ticks {
          transform-origin: 170px 170px;
          animation: reticleRotateCounter 16s steps(60, end) infinite;
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

        /* Brutalist Tactile Buttons */
        .btn-brutal {
          transition: transform 160ms cubic-bezier(0.23, 1, 0.32, 1), background-color 160ms ease, border-color 160ms ease, box-shadow 160ms ease;
        }
        .btn-brutal:hover {
          background-color: #E62E25 !important;
          color: #030407 !important;
          border-color: #ff4d4d !important;
          box-shadow: 0 0 24px rgba(230, 46, 37, 0.6);
        }
        .btn-brutal:active {
          transform: scale(0.97);
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
          transform: translateY(0%);
        }
        .eyelid-bottom {
          bottom: 0;
          transform-origin: bottom;
          border-top: 2px solid rgba(230, 46, 37, 0.45);
          box-shadow: 0 -6px 20px rgba(0, 0, 0, 0.98);
          transform: translateY(0%);
        }

        /* Barcode styling */
        .barcode-strip {
          letter-spacing: -1.5px;
          font-family: monospace;
          font-size: 14px;
          transform: scaleY(1.3);
          display: inline-block;
        }

        /* CLI Terminal Input override to prevent white background box */
        .cli-terminal-input,
        input.cli-terminal-input,
        input[type="text"].cli-terminal-input {
          background-color: transparent !important;
          background: transparent !important;
          color: #E5E7EB !important;
          border: none !important;
          box-shadow: none !important;
          outline: none !important;
          padding: 0 !important;
          -webkit-appearance: none !important;
        }
        .cli-terminal-input:focus,
        input.cli-terminal-input:focus,
        input[type="text"].cli-terminal-input:focus {
          background-color: transparent !important;
          background: transparent !important;
          color: #E5E7EB !important;
          border: none !important;
          box-shadow: none !important;
          outline: none !important;
          ring: 0 !important;
          --tw-ring-color: transparent !important;
        }

        @keyframes entranceTextAnim {
          0% {
            opacity: 0;
            transform: scale(0.92);
          }
          30% {
            opacity: 1;
            transform: scale(1);
          }
          75% {
            opacity: 1;
            transform: scale(1.03);
          }
          100% {
            opacity: 0;
            transform: scale(1.08);
          }
        }
        .entrance-text-fade {
          animation: entranceTextAnim 1100ms ease-out forwards;
        }

        /* Seamless Entrance Fade-In from Intro Reel */
        @keyframes loginFadeIn {
          0% {
            opacity: 0;
            filter: brightness(0.7) contrast(1.05);
          }
          100% {
            opacity: 1;
            filter: brightness(1) contrast(1);
          }
        }
        .login-fade-in-entry {
          animation: loginFadeIn 850ms cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }
      `}</style>

      {/* ========================================== */}
      {/* 1. TOP HEADER // HARDCORE CYBER-HUD & DEFCON TELEMETRY */}
      {/* ========================================== */}
      <header
        className={`relative z-30 w-full mb-1 transition-all duration-500 ${
          isEntering ? 'opacity-0 -translate-y-4 pointer-events-none' : 'opacity-100'
        }`}
      >
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 items-center bg-[#060911]/90 border border-[#1E293B]/80 px-4 py-2 shadow-[0_4px_30px_rgba(0,0,0,0.9)] backdrop-blur-md rounded-sm">
          {/* Left Section (4 cols): System ID, Kernel & Enclave Diagnostics */}
          <div className="lg:col-span-4 flex flex-col gap-1 text-[11px] tracking-[0.08em]">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="inline-block w-2.5 h-2.5 bg-[#E62E25] animate-ping rounded-full" id="sysStatusBeacon"></span>
              <span className="text-white font-black tracking-[0.14em] glitch-chroma">
                SYS_ID // DRISHTI_SEC_ENGINE_V2.0
              </span>
              <span className={engineBadge.className} id="engineBadge">
                {engineBadge.text}
              </span>
            </div>
            <div className="flex items-center gap-2.5 text-[9.5px] text-[#64748B]">
              <span>KERNEL: <span className="text-[#CBD5E1] font-semibold">SEC-ARCH-09.r4</span></span>
              <span className="text-[#10B981] font-mono px-1 bg-[#10B981]/10 border border-[#10B981]/30 rounded-sm">[SELINUX_ENFORCING]</span>
              <span className="text-[#38BDF8] font-mono px-1 bg-[#2563EB]/15 border border-[#2563EB]/40 rounded-sm">[RPC_TLS1.3]</span>
              <span className="text-[#475569]">CYCLE: <span className="text-[#E5E7EB]" id="telemetryCycle">{telemetryCycle}</span></span>
            </div>
          </div>

          {/* Center Section (5 cols): Boot Stage Cards & Hacker Diagnostics Bar */}
          <div className="lg:col-span-5 flex flex-col gap-1 items-center justify-center">
            <div className="grid grid-cols-4 w-full gap-1.5 text-[9px] tracking-[0.05em] font-mono">
              {/* Stage 1 */}
              <div
                className={`px-1 py-1 text-center flex items-center justify-center gap-1 rounded-sm ${
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
                className={`px-1 py-1 text-center flex items-center justify-center gap-1 rounded-sm ${
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
                className={`px-1 py-1 text-center flex items-center justify-center gap-1 rounded-sm ${
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
                className={`px-1 py-1 text-center flex items-center justify-center gap-1 rounded-sm ${
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
              <div className="w-full h-1.5 bg-[#090D18] border border-[#1E293B] relative overflow-hidden flex rounded-sm">
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
              <span className="text-[8.5px] px-1.5 py-0.2 bg-[#10B981]/15 text-[#10B981] border border-[#10B981]/40 font-bold rounded-sm">
                PAYLOADS: 0
              </span>
              <span className="text-[#64748B]">
                DIST: <span className="text-[#E5E7EB] font-bold font-mono" id="subjectDistance">{depth}</span>
              </span>
              <span className="text-[9px] px-1.5 py-0.5 bg-[#E62E25]/25 text-[#EF4444] border border-[#E62E25]/60 font-bold tracking-wider animate-pulse rounded-sm" id="lockStatusBadge">
                [TARGET_LOCKED]
              </span>
            </div>
            <div className="flex items-center gap-2">
              {onReplayIntro && (
                <button
                  type="button"
                  className="flex items-center gap-1.5 text-[9px] text-[#38BDF8] hover:text-white px-2 py-0.5 border border-[#2563EB]/40 hover:border-[#38BDF8] bg-[#0A0E18] hover:bg-[#2563EB]/20 active:scale-95 transition-all duration-150 cursor-pointer shadow-sm font-mono rounded-sm"
                  onClick={onReplayIntro}
                  title="Watch boot video intro again"
                >
                  <span>↺</span>
                  <span>BOOT_INTRO</span>
                </button>
              )}
              <button
                type="button"
                className="flex items-center gap-1.5 text-[9px] text-[#94A3B8] hover:text-white px-2 py-0.5 border border-[#334155]/80 hover:border-[#EF4444] bg-[#0A0E18] hover:bg-[#E62E25]/20 active:scale-95 transition-all duration-150 cursor-pointer shadow-sm font-mono rounded-sm"
                onClick={rebootSequence}
                title="Re-run engine self-test and camera sweep"
              >
                <DoodleIcon name="spark" className="w-3 h-3 text-[#EF4444]" />
                <span>REBOOT_OPTO_MATRIX</span>
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* ========================================== */}
      {/* 2. CENTER STAGE: PURE CIRCULAR BIOMETRIC PORTAL WITH BALANCED LATERAL TELEMETRY */}
      {/* ========================================== */}
      <main className="relative z-30 flex flex-col items-center justify-center flex-1 w-full my-auto overflow-hidden py-0.5">
        {/* Status Bar Pill with Clean Margin to prevent top collision */}
        <div
          className={`flex items-center gap-4 text-[9px] tracking-[0.14em] text-[#64748B] pointer-events-none bg-[#070B14]/90 px-4 py-1 border border-[#1E293B] mb-2.5 shadow-[0_2px_15px_rgba(0,0,0,0.8)] backdrop-blur-sm rounded-full transition-all duration-500 ${
            isEntering ? 'opacity-0 scale-90 pointer-events-none' : 'opacity-100'
          }`}
        >
          <span>SUBJECT: <span className="text-[#60A5FA] font-bold" id="subjectStatusText">HUMAN_HOST_ACTIVE</span></span>
          <span className="text-[#334155]">|</span>
          <span>CONFIDENCE: <span className="text-white font-bold font-mono" id="confVal">99.14%</span></span>
          <span className="text-[#334155]">|</span>
          <span>FIREWALL: <span className="text-[#EF4444] font-bold">L5_OVERRIDE</span></span>
          <span className="text-[#334155]">|</span>
          <span>LIVENESS: <span className="text-[#10B981] font-bold font-mono" id="livenessVal">0.998</span></span>
        </div>

        {/* Main Biometric Row: Perfectly balanced 5-component flex layout */}
        <div className="relative w-full max-w-6xl flex items-center justify-center px-2 gap-4 lg:gap-6">
          {/* LEFT FLANK: Scrolling Memory Hex Dump */}
          <aside
            id="leftFlankDump"
            className={`hidden xl:flex flex-col w-[205px] h-[270px] border border-[#1E293B]/70 bg-[#04060C]/90 p-2 overflow-hidden shadow-[inset_0_0_20px_rgba(0,0,0,0.85)] text-[8px] font-mono leading-relaxed relative rounded-sm shrink-0 transition-all duration-500 ${
              isEntering ? 'opacity-0 -translate-x-8 pointer-events-none' : 'opacity-100'
            }`}
          >
            <div className="flex items-center justify-between border-b border-[#1E293B]/80 pb-1 mb-1 text-[8.5px] font-bold tracking-wider">
              <div className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-[#EF4444] animate-ping"></span>
                <span className="text-[#EF4444]">// MEM_DUMP_0x7FFF</span>
              </div>
              <span className="text-[7.5px] px-1 bg-[#E62E25]/20 text-[#EF4444] border border-[#E62E25]/40 rounded-sm">L1_CACHE</span>
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
            <div className="mt-1 pt-1 border-t border-[#1E293B]/80 text-[7.5px] text-[#64748B] flex justify-between items-center font-semibold">
              <span>HEAP: <span className="text-white font-bold">42.1MB</span></span>
              <span className="text-[#10B981] font-bold">CANARY: SECURE</span>
            </div>
          </aside>

          {/* LEFT TELEMETRY READOUT (Flanking the eye, non-overlapping) */}
          <div
            className={`hidden sm:flex flex-col justify-center w-[135px] gap-2 text-[8.5px] text-[#475569] font-mono leading-relaxed tracking-wider text-right shrink-0 select-none transition-all duration-500 ${
              isEntering ? 'opacity-0 -translate-x-4 pointer-events-none' : 'opacity-100'
            }`}
          >
            <div className="border-b border-[#1E293B]/60 pb-0.5 text-[7.5px] font-bold text-[#EF4444] tracking-widest">// OPTO_ACQUISITION</div>
            <div>
              <span className="text-[#64748B] block text-[7.5px]">FACIAL_DEPTH</span>
              <span className="text-white font-bold" id="depthVal">{depth}</span>
            </div>
            <div>
              <span className="text-[#64748B] block text-[7.5px]">IRIS_SCAN</span>
              <span className="text-[#EF4444] font-bold" id="irisScanVal">{irisScan} MATCH</span>
            </div>
            <div>
              <span className="text-[#64748B] block text-[7.5px]">PUPIL_DILATION</span>
              <span className="text-[#CBD5E1] font-medium" id="pupilDilVal">{pupilDil}</span>
            </div>
            <div>
              <span className="text-[#64748B] block text-[7.5px]">IPD_METRIC</span>
              <span className="text-[#94A3B8]" id="ipdVal">63.8mm</span>
            </div>
            <div>
              <span className="text-[#64748B] block text-[7.5px]">VESSEL_HASH</span>
              <span className="text-[#F87171] font-mono font-bold">0x9E4B..7A</span>
            </div>
            <div>
              <span className="text-[#64748B] block text-[7.5px]">SACCADE_FRQ</span>
              <span className="text-[#38BDF8] font-bold">3.4Hz</span>
            </div>
          </div>

          {/* CENTER: PURE CIRCULAR OCULAR ARENA WITH 60FPS PRECISION RETICLES */}
          <div
            className="relative w-[340px] h-[340px] flex items-center justify-center shrink-0"
            id="scanArena"
            ref={arenaRef}
          >
            {/* Precision Azimuth Degree Radial Marks */}
            <div className="absolute -top-3.5 left-1/2 -translate-x-1/2 bg-[#030407] px-2 text-[7.5px] font-mono tracking-widest text-[#EF4444]/90 pointer-events-none z-30 select-none border border-[#EF4444]/30 rounded-sm">
              AZM 000° // APERTURE_NORTH
            </div>
            <div className="absolute -bottom-3.5 left-1/2 -translate-x-1/2 bg-[#030407] px-2 text-[7.5px] font-mono tracking-widest text-[#64748B] pointer-events-none z-30 select-none border border-[#1E293B] rounded-sm">
              AZM 180° // APERTURE_SOUTH
            </div>

            {/* Precision SVG Reticle System (Counter-rotating precision ticks, zero extra outer rings) */}
            <svg
              className="absolute w-[340px] h-[340px] pointer-events-none z-10 overflow-visible"
              viewBox="0 0 340 340"
            >
              {/* Inner Tick Ring: 60 precision ticks driven at 16s steps(60, end) infinite counter-clockwise */}
              <circle
                cx="170"
                cy="170"
                r="146"
                fill="none"
                stroke={t > 0.5 ? 'rgba(0, 229, 255, 0.75)' : 'rgba(239, 68, 68, 0.55)'}
                strokeWidth="2.8"
                strokeDasharray="2.5 12.789"
                className="reticle-inner-ticks"
              />
              {/* Aperture Crosshair Micro-Accents */}
              <line x1="170" y1="0" x2="170" y2="10" stroke={t > 0.5 ? '#00E5FF' : '#EF4444'} strokeWidth="2" />
              <line x1="170" y1="330" x2="170" y2="340" stroke={t > 0.5 ? '#00E5FF' : '#EF4444'} strokeWidth="2" />
              <line x1="0" y1="170" x2="10" y2="170" stroke={t > 0.5 ? '#00E5FF' : '#EF4444'} strokeWidth="2" />
              <line x1="330" y1="170" x2="340" y2="170" stroke={t > 0.5 ? '#00E5FF' : '#EF4444'} strokeWidth="2" />
            </svg>

            {/* PURE CIRCULAR BIOMETRIC LENS / IRIS PORTAL VIEWPORT */}
            <div
              className={`relative w-[280px] h-[280px] rounded-full overflow-hidden bg-[#070b14] border-2 transition-all duration-500 flex items-center justify-center z-20 ${portalGlow}`}
              id="eyeOrbit"
            >
              {/* Unified Eye Rendering HTML5 Canvas */}
              <canvas
                className="absolute inset-0 w-full h-full block"
                height={280}
                id="eyeCanvas"
                ref={canvasRef}
                width={280}
              />

              {/* Optical Glass Antireflective Depth Layer */}
              <div className="absolute inset-0 rounded-full shadow-[inset_0_0_50px_rgba(0,0,0,0.9),inset_0_15px_30px_rgba(0,0,0,0.7),inset_0_-15px_30px_rgba(0,0,0,0.7)] pointer-events-none z-25"></div>

              {/* Organic Circular Eyelids for natural physiological blinking & slow cinematic reveal */}
              <div
                className="eyelid eyelid-top"
                id="eyelidTop"
                ref={eyelidTopRef}
                style={{
                  borderBottomColor: t > 0.5 ? 'rgba(0, 229, 255, 0.6)' : 'rgba(230, 46, 37, 0.5)',
                }}
              ></div>
              <div
                className="eyelid eyelid-bottom"
                id="eyelidBottom"
                ref={eyelidBottomRef}
                style={{
                  borderTopColor: t > 0.5 ? 'rgba(0, 229, 255, 0.6)' : 'rgba(230, 46, 37, 0.5)',
                }}
              ></div>
            </div>
          </div>

          {/* RIGHT TELEMETRY READOUT (Flanking the eye, non-overlapping) */}
          <div
            className={`hidden sm:flex flex-col justify-center w-[135px] gap-2 text-[8.5px] text-[#475569] font-mono leading-relaxed tracking-wider text-left shrink-0 select-none transition-all duration-500 ${
              isEntering ? 'opacity-0 translate-x-4 pointer-events-none' : 'opacity-100'
            }`}
          >
            <div className="border-b border-[#1E293B]/60 pb-0.5 text-[7.5px] font-bold text-[#38BDF8] tracking-widest">// ENCLAVE_LOCK</div>
            <div>
              <span className="text-[#64748B] block text-[7.5px]">CORNEA_REFRACT</span>
              <span className={`font-bold transition-colors duration-300 ${corneaRefract === 'OK [NOMINAL]' ? 'text-[#10B981]' : 'text-[#38BDF8] animate-pulse'}`}>
                {corneaRefract}
              </span>
            </div>
            <div>
              <span className="text-[#64748B] block text-[7.5px]">BIOMETRIC_LOCK</span>
              <span className="text-[#E62E25] font-bold" id="biolockStatus">{biolockStatus}</span>
            </div>
            <div>
              <span className="text-[#64748B] block text-[7.5px]">GAZE_VECTOR</span>
              <span className="text-white font-mono font-bold" id="gazeVectorVal">{gazeVector}</span>
            </div>
            <div>
              <span className="text-[#64748B] block text-[7.5px]">SPECTRAL_IR</span>
              <span className="text-[#EF4444] font-bold">COHERENT</span>
            </div>
            <div>
              <span className="text-[#64748B] block text-[7.5px]">TRIANGULATION</span>
              <span className="text-[#10B981] font-semibold">LOCKED</span>
            </div>
            <div>
              <span className="text-[#64748B] block text-[7.5px]">ENTROPY_POOL</span>
              <span className="text-white font-mono font-bold">0x88F1</span>
            </div>
          </div>

          {/* RIGHT FLANK: Live Packet Sniffer & Security Hash Stream */}
          <aside
            id="rightFlankSniffer"
            className={`hidden xl:flex flex-col w-[205px] h-[270px] border border-[#1E293B]/70 bg-[#04060C]/90 p-2 overflow-hidden shadow-[inset_0_0_20px_rgba(0,0,0,0.85)] text-[8px] font-mono leading-relaxed relative rounded-sm shrink-0 transition-all duration-500 ${
              isEntering ? 'opacity-0 translate-x-8 pointer-events-none' : 'opacity-100'
            }`}
          >
            <div className="flex items-center justify-between border-b border-[#1E293B]/80 pb-1 mb-1 text-[8.5px] font-bold tracking-wider">
              <div className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-[#38BDF8] animate-ping"></span>
                <span className="text-[#38BDF8]">// PKT_SNIFFER_ETH0</span>
              </div>
              <span className="text-[7.5px] px-1 bg-[#2563EB]/20 text-[#38BDF8] border border-[#2563EB]/40 rounded-sm">PROMISC</span>
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
            <div className="mt-1 pt-1 border-t border-[#1E293B]/80 text-[7.5px] text-[#64748B] flex justify-between items-center font-semibold">
              <span>THROUGHPUT: <span className="text-white font-bold">2.8 MB/s</span></span>
              <span className="text-[#38BDF8] font-bold">MTU: 1500</span>
            </div>
          </aside>
        </div>

        {/* ========================================== */}
        {/* 3. HACKER CLI AUTHENTICATION TERMINAL PROMPT */}
        {/* ========================================== */}
        <div
          className={`relative z-30 w-[490px] max-w-full mt-3 flex flex-col gap-1.5 transition-all duration-500 ${
            isEntering ? 'opacity-0 translate-y-8 pointer-events-none' : 'opacity-100'
          }`}
        >
          {/* Recon Scope Selector Buttons (Clear of any bottom ring overlap) */}
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
          <div className="relative w-full bg-[#060912]/95 border border-[#1E293B] shadow-[0_4px_25px_rgba(0,0,0,0.85)] p-2.5 flex flex-col gap-1.5 rounded-sm">
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

            {/* Prompt & Input Field with Real Blinking Block Cursor & Transparent Field */}
            <div className="flex items-center gap-2 text-[11px] font-mono pt-0.5">
              <span className="text-[#10B981] font-bold whitespace-nowrap select-none">
                ./authenticate_operator --token
              </span>
              <input
                autoComplete="off"
                className="cli-terminal-input w-full !bg-transparent !text-[#E5E7EB] font-mono tracking-wider !border-none !outline-none p-0 text-[11px] placeholder-[#475569] !ring-0 focus:!ring-0"
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
                className="px-1.5 py-0.5 bg-[#0B101D] border border-[#1E293B] hover:border-[#EF4444] hover:text-white active:scale-95 transition-all duration-150 cursor-pointer rounded-sm"
                onClick={() => appendFlag('--bypass-sandbox')}
              >
                [--bypass-sandbox]
              </button>
              <button
                type="button"
                className="px-1.5 py-0.5 bg-[#0B101D] border border-[#1E293B] hover:border-[#EF4444] hover:text-white active:scale-95 transition-all duration-150 cursor-pointer rounded-sm"
                onClick={() => appendFlag('--force-recon')}
              >
                [--force-recon]
              </button>
              <button
                type="button"
                className="px-1.5 py-0.5 bg-[#0B101D] border border-[#1E293B] hover:border-[#EF4444] hover:text-white active:scale-95 transition-all duration-150 cursor-pointer rounded-sm"
                onClick={() => appendFlag('--debug-dump')}
              >
                [--debug-dump]
              </button>
            </div>
          </div>

          {/* Primary Tactical Authorization Trigger */}
          <button
            type="button"
            className={`w-full h-[38px] font-mono text-[11px] font-bold tracking-[0.16em] flex items-center justify-center gap-2 rounded-sm transition-all duration-150 active:scale-[0.98] cursor-pointer disabled:opacity-85 disabled:cursor-wait ${
              isSuccess
                ? 'bg-[#10B981]/20 border border-[#10B981] text-[#10B981] shadow-[0_0_24px_rgba(16,185,129,0.5)] hover:bg-[#10B981]/30'
                : 'bg-[#E62E25]/15 border border-[#E62E25] text-[#EF4444] shadow-[0_0_20px_rgba(230,46,37,0.35)] hover:bg-[#E62E25]/25 hover:text-white'
            }`}
            disabled={isAuthenticating}
            id="authBtn"
            onClick={simulateAuth}
          >
            <span id="authButtonText">{buttonText}</span>
          </button>

          {/* Live Terminal Feedback Log */}
          {authStatus.custom ? (
            <div className={authStatus.className} id="authStatus">
              {authStatus.text}
            </div>
          ) : (
            <div
              className="text-center text-[9px] tracking-[0.14em] text-[#94A3B8] bg-[#070B14] py-0.5 border border-[#1E293B] font-medium min-h-[14px] rounded-sm"
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
      <footer
        className={`relative z-30 flex flex-col items-center justify-end w-full pb-1 transition-all duration-500 ${
          isEntering ? 'opacity-0 translate-y-4 pointer-events-none' : 'opacity-100'
        }`}
      >
        {/* Active Status LED Triad Bar */}
        <div className="flex items-center gap-6 mb-1.5 text-[8px] font-mono tracking-widest text-[#64748B]">
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
        <div className="mb-1 text-center">
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
