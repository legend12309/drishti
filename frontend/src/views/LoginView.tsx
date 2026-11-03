import React, { useState, useEffect, useRef, useCallback } from 'react';
import { OperatorProfile } from '../types';
import {
  Shield,
  ShieldAlert,
  Terminal,
  Activity,
  Cpu,
  Lock,
  Unlock,
  Radio,
  Zap,
  RotateCw,
  Search,
  Crosshair,
  Server,
  Layers,
  ArrowRight,
  ChevronRight,
  Eye,
  AlertTriangle,
  Play,
  CheckCircle2,
  Sliders,
} from 'lucide-react';

export type AuthStage = 'IDLE_RED' | 'SYNCING_BLUE' | 'CLOSING_FLASH' | 'TERMINAL_ACTIVE';

interface LoginViewProps {
  onLoginSuccess: (operator: OperatorProfile, token: string) => void;
  showToast?: (type: 'success' | 'warning' | 'error' | 'info', title: string, detail?: string) => void;
}

// Custom Character Scrambler Hook
function useScrambleText(targetText: string, active = true) {
  const [displayText, setDisplayText] = useState(targetText);
  const chars = '!<>-_\\/[]{}—=+*^?#_0123456789ABCDEF';

  useEffect(() => {
    if (!active) {
      setDisplayText(targetText);
      return;
    }
    let frame = 0;
    const totalFrames = 20;
    const interval = setInterval(() => {
      frame++;
      const progress = frame / totalFrames;
      const length = targetText.length;
      let result = '';

      for (let i = 0; i < length; i++) {
        if (i < progress * length) {
          result += targetText[i];
        } else if (targetText[i] === ' ') {
          result += ' ';
        } else {
          result += chars[Math.floor(Math.random() * chars.length)];
        }
      }

      setDisplayText(result);

      if (frame >= totalFrames) {
        clearInterval(interval);
        setDisplayText(targetText);
      }
    }, 25);

    return () => clearInterval(interval);
  }, [targetText, active]);

  return displayText;
}

export const LoginView: React.FC<LoginViewProps> = ({ onLoginSuccess, showToast }) => {
  // State Machine Controller
  const [stage, setStage] = useState<AuthStage>('IDLE_RED');
  const [flashOpacity, setFlashOpacity] = useState(0);
  const [shutterProgress, setShutterProgress] = useState(0); // 0 = open, 1 = closed horizontal laser
  const [stageScale, setStageScale] = useState(1);

  // Form States
  const [operatorId, setOperatorId] = useState('root@drishti-sec');
  const [passphrase, setPassphrase] = useState('••••••••••••');
  const [tokenInput, setTokenInput] = useState('ED25519-948A-AUTH-BIO-09');
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Telemetry Micro-Readouts
  const [telemetryTimestamp, setTelemetryTimestamp] = useState('');
  const [hexCounter, setHexCounter] = useState('0x7FFF89AC');
  const [pupilCoords, setPupilCoords] = useState('[+0.00, +0.00]');
  const [depthVal, setDepthVal] = useState('54.2 cm');
  const [pupilMm, setPupilMm] = useState('4.82mm');
  const [activeFlags, setActiveFlags] = useState<string[]>([]);

  // Stage 4 Terminal Interactive States
  const [selectedNode, setSelectedNode] = useState<number | null>(5);
  const [countermeasures, setCountermeasures] = useState({
    vlanIsolate: true,
    rekeyEnclave: true,
    deployTarpit: false,
    poisonBgp: false,
  });
  const [logFilter, setLogFilter] = useState('');
  const [autoScrollLogs, setAutoScrollLogs] = useState(true);

  // Canvas Refs & Setup
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const arenaRef = useRef<HTMLDivElement | null>(null);
  const animFrameRef = useRef<number | null>(null);
  const terminalLogEndRef = useRef<HTMLDivElement | null>(null);

  // Transition & Animation Timers
  const transitionTimersRef = useRef<any[]>([]);

  // Geometry
  const SIZE = 280;
  const CENTER = SIZE / 2; // 140
  const IRIS_RADIUS = 58;
  const MAX_IRIS_OFFSET = 36;

  // Eye Physics State
  const physicsRef = useRef({
    mouseX: typeof window !== 'undefined' ? window.innerWidth / 2 : 700,
    mouseY: typeof window !== 'undefined' ? window.innerHeight / 2 : 400,
    curX: 0,
    curY: 0,
    targetX: 0,
    targetY: 0,
    saccadeX: 0,
    saccadeY: 0,
    pupilRadius: 20,
    targetPupilRadius: 20,
    pupilTwitch: 0,
    colorTransition: 0, // 0 = Red, 1 = Blue
    targetColorTransition: 0,
    isBlinking: false,
    blinkStartTime: 0,
    blinkDuration: 140,
    blinkProgress: 0,
  });

  // Vessels & Iris Fiber Seed Caches
  const vesselSeedsRef = useRef<Array<{
    points: Array<{ x: number; y: number }>;
    width: number;
    alpha: number;
  }>>([]);

  const irisFibersRef = useRef<Array<{
    angle: number;
    innerRel: number;
    outerRel: number;
    colRed: string;
    colBlue: string;
    width: number;
  }>>([]);

  // Generate Capillary Seeds
  const generateVessels = useCallback(() => {
    const vessels: typeof vesselSeedsRef.current = [];
    const count = 32;
    for (let i = 0; i < count; i++) {
      const angle = (i / count) * Math.PI * 2 + (Math.random() * 0.2 - 0.1);
      const outerR = CENTER * 0.96;
      const innerR = IRIS_RADIUS * 1.08 + Math.random() * 14;
      const points: Array<{ x: number; y: number }> = [];
      let r = outerR;
      let a = angle;
      while (r > innerR) {
        points.push({
          x: CENTER + Math.cos(a) * r,
          y: CENTER + Math.sin(a) * r,
        });
        r -= 4 + Math.random() * 4;
        a += (Math.random() - 0.5) * 0.22;
      }
      vessels.push({
        points,
        width: 0.5 + Math.random() * 0.9,
        alpha: 0.45 + Math.random() * 0.4,
      });
    }
    vesselSeedsRef.current = vessels;
  }, [CENTER, IRIS_RADIUS]);

  // Generate Iris Fibers (Precomputed Dual-Tone for Red & Neon Electric Blue)
  const generateIrisFibers = useCallback(() => {
    const fibers: typeof irisFibersRef.current = [];
    const FIBER_COUNT = 420;
    for (let i = 0; i < FIBER_COUNT; i++) {
      const angle = (i / FIBER_COUNT) * Math.PI * 2 + (Math.random() * 0.01);
      const innerRel = 0.22 + Math.random() * 0.1;
      const outerRel = 0.97 - Math.random() * 0.03;
      const roll = Math.random();

      // Red tones
      let colRed = 'rgba(220, 38, 38, 0.7)';
      if (roll > 0.8) colRed = 'rgba(255, 255, 255, 0.85)';
      else if (roll > 0.5) colRed = 'rgba(255, 30, 66, 0.85)';
      else if (roll > 0.25) colRed = 'rgba(185, 28, 28, 0.65)';

      // Blue tones
      let colBlue = 'rgba(2, 132, 199, 0.75)';
      if (roll > 0.8) colBlue = 'rgba(255, 255, 255, 0.9)';
      else if (roll > 0.5) colBlue = 'rgba(0, 240, 255, 0.95)';
      else if (roll > 0.25) colBlue = 'rgba(37, 99, 235, 0.85)';

      fibers.push({
        angle,
        innerRel,
        outerRel,
        colRed,
        colBlue,
        width: 0.6 + Math.random() * 0.8,
      });
    }
    irisFibersRef.current = fibers;
  }, []);

  // Natural Blinking
  const triggerBlink = useCallback((duration = 140) => {
    const p = physicsRef.current;
    if (p.isBlinking) return;
    p.isBlinking = true;
    p.blinkStartTime = performance.now();
    p.blinkDuration = duration;
  }, []);

  // Update target physics according to stage
  useEffect(() => {
    const p = physicsRef.current;
    if (stage === 'IDLE_RED') {
      p.targetColorTransition = 0; // Pure Red
      p.targetPupilRadius = 20;
      setShutterProgress(0);
      setFlashOpacity(0);
      setStageScale(1);
    } else if (stage === 'SYNCING_BLUE') {
      p.targetColorTransition = 1; // Neon Electric Blue
      p.targetPupilRadius = 24.5; // Dilation by 1.18x
      setShutterProgress(0);
      setFlashOpacity(0);
      setStageScale(1);
    } else if (stage === 'CLOSING_FLASH') {
      p.targetColorTransition = 1;
      p.targetPupilRadius = 16;
    } else if (stage === 'TERMINAL_ACTIVE') {
      setShutterProgress(0);
      setFlashOpacity(0);
      setStageScale(1);
    }
  }, [stage]);

  // Kinetic Transition Choreography for Stage 3 (Strict Timeline)
  const executeKineticTransition = useCallback(() => {
    // Clear old timers
    transitionTimersRef.current.forEach(clearTimeout);
    transitionTimersRef.current = [];

    setStage('CLOSING_FLASH');
    setIsSubmitting(true);

    // t = 0ms -> 280ms: Mechanical Eyelid Closure into razor-thin laser line
    setShutterProgress(1);

    // t = 280ms -> 450ms: Optic CRT Flash overlay
    const tFlash = setTimeout(() => {
      setFlashOpacity(1);
    }, 280);

    // t = 450ms -> 850ms: Dissipation & Mount of Stage 4 Terminal
    const tMount = setTimeout(() => {
      setFlashOpacity(0);
      setStage('TERMINAL_ACTIVE');
      setIsSubmitting(false);
      setStageScale(1);
      if (showToast) {
        showToast('success', 'Biometric Enclave Verified', 'DRISHTI Cyber Intelligence Core active.');
      }
    }, 550);

    transitionTimersRef.current.push(tFlash, tMount);
  }, [showToast]);

  // User input detection triggering SYNCING_BLUE
  const handleInputChange = (field: 'op' | 'pass' | 'token', val: string) => {
    if (field === 'op') setOperatorId(val);
    if (field === 'pass') setPassphrase(val);
    if (field === 'token') setTokenInput(val);

    // Immediately trigger SYNCING_BLUE if user enters text and we are in IDLE_RED
    if (stage === 'IDLE_RED') {
      setStage('SYNCING_BLUE');
    }
  };

  const handleFormSubmit = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (stage === 'CLOSING_FLASH' || stage === 'TERMINAL_ACTIVE') return;
    executeKineticTransition();
  };

  // Keyboard shortcut Ctrl+Enter or Cmd+Enter
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
        if (stage !== 'TERMINAL_ACTIVE' && stage !== 'CLOSING_FLASH') {
          executeKineticTransition();
        }
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [executeKineticTransition, stage]);

  // Main Canvas Rendering & Ocular Loop
  useEffect(() => {
    generateVessels();
    generateIrisFibers();

    const handleMouseMove = (e: MouseEvent) => {
      physicsRef.current.mouseX = e.clientX;
      physicsRef.current.mouseY = e.clientY;
    };
    window.addEventListener('mousemove', handleMouseMove);

    // Blinking schedule
    let blinkTimer: any;
    const scheduleNextBlink = () => {
      const delay = 3200 + Math.random() * 3800;
      blinkTimer = setTimeout(() => {
        triggerBlink(130 + Math.random() * 30);
        scheduleNextBlink();
      }, delay);
    };
    scheduleNextBlink();

    // Saccades schedule (only active when not centered locked in Blue)
    let saccadeTimer: any;
    const scheduleNextSaccade = () => {
      const delay = 900 + Math.random() * 2200;
      saccadeTimer = setTimeout(() => {
        if (physicsRef.current.colorTransition < 0.6) {
          physicsRef.current.saccadeX = (Math.random() - 0.5) * 4.5;
          physicsRef.current.saccadeY = (Math.random() - 0.5) * 3.5;
          physicsRef.current.pupilTwitch = (Math.random() - 0.5) * 3.0;
          setTimeout(() => {
            physicsRef.current.saccadeX = 0;
            physicsRef.current.saccadeY = 0;
            physicsRef.current.pupilTwitch = 0;
          }, 90);
        }
        scheduleNextSaccade();
      }, delay);
    };
    scheduleNextSaccade();

    // Micro-telemetry Interval
    const telemetryInterval = setInterval(() => {
      const now = new Date();
      setTelemetryTimestamp(
        `${now.toISOString().slice(0, 10)} ${now.toTimeString().slice(0, 8)}.${String(now.getMilliseconds()).padStart(3, '0')} UTC`
      );
      setHexCounter(`0x${(0x7fff0000 + Math.floor(Math.random() * 0xffff)).toString(16).toUpperCase()}`);
      const base = 54.0 + (Math.random() * 0.6 - 0.3);
      setDepthVal(`${base.toFixed(1)} cm`);
      const mm = (3.4 + (physicsRef.current.pupilRadius / 20) * 1.4 + Math.random() * 0.08).toFixed(2);
      setPupilMm(`${mm}mm`);
    }, 380);

    // 60fps Render Loop
    const renderLoop = (timestamp: number) => {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      if (!ctx) return;

      const p = physicsRef.current;

      // Color transition lerp (Red <-> Blue)
      p.colorTransition += (p.targetColorTransition - p.colorTransition) * 0.12;
      const ct = p.colorTransition;

      // Gaze offset calculation
      const arena = arenaRef.current;
      if (arena) {
        const rect = arena.getBoundingClientRect();
        const ax = rect.left + rect.width / 2;
        const ay = rect.top + rect.height / 2;

        if (ct > 0.8) {
          // When in blue state, gaze firmly locks onto center
          p.targetX = 0;
          p.targetY = 0;
        } else {
          const normX = Math.max(-1, Math.min(1, (p.mouseX - ax) / (window.innerWidth / 2)));
          const normY = Math.max(-1, Math.min(1, (p.mouseY - ay) / (window.innerHeight / 2)));
          p.targetX = normX * MAX_IRIS_OFFSET;
          p.targetY = normY * MAX_IRIS_OFFSET;

          const dist = Math.sqrt(p.targetX * p.targetX + p.targetY * p.targetY);
          if (dist > MAX_IRIS_OFFSET) {
            p.targetX = (p.targetX / dist) * MAX_IRIS_OFFSET;
            p.targetY = (p.targetY / dist) * MAX_IRIS_OFFSET;
          }
        }
      }

      // Smooth ocular inertia
      p.curX += (p.targetX + p.saccadeX - p.curX) * 0.14;
      p.curY += (p.targetY + p.saccadeY - p.curY) * 0.14;

      // Micro-hippus oscillation
      const hippus = Math.sin(timestamp * 0.002) * 1.2;
      p.pupilRadius += (p.targetPupilRadius + hippus + p.pupilTwitch - p.pupilRadius) * 0.12;

      // Clear Canvas
      ctx.clearRect(0, 0, SIZE, SIZE);

      ctx.save();
      ctx.beginPath();
      ctx.arc(CENTER, CENTER, CENTER - 2, 0, Math.PI * 2);
      ctx.clip();

      // 1. SCLERA (Dark Void / Cybernetic Optical Glass base with 3D Depth)
      const scleraGrad = ctx.createRadialGradient(CENTER, CENTER, 20, CENTER, CENTER, CENTER);
      scleraGrad.addColorStop(0, '#0D1117');
      scleraGrad.addColorStop(0.5, '#07090E');
      scleraGrad.addColorStop(0.85, '#030407');
      scleraGrad.addColorStop(1.0, '#000000');
      ctx.fillStyle = scleraGrad;
      ctx.fillRect(0, 0, SIZE, SIZE);

      // Peripheral Red or Blue vascular glow flush
      const flushLeft = ctx.createRadialGradient(16, CENTER, 2, 28, CENTER, 85);
      const flushColor = ct > 0.5 ? 'rgba(0, 240, 255, 0.35)' : 'rgba(255, 30, 66, 0.45)';
      flushLeft.addColorStop(0, flushColor);
      flushLeft.addColorStop(1, 'transparent');
      ctx.fillStyle = flushLeft;
      ctx.fillRect(0, 0, SIZE, SIZE);

      const flushRight = ctx.createRadialGradient(SIZE - 16, CENTER, 2, SIZE - 28, CENTER, 85);
      flushRight.addColorStop(0, flushColor);
      flushRight.addColorStop(1, 'transparent');
      ctx.fillStyle = flushRight;
      ctx.fillRect(0, 0, SIZE, SIZE);

      // Scleral micro-capillaries
      vesselSeedsRef.current.forEach((v) => {
        if (v.points.length < 2) return;
        ctx.beginPath();
        ctx.moveTo(v.points[0].x, v.points[0].y);
        for (let i = 1; i < v.points.length; i++) {
          ctx.lineTo(v.points[i].x, v.points[i].y);
        }
        ctx.strokeStyle = ct > 0.5 ? `rgba(0, 240, 255, ${v.alpha * 0.8})` : `rgba(255, 30, 66, ${v.alpha * 0.85})`;
        ctx.lineWidth = v.width;
        ctx.lineCap = 'round';
        ctx.stroke();
      });

      // 2. IRIS & CORNEA POSITION
      const irisX = CENTER + p.curX;
      const irisY = CENTER + p.curY;

      // Limbal Ring Outer Aura
      const limbalAura = ctx.createRadialGradient(irisX, irisY, IRIS_RADIUS - 4, irisX, irisY, IRIS_RADIUS + 8);
      limbalAura.addColorStop(0, 'transparent');
      limbalAura.addColorStop(0.65, ct > 0.5 ? 'rgba(0, 240, 255, 0.7)' : 'rgba(255, 30, 66, 0.75)');
      limbalAura.addColorStop(1.0, 'transparent');
      ctx.fillStyle = limbalAura;
      ctx.beginPath();
      ctx.arc(irisX, irisY, IRIS_RADIUS + 8, 0, Math.PI * 2);
      ctx.fill();

      // Iris Base Gradient (Smoothly blending Red <-> Blue)
      const irisGrad = ctx.createRadialGradient(irisX, irisY, p.pupilRadius * 0.65, irisX, irisY, IRIS_RADIUS);
      if (ct > 0.5) {
        // Neon Electric Blue Palette
        irisGrad.addColorStop(0, '#030B1A');
        irisGrad.addColorStop(0.2, '#0B254E');
        irisGrad.addColorStop(0.55, '#0284C7');
        irisGrad.addColorStop(0.85, '#00F0FF');
        irisGrad.addColorStop(1.0, '#020617');
      } else {
        // Sentinel Crimson Red Palette
        irisGrad.addColorStop(0, '#1A0407');
        irisGrad.addColorStop(0.2, '#4C0913');
        irisGrad.addColorStop(0.55, '#DC2626');
        irisGrad.addColorStop(0.85, '#FF1E42');
        irisGrad.addColorStop(1.0, '#0A0103');
      }
      ctx.fillStyle = irisGrad;
      ctx.beginPath();
      ctx.arc(irisX, irisY, IRIS_RADIUS, 0, Math.PI * 2);
      ctx.fill();

      // Dark Limbal Ring Stroke
      ctx.strokeStyle = ct > 0.5 ? '#00F0FF' : '#FF1E42';
      ctx.lineWidth = 1.8;
      ctx.stroke();

      // Iris Muscle Fibers
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
        ctx.strokeStyle = ct > 0.5 ? f.colBlue : f.colRed;
        ctx.lineWidth = f.width;
        ctx.stroke();
      });

      // Collarette Wavy Crypt Ring
      ctx.beginPath();
      const collaretteR = p.pupilRadius + (IRIS_RADIUS - p.pupilRadius) * 0.44;
      for (let a = 0; a <= Math.PI * 2; a += 0.08) {
        const wobble = Math.sin(a * 20) * 1.8;
        const cr = collaretteR + wobble;
        const cx = irisX + Math.cos(a) * cr;
        const cy = irisY + Math.sin(a) * cr;
        if (a === 0) ctx.moveTo(cx, cy);
        else ctx.lineTo(cx, cy);
      }
      ctx.closePath();
      ctx.strokeStyle = ct > 0.5 ? 'rgba(0, 240, 255, 0.95)' : 'rgba(255, 255, 255, 0.85)';
      ctx.lineWidth = 1.4;
      ctx.stroke();

      // 3. PUPIL & INNER ASCII MATRIX CORE
      ctx.fillStyle = '#000000';
      ctx.beginPath();
      ctx.arc(irisX, irisY, Math.max(8, p.pupilRadius), 0, Math.PI * 2);
      ctx.fill();

      // Sphincter Muscle Radial Shadow
      const sphincter = ctx.createRadialGradient(irisX, irisY, p.pupilRadius * 0.75, irisX, irisY, p.pupilRadius * 1.28);
      sphincter.addColorStop(0, 'rgba(0, 0, 0, 1)');
      sphincter.addColorStop(0.65, ct > 0.5 ? 'rgba(0, 240, 255, 0.35)' : 'rgba(255, 30, 66, 0.4)');
      sphincter.addColorStop(1, 'transparent');
      ctx.fillStyle = sphincter;
      ctx.beginPath();
      ctx.arc(irisX, irisY, p.pupilRadius * 1.28, 0, Math.PI * 2);
      ctx.fill();

      // Inner Matrix Core Glyph
      ctx.fillStyle = ct > 0.5 ? '#00F0FF' : '#FF1E42';
      ctx.font = '8px monospace';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      const matrixChar = ct > 0.5 ? '01' : 'Ø';
      ctx.fillText(matrixChar, irisX, irisY);

      // 4. CORNEAL SPECULAR HIGHLIGHTS
      const glintX = irisX - IRIS_RADIUS * 0.28;
      const glintY = irisY - IRIS_RADIUS * 0.32;
      ctx.save();
      ctx.translate(glintX, glintY);
      ctx.rotate(-0.35);
      ctx.fillStyle = '#FFFFFF';
      ctx.shadowColor = ct > 0.5 ? '#00F0FF' : '#FF1E42';
      ctx.shadowBlur = 8;
      ctx.beginPath();
      ctx.ellipse(0, 0, 6.2, 3.2, 0, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();

      ctx.fillStyle = '#FFFFFF';
      ctx.beginPath();
      ctx.arc(irisX - IRIS_RADIUS * 0.14, irisY - IRIS_RADIUS * 0.12, 1.8, 0, Math.PI * 2);
      ctx.fill();

      // Antireflective Depth Shadow
      const socketShadow = ctx.createLinearGradient(CENTER, 0, CENTER, CENTER + 30);
      socketShadow.addColorStop(0, 'rgba(0, 0, 0, 0.55)');
      socketShadow.addColorStop(0.6, 'rgba(0, 0, 0, 0.15)');
      socketShadow.addColorStop(1, 'transparent');
      ctx.fillStyle = socketShadow;
      ctx.fillRect(0, 0, SIZE, SIZE);

      ctx.restore(); // end clip

      // Update Gaze Readout
      const vx = (p.curX / MAX_IRIS_OFFSET).toFixed(2);
      const vy = (p.curY / MAX_IRIS_OFFSET).toFixed(2);
      const sx = Number(vx) >= 0 ? '+' : '';
      const sy = Number(vy) >= 0 ? '+' : '';
      setPupilCoords(`[${sx}${vx}, ${sy}${vy}]`);

      animFrameRef.current = requestAnimationFrame(renderLoop);
    };

    animFrameRef.current = requestAnimationFrame(renderLoop);

    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      if (blinkTimer) clearTimeout(blinkTimer);
      if (saccadeTimer) clearTimeout(saccadeTimer);
      clearInterval(telemetryInterval);
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
    };
  }, [CENTER, IRIS_RADIUS, MAX_IRIS_OFFSET, generateIrisFibers, generateVessels, triggerBlink]);

  // Scrambled status text
  const statusRawText =
    stage === 'IDLE_RED'
      ? '[STATUS: BIOMETRIC_LOCK_ENGAGED // CLEARANCE_LEVEL: 0]'
      : stage === 'SYNCING_BLUE'
      ? '[STATUS: BIOMETRIC_SIGNATURE_RECOGNIZED // DECRYPTING_GUARD_ENGINE]'
      : stage === 'CLOSING_FLASH'
      ? '[STATUS: ENCLAVE_OPTIC_FLASH // PROVING_ZERO_KNOWLEDGE_PROOF]'
      : '[STATUS: TERMINAL_ACTIVE // DEFCON-5 ONLINE_ROOT]';

  const scrambledStatusText = useScrambleText(statusRawText, stage !== 'CLOSING_FLASH');

  // Trigger entering full Cockpit Dashboard
  const handleLaunchPersistentSession = () => {
    const op: OperatorProfile = {
      id: 'op-alex-morgan',
      name: 'Alex Morgan',
      email: 'root@drishti.sec',
      role: 'Principal Cyber Intelligence Architect',
      clearance: 'LEVEL 5 // TOP SECRET // AIRGAP',
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
      default_scope: 'FULL_ACTIVE_ENFORCED',
      token_fingerprint: 'SHA256: 8f43...27aa4',
    };

    localStorage.setItem('drishti_auth_token', tokenInput.trim() || 'ED25519-948A-AUTH-BIO-09');
    localStorage.setItem('drishti_operator', JSON.stringify(op));

    onLoginSuccess(op, tokenInput.trim());
  };

  const isBlue = stage === 'SYNCING_BLUE' || stage === 'CLOSING_FLASH';

  return (
    <div
      className="relative flex flex-col justify-between w-screen h-screen bg-[#07090E] text-[#E5E7EB] select-none overflow-hidden font-mono"
      style={
        {
          '--theme-color': isBlue ? '#00F0FF' : '#FF1E42',
          '--accent-glow': isBlue ? 'rgba(0, 240, 255, 0.35)' : 'rgba(255, 30, 66, 0.35)',
        } as React.CSSProperties
      }
    >
      {/* ======================================================== */}
      {/* CRT SCANLINE & RETICLE OVERLAY                           */}
      {/* ======================================================== */}
      <style>{`
        /* CRT Scanline and Phosphor Vignette */
        .crt-overlay {
          position: fixed;
          inset: 0;
          pointer-events: none;
          z-index: 45;
          background: radial-gradient(circle at center, transparent 65%, rgba(0, 0, 0, 0.75) 98%),
                      linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.32) 50%);
          background-size: 100% 100%, 100% 3px;
          opacity: 0.85;
        }

        /* Biomechanical Eyelid Shutters for Stage 3 */
        .biomech-shutter-top {
          transform: translateY(${shutterProgress > 0 ? '0%' : '-101%'});
          transition: transform 280ms cubic-bezier(0.16, 1, 0.3, 1);
        }
        .biomech-shutter-bottom {
          transform: translateY(${shutterProgress > 0 ? '0%' : '101%'});
          transition: transform 280ms cubic-bezier(0.16, 1, 0.3, 1);
        }

        /* Kinetic Optic Flash */
        .flash-overlay {
          position: fixed;
          inset: 0;
          pointer-events: none;
          z-index: 60;
          background: radial-gradient(circle, #FFFFFF 0%, #00F0FF 60%, transparent 100%);
          mix-blend-mode: screen;
          transition: opacity 280ms cubic-bezier(0.16, 1, 0.3, 1);
        }

        /* Reticle Rotation Animations */
        @keyframes spinSlow {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        @keyframes spinFast {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        @keyframes counterSpinSlow {
          0% { transform: rotate(360deg); }
          100% { transform: rotate(0deg); }
        }
        .reticle-spin-slow {
          animation: spinSlow ${isBlue ? '1.2s' : '4s'} linear infinite;
        }
        .reticle-counter-spin {
          animation: counterSpinSlow ${isBlue ? '2.5s' : '10s'} linear infinite;
        }

        /* Breathing pulse on Idle Red eye */
        @keyframes breathPulse {
          0%, 100% { transform: scale(0.985); }
          50% { transform: scale(1.015); }
        }
        .eye-breath {
          animation: breathPulse 4s ease-in-out infinite;
        }
      `}</style>

      {/* CRT Scanline Screen Overlay */}
      <div className="crt-overlay"></div>

      {/* Stage 3 Optic CRT Flash Screen */}
      <div
        className="flash-overlay"
        style={{
          opacity: flashOpacity,
        }}
      ></div>

      {/* Corner Crosshairs (+) Registration Marks */}
      <span className="fixed top-2 left-2 z-40 text-[11px] text-[#475569] font-mono pointer-events-none">+</span>
      <span className="fixed top-2 right-2 z-40 text-[11px] text-[#475569] font-mono pointer-events-none">+</span>
      <span className="fixed bottom-2 left-2 z-40 text-[11px] text-[#475569] font-mono pointer-events-none">+</span>
      <span className="fixed bottom-2 right-2 z-40 text-[11px] text-[#475569] font-mono pointer-events-none">+</span>

      {/* Top Left Micro-Telemetry Corner */}
      <div className="fixed top-2.5 left-6 z-40 text-[9px] text-[#64748B] font-mono tracking-wider pointer-events-none hidden md:block">
        <span>SYS_CLK // {telemetryTimestamp || 'SYNCING...'}</span>
        <span className="ml-3 text-[#38BDF8]">MEM_DUMP: {hexCounter}</span>
      </div>

      {/* Top Right Micro-Telemetry Corner */}
      <div className="fixed top-2.5 right-6 z-40 text-[9px] text-[#64748B] font-mono tracking-wider pointer-events-none hidden md:block text-right">
        <span>FRAME_RATE: 60.0 FPS // GPU_ACCEL</span>
        <span className="ml-3 text-[var(--theme-color)] font-bold">STATE: {stage}</span>
      </div>

      {/* ======================================================== */}
      {/* VIEW CONDITIONAL: STAGE 1, 2, 3 (BIOMETRIC GATEWAY)      */}
      {/* ======================================================== */}
      {stage !== 'TERMINAL_ACTIVE' ? (
        <div
          className="relative z-30 flex flex-col items-center justify-center flex-1 w-full max-w-5xl mx-auto px-4 py-3 transition-transform duration-500"
          style={{ transform: `scale(${stageScale})` }}
        >
          {/* Top Status Scramble Badge */}
          <div className="flex items-center gap-2 px-3 py-1 bg-[#0D1117] border border-[rgba(255,255,255,0.12)] mb-3 shadow-[0_0_20px_rgba(0,0,0,0.8)]">
            <span
              className="w-2 h-2 rounded-full animate-ping"
              style={{ backgroundColor: 'var(--theme-color)' }}
            ></span>
            <span
              className="text-[10px] tracking-[0.14em] font-bold"
              style={{ color: 'var(--theme-color)' }}
            >
              {scrambledStatusText}
            </span>
          </div>

          {/* ====================================================== */}
          {/* THE CIRCULAR BIOMETRIC EYE & RETICLE ARRAY             */}
          {/* ====================================================== */}
          <div
            className={`relative w-[340px] h-[340px] flex items-center justify-center mb-3 ${
              stage === 'IDLE_RED' ? 'eye-breath' : ''
            }`}
            id="scanArena"
            ref={arenaRef}
          >
            {/* Azimuth Degree Labels */}
            <div
              className="absolute -top-3 text-[8px] font-mono tracking-widest font-bold pointer-events-none bg-[#07090E] px-2 border"
              style={{ borderColor: 'var(--theme-color)', color: 'var(--theme-color)' }}
            >
              AZM 000° // APERTURE_NORTH
            </div>
            <div className="absolute -bottom-3 text-[8px] font-mono tracking-widest text-[#64748B] pointer-events-none bg-[#07090E] px-2 border border-[rgba(255,255,255,0.12)]">
              AZM 180° // APERTURE_SOUTH
            </div>

            {/* Concentric Rotating HUD Rings */}
            {/* Outer dashed ring with accelerated rotation */}
            <div
              className="absolute w-[334px] h-[334px] rounded-full border border-dashed pointer-events-none reticle-spin-slow"
              style={{
                borderColor: isBlue ? 'rgba(0, 240, 255, 0.55)' : 'rgba(255, 30, 66, 0.45)',
              }}
            ></div>

            {/* Middle counter-spinning ring */}
            <div
              className="absolute w-[314px] h-[314px] rounded-full border border-dotted pointer-events-none reticle-counter-spin"
              style={{
                borderColor: isBlue ? 'rgba(37, 99, 235, 0.45)' : 'rgba(239, 68, 68, 0.35)',
              }}
            ></div>

            {/* Static inner framing ring with degree ticks */}
            <div
              className="absolute w-[296px] h-[296px] rounded-full border pointer-events-none shadow-[0_0_25px_var(--accent-glow)]"
              style={{ borderColor: 'var(--theme-color)' }}
            ></div>

            {/* Degree Ticks SVG */}
            <svg className="absolute inset-0 w-full h-full pointer-events-none z-10" viewBox="0 0 340 340">
              <line x1="170" y1="4" x2="170" y2="16" stroke="var(--theme-color)" strokeWidth="2" />
              <line x1="170" y1="324" x2="170" y2="336" stroke="var(--theme-color)" strokeWidth="2" />
              <line x1="4" y1="170" x2="16" y2="170" stroke="var(--theme-color)" strokeWidth="2" />
              <line x1="324" y1="170" x2="336" y2="170" stroke="var(--theme-color)" strokeWidth="2" />
              <circle cx="170" cy="170" r="148" fill="none" stroke="rgba(255,255,255,0.1)" strokeDasharray="2 10" strokeWidth="1" />
            </svg>

            {/* Circular Eye Portal Container */}
            <div
              className="relative w-[280px] h-[280px] rounded-full overflow-hidden bg-[#07090E] border-2 shadow-[0_0_35px_var(--accent-glow),inset_0_0_40px_rgba(0,0,0,0.95)] flex items-center justify-center z-20"
              style={{ borderColor: 'var(--theme-color)' }}
            >
              {/* HTML5 Canvas */}
              <canvas
                className="absolute inset-0 w-full h-full block z-10"
                height={SIZE}
                ref={canvasRef}
                width={SIZE}
              ></canvas>

              {/* Anti-reflective Optical Depth Vignette */}
              <div className="absolute inset-0 rounded-full shadow-[inset_0_0_45px_rgba(0,0,0,0.95),inset_0_15px_25px_rgba(255,255,255,0.15)] pointer-events-none z-20"></div>

              {/* Biomechanical Shutters / Eyelids (0ms -> 280ms vertical snap closure) */}
              <div
                className="absolute top-0 left-0 w-full h-1/2 bg-[#07090E] z-30 pointer-events-none biomech-shutter-top border-b-2"
                style={{ borderColor: 'var(--theme-color)', boxShadow: '0 4px 16px var(--accent-glow)' }}
              ></div>
              <div
                className="absolute bottom-0 left-0 w-full h-1/2 bg-[#07090E] z-30 pointer-events-none biomech-shutter-bottom border-t-2"
                style={{ borderColor: 'var(--theme-color)', boxShadow: '0 -4px 16px var(--accent-glow)' }}
              ></div>
            </div>

            {/* Flanking Micro-Metrics (Left) */}
            <div className="absolute -left-20 top-1/2 -translate-y-1/2 text-[8.5px] text-[#64748B] font-mono leading-relaxed tracking-wider text-left pointer-events-none hidden lg:block">
              <div className="text-[var(--theme-color)] font-bold">// OPTO_ACQUISITION</div>
              <div>FACIAL_DEPTH: <span className="text-white font-bold">{depthVal}</span></div>
              <div>PUPIL_DIL: <span className="text-[#38BDF8]">{pupilMm}</span></div>
              <div>IPD_METRIC: <span className="text-white">63.8mm</span></div>
              <div>VESSEL_HASH: <span className="text-[var(--theme-color)]">0x9E4B..7A</span></div>
            </div>

            {/* Flanking Micro-Metrics (Right) */}
            <div className="absolute -right-20 top-1/2 -translate-y-1/2 text-[8.5px] text-[#64748B] font-mono leading-relaxed tracking-wider text-right pointer-events-none hidden lg:block">
              <div className="text-[#38BDF8] font-bold">// ENCLAVE_LOCK</div>
              <div>GAZE_VECTOR: <span className="text-white font-mono">{pupilCoords}</span></div>
              <div>CLEARANCE: <span className="text-[var(--theme-color)] font-bold">{stage === 'IDLE_RED' ? 'LEVEL_0' : 'LEVEL_5'}</span></div>
              <div>CORNEA_REFRACT: <span className="text-[#10B981]">OK</span></div>
              <div>ENTROPY_POOL: <span className="text-white font-mono">0x88F1</span></div>
            </div>
          </div>

          {/* ====================================================== */}
          {/* BRUTALIST CREDENTIAL MODULE (OPERATOR_ID & PASSPHRASE)  */}
          {/* ====================================================== */}
          <form
            onSubmit={handleFormSubmit}
            className="relative w-full max-w-[500px] bg-[#0D1117] border border-[rgba(255,255,255,0.12)] p-3.5 flex flex-col gap-2.5 shadow-[0_8px_32px_rgba(0,0,0,0.85)] z-30"
          >
            {/* Header Strip */}
            <div className="flex items-center justify-between text-[9px] text-[#94A3B8] border-b border-[rgba(255,255,255,0.08)] pb-1.5">
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: 'var(--theme-color)' }}></span>
                <span className="text-white font-bold tracking-wider">
                  OPERATOR_AUTHENTICATION // ENCLAVE_SECRETS
                </span>
              </div>
              <span className="text-[#64748B] font-mono text-[8px]">DEFCON-1 : ACTIVE</span>
            </div>

            {/* Input Row 1: OPERATOR_ID */}
            <div className="flex flex-col gap-1">
              <label className="text-[8.5px] text-[#64748B] tracking-wider font-semibold">
                OPERATOR_ID (OR SERVICE ACCOUNT)
              </label>
              <div className="flex items-center bg-[#161B22] border border-[rgba(255,255,255,0.1)] px-2.5 py-1.5 focus-within:border-[var(--theme-color)] transition-colors">
                <span className="text-[#38BDF8] text-[10px] mr-2">root@</span>
                <input
                  type="text"
                  value={operatorId}
                  onChange={(e) => handleInputChange('op', e.target.value)}
                  placeholder="OPERATOR_CALLSIGN..."
                  className="bg-transparent border-none outline-none text-[#F8FAFC] text-[11px] font-mono w-full focus:ring-0 p-0"
                  spellCheck={false}
                  autoComplete="off"
                />
              </div>
            </div>

            {/* Input Row 2: PASSPHRASE */}
            <div className="flex flex-col gap-1">
              <label className="text-[8.5px] text-[#64748B] tracking-wider font-semibold">
                PASSPHRASE // HARDWARE_KEY_TOKEN
              </label>
              <div className="flex items-center bg-[#161B22] border border-[rgba(255,255,255,0.1)] px-2.5 py-1.5 focus-within:border-[var(--theme-color)] transition-colors">
                <Lock className="w-3 h-3 text-[#64748B] mr-2" />
                <input
                  type="password"
                  value={passphrase}
                  onChange={(e) => handleInputChange('pass', e.target.value)}
                  placeholder="PASSPHRASE..."
                  className="bg-transparent border-none outline-none text-[#F8FAFC] text-[11px] font-mono w-full focus:ring-0 p-0"
                  spellCheck={false}
                  autoComplete="off"
                />
              </div>
            </div>

            {/* Flag Toggles */}
            <div className="flex items-center justify-between text-[8px] text-[#94A3B8] pt-1 border-t border-[rgba(255,255,255,0.08)]">
              <div className="flex items-center gap-1.5 overflow-x-auto">
                <span className="text-[#64748B] font-bold">FLAGS:</span>
                {['--bypass-sandbox', '--force-recon', '--elevate-root'].map((flag) => {
                  const isActive = activeFlags.includes(flag);
                  return (
                    <button
                      key={flag}
                      type="button"
                      onClick={() => {
                        setActiveFlags((prev) =>
                          prev.includes(flag) ? prev.filter((f) => f !== flag) : [...prev, flag]
                        );
                        if (stage === 'IDLE_RED') setStage('SYNCING_BLUE');
                      }}
                      className={`px-1.5 py-0.5 border text-[8px] font-mono transition-colors cursor-pointer ${
                        isActive
                          ? 'bg-[var(--theme-color)] text-[#07090E] border-[var(--theme-color)] font-bold'
                          : 'bg-[#161B22] border-[rgba(255,255,255,0.12)] text-[#94A3B8] hover:text-white'
                      }`}
                    >
                      [{flag}]
                    </button>
                  );
                })}
              </div>
              <span className="text-[#64748B] text-[7.5px] select-none">SHA256: 8f43..27aa4</span>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full h-[38px] mt-1 text-[11px] font-bold tracking-[0.16em] flex items-center justify-center gap-2 border transition-all cursor-pointer shadow-[0_4px_20px_var(--accent-glow)]"
              style={{
                backgroundColor: 'var(--theme-color)',
                borderColor: 'var(--theme-color)',
                color: '#07090E',
              }}
            >
              <Zap className="w-3.5 h-3.5 fill-current" />
              <span>
                {stage === 'SYNCING_BLUE'
                  ? '[ EXECUTE BIOMETRIC SYNC ⌘↵ ]'
                  : '[ INITIATE BIOMETRIC DECRYPTION ⌘↵ ]'}
              </span>
            </button>
          </form>
        </div>
      ) : (
        /* ======================================================== */
        /* STAGE 4: TERMINAL_ACTIVE (DRISHTI MAIN SOFTWARE SCREEN)  */
        /* ======================================================== */
        <div className="relative z-30 flex flex-col flex-1 w-full h-full p-3 gap-2 overflow-hidden animate-fadeIn">
          {/* Top Bar: System Status, Operator Badge, 3-Layer GUARD Engine Pills */}
          <header className="flex items-center justify-between w-full bg-[#0D1117] border border-[rgba(255,255,255,0.12)] px-4 py-2 shadow-md shrink-0">
            {/* System Status & Brand */}
            <div className="flex items-center gap-3">
              <span className="w-2.5 h-2.5 rounded-full bg-[#00F0FF] animate-pulse"></span>
              <div>
                <span className="text-[12px] text-white font-extrabold tracking-[0.14em]">
                  DRISHTI // v1.0.0-rc1
                </span>
                <span className="ml-2 text-[9px] px-1.5 py-0.5 bg-[#00F0FF]/15 text-[#00F0FF] border border-[#00F0FF]/40 font-bold">
                  AIR-GAP MATRIX
                </span>
              </div>
            </div>

            {/* 3-Layer GUARD Engine Status Pills */}
            <div className="hidden md:flex items-center gap-2 text-[9px] font-mono">
              <div className="bg-[#161B22] border border-[#10B981]/50 px-2 py-0.5 flex items-center gap-1.5">
                <CheckCircle2 className="w-3 h-3 text-[#10B981]" />
                <span className="text-[#10B981] font-bold">LAYER 1: INGEST</span>
                <span className="text-[#64748B]">[0 REJECTS]</span>
              </div>
              <div className="bg-[#161B22] border border-[#38BDF8]/50 px-2 py-0.5 flex items-center gap-1.5">
                <Shield className="w-3 h-3 text-[#38BDF8]" />
                <span className="text-[#38BDF8] font-bold">LAYER 2: HEURISTIC</span>
                <span className="text-[#64748B]">[PROMPT_GUARD]</span>
              </div>
              <div className="bg-[#161B22] border border-[#FF1E42]/50 px-2 py-0.5 flex items-center gap-1.5">
                <Lock className="w-3 h-3 text-[#FF1E42]" />
                <span className="text-[#FF1E42] font-bold">LAYER 3: CONTAINMENT</span>
                <span className="text-[#64748B]">[AIRGAP_ENFORCED]</span>
              </div>
            </div>

            {/* Active Operator Badge & Action */}
            <div className="flex items-center gap-3">
              <div className="text-right">
                <span className="text-[9px] text-[#94A3B8] block">AUTHENTICATED OPERATOR</span>
                <span className="text-[10.5px] text-white font-bold">ALEX MORGAN // SEC-ARCH-09</span>
              </div>
              <button
                type="button"
                onClick={handleLaunchPersistentSession}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-[#00F0FF] hover:bg-[#38BDF8] text-[#07090E] text-[10px] font-bold tracking-wider transition-colors cursor-pointer shadow-[0_0_15px_rgba(0,240,255,0.4)]"
                title="Open persistent cockpit session"
              >
                <span>ENTER COCKPIT</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            </div>
          </header>

          {/* Core 3-Pane Clinical Layout */}
          <div className="grid grid-cols-12 gap-2 flex-1 w-full min-h-0 overflow-hidden">
            {/* ==================================================== */}
            {/* PANE 1 (LEFT): Nmap / Target Recon Console          */}
            {/* ==================================================== */}
            <div className="col-span-12 lg:col-span-3 flex flex-col bg-[#0D1117] border border-[rgba(255,255,255,0.12)] p-2.5 overflow-hidden">
              <div className="flex items-center justify-between border-b border-[rgba(255,255,255,0.1)] pb-1.5 mb-2 text-[9px] font-bold tracking-wider">
                <div className="flex items-center gap-1.5 text-[#38BDF8]">
                  <Terminal className="w-3.5 h-3.5" />
                  <span>// NMAP_RECON_STREAM [ETH0]</span>
                </div>
                <span className="text-[8px] px-1 bg-[#38BDF8]/15 text-[#38BDF8] border border-[#38BDF8]/30">
                  LIVE_PROBES
                </span>
              </div>

              {/* Console Output */}
              <div className="flex-1 overflow-y-auto space-y-1.5 text-[8.5px] font-mono leading-relaxed pr-1 text-[#94A3B8]">
                <div className="text-[#38BDF8]">[+] [10.0.4.15] TCP SYN stealth scan initiated against 1024 ports</div>
                <div className="text-[#10B981]">[+] Discovered 22/tcp (OpenSSH 8.9p1 Ubuntu)</div>
                <div className="text-[#38BDF8]">[!] Discovered 443/tcp (nginx 1.24.0 // ALPN: h2, http/1.1)</div>
                <div className="text-[#FF1E42] font-bold">[CRIT] Discovered 8080/tcp (Spring Boot // Exposed Actuator /env)</div>
                <div className="text-[#FBBF24]">[*] Automated credential leak detected in /actuator/env: DRISHTI_TOKEN_HASH</div>
                <div className="text-[#64748B]">[*] Traceroute hop 1: 192.168.1.1 (0.41ms)</div>
                <div className="text-[#64748B]">[*] Traceroute hop 2: 10.0.4.1 (0.88ms)</div>
                <div className="text-[#10B981]">[+] Target OS fingerprint: Linux 5.15 (99% confidence)</div>
                <div className="text-[#38BDF8]">[+] SSL/TLS Cert: CN=internal-auth.drishti.sec [VALID]</div>
                <div className="text-[#FF1E42]">[CRIT] Vulnerability CVE-2024-38819 detected on route handler</div>
                <div className="text-[#64748B]">[*] Active SYN packet rate: 450 pkts/sec</div>
                <div className="text-[#10B981]">[+] Scope confirmation: 10.0.4.0/24 cryptographically sealed</div>
                <div ref={terminalLogEndRef}></div>
              </div>

              {/* Recon Command Input */}
              <div className="mt-2 pt-1.5 border-t border-[rgba(255,255,255,0.1)] flex items-center gap-1.5 text-[8.5px]">
                <span className="text-[#38BDF8] font-bold">&gt;</span>
                <input
                  type="text"
                  placeholder="EXEC_PROBE (e.g. --script vuln)..."
                  className="bg-transparent border-none outline-none text-white text-[8.5px] w-full p-0 font-mono focus:ring-0"
                />
              </div>
            </div>

            {/* ==================================================== */}
            {/* PANE 2 (CENTER): Interactive NetworkX Attack Graph   */}
            {/* ==================================================== */}
            <div className="col-span-12 lg:col-span-6 flex flex-col bg-[#0D1117] border border-[rgba(255,255,255,0.12)] p-2.5 overflow-hidden">
              <div className="flex items-center justify-between border-b border-[rgba(255,255,255,0.1)] pb-1.5 mb-2 text-[9px] font-bold tracking-wider">
                <div className="flex items-center gap-1.5 text-[var(--theme-color)]">
                  <Crosshair className="w-3.5 h-3.5" />
                  <span>// NETWORKX_ATTACK_GRAPH_PATHFINDER</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[8px] text-[#10B981] font-mono">DIJKSTRA_COST: 2.84</span>
                  <span className="text-[8px] px-1 bg-[#FF1E42]/20 text-[#FF1E42] border border-[#FF1E42]/40 font-bold">
                    CRITICAL_PATH_LOCKED
                  </span>
                </div>
              </div>

              {/* Interactive Graph Canvas */}
              <div className="relative flex-1 bg-[#07090E] border border-[rgba(255,255,255,0.06)] overflow-hidden flex items-center justify-center p-2">
                <svg className="w-full h-full" viewBox="0 0 600 360">
                  <defs>
                    <marker id="arrowRed" markerWidth="6" markerHeight="6" refX="10" refY="3" orient="auto">
                      <path d="M0,0 L0,6 L9,3 z" fill="#FF1E42" />
                    </marker>
                    <marker id="arrowCyan" markerWidth="6" markerHeight="6" refX="10" refY="3" orient="auto">
                      <path d="M0,0 L0,6 L9,3 z" fill="#00F0FF" />
                    </marker>
                  </defs>

                  {/* Directed Edges */}
                  {/* Node 0 -> Node 1 */}
                  <line x1="70" y1="180" x2="160" y2="100" stroke="#FF1E42" strokeWidth="2.5" strokeDasharray="4 2" markerEnd="url(#arrowRed)" />
                  {/* Node 0 -> Node 2 */}
                  <line x1="70" y1="180" x2="160" y2="260" stroke="rgba(255,255,255,0.2)" strokeWidth="1.2" />
                  {/* Node 1 -> Node 3 */}
                  <line x1="180" y1="90" x2="280" y2="140" stroke="#FF1E42" strokeWidth="2.5" strokeDasharray="4 2" markerEnd="url(#arrowRed)" />
                  {/* Node 2 -> Node 3 */}
                  <line x1="180" y1="260" x2="280" y2="160" stroke="rgba(255,255,255,0.2)" strokeWidth="1.2" />
                  {/* Node 3 -> Node 4 */}
                  <line x1="310" y1="150" x2="410" y2="230" stroke="rgba(255,255,255,0.2)" strokeWidth="1.2" />
                  {/* Node 3 -> Node 5 (CRITICAL TO CROWN JEWEL) */}
                  <line x1="310" y1="150" x2="470" y2="150" stroke="#FF1E42" strokeWidth="3" strokeDasharray="5 3" markerEnd="url(#arrowRed)">
                    <animate attributeName="stroke-dashoffset" values="0;-32" dur="1s" repeatCount="indefinite" />
                  </line>

                  {/* Edge Cost Tags */}
                  <text x="100" y="125" fill="#FF1E42" fontSize="8" fontFamily="monospace">p=0.88</text>
                  <text x="210" y="105" fill="#FF1E42" fontSize="8" fontFamily="monospace">p=0.92</text>
                  <text x="375" y="140" fill="#FF1E42" fontSize="9" fontWeight="bold" fontFamily="monospace">EXPLOIT (p=0.98)</text>

                  {/* Graph Nodes */}
                  {/* Node 0: ATTACKER INGRESS */}
                  <g onClick={() => setSelectedNode(0)} className="cursor-pointer">
                    <circle cx="60" cy="180" r="18" fill="#161B22" stroke="#38BDF8" strokeWidth="2" />
                    <text x="60" y="184" fill="#38BDF8" fontSize="8" textAnchor="middle" fontWeight="bold">INGRESS</text>
                    <text x="60" y="210" fill="#94A3B8" fontSize="7.5" textAnchor="middle">192.168.1.10</text>
                  </g>

                  {/* Node 1: DMZ PROXY (Compromised) */}
                  <g onClick={() => setSelectedNode(1)} className="cursor-pointer">
                    <circle cx="170" cy="90" r="18" fill="#1C0A0D" stroke="#FF1E42" strokeWidth="2.5" />
                    <text x="170" y="94" fill="#FF1E42" fontSize="8" textAnchor="middle" fontWeight="bold">DMZ_01</text>
                    <text x="170" y="65" fill="#F87171" fontSize="7.5" textAnchor="middle">443/TCP EXPLOIT</text>
                  </g>

                  {/* Node 2: PERIMETER WAF */}
                  <g onClick={() => setSelectedNode(2)} className="cursor-pointer">
                    <circle cx="170" cy="260" r="18" fill="#161B22" stroke="rgba(255,255,255,0.3)" strokeWidth="1.5" />
                    <text x="170" y="264" fill="#94A3B8" fontSize="8" textAnchor="middle">WAF_L7</text>
                    <text x="170" y="290" fill="#64748B" fontSize="7.5" textAnchor="middle">BYPASSED</text>
                  </g>

                  {/* Node 3: INTERNAL ROUTER / AUTH ENCLAVE */}
                  <g onClick={() => setSelectedNode(3)} className="cursor-pointer">
                    <circle cx="295" cy="150" r="22" fill="#1C0A0D" stroke="#FF1E42" strokeWidth="2.5" />
                    <text x="295" y="154" fill="#FF1E42" fontSize="8" textAnchor="middle" fontWeight="bold">AUTH_ENCLAVE</text>
                    <text x="295" y="182" fill="#F87171" fontSize="7.5" textAnchor="middle">ACTUATOR_LEAK</text>
                  </g>

                  {/* Node 4: INTERNAL BACKUP DB */}
                  <g onClick={() => setSelectedNode(4)} className="cursor-pointer">
                    <circle cx="420" cy="240" r="18" fill="#161B22" stroke="rgba(255,255,255,0.3)" strokeWidth="1.5" />
                    <text x="420" y="244" fill="#94A3B8" fontSize="8" textAnchor="middle">BACKUP_DB</text>
                    <text x="420" y="270" fill="#64748B" fontSize="7.5" textAnchor="middle">STANDBY</text>
                  </g>

                  {/* Node 5: CROWN JEWEL (Primary Target) */}
                  <g onClick={() => setSelectedNode(5)} className="cursor-pointer">
                    <circle cx="490" cy="150" r="26" fill="#1C0A0D" stroke="#FF1E42" strokeWidth="3" className="animate-pulse" />
                    <circle cx="490" cy="150" r="32" fill="none" stroke="#FF1E42" strokeWidth="1" strokeDasharray="3 3" />
                    <text x="490" y="154" fill="#FF1E42" fontSize="8" textAnchor="middle" fontWeight="black">CROWN_JEWEL</text>
                    <text x="490" y="190" fill="#FF1E42" fontSize="7.5" textAnchor="middle" fontWeight="bold">SRV_CORE_0x9A</text>
                  </g>
                </svg>

                {/* Node Inspection Sub-Bar */}
                <div className="absolute bottom-1.5 left-2 right-2 bg-[#0D1117]/95 border border-[rgba(255,255,255,0.12)] px-2.5 py-1 flex items-center justify-between text-[8px] font-mono">
                  <span>SELECTED_TARGET: <strong className="text-[#FF1E42]">CROWN_JEWEL_SRV_0x9A (CRITICAL)</strong></span>
                  <span>CVSS: <strong className="text-[#FF1E42]">9.8 [HIGH_IMPACT]</strong></span>
                  <span>RECOMMENDED: <strong className="text-[#10B981]">APPLY AIRGAP ENCLAVE ISOLATION</strong></span>
                </div>
              </div>
            </div>

            {/* ==================================================== */}
            {/* PANE 3 (RIGHT): Threat Telemetry & Countermeasures   */}
            {/* ==================================================== */}
            <div className="col-span-12 lg:col-span-3 flex flex-col bg-[#0D1117] border border-[rgba(255,255,255,0.12)] p-2.5 overflow-hidden gap-2">
              <div className="flex items-center justify-between border-b border-[rgba(255,255,255,0.1)] pb-1.5 text-[9px] font-bold tracking-wider">
                <div className="flex items-center gap-1.5 text-[#FF1E42]">
                  <Activity className="w-3.5 h-3.5" />
                  <span>// THREAT_TELEMETRY</span>
                </div>
                <span className="text-[8px] px-1 bg-[#FF1E42]/15 text-[#FF1E42] border border-[#FF1E42]/30">
                  SEV-1 ALERT
                </span>
              </div>

              {/* Anomaly Gauge */}
              <div className="bg-[#161B22] border border-[rgba(255,255,255,0.08)] p-2 flex flex-col items-center">
                <span className="text-[8px] text-[#64748B] mb-1">AGGREGATED ANOMALY SCORE</span>
                <div className="flex items-baseline gap-1">
                  <span className="text-[26px] font-black text-[#FF1E42] leading-none">88.4</span>
                  <span className="text-[11px] text-[#64748B]">/ 100</span>
                </div>
                <div className="w-full h-1.5 bg-[#07090E] border border-[rgba(255,255,255,0.1)] mt-2 overflow-hidden flex">
                  <div className="h-full bg-gradient-to-r from-[#10B981] via-[#FBBF24] to-[#FF1E42]" style={{ width: '88.4%' }}></div>
                </div>
              </div>

              {/* MITRE ATT&CK Matrix */}
              <div className="flex flex-col gap-1 text-[8px]">
                <span className="text-[#64748B] font-bold">MITRE ATT&amp;CK KILLCHAIN PHASES</span>
                <div className="grid grid-cols-2 gap-1 text-[7.5px]">
                  <div className="bg-[#161B22] border border-[#10B981]/40 p-1 text-[#10B981]">01: RECON [CONFIRMED]</div>
                  <div className="bg-[#161B22] border border-[#FF1E42]/50 p-1 text-[#FF1E42]">02: WEAPONIZE [ACTIVE]</div>
                  <div className="bg-[#161B22] border border-[#38BDF8]/40 p-1 text-[#38BDF8]">03: DELIVERY [FILTERED]</div>
                  <div className="bg-[#161B22] border border-[#FF1E42]/80 p-1 text-[#FF1E42] font-bold animate-pulse">04: EXPLOIT [BLOCKED]</div>
                </div>
              </div>

              {/* Active Countermeasures Toggle Buttons */}
              <div className="flex flex-col gap-1.5 mt-auto pt-2 border-t border-[rgba(255,255,255,0.1)]">
                <span className="text-[8px] text-[#64748B] font-bold">DEFENSIVE COUNTERMEASURES</span>
                <button
                  type="button"
                  onClick={() =>
                    setCountermeasures((prev) => ({ ...prev, vlanIsolate: !prev.vlanIsolate }))
                  }
                  className={`px-2 py-1 border text-[8px] font-mono flex items-center justify-between transition-colors ${
                    countermeasures.vlanIsolate
                      ? 'bg-[#10B981]/15 text-[#10B981] border-[#10B981]/50 font-bold'
                      : 'bg-[#161B22] border-[rgba(255,255,255,0.12)] text-[#64748B]'
                  }`}
                >
                  <span>ISOLATE_SUBNET_VLAN_4</span>
                  <span>{countermeasures.vlanIsolate ? '[ACTIVE]' : '[STANDBY]'}</span>
                </button>
                <button
                  type="button"
                  onClick={() =>
                    setCountermeasures((prev) => ({ ...prev, rekeyEnclave: !prev.rekeyEnclave }))
                  }
                  className={`px-2 py-1 border text-[8px] font-mono flex items-center justify-between transition-colors ${
                    countermeasures.rekeyEnclave
                      ? 'bg-[#00F0FF]/15 text-[#00F0FF] border-[#00F0FF]/50 font-bold'
                      : 'bg-[#161B22] border-[rgba(255,255,255,0.12)] text-[#64748B]'
                  }`}
                >
                  <span>REKEY_ENCLAVE_SECRETS</span>
                  <span>{countermeasures.rekeyEnclave ? '[VERIFIED]' : '[OFFLINE]'}</span>
                </button>
                <button
                  type="button"
                  onClick={() =>
                    setCountermeasures((prev) => ({ ...prev, deployTarpit: !prev.deployTarpit }))
                  }
                  className={`px-2 py-1 border text-[8px] font-mono flex items-center justify-between transition-colors ${
                    countermeasures.deployTarpit
                      ? 'bg-[#FBBF24]/15 text-[#FBBF24] border-[#FBBF24]/50 font-bold'
                      : 'bg-[#161B22] border-[rgba(255,255,255,0.12)] text-[#64748B]'
                  }`}
                >
                  <span>DEPLOY_TARPIT_HONEYPOT</span>
                  <span>{countermeasures.deployTarpit ? '[ENGAGED]' : '[ARMED]'}</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ======================================================== */}
      {/* FLOATING INTERACTIVE DEBUG SCRUBBER BAR (BOTTOM-RIGHT)   */}
      {/* ======================================================== */}
      <aside className="fixed bottom-3 right-4 z-50 flex items-center gap-1.5 bg-[#0D1117]/95 border border-[rgba(255,255,255,0.2)] px-2.5 py-1.5 shadow-[0_6px_25px_rgba(0,0,0,0.9)] backdrop-blur-md">
        <span className="text-[7.5px] text-[#64748B] font-mono font-bold uppercase mr-1">
          SCRUB //
        </span>

        {/* 1: Red Eye */}
        <button
          type="button"
          onClick={() => setStage('IDLE_RED')}
          className={`px-2 py-0.5 text-[8px] font-mono border transition-all cursor-pointer ${
            stage === 'IDLE_RED'
              ? 'bg-[#FF1E42] text-[#07090E] border-[#FF1E42] font-extrabold shadow-[0_0_10px_rgba(255,30,66,0.6)]'
              : 'bg-[#161B22] border-[rgba(255,255,255,0.12)] text-[#94A3B8] hover:text-white'
          }`}
          title="Force Stage 1: Idle Red Biometric Eye"
        >
          [1: RED EYE]
        </button>

        {/* 2: Blue Sync */}
        <button
          type="button"
          onClick={() => setStage('SYNCING_BLUE')}
          className={`px-2 py-0.5 text-[8px] font-mono border transition-all cursor-pointer ${
            stage === 'SYNCING_BLUE'
              ? 'bg-[#00F0FF] text-[#07090E] border-[#00F0FF] font-extrabold shadow-[0_0_10px_rgba(0,240,255,0.6)]'
              : 'bg-[#161B22] border-[rgba(255,255,255,0.12)] text-[#94A3B8] hover:text-white'
          }`}
          title="Force Stage 2: Syncing Blue Reticle & Locked Gaze"
        >
          [2: BLUE SYNC]
        </button>

        {/* 3: Close & Flash */}
        <button
          type="button"
          onClick={() => executeKineticTransition()}
          className={`px-2 py-0.5 text-[8px] font-mono border transition-all cursor-pointer ${
            stage === 'CLOSING_FLASH'
              ? 'bg-[#FFFFFF] text-[#07090E] border-[#FFFFFF] font-extrabold shadow-[0_0_12px_rgba(255,255,255,0.8)]'
              : 'bg-[#161B22] border-[rgba(255,255,255,0.12)] text-[#94A3B8] hover:text-white'
          }`}
          title="Trigger Stage 3: Kinetic Eyelid Shutter & CRT Flash"
        >
          [3: CLOSE &amp; FLASH]
        </button>

        {/* 4: Main Terminal */}
        <button
          type="button"
          onClick={() => setStage('TERMINAL_ACTIVE')}
          className={`px-2 py-0.5 text-[8px] font-mono border transition-all cursor-pointer ${
            stage === 'TERMINAL_ACTIVE'
              ? 'bg-[#10B981] text-[#07090E] border-[#10B981] font-extrabold shadow-[0_0_10px_rgba(16,185,129,0.6)]'
              : 'bg-[#161B22] border-[rgba(255,255,255,0.12)] text-[#94A3B8] hover:text-white'
          }`}
          title="Mount Stage 4: DRISHTI Cyber Intelligence Software Screen"
        >
          [4: MAIN TERMINAL]
        </button>
      </aside>
    </div>
  );
};
