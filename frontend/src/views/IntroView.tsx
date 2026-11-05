import React, { useState, useRef, useEffect, useCallback } from 'react';
import { DoodleIcon } from '../components/DoodleIcon';

interface IntroViewProps {
  onComplete: () => void;
  onBeginExit?: () => void;
}

export const IntroView: React.FC<IntroViewProps> = ({ onComplete, onBeginExit }) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const [isPlaying, setIsPlaying] = useState<boolean>(true);
  const [isMuted, setIsMuted] = useState<boolean>(true);
  const [hasInteracted, setHasInteracted] = useState<boolean>(false);
  const [isFullscreen, setIsFullscreen] = useState<boolean>(false);

  // isVideoFadingOut: triggers the cinematic fade-out of the video to pitch black in its final seconds
  const [isVideoFadingOut, setIsVideoFadingOut] = useState<boolean>(false);
  // isContainerExiting: triggers the slow, majestic dissolve from pitch black into LoginView
  const [isContainerExiting, setIsContainerExiting] = useState<boolean>(false);
  const [isReady, setIsReady] = useState<boolean>(false);
  const transitionStartedRef = useRef<boolean>(false);

  // Smooth entrance fade-in on mount
  useEffect(() => {
    const t = setTimeout(() => setIsReady(true), 40);
    return () => clearTimeout(t);
  }, []);

  // Fade out audio smoothly over specified duration
  const fadeOutAudio = useCallback((durationMs = 1200) => {
    const v = videoRef.current;
    if (v && !v.muted) {
      const stepTime = 50;
      const stepDecrease = 1 / (durationMs / stepTime);
      const fadeAudioInterval = setInterval(() => {
        if (v.volume > stepDecrease) {
          v.volume = Math.max(0, v.volume - stepDecrease);
        } else {
          v.volume = 0;
          clearInterval(fadeAudioInterval);
        }
      }, stepTime);
    }
  }, []);

  // Cinematic two-step transition:
  // Step 1: Fade out the video completely into pure black (#030407)
  // Step 2: Slowly dissolve out IntroView while LoginView slowly fades in from pure black
  // Step 3: Complete handoff to LoginView once fade-in has fully engaged
  const startVideoFadeOut = useCallback((quick = false) => {
    if (transitionStartedRef.current) return;
    transitionStartedRef.current = true;
    setIsVideoFadingOut(true);

    const videoFadeDuration = quick ? 350 : 1000;
    fadeOutAudio(videoFadeDuration);

    setTimeout(() => {
      const v = videoRef.current;
      if (v) {
        // Freeze video permanently in pure blackness so neither the flash (14.5s) nor the copyright (15.15s) ever appears
        v.pause();
      }

      if (document.fullscreenElement) {
        document.exitFullscreen().catch(() => {});
      }

      // Step 2: Now that screen is 100% pitch black, begin slow reveal of LoginView
      onBeginExit?.();
      setIsContainerExiting(true);

      // Step 3: Complete handoff to LoginView after the slow 2000ms dissolve finishes
      const revealDuration = quick ? 1600 : 2000;
      setTimeout(() => {
        onComplete();
      }, revealDuration);
    }, videoFadeDuration);
  }, [fadeOutAudio, onBeginExit, onComplete]);

  // Video time tracker: detect when video reaches final action climax (12.60s) to begin fade-out to black
  const handleTimeUpdate = () => {
    const v = videoRef.current;
    if (v && !isNaN(v.duration) && v.duration > 0 && !transitionStartedRef.current) {
      // Start fade out at 12.60s (last ~1.2s before the flash at 14.50s)
      const fadeTriggerTime = v.duration > 15.0 ? 12.60 : Math.max(1.0, v.duration - 2.8);
      if (v.currentTime >= fadeTriggerTime) {
        startVideoFadeOut(false);
      }
    }
  };

  // Video ended fallback: runs completely to completion
  const handleVideoEnded = () => {
    startVideoFadeOut(true);
  };

  // Toggle play/pause
  const togglePlay = (e: React.MouseEvent) => {
    e.stopPropagation();
    const v = videoRef.current;
    if (!v) return;
    if (v.paused) {
      v.play();
      setIsPlaying(true);
    } else {
      v.pause();
      setIsPlaying(false);
    }
  };

  // Click on video: unmutes on first interaction if muted, otherwise toggles play/pause
  const handleVideoClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    const v = videoRef.current;
    if (!v) return;
    if (v.muted && !hasInteracted) {
      v.muted = false;
      setIsMuted(false);
      setHasInteracted(true);
      if (v.paused) {
        v.play().catch(() => {});
        setIsPlaying(true);
      }
      return;
    }
    togglePlay(e);
  };

  // Toggle mute / unmute
  const toggleMute = (e: React.MouseEvent) => {
    e.stopPropagation();
    const v = videoRef.current;
    if (!v) return;
    v.muted = !v.muted;
    setIsMuted(v.muted);
    setHasInteracted(true);
  };

  // Toggle browser fullscreen
  const toggleFullscreen = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (!document.fullscreenElement) {
      containerRef.current?.requestFullscreen?.().catch(() => {
        document.documentElement.requestFullscreen?.().catch(() => {});
      });
    } else {
      document.exitFullscreen?.().catch(() => {});
    }
  };

  useEffect(() => {
    const handleFullscreenChange = () => {
      setIsFullscreen(!!document.fullscreenElement);
    };
    document.addEventListener('fullscreenchange', handleFullscreenChange);
    return () => document.removeEventListener('fullscreenchange', handleFullscreenChange);
  }, []);

  // Keyboard hotkeys: Space to pause, M to mute, F for fullscreen, Enter / Esc to skip if desired
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' || e.key === 'Enter') {
        startVideoFadeOut(true);
      } else if (e.key === ' ' || e.code === 'Space') {
        e.preventDefault();
        const v = videoRef.current;
        if (!v) return;
        if (v.paused) {
          v.play();
          setIsPlaying(true);
        } else {
          v.pause();
          setIsPlaying(false);
        }
      } else if (e.key === 'm' || e.key === 'M') {
        const v = videoRef.current;
        if (v) {
          v.muted = !v.muted;
          setIsMuted(v.muted);
          setHasInteracted(true);
        }
      } else if (e.key === 'f' || e.key === 'F') {
        if (!document.fullscreenElement) {
          containerRef.current?.requestFullscreen?.().catch(() => {});
        } else {
          document.exitFullscreen?.().catch(() => {});
        }
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [startVideoFadeOut]);

  // Autoplay handler with graceful muted fallback
  useEffect(() => {
    const v = videoRef.current;
    if (v) {
      v.play().catch(() => {
        v.muted = true;
        setIsMuted(true);
        v.play().catch(() => setIsPlaying(false));
      });
    }
  }, []);

  return (
    <div
      ref={containerRef}
      className={`fixed inset-0 w-screen h-screen z-50 bg-[#030407] select-none overflow-hidden flex items-center justify-center transition-opacity duration-[2000ms] ease-in-out ${
        isContainerExiting
          ? 'opacity-0 pointer-events-none'
          : isReady
          ? 'opacity-100 pointer-events-auto'
          : 'opacity-0 pointer-events-none'
      }`}
    >
      {/* ======================================================== */}
      {/* 1. CINEMATIC FULLSCREEN VIDEO CANVAS                     */}
      {/* ======================================================== */}
      <video
        ref={videoRef}
        src="/intro.mp4"
        className="w-full h-full object-contain md:object-cover cursor-pointer"
        playsInline
        autoPlay
        muted={isMuted}
        onTimeUpdate={handleTimeUpdate}
        onEnded={handleVideoEnded}
        onClick={handleVideoClick}
        onDoubleClick={toggleFullscreen}
      />

      {/* ======================================================== */}
      {/* CINEMATIC BLACKOUT FADE-OUT CURTAIN IN LAST OF VIDEO     */}
      {/* ======================================================== */}
      <div
        className={`absolute inset-0 bg-[#030407] pointer-events-none z-45 transition-opacity duration-[1200ms] ease-in-out ${
          isVideoFadingOut ? 'opacity-100' : 'opacity-0'
        }`}
      />

      {/* Subtle CRT Scanline Overlay */}
      <div className="crt-overlay pointer-events-none absolute inset-0 z-20"></div>

      {/* Ultra-subtle Viewfinder Frame Margins — strictly outside content safe area */}
      <div
        className={`pointer-events-none absolute inset-3 z-25 transition-opacity duration-700 ${
          isVideoFadingOut ? 'opacity-0' : 'opacity-40'
        }`}
      >
        <div className="absolute top-0 left-0 w-3 h-3 border-t border-l border-white/50"></div>
        <div className="absolute top-0 right-0 w-3 h-3 border-t border-r border-white/50"></div>
        <div className="absolute bottom-0 left-0 w-3 h-3 border-b border-l border-white/50"></div>
        <div className="absolute bottom-0 right-0 w-3 h-3 border-b border-r border-white/50"></div>
      </div>

      {/* Center Pause Indicator Overlay */}
      {!isPlaying && (
        <div
          className="absolute inset-0 flex items-center justify-center bg-black/60 backdrop-blur-[2px] z-35 cursor-pointer animate-fade-in"
          onClick={handleVideoClick}
        >
          <div className="px-5 py-2.5 bg-[#0B101D]/95 border border-[#EF4444] text-[#EF4444] text-xs font-mono font-bold tracking-[0.2em] flex items-center gap-3 shadow-[0_0_25px_rgba(239,68,68,0.4)] active:scale-95 transition-transform">
            <span className="w-2 h-2 rounded-full bg-[#EF4444] animate-ping"></span>
            <span>❚❚ PAUSED // CLICK TO RESUME</span>
          </div>
        </div>
      )}

      {/* Minimal Unmute Prompt Pill — Sleek, quiet, non-bouncing */}
      {isMuted && !hasInteracted && isPlaying && !isVideoFadingOut && (
        <div
          className="absolute top-[56px] right-6 md:right-8 z-35 px-2.5 py-1 bg-black/85 border border-white/15 text-white/80 text-[9px] font-mono tracking-wider backdrop-blur-md cursor-pointer hover:border-white/40 hover:text-white transition-all flex items-center gap-2 shadow-sm animate-fade-in"
          onClick={toggleMute}
          title="Click to unmute audio"
        >
          <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse"></span>
          <span>CLICK ANYWHERE OR PRESS [M] TO UNMUTE</span>
        </div>
      )}

      {/* ======================================================== */}
      {/* 2. MINIMAL FLOATING TOP CONTROLS                         */}
      {/* ======================================================== */}
      <header
        className={`absolute top-0 inset-x-0 z-30 px-6 md:px-8 pt-5 flex items-center justify-between text-[10px] pointer-events-auto transition-opacity duration-700 ${
          isVideoFadingOut ? 'opacity-0 pointer-events-none' : 'opacity-100'
        }`}
      >
        <div className="flex items-center gap-2.5 font-mono">
          <span className="font-bold text-white tracking-[0.22em] text-[11px] drop-shadow-[0_2px_4px_rgba(0,0,0,0.8)]">
            DRISHTI <span className="text-[#EF4444]">//</span> BOOT_INTRO
          </span>
          <span className="text-[8.5px] px-1.5 py-0.5 bg-[#EF4444]/20 border border-[#EF4444]/60 text-[#EF4444] font-bold tracking-wider">
            LIVE
          </span>
        </div>

        <div className="flex items-center gap-2 font-mono">
          <button
            type="button"
            onClick={toggleMute}
            className={`px-3 py-1.5 border text-[9px] font-bold tracking-wider cursor-pointer backdrop-blur-md flex items-center gap-2 active:scale-95 transition-all duration-150 ${
              isMuted
                ? 'bg-black/80 border-[#F59E0B] text-[#F59E0B] hover:border-white hover:text-white shadow-[0_0_12px_rgba(245,158,11,0.25)]'
                : 'bg-[#00E5FF]/20 border-[#00E5FF] text-[#00E5FF] shadow-[0_0_12px_rgba(0,229,255,0.3)]'
            }`}
            title={isMuted ? 'Click to Unmute (M)' : 'Mute Audio (M)'}
          >
            <DoodleIcon name={isMuted ? 'muted' : 'audio'} className="w-3.5 h-3.5" />
            <span>{isMuted ? 'UNMUTE [M]' : 'AUDIO: LIVE'}</span>
            {isMuted && !hasInteracted && (
              <span className="w-1.5 h-1.5 rounded-full bg-[#F59E0B] animate-ping"></span>
            )}
          </button>

          <button
            type="button"
            onClick={toggleFullscreen}
            className="px-3 py-1.5 border border-white/20 bg-black/60 hover:border-white hover:text-white text-white/80 text-[9px] font-bold tracking-wider cursor-pointer backdrop-blur-md flex items-center gap-1.5 active:scale-95 transition-all duration-150"
            title="Toggle Fullscreen (F)"
          >
            <DoodleIcon name={isFullscreen ? 'window' : 'fullscreen'} className="w-3.5 h-3.5" />
            <span>{isFullscreen ? 'WINDOW' : 'FULL'}</span>
          </button>
        </div>
      </header>

      {/* ======================================================== */}
      {/* 3. MINIMAL BOTTOM CONTROLS & BALANCED TELEMETRY          */}
      {/* ======================================================== */}
      <footer
        className={`absolute bottom-0 inset-x-0 z-30 px-6 md:px-8 pb-5 flex items-center justify-between pointer-events-auto transition-opacity duration-700 ${
          isVideoFadingOut ? 'opacity-0 pointer-events-none' : 'opacity-100'
        }`}
      >
        {/* Telemetry Indicator on bottom-left — cleanly anchors the frame */}
        <div className="flex items-center gap-2 text-[10px] font-mono tracking-[0.2em] text-white/50 backdrop-blur-sm bg-black/40 px-3 py-1.5 border border-white/10">
          <span className="w-1.5 h-1.5 bg-signalGreen rounded-full inline-block animate-pulse"></span>
          <span className="text-white/80 font-bold">SYSTEM // GATEWAY_BOOT</span>
          <span className="hidden sm:inline text-white/40">// SEC_LEVEL_5</span>
        </div>

        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            startVideoFadeOut(true);
          }}
          className="px-4 py-2 font-mono text-[10px] font-bold tracking-[0.16em] bg-[#E62E25]/20 border border-[#EF4444] text-white shadow-[0_0_15px_rgba(239,68,68,0.35)] hover:bg-[#E62E25]/40 hover:border-white active:scale-[0.98] transition-all duration-150 cursor-pointer flex items-center gap-2 group backdrop-blur-sm"
          id="skipIntroBtn"
        >
          <span>[ SKIP INTRO // ENTER GATEWAY ⌘↵ ]</span>
          <span className="group-hover:translate-x-1 transition-transform duration-150">→</span>
        </button>
      </footer>

      {/* Scoped Scanline Filter */}
      <style>{`
        .crt-overlay {
          background: radial-gradient(circle at center, transparent 75%, rgba(0, 0, 0, 0.45) 100%),
                      linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.15) 50%);
          background-size: 100% 100%, 100% 3px;
          opacity: 0.35;
        }
      `}</style>
    </div>
  );
};
