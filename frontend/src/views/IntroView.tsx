import React, { useState, useRef, useEffect, useCallback } from 'react';

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

  // isExiting: triggers the fade-out from the last black frame
  const [isExiting, setIsExiting] = useState<boolean>(false);
  const [isReady, setIsReady] = useState<boolean>(false);

  // Smooth entrance fade-in on mount
  useEffect(() => {
    const t = setTimeout(() => setIsReady(true), 40);
    return () => clearTimeout(t);
  }, []);

  // Trigger cinematic fade-out at the last 8 seconds and simultaneous fade-in of login page
  const handleTransitionToLogin = useCallback(() => {
    if (isExiting) return;
    setIsExiting(true);

    if (document.fullscreenElement) {
      document.exitFullscreen().catch(() => {});
    }

    // Notify LoginView to begin its smooth cinematic fade-in simultaneously
    onBeginExit?.();

    // Smoothly fade out audio over the 1800ms transition to prevent popping
    const v = videoRef.current;
    if (v && !v.muted) {
      const fadeAudioInterval = setInterval(() => {
        if (v.volume > 0.05) {
          v.volume = Math.max(0, v.volume - 0.05);
        } else {
          v.volume = 0;
          clearInterval(fadeAudioInterval);
        }
      }, 50);
    }

    // Wait for the 1800ms cinematic fade-out to complete, then unmount IntroView
    setTimeout(() => {
      onComplete();
    }, 1800);
  }, [isExiting, onBeginExit, onComplete]);

  // Video time tracker: detect when the video enters its final 8 seconds
  const handleTimeUpdate = () => {
    const v = videoRef.current;
    if (v && !isNaN(v.duration) && v.duration > 0) {
      // Trigger cinematic fade-out when reaching the last 8 seconds of the video
      const fadeTriggerTime = Math.max(1.0, v.duration - 8.0);
      if (v.currentTime >= fadeTriggerTime) {
        handleTransitionToLogin();
      }
    }
  };

  // Video ended fallback: runs completely to completion
  const handleVideoEnded = () => {
    handleTransitionToLogin();
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
        handleTransitionToLogin();
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
  }, [handleTransitionToLogin]);

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
      className={`fixed inset-0 w-screen h-screen z-50 bg-[#030407] select-none overflow-hidden flex items-center justify-center transition-opacity duration-[1800ms] ease-out ${
        isExiting
          ? 'opacity-0 pointer-events-none'
          : isReady
          ? 'opacity-100 pointer-events-auto'
          : 'opacity-0 pointer-events-none'
      }`}
      style={{
        transitionTimingFunction: 'cubic-bezier(0.16, 1, 0.3, 1)',
      }}
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
        onClick={togglePlay}
        onDoubleClick={toggleFullscreen}
      />

      {/* Subtle CRT Scanline Overlay */}
      <div className="crt-overlay pointer-events-none absolute inset-0 z-20"></div>

      {/* Tactical Edge Viewport Corner Brackets with Ambient Crimson Glow */}
      <div className="absolute top-4 left-4 w-7 h-7 border-t-2 border-l-2 border-[#EF4444] pointer-events-none z-30 opacity-85 shadow-[0_0_12px_rgba(239,68,68,0.4)]"></div>
      <div className="absolute top-4 right-4 w-7 h-7 border-t-2 border-r-2 border-[#EF4444] pointer-events-none z-30 opacity-85 shadow-[0_0_12px_rgba(239,68,68,0.4)]"></div>
      <div className="absolute bottom-4 left-4 w-7 h-7 border-b-2 border-l-2 border-[#EF4444] pointer-events-none z-30 opacity-85 shadow-[0_0_12px_rgba(239,68,68,0.4)]"></div>
      <div className="absolute bottom-4 right-4 w-7 h-7 border-b-2 border-r-2 border-[#EF4444] pointer-events-none z-30 opacity-85 shadow-[0_0_12px_rgba(239,68,68,0.4)]"></div>

      {/* Center Pause Indicator Overlay */}
      {!isPlaying && (
        <div
          className="absolute inset-0 flex items-center justify-center bg-black/60 backdrop-blur-[2px] z-35 cursor-pointer animate-fade-in"
          onClick={togglePlay}
        >
          <div className="px-6 py-3 bg-[#0B101D]/95 border border-[#EF4444] text-[#EF4444] text-xs font-bold tracking-[0.2em] flex items-center gap-3 shadow-[0_0_35px_rgba(239,68,68,0.5)] active:scale-95 transition-transform">
            <span className="w-2 h-2 rounded-full bg-[#EF4444] animate-ping"></span>
            <span>❚❚ PAUSED // CLICK TO RESUME</span>
          </div>
        </div>
      )}

      {/* Unmute Prompt Pill if video started muted */}
      {isMuted && !hasInteracted && isPlaying && !isExiting && (
        <div
          className="absolute top-16 right-6 md:right-8 z-35 px-3 py-1.5 bg-[#0B101D]/90 border border-[#38BDF8] text-[#38BDF8] text-[9.5px] font-bold tracking-wider rounded-sm shadow-[0_0_20px_rgba(56,189,248,0.4)] animate-bounce cursor-pointer hover:bg-[#38BDF8]/20 active:scale-95 transition-all flex items-center gap-2 backdrop-blur-sm"
          onClick={toggleMute}
        >
          <span>🔊</span>
          <span>CLICK TO UNMUTE AUDIO [M]</span>
        </div>
      )}

      {/* ======================================================== */}
      {/* 2. MINIMAL FLOATING TOP CONTROLS                         */}
      {/* ======================================================== */}
      <header className="absolute top-0 inset-x-0 z-30 px-6 md:px-8 pt-4 flex items-center justify-between text-[10px] pointer-events-auto">
        <div className="flex items-center gap-2">
          <span className="font-bold text-white tracking-[0.22em] text-[11px] drop-shadow-[0_2px_4px_rgba(0,0,0,0.8)]">
            DRISHTI <span className="text-[#EF4444]">//</span> BOOT_INTRO
          </span>
          <span className="hidden sm:inline-block text-[8.5px] px-1.5 py-0.5 bg-[#EF4444]/25 border border-[#EF4444] text-[#EF4444] font-bold rounded-sm shadow-[0_0_8px_rgba(239,68,68,0.3)] animate-pulse">
            LIVE
          </span>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={toggleMute}
            className={`px-2.5 py-1 border text-[9px] font-bold tracking-wider rounded-sm cursor-pointer backdrop-blur-sm flex items-center gap-1.5 active:scale-95 transition-all duration-150 ${
              isMuted
                ? 'bg-black/60 border-[#475569] text-[#94A3B8] hover:border-[#38BDF8] hover:text-white'
                : 'bg-[#00E5FF]/20 border-[#00E5FF] text-[#00E5FF] shadow-[0_0_12px_rgba(0,229,255,0.4)]'
            }`}
          >
            <span>{isMuted ? '🔇 AUDIO: MUTED' : '🔊 AUDIO: LIVE'}</span>
          </button>

          <button
            type="button"
            onClick={toggleFullscreen}
            className="px-2.5 py-1 border border-[#475569] bg-black/60 hover:border-white hover:text-white text-[#94A3B8] text-[9px] font-bold tracking-wider rounded-sm cursor-pointer backdrop-blur-sm flex items-center gap-1.5 active:scale-95 transition-all duration-150"
            title="Toggle Fullscreen (F)"
          >
            <span>{isFullscreen ? '⤦ WINDOW' : '⛶ FULL'}</span>
          </button>
        </div>
      </header>

      {/* ======================================================== */}
      {/* 3. MINIMAL BOTTOM SKIP ACTION                            */}
      {/* ======================================================== */}
      <footer className="absolute bottom-0 inset-x-0 z-30 px-6 md:px-8 pb-5 flex items-center justify-end pointer-events-auto">
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            handleTransitionToLogin();
          }}
          className="px-4 py-2 font-mono text-[10px] font-bold tracking-[0.16em] bg-[#E62E25]/20 border border-[#EF4444] text-[#FFFFFF] rounded-sm shadow-[0_0_20px_rgba(239,68,68,0.45)] hover:bg-[#E62E25]/40 hover:border-white active:scale-[0.98] transition-all duration-150 cursor-pointer flex items-center gap-2 group backdrop-blur-sm ml-auto"
          id="skipIntroBtn"
        >
          <span>[ SKIP INTRO // ENTER GATEWAY ⌘↵ ]</span>
          <span className="group-hover:translate-x-1 transition-transform duration-150">→</span>
        </button>
      </footer>

      {/* Scoped Scanline Filter */}
      <style>{`
        .crt-overlay {
          background: radial-gradient(circle at center, transparent 70%, rgba(0, 0, 0, 0.6) 100%),
                      linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.2) 50%);
          background-size: 100% 100%, 100% 3px;
          opacity: 0.55;
        }
      `}</style>
    </div>
  );
};
