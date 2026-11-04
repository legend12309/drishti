import React, { useState, useRef, useEffect, useCallback } from 'react';

interface IntroViewProps {
  onComplete: () => void;
}

export const IntroView: React.FC<IntroViewProps> = ({ onComplete }) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const [isPlaying, setIsPlaying] = useState<boolean>(true);
  const [isMuted, setIsMuted] = useState<boolean>(true);
  const [duration, setDuration] = useState<number>(18);
  const [hasInteracted, setHasInteracted] = useState<boolean>(false);
  const [isExiting, setIsExiting] = useState<boolean>(false);
  const [isFullscreen, setIsFullscreen] = useState<boolean>(false);

  // Smooth cinematic fade-to-black over the video's final 5 seconds
  const [endFadeOpacity, setEndFadeOpacity] = useState<number>(0);

  // Smooth finish transition into LoginView
  const handleTransitionToLogin = useCallback(() => {
    if (isExiting) return;
    setIsExiting(true);

    if (document.fullscreenElement) {
      document.exitFullscreen().catch(() => {});
    }

    // Set fade overlay to full black smoothly
    setEndFadeOpacity(1);

    setTimeout(() => {
      onComplete();
    }, 450);
  }, [isExiting, onComplete]);

  // Frame-by-frame check: Apply smooth fade-in effect to dark void over the final 5 seconds
  useEffect(() => {
    let animId: number;
    const checkEndingFade = () => {
      const v = videoRef.current;
      if (v && duration > 0 && !isExiting) {
        const remaining = duration - v.currentTime;
        if (remaining <= 5 && remaining >= 0) {
          // Progress from 0.0 at (duration - 5)s to 1.0 at end
          const progress = Math.min(1, Math.max(0, (5 - remaining) / 5));
          // Cinematic ease-in power curve
          const curvedOpacity = Math.pow(progress, 1.25);
          setEndFadeOpacity(curvedOpacity);

          // Synchronized audio fade out over the final 5 seconds
          if (!v.muted) {
            v.volume = Math.max(0, 1 - progress);
          }
        } else if (remaining > 5) {
          setEndFadeOpacity(0);
          if (!v.muted) {
            v.volume = 1;
          }
        }
      }
      animId = requestAnimationFrame(checkEndingFade);
    };

    animId = requestAnimationFrame(checkEndingFade);
    return () => cancelAnimationFrame(animId);
  }, [duration, isExiting]);

  const handleLoadedMetadata = () => {
    if (videoRef.current && !isNaN(videoRef.current.duration)) {
      setDuration(videoRef.current.duration);
    }
  };

  const handleVideoEnded = () => {
    handleTransitionToLogin();
  };

  // Toggle play/pause
  const togglePlay = () => {
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
  const toggleMute = (e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    const v = videoRef.current;
    if (!v) return;
    v.muted = !v.muted;
    setIsMuted(v.muted);
    setHasInteracted(true);
  };

  // Toggle browser fullscreen
  const toggleFullscreen = (e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
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

  // Keyboard controls: ESC or Enter to skip, M to mute, F for fullscreen, Space to play/pause
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        if (document.fullscreenElement) {
          // ESC exits fullscreen naturally
        } else {
          handleTransitionToLogin();
        }
      } else if (e.key === 'Enter') {
        handleTransitionToLogin();
      } else if (e.key === ' ' || e.code === 'Space') {
        e.preventDefault();
        togglePlay();
      } else if (e.key === 'm' || e.key === 'M') {
        toggleMute();
      } else if (e.key === 'f' || e.key === 'F') {
        toggleFullscreen();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [handleTransitionToLogin]);

  // Try initial autoplay
  useEffect(() => {
    const v = videoRef.current;
    if (v) {
      v.play().catch(() => {
        // Autoplay policy fallback: keep muted and retry
        v.muted = true;
        setIsMuted(true);
        v.play().catch(() => setIsPlaying(false));
      });
    }
  }, []);

  const controlsOpacity = Math.max(0, 1 - endFadeOpacity * 1.5);

  return (
    <div
      ref={containerRef}
      className="fixed inset-0 w-screen h-screen bg-[#000000] text-[#E5E7EB] font-mono select-none overflow-hidden flex items-center justify-center"
    >
      {/* ======================================================== */}
      {/* 1. CINEMATIC CLEAN FULLSCREEN VIDEO (NO TIMELINE)        */}
      {/* ======================================================== */}
      <video
        ref={videoRef}
        src="/intro.mp4"
        className="w-full h-full object-contain md:object-cover cursor-pointer"
        playsInline
        autoPlay
        muted={isMuted}
        onLoadedMetadata={handleLoadedMetadata}
        onEnded={handleVideoEnded}
        onClick={togglePlay}
        onDoubleClick={toggleFullscreen}
      />

      {/* Subtle CRT Scanline Overlay */}
      <div className="crt-overlay pointer-events-none absolute inset-0 z-20"></div>

      {/* ======================================================== */}
      {/* 2. PROGRESSIVE 5-SECOND FADE-IN TRANSITION TO BLACK      */}
      {/* ======================================================== */}
      <div
        className="pointer-events-none fixed inset-0 z-40 bg-[#030407]"
        id="introFadeOverlay"
        style={{
          opacity: endFadeOpacity,
          transition: isExiting ? 'opacity 420ms cubic-bezier(0.16, 1, 0.3, 1)' : 'none',
        }}
      ></div>

      {/* Tactical Edge Viewport Corner Brackets */}
      <div
        className="absolute top-4 left-4 w-7 h-7 border-t-2 border-l-2 border-[#EF4444] pointer-events-none z-30 transition-opacity duration-300"
        style={{ opacity: controlsOpacity }}
      ></div>
      <div
        className="absolute top-4 right-4 w-7 h-7 border-t-2 border-r-2 border-[#EF4444] pointer-events-none z-30 transition-opacity duration-300"
        style={{ opacity: controlsOpacity }}
      ></div>
      <div
        className="absolute bottom-4 left-4 w-7 h-7 border-b-2 border-l-2 border-[#EF4444] pointer-events-none z-30 transition-opacity duration-300"
        style={{ opacity: controlsOpacity }}
      ></div>
      <div
        className="absolute bottom-4 right-4 w-7 h-7 border-b-2 border-r-2 border-[#EF4444] pointer-events-none z-30 transition-opacity duration-300"
        style={{ opacity: controlsOpacity }}
      ></div>

      {/* Center Pause Indicator Overlay */}
      {!isPlaying && (
        <div
          className="absolute inset-0 flex items-center justify-center bg-black/55 backdrop-blur-[2px] z-35 cursor-pointer"
          onClick={togglePlay}
        >
          <div className="px-6 py-3 bg-[#0B101D]/90 border border-[#EF4444] text-[#EF4444] text-xs font-bold tracking-[0.2em] flex items-center gap-3 shadow-[0_0_35px_rgba(239,68,68,0.5)]">
            <span className="w-2 h-2 rounded-full bg-[#EF4444] animate-ping"></span>
            <span>❚❚ PAUSED // CLICK TO RESUME</span>
          </div>
        </div>
      )}

      {/* Unmute Prompt Pill if video started muted */}
      {isMuted && !hasInteracted && isPlaying && endFadeOpacity < 0.5 && (
        <div
          className="absolute top-16 right-6 md:right-10 z-35 px-3 py-1.5 bg-[#0B101D]/90 border border-[#38BDF8] text-[#38BDF8] text-[9.5px] font-bold tracking-wider rounded-sm shadow-[0_0_20px_rgba(56,189,248,0.4)] animate-bounce cursor-pointer hover:bg-[#38BDF8]/20 transition-all flex items-center gap-2 backdrop-blur-sm"
          onClick={toggleMute}
        >
          <span>🔊</span>
          <span>CLICK TO UNMUTE AUDIO [M]</span>
        </div>
      )}

      {/* ======================================================== */}
      {/* 3. MINIMAL FLOATING TOP CONTROLS (NO TIMELINE)           */}
      {/* ======================================================== */}
      <header
        className="absolute top-0 inset-x-0 z-30 px-6 md:px-8 pt-4 flex items-center justify-between text-[10px] pointer-events-auto transition-opacity duration-300"
        style={{ opacity: controlsOpacity }}
      >
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
            className={`px-2 py-1 border text-[9px] font-bold tracking-wider rounded-sm transition-all cursor-pointer backdrop-blur-sm flex items-center gap-1.5 ${
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
            className="px-2 py-1 border border-[#475569] bg-black/60 hover:border-white hover:text-white text-[#94A3B8] text-[9px] font-bold tracking-wider rounded-sm transition-all cursor-pointer backdrop-blur-sm flex items-center gap-1.5"
            title="Toggle Fullscreen (F)"
          >
            <span>{isFullscreen ? '⤦ WINDOW' : '⛶ FULL'}</span>
          </button>
        </div>
      </header>

      {/* ======================================================== */}
      {/* 4. MINIMAL BOTTOM SKIP ACTION (NO TIMELINE BAR)          */}
      {/* ======================================================== */}
      <footer
        className="absolute bottom-0 inset-x-0 z-30 px-6 md:px-8 pb-5 flex items-center justify-end pointer-events-auto transition-opacity duration-300"
        style={{ opacity: controlsOpacity }}
      >
        <button
          type="button"
          onClick={handleTransitionToLogin}
          className="px-4 py-2 font-mono text-[10px] font-bold tracking-[0.16em] bg-[#E62E25]/20 border border-[#EF4444] text-[#FFFFFF] rounded-sm shadow-[0_0_20px_rgba(239,68,68,0.45)] hover:bg-[#E62E25]/40 hover:border-white transition-all cursor-pointer flex items-center gap-2 group backdrop-blur-sm"
          id="skipIntroBtn"
        >
          <span>[ SKIP INTRO // ENTER GATEWAY ⌘↵ ]</span>
          <span className="group-hover:translate-x-1 transition-transform">→</span>
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
