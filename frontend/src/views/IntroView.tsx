import React, { useState, useRef, useEffect, useCallback } from 'react';

interface IntroViewProps {
  onComplete: () => void;
}

export const IntroView: React.FC<IntroViewProps> = ({ onComplete }) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const [isPlaying, setIsPlaying] = useState<boolean>(true);
  const [isMuted, setIsMuted] = useState<boolean>(true);
  const [currentTime, setCurrentTime] = useState<number>(0);
  const [duration, setDuration] = useState<number>(18);
  const [flashOpacity, setFlashOpacity] = useState<number>(0);
  const [hasInteracted, setHasInteracted] = useState<boolean>(false);
  const [isExiting, setIsExiting] = useState<boolean>(false);
  const [isFullscreen, setIsFullscreen] = useState<boolean>(false);

  // Smooth finish transition into LoginView
  const handleTransitionToLogin = useCallback(() => {
    if (isExiting) return;
    setIsExiting(true);

    // If browser is in fullscreen mode, exit gracefully so login looks pristine
    if (document.fullscreenElement) {
      document.exitFullscreen().catch(() => {});
    }

    // Trigger smooth optic white exposure flash bloom
    setFlashOpacity(1);

    setTimeout(() => {
      onComplete();
    }, 420);
  }, [isExiting, onComplete]);

  // Video time and duration tracking
  const handleTimeUpdate = () => {
    if (videoRef.current) {
      setCurrentTime(videoRef.current.currentTime);
    }
  };

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

  // Toggle true browser fullscreen
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
          // ESC will exit fullscreen naturally, but if pressed again or if already exited, skip
          // User can also use Enter to immediately skip
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
        // Autoplay policy prevented playback, keep muted and retry
        v.muted = true;
        setIsMuted(true);
        v.play().catch(() => setIsPlaying(false));
      });
    }
  }, []);

  // Format time MM:SS
  const formatTime = (secs: number) => {
    const m = Math.floor(secs / 60);
    const s = Math.floor(secs % 60);
    return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
  };

  const progressPercent = duration > 0 ? (currentTime / duration) * 100 : 0;

  return (
    <div
      ref={containerRef}
      className="fixed inset-0 w-screen h-screen bg-[#020306] text-[#E5E7EB] font-mono select-none overflow-hidden"
    >
      {/* ======================================================== */}
      {/* 1. FULLSCREEN EDGE-TO-EDGE VIDEO CANVAS                  */}
      {/* ======================================================== */}
      <video
        ref={videoRef}
        src="/intro.mp4"
        className="absolute inset-0 w-full h-full object-cover z-10 cursor-pointer"
        playsInline
        autoPlay
        muted={isMuted}
        onTimeUpdate={handleTimeUpdate}
        onLoadedMetadata={handleLoadedMetadata}
        onEnded={handleVideoEnded}
        onClick={togglePlay}
        onDoubleClick={toggleFullscreen}
      />

      {/* Cinematic Dark Ambient Gradients for Text Legibility */}
      <div className="absolute inset-0 pointer-events-none z-20 bg-gradient-to-b from-black/85 via-black/20 to-black/90"></div>

      {/* CRT Scanline & Phosphor Vignette Overlay */}
      <div className="crt-overlay pointer-events-none absolute inset-0 z-25"></div>

      {/* Fullscreen Optic White Exposure Flash on transition into Login */}
      <div
        className="pointer-events-none fixed inset-0 z-50 bg-[#F8FAFC] transition-opacity duration-450 ease-in-out"
        id="introFlashOverlay"
        style={{ opacity: flashOpacity }}
      ></div>

      {/* Tactical Edge Viewport Corner Brackets */}
      <div className="absolute top-4 left-4 w-7 h-7 border-t-2 border-l-2 border-[#EF4444] pointer-events-none z-30"></div>
      <div className="absolute top-4 right-4 w-7 h-7 border-t-2 border-r-2 border-[#EF4444] pointer-events-none z-30"></div>
      <div className="absolute bottom-4 left-4 w-7 h-7 border-b-2 border-l-2 border-[#EF4444] pointer-events-none z-30"></div>
      <div className="absolute bottom-4 right-4 w-7 h-7 border-b-2 border-r-2 border-[#EF4444] pointer-events-none z-30"></div>

      {/* Center Pause Indicator Overlay */}
      {!isPlaying && (
        <div
          className="absolute inset-0 flex items-center justify-center bg-black/55 backdrop-blur-[3px] z-35 cursor-pointer"
          onClick={togglePlay}
        >
          <div className="px-6 py-3 bg-[#0B101D]/90 border border-[#EF4444] text-[#EF4444] text-xs md:text-sm font-bold tracking-[0.2em] flex items-center gap-3 shadow-[0_0_35px_rgba(239,68,68,0.5)]">
            <span className="w-2 h-2 rounded-full bg-[#EF4444] animate-ping"></span>
            <span>❚❚ PAUSED // CLICK TO RESUME PLAYBACK</span>
          </div>
        </div>
      )}

      {/* Unmute Prompt Pill if video started muted */}
      {isMuted && !hasInteracted && isPlaying && (
        <div
          className="absolute top-16 right-6 md:right-10 z-35 px-3 py-1.5 bg-[#0B101D]/95 border border-[#38BDF8] text-[#38BDF8] text-[10px] font-bold tracking-wider rounded-sm shadow-[0_0_20px_rgba(56,189,248,0.4)] animate-bounce cursor-pointer hover:bg-[#38BDF8]/20 transition-all flex items-center gap-2"
          onClick={toggleMute}
        >
          <span>🔊</span>
          <span>CLICK TO ENABLE AUDIO [M]</span>
        </div>
      )}

      {/* ======================================================== */}
      {/* 2. FLOATING TOP HUD TELEMETRY BAR                        */}
      {/* ======================================================== */}
      <header className="absolute top-0 inset-x-0 z-30 px-6 md:px-10 pt-4 pb-3 flex items-center justify-between text-[10px] tracking-wider text-[#94A3B8] pointer-events-auto">
        <div className="flex items-center gap-3">
          <span className="font-bold text-[#FFFFFF] tracking-[0.25em] text-xs drop-shadow-[0_2px_4px_rgba(0,0,0,0.8)]">
            DRISHTI <span className="text-[#EF4444]">//</span> BOOT_INTRO
          </span>
          <span className="hidden sm:inline-block text-[9px] px-2 py-0.5 bg-[#EF4444]/25 border border-[#EF4444] text-[#EF4444] font-bold rounded-sm shadow-[0_0_10px_rgba(239,68,68,0.3)] animate-pulse">
            LIVE_FEED: ACTIVE
          </span>
          <span className="hidden lg:inline-block text-[9px] text-[#64748B]">
            FULLSCREEN CINEMATIC FEED // AIR-GAP C2
          </span>
        </div>

        <div className="flex items-center gap-2 md:gap-3">
          <div className="hidden sm:block text-[9px] font-mono px-2 py-1 bg-black/60 border border-[#334155]/60 rounded-sm backdrop-blur-sm">
            FEED: <span className="text-[#38BDF8] font-bold">{formatTime(currentTime)}</span>
            <span className="text-[#64748B]"> / {formatTime(duration)}</span>
          </div>

          <button
            type="button"
            onClick={toggleMute}
            className={`px-2.5 py-1 border text-[9px] font-bold tracking-wider rounded-sm transition-all cursor-pointer backdrop-blur-sm flex items-center gap-1.5 ${
              isMuted
                ? 'bg-black/60 border-[#475569] text-[#94A3B8] hover:border-[#38BDF8] hover:text-white'
                : 'bg-[#00E5FF]/20 border-[#00E5FF] text-[#00E5FF] shadow-[0_0_15px_rgba(0,229,255,0.4)]'
            }`}
          >
            <span>{isMuted ? '🔇 AUDIO: MUTED' : '🔊 AUDIO: LIVE'}</span>
          </button>

          <button
            type="button"
            onClick={toggleFullscreen}
            className="px-2.5 py-1 border border-[#475569] bg-black/60 hover:border-white hover:text-white text-[#94A3B8] text-[9px] font-bold tracking-wider rounded-sm transition-all cursor-pointer backdrop-blur-sm flex items-center gap-1.5"
            title="Toggle Fullscreen (F)"
          >
            <span>{isFullscreen ? '⤦ WINDOWED' : '⛶ FULLSCREEN'}</span>
          </button>
        </div>
      </header>

      {/* ======================================================== */}
      {/* 3. FLOATING BOTTOM HUD TIMELINE & FAST SKIP BAR          */}
      {/* ======================================================== */}
      <footer className="absolute bottom-0 inset-x-0 z-30 px-6 md:px-10 pb-5 pt-3 flex flex-col gap-2.5 pointer-events-auto">
        {/* Full-bleed timeline scrubber bar */}
        <div className="w-full flex flex-col gap-1">
          <div className="w-full h-1.5 bg-black/70 border border-[#334155]/80 rounded-sm overflow-hidden relative backdrop-blur-sm">
            <div
              className="h-full bg-gradient-to-r from-[#EF4444] via-[#F59E0B] to-[#00E5FF] transition-all duration-100 shadow-[0_0_10px_#EF4444]"
              style={{ width: `${progressPercent}%` }}
            ></div>
          </div>
          <div className="flex items-center justify-between text-[8px] text-[#94A3B8] tracking-widest px-0.5">
            <span className="text-[#64748B]">DRISHTI // REEL_BUFFER_STREAM</span>
            <span className="text-[#38BDF8] font-mono font-bold">
              {progressPercent.toFixed(1)}% PLAYED
            </span>
          </div>
        </div>

        {/* Action Controls & Fast Skip */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-1">
          <div className="flex items-center gap-3 text-[9px] text-[#64748B]">
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[#10B981] animate-ping"></span>
              <span className="text-[#10B981] font-bold">SOVEREIGN_GATEWAY_STANDBY</span>
            </div>
            <span className="hidden md:inline text-[#64748B]">
              [HOTKEYS: SPACE = PAUSE | M = AUDIO | F = FULLSCREEN | ENTER / ESC = SKIP]
            </span>
          </div>

          <button
            type="button"
            onClick={handleTransitionToLogin}
            className="w-full sm:w-auto px-5 py-2 font-mono text-[10.5px] font-bold tracking-[0.18em] bg-[#E62E25]/25 border-2 border-[#EF4444] text-[#FFFFFF] rounded-sm shadow-[0_0_24px_rgba(239,68,68,0.5)] hover:bg-[#E62E25]/45 hover:border-white transition-all cursor-pointer flex items-center justify-center gap-2 group backdrop-blur-sm"
            id="skipIntroBtn"
          >
            <span>[ SKIP INTRO // ENTER GATEWAY ⌘↵ ]</span>
            <span className="group-hover:translate-x-1 transition-transform">→</span>
          </button>
        </div>
      </footer>

      {/* Local Scoped Keyframe & Technical Styles */}
      <style>{`
        .crt-overlay {
          background: radial-gradient(circle at center, transparent 65%, rgba(0, 0, 0, 0.7) 100%),
                      linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%),
                      linear-gradient(90deg, rgba(255, 0, 0, 0.015), rgba(0, 255, 0, 0.005), rgba(0, 255, 0, 0.015));
          background-size: 100% 100%, 100% 3px, 6px 100%;
          box-shadow: inset 0 0 100px rgba(0, 0, 0, 0.85);
          opacity: 0.65;
        }
      `}</style>
    </div>
  );
};
