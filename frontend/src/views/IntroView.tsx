import React, { useState, useRef, useEffect, useCallback } from 'react';

interface IntroViewProps {
  onComplete: () => void;
}

export const IntroView: React.FC<IntroViewProps> = ({ onComplete }) => {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const [isPlaying, setIsPlaying] = useState<boolean>(true);
  const [isMuted, setIsMuted] = useState<boolean>(true);
  const [currentTime, setCurrentTime] = useState<number>(0);
  const [duration, setDuration] = useState<number>(18);
  const [flashOpacity, setFlashOpacity] = useState<number>(0);
  const [hasInteracted, setHasInteracted] = useState<boolean>(false);
  const [isExiting, setIsExiting] = useState<boolean>(false);

  // Smooth finish transition into LoginView
  const handleTransitionToLogin = useCallback(() => {
    if (isExiting) return;
    setIsExiting(true);

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

  // Keyboard controls: ESC or Enter to skip, M to mute, Space to play/pause
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' || e.key === 'Enter') {
        handleTransitionToLogin();
      } else if (e.key === ' ' || e.code === 'Space') {
        e.preventDefault();
        togglePlay();
      } else if (e.key === 'm' || e.key === 'M') {
        toggleMute();
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
    <div className="relative w-screen h-screen bg-[#030407] text-[#E5E7EB] font-mono select-none overflow-hidden flex flex-col justify-between p-3 md:p-6">
      {/* CRT Scanline & Phosphor Vignette Overlay */}
      <div className="crt-overlay pointer-events-none fixed inset-0 z-40"></div>

      {/* Fullscreen Optic White Exposure Flash on transition into Login */}
      <div
        className="pointer-events-none fixed inset-0 z-50 bg-[#F8FAFC] transition-opacity duration-450 ease-in-out"
        id="introFlashOverlay"
        style={{ opacity: flashOpacity }}
      ></div>

      {/* ========================================== */}
      {/* 1. TOP TELEMETRY STATUS BAR                */}
      {/* ========================================== */}
      <header className="relative z-30 flex items-center justify-between border-b border-[#1E293B] pb-2 text-[10px] tracking-wider text-[#64748B]">
        <div className="flex items-center gap-3">
          <span className="font-bold text-[#E5E7EB] tracking-[0.2em]">
            DRISHTI <span className="text-[#EF4444]">//</span> BOOT_SEQUENCE
          </span>
          <span className="hidden sm:inline-block text-[9px] px-1.5 py-0.5 bg-[#EF4444]/15 border border-[#EF4444]/40 text-[#EF4444] font-bold rounded-sm animate-pulse">
            LIVE_FEED: ACTIVE
          </span>
          <span className="hidden md:inline-block text-[8.5px] text-[#475569]">
            CLASSIFIED AIR-GAP INITIALIZATION
          </span>
        </div>

        <div className="flex items-center gap-3">
          <div className="text-[9px] font-mono">
            BUFFER: <span className="text-[#38BDF8] font-bold">{formatTime(currentTime)}</span>
            <span className="text-[#475569]"> / {formatTime(duration)}</span>
          </div>

          <button
            type="button"
            onClick={toggleMute}
            className={`px-2 py-0.5 border text-[9px] font-bold tracking-wider rounded-sm transition-all cursor-pointer flex items-center gap-1.5 ${
              isMuted
                ? 'bg-[#1E293B]/40 border-[#334155] text-[#94A3B8] hover:border-[#38BDF8] hover:text-white'
                : 'bg-[#00E5FF]/15 border-[#00E5FF]/60 text-[#00E5FF] shadow-[0_0_12px_rgba(0,229,255,0.4)]'
            }`}
          >
            <span>{isMuted ? '🔇 AUDIO: MUTED' : '🔊 AUDIO: LIVE'}</span>
          </button>
        </div>
      </header>

      {/* ========================================== */}
      {/* 2. CENTER: CINEMATIC VIDEO THEATER FRAME   */}
      {/* ========================================== */}
      <main className="relative z-20 flex-1 flex flex-col items-center justify-center p-2 my-auto">
        <div className="relative w-full max-w-4xl max-h-[75vh] flex flex-col items-center justify-center group">
          
          {/* Tactical Outer Cyber Corner Brackets */}
          <div className="absolute -top-3 -left-3 w-6 h-6 border-t-2 border-l-2 border-[#EF4444] pointer-events-none z-30"></div>
          <div className="absolute -top-3 -right-3 w-6 h-6 border-t-2 border-r-2 border-[#EF4444] pointer-events-none z-30"></div>
          <div className="absolute -bottom-3 -left-3 w-6 h-6 border-b-2 border-l-2 border-[#EF4444] pointer-events-none z-30"></div>
          <div className="absolute -bottom-3 -right-3 w-6 h-6 border-b-2 border-r-2 border-[#EF4444] pointer-events-none z-30"></div>

          {/* Tactical Azimuth & Feed Markers */}
          <div className="absolute -top-5 left-1/2 -translate-x-1/2 px-2 bg-[#030407] border border-[#1E293B] text-[7.5px] text-[#64748B] font-mono tracking-widest pointer-events-none z-30">
            DRISHTI // ARCHIVAL_FEED_STREAM_01
          </div>

          {/* Video Container with Dark Ambient Glow */}
          <div
            className="relative w-full aspect-video bg-[#04060C] border border-[#1E293B]/80 rounded-sm overflow-hidden shadow-[0_0_50px_rgba(0,0,0,0.9),0_0_20px_rgba(239,68,68,0.15)] flex items-center justify-center cursor-pointer"
            onClick={togglePlay}
          >
            <video
              ref={videoRef}
              src="/intro.mp4"
              className="w-full h-full object-contain"
              playsInline
              autoPlay
              muted={isMuted}
              onTimeUpdate={handleTimeUpdate}
              onLoadedMetadata={handleLoadedMetadata}
              onEnded={handleVideoEnded}
            />

            {/* Subtle Video Scanline & Vignette Treatment */}
            <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(ellipse_at_center,transparent_65%,rgba(3,4,7,0.75)_100%)] shadow-[inset_0_0_40px_rgba(0,0,0,0.8)]"></div>

            {/* Center Pause Indicator Overlay */}
            {!isPlaying && (
              <div className="absolute inset-0 flex items-center justify-center bg-black/45 backdrop-blur-[2px] z-20 pointer-events-none">
                <div className="px-4 py-2 bg-[#0B101D]/90 border border-[#EF4444] text-[#EF4444] text-xs font-bold tracking-widest flex items-center gap-2 shadow-[0_0_25px_rgba(239,68,68,0.5)]">
                  <span>❚❚ PAUSED // CLICK TO RESUME</span>
                </div>
              </div>
            )}

            {/* Audio Prompt Notification if muted on first run */}
            {isMuted && !hasInteracted && (
              <div
                className="absolute top-3 right-3 z-30 px-2.5 py-1 bg-[#0B101D]/90 border border-[#38BDF8]/60 text-[#38BDF8] text-[9px] font-bold tracking-wider rounded-sm shadow-[0_0_15px_rgba(56,189,248,0.3)] animate-pulse hover:bg-[#38BDF8]/20 transition-colors"
                onClick={toggleMute}
              >
                <span>🔊 CLICK TO ENABLE SOUND</span>
              </div>
            )}
          </div>

          {/* Video Scrubber & Playback Timeline Bar */}
          <div className="w-full mt-2.5 flex flex-col gap-1">
            <div className="w-full h-1.5 bg-[#0A0E1A] border border-[#1E293B] rounded-sm overflow-hidden relative">
              <div
                className="h-full bg-gradient-to-r from-[#EF4444] via-[#F59E0B] to-[#00E5FF] transition-all duration-100 shadow-[0_0_8px_#EF4444]"
                style={{ width: `${progressPercent}%` }}
              ></div>
            </div>

            <div className="flex items-center justify-between text-[8px] text-[#475569] tracking-wider px-0.5">
              <span>INITIALIZING SEC_KERNEL_OPTO_MATRIX</span>
              <span className="text-[#38BDF8] font-bold font-mono">
                {progressPercent.toFixed(1)}% REEL BUFFERED
              </span>
            </div>
          </div>
        </div>
      </main>

      {/* ========================================== */}
      {/* 3. BOTTOM CONTROL & FAST SKIP BAR          */}
      {/* ========================================== */}
      <footer className="relative z-30 flex flex-col sm:flex-row items-center justify-between border-t border-[#1E293B] pt-2 gap-2 text-[9px] text-[#64748B]">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-[#10B981] animate-ping"></span>
            <span className="text-[#10B981] font-bold">SOVEREIGN_GATEWAY_STANDBY</span>
          </div>
          <span className="hidden md:inline text-[#475569]">
            HOTKEYS: [SPACE: PLAY/PAUSE] [M: MUTE] [ESC / ENTER: SKIP]
          </span>
        </div>

        {/* Primary Tactical Skip Action Button */}
        <div className="flex items-center gap-2 w-full sm:w-auto">
          <button
            type="button"
            onClick={handleTransitionToLogin}
            className="w-full sm:w-auto px-4 py-2 font-mono text-[10px] font-bold tracking-[0.16em] bg-[#E62E25]/15 border border-[#E62E25] text-[#EF4444] rounded-sm shadow-[0_0_18px_rgba(230,46,37,0.35)] hover:bg-[#E62E25]/25 hover:text-white transition-all cursor-pointer flex items-center justify-center gap-2 group"
            id="skipIntroBtn"
          >
            <span>[ SKIP INTRO // ENTER GATEWAY ⌘↵ ]</span>
            <span className="group-hover:translate-x-0.5 transition-transform">→</span>
          </button>
        </div>
      </footer>

      {/* Local Scoped Keyframe & Technical Styles */}
      <style>{`
        .crt-overlay {
          background: radial-gradient(circle at center, transparent 60%, rgba(0, 0, 0, 0.72) 98%),
                      linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.35) 50%),
                      linear-gradient(90deg, rgba(255, 0, 0, 0.015), rgba(0, 255, 0, 0.005), rgba(0, 255, 0, 0.015));
          background-size: 100% 100%, 100% 3px, 6px 100%;
          box-shadow: inset 0 0 80px rgba(0, 0, 0, 0.85);
          opacity: 0.75;
        }
      `}</style>
    </div>
  );
};
