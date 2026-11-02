import React, { useState, useEffect } from 'react';
import { OperatorProfile } from '../types';

interface TopUtilityBarProps {
  operator?: OperatorProfile | null;
  target?: string;
  onOpenCommandPalette: () => void;
  onOpenProfile: () => void;
  onNavigateToSettings: () => void;
  onCreateScan?: () => void;
  onNavigateToIntel?: () => void;
}

export const TopUtilityBar: React.FC<TopUtilityBarProps> = ({
  operator,
  target = 'vvdx.in',
  onOpenCommandPalette,
  onOpenProfile,
  onCreateScan,
  onNavigateToIntel,
}) => {
  const [utcTime, setUtcTime] = useState<string>('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      const pad = (n: number) => String(n).padStart(2, '0');
      const year = now.getUTCFullYear();
      const month = pad(now.getUTCMonth() + 1);
      const day = pad(now.getUTCDate());
      const hours = pad(now.getUTCHours());
      const mins = pad(now.getUTCMinutes());
      const secs = pad(now.getUTCSeconds());
      setUtcTime(`${year}.${month}.${day} ${hours}:${mins}:${secs} UTC`);
    };

    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header
      className="h-12 w-full border-b border-hairline bg-pureWhite px-3.5 flex items-center justify-between text-xs tracking-wider shrink-0 z-30 select-none font-mono"
      data-purpose="top-command-bar"
    >
      {/* Left Identity Dossier Badge */}
      <div className="flex items-center space-x-2 sm:space-x-3">
        <div className="w-7 h-7 border border-hairline flex items-center justify-center bg-pureWhite shadow-xs shrink-0">
          <svg className="w-4 h-4 text-vermilion" fill="none" stroke="currentColor" strokeWidth="1.8" viewBox="0 0 24 24">
            <path d="M12 2L3 7v6c0 5.25 3.82 10.18 9 11.35 5.18-1.17 9-6.1 9-11.35V7l-9-5z"></path>
            <circle cx="12" cy="12" r="2.5" fill="#FF2E00"></circle>
          </svg>
        </div>
        <div className="flex items-baseline space-x-1.5 font-grotesk font-bold text-sm tracking-widest text-ink">
          <span>DRISHTI</span>
          <span className="text-charcoal text-xs font-mono font-normal tracking-normal hidden md:inline">
            // SEC-OPS-09
          </span>
        </div>
        <div className="inline-flex items-center space-x-1.5 px-2 py-0.5 border border-hairline bg-boneLight text-[10px] text-signalGreen font-mono font-bold">
          <span className="w-1.5 h-1.5 bg-signalGreen animate-pulse"></span>
          <span>[ ENGINES ONLINE ]</span>
        </div>
        <span className="hidden lg:inline-block border border-hairline px-1.5 py-0.5 text-[9px] font-mono text-charcoal bg-boneDark/40 font-semibold">
          ENV: PROD-US-EAST
        </span>
        <span className="hidden xl:inline-block border border-hairline px-1.5 py-0.5 text-[9px] font-mono text-charcoal bg-boneLight font-medium">
          AGENT v4.2.0-STABLE
        </span>
      </div>

      {/* Center Recon Target Input Bar */}
      <div className="flex items-center space-x-1.5 sm:space-x-2">
        <div className="border border-hairline bg-pureWhite px-2.5 py-1 text-ink font-mono text-xs flex items-center space-x-2 shadow-xs">
          <span className="text-charcoal font-semibold text-[10px]">TARGET:</span>
          <span className="font-bold text-ink">{target}</span>
          <span className="text-[9px] text-signalGreen font-bold bg-signalGreenBg px-1 border border-signalGreen">
            RESOLVED
          </span>
        </div>
        <span className="hidden sm:inline-block border border-hairline text-charcoal text-[10px] px-1.5 py-1 tracking-tighter bg-boneDark font-medium">
          [ RFC-8655 VERIFIED ]
        </span>
        <button
          onClick={onCreateScan}
          className="bg-vermilion hover:bg-crimson text-white font-mono font-bold px-2.5 sm:px-3 py-1 text-xs uppercase tracking-wider transition-colors duration-75 border border-hairline shadow-xs flex items-center space-x-1 cursor-pointer"
          title="Launch Autonomous Recon"
        >
          <span>⚡</span>
          <span className="hidden sm:inline">[ LAUNCH RECON ]</span>
        </button>
        <button
          onClick={onNavigateToIntel}
          className="hidden md:inline-block border border-hairline hover:bg-ink hover:text-pureWhite text-ink font-mono px-2.5 py-1 text-xs uppercase tracking-wider transition-colors duration-75 bg-boneLight font-semibold cursor-pointer"
          title="Synthesize AI Consensus Threat Brief"
        >
          [ AI CONSENSUS BRIEF ]
        </button>
      </div>

      {/* Right Telemetry & Clearance Indicators */}
      <div className="flex items-center space-x-2 sm:space-x-2.5 text-[11px] font-mono">
        <button
          onClick={onOpenCommandPalette}
          className="border border-hairline bg-boneLight px-2 py-0.5 text-charcoal hover:text-ink font-semibold cursor-pointer"
          title="Press ⌘K or Ctrl+K"
        >
          [ ⌘K PALETTE ]
        </button>
        <div className="hidden lg:inline-block text-ink font-bold px-2 py-0.5 border border-hairline bg-pureWhite">
          [ {utcTime || '2026.11.02 16:18:24 UTC'} ]
        </div>
        <div
          onClick={onOpenProfile}
          className="border border-vermilion text-vermilion bg-vermilion/10 px-2 py-0.5 font-bold tracking-tight text-[10px] cursor-pointer hover:bg-vermilion hover:text-white transition-colors"
          title={`Operator: ${operator?.name || 'Alex Morgan'} (${operator?.clearance || 'LEVEL 5'})`}
        >
          [ TOP SECRET // ORCON ]
        </div>
      </div>
    </header>
  );
};
