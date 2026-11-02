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
  target = 'SELECT TARGET',
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

  const displayTarget = target && target !== 'vvdx.in' ? target : 'curezy.in';

  return (
    <header
      className="h-12 w-full border-b border-hairline bg-pureWhite px-3.5 flex items-center justify-between text-xs tracking-wider shrink-0 z-30 select-none font-mono"
      data-purpose="top-command-bar"
    >
      {/* Left Hacker Identity & System Status */}
      <div className="flex items-center space-x-2 sm:space-x-3">
        <div className="w-7 h-7 border border-hairline flex items-center justify-center bg-boneLight shadow-xs shrink-0">
          <span className="text-signalGreen font-bold text-xs select-none">#_</span>
        </div>
        <div className="flex items-baseline space-x-1.5 font-grotesk font-bold text-sm tracking-widest text-ink">
          <span className="text-signalGreen">DRISHTI</span>
          <span className="text-charcoal text-xs font-mono font-normal tracking-normal hidden md:inline">
            // ROOT@COCKPIT:~#
          </span>
        </div>
        <div className="inline-flex items-center space-x-1.5 px-2 py-0.5 border border-signalGreen/40 bg-signalGreenBg text-[10px] text-signalGreen font-mono font-bold">
          <span className="w-1.5 h-1.5 bg-signalGreen animate-pulse"></span>
          <span>[ CORE ARMED ]</span>
        </div>
        <span className="hidden lg:inline-block border border-hairline px-1.5 py-0.5 text-[9px] font-mono text-cyan bg-cyanBg font-semibold">
          MODE: PROWLER-STEALTH
        </span>
        <span className="hidden xl:inline-block border border-hairline px-1.5 py-0.5 text-[9px] font-mono text-charcoal bg-boneLight font-medium">
          ENCLAVE: ZERO-EGRESS
        </span>
      </div>

      {/* Center Target Acquisition & Quick Probe */}
      <div className="flex items-center space-x-1.5 sm:space-x-2">
        <div className="border border-hairline bg-pureWhite px-2.5 py-1 text-ink font-mono text-xs flex items-center space-x-2 shadow-xs">
          <span className="text-charcoal font-semibold text-[10px]">TARGET:</span>
          <span className="font-bold text-cyan">{displayTarget}</span>
          <span className="text-[9px] text-signalGreen font-bold bg-signalGreenBg px-1 border border-signalGreen/30">
            ARMED
          </span>
        </div>
        <span className="hidden sm:inline-block border border-hairline text-charcoal text-[10px] px-1.5 py-1 tracking-tighter bg-boneDark font-medium">
          [ RFC-8655 AUTH ]
        </span>
        <button
          onClick={onCreateScan}
          className="bg-vermilion hover:bg-crimson text-white font-mono font-bold px-2.5 sm:px-3 py-1 text-xs uppercase tracking-wider transition-colors duration-75 border border-hairline shadow-xs flex items-center space-x-1 cursor-pointer"
          title="Launch Autonomous Recon Pipeline"
        >
          <span>⚡</span>
          <span className="hidden sm:inline">[ EXECUTE RECON ]</span>
        </button>
        <button
          onClick={onNavigateToIntel}
          className="hidden md:inline-block border border-hairline hover:border-cyan text-ink hover:text-cyan font-mono px-2.5 py-1 text-xs uppercase tracking-wider transition-colors duration-75 bg-boneLight font-semibold cursor-pointer"
          title="Synthesize AI Consensus Threat Brief"
        >
          [ AI INTEL BRIEF ]
        </button>
      </div>

      {/* Right Telemetry & Clearance Indicators */}
      <div className="flex items-center space-x-2 sm:space-x-2.5 text-[11px] font-mono">
        <button
          onClick={onOpenCommandPalette}
          className="border border-hairline bg-boneLight px-2 py-0.5 text-charcoal hover:text-ink font-semibold cursor-pointer hover:border-signalGreen"
          title="Press ⌘K or Ctrl+K"
        >
          [ ⌘K CLI ]
        </button>
        <div className="hidden lg:inline-block text-ink font-bold px-2 py-0.5 border border-hairline bg-boneDark">
          [ {utcTime || '2026.11.02 UTC'} ]
        </div>
        <div
          onClick={onOpenProfile}
          className="border border-signalGreen text-signalGreen bg-signalGreenBg px-2 py-0.5 font-bold tracking-tight text-[10px] cursor-pointer hover:bg-signalGreen hover:text-white transition-colors"
          title={`Operator: ${operator?.name || 'Security Operator'} (${operator?.clearance || 'LEVEL 3'})`}
        >
          [ CLEARANCE // TOP-SECRET ]
        </div>
      </div>
    </header>
  );
};
