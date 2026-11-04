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

  const displayTarget = target && target.trim() !== '' ? target.trim() : '';

  return (
    <header
      className="module-cascade-0 h-13 w-full border-b border-hairline bg-pureWhite px-4 sm:px-6 flex items-center justify-between text-xs shrink-0 z-30 select-none font-mono tracking-tight shadow-xs"
      data-purpose="top-command-bar"
    >
      {/* 1. Left: Brand & Enclave Security State */}
      <div className="flex items-center space-x-3 shrink-0">
        <div className="w-8 h-8 border border-hairline flex items-center justify-center bg-boneDark text-signalGreen font-bold text-xs shadow-xs">
          #_
        </div>

        <div className="flex items-center space-x-2">
          <span className="font-grotesk font-extrabold text-sm tracking-widest text-ink uppercase">
            DRISHTI
          </span>
          <span className="text-pencil text-[10px] font-mono hidden md:inline">
            // CYBER LAB
          </span>
        </div>

        <div className="h-4 w-px bg-hairline hidden sm:block"></div>

        <div className="inline-flex items-center space-x-1.5 px-2 py-0.5 border border-signalGreen/40 bg-signalGreenBg text-[10px] text-signalGreen font-bold">
          <span className="w-1.5 h-1.5 bg-signalGreen animate-pulse"></span>
          <span>[ LIVE HUD ]</span>
        </div>

        <span className="hidden xl:inline-block border border-hairline px-2 py-0.5 text-[9px] font-mono text-charcoal bg-boneLight font-medium">
          AIR-GAP ENCLAVE
        </span>
      </div>

      {/* 2. Center: Active Target Focus HUD */}
      <div className="flex items-center justify-center space-x-2 flex-1 max-w-md mx-4">
        <div className="flex items-center border border-hairline bg-boneLight px-3 py-1 shadow-xs space-x-2 text-xs">
          <span className="text-[10px] font-bold text-charcoal uppercase tracking-wider">TARGET:</span>
          {displayTarget ? (
            <>
              <span className="font-bold text-cyan font-mono">{displayTarget}</span>
              <span className="w-1.5 h-1.5 bg-cyan animate-pulse"></span>
            </>
          ) : (
            <>
              <span className="font-semibold text-charcoal/80 font-mono text-[11px]">[ NO TARGET ARMED ]</span>
              <span className="w-1.5 h-1.5 bg-pencil"></span>
            </>
          )}
        </div>

        <span className="hidden md:inline-block border border-hairline px-2 py-1 text-[10px] text-charcoal bg-pureWhite font-medium">
          RFC 8655 READY
        </span>

        <button
          onClick={onCreateScan}
          className="bg-vermilion hover:bg-crimson text-white font-mono font-bold px-3 py-1 text-xs uppercase tracking-wider transition-colors duration-75 border border-hairline shadow-xs flex items-center space-x-1 cursor-pointer shrink-0"
          title="Launch Autonomous Recon Pipeline"
        >
          <span>⚡</span>
          <span className="hidden sm:inline">[ RUN AUDIT ]</span>
        </button>
      </div>

      {/* 3. Right: Telemetry, CLI & Operator Credentials */}
      <div className="flex items-center space-x-2.5 shrink-0 text-xs">
        <button
          onClick={onOpenCommandPalette}
          className="border border-hairline bg-boneLight hover:bg-boneDark px-2.5 py-1 text-charcoal hover:text-ink font-semibold cursor-pointer text-[11px] transition-colors flex items-center space-x-1"
          title="Press ⌘K or Ctrl+K"
        >
          <span className="text-pencil font-bold text-[10px]">⌘K</span>
          <span>[ CLI ]</span>
        </button>

        <div className="hidden lg:inline-flex items-center text-ink font-mono font-bold px-2.5 py-1 border border-hairline bg-boneLight text-[10px]">
          [ {utcTime || '2026.11.03 UTC'} ]
        </div>

        <div
          onClick={onOpenProfile}
          className="border border-signalGreen text-signalGreen bg-signalGreenBg px-2.5 py-1 font-bold text-[10px] cursor-pointer hover:bg-signalGreen hover:text-white transition-colors flex items-center space-x-1"
          title={`Operator: ${operator?.name || 'Security Operator'} (${operator?.clearance || 'LEVEL 5'})`}
        >
          <span>OP:</span>
          <span className="uppercase">{operator?.avatar_text || 'AM'}</span>
          <span className="hidden sm:inline">// LVL 5</span>
        </div>
      </div>
    </header>
  );
};
