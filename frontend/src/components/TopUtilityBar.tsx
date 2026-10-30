import React from 'react';
import { OperatorProfile } from '../types';

interface TopUtilityBarProps {
  operator?: OperatorProfile | null;
  onOpenCommandPalette: () => void;
  onOpenProfile: () => void;
  onNavigateToSettings: () => void;
  onExportData?: () => void;
  onCreateScan?: () => void;
}

export const TopUtilityBar: React.FC<TopUtilityBarProps> = ({
  operator,
  onOpenCommandPalette,
  onOpenProfile,
  onNavigateToSettings,
  onCreateScan,
}) => {
  return (
    <header className="h-[72px] bg-transparent flex items-center justify-between px-6 z-20 shrink-0 select-none border-b border-[#E8E4F2]">
      {/* Search Input Command Bar */}
      <div className="flex-1 max-w-md">
        <button
          onClick={onOpenCommandPalette}
          className="w-full flex items-center justify-between bg-[#FAF9FF] border border-[#E8E4F2] hover:border-[#6C4CF1]/50 px-4 py-2 rounded-2xl text-[13px] text-[#77758E] transition-all shadow-[0_2px_8px_rgba(108,76,241,0.02)] group"
        >
          <div className="flex items-center gap-2.5">
            <span className="material-symbols-outlined text-[18px] text-[#9896AA] group-hover:text-[#6C4CF1] transition-colors">
              search
            </span>
            <span className="text-[13px] text-[#77758E] font-normal">Search targets, CVEs, or command...</span>
          </div>
          <kbd className="hidden sm:inline-block bg-white text-[#77758E] border border-[#E8E4F2] text-[10px] font-mono px-2 py-0.5 rounded-md shadow-xs">
            ⌘K
          </kbd>
        </button>
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-3 ml-4">
        {/* Active Engine Indicator */}
        <div className="hidden sm:flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-[#EAF8F1] border border-[#E8E4F2] text-[#299B75] text-[11px] font-semibold shadow-xs">
          <span className="w-2 h-2 rounded-full bg-[#299B75] animate-pulse"></span>
          <span>5 Engines Ready</span>
        </div>

        {/* Notifications Icon Button */}
        <button
          onClick={onOpenCommandPalette}
          className="w-10 h-10 rounded-2xl bg-[#FAF9FF] border border-[#E8E4F2] hover:border-[#6C4CF1]/50 hover:text-[#6C4CF1] text-[#77758E] flex items-center justify-center transition-all shadow-xs active:scale-95"
          title="Notifications & Alerts"
        >
          <span className="material-symbols-outlined text-[19px]">notifications</span>
        </button>

        {/* Settings Icon Button */}
        <button
          onClick={onNavigateToSettings}
          className="w-10 h-10 rounded-2xl bg-[#FAF9FF] border border-[#E8E4F2] hover:border-[#6C4CF1]/50 hover:text-[#6C4CF1] text-[#77758E] flex items-center justify-center transition-all shadow-xs active:scale-95"
          title="Engine Configuration"
        >
          <span className="material-symbols-outlined text-[19px]">tune</span>
        </button>

        {/* Primary Action Button: Launch Target Scan */}
        {onCreateScan && (
          <button
            onClick={onCreateScan}
            className="hidden md:flex items-center gap-1.5 bg-gradient-to-r from-[#6C4CF1] to-[#5940D8] hover:opacity-95 text-white px-4 py-2.5 rounded-2xl text-[13px] font-semibold tracking-wide shadow-[0_4px_16px_rgba(108,76,241,0.25)] transition-all active:scale-95"
          >
            <span className="material-symbols-outlined text-[17px]">radar</span>
            <span>New Scan</span>
          </button>
        )}

        {/* Operator Capsule */}
        <div
          onClick={onOpenProfile}
          className="flex items-center gap-2.5 pl-3 pr-2 py-1.5 rounded-2xl bg-[#FAF9FF] border border-[#E8E4F2] hover:border-[#6C4CF1]/40 cursor-pointer transition-all shadow-xs group"
        >
          <div className="flex flex-col text-right hidden sm:flex">
            <span className="text-[13px] font-semibold text-[#22213A] leading-tight group-hover:text-[#6C4CF1] transition-colors">
              {operator?.name || 'Alex Morgan'}
            </span>
            <span className="text-[11px] text-[#77758E] leading-none mt-0.5">
              {operator?.role || 'SecOps Lead'}
            </span>
          </div>
          <div className="w-8 h-8 rounded-xl bg-[#EAE4FF] text-[#6C4CF1] border border-[#E8E4F2] flex items-center justify-center font-bold text-[12px] shadow-xs">
            {operator?.avatar_text || 'AM'}
          </div>
        </div>
      </div>
    </header>
  );
};
