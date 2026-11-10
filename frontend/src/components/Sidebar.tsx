import React from 'react';
import { TabId } from '../types';
import { DoodleIcon } from './DoodleIcon';

interface SidebarProps {
  activeTab: TabId;
  onSelectTab: (tab: TabId) => void;
  walActive?: boolean;
  isCollapsed?: boolean;
  onToggleCollapse?: () => void;
  onLogout?: () => void;
}

interface NavItem {
  id: TabId;
  index: string;
  label: string;
}

// Canonical DRISHTI Operational Engines (Streamlined Core)
const NAV_ITEMS: NavItem[] = [
  { id: 'dashboard', index: '01_', label: 'COCKPIT' },
  { id: 'recon', index: '02_', label: 'RECON' },
  { id: 'intel', index: '03_', label: 'INTEL' },
  { id: 'graph', index: '04_', label: 'GRAPH' },
  { id: 'guard', index: '05_', label: 'GUARD' },
  { id: 'reports', index: '06_', label: 'REPORTS' },
  { id: 'settings', index: '07_', label: 'CONFIG' },
];

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  onLogout,
}) => {
  return (
    <nav
      className="w-16 h-full border-r border-hairline bg-boneLight flex flex-col justify-between py-2 shrink-0 z-20 select-none font-mono"
      data-purpose="vertical-navigation-rail"
    >
      {/* Hacker Command Nav Stack */}
      <div className="flex flex-col space-y-0.5 w-full">
        {NAV_ITEMS.map((item) => {
          const isActive = item.id === activeTab;
          return (
            <button
              key={item.index}
              onClick={() => onSelectTab(item.id)}
              className={`w-full py-2 px-1 flex flex-col items-center justify-center active:scale-95 transition-all duration-150 text-center cursor-pointer ${
                isActive
                  ? 'text-signalGreen bg-pureWhite border-l-[3px] border-signalGreen shadow-xs'
                  : 'text-charcoal hover:text-ink hover:bg-boneDark border-l-2 border-transparent'
              }`}
              title={`${item.index} ${item.label}`}
            >
              <span
                className={`text-[10.5px] font-mono leading-none ${
                  isActive ? 'font-black text-signalGreen' : 'text-charcoal font-semibold'
                }`}
              >
                {item.index}
              </span>
              <span
                className={`text-[9.5px] font-mono tracking-wider mt-0.5 uppercase ${
                  isActive ? 'font-black text-ink' : 'font-bold text-charcoal'
                }`}
              >
                {item.label}
              </span>
            </button>
          );
        })}
      </div>

      {/* Rail Footer: Hardware Telemetry & Quick Exit */}
      <div className="flex flex-col items-center space-y-2 pt-2 border-t border-hairline">
        <button
          type="button"
          onClick={onLogout}
          className="w-12 py-1 flex flex-col items-center justify-center text-charcoal hover:text-vermilion hover:bg-boneDark border border-transparent hover:border-hairline transition-colors cursor-pointer text-[9px] font-mono font-bold"
          title="Disconnect Enclave & Terminate Session"
        >
          <DoodleIcon name="lock" className="w-3.5 h-3.5 mb-0.5" />
          <span>EXIT</span>
        </button>
        <span className="text-[9.5px] font-mono text-signalGreen font-black flex items-center gap-1">
          <span className="w-1.5 h-1.5 bg-signalGreen animate-ping"></span>
          <span>14ms</span>
        </span>
        <div
          className="w-4 h-4 border border-hairline flex items-center justify-center text-[9px] text-ink font-bold bg-pureWhite shadow-xs"
          title="Hardware Cryptographic Enclave Verified"
        >
          ■
        </div>
      </div>
    </nav>
  );
};
