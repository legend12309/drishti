import React from 'react';
import { TabId } from '../types';

interface SidebarProps {
  activeTab: TabId;
  onSelectTab: (tab: TabId) => void;
  walActive?: boolean;
  isCollapsed?: boolean;
  onToggleCollapse?: () => void;
  onLogout?: () => void;
}

interface NavItem {
  id: TabId | 'login';
  index: string;
  label: string;
}

const NAV_ITEMS: NavItem[] = [
  { id: 'login', index: '01_', label: 'LOGIN' },
  { id: 'dashboard', index: '02_', label: 'COCKPIT' },
  { id: 'recon', index: '03_', label: 'RECON' },
  { id: 'intel', index: '04_', label: 'INTEL' },
  { id: 'graph', index: '05_', label: 'GRAPH' },
  { id: 'guard', index: '06_', label: 'GUARD' },
  { id: 'stix', index: '07_', label: 'STIX' },
  { id: 'reports', index: '08_', label: 'REP' },
  { id: 'audit', index: '09_', label: 'AUDIT' },
  { id: 'settings', index: '10_', label: 'CONF' },
  { id: 'profile', index: '11_', label: 'AUTH' },
];

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  onLogout,
}) => {
  return (
    <nav
      className="w-16 h-full border-r border-hairline bg-boneDark flex flex-col justify-between py-2 shrink-0 z-20 select-none font-mono"
      data-purpose="vertical-navigation-rail"
    >
      {/* Hacker Command Nav Stack */}
      <div className="flex flex-col space-y-0.5 w-full">
        {NAV_ITEMS.map((item) => {
          const isActive = item.id === activeTab;
          return (
            <button
              key={item.index}
              onClick={() => {
                if (item.id === 'login') {
                  if (onLogout) onLogout();
                } else {
                  onSelectTab(item.id as TabId);
                }
              }}
              className={`w-full py-2 px-1 flex flex-col items-center justify-center transition-all duration-75 text-center cursor-pointer ${
                isActive
                  ? 'text-signalGreen bg-bone border-l-[3px] border-signalGreen shadow-sm'
                  : 'text-charcoal hover:text-ink hover:bg-boneLight border-l-2 border-transparent'
              }`}
              title={`${item.index} ${item.label}`}
            >
              <span
                className={`text-[9px] font-mono leading-none ${
                  isActive ? 'font-bold text-signalGreen' : 'text-pencil'
                }`}
              >
                {item.index}
              </span>
              <span
                className={`text-[8px] font-mono tracking-wider mt-0.5 uppercase ${
                  isActive ? 'font-bold text-ink' : 'font-medium'
                }`}
              >
                {item.label}
              </span>
            </button>
          );
        })}
      </div>

      {/* Rail Footer Hardware Telemetry */}
      <div className="flex flex-col items-center space-y-1 pt-2 border-t border-hairline">
        <span className="text-[9px] font-mono text-signalGreen font-bold flex items-center gap-1">
          <span className="w-1.5 h-1.5 bg-signalGreen animate-ping"></span>
          <span>14ms</span>
        </span>
        <div
          className="w-4 h-4 border border-signalGreen/40 flex items-center justify-center text-[7px] text-signalGreen font-bold bg-bone shadow-xs"
          title="Hardware Cryptographic Enclave Verified"
        >
          ■
        </div>
      </div>
    </nav>
  );
};
