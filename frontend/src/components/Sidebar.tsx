import React from 'react';
import { TabId } from '../types';

interface SidebarProps {
  activeTab: TabId;
  onSelectTab: (tab: TabId) => void;
  walActive?: boolean;
  isCollapsed: boolean;
  onToggleCollapse: () => void;
}

interface NavItem {
  id: TabId;
  label: string;
  icon: string;
  badge?: string;
  group?: 'Overview' | 'Discovery' | 'Intelligence' | 'Defense' | 'System';
}

const NAV_GROUPS: {
  title: string;
  items: NavItem[];
}[] = [
  {
    title: 'Overview',
    items: [
      { id: 'dashboard', label: 'Dashboard', icon: 'grid_view' },
    ],
  },
  {
    title: 'Discovery & Recon',
    items: [
      { id: 'recon', label: 'AutoRecon & Assets', icon: 'radar' },
    ],
  },
  {
    title: 'Security Intelligence',
    items: [
      { id: 'intel', label: 'Vulnerability Intel', icon: 'psychology' },
      { id: 'graph', label: 'Attack Paths', icon: 'hub' },
      { id: 'stix', label: 'Reports & STIX', icon: 'description' },
    ],
  },
  {
    title: 'AI & Defense',
    items: [
      { id: 'guard', label: 'AI Prompt Guard', icon: 'shield' },
    ],
  },
  {
    title: 'System & Audit',
    items: [
      { id: 'audit', label: 'Audit Trail', icon: 'history_edu' },
      { id: 'settings', label: 'Settings & Keys', icon: 'tune' },
    ],
  },
];

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  isCollapsed,
  onToggleCollapse,
}) => {
  return (
    <aside
      className={`bg-white rounded-3xl border border-[#E8E4F2] shadow-[0_8px_24px_rgba(108,76,241,0.04)] flex flex-col shrink-0 select-none transition-all duration-300 my-4 ml-4 mr-0 z-30 ${
        isCollapsed ? 'w-[76px]' : 'w-[244px]'
      }`}
      style={{ height: 'calc(100vh - 32px)' }}
    >
      {/* Brand Header */}
      <div className={`h-[72px] flex items-center border-b border-[#E8E4F2] ${
        isCollapsed ? 'justify-center px-2 relative' : 'justify-between px-5'
      }`}>
        {isCollapsed ? (
          /* Collapsed Header: Centered full-visibility Logo with hover expand button */
          <div className="relative group flex items-center justify-center">
            <button
              onClick={() => onSelectTab('dashboard')}
              className="w-11 h-11 rounded-2xl bg-gradient-to-tr from-[#6C4CF1] to-[#5940D8] flex items-center justify-center text-white shrink-0 shadow-[0_4px_16px_rgba(108,76,241,0.25)] hover:scale-105 transition-all"
              title="DRISHTI Dashboard"
            >
              <span className="material-symbols-outlined text-[22px]">security</span>
            </button>
            <button
              onClick={onToggleCollapse}
              className="absolute -right-3.5 -top-1 w-5 h-5 rounded-full bg-white border border-[#E8E4F2] shadow-sm text-[#77758E] hover:text-[#6C4CF1] hover:scale-110 flex items-center justify-center transition-all opacity-0 group-hover:opacity-100 z-10"
              title="Expand sidebar"
            >
              <span className="material-symbols-outlined text-[13px]">chevron_right</span>
            </button>
          </div>
        ) : (
          /* Expanded Header: Logo + DRISHTI wordmark + Collapse button */
          <>
            <div
              className="flex items-center gap-3 overflow-hidden cursor-pointer"
              onClick={() => onSelectTab('dashboard')}
            >
              <div className="w-10 h-10 rounded-2xl bg-gradient-to-tr from-[#6C4CF1] to-[#5940D8] flex items-center justify-center text-white shrink-0 shadow-[0_4px_16px_rgba(108,76,241,0.25)]">
                <span className="material-symbols-outlined text-[20px]">security</span>
              </div>
              <div className="flex flex-col min-w-0">
                <div className="flex items-center gap-1.5">
                  <span className="font-extrabold text-[16px] text-[#22213A] tracking-wider leading-none">
                    DRISHTI
                  </span>
                  <span className="w-2 h-2 rounded-full bg-[#6C4CF1] animate-pulse"></span>
                </div>
                <span className="text-[10px] font-mono text-[#9896AA] uppercase tracking-widest leading-none mt-1 truncate">
                  Cyber Defense Intel
                </span>
              </div>
            </div>

            <button
              onClick={onToggleCollapse}
              className="w-7 h-7 rounded-xl text-[#77758E] hover:text-[#6C4CF1] hover:bg-[#F3F0FF] transition-colors flex items-center justify-center"
              title="Collapse sidebar"
            >
              <span className="material-symbols-outlined text-[18px]">chevron_left</span>
            </button>
          </>
        )}
      </div>

      {/* Navigation Group Section */}
      <div className={`flex-1 py-4 flex flex-col gap-4 overflow-y-auto ${
        isCollapsed ? 'px-2.5 items-center' : 'px-3.5'
      }`}>
        {NAV_GROUPS.map((group, gIdx) => (
          <div key={gIdx} className="w-full flex flex-col gap-1">
            {!isCollapsed && (
              <div className="text-[10px] font-bold text-[#9896AA] uppercase tracking-widest px-3.5 py-1 select-none font-mono">
                {group.title}
              </div>
            )}

            {group.items.map((item) => {
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onSelectTab(item.id)}
                  className={`rounded-2xl text-[13px] font-medium transition-all duration-200 text-left flex items-center relative group ${
                    isCollapsed
                      ? 'w-11 h-11 justify-center p-0'
                      : 'w-full gap-3 px-3.5 py-2.5'
                  } ${
                    isActive
                      ? 'bg-gradient-to-r from-[#6C4CF1] to-[#5940D8] text-white shadow-[0_4px_16px_rgba(108,76,241,0.25)] font-semibold'
                      : 'text-[#77758E] hover:text-[#22213A] hover:bg-[#F3F0FF]'
                  }`}
                  title={isCollapsed ? item.label : undefined}
                >
                  <span
                    className={`material-symbols-outlined text-[20px] shrink-0 transition-colors ${
                      isActive ? 'text-white' : 'text-[#77758E] group-hover:text-[#6C4CF1]'
                    }`}
                  >
                    {item.icon}
                  </span>

                  {!isCollapsed && (
                    <span className="truncate flex-1">
                      {item.label}
                    </span>
                  )}

                  {!isCollapsed && item.badge && (
                    <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${
                      isActive ? 'bg-white/20 text-white' : 'bg-[#EAE4FF] text-[#6C4CF1] border border-[#E8E4F2]'
                    }`}>
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        ))}
      </div>

      {/* Footer Profile & Clearance Capsule */}
      <div className={`p-3 border-t border-[#E8E4F2] flex ${isCollapsed ? 'justify-center' : ''}`}>
        <button
          onClick={() => onSelectTab('profile')}
          className={`flex items-center rounded-2xl transition-all ${
            isCollapsed
              ? 'w-11 h-11 justify-center p-0'
              : 'w-full gap-3 p-2.5'
          } ${
            activeTab === 'profile'
              ? 'bg-[#F3F0FF] text-[#22213A]'
              : 'hover:bg-[#FAF9FF] text-[#77758E]'
          }`}
          title={isCollapsed ? 'Operator Profile' : undefined}
        >
          <div className="w-9 h-9 rounded-2xl bg-[#EAE4FF] text-[#6C4CF1] border border-[#E8E4F2] flex items-center justify-center font-bold text-[12px] shrink-0 shadow-sm">
            AM
          </div>
          {!isCollapsed && (
            <div className="flex flex-col text-left min-w-0">
              <span className="text-[13px] font-semibold text-[#22213A] leading-tight truncate">
                Alex Morgan
              </span>
              <span className="text-[11px] font-mono text-[#9896AA] leading-none mt-0.5 truncate">
                SecOps Lead // L5
              </span>
            </div>
          )}
        </button>
      </div>
    </aside>
  );
};
