import React, { useState, useEffect } from 'react';
import { TabId } from '../types';

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectTab: (tab: TabId) => void;
  onTriggerAction?: (actionId: string) => void;
}

interface CommandItem {
  id: string;
  category: 'NAVIGATION' | 'ACTION' | 'INTEL';
  title: string;
  subtitle: string;
  icon: string;
  tab?: TabId;
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({
  isOpen,
  onClose,
  onSelectTab,
  onTriggerAction,
}) => {
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);

  const items: CommandItem[] = [
    { id: 'nav-dash', category: 'NAVIGATION', title: 'Dashboard', subtitle: 'Overview, composite posture, and scanner telemetry', icon: 'grid_view', tab: 'dashboard' },
    { id: 'nav-recon', category: 'NAVIGATION', title: 'AutoRecon Security Audit', subtitle: 'Unified assessment engine and DNS authorization', icon: 'radar', tab: 'recon' },
    { id: 'nav-intel', category: 'NAVIGATION', title: 'Vulnerability Intelligence', subtitle: 'CVE correlation, EPSS probability, and AI advisories', icon: 'security_update_warning', tab: 'intel' },
    { id: 'nav-graph', category: 'NAVIGATION', title: 'Attack Graph & Topology', subtitle: 'NetworkX topology and Dijkstra shortest attack paths', icon: 'hub', tab: 'graph' },
    { id: 'nav-guard', category: 'NAVIGATION', title: 'AI Guard & Injection Defense', subtitle: '3-Layer defense evaluation and threat sandbox', icon: 'verified_user', tab: 'guard' },
    { id: 'nav-stix', category: 'NAVIGATION', title: 'STIX 2.1 Threat Sharing', subtitle: 'Standardized threat bundles, audit reports, and exports', icon: 'description', tab: 'stix' },
    { id: 'nav-reports', category: 'NAVIGATION', title: 'Reports & Executive Dossier', subtitle: 'Automated executive threat briefing and PDF exports', icon: 'description', tab: 'reports' },
    { id: 'nav-audit', category: 'NAVIGATION', title: 'Cryptographic Audit Trail', subtitle: 'Immutable SHA-256 hash-chained compliance ledger', icon: 'history', tab: 'audit' },
    { id: 'nav-settings', category: 'NAVIGATION', title: 'Settings & Providers', subtitle: 'Configure LLM providers and scanner paths', icon: 'tune', tab: 'settings' },
    { id: 'act-scan', category: 'ACTION', title: 'Start Security Assessment', subtitle: 'Dispatch unified AutoRecon audit', icon: 'play_arrow', tab: 'recon' },
    { id: 'act-export-stix', category: 'ACTION', title: 'Export STIX 2.1 Threat Bundle', subtitle: 'Download drishti-stix-bundle.json', icon: 'download', tab: 'stix' },
  ];

  const filtered = items.filter(
    (item) =>
      item.title.toLowerCase().includes(query.toLowerCase()) ||
      item.subtitle.toLowerCase().includes(query.toLowerCase())
  );

  useEffect(() => {
    setSelectedIndex(0);
  }, [query]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        onClose();
      }
      if (!isOpen) return;

      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        setSelectedIndex((idx) => (idx + 1) % (filtered.length || 1));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setSelectedIndex((idx) => (idx - 1 + (filtered.length || 1)) % (filtered.length || 1));
      } else if (e.key === 'Enter') {
        e.preventDefault();
        const selected = filtered[selectedIndex];
        if (selected) {
          if (selected.tab) onSelectTab(selected.tab);
          if (onTriggerAction) onTriggerAction(selected.id);
          onClose();
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, selectedIndex, filtered, onClose, onSelectTab, onTriggerAction]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/40 backdrop-blur-sm flex items-start justify-center pt-20 p-4 animate-fadeIn text-[#22213A]">
      <div className="bg-white rounded-2xl border border-[#E8E4F2] shadow-2xl max-w-xl w-full overflow-hidden">
        {/* Search Input */}
        <div className="px-5 py-4 border-b border-[#E8E4F2] flex items-center gap-3">
          <span className="material-symbols-outlined text-[20px] text-[#6C4CF1]">search</span>
          <input
            type="text"
            placeholder="Search commands, views, or actions..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            autoFocus
            className="w-full text-sm bg-transparent outline-none text-[#22213A] placeholder:text-[#9896AA]"
          />
          <kbd className="bg-[#FAF9FF] text-[#77758E] border border-[#E8E4F2] text-[10px] font-mono px-2 py-0.5 rounded-md">
            ESC
          </kbd>
        </div>

        {/* Command List */}
        <div className="max-h-[360px] overflow-y-auto p-2">
          {filtered.length === 0 ? (
            <div className="py-8 text-center text-[#77758E] text-xs">
              No commands found for "{query}"
            </div>
          ) : (
            filtered.map((item, index) => {
              const isSelected = index === selectedIndex;
              return (
                <div
                  key={item.id}
                  onClick={() => {
                    if (item.tab) onSelectTab(item.tab);
                    if (onTriggerAction) onTriggerAction(item.id);
                    onClose();
                  }}
                  onMouseEnter={() => setSelectedIndex(index)}
                  className={`px-4 py-2.5 rounded-xl flex items-center gap-3.5 cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-[#F4F1FF] text-[#6C4CF1]'
                      : 'hover:bg-[#FAF9FF] text-[#22213A]'
                  }`}
                >
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${
                    isSelected ? 'bg-[#6C4CF1] text-white shadow-sm' : 'bg-[#FAF9FF] text-[#77758E]'
                  }`}>
                    <span className="material-symbols-outlined text-[17px]">{item.icon}</span>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-semibold leading-tight truncate text-[#22213A]">
                      {item.title}
                    </div>
                    <div className="text-[11px] text-[#77758E] leading-none mt-1 truncate">
                      {item.subtitle}
                    </div>
                  </div>
                  <span className="text-[9px] font-bold text-[#77758E] uppercase tracking-wider px-2 py-0.5 rounded bg-[#FAF9FF] border border-[#E8E4F2]">
                    {item.category}
                  </span>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
};
