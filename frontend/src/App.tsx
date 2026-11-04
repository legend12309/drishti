import React, { useState, useEffect, useCallback } from 'react';
import { TabId, SystemHealth, OperatorProfile } from './types';
import { Sidebar } from './components/Sidebar';
import { TopUtilityBar } from './components/TopUtilityBar';
import { ToastContainer, ToastMessage } from './components/Toast';
import { CommandPalette } from './components/CommandPalette';
import { ProfileModal } from './components/ProfileModal';
import { LoginView } from './views/LoginView';
import { DashboardView } from './views/DashboardView';
import { ReconView } from './views/ReconView';
import { IntelView } from './views/IntelView';
import { GuardView } from './views/GuardView';
import { GraphView } from './views/GraphView';
import { StixView } from './views/StixView';
import { ReportsView } from './views/ReportsView';
import { AuditView } from './views/AuditView';
import { SettingsView } from './views/SettingsView';
import { ProfileView } from './views/ProfileView';

const DEFAULT_OPERATOR: OperatorProfile = {
  id: 'local-operator-dev',
  name: 'Alex Morgan',
  email: 'a.morgan@drishti.sec',
  role: 'SecOps Lead',
  clearance: 'LEVEL 5 // TOP SECRET // SI-TK / GBD-AUTH',
  organization: 'Cyber Intelligence Division (Monolith SecOps)',
  avatar_text: 'AM',
  permissions: [
    'FULL_PASSIVE_RECON',
    'ATTACK_GRAPH_PATHFINDING',
    'PROMPT_GUARD_EVAL',
    'STIX_BUNDLE_EXPORT',
    'WAL_AUDIT_INSPECTION',
    'SCOPE_CHALLENGE_ISSUER',
  ],
  client_ip: '127.0.0.1 (Local Monolith)',
  mfa_enabled: true,
  hardware_key_bound: true,
  default_scope: 'FULL_PASSIVE',
  token_fingerprint: 'SHA256: 8f43...27aa4',
};

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(() => {
    return !!localStorage.getItem('drishti_auth_token');
  });

  const [operator, setOperator] = useState<OperatorProfile | null>(() => {
    const saved = localStorage.getItem('drishti_operator');
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch {
        return DEFAULT_OPERATOR;
      }
    }
    return DEFAULT_OPERATOR;
  });

  const [activeTarget, setActiveTarget] = useState<string>(() => localStorage.getItem('drishti_target_domain') || '');
  const [entranceFlash, setEntranceFlash] = useState<boolean>(false);

  useEffect(() => {
    if (entranceFlash) {
      const timer = setTimeout(() => {
        setEntranceFlash(false);
      }, 850);
      return () => clearTimeout(timer);
    }
  }, [entranceFlash]);

  useEffect(() => {
    const handleTargetChange = (e: any) => {
      if (typeof e.detail === 'string') {
        setActiveTarget(e.detail);
      }
    };
    window.addEventListener('drishti_target_updated', handleTargetChange);
    return () => window.removeEventListener('drishti_target_updated', handleTargetChange);
  }, []);
  const [activeTab, setActiveTab] = useState<TabId>('dashboard');
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [isCommandOpen, setIsCommandOpen] = useState(false);
  const [isProfileOpen, setIsProfileOpen] = useState(false);
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  const showToast = useCallback((type: 'success' | 'warning' | 'error' | 'info', title: string, detail?: string) => {
    const id = Math.random().toString(36).substring(2, 9);
    setToasts((prev) => [...prev, { id, type, title, detail }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4000);
  }, []);

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const handleLogout = useCallback(() => {
    localStorage.removeItem('drishti_auth_token');
    localStorage.removeItem('drishti_operator');
    setIsAuthenticated(false);
    showToast('info', 'Session Ended', 'Operator logged out.');
  }, [showToast]);

  // Fetch System Health status
  useEffect(() => {
    let isMounted = true;
    const checkHealth = async () => {
      try {
        const res = await fetch('/api/health');
        if (res.ok && isMounted) {
          const data = await res.json();
          setHealth(data);
        }
      } catch {}
    };

    checkHealth();
    const interval = setInterval(checkHealth, 30000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  // Global Command Palette Shortcut (Ctrl+K or Cmd+K)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setIsCommandOpen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const handleCommandAction = (actionId: string) => {
    if (actionId === 'act-scan') {
      setActiveTab('recon');
      showToast('info', 'Scope Enforced Recon', 'Navigated to active recon console.');
    } else if (actionId === 'act-dijkstra') {
      setActiveTab('graph');
      showToast('info', 'Pathfinding Initiated', 'Calculating Dijkstra shortest attack vector.');
    } else if (actionId === 'act-export-stix') {
      setActiveTab('stix');
      showToast('success', 'STIX 2.1 Ready', 'Navigated to threat intelligence bundle export.');
    }
  };

  if (!isAuthenticated) {
    return (
      <LoginView
        onLoginSuccess={(op) => {
          setOperator(op);
          setIsAuthenticated(true);
          setEntranceFlash(true);
        }}
        showToast={showToast}
      />
    );
  }

  return (
    <div className="w-full h-screen flex flex-col bg-bone border border-hairline select-none overflow-hidden text-ink font-mono relative">
      {/* Seamless Entrance Flash Dissipation from Biometric Ocular Login */}
      {entranceFlash && (
        <div
          className="pointer-events-none fixed inset-0 z-[9999] bg-white"
          style={{
            animation: 'flashExit 850ms cubic-bezier(0.16, 1, 0.3, 1) forwards',
          }}
        >
          <style>{`
            @keyframes flashExit {
              0% { opacity: 1; filter: blur(0px); }
              30% { opacity: 0.9; filter: blur(4px); }
              70% { opacity: 0.35; filter: blur(10px); }
              100% { opacity: 0; filter: blur(18px); visibility: hidden; }
            }
          `}</style>
        </div>
      )}
      {/* Top Tactical Command Bar (Swiss Editorial Archival Header) */}
      <TopUtilityBar
        operator={operator}
        target={activeTarget}
        onOpenCommandPalette={() => setIsCommandOpen(true)}
        onOpenProfile={() => setIsProfileOpen(true)}
        onNavigateToSettings={() => setActiveTab('settings')}
        onCreateScan={() => setActiveTab('recon')}
        onNavigateToIntel={() => setActiveTab('intel')}
      />

      {/* Core Layout Container (Rail + Main Workspace Canvas) */}
      <div className="flex flex-1 w-full overflow-hidden bg-bone">
        {/* Left Vertical Navigation Rail (Swiss Index Style) */}
        <Sidebar
          activeTab={activeTab}
          onSelectTab={(tab) => setActiveTab(tab)}
          walActive={health?.sqlite?.wal_mode ?? true}
          onLogout={handleLogout}
        />

        {/* Main Command Workspace View Container */}
        <main className="flex-1 flex flex-col bg-bone overflow-hidden min-w-0">
          {activeTab === 'dashboard' && (
            <DashboardView
              health={health}
              onNavigate={(tab) => setActiveTab(tab)}
              showToast={showToast}
            />
          )}
          {activeTab === 'recon' && (
            <ReconView
              onNavigate={(tab) => setActiveTab(tab)}
              showToast={showToast}
            />
          )}
          {activeTab === 'intel' && (
            <IntelView
              onNavigate={(tab) => setActiveTab(tab)}
              showToast={showToast}
            />
          )}
          {activeTab === 'graph' && (
            <GraphView
              onNavigate={(tab) => setActiveTab(tab)}
              showToast={showToast}
            />
          )}
          {activeTab === 'guard' && (
            <GuardView
              onNavigate={(tab) => setActiveTab(tab)}
              showToast={showToast}
            />
          )}
          {activeTab === 'stix' && (
            <StixView
              onNavigate={(tab) => setActiveTab(tab)}
              showToast={showToast}
            />
          )}
          {activeTab === 'reports' && (
            <ReportsView
              onNavigate={(tab) => setActiveTab(tab)}
              showToast={showToast}
            />
          )}
          {activeTab === 'audit' && (
            <AuditView
              onNavigate={(tab) => setActiveTab(tab)}
              showToast={showToast}
            />
          )}
          {activeTab === 'settings' && (
            <SettingsView
              onNavigate={(tab) => setActiveTab(tab)}
              showToast={showToast}
            />
          )}
          {activeTab === 'profile' && (
            <ProfileView
              operator={operator}
              onLogout={handleLogout}
              onNavigate={(tab) => setActiveTab(tab)}
              showToast={showToast}
            />
          )}
        </main>
      </div>

      {/* Quick Profile Drawer / Modal */}
      <ProfileModal
        isOpen={isProfileOpen}
        onClose={() => setIsProfileOpen(false)}
        operator={operator}
        onLogout={handleLogout}
        showToast={showToast}
      />

      {/* Command Palette Modal */}
      <CommandPalette
        isOpen={isCommandOpen}
        onClose={() => setIsCommandOpen(false)}
        onSelectTab={(tab) => setActiveTab(tab)}
        onTriggerAction={handleCommandAction}
      />

      {/* Global Toast Notifications */}
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />
    </div>
  );
}
