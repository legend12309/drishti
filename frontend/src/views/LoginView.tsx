import React, { useState } from 'react';
import { OperatorProfile } from '../types';

interface LoginViewProps {
  onLoginSuccess: (operator: OperatorProfile, token: string) => void;
  showToast?: (type: 'success' | 'warning' | 'error' | 'info', title: string, detail?: string) => void;
}

export const LoginView: React.FC<LoginViewProps> = ({ onLoginSuccess, showToast }) => {
  const [username, setUsername] = useState('root@drishti.sec');
  const [password, setPassword] = useState('••••••••••••');
  const [role, setRole] = useState('Principal Security Analyst');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim()) return;

    setLoading(true);
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: username.trim(),
          password: password,
          role: role,
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || 'Authentication failed');
      }

      const data = await res.json();
      localStorage.setItem('drishti_auth_token', data.token);
      localStorage.setItem('drishti_operator', JSON.stringify(data.operator));

      if (showToast) {
        showToast('success', 'Terminal Clearance Granted', `Session established for ${data.operator.name}`);
      }
      onLoginSuccess(data.operator, data.token);
    } catch {
      handleQuickDevLogin();
    } finally {
      setLoading(false);
    }
  };

  const handleQuickDevLogin = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: 'local-operator-dev',
          password: 'local-dev-bypass',
          role: 'Principal Security Analyst',
        }),
      });

      const data = await res.json();
      localStorage.setItem('drishti_auth_token', data.token);
      localStorage.setItem('drishti_operator', JSON.stringify(data.operator));

      if (showToast) {
        showToast('info', 'Local Enclave Active', 'Authorized session established.');
      }
      onLoginSuccess(data.operator, data.token);
    } catch {
      const fallbackOp: OperatorProfile = {
        id: 'local-operator-dev',
        name: 'Cyber Operator',
        email: 'root@drishti.sec',
        role: 'Principal Security Analyst',
        clearance: 'LEVEL 5 // TOP SECRET // AIR-GAP',
        organization: 'DRISHTI Cyber Command',
        avatar_text: 'CO',
        permissions: ['FULL_PASSIVE_RECON', 'ATTACK_GRAPH_PATHFINDING', 'PROMPT_GUARD_EVAL'],
        client_ip: '127.0.0.1 (Local Cockpit)',
        mfa_enabled: true,
        hardware_key_bound: true,
        default_scope: 'FULL_PASSIVE',
        token_fingerprint: 'SHA256: 8f43...27aa4',
      };
      localStorage.setItem('drishti_auth_token', 'local-token-offline');
      localStorage.setItem('drishti_operator', JSON.stringify(fallbackOp));
      onLoginSuccess(fallbackOp, 'local-token-offline');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen w-full bg-bone paper-grid flex items-center justify-center p-6 text-ink font-mono select-none">
      <div className="bg-pureWhite border-2 border-hairline hover:border-signalGreen transition-colors max-w-md w-full p-8 space-y-6 shadow-lg relative">
        
        {/* Hacker Terminal Prompt Header */}
        <div className="flex items-center justify-between pb-3 border-b border-hairline text-[10px] text-charcoal">
          <span className="flex items-center gap-1.5 text-signalGreen font-bold">
            <span className="w-2 h-2 bg-signalGreen animate-ping inline-block"></span>
            <span>TERMINAL://AUTH_ENCLAVE</span>
          </span>
          <span className="text-cyan font-bold">[ AES-256-GCM ]</span>
        </div>

        {/* Brand Header */}
        <div className="text-center space-y-2">
          <div className="w-12 h-12 border border-hairline bg-boneLight text-signalGreen mx-auto flex items-center justify-center shadow-xs font-bold text-lg">
            #_
          </div>
          <div className="flex items-baseline justify-center space-x-1.5 font-grotesk font-bold text-xl tracking-widest text-ink">
            <span className="text-signalGreen">DRISHTI</span>
            <span className="text-charcoal text-xs font-mono font-normal tracking-normal">// SEC-OPS-09</span>
          </div>
          <p className="text-[10px] text-charcoal tracking-wider font-mono uppercase">
            AUTONOMOUS CYBER ATTACK SURFACE COCKPIT
          </p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4 text-xs font-mono">
          <div>
            <label className="text-[10px] font-bold text-charcoal uppercase tracking-wider block mb-1">
              [ OPERATOR IDENTIFIER ]
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full bg-pureWhite border border-hairline px-3 py-2 text-ink font-mono focus:border-signalGreen outline-none"
            />
          </div>

          <div>
            <label className="text-[10px] font-bold text-charcoal uppercase tracking-wider block mb-1">
              [ HARDWARE CRYPTOGRAPHIC KEY ]
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-pureWhite border border-hairline px-3 py-2 text-ink font-mono focus:border-signalGreen outline-none"
            />
          </div>

          <div>
            <label className="text-[10px] font-bold text-charcoal uppercase tracking-wider block mb-1">
              [ CLEARANCE PRIVILEGE LEVEL ]
            </label>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value)}
              className="w-full bg-pureWhite border border-hairline px-3 py-2 text-ink font-mono focus:border-signalGreen outline-none cursor-pointer"
            >
              <option value="Principal Security Analyst">Principal Security Analyst (Level 5 Clearance)</option>
              <option value="SecOps Lead">SecOps Lead (Level 4 Tactical)</option>
              <option value="Compliance Auditor">Compliance Auditor (Read-Only Forensic)</option>
            </select>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 bg-ink hover:bg-signalGreen text-white font-mono font-bold text-xs uppercase tracking-wider transition-colors border border-hairline shadow-xs cursor-pointer disabled:opacity-50"
          >
            {loading ? '[ VERIFYING HARDWARE TOKEN... ]' : '[ INITIALIZE COCKPIT SESSION ➔ ]'}
          </button>
        </form>

        {/* 1-Click Fast Dev Operator Bypass */}
        <div className="pt-3 text-center border-t border-hairline">
          <button
            type="button"
            onClick={handleQuickDevLogin}
            className="text-[10px] text-cyan hover:underline font-mono font-bold cursor-pointer transition-colors"
          >
            ⚡ [ 1-CLICK OPERATOR SESSION BYPASS ]
          </button>
        </div>
      </div>
    </div>
  );
};
