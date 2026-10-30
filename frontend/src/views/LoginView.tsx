import React, { useState } from 'react';
import { OperatorProfile } from '../types';

interface LoginViewProps {
  onLoginSuccess: (operator: OperatorProfile, token: string) => void;
  showToast?: (type: 'success' | 'warning' | 'error' | 'info', title: string, detail?: string) => void;
}

export const LoginView: React.FC<LoginViewProps> = ({ onLoginSuccess, showToast }) => {
  const [username, setUsername] = useState('operator@drishti.local');
  const [password, setPassword] = useState('••••••••••••');
  const [role, setRole] = useState('Principal Security Analyst');
  const [showPassword, setShowPassword] = useState(false);
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
        showToast('success', 'Authentication Verified', `Welcome back, ${data.operator.name}`);
      }
      onLoginSuccess(data.operator, data.token);
    } catch (err: any) {
      if (showToast) {
        showToast('error', 'Login Failed', err.message || 'Check your credentials.');
      }
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
        showToast('info', 'Local Session Active', 'Authorized session established.');
      }
      onLoginSuccess(data.operator, data.token);
    } catch {
      const fallbackOp: OperatorProfile = {
        id: 'local-operator-dev',
        name: 'Security Operator',
        email: 'operator@drishti.local',
        role: 'Principal Security Analyst',
        clearance: 'L3 / Enterprise Security Operations',
        organization: 'DRISHTI Cyber Intelligence',
        avatar_text: 'SO',
        permissions: ['UNIFIED_AUTORECON', 'ATTACK_GRAPH_PATHFINDING', 'PROMPT_GUARD_EVAL'],
        client_ip: '127.0.0.1 (Local Session)',
        mfa_enabled: true,
        hardware_key_bound: true,
        default_scope: 'ACTIVE_AUDIT',
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
    <div className="min-h-screen w-full bg-[#F4F1FF] flex items-center justify-center p-6 text-[#22213A]">
      <div className="bg-white rounded-3xl border border-[#E8E4F2] shadow-sm max-w-md w-full p-8 space-y-6">
        
        {/* Brand Header */}
        <div className="text-center space-y-2">
          <div className="w-14 h-14 rounded-2xl bg-[#6C4CF1] text-white mx-auto flex items-center justify-center shadow-sm">
            <span className="material-symbols-outlined text-[28px]">shield</span>
          </div>
          <h2 className="text-2xl font-bold tracking-tight text-[#22213A]">
            DRISHTI
          </h2>
          <p className="text-xs text-[#77758E]">
            Enterprise Cybersecurity Intelligence Platform
          </p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="text-[11px] font-bold text-[#77758E] uppercase tracking-wider block mb-1.5">
              Operator Identifier
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full px-4 py-2.5 rounded-xl bg-[#FAF9FF] border border-[#E8E4F2] text-[#22213A] text-sm focus:border-[#6C4CF1] outline-none"
            />
          </div>

          <div>
            <label className="text-[11px] font-bold text-[#77758E] uppercase tracking-wider block mb-1.5">
              Security Token / Password
            </label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-4 py-2.5 rounded-xl bg-[#FAF9FF] border border-[#E8E4F2] text-[#22213A] text-sm focus:border-[#6C4CF1] outline-none pr-10"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-2.5 text-[#9896AA] hover:text-[#22213A]"
              >
                <span className="material-symbols-outlined text-[18px]">
                  {showPassword ? 'visibility_off' : 'visibility'}
                </span>
              </button>
            </div>
          </div>

          <div>
            <label className="text-[11px] font-bold text-[#77758E] uppercase tracking-wider block mb-1.5">
              Authorized Role
            </label>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value)}
              className="w-full px-4 py-2.5 rounded-xl bg-[#FAF9FF] border border-[#E8E4F2] text-[#22213A] text-sm focus:border-[#6C4CF1] outline-none"
            >
              <option value="Principal Security Analyst">Principal Security Analyst</option>
              <option value="SecOps Lead">SecOps Lead</option>
              <option value="Compliance Auditor">Compliance Auditor (Read-Only)</option>
            </select>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-3 rounded-xl bg-[#6C4CF1] hover:bg-[#5940D8] text-white font-semibold text-xs tracking-wide shadow-sm transition-all active:scale-95 disabled:opacity-50"
          >
            {loading ? 'Authenticating...' : 'Sign In to Workspace'}
          </button>
        </form>

        {/* Quick Dev Bypass */}
        <div className="pt-2 text-center">
          <button
            type="button"
            onClick={handleQuickDevLogin}
            className="text-xs text-[#6C4CF1] hover:underline font-semibold"
          >
            Fast Local Development Bypass →
          </button>
        </div>

      </div>
    </div>
  );
};
