import React, { useState } from 'react';
import { OperatorProfile, TabId } from '../types';

interface ProfileViewProps {
  operator: OperatorProfile | null;
  onLogout: () => void;
  onNavigate?: (tab: TabId) => void;
  showToast?: (type: 'success' | 'warning' | 'error' | 'info', title: string, detail?: string) => void;
}

export const ProfileView: React.FC<ProfileViewProps> = ({
  operator,
  onLogout,
  onNavigate,
  showToast,
}) => {
  const currentOp = operator || {
    id: 'local-operator-dev',
    name: 'Security Operator',
    email: 'operator@drishti.local',
    role: 'Principal Security Analyst',
    clearance: 'L3 / Enterprise Security Operations',
    organization: 'DRISHTI Cyber Intelligence',
    avatar_text: 'SO',
    permissions: [
      'UNIFIED_AUTORECON',
      'ATTACK_GRAPH_PATHFINDING',
      'PROMPT_GUARD_EVAL',
      'STIX_BUNDLE_EXPORT',
      'AUDIT_INSPECTION',
      'SCOPE_CHALLENGE_ISSUER',
    ],
    client_ip: '127.0.0.1 (Local Session)',
    mfa_enabled: true,
    hardware_key_bound: true,
    default_scope: 'ACTIVE_AUDIT',
    token_fingerprint: 'SHA256: 8f43...27aa4',
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    if (showToast) {
      showToast('info', 'Copied to Clipboard', `${label}: ${text}`);
    }
  };

  return (
    <div className="flex-1 overflow-y-auto p-6 lg:p-8 bg-[#F4F1FF] text-[#22213A]">
      <div className="max-w-[1000px] mx-auto space-y-6">
        
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[20px] text-[#6C4CF1]">manage_accounts</span>
              <h1 className="text-2xl font-bold tracking-tight text-[#22213A]">
                Operator Identity & Access
              </h1>
            </div>
            <p className="text-sm text-[#77758E] mt-1">
              Active security session parameters, clearance attributes, and cryptographic hardware tokens.
            </p>
          </div>

          <button
            onClick={onLogout}
            className="px-4 py-2 rounded-xl border border-[#DC4655]/20 bg-[#FFF0F1] text-[#DC4655] hover:bg-[#FFE3E5] text-xs font-semibold transition-all flex items-center gap-2 shadow-sm"
          >
            <span className="material-symbols-outlined text-[17px]">logout</span>
            <span>Terminate Session</span>
          </button>
        </div>

        {/* Identity Overview Card */}
        <div className="bg-white rounded-2xl border border-[#E8E4F2] p-6 shadow-sm flex items-center gap-6">
          <div className="w-16 h-16 rounded-2xl bg-[#6C4CF1] text-white flex items-center justify-center font-bold text-xl shrink-0 shadow-sm">
            {currentOp.avatar_text || 'SO'}
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3">
              <h2 className="text-lg font-bold text-[#22213A] truncate">
                {currentOp.name}
              </h2>
              <span className="px-2.5 py-0.5 rounded-md bg-[#F3F0FF] text-[#6C4CF1] border border-[#6C4CF1]/20 text-xs font-semibold">
                {currentOp.role}
              </span>
            </div>
            <p className="text-xs text-[#77758E] mt-1">
              {currentOp.email} • {currentOp.organization}
            </p>
          </div>
        </div>

        {/* Security Parameters Details */}
        <div className="bg-white rounded-2xl border border-[#E8E4F2] p-6 shadow-sm space-y-4">
          <h3 className="text-xs font-bold text-[#22213A] uppercase tracking-wider pb-3 border-b border-[#E8E4F2]">
            Role-Based Clearance & Credentials
          </h3>

          <div className="space-y-3 text-xs">
            <div className="p-3.5 rounded-xl bg-[#FAF9FF] border border-[#E8E4F2] flex items-center justify-between">
              <span className="text-[#77758E]">Access Classification</span>
              <span className="font-semibold text-[#22213A]">{currentOp.clearance}</span>
            </div>
            <div className="p-3.5 rounded-xl bg-[#FAF9FF] border border-[#E8E4F2] flex items-center justify-between">
              <span className="text-[#77758E]">Default Assessment Mode</span>
              <span className="font-semibold text-[#6C4CF1]">{currentOp.default_scope}</span>
            </div>
            <div className="p-3.5 rounded-xl bg-[#FAF9FF] border border-[#E8E4F2] flex items-center justify-between">
              <span className="text-[#77758E]">Hardware MFA Enforcement</span>
              <span className="font-semibold text-[#299B75] flex items-center gap-1.5">
                <span className="material-symbols-outlined text-[16px]">verified</span>
                FIDO2 / U2F Verified
              </span>
            </div>
            <div className="p-3.5 rounded-xl bg-[#FAF9FF] border border-[#E8E4F2] flex items-center justify-between">
              <span className="text-[#77758E]">Session Token Fingerprint</span>
              <div className="flex items-center gap-2">
                <span className="font-mono text-[#22213A] text-[11px]">{currentOp.token_fingerprint}</span>
                <button
                  type="button"
                  onClick={() => copyToClipboard(currentOp.token_fingerprint, 'Fingerprint')}
                  className="text-[#6C4CF1] hover:underline text-xs font-semibold"
                >
                  Copy
                </button>
              </div>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
};
