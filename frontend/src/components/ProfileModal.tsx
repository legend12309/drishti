import React, { useState } from 'react';
import { OperatorProfile } from '../types';

interface ProfileModalProps {
  isOpen: boolean;
  onClose: () => void;
  operator: OperatorProfile | null;
  onLogout: () => void;
  showToast?: (type: 'success' | 'warning' | 'error' | 'info', title: string, detail?: string) => void;
}

export const ProfileModal: React.FC<ProfileModalProps> = ({
  isOpen,
  onClose,
  operator,
  onLogout,
  showToast,
}) => {
  if (!isOpen) return null;

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

  const [defaultScope, setDefaultScope] = useState(currentOp.default_scope || 'ACTIVE_AUDIT');

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    if (showToast) {
      showToast('info', 'Copied to Clipboard', `${label}: ${text}`);
    }
  };

  const handleSavePreferences = () => {
    if (showToast) {
      showToast('success', 'Preferences Saved', `Default scope set to ${defaultScope}`);
    }
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/40 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-white rounded-2xl border border-[#E8E4F2] shadow-2xl max-w-xl w-full overflow-hidden animate-scaleIn text-[#22213A]">
        {/* Header */}
        <div className="bg-[#FAF9FF] px-6 py-5 border-b border-[#E8E4F2] flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-[#F4F1FF] text-[#6C4CF1] flex items-center justify-center shadow-sm">
              <span className="material-symbols-outlined text-[20px]">badge</span>
            </div>
            <div>
              <h3 className="text-sm font-bold text-[#22213A] uppercase tracking-wider">
                Operator Clearance & Identity
              </h3>
              <p className="text-xs text-[#77758E]">
                Session identity and authorized scopes
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="w-8 h-8 rounded-lg bg-[#FAF9FF] hover:bg-[#F4F1FF] text-[#77758E] flex items-center justify-center transition-all"
          >
            <span className="material-symbols-outlined text-[16px]">close</span>
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-5">
          <div className="flex items-center gap-4 p-4 rounded-xl bg-[#FAF9FF] border border-[#E8E4F2]">
            <div className="w-12 h-12 rounded-xl bg-[#6C4CF1] text-white flex items-center justify-center font-bold text-lg shadow-sm">
              {currentOp.avatar_text || 'SO'}
            </div>
            <div>
              <h4 className="text-sm font-bold text-[#22213A]">{currentOp.name}</h4>
              <p className="text-xs text-[#77758E] mt-0.5">{currentOp.email}</p>
              <span className="inline-block mt-1 text-[10px] font-bold px-2 py-0.5 rounded bg-[#F3F0FF] text-[#6C4CF1] border border-[#6C4CF1]/20">
                {currentOp.role}
              </span>
            </div>
          </div>

          <div className="space-y-3 text-xs">
            <div className="p-3 rounded-xl bg-[#FAF9FF] border border-[#E8E4F2] flex items-center justify-between">
              <span className="text-[#77758E]">Clearance Level</span>
              <span className="font-semibold text-[#22213A]">{currentOp.clearance}</span>
            </div>

            <div className="p-3 rounded-xl bg-[#FAF9FF] border border-[#E8E4F2] flex items-center justify-between">
              <span className="text-[#77758E]">Session Host</span>
              <span className="font-mono text-[#22213A]">{currentOp.client_ip}</span>
            </div>

            <div className="p-3 rounded-xl bg-[#FAF9FF] border border-[#E8E4F2] flex items-center justify-between">
              <span className="text-[#77758E]">MFA Token Status</span>
              <span className="font-semibold text-[#299B75] flex items-center gap-1">
                <span className="material-symbols-outlined text-[15px]">verified</span>
                FIDO2 / U2F Verified
              </span>
            </div>

            <div className="p-3 rounded-xl bg-[#FAF9FF] border border-[#E8E4F2] flex items-center justify-between">
              <span className="text-[#77758E]">Token Fingerprint</span>
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

          <div className="pt-2 flex items-center justify-between border-t border-[#E8E4F2]">
            <button
              onClick={() => {
                onLogout();
                onClose();
              }}
              className="px-4 py-2 rounded-xl border border-[#DC4655]/20 bg-[#FFF0F1] text-[#DC4655] hover:bg-[#FFE3E5] text-xs font-semibold transition-all flex items-center gap-1.5"
            >
              <span className="material-symbols-outlined text-[16px]">logout</span>
              <span>Terminate Session</span>
            </button>

            <button
              onClick={handleSavePreferences}
              className="px-5 py-2 rounded-xl bg-[#6C4CF1] hover:bg-[#5940D8] text-white text-xs font-semibold shadow-sm transition-all"
            >
              Done
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
