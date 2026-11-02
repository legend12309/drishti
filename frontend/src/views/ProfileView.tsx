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
    organization: 'DRISHTI Cyber Command',
    avatar_text: 'SO',
    permissions: [
      'UNIFIED_AUTORECON',
      'ATTACK_GRAPH_PATHFINDING',
      'PROMPT_GUARD_EVAL',
      'STIX_BUNDLE_EXPORT',
      'AUDIT_INSPECTION',
      'SCOPE_CHALLENGE_ISSUER',
    ],
    client_ip: '127.0.0.1 (Local Cockpit)',
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
    <div className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8 bg-bone text-ink font-mono text-xs select-none scrollbar-tactical">
      <div className="max-w-[1100px] mx-auto space-y-4">
        
        {/* Editorial Top Command Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-hairline pb-3 bg-pureWhite p-3 shadow-xs">
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-vermilion font-extrabold text-sm">11 //</span>
              <h1 className="text-sm font-grotesk font-bold uppercase tracking-wider text-ink">
                OPERATOR IDENTITY & CLEARANCE CREDENTIALS
              </h1>
              <span className="text-[9px] font-bold px-1.5 py-0.5 border border-hairline bg-boneLight text-charcoal">
                CLEARANCE VERIFIED
              </span>
            </div>
            <p className="text-[10px] text-charcoal mt-0.5">
              Active security session parameters, clearance attributes, hardware cryptographic tokens, and authorized system privileges.
            </p>
          </div>

          <button
            onClick={onLogout}
            className="border border-vermilion bg-white hover:bg-vermilion text-vermilion hover:text-white px-3 py-1.5 text-xs font-mono font-bold transition-colors shadow-xs flex items-center gap-1.5 cursor-pointer"
          >
            <span>[ TERMINATE SESSION ]</span>
          </button>
        </div>

        {/* Identity Overview Card */}
        <div className="bg-pureWhite border border-hairline p-6 shadow-xs flex flex-col sm:flex-row sm:items-center gap-5">
          <div className="w-16 h-16 bg-ink text-pureWhite border border-hairline flex items-center justify-center font-bold text-xl shrink-0 font-condensed">
            {currentOp.avatar_text || 'SO'}
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 flex-wrap">
              <h2 className="text-base font-bold text-ink uppercase tracking-wide font-grotesk truncate">
                {currentOp.name}
              </h2>
              <span className="px-2 py-0.5 bg-boneDark text-ink border border-hairline text-[10px] font-bold uppercase font-mono">
                {currentOp.role}
              </span>
              <span className="px-2 py-0.5 bg-signalGreenBg text-signalGreen border border-signalGreen text-[9px] font-bold uppercase font-mono">
                SESSION ACTIVE
              </span>
            </div>
            <p className="text-xs text-charcoal mt-1 font-mono">
              {currentOp.email} • {currentOp.organization} • IP: {currentOp.client_ip}
            </p>
          </div>
        </div>

        {/* Security Parameters Details */}
        <div className="bg-pureWhite border border-hairline shadow-xs">
          <div className="flex items-center justify-between px-4 py-2.5 border-b border-hairline bg-boneDark">
            <span className="text-[10px] font-bold text-ink uppercase tracking-wider">
              CRYPTOGRAPHIC SESSION & CLEARANCE ATTRIBUTES
            </span>
            <span className="text-[9px] text-charcoal font-mono">
              FIPS 140-3 COMPLIANT
            </span>
          </div>

          <div className="p-4 space-y-2 font-mono text-xs">
            <div className="p-3 bg-[#FAF8F5] border border-hairline flex items-center justify-between">
              <span className="text-charcoal uppercase text-[10px] font-bold">[ ACCESS CLASSIFICATION ]</span>
              <span className="font-bold text-ink">{currentOp.clearance}</span>
            </div>

            <div className="p-3 bg-[#FAF8F5] border border-hairline flex items-center justify-between">
              <span className="text-charcoal uppercase text-[10px] font-bold">[ ASSESSMENT SCOPE MODE ]</span>
              <span className="font-bold text-vermilion">{currentOp.default_scope}</span>
            </div>

            <div className="p-3 bg-[#FAF8F5] border border-hairline flex items-center justify-between">
              <span className="text-charcoal uppercase text-[10px] font-bold">[ HARDWARE MFA ENFORCEMENT ]</span>
              <span className="font-bold text-signalGreen flex items-center gap-1.5">
                <span className="w-2 h-2 bg-signalGreen inline-block"></span>
                <span>FIDO2 / U2F KEY BOUND</span>
              </span>
            </div>

            <div className="p-3 bg-[#FAF8F5] border border-hairline flex items-center justify-between">
              <span className="text-charcoal uppercase text-[10px] font-bold">[ SESSION TOKEN FINGERPRINT ]</span>
              <div className="flex items-center gap-3">
                <span className="font-mono text-ink text-[11px] bg-boneDark px-2 py-0.5 border border-hairline">
                  {currentOp.token_fingerprint}
                </span>
                <button
                  type="button"
                  onClick={() => copyToClipboard(currentOp.token_fingerprint, 'Fingerprint')}
                  className="bg-pureWhite border border-hairline hover:bg-boneDark px-2 py-0.5 text-[10px] font-bold text-ink transition-colors cursor-pointer"
                >
                  [ COPY ]
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Permissions Matrix */}
        <div className="bg-pureWhite border border-hairline p-5 shadow-xs space-y-3">
          <div className="text-[10px] font-bold text-ink uppercase tracking-wider pb-2 border-b border-hairline font-grotesk flex items-center justify-between">
            <span>AUTHORIZED CAPABILITIES & ROLE-BASED ACCESS CONTROL (RBAC)</span>
            <span className="text-signalGreen font-mono text-[9px] font-bold">6/6 ROLES ASSIGNED</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2 pt-1 font-mono text-xs">
            {currentOp.permissions.map((perm, idx) => (
              <div key={idx} className="p-2.5 bg-boneLight border border-hairline flex items-center space-x-2">
                <span className="text-signalGreen font-bold">✓</span>
                <span className="text-ink text-[11px] font-bold">{perm}</span>
              </div>
            ))}
          </div>
        </div>

      </div>
    </div>
  );
};
