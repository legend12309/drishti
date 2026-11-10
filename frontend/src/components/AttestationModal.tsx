import React, { useState, useEffect } from 'react';
import { DoodleIcon } from './DoodleIcon';

interface AttestationModalProps {
  isOpen: boolean;
  onClose: () => void;
  showToast?: (type: 'success' | 'warning' | 'error' | 'info', title: string, detail?: string) => void;
}

interface AttestationData {
  status: string;
  platform: string;
  version: string;
  attestation: {
    node_id: string;
    platform_host: string;
    enclave_os: string;
    registered_author: string;
    institution_enclave: string;
    cryptographic_signature: string;
    tamper_evident_root: string;
    attestation_timestamp: string;
    ip_protection_notice: string;
  };
  codebase_integrity: {
    status: string;
    checked_modules: string[];
    tamper_digest: string;
    integrity_verified_at: string;
  };
}

export const AttestationModal: React.FC<AttestationModalProps> = ({
  isOpen,
  onClose,
  showToast,
}) => {
  const [data, setData] = useState<AttestationData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    if (!isOpen) return;
    let isMounted = true;
    setLoading(true);

    fetch('/api/system/attestation')
      .then((res) => res.json())
      .then((json) => {
        if (isMounted) {
          setData(json);
          setLoading(false);
        }
      })
      .catch((err) => {
        console.error('Failed to fetch attestation:', err);
        if (isMounted) setLoading(false);
      });

    return () => {
      isMounted = false;
    };
  }, [isOpen]);

  if (!isOpen) return null;

  const copyCert = () => {
    if (!data) return;
    const certText = `
DRISHTI CYBER INTELLIGENCE PLATFORM // CRYPTOGRAPHIC ENCLAVE ATTESTATION
========================================================================
REGISTERED AUTHOR   : ${data.attestation?.registered_author}
INSTITUTION ENCLAVE : ${data.attestation?.institution_enclave}
HARDWARE NODE ID    : ${data.attestation?.node_id}
ENCLAVE OS / HOST   : ${data.attestation?.enclave_os} (${data.attestation?.platform_host})
CRYPTOGRAPHIC SEAL  : ${data.attestation?.cryptographic_signature}
MERKLE INTEGRITY    : ${data.codebase_integrity?.status} (${data.codebase_integrity?.tamper_digest})
MODULES VERIFIED    : ${data.codebase_integrity?.checked_modules?.join(', ')}
ATTESTATION TIME    : ${data.attestation?.attestation_timestamp}
LEGAL PROTECTION    : ${data.attestation?.ip_protection_notice}
========================================================================
CERTIFIED IMMUTABLE ACADEMIC INTELLECTUAL PROPERTY // ANTI-COPY ENFORCED
    `.trim();

    navigator.clipboard.writeText(certText);
    if (showToast) {
      showToast('success', 'Attestation Copied', 'Hardware enclave certificate copied to clipboard.');
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4 font-mono select-none">
      <div className="bg-pureWhite border-2 border-ink shadow-2xl max-w-2xl w-full overflow-hidden flex flex-col text-xs animate-scaleIn">
        {/* Terminal Header */}
        <div className="bg-boneDark px-4 py-3 border-b border-hairline flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <span className="w-2.5 h-2.5 bg-signalGreen animate-pulse"></span>
            <span className="font-bold text-ink uppercase tracking-wider text-[11px]">
              DRISHTI // CRYPTOGRAPHIC ENCLAVE ATTESTATION & ANTI-COPY SEAL
            </span>
          </div>
          <button
            onClick={onClose}
            className="text-pencil hover:text-ink font-bold text-sm px-1.5 py-0.5 border border-transparent hover:border-hairline transition-colors"
          >
            [X]
          </button>
        </div>

        {/* Content Body */}
        <div className="p-5 space-y-4 max-h-[80vh] overflow-y-auto bg-boneLight">
          {/* Top Enclave Badge */}
          <div className="p-3 bg-pureWhite border border-signalGreen/60 shadow-xs flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="w-9 h-9 border border-signalGreen bg-signalGreenBg text-signalGreen font-bold flex items-center justify-center text-sm shadow-xs">
                <DoodleIcon name="shield" size={18} className="text-signalGreen" />
              </div>
              <div>
                <div className="text-[11px] font-black text-ink uppercase">
                  SOVEREIGN HARDWARE BINDING: ACTIVE
                </div>
                <div className="text-[10px] text-pencil font-medium">
                  Dissertation IP Protected • Anti-Tampering Engine Armed
                </div>
              </div>
            </div>
            <span className="px-2 py-1 bg-signalGreenBg border border-signalGreen text-signalGreen text-[10px] font-bold">
              [ ATTESTED & IMMUTABLE ]
            </span>
          </div>

          {loading ? (
            <div className="py-8 text-center text-pencil">
              [ VERIFYING HARDWARE ENCLAVE & MERKLE TREE HASHES... ]
            </div>
          ) : data ? (
            <>
              {/* Ownership Matrix */}
              <div className="bg-pureWhite p-3.5 border border-hairline space-y-2">
                <div className="text-[10px] font-bold text-charcoal uppercase tracking-wider border-b border-hairline pb-1">
                  [01] REGISTERED AUTHOR & DISSERTATION PROVENANCE
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[10.5px]">
                  <div>
                    <span className="text-pencil block text-[9.5px]">REGISTERED AUTHOR:</span>
                    <span className="font-bold text-ink">{data.attestation?.registered_author}</span>
                  </div>
                  <div>
                    <span className="text-pencil block text-[9.5px]">INSTITUTION / ENCLAVE:</span>
                    <span className="font-bold text-ink">{data.attestation?.institution_enclave}</span>
                  </div>
                  <div>
                    <span className="text-pencil block text-[9.5px]">ENCLAVE NODE ID:</span>
                    <span className="font-mono font-bold text-cyan">{data.attestation?.node_id}</span>
                  </div>
                  <div>
                    <span className="text-pencil block text-[9.5px]">HOST & ARCHITECTURE:</span>
                    <span className="font-mono text-ink">{data.attestation?.enclave_os} ({data.attestation?.platform_host})</span>
                  </div>
                </div>
              </div>

              {/* Cryptographic Signature & Merkle Root */}
              <div className="bg-pureWhite p-3.5 border border-hairline space-y-2">
                <div className="text-[10px] font-bold text-charcoal uppercase tracking-wider border-b border-hairline pb-1">
                  [02] CRYPTOGRAPHIC SIGNATURE & MERKLE INTEGRITY
                </div>
                <div className="space-y-1.5 text-[10.5px]">
                  <div>
                    <span className="text-pencil block text-[9.5px]">HMAC-SHA256 SIGNATURE:</span>
                    <span className="font-mono text-signalGreen text-[10px] break-all">
                      {data.attestation?.cryptographic_signature}
                    </span>
                  </div>
                  <div>
                    <span className="text-pencil block text-[9.5px]">MERKLE TREE DIGEST:</span>
                    <span className="font-mono text-charcoal text-[10px]">
                      {data.codebase_integrity?.tamper_digest} [STATUS: {data.codebase_integrity?.status}]
                    </span>
                  </div>
                  <div>
                    <span className="text-pencil block text-[9.5px]">VERIFIED CORE ENGINE MODULES:</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {data.codebase_integrity?.checked_modules?.map((m, i) => (
                        <span key={i} className="px-1.5 py-0.5 bg-boneDark border border-hairline text-[9px] text-ink font-bold inline-flex items-center gap-1">
                          <DoodleIcon name="check" size={9} className="text-signalGreen" />
                          <span>{m}</span>
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              {/* Anti-Copy Protection Notice */}
              <div className="bg-boneDark p-3 border border-hairline text-[10px] text-pencil leading-relaxed">
                <span className="font-bold text-ink block mb-0.5">LEGAL ANTI-COPY & IP RESTRICTION:</span>
                This system, its attack graph Dijkstra pathfinding algorithms, prompt injection filters, and WAF defense synthesizers are the proprietary intellectual property of the registered author. Any unauthorized duplication, reverse engineering, unauthorized deployment, or plagiarism is strictly prohibited and cryptographically attested.
              </div>
            </>
          ) : (
            <div className="py-6 text-center text-vermilion">
              [ ERROR: COULD NOT CONNECT TO ATTESTATION DAEMON ]
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="bg-pureWhite px-4 py-3 border-t border-hairline flex items-center justify-between">
          <button
            onClick={copyCert}
            className="px-3 py-1.5 border border-ink bg-boneLight hover:bg-pureWhite font-bold text-[10px] text-ink active:scale-95 transition-all flex items-center space-x-1.5 cursor-pointer"
          >
            <DoodleIcon name="copy" size={12} className="text-ink" />
            <span>[ COPY CERTIFICATE ]</span>
          </button>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-ink text-pureWhite font-bold text-[10px] hover:bg-charcoal active:scale-95 transition-all"
          >
            [ CLOSE ]
          </button>
        </div>
      </div>
    </div>
  );
};
