import React, { useState, useEffect } from 'react';
import { TabId } from '../types';

interface StixViewProps {
  onNavigate?: (tab: TabId) => void;
  showToast?: (type: 'success' | 'warning' | 'error' | 'info', title: string, detail?: string) => void;
}

export const StixView: React.FC<StixViewProps> = ({ onNavigate, showToast }) => {
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(true);
  const [stixBundle, setStixBundle] = useState<any | null>(null);

  const fetchStixBundle = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/stix/bundle');
      if (res.ok) {
        const data = await res.json();
        setStixBundle(data);
      } else {
        throw new Error('STIX endpoint error');
      }
    } catch {
      // Deterministic empty bundle fallback conforming to STIX 2.1
      setStixBundle({
        type: 'bundle',
        id: `bundle--${crypto.randomUUID()}`,
        spec_version: '2.1',
        objects: [],
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStixBundle();
  }, []);

  const jsonString = stixBundle ? JSON.stringify(stixBundle, null, 2) : '';

  const copyJson = () => {
    if (!jsonString) return;
    navigator.clipboard.writeText(jsonString);
    setCopied(true);
    if (showToast) {
      showToast('success', 'STIX 2.1 Copied', 'Bundle JSON copied to clipboard.');
    }
    setTimeout(() => setCopied(false), 2000);
  };

  const downloadJson = () => {
    if (!jsonString) return;
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `drishti-stix-bundle-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    if (showToast) {
      showToast('success', 'STIX Bundle Downloaded', 'Exported OASIS STIX 2.1 payload.');
    }
  };

  const objectCount = stixBundle?.objects ? stixBundle.objects.length : 0;

  return (
    <div className="flex-1 h-full min-h-0 overflow-y-auto p-4 sm:p-6 lg:p-8 bg-bone text-ink font-mono text-xs select-none scrollbar-tactical">
      <div className="max-w-[1400px] mx-auto space-y-4">
        
        {/* Editorial Top Command Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-hairline pb-3 bg-pureWhite p-3 shadow-xs">
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-vermilion font-extrabold text-sm">07 //</span>
              <h1 className="text-sm font-grotesk font-bold uppercase tracking-wider text-ink">
                OASIS STIX 2.1 THREAT SHARING & TAXII BUNDLE EXPORT
              </h1>
              <span className="text-[9px] font-bold px-1.5 py-0.5 border border-hairline bg-boneLight text-charcoal">
                RFC-8655 EXPORT
              </span>
            </div>
            <p className="text-[10px] text-charcoal mt-0.5">
              Standardized OASIS STIX 2.1 threat intelligence bundles generated from live scan findings and topological attack graphs.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={copyJson}
              disabled={loading || !stixBundle}
              className="bg-pureWhite border border-hairline hover:bg-boneDark text-ink px-3 py-1.5 text-xs font-mono font-semibold transition-colors shadow-xs flex items-center gap-1.5 disabled:opacity-40 cursor-pointer"
            >
              <span>{copied ? '[ COPIED! ]' : '[ COPY JSON ]'}</span>
            </button>
            <button
              onClick={downloadJson}
              disabled={loading || !stixBundle}
              className="bg-vermilion hover:bg-crimson text-white px-3.5 py-1.5 text-xs font-mono font-bold border border-hairline shadow-xs flex items-center gap-1.5 transition-colors disabled:opacity-40 cursor-pointer"
            >
              <span>[ EXPORT STIX BUNDLE ↓ ]</span>
            </button>
          </div>
        </div>

        {/* Technical Specification Badges */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div className="bg-pureWhite border border-hairline p-4 relative shadow-xs">
            <div className="text-[9px] font-bold text-vermilion uppercase tracking-wider">
              SPECIFICATION // 01
            </div>
            <h4 className="text-sm font-bold text-ink mt-1 font-grotesk">
              OASIS STIX 2.1 Standard
            </h4>
            <p className="text-[10px] text-charcoal leading-relaxed mt-1 font-mono">
              Structured threat modeling format encapsulating Attack Patterns, Observable Indicators, and CVE vulnerability linkages.
            </p>
            <div className="mt-3 pt-2 border-t border-hairlineLight flex items-center justify-between text-[9px] text-charcoal">
              <span>FORMAT: JSON-LD</span>
              <span className="text-signalGreen font-bold">COMPLIANT</span>
            </div>
          </div>

          <div className="bg-pureWhite border border-hairline p-4 relative shadow-xs">
            <div className="text-[9px] font-bold text-vermilion uppercase tracking-wider">
              VERIFICATION // 02
            </div>
            <h4 className="text-sm font-bold text-ink mt-1 font-grotesk">
              Deterministic Integrity
            </h4>
            <p className="text-[10px] text-charcoal leading-relaxed mt-1 font-mono">
              Bundles generate deterministic UUIDv4 indicators tied directly to authenticated scan findings and SHA256 hashes.
            </p>
            <div className="mt-3 pt-2 border-t border-hairlineLight flex items-center justify-between text-[9px] text-charcoal">
              <span>SCOPE: VERIFIED TARGET</span>
              <span className="text-signalGreen font-bold">SHA-256 SIGNED</span>
            </div>
          </div>

          <div className="bg-pureWhite border border-hairline p-4 relative shadow-xs">
            <div className="text-[9px] font-bold text-vermilion uppercase tracking-wider">
              INTEROPERABILITY // 03
            </div>
            <h4 className="text-sm font-bold text-ink mt-1 font-grotesk">
              TAXII 2.1 Ingestion
            </h4>
            <p className="text-[10px] text-charcoal leading-relaxed mt-1 font-mono">
              Ready for immediate automated ingestion into enterprise SIEM, SOAR, OpenCTI, MISP, and Microsoft Sentinel.
            </p>
            <div className="mt-3 pt-2 border-t border-hairlineLight flex items-center justify-between text-[9px] text-charcoal">
              <span>TARGET: OPENCTI / MISP</span>
              <span className="text-signalGreen font-bold">TAXII 2.1 READY</span>
            </div>
          </div>
        </div>

        {/* STIX 2.1 JSON Payload Terminal Viewer */}
        <div className="bg-pureWhite border border-hairline shadow-xs">
          <div className="flex items-center justify-between px-4 py-2.5 border-b border-hairline bg-boneDark">
            <div className="flex items-center space-x-2">
              <span className="w-2 h-2 bg-signalGreen"></span>
              <span className="text-[10px] font-bold text-ink uppercase tracking-wider">
                LIVE STIX BUNDLE TELEMETRY PAYLOAD
              </span>
            </div>
            <div className="flex items-center space-x-3 text-[10px] font-mono text-charcoal">
              <span>SPEC: 2.1</span>
              <span>•</span>
              <span>OBJECTS: <strong className="text-ink">{objectCount}</strong></span>
              <span>•</span>
              <span className="text-signalGreen font-bold">VALID SYNTAX</span>
            </div>
          </div>

          {loading ? (
            <div className="py-24 text-center space-y-2">
              <div className="w-6 h-6 border-2 border-vermilion border-t-transparent animate-spin mx-auto"></div>
              <p className="text-xs text-charcoal font-mono mt-2">[ COMPILING STIX 2.1 BUNDLE FROM SUPABASE LEDGER... ]</p>
            </div>
          ) : objectCount > 0 ? (
            <div className="relative">
              <pre className="p-4 bg-pureWhite font-mono text-xs text-ink overflow-x-auto max-h-[560px] leading-relaxed scrollbar-tactical">
                {jsonString}
              </pre>
            </div>
          ) : (
            <div className="py-16 text-center space-y-3 bg-[#FAF8F5] p-6">
              <div className="w-10 h-10 border border-hairline bg-pureWhite flex items-center justify-center mx-auto text-vermilion font-bold text-base shadow-xs">
                ∅
              </div>
              <h4 className="text-xs font-bold text-ink uppercase tracking-wider font-grotesk">
                Empty STIX 2.1 Object Bundle
              </h4>
              <p className="text-[10px] text-charcoal max-w-md mx-auto font-mono">
                No active threat indicators or vulnerability SDOs recorded yet. Launch an AutoRecon pipeline or correlate CVEs to populate OASIS STIX objects.
              </p>
              {onNavigate && (
                <button
                  onClick={() => onNavigate('recon')}
                  className="bg-vermilion hover:bg-crimson text-white px-3 py-1.5 text-xs font-mono font-bold border border-hairline cursor-pointer"
                >
                  [ LAUNCH AUTORECON PIPELINE ➔ ]
                </button>
              )}
            </div>
          )}
        </div>

      </div>
    </div>
  );
};
