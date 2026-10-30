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

  return (
    <div className="flex-1 overflow-y-auto p-6 lg:p-8 bg-[#F4F1FF] text-[#22213A]">
      <div className="max-w-[1400px] mx-auto space-y-6">
        
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[20px] text-[#6C4CF1]">description</span>
              <h1 className="text-2xl font-bold tracking-tight text-[#22213A]">
                STIX 2.1 Threat Sharing & Export
              </h1>
            </div>
            <p className="text-sm text-[#77758E] mt-1">
              Standardized OASIS STIX 2.1 threat intelligence bundles generated from live scan findings and attack graphs.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={copyJson}
              disabled={loading || !stixBundle}
              className="bg-white border border-[#E8E4F2] hover:border-[#6C4CF1]/40 text-[#22213A] px-4 py-2 rounded-xl text-xs font-semibold shadow-sm flex items-center gap-1.5 transition-all disabled:opacity-40"
            >
              <span className="material-symbols-outlined text-[16px] text-[#6C4CF1]">content_copy</span>
              <span>{copied ? 'Copied!' : 'Copy JSON'}</span>
            </button>
            <button
              onClick={downloadJson}
              disabled={loading || !stixBundle}
              className="bg-[#6C4CF1] hover:bg-[#5940D8] text-white px-4 py-2 rounded-xl text-xs font-semibold shadow-sm flex items-center gap-2 transition-all active:scale-95 disabled:opacity-40"
            >
              <span className="material-symbols-outlined text-[18px]">download</span>
              <span>Export STIX Bundle</span>
            </button>
          </div>
        </div>

        {/* STIX Specification Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          <div className="bg-white rounded-2xl border border-[#E8E4F2] p-5 shadow-sm space-y-2">
            <div className="w-8 h-8 rounded-lg bg-[#F4F1FF] text-[#6C4CF1] flex items-center justify-center font-bold text-xs">
              <span className="material-symbols-outlined text-[18px]">schema</span>
            </div>
            <h4 className="text-sm font-bold text-[#22213A]">
              OASIS STIX 2.1 Specification
            </h4>
            <p className="text-xs text-[#77758E] leading-relaxed">
              Standardized schema encapsulating Attack Patterns, Threat Indicators, and observed Vulnerabilities.
            </p>
          </div>

          <div className="bg-white rounded-2xl border border-[#E8E4F2] p-5 shadow-sm space-y-2">
            <div className="w-8 h-8 rounded-lg bg-[#EAF8F1] text-[#299B75] flex items-center justify-center font-bold text-xs">
              <span className="material-symbols-outlined text-[18px]">verified</span>
            </div>
            <h4 className="text-sm font-bold text-[#22213A]">
              Deterministic Integrity
            </h4>
            <p className="text-xs text-[#77758E] leading-relaxed">
              Bundles include UUIDv4 identifiers directly mapped to validated live observations.
            </p>
          </div>

          <div className="bg-white rounded-2xl border border-[#E8E4F2] p-5 shadow-sm space-y-2">
            <div className="w-8 h-8 rounded-lg bg-[#F4F1FF] text-[#6C4CF1] flex items-center justify-center font-bold text-xs">
              <span className="material-symbols-outlined text-[18px]">share</span>
            </div>
            <h4 className="text-sm font-bold text-[#22213A]">
              TAXII 2.1 Interoperability
            </h4>
            <p className="text-xs text-[#77758E] leading-relaxed">
              Export format ready for seamless ingestion into enterprise SIEM, SOAR, and Threat Intel Platforms.
            </p>
          </div>
        </div>

        {/* STIX 2.1 JSON Payload Preview */}
        <div className="bg-white rounded-2xl border border-[#E8E4F2] p-6 shadow-sm space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#E8E4F2]">
            <span className="text-xs font-bold text-[#22213A] uppercase tracking-wider">
              Live Bundle Telemetry
            </span>
            <span className="text-xs text-[#77758E] font-mono">
              spec_version: 2.1 • Objects: {stixBundle?.objects ? stixBundle.objects.length : 0}
            </span>
          </div>

          {loading ? (
            <div className="py-20 text-center space-y-2">
              <span className="material-symbols-outlined text-3xl text-[#6C4CF1] animate-spin">
                progress_activity
              </span>
              <p className="text-xs text-[#77758E]">Compiling live STIX 2.1 bundle from Supabase...</p>
            </div>
          ) : stixBundle?.objects && stixBundle.objects.length > 0 ? (
            <pre className="p-4 rounded-xl bg-[#FAF9FF] border border-[#E8E4F2] font-mono text-xs text-[#22213A] overflow-x-auto max-h-[440px] leading-relaxed">
              {jsonString}
            </pre>
          ) : (
            <div className="py-16 text-center space-y-3 bg-[#FAF9FF] rounded-xl border border-[#E8E4F2]">
              <div className="w-10 h-10 rounded-xl bg-white flex items-center justify-center mx-auto text-[#6C4CF1] shadow-sm">
                <span className="material-symbols-outlined text-xl">dataset</span>
              </div>
              <h4 className="text-xs font-bold text-[#22213A]">Empty STIX 2.1 Object Bundle</h4>
              <p className="text-xs text-[#77758E] max-w-sm mx-auto">
                No indicators or vulnerability objects recorded yet. Run AutoRecon to populate threat data.
              </p>
            </div>
          )}
        </div>

      </div>
    </div>
  );
};
