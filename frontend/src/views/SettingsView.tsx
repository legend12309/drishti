import React, { useState, useEffect } from 'react';
import { TabId } from '../types';
import { DoodleIcon } from '../components/DoodleIcon';

interface SettingsViewProps {
  onNavigate?: (tab: TabId) => void;
  showToast?: (type: 'success' | 'warning' | 'error' | 'info', title: string, detail?: string) => void;
}

interface EngineMode {
  mode: string;
  provider: string;
  description: string;
}

export const SettingsView: React.FC<SettingsViewProps> = ({ onNavigate, showToast }) => {
  const [googleKey, setGoogleKey] = useState('');
  const [nvidiaKey, setNvidiaKey] = useState('');
  const [huggingfaceKey, setHuggingfaceKey] = useState('');
  const [groqKey, setGroqKey] = useState('');
  const [forceLocal, setForceLocal] = useState(false);

  const [engineMode, setEngineMode] = useState<EngineMode>({
    mode: 'LOCAL_COMMODITY',
    provider: 'Local CPU (all-MiniLM-L6-v2 + Heuristic Rules)',
    description: 'No external API keys detected. DRISHTI is running 100% locally on commodity hardware.',
  });

  const [saving, setSaving] = useState(false);

  useEffect(() => {
    fetch('/api/settings')
      .then((res) => res.json())
      .then((data) => {
        if (data.keys) {
          if (data.keys.google?.masked) setGoogleKey(data.keys.google.masked);
          else if (data.keys.gemini?.masked) setGoogleKey(data.keys.gemini.masked);
          if (data.keys.nvidia?.masked) setNvidiaKey(data.keys.nvidia.masked);
          if (data.keys.huggingface?.masked) setHuggingfaceKey(data.keys.huggingface.masked);
          if (data.keys.groq?.masked) setGroqKey(data.keys.groq.masked);
        }
        if (data.engine_mode) setEngineMode(data.engine_mode);
        if (data.force_local_mode !== undefined) setForceLocal(data.force_local_mode);
      })
      .catch(() => {});
  }, []);

  const handleSave = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setSaving(true);
    try {
      const res = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          gemini_api_key: googleKey.includes('••') ? undefined : googleKey,
          nvidia_api_key: nvidiaKey.includes('••') ? undefined : nvidiaKey,
          huggingface_api_key: huggingfaceKey.includes('••') ? undefined : huggingfaceKey,
          groq_api_key: groqKey.includes('••') ? undefined : groqKey,
          force_local_mode: forceLocal,
        }),
      });

      if (!res.ok) throw new Error('Settings save failed');
      const data = await res.json();
      if (data.engine_mode) setEngineMode(data.engine_mode);

      if (showToast) {
        showToast('success', 'Settings Synchronized', 'AI provider parameters updated in secure memory.');
      }
    } catch {
      if (showToast) {
        showToast('error', 'Update Failed', 'Failed to persist settings changes.');
      }
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="flex-1 h-full min-h-0 overflow-y-auto p-4 sm:p-6 lg:p-8 bg-bone text-ink font-mono text-xs select-none scrollbar-tactical">
      <div className="max-w-[1200px] mx-auto space-y-4">
        
        {/* Editorial Top Command Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-hairline pb-3 bg-pureWhite p-3 shadow-xs">
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-vermilion font-extrabold text-sm">10 //</span>
              <h1 className="text-sm font-grotesk font-bold uppercase tracking-wider text-ink">
                ENGINE CONFIGURATION & SECURITY CREDENTIALS
              </h1>
              <span className="text-[9px] font-bold px-1.5 py-0.5 border border-hairline bg-boneLight text-charcoal">
                ZERO-EGRESS AIR-GAP READY
              </span>
            </div>
            <p className="text-[10px] text-charcoal mt-0.5">
              Manage LLM API provider credentials, local model fallbacks, and air-gapped zero-egress operational boundaries.
            </p>
          </div>

          <button
            onClick={() => handleSave()}
            disabled={saving}
            className="bg-vermilion hover:bg-crimson text-white px-4 py-2 text-xs font-mono font-bold border border-hairline shadow-xs flex items-center gap-2 transition-colors disabled:opacity-50 cursor-pointer"
          >
            <span>{saving ? '[ PERSISTING... ]' : '[ SAVE CONFIGURATION ➔ ]'}</span>
          </button>
        </div>

        {/* Active Engine Telemetry Card */}
        <div className="bg-pureWhite border border-hairline p-5 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 bg-boneDark border border-hairline text-ink flex items-center justify-center shrink-0">
              <DoodleIcon name="gear" className="w-6 h-6 text-ink" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-ink uppercase tracking-wider font-grotesk">
                  ACTIVE ENGINE RUNTIME: {engineMode.mode}
                </span>
                <span className="px-2 py-0.5 bg-signalGreenBg text-signalGreen border border-signalGreen text-[9px] font-bold uppercase">
                  OPERATIONAL
                </span>
              </div>
              <div className="text-xs text-charcoal mt-1 font-mono">
                Provider: <strong className="text-ink">{engineMode.provider}</strong>
              </div>
              <p className="text-[11px] text-charcoal mt-1 leading-relaxed max-w-2xl font-mono">
                {engineMode.description}
              </p>
            </div>
          </div>

          <div className="text-right text-[10px] font-mono border-t md:border-t-0 md:border-l border-hairlineLight pt-3 md:pt-0 md:pl-5 shrink-0 space-y-1">
            <div className="text-charcoal uppercase">ARCHITECTURE</div>
            <div className="font-bold text-ink">HYBRID LOCAL / CLOUD</div>
            <div className="text-signalGreen font-bold">FALLBACK CPU ACTIVE</div>
          </div>
        </div>

        {/* API Credentials Configuration Panel */}
        <div className="bg-pureWhite border border-hairline p-6 shadow-xs space-y-6">
          <div className="flex items-center justify-between pb-3 border-b border-hairline bg-boneDark -mx-6 -mt-6 p-4">
            <span className="text-[10px] font-bold text-ink uppercase tracking-wider">
              AI PROVIDER CREDENTIALS & SECURE ENCLAVE STORAGE
            </span>
            <span className="text-[9px] text-charcoal font-mono">
              AES-256-GCM ENCRYPTED AT REST
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-[10px] font-bold uppercase tracking-wider text-charcoal block mb-1 font-mono flex items-center justify-between">
                <span>Google Gemini API Key</span>
                <span className="text-[9px] text-pencil font-normal">Fast Multimodal</span>
              </label>
              <input
                type="password"
                value={googleKey}
                onChange={(e) => setGoogleKey(e.target.value)}
                placeholder="AIzaSy..."
                className="w-full px-3 py-2 bg-[#FAF8F5] border border-hairline text-xs text-ink focus:border-vermilion outline-none font-mono"
              />
            </div>

            <div>
              <label className="text-[10px] font-bold uppercase tracking-wider text-charcoal block mb-1 font-mono flex items-center justify-between">
                <span>Groq Cloud API Key</span>
                <span className="text-[9px] text-pencil font-normal">Ultra-Low Latency LPU</span>
              </label>
              <input
                type="password"
                value={groqKey}
                onChange={(e) => setGroqKey(e.target.value)}
                placeholder="gsk_..."
                className="w-full px-3 py-2 bg-[#FAF8F5] border border-hairline text-xs text-ink focus:border-vermilion outline-none font-mono"
              />
            </div>

            <div>
              <label className="text-[10px] font-bold uppercase tracking-wider text-charcoal block mb-1 font-mono flex items-center justify-between">
                <span>NVIDIA NIM API Key</span>
                <span className="text-[9px] text-pencil font-normal">GPU Accelerated Microservice</span>
              </label>
              <input
                type="password"
                value={nvidiaKey}
                onChange={(e) => setNvidiaKey(e.target.value)}
                placeholder="nvapi-..."
                className="w-full px-3 py-2 bg-[#FAF8F5] border border-hairline text-xs text-ink focus:border-vermilion outline-none font-mono"
              />
            </div>

            <div>
              <label className="text-[10px] font-bold uppercase tracking-wider text-charcoal block mb-1 font-mono flex items-center justify-between">
                <span>HuggingFace Token</span>
                <span className="text-[9px] text-pencil font-normal">Open-Weights Inference</span>
              </label>
              <input
                type="password"
                value={huggingfaceKey}
                onChange={(e) => setHuggingfaceKey(e.target.value)}
                placeholder="hf_..."
                className="w-full px-3 py-2 bg-[#FAF8F5] border border-hairline text-xs text-ink focus:border-vermilion outline-none font-mono"
              />
            </div>
          </div>

          {/* Air-Gap Offline Toggle */}
          <div 
            onClick={() => setForceLocal(!forceLocal)}
            className="pt-4 border-t border-hairline flex items-center justify-between cursor-pointer group bg-boneLight p-4"
          >
            <div>
              <div className="text-xs font-bold text-ink uppercase tracking-wider flex items-center gap-2 font-grotesk">
                <span>ENFORCE ZERO-EGRESS AIR-GAP OFFLINE MODE</span>
                {forceLocal && (
                  <span className="text-[9px] bg-vermilion text-white px-2 py-0.5 font-bold uppercase font-mono">
                    AIR-GAP ACTIVE
                  </span>
                )}
              </div>
              <div className="text-[10px] text-charcoal mt-1 font-mono">
                Strictly prohibits all outbound external HTTP API calls. All embedding, clustering, and heuristic evaluations execute 100% locally on CPU.
              </div>
            </div>

            <button
              type="button"
              role="switch"
              aria-checked={forceLocal}
              onClick={(e) => {
                e.stopPropagation();
                setForceLocal(!forceLocal);
              }}
              className={`w-14 h-7 border border-hairline transition-colors relative cursor-pointer ${
                forceLocal ? 'bg-vermilion' : 'bg-pureWhite'
              }`}
            >
              <span
                className={`w-5 h-5 bg-ink border border-pureWhite block absolute top-0.5 transition-transform duration-150 ${
                  forceLocal ? 'translate-x-7 bg-pureWhite' : 'translate-x-0.5'
                }`}
              />
            </button>
          </div>
        </div>

      </div>
    </div>
  );
};
