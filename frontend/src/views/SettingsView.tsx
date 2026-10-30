import React, { useState, useEffect } from 'react';
import { TabId } from '../types';

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
    <div className="flex-1 overflow-y-auto p-6 lg:p-8 bg-[#F4F1FF] text-[#22213A]">
      <div className="max-w-[1100px] mx-auto space-y-6">
        
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[20px] text-[#6C4CF1]">tune</span>
              <h1 className="text-2xl font-bold tracking-tight text-[#22213A]">
                Engine Configuration & Providers
              </h1>
            </div>
            <p className="text-sm text-[#77758E] mt-1">
              Manage LLM API providers, local model fallbacks, and zero-egress operational boundaries.
            </p>
          </div>

          <button
            onClick={() => handleSave()}
            disabled={saving}
            className="bg-[#6C4CF1] hover:bg-[#5940D8] text-white px-5 py-2.5 rounded-xl text-xs font-semibold shadow-sm flex items-center gap-2 transition-all active:scale-95 disabled:opacity-50"
          >
            <span className="material-symbols-outlined text-[18px]">save</span>
            <span>{saving ? 'Saving...' : 'Save Configuration'}</span>
          </button>
        </div>

        {/* Active Engine Card */}
        <div className="bg-white rounded-2xl border border-[#E8E4F2] p-6 shadow-sm flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-[#F4F1FF] text-[#6C4CF1] flex items-center justify-center shrink-0">
              <span className="material-symbols-outlined text-2xl">memory</span>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-base font-bold text-[#22213A]">
                  Active Engine: {engineMode.mode}
                </span>
                <span className="px-2.5 py-0.5 rounded-md bg-[#EAF8F1] text-[#299B75] border border-[#299B75]/20 text-[10px] font-bold uppercase">
                  Connected
                </span>
              </div>
              <p className="text-xs text-[#77758E] mt-1">
                {engineMode.description}
              </p>
            </div>
          </div>
        </div>

        {/* API Keys Configuration Form */}
        <div className="bg-white rounded-2xl border border-[#E8E4F2] p-8 shadow-sm space-y-6">
          <h3 className="text-xs font-bold text-[#22213A] uppercase tracking-wider pb-3 border-b border-[#E8E4F2]">
            AI Provider Credentials
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <div>
              <label className="text-[11px] font-bold uppercase tracking-wider text-[#77758E] block mb-1.5">
                Google Gemini API Key
              </label>
              <input
                type="password"
                value={googleKey}
                onChange={(e) => setGoogleKey(e.target.value)}
                placeholder="AIzaSy..."
                className="w-full px-4 py-2.5 rounded-xl bg-[#FAF9FF] border border-[#E8E4F2] text-sm text-[#22213A] focus:border-[#6C4CF1] outline-none font-mono"
              />
            </div>

            <div>
              <label className="text-[11px] font-bold uppercase tracking-wider text-[#77758E] block mb-1.5">
                Groq Cloud API Key
              </label>
              <input
                type="password"
                value={groqKey}
                onChange={(e) => setGroqKey(e.target.value)}
                placeholder="gsk_..."
                className="w-full px-4 py-2.5 rounded-xl bg-[#FAF9FF] border border-[#E8E4F2] text-sm text-[#22213A] focus:border-[#6C4CF1] outline-none font-mono"
              />
            </div>

            <div>
              <label className="text-[11px] font-bold uppercase tracking-wider text-[#77758E] block mb-1.5">
                NVIDIA NIM API Key
              </label>
              <input
                type="password"
                value={nvidiaKey}
                onChange={(e) => setNvidiaKey(e.target.value)}
                placeholder="nvapi-..."
                className="w-full px-4 py-2.5 rounded-xl bg-[#FAF9FF] border border-[#E8E4F2] text-sm text-[#22213A] focus:border-[#6C4CF1] outline-none font-mono"
              />
            </div>

            <div>
              <label className="text-[11px] font-bold uppercase tracking-wider text-[#77758E] block mb-1.5">
                HuggingFace Token
              </label>
              <input
                type="password"
                value={huggingfaceKey}
                onChange={(e) => setHuggingfaceKey(e.target.value)}
                placeholder="hf_..."
                className="w-full px-4 py-2.5 rounded-xl bg-[#FAF9FF] border border-[#E8E4F2] text-sm text-[#22213A] focus:border-[#6C4CF1] outline-none font-mono"
              />
            </div>
          </div>

          <div 
            onClick={() => setForceLocal(!forceLocal)}
            className="pt-4 border-t border-[#E8E4F2] flex items-center justify-between cursor-pointer group"
          >
            <div>
              <div className="text-sm font-bold text-[#22213A] group-hover:text-[#6C4CF1] transition-colors">
                Enforce Local Offline Mode
              </div>
              <div className="text-xs text-[#77758E] mt-0.5">
                Disallow external HTTP network egress for LLM operations. Enforces zero-cloud privacy.
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
              className={`w-12 h-6 rounded-full transition-colors relative cursor-pointer focus:outline-none focus:ring-2 focus:ring-[#6C4CF1]/20 ${
                forceLocal ? 'bg-[#6C4CF1]' : 'bg-[#E8E4F2]'
              }`}
            >
              <span
                className={`w-5 h-5 rounded-full bg-white block absolute top-0.5 shadow-sm transition-transform duration-200 ease-in-out ${
                  forceLocal ? 'translate-x-6' : 'translate-x-0.5'
                }`}
              />
            </button>
          </div>
        </div>

      </div>
    </div>
  );
};
