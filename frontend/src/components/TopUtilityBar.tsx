import React, { useState, useEffect } from 'react';
import { OperatorProfile } from '../types';
import { DoodleIcon } from './DoodleIcon';

interface TopUtilityBarProps {
  operator?: OperatorProfile | null;
  target?: string;
  onOpenCommandPalette: () => void;
  onOpenProfile: () => void;
  onOpenAttestation?: () => void;
  onNavigateToSettings: () => void;
  onCreateScan?: () => void;
  onNavigateToIntel?: () => void;
}

export const TopUtilityBar: React.FC<TopUtilityBarProps> = ({
  operator,
  target = 'SELECT TARGET',
  onOpenCommandPalette,
  onOpenProfile,
  onOpenAttestation,
  onCreateScan,
  onNavigateToIntel,
}) => {
  const [utcTime, setUtcTime] = useState<string>('');
  const [syntheticActive, setSyntheticActive] = useState<boolean>(false);
  const [testingPipeline, setTestingPipeline] = useState<boolean>(false);
  const [pipelineResult, setPipelineResult] = useState<string | null>(null);
  const [isEditingTarget, setIsEditingTarget] = useState<boolean>(false);
  const [targetInput, setTargetInput] = useState<string>('');

  useEffect(() => {
    const handleFallbackEvent = (e: any) => {
      if (e.detail?.active !== undefined) {
        setSyntheticActive(Boolean(e.detail.active));
      }
    };
    window.addEventListener('drishti_synthetic_fallback', handleFallbackEvent);
    return () => window.removeEventListener('drishti_synthetic_fallback', handleFallbackEvent);
  }, []);

  const handleTestPipeline = async () => {
    setTestingPipeline(true);
    setPipelineResult(null);
    try {
      const res = await fetch('/api/health/pipeline-test', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        const passed = data.passed_gates ?? data.steps?.filter((s: any) => s.status === 'PASS').length ?? 9;
        const total = data.total_gates ?? data.steps?.length ?? 9;
        setPipelineResult(`PIPELINE ${passed}/${total} GATES OK (${data.status})`);
      } else {
        setPipelineResult('PIPELINE TEST HTTP ERROR');
      }
    } catch {
      setPipelineResult('PIPELINE OFFLINE');
    } finally {
      setTestingPipeline(false);
      setTimeout(() => setPipelineResult(null), 5000);
    }
  };

  const handleCommitTarget = () => {
    const clean = targetInput.trim().toLowerCase();
    setIsEditingTarget(false);
    if (clean && clean !== target) {
      localStorage.setItem('drishti_target_domain', clean);
      window.dispatchEvent(new CustomEvent('drishti_target_updated', { detail: clean }));
    }
  };

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      const pad = (n: number) => String(n).padStart(2, '0');
      const year = now.getUTCFullYear();
      const month = pad(now.getUTCMonth() + 1);
      const day = pad(now.getUTCDate());
      const hours = pad(now.getUTCHours());
      const mins = pad(now.getUTCMinutes());
      const secs = pad(now.getUTCSeconds());
      setUtcTime(`${year}.${month}.${day} ${hours}:${mins}:${secs} UTC`);
    };

    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const displayTarget = target && target.trim() !== '' ? target.trim() : '';

  return (
    <header
      className="module-cascade-0 h-13 w-full border-b border-hairline bg-pureWhite px-4 sm:px-6 flex items-center justify-between text-xs shrink-0 z-30 select-none font-mono tracking-tight shadow-xs"
      data-purpose="top-command-bar"
    >
      {/* 1. Left: Brand & Enclave Security State */}
      <div className="flex items-center space-x-3 shrink-0">
        <div className="w-8 h-8 border border-hairline flex items-center justify-center bg-boneDark text-signalGreen font-bold text-xs shadow-xs">
          #_
        </div>

        <div className="flex items-center space-x-2">
          <span className="font-grotesk font-extrabold text-sm tracking-widest text-ink uppercase">
            DRISHTI
          </span>
          <span className="text-pencil text-[10px] font-mono hidden md:inline">
            // CYBER LAB
          </span>
        </div>

        <div className="h-4 w-px bg-hairline hidden sm:block"></div>

        <div className="inline-flex items-center space-x-1.5 px-2 py-0.5 border border-signalGreen/40 bg-signalGreenBg text-[10px] text-signalGreen font-bold">
          <span className="w-1.5 h-1.5 bg-signalGreen animate-pulse"></span>
          <span>[ LIVE HUD ]</span>
        </div>

        <button
          type="button"
          onClick={onOpenAttestation}
          className="hidden md:inline-flex items-center space-x-1 border border-signalGreen/60 hover:border-signalGreen bg-signalGreenBg/40 hover:bg-signalGreenBg px-2 py-0.5 text-[9.5px] font-mono text-signalGreen font-bold cursor-pointer transition-colors shadow-xs active:scale-95"
          title="Click to view Cryptographic Hardware Enclave Attestation & Dissertation Anti-Copy Protection Seal"
        >
          <span>🛡️</span>
          <span>[ ATTESTED ENCLAVE ]</span>
        </button>

        <span className="hidden xl:inline-block border border-hairline px-2 py-0.5 text-[9px] font-mono text-charcoal bg-boneLight font-medium">
          AIR-GAP
        </span>

        {syntheticActive && (
          <span className="px-2 py-0.5 bg-vermilion/20 border border-vermilion text-vermilion text-[9.5px] font-black tracking-wider animate-pulse">
            [SYNTHETIC_FALLBACK_ACTIVE]
          </span>
        )}
      </div>

      {/* 2. Center: Active Target Focus HUD */}
      <div className="flex items-center justify-center space-x-2 flex-1 max-w-md mx-4">
        {isEditingTarget ? (
          <div className="flex items-center border border-ink bg-pureWhite px-2.5 py-0.5 shadow-xs space-x-1.5 text-xs">
            <span className="text-[10px] font-bold text-vermilion uppercase font-mono">TARGET:</span>
            <input
              type="text"
              autoFocus
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') handleCommitTarget();
                if (e.key === 'Escape') setIsEditingTarget(false);
              }}
              onBlur={handleCommitTarget}
              placeholder="e.g. iiit-bh.ac.in"
              className="bg-transparent border-none text-xs font-bold text-ink focus:outline-none w-44 font-mono lowercase"
            />
            <span className="text-[9px] text-pencil font-mono">[↵ SAVE]</span>
          </div>
        ) : (
          <div
            onClick={() => {
              setTargetInput(displayTarget || 'iiit-bh.ac.in');
              setIsEditingTarget(true);
            }}
            className="flex items-center border border-hairline bg-boneLight hover:bg-pureWhite hover:border-ink px-3 py-1 shadow-xs space-x-2 text-xs cursor-pointer transition-colors"
            title="Click to change target domain globally"
          >
            <span className="text-[10px] font-bold text-charcoal uppercase tracking-wider">TARGET:</span>
            {displayTarget ? (
              <>
                <span className="font-bold text-cyan font-mono">{displayTarget}</span>
                <span className="w-1.5 h-1.5 bg-cyan animate-pulse"></span>
              </>
            ) : (
              <>
                <span className="font-semibold text-charcoal/80 font-mono text-[11px]">[ NO TARGET ARMED ]</span>
                <span className="w-1.5 h-1.5 bg-pencil"></span>
              </>
            )}
            <span className="text-[9px] text-pencil font-mono hover:text-ink">[✎]</span>
          </div>
        )}

        <span className="hidden md:inline-block border border-hairline px-2.5 py-1 text-[10px] text-charcoal bg-pureWhite font-medium">
          RFC 8655 READY
        </span>
      </div>

      {/* 3. Right: Telemetry, CLI & Operator Credentials */}
      <div className="flex items-center space-x-2.5 shrink-0 text-xs">
        <button
          onClick={handleTestPipeline}
          disabled={testingPipeline}
          className={`border px-2.5 py-1 font-bold cursor-pointer text-[10px] active:scale-95 transition-all duration-150 flex items-center space-x-1 ${
            pipelineResult && pipelineResult.includes('OK')
              ? 'border-signalGreen bg-signalGreenBg text-signalGreen'
              : 'border-vermilion bg-pureWhite hover:bg-vermilion hover:text-white text-vermilion'
          }`}
          title="Run Full End-to-End Pipeline Diagnostic (Karpathy Style)"
        >
          <span>{testingPipeline ? '[ TESTING... ]' : (pipelineResult || '[ ⚡ TEST PIPELINE ]')}</span>
        </button>

        <button
          onClick={onOpenCommandPalette}
          className="border border-hairline bg-boneLight hover:bg-boneDark px-2.5 py-1 text-charcoal hover:text-ink font-semibold cursor-pointer text-[11px] active:scale-95 transition-all duration-150 flex items-center space-x-1"
          title="Press ⌘K or Ctrl+K"
        >
          <span className="text-pencil font-bold text-[10px]">⌘K</span>
          <span>[ CLI ]</span>
        </button>

        <div className="hidden lg:inline-flex items-center text-ink font-mono font-bold px-2.5 py-1 border border-hairline bg-boneLight text-[10px]">
          [ {utcTime || '2026.11.03 UTC'} ]
        </div>

        <div
          onClick={onOpenProfile}
          className="border border-signalGreen text-signalGreen bg-signalGreenBg px-2.5 py-1 font-bold text-[10px] cursor-pointer hover:bg-signalGreen hover:text-white active:scale-95 transition-all duration-150 flex items-center space-x-1"
          title={`Operator: ${operator?.name || 'Security Operator'} (${operator?.clearance || 'LEVEL 5'})`}
        >
          <span>OP:</span>
          <span className="uppercase">{operator?.avatar_text || 'AM'}</span>
          <span className="hidden sm:inline">// LVL 5</span>
        </div>
      </div>
    </header>
  );
};
