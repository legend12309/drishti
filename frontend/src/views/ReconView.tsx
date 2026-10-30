import React, { useState, useEffect, useRef, useCallback } from 'react';
import { TabId } from '../types';

const TERMINAL_WORKFLOW_STATES = ['completed', 'partially_completed', 'failed', 'cancelled'] as const;

interface ReconViewProps {
  onNavigate?: (tab: TabId) => void;
  showToast?: (type: 'success' | 'warning' | 'error' | 'info', title: string, detail?: string) => void;
}

interface SubdomainRecord {
  host: string;
  ip: string;
  tech: string;
  status: string;
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  score: string;
  ports: number[];
}

interface AuthStatus {
  authorized: boolean;
  authorization_id?: string;
  target_domain?: string;
  permitted_scope?: string;
  expires_at?: string;
  message?: string;
}

interface ChallengeData {
  id: string;
  target_domain: string;
  permitted_scope: string;
  challenge_record_name: string;
  verification_token: string;
  status: string;
  expires_at: string;
}

export const ReconView: React.FC<ReconViewProps> = ({ onNavigate, showToast }) => {
  const [target, setTarget] = useState('curezy.in');
  const [activeTab, setActiveTab] = useState<'timeline' | 'assets' | 'findings'>('timeline');
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [statusText, setStatusText] = useState('Awaiting target assessment');
  const [currentScanId, setCurrentScanId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Phase 11 Orchestrator State
  const [orchestratorWorkflow, setOrchestratorWorkflow] = useState<any | null>(null);

  // Persist scan ID in localStorage so it survives tab switches
  const STORAGE_KEY = 'drishti_active_scan_id';

  // Results State
  const [subdomains, setSubdomains] = useState<SubdomainRecord[]>([]);

  // Authorization State
  const [authStatus, setAuthStatus] = useState<AuthStatus | null>(null);
  const [checkingAuth, setCheckingAuth] = useState(false);
  const [showVerifyModal, setShowVerifyModal] = useState(false);
  const [challengeData, setChallengeData] = useState<ChallengeData | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [verificationError, setVerificationError] = useState<string | null>(null);
  const [copiedField, setCopiedField] = useState<'record' | 'token' | null>(null);

  const eventSourceRef = useRef<EventSource | null>(null);

  const checkAuthorization = useCallback(async (domainToCheck: string, scopeToCheck: string = 'FULL_PASSIVE') => {
    if (!domainToCheck || !domainToCheck.trim()) {
      setAuthStatus(null);
      return;
    }
    setCheckingAuth(true);
    setVerificationError(null);
    try {
      const res = await fetch(`/api/authorizations/check?target=${encodeURIComponent(domainToCheck.trim())}&scope=${encodeURIComponent(scopeToCheck)}`);
      if (res.ok) {
        const data = await res.json();
        setAuthStatus(data);
      } else {
        setAuthStatus({ authorized: false });
      }
    } catch (err) {
      setAuthStatus({ authorized: false });
    } finally {
      setCheckingAuth(false);
    }
  }, []);

  useEffect(() => {
    const timer = setTimeout(() => {
      checkAuthorization(target, 'FULL_PASSIVE');
    }, 400);
    return () => clearTimeout(timer);
  }, [target, checkAuthorization]);

  const loadFindingsForScan = useCallback(async (scanId: string, targetDomain: string) => {
    try {
      const findingsRes = await fetch(`/api/scans/${scanId}/findings`);
      if (findingsRes.ok) {
        const findingsData = await findingsRes.json();
        if (findingsData.findings && findingsData.findings.length > 0) {
          const mappedAssets: SubdomainRecord[] = findingsData.findings.map((f: any) => ({
            host: f.host || targetDomain,
            ip: f.ip || 'Resolved Host',
            tech: f.tech || 'HTTP Service',
            status: f.status || 'Active',
            risk: (f.risk || 'LOW').toUpperCase(),
            score: f.score || '3.5',
            ports: f.ports || [80],
          }));
          setSubdomains(mappedAssets);
        }
      }
    } catch (e) {
      console.error('Failed to load findings for scan:', e);
    }
  }, []);

  const attachWorkflowStream = useCallback((workflowId: string, targetDomain?: string) => {
    if (eventSourceRef.current) eventSourceRef.current.close();
    const es = new EventSource(`/api/scans/orchestrator/workflows/${workflowId}/stream`);
    eventSourceRef.current = es;

    const finalizeScan = async () => {
      setScanning(false);
      es.close();
      try {
        const wfRes = await fetch(`/api/scans/orchestrator/workflows/${workflowId}`);
        if (wfRes.ok) {
          const wfData = await wfRes.json();
          if (wfData.workflow) {
            setOrchestratorWorkflow(wfData.workflow);
            if (wfData.workflow.progress !== undefined) setProgress(wfData.workflow.progress);
            if (wfData.workflow.current_step) setStatusText(wfData.workflow.current_step);
          }
        }
      } catch (err) {}
      await loadFindingsForScan(workflowId, targetDomain || target);
    };

    es.onmessage = async (event) => {
      try {
        const payload = JSON.parse(event.data);
        const eventType = payload.type;
        const data = payload.data || {};

        if (eventType === 'workflow_snapshot' || data.stages) {
          setOrchestratorWorkflow(data);
          if (data.progress !== undefined) setProgress(data.progress);
          if (data.current_step) setStatusText(data.current_step);
          if (TERMINAL_WORKFLOW_STATES.includes(data.overall_status)) {
            finalizeScan();
          }
          return;
        }

        if (eventType === 'stage_started') {
          if (data.step) setStatusText(data.step);
          setOrchestratorWorkflow((prev: any) => {
            if (!prev || !prev.stages) return prev;
            return {
              ...prev,
              current_step: data.step || prev.current_step,
              stages: prev.stages.map((st: any) =>
                st.stage_name === data.scanner || st.scanner_name === data.scanner_name
                  ? { ...st, status: 'running', progress: 50 }
                  : st
              ),
            };
          });
        } else if (eventType === 'stage_completed') {
          setOrchestratorWorkflow((prev: any) => {
            if (!prev || !prev.stages) return prev;
            return {
              ...prev,
              stages: prev.stages.map((st: any) =>
                st.stage_name === data.scanner
                  ? {
                      ...st,
                      status: 'completed',
                      progress: 100,
                      findings_count: data.findings_count ?? st.findings_count,
                      duration_seconds: data.duration_seconds ?? st.duration_seconds,
                    }
                  : st
              ),
            };
          });
          loadFindingsForScan(workflowId, targetDomain || target);
        } else if (eventType === 'stage_skipped') {
          setOrchestratorWorkflow((prev: any) => {
            if (!prev || !prev.stages) return prev;
            return {
              ...prev,
              stages: prev.stages.map((st: any) =>
                st.stage_name === data.scanner
                  ? { ...st, status: 'skipped', progress: 100, error_message: data.reason || 'Skipped' }
                  : st
              ),
            };
          });
        } else if (eventType === 'stage_failed') {
          setOrchestratorWorkflow((prev: any) => {
            if (!prev || !prev.stages) return prev;
            return {
              ...prev,
              stages: prev.stages.map((st: any) =>
                st.stage_name === data.scanner
                  ? { ...st, status: 'failed', progress: 100, error_message: data.error || 'Stage failed' }
                  : st
              ),
            };
          });
        } else if (
          eventType === 'workflow_completed' ||
          eventType === 'workflow_failed' ||
          eventType === 'workflow_cancelled' ||
          (data.overall_status && TERMINAL_WORKFLOW_STATES.includes(data.overall_status))
        ) {
          finalizeScan();
          if (showToast) {
            showToast(
              eventType === 'workflow_failed' ? 'error' : 'success',
              'AutoRecon Complete',
              `Assessment status: ${data.status || eventType}`
            );
          }
        }
      } catch (err) {
        // Ignore malformed SSE frames
      }
    };

    es.onerror = () => {
      finalizeScan();
    };
    return es;
  }, [loadFindingsForScan, target, showToast]);

  const reconnectToWorkflow = useCallback(async (workflowId: string) => {
    try {
      const res = await fetch(`/api/scans/orchestrator/workflows/${workflowId}`);
      if (!res.ok) {
        localStorage.removeItem(STORAGE_KEY);
        return;
      }
      const payload = await res.json();
      const wf = payload.workflow || payload;
      if (!wf || !wf.workflow_id) {
        localStorage.removeItem(STORAGE_KEY);
        return;
      }
      setOrchestratorWorkflow(wf);
      if (wf.progress !== undefined) setProgress(wf.progress);
      if (wf.current_step) setStatusText(wf.current_step);
      if (wf.target) {
        setTarget(wf.target);
        await loadFindingsForScan(workflowId, wf.target);
      }

      if (TERMINAL_WORKFLOW_STATES.includes(wf.overall_status)) {
        setScanning(false);
        return;
      }
      setScanning(true);
      attachWorkflowStream(workflowId, wf.target);
    } catch (err) {
      setScanning(false);
    }
  }, [attachWorkflowStream, loadFindingsForScan]);

  const fetchLatestScan = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/scans?limit=1');
      if (!res.ok) throw new Error('Failed to fetch latest scan');
      const data = await res.json();
      if (data.scans && data.scans.length > 0) {
        const latest = data.scans[0];
        setCurrentScanId(latest.id);
        localStorage.setItem(STORAGE_KEY, latest.id);
        const t = latest.target || 'scanme.nmap.org';
        setTarget(t);
        setProgress(latest.progress || 0);
        setStatusText(latest.current_step || 'Awaiting target assessment');

        if (latest.id.startsWith('wf-')) {
          const wfRes = await fetch(`/api/scans/orchestrator/workflows/${latest.id}`);
          if (wfRes.ok) {
            const wfData = await wfRes.json();
            if (wfData.workflow) {
              setOrchestratorWorkflow(wfData.workflow);
            }
          }
        }

        await loadFindingsForScan(latest.id, t);

        if (!TERMINAL_WORKFLOW_STATES.includes(latest.status)) {
          setScanning(true);
          attachWorkflowStream(latest.id, t);
        }
      }
    } catch (e) {
      console.error('Failed to load latest scan:', e);
    } finally {
      setLoading(false);
    }
  }, [attachWorkflowStream, loadFindingsForScan]);

  // Load latest scan telemetry on mount
  useEffect(() => {
    // On mount: restore active scan from localStorage and reconnect SSE
    const savedScanId = localStorage.getItem(STORAGE_KEY);
    if (savedScanId) {
      setCurrentScanId(savedScanId);
      reconnectToWorkflow(savedScanId);
    }

    const loadLatestScan = async () => {
      try {
        const res = await fetch('/api/scans?limit=1');
        if (res.ok) {
          const data = await res.json();
          if (data.scans && data.scans.length > 0) {
            const latest = data.scans[0];
            setCurrentScanId(latest.id);
            localStorage.setItem(STORAGE_KEY, latest.id);
            setTarget(latest.target || 'scanme.nmap.org');
            setProgress(latest.progress || 100);
            setStatusText(latest.current_step || 'Assessment recorded');

            // Fetch findings for this scan
            const findingsRes = await fetch(`/api/scans/${latest.id}/findings`);
            if (findingsRes.ok) {
              const findingsData = await findingsRes.json();
              if (findingsData.findings && findingsData.findings.length > 0) {
                const mappedAssets: SubdomainRecord[] = findingsData.findings.map((f: any) => ({
                  host: f.host || latest.target,
                  ip: f.ip || 'Resolved Host',
                  tech: f.tech || 'HTTP Service',
                  status: f.status || 'Active',
                  risk: (f.risk || 'LOW').toUpperCase(),
                  score: f.score || '3.5',
                  ports: f.ports || [80],
                }));
                setSubdomains(mappedAssets);
              }
            }

            // Reflect the real persisted scan record only — never synthesize stage data
            setOrchestratorWorkflow({
              workflow_id: latest.id,
              target: latest.target,
              overall_status: latest.status,
              progress: latest.progress || 100,
              current_step: latest.current_step || 'Completed',
              stages: [],
            });
          }
        }
      } catch (e) {
        console.error('Failed to load initial scan telemetry:', e);
      }
    };
    loadLatestScan();
  }, []);

  const initiateDNSChallenge = async () => {
    setVerificationError(null);
    try {
      const res = await fetch('/api/authorizations/challenges', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_domain: target.trim(),
          permitted_scope: 'FULL_PASSIVE',
        }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || 'Challenge creation failed');
      }
      const data = await res.json();
      setChallengeData(data.challenge);
      setShowVerifyModal(true);
      if (showToast) {
        showToast('info', 'DNS Challenge Generated', `Add TXT record for _drishti-challenge.${target.trim()}`);
      }
    } catch (err: any) {
      const msg = err.message || 'Could not issue authorization challenge.';
      setVerificationError(msg);
      if (showToast) showToast('error', 'Challenge Error', msg);
    }
  };

  const copyToClipboard = (text: string, field: 'record' | 'token') => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
    if (showToast) {
      showToast('success', 'Copied to Clipboard', field === 'record' ? 'Record name copied.' : 'TXT token copied.');
    }
  };

  const verifyDNSChallenge = async () => {
    if (!challengeData) return;
    setVerifying(true);
    setVerificationError(null);
    try {
      const res = await fetch('/api/authorizations/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ authorization_id: challengeData.id }),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        if (showToast) showToast('success', 'Domain Authorized', `${target} verified successfully.`);
        setShowVerifyModal(false);
        setChallengeData(null);
        await checkAuthorization(target, 'FULL_PASSIVE');
      } else {
        const errMsg = data.detail || data.message || 'DNS TXT token not found. Please allow 1-2 minutes for DNS propagation.';
        setVerificationError(errMsg);
        if (showToast) showToast('warning', 'Verification Pending', errMsg);
      }
    } catch (err: any) {
      const errMsg = err.message || 'Network or DNS resolver timeout.';
      setVerificationError(errMsg);
      if (showToast) showToast('error', 'Verification Failed', errMsg);
    } finally {
      setVerifying(false);
    }
  };

  /**
   * One-Click Entry Point: "Start AutoRecon"
   * The backend dynamically determines compatible scanners (Nmap, HTTPX, ZAP, Trivy, Nuclei)
   * according to target compatibility and authorization scope.
   */
  const startAutoRecon = async () => {
    setScanning(true);
    setProgress(10);
    setStatusText('Resolving perimeter scope & initializing scanning pipeline...');
    setActiveTab('timeline');

    const requestedScope = authStatus?.permitted_scope || 'FULL_ACTIVE';
    const requestedScanners = ['nmap', 'httpx', 'zap', 'trivy', 'nuclei'];

    try {
      const res = await fetch('/api/scans/orchestrator/workflows', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: target.trim(),
          scanners: requestedScanners,
          scope: requestedScope,
          authorization_id: authStatus?.authorization_id || undefined,
          allow_partial_completion: true,
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || 'AutoRecon launch rejected');
      }

      const data = await res.json();
      setCurrentScanId(data.workflow_id);

      if (showToast) showToast('info', 'AutoRecon Pipeline Dispatched', `Assessment ID: ${data.workflow_id}`);

      localStorage.setItem(STORAGE_KEY, data.workflow_id);
      attachWorkflowStream(data.workflow_id, target.trim());
    } catch (err: any) {
      if (showToast) showToast('error', 'Execution Error', err.message || 'AutoRecon could not be started.');
      setScanning(false);
    }
  };

  const cancelWorkflow = async () => {
    if (!currentScanId) return;
    try {
      await fetch(`/api/scans/orchestrator/workflows/${currentScanId}/cancel`, { method: 'POST' });
      if (showToast) showToast('warning', 'Cancellation Requested', 'Stopping worker subprocesses.');
      setScanning(false);
      setStatusText('Workflow cancelled by operator');
    } catch (err) {
      // Ignore cancellation errors
    }
  };

  return (
    <div className="flex-1 overflow-y-auto p-6 lg:p-8 select-none font-sans">
      <div className="max-w-[1400px] mx-auto space-y-6">
        
        {/* Page Header with Single Primary Action */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[12px] font-bold uppercase tracking-wider text-[#5A45FF] bg-indigo-50 px-2.5 py-0.5 rounded-full border border-indigo-100">
                Enterprise Recon Pipeline
              </span>
            </div>
            <h1 className="text-[26px] lg:text-[28px] font-extrabold text-slate-900 tracking-tight mt-1">
              Attack Surface Discovery & Security Auditing
            </h1>
            <p className="text-[13px] text-slate-500 mt-0.5">
              Coordinated Multi-Engine Pipeline: Nmap • HTTPX • OWASP ZAP • Trivy • Nuclei
            </p>
          </div>

          <div className="flex items-center gap-3">
            {authStatus?.authorized ? (
              <div className="flex items-center gap-2 px-3.5 py-2 rounded-2xl bg-emerald-50 border border-emerald-200/80 text-emerald-700 text-[12px] font-semibold shadow-xs">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
                <span>Scope Authorized</span>
              </div>
            ) : (
              <button
                onClick={initiateDNSChallenge}
                className="bg-white border border-slate-200 hover:border-[#5A45FF]/50 text-slate-700 px-4 py-2.5 rounded-2xl text-[13px] font-semibold shadow-xs flex items-center gap-2 transition-all hover:bg-slate-50 active:scale-95"
              >
                <span className="material-symbols-outlined text-[17px] text-[#5A45FF]">verified</span>
                <span>Verify Scope (DNS)</span>
              </button>
            )}

            <button
              onClick={fetchLatestScan}
              disabled={loading}
              className="bg-white border border-slate-200 hover:border-[#5A45FF]/50 text-slate-700 px-4 py-2.5 rounded-2xl text-[13px] font-semibold shadow-xs flex items-center gap-2 transition-all hover:bg-slate-50 active:scale-95"
            >
              <span className="material-symbols-outlined text-[17px] text-[#5A45FF]">refresh</span>
              <span>Refresh</span>
            </button>

            <button
              onClick={startAutoRecon}
              disabled={scanning}
              className="bg-gradient-to-r from-[#5A45FF] to-[#6C5CE7] hover:opacity-95 disabled:opacity-50 text-white px-6 py-2.5 rounded-2xl text-[13px] font-semibold shadow-[0_4px_16px_rgba(90,69,255,0.25)] flex items-center gap-2 transition-all active:scale-95"
            >
              <span className="material-symbols-outlined text-[18px]">radar</span>
              <span>{scanning ? 'Running Pipeline...' : 'Start Full Security Audit'}</span>
            </button>
          </div>
        </div>

        {/* Target Configuration & Domain Verification Panel */}
        <div className="bg-white rounded-3xl border border-[#E8E4F2] p-6 sm:p-7 shadow-[0_8px_24px_rgba(108,76,241,0.04)] space-y-6">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
            <div className="flex-1 max-w-xl">
              <label className="text-[12px] font-bold text-[#22213A] uppercase tracking-wider block mb-2 flex items-center justify-between">
                <span>Assessment Target Domain</span>
                {checkingAuth && (
                  <span className="text-[11px] text-[#77758E] font-mono flex items-center gap-1.5 normal-case">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#6C4CF1] animate-ping"></span>
                    Checking Authorization...
                  </span>
                )}
              </label>
              <div className="relative">
                <input
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="e.g. curezy.in or scanme.nmap.org"
                  className="w-full px-4 py-3.5 rounded-2xl bg-[#FAF9FF] border border-[#E8E4F2] text-[14px] text-[#22213A] focus:border-[#6C4CF1] focus:bg-white outline-none font-mono transition-all"
                />
                <span className="absolute right-3.5 top-3.5 text-[10px] font-bold text-[#6C4CF1] bg-[#EAE4FF] border border-[#E8E4F2] px-2.5 py-1 rounded-full uppercase tracking-wider">
                  RFC 8655 Verified
                </span>
              </div>
            </div>

            <div className="flex items-center gap-8 text-[12px] text-[#77758E] border-t lg:border-t-0 lg:border-l border-[#E8E4F2] pt-4 lg:pt-0 lg:pl-8">
              <div>
                <span className="font-bold text-[#22213A] block text-[13px]">5 Automated Engines</span>
                <span className="text-[#77758E] text-[12px] mt-0.5 block">Nmap • HTTPX • ZAP • Trivy • Nuclei</span>
              </div>
              <div>
                <span className="font-bold text-[#22213A] block text-[13px]">Dependency DAG</span>
                <span className="text-[#77758E] text-[12px] mt-0.5 block">Host Discovery → CVE Correlation</span>
              </div>
            </div>
          </div>

          {/* Verification Status Banner */}
          <div className={`p-4 rounded-2xl border flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition-all ${
            authStatus?.authorized
              ? 'bg-[#EAF8F1] border-[#299B75]/30 text-[#299B75]'
              : 'bg-[#F3F0FF] border-[#E8E4F2] text-[#77758E]'
          }`}>
            <div className="flex items-start gap-3.5">
              <div className={`w-9 h-9 rounded-2xl flex items-center justify-center shrink-0 ${
                authStatus?.authorized
                  ? 'bg-emerald-100 text-[#299B75]'
                  : 'bg-[#EAE4FF] text-[#6C4CF1]'
              }`}>
                <span className="material-symbols-outlined text-[19px]">
                  {authStatus?.authorized ? 'verified_user' : 'gpp_maybe'}
                </span>
              </div>
              <div>
                <div className="text-[14px] font-bold text-[#22213A] flex items-center gap-2">
                  <span>{authStatus?.authorized ? 'Domain Ownership Verified' : 'Domain Scope Verification'}</span>
                  {authStatus?.authorized && (
                    <span className="text-[10px] bg-emerald-100 text-[#299B75] font-bold px-2.5 py-0.5 rounded-full uppercase">
                      ACTIVE ({authStatus.permitted_scope || 'FULL_ACTIVE'})
                    </span>
                  )}
                </div>
                <div className="text-[12px] text-[#77758E] mt-0.5">
                  {authStatus?.authorized
                    ? `Target '${target}' is authorized and ready for deep discovery, port probing, and vulnerability auditing.`
                    : `Active security probing requires explicit authorization via DNS challenge token or Sandbox verification to ensure compliance.`}
                </div>
              </div>
            </div>

            <div className="shrink-0 flex items-center gap-2">
              {!authStatus?.authorized && (
                <button
                  onClick={initiateDNSChallenge}
                  className="bg-[#6C4CF1] hover:bg-[#5940D8] text-white px-4 py-2 rounded-2xl text-[12px] font-semibold shadow-xs flex items-center gap-1.5 transition-all active:scale-95"
                >
                  <span className="material-symbols-outlined text-[16px]">domain_verification</span>
                  <span>Generate TXT Challenge</span>
                </button>
              )}
            </div>
          </div>

        {/* Live Execution & Progress Card */}
        {scanning && (
          <div className="p-5 rounded-3xl bg-white border border-[#E8E4F2] space-y-3 shadow-[0_8px_24px_rgba(108,76,241,0.04)] animate-fadeIn">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <span className="material-symbols-outlined text-[22px] text-[#6C4CF1] animate-spin">
                  progress_activity
                </span>
                <div>
                  <div className="text-[14px] font-bold text-[#22213A]">
                    {statusText}
                  </div>
                  <div className="text-[12px] text-[#9896AA] font-mono">
                    Workflow {currentScanId} • {progress}% Complete
                  </div>
                </div>
              </div>

              <button
                onClick={cancelWorkflow}
                className="px-4 py-2 rounded-2xl bg-[#FFF0F1] border border-[#DC4655]/20 text-[#DC4655] text-[12px] font-semibold hover:bg-[#FFF0F1]/80 transition-all shadow-xs"
              >
                Abort Workflow
              </button>
            </div>

            {/* Progress track */}
            <div className="w-full bg-[#FAF9FF] border border-[#E8E4F2] h-2.5 rounded-full overflow-hidden">
              <div
                className="bg-gradient-to-r from-[#6C4CF1] to-[#818CF8] h-full rounded-full transition-all duration-300"
                style={{ width: `${progress}%` }}
              ></div>
            </div>
          </div>
        )}

        {/* Navigation Tabs */}
        <div className="flex items-center gap-2 border-b border-[#E8E4F2] pb-3">
          {[
            { id: 'timeline', label: 'Stage Execution Timeline' },
            { id: 'assets', label: 'Discovered Assets & Ports' },
            { id: 'findings', label: 'Aggregated Observations' },
          ].map((t) => (
            <button
              key={t.id}
              onClick={() => setActiveTab(t.id as any)}
              className={`px-4 py-2 rounded-2xl text-[13px] font-semibold transition-all ${
                activeTab === t.id
                  ? 'bg-gradient-to-r from-[#6C4CF1] to-[#5940D8] text-white shadow-[0_4px_16px_rgba(108,76,241,0.25)]'
                  : 'text-[#77758E] hover:text-[#22213A] hover:bg-[#FAF9FF]'
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* Tab 1: Stage Timeline */}
        {activeTab === 'timeline' && (
          <div className="bg-white rounded-3xl border border-[#E8E4F2] p-8 shadow-[0_8px_24px_rgba(108,76,241,0.04)] space-y-6">
            <div className="flex items-center justify-between pb-4 border-b border-[#E8E4F2]">
              <div>
                <h3 className="text-[16px] font-bold text-[#22213A] tracking-tight">
                  Stage-by-Stage Coordinated Execution
                </h3>
                <p className="text-[12px] text-[#77758E] mt-0.5">
                  Sequential dependency enforcement and isolated subprocess tracking
                </p>
              </div>

              <span className="px-3.5 py-1 rounded-full bg-[#EAE4FF] border border-[#E8E4F2] text-[#6C4CF1] text-[11px] font-bold uppercase">
                Status: {orchestratorWorkflow?.overall_status || 'Ready'}
              </span>
            </div>

            {/* Vertical Stage Cards or Empty State */}
            {orchestratorWorkflow && orchestratorWorkflow.stages && orchestratorWorkflow.stages.length > 0 ? (
              <div className="space-y-3.5">
                {orchestratorWorkflow.stages.map((st: any, idx: number) => (
                  <div
                    key={idx}
                    className="p-5 rounded-2xl bg-[#FAF9FF] border border-[#E8E4F2] flex flex-col md:flex-row md:items-center justify-between gap-4 transition-all hover:border-[#6C4CF1]/40"
                  >
                    <div className="flex items-start gap-3.5">
                      <div className="w-8 h-8 rounded-xl bg-[#EAE4FF] text-[#6C4CF1] flex items-center justify-center font-bold text-[12px] shrink-0 shadow-xs">
                        {idx + 1}
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-[14px] font-bold text-[#22213A]">
                            {st.scanner_name}
                          </span>
                          <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider ${
                            st.status === 'completed'
                              ? 'bg-[#EAF8F1] text-[#299B75] border border-[#299B75]/20'
                              : st.status === 'running'
                              ? 'bg-[#EAE4FF] text-[#6C4CF1] border border-[#6C4CF1]/20'
                              : st.status === 'skipped' || st.status === 'not_applicable'
                              ? 'bg-[#FFF9EA] text-[#B76E00] border border-[#B76E00]/30'
                              : st.status === 'failed'
                              ? 'bg-[#FFF0F1] text-[#DC4655] border border-[#DC4655]/20'
                              : st.status === 'blocked'
                              ? 'bg-[#F1F3F5] text-[#495057] border border-[#ADB5BD]/30'
                              : 'bg-[#FAF9FF] text-[#77758E] border border-[#E8E4F2]'
                          }`}>
                            {st.status}
                          </span>
                        </div>
                        <p className="text-[12px] text-[#77758E] mt-1">
                          {st.error_message || st.desc || 'Pipeline stage'}
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center gap-4 text-[12px] font-mono text-[#77758E] shrink-0">
                      <span>Findings: <strong className="text-[#22213A]">{st.findings_count ?? 0}</strong></span>
                      <span>Progress: <strong className="text-[#6C4CF1]">{st.progress ?? 0}%</strong></span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="py-12 text-center text-[#9896AA] text-[13px]">
                No active scan workflow in memory. Click "Start Full Security Audit" above to dispatch assessment telemetry.
              </div>
            )}
          </div>
        )}

        {/* Tab 2: Assets */}
        {activeTab === 'assets' && (
          <div className="bg-white rounded-3xl border border-slate-100 p-8 shadow-[0_10px_30px_rgba(0,0,0,0.04)]">
            <h3 className="text-[16px] font-bold text-slate-900 tracking-tight mb-4">
              Discovered Perimeter Targets
            </h3>
            {subdomains.length > 0 ? (
              <div className="space-y-3">
                {subdomains.map((sd, idx) => (
                  <div key={idx} className="p-4 rounded-2xl bg-slate-50 border border-slate-100 flex items-center justify-between">
                    <div>
                      <div className="text-[14px] font-bold text-slate-900">{sd.host}</div>
                      <div className="text-[12px] text-slate-500">{sd.ip} • {sd.tech}</div>
                    </div>
                    <div className="flex items-center gap-2">
                      {sd.ports.map((p) => (
                        <span key={p} className="px-2.5 py-0.5 rounded-full bg-indigo-50 border border-indigo-100 text-[#5A45FF] text-[11px] font-bold font-mono">
                          :{p}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="py-16 text-center space-y-3">
                <span className="material-symbols-outlined text-4xl text-slate-300">
                  dns
                </span>
                <p className="text-[13px] text-slate-400">
                  No hosts or perimeter ports discovered yet. Launch AutoRecon to probe target infrastructure.
                </p>
              </div>
            )}
          </div>
        )}

        {/* Tab 3: Findings */}
        {activeTab === 'findings' && (
          <div className="bg-white rounded-3xl border border-[#E8E4F2] p-8 shadow-[0_8px_24px_rgba(108,76,241,0.04)]">
            <div className="flex items-center justify-between pb-4 border-b border-[#E8E4F2] mb-6">
              <div>
                <h3 className="text-[16px] font-bold text-[#22213A] tracking-tight">
                  Aggregated Observations & Vulnerability Evidence
                </h3>
                <p className="text-[12px] text-[#77758E] mt-0.5">
                  Correlated vulnerability and service evidence streamed directly from scanning engines
                </p>
              </div>
              <span className="px-3.5 py-1 rounded-full bg-[#EAE4FF] border border-[#E8E4F2] text-[#6C4CF1] text-[11px] font-bold uppercase">
                Total Findings: {subdomains.length}
              </span>
            </div>

            {subdomains.length > 0 ? (
              <div className="space-y-3.5">
                {subdomains.map((f, idx) => (
                  <div
                    key={idx}
                    className="p-5 rounded-2xl bg-[#FAF9FF] border border-[#E8E4F2] flex flex-col md:flex-row md:items-center justify-between gap-4 transition-all hover:border-[#6C4CF1]/40"
                  >
                    <div className="flex items-start gap-3.5">
                      <div className={`px-2.5 py-1 rounded-xl font-bold text-[11px] shrink-0 uppercase tracking-wider ${
                        f.risk === 'CRITICAL'
                          ? 'bg-rose-50 text-rose-700 border border-rose-200'
                          : f.risk === 'HIGH'
                          ? 'bg-orange-50 text-orange-700 border border-orange-200'
                          : f.risk === 'MEDIUM'
                          ? 'bg-amber-50 text-amber-700 border border-amber-200'
                          : 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                      }`}>
                        {f.risk}
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-[14px] font-bold text-[#22213A]">{f.host}</span>
                          <span className="text-[12px] text-[#77758E] font-mono">({f.ip})</span>
                        </div>
                        <p className="text-[13px] text-[#55536D] mt-1 font-medium">{f.tech}</p>
                      </div>
                    </div>

                    <div className="flex items-center gap-3 shrink-0">
                      <span className="text-[12px] text-[#77758E] font-mono bg-white px-2.5 py-1 rounded-xl border border-[#E8E4F2]">
                        Score: <strong className="text-[#22213A]">{f.score}</strong>
                      </span>
                      {f.ports && f.ports.length > 0 && (
                        <div className="flex items-center gap-1.5">
                          {f.ports.map((p) => (
                            <span key={p} className="px-2 py-0.5 rounded-lg bg-[#EAE4FF] text-[#6C4CF1] font-mono text-[11px] font-bold">
                              :{p}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="py-12 text-center text-[#9896AA] text-[13px]">
                No observations or vulnerability evidence recorded yet. Launch an assessment to populate findings.
              </div>
            )}
          </div>
        )}

        {/* DNS Verification Modal */}
        {showVerifyModal && challengeData && (
          <div className="fixed inset-0 z-50 bg-slate-900/40 backdrop-blur-sm flex items-center justify-center p-4">
            <div className="bg-white rounded-3xl border border-slate-200 shadow-[0_20px_50px_rgba(0,0,0,0.1)] max-w-xl w-full p-6 space-y-5 animate-fadeIn font-sans">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                <div className="flex items-center gap-2">
                  <span className="material-symbols-outlined text-[#5A45FF] text-[20px]">verified</span>
                  <h3 className="text-[16px] font-bold text-slate-900">
                    DNS TXT Domain Verification
                  </h3>
                </div>
                <button
                  onClick={() => setShowVerifyModal(false)}
                  className="text-slate-400 hover:text-slate-700 transition-colors"
                >
                  <span className="material-symbols-outlined text-[18px]">close</span>
                </button>
              </div>

              <div className="space-y-2">
                <p className="text-[13px] text-slate-600 leading-relaxed">
                  Publish the following DNS TXT record at your DNS provider (Cloudflare, Route53, GoDaddy) to prove administrative ownership of <strong className="text-slate-900">{target}</strong>.
                </p>
                <div className="text-[11px] text-slate-400 flex items-center gap-2 font-mono">
                  <span>Record:</span>
                  <span className="bg-slate-100 px-2 py-1 rounded text-slate-900">{challengeData.challenge_record_name}</span>
                  <button
                    onClick={() => copyToClipboard(challengeData.challenge_record_name, 'record')}
                    className="text-[#5A45FF] hover:text-[#6C4CF1] text-xs underline"
                  >
                    Copy
                  </button>
                </div>
                <div className="text-[11px] text-slate-400 flex items-center gap-2 font-mono">
                  <span>Token:</span>
                  <span className="bg-slate-100 px-2 py-1 rounded text-slate-900">{challengeData.verification_token}</span>
                  <button
                    onClick={() => copyToClipboard(challengeData.verification_token, 'token')}
                    className="text-[#5A45FF] hover:text-[#6C4CF1] text-xs underline"
                  >
                    Copy
                  </button>
                </div>
                <p className="text-[11px] text-slate-500">
                  DNS propagation typically takes 30-120 seconds. Click <strong>Verify</strong> once the record is live.
                </p>
              </div>

              <div className="space-y-2">
                <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
                  <div className="text-[11px] text-slate-400 font-medium mb-1">Status</div>
                  <div className="text-[13px] font-semibold text-slate-900">
                    {verificationError ? (
                      <span className="text-rose-600">{verificationError}</span>
                    ) : (
                      <span className="text-amber-600">Awaiting DNS propagation...</span>
                    )}
                  </div>
                </div>
                <button
                  onClick={verifyDNSChallenge}
                  disabled={verifying}
                  className="w-full bg-[#6C4CF1] hover:bg-[#5940D8] text-white px-4 py-2.5 rounded-xl text-[13px] font-semibold shadow-xs flex items-center justify-center gap-2 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {verifying ? (
                    <>
                      <span className="material-symbols-outlined text-[16px] animate-spin">sync</span>
                      <span>Verifying...</span>
                    </>
                  ) : (
                    <>
                      <span className="material-symbols-outlined text-[16px]">verified</span>
                      <span>Verify Domain</span>
                    </>
                  )}
                </button>
                <button
                  onClick={() => setShowVerifyModal(false)}
                  className="w-full bg-white border border-slate-300 hover:border-slate-400 text-slate-700 px-4 py-2.5 rounded-xl text-[13px] font-semibold transition-all"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        )}

        {/* DNS Challenge Tooltip */}
        {copiedField && (
          <div className="fixed bottom-6 right-6 z-50 animate-fadeIn">
            <div className="bg-slate-900 text-white px-4 py-2 rounded-xl shadow-[0_10px_30px_rgba(0,0,0,0.2)] flex items-center gap-2">
              <span className="material-symbols-outlined text-green-400">check_circle</span>
              <span className="text-sm font-medium">{copiedField === 'record' ? 'Record name copied' : 'TXT token copied'}</span>
            </div>
          </div>
        )}

        {/* Loading Overlay */}
        {loading && (
          <div className="fixed inset-0 z-40 bg-white/80 backdrop-blur-sm flex items-center justify-center">
            <div className="flex flex-col items-center gap-3">
              <span className="material-symbols-outlined text-[40px] text-[#6C4CF1] animate-spin">progress_activity</span>
              <p className="text-[14px] text-slate-600">Loading latest scan...</p>
            </div>
          </div>
        )}
      </div>
    </div>
    </div>
  );
};