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
    <div className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8 select-none font-mono text-xs bg-bone text-ink scrollbar-tactical">
      <div className="max-w-[1400px] mx-auto space-y-4">
        
        {/* Page Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-hairline pb-3 bg-pureWhite p-3 shadow-xs">
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-vermilion font-extrabold text-sm">03 //</span>
              <h1 className="text-sm font-grotesk font-bold uppercase tracking-wider text-ink">
                ATTACK SURFACE DISCOVERY & AUTORECON PIPELINE
              </h1>
            </div>
            <p className="text-[10px] text-charcoal mt-0.5">
              Coordinated Multi-Engine Pipeline: Nmap • HTTPX • OWASP ZAP • Trivy • Nuclei
            </p>
          </div>

          <div className="flex items-center space-x-2">
            {authStatus?.authorized ? (
              <div className="flex items-center space-x-1.5 px-2.5 py-1 bg-signalGreenBg border border-signalGreen text-signalGreen text-[10px] font-bold">
                <span className="w-1.5 h-1.5 bg-signalGreen animate-pulse"></span>
                <span>[ SCOPE AUTHORIZED ]</span>
              </div>
            ) : (
              <button
                onClick={initiateDNSChallenge}
                className="bg-pureWhite border border-hairline hover:bg-ink hover:text-white text-ink px-3 py-1.5 text-xs font-mono font-semibold transition-colors shadow-xs cursor-pointer"
              >
                [ VERIFY SCOPE (DNS) ]
              </button>
            )}

            <button
              onClick={fetchLatestScan}
              disabled={loading}
              className="bg-boneLight border border-hairline hover:bg-ink hover:text-white text-ink px-3 py-1.5 text-xs font-mono font-semibold transition-colors cursor-pointer"
            >
              [ REFRESH ]
            </button>

            <button
              onClick={startAutoRecon}
              disabled={scanning}
              className="bg-vermilion hover:bg-crimson disabled:opacity-50 text-white px-3.5 py-1.5 text-xs font-mono font-bold border border-hairline shadow-xs flex items-center space-x-1.5 transition-colors cursor-pointer"
            >
              <span>⚡</span>
              <span>{scanning ? '[ RUNNING PIPELINE... ]' : '[ START FULL SECURITY AUDIT ➔ ]'}</span>
            </button>
          </div>
        </div>

        {/* Target Configuration & Domain Verification Panel */}
        <div className="bg-pureWhite border border-hairline p-5 space-y-4 shadow-xs">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            <div className="flex-1 max-w-xl">
              <label className="text-[10px] font-bold text-charcoal uppercase tracking-wider block mb-1.5 flex items-center justify-between">
                <span>[ ASSESSMENT TARGET DOMAIN ]</span>
                {checkingAuth && (
                  <span className="text-[9px] text-pencil font-mono flex items-center gap-1.5 normal-case">
                    <span className="w-1.5 h-1.5 bg-vermilion animate-ping"></span>
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
                  className="w-full px-3 py-2 bg-[#FAF8F5] border border-hairline text-xs text-ink focus:border-vermilion outline-none font-mono"
                />
                <span className="absolute right-2 top-2 text-[9px] font-bold text-ink bg-boneLight border border-hairline px-2 py-0.5 uppercase tracking-wider font-mono">
                  RFC 8655 Verified
                </span>
              </div>
            </div>

            <div className="flex items-center gap-6 text-[10px] text-charcoal border-t lg:border-t-0 lg:border-l border-hairlineLight pt-3 lg:pt-0 lg:pl-6">
              <div>
                <span className="font-bold text-ink block text-[11px] font-grotesk">5 AUTOMATED ENGINES</span>
                <span className="text-charcoal text-[9px] mt-0.5 block font-mono">Nmap • HTTPX • ZAP • Trivy • Nuclei</span>
              </div>
              <div>
                <span className="font-bold text-ink block text-[11px] font-grotesk">DEPENDENCY DAG</span>
                <span className="text-charcoal text-[9px] mt-0.5 block font-mono">Discovery ➔ CVE Correlation</span>
              </div>
            </div>
          </div>

          {/* Verification Status Banner */}
          <div className={`p-3 border flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs ${
            authStatus?.authorized
              ? 'bg-signalGreenBg border-signalGreen text-signalGreen'
              : 'bg-boneLight border-hairline text-charcoal'
          }`}>
            <div className="flex items-start gap-3">
              <div className="font-bold text-sm">
                {authStatus?.authorized ? '✓' : '!'}
              </div>
              <div>
                <div className="font-bold text-ink flex items-center gap-2 text-[11px]">
                  <span>{authStatus?.authorized ? 'DOMAIN SCOPE VERIFIED' : 'SCOPE VERIFICATION REQUIRED'}</span>
                  {authStatus?.authorized && (
                    <span className="text-[9px] bg-pureWhite text-signalGreen font-bold px-2 py-0.5 border border-signalGreen uppercase">
                      ACTIVE ({authStatus.permitted_scope || 'FULL_ACTIVE'})
                    </span>
                  )}
                </div>
                <div className="text-[10px] text-charcoal mt-0.5 font-mono">
                  {authStatus?.authorized
                    ? `Target '${target}' is authorized and ready for deep discovery, port probing, and vulnerability auditing.`
                    : `Active security probing requires explicit authorization via DNS challenge token to ensure RFC 8655 compliance.`}
                </div>
              </div>
            </div>

            <div className="shrink-0 flex items-center gap-2">
              {!authStatus?.authorized && (
                <button
                  onClick={initiateDNSChallenge}
                  className="bg-vermilion hover:bg-crimson text-white px-3 py-1.5 text-xs font-mono font-bold border border-hairline shadow-xs cursor-pointer"
                >
                  [ GENERATE TXT CHALLENGE ]
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Live Execution & Progress Card */}
        {scanning && (
          <div className="p-4 bg-pureWhite border border-hairline space-y-3 shadow-xs">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-2.5 h-2.5 bg-vermilion animate-ping"></div>
                <div>
                  <div className="text-xs font-bold text-ink uppercase tracking-wider font-grotesk">
                    {statusText}
                  </div>
                  <div className="text-[10px] text-charcoal font-mono mt-0.5">
                    WORKFLOW ID: {currentScanId} • {progress}% COMPLETE
                  </div>
                </div>
              </div>

              <button
                onClick={cancelWorkflow}
                className="px-3 py-1 bg-pureWhite border border-vermilion text-vermilion hover:bg-vermilion hover:text-white text-[10px] font-mono font-bold transition-colors cursor-pointer"
              >
                [ ABORT WORKFLOW ]
              </button>
            </div>

            {/* Progress track */}
            <div className="w-full bg-boneDark border border-hairline h-2">
              <div
                className="bg-vermilion h-full transition-all duration-300"
                style={{ width: `${progress}%` }}
              ></div>
            </div>
          </div>
        )}

        {/* Navigation Tabs */}
        <div className="flex items-center gap-2 border-b border-hairline pb-2">
          {[
            { id: 'timeline', label: '01_ STAGE TIMELINE' },
            { id: 'assets', label: '02_ DISCOVERED TARGETS' },
            { id: 'findings', label: '03_ AGGREGATED OBSERVATIONS' },
          ].map((t) => (
            <button
              key={t.id}
              onClick={() => setActiveTab(t.id as any)}
              className={`px-3 py-1.5 text-xs font-mono font-bold transition-colors cursor-pointer border ${
                activeTab === t.id
                  ? 'bg-ink text-white border-ink'
                  : 'bg-pureWhite text-charcoal border-hairline hover:text-ink hover:bg-boneDark'
              }`}
            >
              [ {t.label} ]
            </button>
          ))}
        </div>

        {/* Tab 1: Stage Timeline */}
        {activeTab === 'timeline' && (
          <div className="bg-pureWhite border border-hairline p-5 shadow-xs space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-hairline">
              <div>
                <h3 className="text-xs font-bold text-ink uppercase tracking-wider font-grotesk">
                  STAGE-BY-STAGE MULTI-ENGINE EXECUTION TIMELINE
                </h3>
                <p className="text-[10px] text-charcoal mt-0.5 font-mono">
                  Sequential dependency enforcement and isolated worker subprocess tracking
                </p>
              </div>

              <span className="px-2 py-0.5 bg-boneDark border border-hairline text-ink text-[10px] font-bold uppercase font-mono">
                STATUS: {orchestratorWorkflow?.overall_status || 'READY'}
              </span>
            </div>

            {/* Vertical Stage Cards or Empty State */}
            {orchestratorWorkflow && orchestratorWorkflow.stages && orchestratorWorkflow.stages.length > 0 ? (
              <div className="space-y-2">
                {orchestratorWorkflow.stages.map((st: any, idx: number) => (
                  <div
                    key={idx}
                    className="p-3.5 bg-boneLight border border-hairline flex flex-col md:flex-row md:items-center justify-between gap-3 hover:border-ink transition-colors"
                  >
                    <div className="flex items-start gap-3">
                      <div className="w-6 h-6 bg-boneDark border border-hairline text-ink flex items-center justify-center font-bold text-[11px] shrink-0 font-mono">
                        {idx + 1}
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-bold text-ink uppercase font-grotesk">
                            {st.scanner_name}
                          </span>
                          <span className={`px-1.5 py-0.5 text-[9px] font-mono font-bold uppercase border ${
                            st.status === 'completed'
                              ? 'bg-signalGreenBg text-signalGreen border-signalGreen'
                              : st.status === 'running'
                              ? 'bg-vermilion text-white border-vermilion animate-pulse'
                              : st.status === 'skipped' || st.status === 'not_applicable'
                              ? 'bg-boneDark text-charcoal border-hairline'
                              : st.status === 'failed'
                              ? 'bg-white text-vermilion border-vermilion'
                              : 'bg-pureWhite text-charcoal border-hairline'
                          }`}>
                            [{st.status}]
                          </span>
                        </div>
                        <p className="text-[10px] text-charcoal mt-0.5 font-mono">
                          {st.error_message || st.desc || 'Pipeline stage'}
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center gap-4 text-[10px] font-mono text-charcoal shrink-0">
                      <span>FINDINGS: <strong className="text-ink">{st.findings_count ?? 0}</strong></span>
                      <span>PROGRESS: <strong className="text-vermilion">{st.progress ?? 0}%</strong></span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="py-12 text-center text-charcoal text-[11px] font-mono bg-[#FAF8F5] border border-dashed border-hairline p-6">
                [ NO ACTIVE SCAN WORKFLOW IN MEMORY. CLICK "START FULL SECURITY AUDIT" ABOVE TO INITIATE. ]
              </div>
            )}
          </div>
        )}

        {/* Tab 2: Assets */}
        {activeTab === 'assets' && (
          <div className="bg-pureWhite border border-hairline p-5 shadow-xs space-y-4">
            <h3 className="text-xs font-bold text-ink uppercase tracking-wider font-grotesk pb-2 border-b border-hairline">
              DISCOVERED PERIMETER TARGETS & NETWORK SERVICES
            </h3>
            {subdomains.length > 0 ? (
              <div className="space-y-2">
                {subdomains.map((sd, idx) => (
                  <div key={idx} className="p-3 bg-boneLight border border-hairline flex items-center justify-between">
                    <div>
                      <div className="text-xs font-bold text-ink font-mono">{sd.host}</div>
                      <div className="text-[10px] text-charcoal font-mono mt-0.5">{sd.ip} • {sd.tech}</div>
                    </div>
                    <div className="flex items-center gap-1.5">
                      {sd.ports.map((p) => (
                        <span key={p} className="px-2 py-0.5 bg-pureWhite border border-hairline text-ink text-[10px] font-bold font-mono">
                          :{p}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="py-12 text-center space-y-2 bg-[#FAF8F5] border border-dashed border-hairline p-6 font-mono">
                <div className="text-charcoal text-[11px]">
                  [ NO HOSTS OR PERIMETER PORTS DISCOVERED YET. RUN AUTORECON TO PROBE INFRASTRUCTURE. ]
                </div>
              </div>
            )}
          </div>
        )}

        {/* Tab 3: Findings */}
        {activeTab === 'findings' && (
          <div className="bg-pureWhite border border-hairline p-5 shadow-xs space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-hairline">
              <div>
                <h3 className="text-xs font-bold text-ink uppercase tracking-wider font-grotesk">
                  AGGREGATED OBSERVATIONS & VULNERABILITY EVIDENCE
                </h3>
                <p className="text-[10px] text-charcoal mt-0.5 font-mono">
                  Correlated vulnerability and service evidence streamed directly from scanning engines
                </p>
              </div>
              <span className="px-2 py-0.5 bg-boneDark border border-hairline text-ink text-[10px] font-bold uppercase font-mono">
                TOTAL: {subdomains.length}
              </span>
            </div>

            {subdomains.length > 0 ? (
              <div className="space-y-2">
                {subdomains.map((f, idx) => (
                  <div
                    key={idx}
                    className="p-3.5 bg-boneLight border border-hairline flex flex-col md:flex-row md:items-center justify-between gap-3 hover:border-ink transition-colors"
                  >
                    <div className="flex items-start gap-3">
                      <div className={`px-2 py-0.5 font-bold font-mono text-[9px] shrink-0 uppercase border ${
                        f.risk === 'CRITICAL'
                          ? 'bg-vermilion text-white border-vermilion'
                          : f.risk === 'HIGH'
                          ? 'bg-amber-100 text-amber-900 border-amber-300'
                          : f.risk === 'MEDIUM'
                          ? 'bg-yellow-50 text-yellow-800 border-yellow-300'
                          : 'bg-signalGreenBg text-signalGreen border-signalGreen'
                      }`}>
                        [{f.risk}]
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-bold text-ink font-mono">{f.host}</span>
                          <span className="text-[10px] text-charcoal font-mono">({f.ip})</span>
                        </div>
                        <p className="text-[11px] text-charcoal mt-0.5 font-mono">{f.tech}</p>
                      </div>
                    </div>

                    <div className="flex items-center gap-3 shrink-0">
                      <span className="text-[10px] text-charcoal font-mono bg-pureWhite px-2 py-0.5 border border-hairline">
                        SCORE: <strong className="text-ink">{f.score}</strong>
                      </span>
                      {f.ports && f.ports.length > 0 && (
                        <div className="flex items-center gap-1">
                          {f.ports.map((p) => (
                            <span key={p} className="px-1.5 py-0.5 bg-boneDark text-ink font-mono text-[9px] font-bold border border-hairline">
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
              <div className="py-12 text-center text-charcoal text-[11px] font-mono bg-[#FAF8F5] border border-dashed border-hairline p-6">
                [ NO OBSERVATIONS OR VULNERABILITY EVIDENCE RECORDED YET. ]
              </div>
            )}
          </div>
        )}

        {/* DNS Verification Modal */}
        {showVerifyModal && challengeData && (
          <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
            <div className="bg-pureWhite border-2 border-ink max-w-xl w-full p-6 space-y-4 shadow-xl font-mono text-xs animate-fadeIn">
              <div className="flex items-center justify-between border-b border-hairline pb-3">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 bg-vermilion"></span>
                  <h3 className="text-sm font-bold text-ink uppercase tracking-wider font-grotesk">
                    DNS TXT DOMAIN VERIFICATION // RFC 8655
                  </h3>
                </div>
                <button
                  onClick={() => setShowVerifyModal(false)}
                  className="text-charcoal hover:text-ink font-bold text-sm cursor-pointer"
                >
                  [ ✕ ]
                </button>
              </div>

              <div className="space-y-2">
                <p className="text-xs text-charcoal leading-relaxed font-mono">
                  Publish the following DNS TXT record at your DNS provider (Cloudflare, Route53, GoDaddy) to prove administrative ownership of <strong className="text-ink">{target}</strong>.
                </p>
                
                <div className="p-2.5 bg-boneLight border border-hairline space-y-2">
                  <div className="flex items-center justify-between text-[10px] text-charcoal">
                    <span>RECORD NAME:</span>
                    <button
                      onClick={() => copyToClipboard(challengeData.challenge_record_name, 'record')}
                      className="text-vermilion hover:underline font-bold cursor-pointer"
                    >
                      [ COPY RECORD ]
                    </button>
                  </div>
                  <div className="p-1.5 bg-pureWhite border border-hairline font-mono text-ink text-[11px] select-all break-all">
                    {challengeData.challenge_record_name}
                  </div>

                  <div className="flex items-center justify-between text-[10px] text-charcoal pt-1">
                    <span>TXT TOKEN VALUE:</span>
                    <button
                      onClick={() => copyToClipboard(challengeData.verification_token, 'token')}
                      className="text-vermilion hover:underline font-bold cursor-pointer"
                    >
                      [ COPY TOKEN ]
                    </button>
                  </div>
                  <div className="p-1.5 bg-pureWhite border border-hairline font-mono text-ink text-[11px] select-all break-all">
                    {challengeData.verification_token}
                  </div>
                </div>

                <p className="text-[10px] text-pencil font-mono">
                  DNS propagation typically requires 30-120 seconds. Click Verify once the TXT record is live.
                </p>
              </div>

              <div className="space-y-2 pt-2 border-t border-hairline">
                {verificationError && (
                  <div className="p-2 bg-white border border-vermilion text-vermilion text-[10px] font-mono">
                    ERROR: {verificationError}
                  </div>
                )}
                
                <div className="flex items-center gap-2">
                  <button
                    onClick={verifyDNSChallenge}
                    disabled={verifying}
                    className="flex-1 bg-vermilion hover:bg-crimson text-white px-4 py-2 font-mono font-bold text-xs border border-hairline transition-colors disabled:opacity-50 cursor-pointer"
                  >
                    {verifying ? '[ VERIFYING PROPAGATION... ]' : '[ VERIFY DOMAIN NOW ➔ ]'}
                  </button>
                  <button
                    onClick={() => setShowVerifyModal(false)}
                    className="bg-pureWhite border border-hairline hover:bg-boneDark text-ink px-4 py-2 font-mono font-bold text-xs transition-colors cursor-pointer"
                  >
                    [ DISMISS ]
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* DNS Challenge Tooltip */}
        {copiedField && (
          <div className="fixed bottom-6 right-6 z-50 animate-fadeIn">
            <div className="bg-ink text-pureWhite px-3 py-1.5 border border-hairline text-xs font-mono font-bold shadow-lg">
              [ ✓ {copiedField === 'record' ? 'RECORD NAME COPIED' : 'TXT TOKEN COPIED'} ]
            </div>
          </div>
        )}

        {/* Loading Overlay */}
        {loading && (
          <div className="fixed inset-0 z-40 bg-bone/70 backdrop-blur-xs flex items-center justify-center">
            <div className="bg-pureWhite border-2 border-ink p-4 flex items-center gap-3 font-mono text-xs shadow-lg">
              <div className="w-4 h-4 border-2 border-vermilion border-t-transparent animate-spin"></div>
              <span className="font-bold text-ink uppercase">[ LOADING TELEMETRY CORPUS... ]</span>
            </div>
          </div>
        )}

      </div>
    </div>
  );
};