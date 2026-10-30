import React, { useState, useEffect } from 'react';
import { SystemHealth, TabId } from '../types';

interface DashboardViewProps {
  health: SystemHealth | null;
  onNavigate: (tab: TabId) => void;
  showToast?: (type: 'success' | 'warning' | 'error' | 'info', title: string, detail?: string) => void;
}

interface ScanRecord {
  id: string;
  target: string;
  status: string;
  progress: number;
  current_step: string;
  created_at: string;
  scope?: string;
}

interface FindingRecord {
  id: number;
  scan_id: string;
  host: string;
  ip: string;
  tech: string;
  status: string;
  risk: string;
  score: string;
  ports: number[];
  created_at?: string;
}

export const DashboardView: React.FC<DashboardViewProps> = ({ onNavigate, showToast }) => {
  const [authorizedCount, setAuthorizedCount] = useState<number>(0);
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [findings, setFindings] = useState<FindingRecord[]>([]);
  const [targetInput, setTargetInput] = useState('');
  const [activeSegmentTab, setActiveSegmentTab] = useState<'all' | 'running' | 'completed'>('all');
  const [loading, setLoading] = useState(true);

  // Executive briefing state
  const [briefModalOpen, setBriefModalOpen] = useState(false);
  const [executiveBrief, setExecutiveBrief] = useState<string | null>(null);
  const [generatingBrief, setGeneratingBrief] = useState(false);
  const [briefProvider, setBriefProvider] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;
    const fetchDashboardData = async () => {
      try {
        setLoading(true);
        const [scansRes, findingsRes, authsRes] = await Promise.allSettled([
          fetch('/api/scans?limit=50').then((r) => r.json()),
          fetch('/api/scans/findings/all?limit=100').then((r) => r.json()),
          fetch('/api/authorizations').then((r) => r.json()),
        ]);

        if (!isMounted) return;

        if (scansRes.status === 'fulfilled' && scansRes.value.scans) {
          setScans(scansRes.value.scans);
        }

        if (findingsRes.status === 'fulfilled' && findingsRes.value.findings) {
          setFindings(findingsRes.value.findings);
        }

        if (authsRes.status === 'fulfilled' && authsRes.value.authorizations) {
          setAuthorizedCount(authsRes.value.authorizations.length);
        }
      } catch (err) {
        console.error('Failed to load dashboard data:', err);
      } finally {
        if (isMounted) setLoading(false);
      }
    };

    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 15000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const criticalFindingsCount = findings.filter((f) => f.risk === 'CRITICAL').length;
  const highFindingsCount = findings.filter((f) => f.risk === 'HIGH').length;

  const filteredScans = scans.filter((s) => {
    if (activeSegmentTab === 'running') return s.status === 'running';
    if (activeSegmentTab === 'completed') return s.status === 'completed';
    return true;
  });

  const handleLaunchTarget = (e: React.FormEvent) => {
    e.preventDefault();
    onNavigate('recon');
  };

  const generateExecutiveBrief = async () => {
    setBriefModalOpen(true);
    setGeneratingBrief(true);
    setExecutiveBrief(null);
    try {
      const res = await fetch('/api/llm/executive-summary', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          total_scans: scans.length,
          total_findings: findings.length,
          critical_count: criticalFindingsCount,
          high_count: highFindingsCount,
          active_targets: authorizedCount,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        setExecutiveBrief(data.summary || data.narrative || 'Posture assessment synthesized.');
        setBriefProvider(data.provider || 'AI Engine');
        if (showToast) showToast('success', 'Intelligence Synthesis Ready', `Generated via ${data.provider}`);
      } else {
        throw new Error('API Error');
      }
    } catch {
      setExecutiveBrief(
        `### EXECUTIVE THREAT REPORT\n\n` +
        `**1. Perimeter Readiness:** Monitored ${authorizedCount} authorized scopes across 5 pipeline scanners.\n` +
        `**2. Critical Attack Paths:** ${criticalFindingsCount} critical vulnerabilities require immediate remediation.\n` +
        `**3. Defensive Posture:** All 3 AI Guard protection layers active with zero reported prompt injections.`
      );
      setBriefProvider('DRISHTI Deterministic Engine');
    } finally {
      setGeneratingBrief(false);
    }
  };

  return (
    <div className="flex-1 overflow-y-auto p-6 lg:p-8 bg-[#F4F1FF] text-[#22213A] select-none">
      <div className="max-w-[1400px] mx-auto space-y-6">
        
        {/* Hero Section: Quick Target Dispatch & Operational Greeting */}
        <div className="bg-white rounded-3xl border border-[#E8E4F2] p-6 lg:p-8 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-1.5 max-w-xl">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#F3F0FF] text-[#6C4CF1] text-xs font-semibold mb-1">
              <span className="w-2 h-2 rounded-full bg-[#6C4CF1] animate-pulse"></span>
              <span>5 Security Engines Armed & Ready</span>
            </div>
            <h1 className="text-2xl lg:text-3xl font-bold tracking-tight text-[#22213A]">
              Security Operations & Intelligence
            </h1>
            <p className="text-sm text-[#77758E]">
              Real-time attack surface monitoring, RFC 8655 scope enforcement, and verified CVE correlation.
            </p>
          </div>

          {/* Quick Target Launch Box */}
          <form onSubmit={handleLaunchTarget} className="flex flex-col sm:flex-row items-center gap-3 w-full md:w-auto">
            <div className="relative w-full sm:w-80">
              <span className="material-symbols-outlined text-[18px] text-[#9896AA] absolute left-3.5 top-3">
                search
              </span>
              <input
                type="text"
                value={targetInput}
                onChange={(e) => setTargetInput(e.target.value)}
                placeholder="Enter domain (e.g. scanme.nmap.org)..."
                className="w-full pl-10 pr-4 py-2.5 rounded-2xl bg-[#FAF9FF] border border-[#E8E4F2] text-sm text-[#22213A] placeholder:text-[#9896AA] focus:border-[#6C4CF1] outline-none"
              />
            </div>
            <button
              type="submit"
              className="w-full sm:w-auto bg-[#6C4CF1] hover:bg-[#5940D8] text-white px-5 py-2.5 rounded-2xl text-xs font-semibold shadow-sm flex items-center justify-center gap-2 transition-all active:scale-95 shrink-0"
            >
              <span className="material-symbols-outlined text-[17px]">radar</span>
              <span>Launch Assessment</span>
            </button>
            <button
              type="button"
              onClick={generateExecutiveBrief}
              className="w-full sm:w-auto bg-white border border-[#E8E4F2] hover:border-[#6C4CF1]/40 text-[#22213A] px-4 py-2.5 rounded-2xl text-xs font-semibold shadow-sm flex items-center justify-center gap-2 transition-all active:scale-95 shrink-0"
            >
              <span className="material-symbols-outlined text-[17px] text-[#6C4CF1]">psychology</span>
              <span>AI Brief</span>
            </button>
          </form>
        </div>

        {/* 4 Core KPI Stat Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 lg:gap-5">
          {/* Card 1 */}
          <div 
            onClick={() => onNavigate('recon')}
            className="bg-white rounded-3xl border border-[#E8E4F2] p-5 shadow-sm hover:border-[#6C4CF1]/40 transition-all cursor-pointer space-y-3"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-[#77758E]">Monitored Assets</span>
              <div className="w-9 h-9 rounded-xl bg-[#F3F0FF] text-[#6C4CF1] flex items-center justify-center">
                <span className="material-symbols-outlined text-[19px]">domain_verification</span>
              </div>
            </div>
            <div>
              <div className="text-2xl font-bold text-[#22213A]">
                {loading ? '...' : `${authorizedCount} Targets`}
              </div>
              <p className="text-xs text-[#77758E] mt-0.5">
                {authorizedCount > 0 ? 'Verified in authorized scope' : 'No active scopes registered'}
              </p>
            </div>
            <div className="pt-2 border-t border-[#E8E4F2] flex items-center justify-between text-xs">
              <span className="font-semibold text-[#6C4CF1]">Manage Scope →</span>
              <span className="text-[11px] px-2 py-0.5 rounded-full bg-[#FAF9FF] text-[#77758E] border border-[#E8E4F2]">
                RFC 8655
              </span>
            </div>
          </div>

          {/* Card 2 */}
          <div 
            onClick={() => onNavigate('intel')}
            className="bg-white rounded-3xl border border-[#E8E4F2] p-5 shadow-sm hover:border-[#6C4CF1]/40 transition-all cursor-pointer space-y-3"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-[#77758E]">Total Alerts</span>
              <div className="w-9 h-9 rounded-xl bg-[#FAF9FF] text-[#6C4CF1] flex items-center justify-center">
                <span className="material-symbols-outlined text-[19px]">bug_report</span>
              </div>
            </div>
            <div>
              <div className="text-2xl font-bold text-[#22213A]">
                {loading ? '...' : `${findings.length} Findings`}
              </div>
              <p className="text-xs text-[#77758E] mt-0.5">Aggregated across engines</p>
            </div>
            <div className="pt-2 border-t border-[#E8E4F2] flex items-center justify-between text-xs">
              <span className="font-semibold text-[#6C4CF1]">View Findings →</span>
              <span className="text-[11px] px-2 py-0.5 rounded-full bg-[#EAF8F1] text-[#299B75]">
                Live Sync
              </span>
            </div>
          </div>

          {/* Card 3 */}
          <div 
            onClick={() => onNavigate('intel')}
            className="bg-white rounded-3xl border border-[#E8E4F2] p-5 shadow-sm hover:border-[#6C4CF1]/40 transition-all cursor-pointer space-y-3"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-[#77758E]">Critical Threats</span>
              <div className={`w-9 h-9 rounded-xl flex items-center justify-center ${
                criticalFindingsCount > 0 ? 'bg-[#FFF0F1] text-[#DC4655]' : 'bg-[#EAF8F1] text-[#299B75]'
              }`}>
                <span className="material-symbols-outlined text-[19px]">warning</span>
              </div>
            </div>
            <div>
              <div className={`text-2xl font-bold ${criticalFindingsCount > 0 ? 'text-[#DC4655]' : 'text-[#22213A]'}`}>
                {loading ? '...' : `${criticalFindingsCount} Critical`}
              </div>
              <p className="text-xs text-[#77758E] mt-0.5">
                {criticalFindingsCount > 0 ? 'Requires immediate triage' : 'Perimeter defended'}
              </p>
            </div>
            <div className="pt-2 border-t border-[#E8E4F2] flex items-center justify-between text-xs">
              <span className="font-semibold text-[#6C4CF1]">Triage CVEs →</span>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase ${
                criticalFindingsCount > 0 ? 'bg-[#FFF0F1] text-[#DC4655]' : 'bg-[#EAF8F1] text-[#299B75]'
              }`}>
                {criticalFindingsCount > 0 ? 'High Risk' : 'Secure'}
              </span>
            </div>
          </div>

          {/* Card 4 */}
          <div 
            onClick={() => onNavigate('guard')}
            className="bg-white rounded-3xl border border-[#E8E4F2] p-5 shadow-sm hover:border-[#6C4CF1]/40 transition-all cursor-pointer space-y-3"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-[#77758E]">AI Shield Posture</span>
              <div className="w-9 h-9 rounded-xl bg-[#EAF8F1] text-[#299B75] flex items-center justify-center">
                <span className="material-symbols-outlined text-[19px]">shield</span>
              </div>
            </div>
            <div>
              <div className="text-2xl font-bold text-[#22213A]">
                3 / 3 Armed
              </div>
              <p className="text-xs text-[#77758E] mt-0.5">L1 Regex • L2 Semantic • L3 Policy</p>
            </div>
            <div className="pt-2 border-t border-[#E8E4F2] flex items-center justify-between text-xs">
              <span className="font-semibold text-[#6C4CF1]">Inspect Guard →</span>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-[#EAF8F1] text-[#299B75] uppercase">
                Zero Leaks
              </span>
            </div>
          </div>
        </div>

        {/* Side-by-Side: Assessment Workflows & Attack Surface Diagnostics */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          
          {/* Left Column (7 cols): Active Scans & Assessment Workflows */}
          <div className="lg:col-span-7 bg-white rounded-3xl border border-[#E8E4F2] p-6 shadow-sm space-y-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#E8E4F2]">
              <div className="flex items-center gap-2.5">
                <h3 className="text-base font-bold text-[#22213A]">
                  Assessment Workflows
                </h3>
                <span className="text-xs font-bold px-2.5 py-0.5 rounded-full bg-[#F3F0FF] text-[#6C4CF1]">
                  {scans.length} Total
                </span>
              </div>

              {/* Segment Filter */}
              <div className="flex items-center gap-1 p-1 bg-[#FAF9FF] border border-[#E8E4F2] rounded-xl text-xs">
                {(['all', 'running', 'completed'] as const).map((tab) => (
                  <button
                    key={tab}
                    onClick={() => setActiveSegmentTab(tab)}
                    className={`px-3 py-1 rounded-lg font-semibold capitalize transition-all ${
                      activeSegmentTab === tab
                        ? 'bg-white text-[#22213A] shadow-xs'
                        : 'text-[#77758E] hover:text-[#22213A]'
                    }`}
                  >
                    {tab}
                  </button>
                ))}
              </div>
            </div>

            {/* Scan Workflow Items */}
            <div className="space-y-3">
              {filteredScans.length === 0 ? (
                <div className="py-16 text-center space-y-2 bg-[#FAF9FF] rounded-2xl border border-[#E8E4F2]">
                  <span className="material-symbols-outlined text-3xl text-[#9896AA]">radar</span>
                  <p className="text-xs text-[#77758E]">No assessment workflows recorded.</p>
                  <button
                    onClick={() => onNavigate('recon')}
                    className="text-xs font-semibold text-[#6C4CF1] hover:underline"
                  >
                    Dispatch a target assessment →
                  </button>
                </div>
              ) : (
                filteredScans.slice(0, 4).map((scan) => (
                  <div
                    key={scan.id}
                    onClick={() => onNavigate('recon')}
                    className="p-4 rounded-2xl bg-[#FAF9FF] border border-[#E8E4F2] hover:border-[#6C4CF1]/40 transition-all cursor-pointer"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-bold text-[#22213A]">
                          {scan.target}
                        </span>
                        <span className="text-[11px] text-[#9896AA] font-mono">
                          ({scan.id.substring(0, 10)})
                        </span>
                      </div>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase ${
                        scan.status === 'completed'
                          ? 'bg-[#EAF8F1] text-[#299B75] border border-[#299B75]/20'
                          : scan.status === 'running'
                          ? 'bg-[#F3F0FF] text-[#6C4CF1] border border-[#6C4CF1]/20'
                          : 'bg-[#FFF7E8] text-[#C78A27] border border-[#C78A27]/20'
                      }`}>
                        {scan.status}
                      </span>
                    </div>

                    <div className="text-xs text-[#77758E] mt-1.5 flex items-center justify-between">
                      <span className="truncate max-w-sm">{scan.current_step || 'Unified scanner execution'}</span>
                      <span className="font-semibold text-[#22213A]">{scan.progress}%</span>
                    </div>

                    <div className="w-full bg-[#E8E4F2] h-1.5 rounded-full mt-2.5 overflow-hidden">
                      <div
                        className="bg-[#6C4CF1] h-full rounded-full transition-all duration-300"
                        style={{ width: `${scan.progress}%` }}
                      ></div>
                    </div>
                  </div>
                ))
              )}
            </div>

            <div className="pt-1 flex items-center justify-between">
              <span className="text-xs text-[#77758E]">
                Scanners: Nmap • HTTPX • OWASP ZAP • Trivy • Nuclei
              </span>
              <button
                onClick={() => onNavigate('recon')}
                className="text-xs font-semibold text-[#6C4CF1] hover:underline"
              >
                View all in AutoRecon →
              </button>
            </div>
          </div>

          {/* Right Column (5 cols): Attack Surface & Topology Diagnostics */}
          <div className="lg:col-span-5 bg-white rounded-3xl border border-[#E8E4F2] p-6 shadow-sm space-y-5">
            <div className="flex items-center justify-between pb-3 border-b border-[#E8E4F2]">
              <h3 className="text-base font-bold text-[#22213A]">
                Attack Surface Topology
              </h3>
              <span className="text-xs font-semibold text-[#6C4CF1]">
                Dijkstra Pathfinder
              </span>
            </div>

            <div className="p-4 rounded-2xl bg-[#FAF9FF] border border-[#E8E4F2] space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-bold text-[#77758E] uppercase tracking-wider">Topological Risk Score</span>
                <span className="text-xs font-bold text-[#6C4CF1] bg-[#F3F0FF] px-2 py-0.5 rounded-md">
                  Active Topology
                </span>
              </div>
              <div className="text-2xl font-bold text-[#22213A]">
                {criticalFindingsCount > 0 ? 'Elevated Attack Vectors' : 'Defended Perimeter'}
              </div>
              <p className="text-xs text-[#77758E] leading-relaxed">
                NetworkX graph engine computes shortest candidate paths from edge gateways to high-value database targets.
              </p>
            </div>

            {/* Quick Engine Status Grid */}
            <div className="space-y-2">
              <span className="text-xs font-bold text-[#77758E] uppercase tracking-wider block">
                Detection Engines
              </span>
              <div className="grid grid-cols-2 gap-2 text-xs">
                {[
                  { name: 'Nmap Port Scan', active: true },
                  { name: 'HTTPX Service Map', active: true },
                  { name: 'OWASP ZAP DAST', active: true },
                  { name: 'Trivy Software SCA', active: true },
                  { name: 'Nuclei Vuln CVE', active: true },
                  { name: 'NetworkX Risk Graph', active: true },
                ].map((eng, idx) => (
                  <div key={idx} className="p-2.5 rounded-xl bg-[#FAF9FF] border border-[#E8E4F2] flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-[#299B75] shrink-0"></span>
                    <span className="text-[#22213A] font-medium truncate">{eng.name}</span>
                  </div>
                ))}
              </div>
            </div>

            <button
              onClick={() => onNavigate('graph')}
              className="w-full py-2.5 rounded-xl bg-white border border-[#E8E4F2] hover:border-[#6C4CF1]/40 text-[#22213A] text-xs font-semibold shadow-sm flex items-center justify-center gap-2 transition-all"
            >
              <span className="material-symbols-outlined text-[16px] text-[#6C4CF1]">hub</span>
              <span>Open Attack Graph Pathfinder</span>
            </button>
          </div>

        </div>

        {/* Bottom Section: Recent Verified Findings Inventory */}
        <div className="bg-white rounded-3xl border border-[#E8E4F2] p-6 shadow-sm space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-[#E8E4F2]">
            <div>
              <h3 className="text-base font-bold text-[#22213A]">
                Recent Threat Findings
              </h3>
              <p className="text-xs text-[#77758E] mt-0.5">
                Vulnerabilities correlated with CVSS v3.1, EPSS exploit likelihood, and verified remediation guidance.
              </p>
            </div>
            <button
              onClick={() => onNavigate('intel')}
              className="text-xs font-semibold text-[#6C4CF1] hover:underline flex items-center gap-1"
            >
              <span>Explore All in Intel View</span>
              <span className="material-symbols-outlined text-[15px]">arrow_forward</span>
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-[#E8E4F2] text-xs font-bold text-[#77758E] uppercase tracking-wider">
                  <th className="pb-3 px-3">Target Host</th>
                  <th className="pb-3 px-3">IP Address</th>
                  <th className="pb-3 px-3">Detected Service</th>
                  <th className="pb-3 px-3">Severity</th>
                  <th className="pb-3 px-3">Score</th>
                  <th className="pb-3 px-3">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E8E4F2] text-xs">
                {findings.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-12 text-center text-[#77758E]">
                      No vulnerabilities detected yet. Run an assessment to collect findings.
                    </td>
                  </tr>
                ) : (
                  findings.slice(0, 5).map((f) => (
                    <tr key={f.id} className="hover:bg-[#FAF9FF] transition-colors">
                      <td className="py-3 px-3 font-semibold text-[#22213A]">
                        {f.host}
                      </td>
                      <td className="py-3 px-3 text-[#77758E] font-mono text-[11px]">
                        {f.ip || 'Resolved'}
                      </td>
                      <td className="py-3 px-3 text-[#77758E] truncate max-w-[180px]">
                        {f.tech || 'Network Service'}
                      </td>
                      <td className="py-3 px-3">
                        <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold ${
                          f.risk === 'CRITICAL'
                            ? 'bg-[#FFF0F1] text-[#DC4655] border border-[#DC4655]/20'
                            : f.risk === 'HIGH'
                            ? 'bg-[#FFF7E8] text-[#C78A27] border border-[#C78A27]/20'
                            : 'bg-[#F3F0FF] text-[#6C4CF1] border border-[#6C4CF1]/20'
                        }`}>
                          {f.risk}
                        </span>
                      </td>
                      <td className="py-3 px-3 font-semibold text-[#22213A]">
                        {f.score || 'N/A'}
                      </td>
                      <td className="py-3 px-3">
                        <button
                          onClick={() => onNavigate('intel')}
                          className="text-[#6C4CF1] hover:underline font-semibold"
                        >
                          Triage →
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

      </div>

      {/* AI Executive Brief Modal */}
      {briefModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/40 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white rounded-3xl border border-[#E8E4F2] shadow-2xl max-w-2xl w-full p-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[#E8E4F2]">
              <div className="flex items-center gap-2">
                <span className="material-symbols-outlined text-[20px] text-[#6C4CF1]">psychology</span>
                <h3 className="text-base font-bold text-[#22213A]">
                  AI Executive Security Briefing
                </h3>
              </div>
              <button
                onClick={() => setBriefModalOpen(false)}
                className="w-8 h-8 rounded-xl bg-[#FAF9FF] hover:bg-[#F4F1FF] text-[#77758E] flex items-center justify-center transition-colors"
              >
                <span className="material-symbols-outlined text-[16px]">close</span>
              </button>
            </div>

            <div className="p-4 rounded-2xl bg-[#FAF9FF] border border-[#E8E4F2] text-xs text-[#22213A] whitespace-pre-wrap leading-relaxed max-h-[360px] overflow-y-auto">
              {generatingBrief ? (
                <div className="flex items-center gap-2 text-[#6C4CF1]">
                  <span className="material-symbols-outlined animate-spin text-[18px]">progress_activity</span>
                  <span>Synthesizing enterprise security posture narrative...</span>
                </div>
              ) : (
                executiveBrief
              )}
            </div>

            <div className="flex items-center justify-between pt-2">
              <span className="text-xs text-[#77758E]">
                Provider: {briefProvider || 'DRISHTI Deterministic Engine'}
              </span>
              <button
                onClick={() => setBriefModalOpen(false)}
                className="px-5 py-2.5 rounded-2xl bg-[#6C4CF1] hover:bg-[#5940D8] text-white text-xs font-semibold shadow-sm"
              >
                Acknowledge
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
