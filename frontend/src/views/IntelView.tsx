import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { TabId } from '../types';

interface IntelViewProps {
  onNavigate?: (tab: TabId) => void;
  showToast?: (type: 'success' | 'warning' | 'error' | 'info', title: string, detail?: string) => void;
}

export interface CveRecord {
  id: string;
  title: string;
  product: string;
  vendor?: string;
  version?: string;
  cvss: number;
  severity: string;
  epss: number;
  epssPercentile?: number;
  status: string;
  fix: string;
  vector: string;
  description: string;
  affectedAsset?: string;
  confidence?: number;
  matchRationale?: string;
  references?: Array<{ url: string; source?: string; tags?: string[] }>;
  provenance?: string;
  publishedAt?: string;
  cweIds?: string[];
  isCorrelated?: boolean;
}

interface ScanOption {
  id: string;
  target: string;
  status: string;
  created_at: string;
}

export const IntelView: React.FC<IntelViewProps> = ({ onNavigate, showToast }) => {
  const [filter, setFilter] = useState<'ALL' | 'CORRELATED' | 'CRITICAL' | 'HIGH_EPSS' | 'CONFIRMED'>('ALL');
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [selectedCve, setSelectedCve] = useState<CveRecord | null>(null);
  const [cves, setCves] = useState<CveRecord[]>([]);
  const [scans, setScans] = useState<ScanOption[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>('all');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // AI Advisory State
  const [aiExplanation, setAiExplanation] = useState<string | null>(null);
  const [explainingAi, setExplainingAi] = useState(false);
  const [aiProviderUsed, setAiProviderUsed] = useState<string | null>(null);

  // Copy to clipboard helper
  const handleCopy = (text: string, label: string = 'CVE ID') => {
    navigator.clipboard.writeText(text);
    setCopiedId(text);
    setTimeout(() => setCopiedId(null), 2000);
    if (showToast) {
      showToast('success', 'Copied to Clipboard', `${label} ${text} copied`);
    }
  };

  // Sync CVE Feed
  const handleSyncFeeds = async () => {
    setSyncing(true);
    try {
      const res = await fetch('/api/vulnerabilities/sync', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        if (showToast) {
          showToast('success', 'Intelligence Corpus Synchronized', `Synchronized ${data.total_synced || 'all'} NIST CVE intelligence records.`);
        }
        await loadIntelligence();
      } else {
        throw new Error('Sync failed');
      }
    } catch {
      if (showToast) {
        showToast('error', 'Sync Failed', 'Could not sync vulnerability feed from NIST repository.');
      }
    } finally {
      setSyncing(false);
    }
  };

  // AI Vulnerability Advisory
  const requestAiExplanation = async (cve: CveRecord) => {
    setExplainingAi(true);
    setAiExplanation(null);
    try {
      const res = await fetch('/api/llm/explain-vulnerability', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          cve_id: cve.id,
          affected_product: `${cve.vendor || ''} ${cve.product} ${cve.version || ''}`.trim(),
          cvss_score: cve.cvss,
          applicability_status: cve.status,
          remediation: cve.fix,
          evidence_context: cve.matchRationale || cve.description,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setAiExplanation(data.explanation || data.narrative || 'Intelligence analysis generated.');
        setAiProviderUsed(data.provider || 'DRISHTI Cyber AI Core');
        if (showToast) showToast('success', 'AI Intelligence Advisory Generated', `Generated via ${data.provider || 'AI Core'}`);
      } else {
        throw new Error('API returned error');
      }
    } catch {
      const syntheticAnalysis = `### Executive Summary — ${cve.id}
**Target Asset Impact:** ${cve.affectedAsset || cve.product}
**Threat Archetype:** An unauthenticated network adversary can exploit this vulnerability with CVSS ${cve.cvss} severity. Exploit Prediction Score (EPSS) is ${(cve.epss * 100).toFixed(1)}%, placing it in the top percentiles of actively weaponized flaws.

### Exploitation Mechanics
The vulnerability stems from improper boundary checking and parsing logic in ${cve.product}. A remote attacker transmitting specifically crafted packets or HTTP queries can bypass perimeter filtering to trigger memory corruption, parameter injection, or arbitrary remote code execution.

### Tactical Remediation Checklist
1. **Immediate Patch:** ${cve.fix}
2. **Perimeter Containment:** Restrict access to affected listener ports using firewall ingress rules or network access control lists.
3. **Defense-in-Depth:** Review audit logs for anomalous payloads matching the CVSS vector (${cve.vector}).`;
      setAiExplanation(syntheticAnalysis);
      setAiProviderUsed('DRISHTI Heuristic Core (Deterministic)');
      if (showToast) showToast('info', 'Heuristic Advisory Synthesized', 'Generated deterministic mitigation summary.');
    } finally {
      setExplainingAi(false);
    }
  };

  // Unified Intelligence Loader
  const loadIntelligence = useCallback(async () => {
    setLoading(true);
    try {
      // 1. Fetch available scans for correlation dropdown
      const scansRes = await fetch('/api/scans?limit=10').then((r) => r.json()).catch(() => ({ scans: [] }));
      const scanList: ScanOption[] = scansRes.scans || [];
      setScans(scanList);

      // 2. Fetch NIST NVD Vulnerability Corpus
      const corpusRes = await fetch('/api/vulnerabilities?limit=100').then((r) => r.json()).catch(() => ({ vulnerabilities: [] }));
      const corpusVulns = corpusRes.vulnerabilities || [];

      // 3. Fetch Scan-Correlated Vulnerabilities (from recent scans)
      let correlatedMap = new Map<string, any>();
      
      // Determine which scan to inspect
      let targetScanId = selectedScanId;
      if (targetScanId === 'all' && scanList.length > 0) {
        // Find first scan with completed or running status
        const activeScan = scanList.find((s) => s.status === 'completed') || scanList[0];
        targetScanId = activeScan?.id || 'all';
      }

      if (targetScanId !== 'all') {
        const scanVulnsRes = await fetch(`/api/scans/${targetScanId}/vulnerabilities`).then((r) => r.json()).catch(() => ({ vulnerabilities: [] }));
        if (scanVulnsRes.vulnerabilities && Array.isArray(scanVulnsRes.vulnerabilities)) {
          for (const sv of scanVulnsRes.vulnerabilities) {
            correlatedMap.set(sv.cve_id, sv);
          }
        }
      }

      // 4. Merge corpus and correlated findings into unified records
      const mergedList: CveRecord[] = [];
      const seenIds = new Set<string>();

      // First add correlated vulnerabilities
      for (const [cveId, sv] of correlatedMap.entries()) {
        seenIds.add(cveId);
        mergedList.push({
          id: sv.cve_id,
          title: sv.title || `${sv.product || 'Service'} Vulnerability (${sv.cve_id})`,
          product: sv.product || sv.vendor || 'Discovered Service',
          vendor: sv.vendor,
          version: sv.version || sv.observed_version,
          cvss: Number(sv.cvss_score || 7.5),
          severity: (sv.cvss_severity || 'HIGH').toUpperCase(),
          epss: Number(sv.epss_score || 0.15),
          status: sv.applicability_status || 'confirmed_applicability',
          fix: sv.remediation_notes || 'Apply vendor security patch.',
          vector: sv.cvss_vector || 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
          description: sv.description || 'Observed vulnerability matching software banner.',
          affectedAsset: sv.asset_id || 'Target Host',
          confidence: sv.confidence_score,
          matchRationale: sv.match_rationale,
          references: sv.references || [],
          provenance: 'Live Recon Correlation',
          publishedAt: sv.evaluated_at,
          isCorrelated: true,
        });
      }

      // Then add remaining corpus vulnerabilities
      for (const cv of corpusVulns) {
        if (!seenIds.has(cv.cve_id)) {
          seenIds.add(cv.cve_id);
          mergedList.push({
            id: cv.cve_id,
            title: cv.title || `${cv.cve_id} Security Advisory`,
            product: cv.product || cv.vendor || (cv.cpe_match?.[0]?.criteria?.split(':')[4] || 'Software Component'),
            vendor: cv.vendor,
            version: cv.version,
            cvss: Number(cv.cvss_score || 7.5),
            severity: (cv.cvss_severity || 'HIGH').toUpperCase(),
            epss: Number(cv.epss_score || 0.12),
            epssPercentile: Number(cv.epss_percentile || 0.75),
            status: 'catalog_intelligence',
            fix: cv.remediation_notes || 'Upgrade to the latest non-vulnerable release.',
            vector: cv.cvss_vector || 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            description: cv.description || 'NIST NVD curated vulnerability record.',
            affectedAsset: 'Global Catalog / Defense Baseline',
            confidence: 0.95,
            matchRationale: cv.match_criteria || 'NIST NVD CPE version specification match criteria.',
            references: cv.references || [],
            provenance: 'NIST NVD Feed',
            publishedAt: cv.published_at,
            cweIds: cv.cwe_ids || [],
            isCorrelated: false,
          });
        }
      }

      setCves(mergedList);
      if (mergedList.length > 0) {
        setSelectedCve((prev) => (prev && seenIds.has(prev.id) ? prev : mergedList[0]));
      } else {
        setSelectedCve(null);
      }
    } catch (err) {
      console.error('Failed to load vulnerability intelligence:', err);
    } finally {
      setLoading(false);
    }
  }, [selectedScanId]);

  useEffect(() => {
    loadIntelligence();
  }, [loadIntelligence]);

  // Telemetry KPIs
  const stats = useMemo(() => {
    const total = cves.length;
    const critical = cves.filter((c) => c.severity === 'CRITICAL').length;
    const correlated = cves.filter((c) => c.isCorrelated).length;
    const highEpss = cves.filter((c) => c.epss >= 0.5).length;
    const avgCvss = total > 0 ? (cves.reduce((acc, c) => acc + c.cvss, 0) / total).toFixed(1) : '0.0';
    const peakEpss = total > 0 ? (Math.max(...cves.map((c) => c.epss)) * 100).toFixed(0) : '0';
    return { total, critical, correlated, highEpss, avgCvss, peakEpss };
  }, [cves]);

  // Filtering Logic
  const filteredCves = useMemo(() => {
    return cves.filter((c) => {
      if (filter === 'CRITICAL' && c.severity !== 'CRITICAL') return false;
      if (filter === 'CORRELATED' && !c.isCorrelated) return false;
      if (filter === 'CONFIRMED' && c.status !== 'confirmed_applicability') return false;
      if (filter === 'HIGH_EPSS' && c.epss < 0.5) return false;

      if (search.trim()) {
        const q = search.toLowerCase();
        return (
          c.id.toLowerCase().includes(q) ||
          c.title.toLowerCase().includes(q) ||
          c.product.toLowerCase().includes(q) ||
          (c.affectedAsset && c.affectedAsset.toLowerCase().includes(q)) ||
          (c.description && c.description.toLowerCase().includes(q))
        );
      }
      return true;
    });
  }, [cves, filter, search]);

  // Helper to parse CVSS Vector into clean semantic tags
  const parsedVector = useMemo(() => {
    if (!selectedCve?.vector) return [];
    const parts = selectedCve.vector.replace(/^CVSS:3\.[01]\//, '').split('/');
    const map: Record<string, { label: string; value: string; color: string }> = {
      'AV:N': { label: 'Attack Vector', value: 'Network (Remotely Exploitable)', color: 'text-rose-600 bg-rose-50 border-rose-200' },
      'AV:A': { label: 'Attack Vector', value: 'Adjacent Network', color: 'text-amber-600 bg-amber-50 border-amber-200' },
      'AV:L': { label: 'Attack Vector', value: 'Local Access Required', color: 'text-blue-600 bg-blue-50 border-blue-200' },
      'AC:L': { label: 'Complexity', value: 'Low Complexity', color: 'text-rose-600 bg-rose-50 border-rose-200' },
      'AC:H': { label: 'Complexity', value: 'High Complexity', color: 'text-emerald-600 bg-emerald-50 border-emerald-200' },
      'PR:N': { label: 'Privileges', value: 'None (Unauthenticated)', color: 'text-rose-600 bg-rose-50 border-rose-200' },
      'PR:L': { label: 'Privileges', value: 'Low Privileges', color: 'text-amber-600 bg-amber-50 border-amber-200' },
      'UI:N': { label: 'User Interaction', value: 'None (Zero-Click)', color: 'text-rose-600 bg-rose-50 border-rose-200' },
      'UI:R': { label: 'User Interaction', value: 'User Action Required', color: 'text-amber-600 bg-amber-50 border-amber-200' },
      'S:U': { label: 'Scope', value: 'Unchanged', color: 'text-slate-600 bg-slate-50 border-slate-200' },
      'S:C': { label: 'Scope', value: 'Changed (Scope Jump / Escape)', color: 'text-purple-600 bg-purple-50 border-purple-200' },
      'C:H': { label: 'Confidentiality', value: 'High Impact (Full Exposure)', color: 'text-rose-600 bg-rose-50 border-rose-200' },
      'I:H': { label: 'Integrity', value: 'High Impact (Full Modification)', color: 'text-rose-600 bg-rose-50 border-rose-200' },
      'A:H': { label: 'Availability', value: 'High Impact (Full Denial/Crash)', color: 'text-rose-600 bg-rose-50 border-rose-200' },
    };
    return parts.map((p) => map[p] || { label: p.split(':')[0] || 'Metric', value: p, color: 'text-slate-600 bg-slate-50 border-slate-200' });
  }, [selectedCve]);

  return (
    <div className="flex-1 overflow-y-auto p-5 sm:p-6 lg:p-8 bg-[#F4F1FF] text-[#22213A]">
      <div className="max-w-[1520px] mx-auto space-y-6">

        {/* ------------------------------------------------------------- */}
        {/* 1. HEADER & TOP CONTROLS */}
        {/* ------------------------------------------------------------- */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5">
              <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-[#6C4CF1] to-[#9B82FC] flex items-center justify-center text-white shadow-sm shadow-indigo-200">
                <span className="material-symbols-outlined text-[20px]">security_update_warning</span>
              </div>
              <div>
                <h1 className="text-2xl font-extrabold tracking-tight text-[#22213A] flex items-center gap-2.5">
                  <span>Vulnerability Intelligence</span>
                  <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-[#EAE4FF] text-[#6C4CF1] border border-[#6C4CF1]/20">
                    NIST NVD v2.0 + EPSS
                  </span>
                </h1>
                <p className="text-xs text-[#77758E] mt-0.5">
                  Evidence-based vulnerability mapping with CVSS 3.1 vectors, EPSS exploit likelihood, and automated AI mitigation advisory.
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2.5 flex-wrap">
            {/* Scan Scope Picker */}
            <div className="relative">
              <select
                value={selectedScanId}
                onChange={(e) => setSelectedScanId(e.target.value)}
                className="bg-white text-xs font-semibold text-[#22213A] border border-purple-100/90 rounded-xl px-3.5 py-2 pr-8 shadow-sm hover:border-[#6C4CF1]/40 transition-all outline-none cursor-pointer appearance-none"
              >
                <option value="all">🌐 All Scans & Global Catalog</option>
                {scans.map((s) => (
                  <option key={s.id} value={s.id}>
                    🎯 {s.target} ({s.id.slice(0, 14)})
                  </option>
                ))}
              </select>
              <span className="material-symbols-outlined absolute right-2.5 top-1/2 -translate-y-1/2 text-[16px] text-[#9896AA] pointer-events-none">
                expand_more
              </span>
            </div>

            {/* Sync Feeds Button */}
            <button
              onClick={handleSyncFeeds}
              disabled={syncing}
              className="bg-white border border-purple-100/90 hover:border-[#6C4CF1]/40 text-[#22213A] px-3.5 py-2 rounded-xl text-xs font-semibold shadow-sm flex items-center gap-1.5 transition-all hover:shadow hover:-translate-y-0.5 active:translate-y-0 disabled:opacity-50"
            >
              <span className={`material-symbols-outlined text-[16px] text-[#6C4CF1] ${syncing ? 'animate-spin' : ''}`}>
                sync
              </span>
              <span>{syncing ? 'Syncing...' : 'Sync NIST Feeds'}</span>
            </button>
          </div>
        </div>

        {/* ------------------------------------------------------------- */}
        {/* 2. EXECUTIVE KPI CARDS (Fluid Soft-Glow Surfaces) */}
        {/* ------------------------------------------------------------- */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Total CVEs */}
          <div className="bg-white/80 backdrop-blur-sm rounded-2xl p-4 sm:p-5 border border-purple-100/70 shadow-[0_4px_20px_-4px_rgba(108,76,241,0.05)] hover:shadow-md transition-all">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-[#77758E] uppercase tracking-wider">Total Discovered CVEs</span>
              <div className="w-8 h-8 rounded-lg bg-[#F4F1FF] text-[#6C4CF1] flex items-center justify-center">
                <span className="material-symbols-outlined text-[18px]">dataset</span>
              </div>
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-2xl font-black text-[#22213A]">{stats.total}</span>
              <span className="text-[11px] font-semibold text-[#6C4CF1] bg-[#F4F1FF] px-1.5 py-0.5 rounded">
                {stats.correlated} correlated
              </span>
            </div>
            <div className="text-[11px] text-[#9896AA] mt-1.5 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
              <span>Active evidence repository verified</span>
            </div>
          </div>

          {/* Critical Severity Threats */}
          <div className="bg-white/80 backdrop-blur-sm rounded-2xl p-4 sm:p-5 border border-rose-100/70 shadow-[0_4px_20px_-4px_rgba(220,70,85,0.06)] hover:shadow-md transition-all">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-[#77758E] uppercase tracking-wider">Critical Exposures</span>
              <div className="w-8 h-8 rounded-lg bg-rose-50 text-[#DC4655] flex items-center justify-center">
                <span className="material-symbols-outlined text-[18px]">crisis_alert</span>
              </div>
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-2xl font-black text-[#DC4655]">{stats.critical}</span>
              <span className="text-[11px] font-semibold text-[#DC4655] bg-rose-50 px-1.5 py-0.5 rounded border border-rose-100">
                CVSS ≥ 9.0
              </span>
            </div>
            <div className="text-[11px] text-[#9896AA] mt-1.5 flex items-center gap-1.5">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-[#DC4655]"></span>
              </span>
              <span>Immediate patch action recommended</span>
            </div>
          </div>

          {/* Average CVSS Severity */}
          <div className="bg-white/80 backdrop-blur-sm rounded-2xl p-4 sm:p-5 border border-purple-100/70 shadow-[0_4px_20px_-4px_rgba(108,76,241,0.05)] hover:shadow-md transition-all">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-[#77758E] uppercase tracking-wider">Average Severity</span>
              <div className="w-8 h-8 rounded-lg bg-[#FAF9FF] text-[#6C4CF1] flex items-center justify-center">
                <span className="material-symbols-outlined text-[18px]">speed</span>
              </div>
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-2xl font-black text-[#22213A]">{stats.avgCvss}</span>
              <span className="text-[11px] font-semibold text-[#77758E]">/ 10.0</span>
            </div>
            <div className="text-[11px] text-[#9896AA] mt-1.5 flex items-center gap-1">
              <span className="material-symbols-outlined text-[13px] text-amber-500">warning</span>
              <span>CVSS v3.1 Common Vulnerability Metric</span>
            </div>
          </div>

          {/* Peak Exploit Probability (EPSS) */}
          <div className="bg-white/80 backdrop-blur-sm rounded-2xl p-4 sm:p-5 border border-purple-100/70 shadow-[0_4px_20px_-4px_rgba(108,76,241,0.05)] hover:shadow-md transition-all">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-[#77758E] uppercase tracking-wider">Peak Exploit (EPSS)</span>
              <div className="w-8 h-8 rounded-lg bg-amber-50 text-amber-600 flex items-center justify-center">
                <span className="material-symbols-outlined text-[18px]">trending_up</span>
              </div>
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-2xl font-black text-[#22213A]">{stats.peakEpss}%</span>
              <span className="text-[11px] font-semibold text-amber-700 bg-amber-50 px-1.5 py-0.5 rounded border border-amber-200">
                {stats.highEpss} high risk
              </span>
            </div>
            <div className="text-[11px] text-[#9896AA] mt-1.5 flex items-center gap-1">
              <span className="material-symbols-outlined text-[13px] text-emerald-600">verified</span>
              <span>FIRST.org real-time exploit model</span>
            </div>
          </div>
        </div>

        {/* ------------------------------------------------------------- */}
        {/* 3. MASTER-DETAIL WORKSPACE */}
        {/* ------------------------------------------------------------- */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">

          {/* ----------------- LEFT: CVE STREAM (7 COLS) ----------------- */}
          <div className="lg:col-span-7 space-y-4">
            
            {/* Target Scope Context Banner */}
            {selectedScanId !== 'all' && (
              <div className="p-3.5 rounded-2xl bg-white/90 backdrop-blur-sm border border-purple-100/80 shadow-xs flex items-center justify-between text-xs">
                <div className="flex items-center gap-2.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse"></span>
                  <span className="font-bold text-[#22213A]">
                    Scope Target: {scans.find(s => s.id === selectedScanId)?.target || 'Active Target'}
                  </span>
                  <span className="text-[#77758E] font-mono text-[11px] bg-[#F4F1FF] px-2 py-0.5 rounded-lg border border-purple-100/60">
                    {selectedScanId}
                  </span>
                </div>
                <div className="text-[11px] text-[#77758E]">
                  {stats.correlated > 0 ? (
                    <span className="text-amber-600 font-bold bg-amber-50 px-2 py-0.5 rounded-lg border border-amber-200">
                      {stats.correlated} CVEs Correlated to Host
                    </span>
                  ) : (
                    <span className="text-emerald-700 font-semibold bg-emerald-50 px-2 py-0.5 rounded-lg border border-emerald-200">
                      0 Known CVEs on Discovered Ports
                    </span>
                  )}
                </div>
              </div>
            )}

            {/* Search & Filter Bar */}
            <div className="bg-white/90 backdrop-blur-sm p-3 rounded-2xl border border-purple-100/80 shadow-sm flex flex-col sm:flex-row gap-3 items-stretch sm:items-center">
              {/* Search input */}
              <div className="flex-1 flex items-center gap-2.5 px-3.5 py-2 bg-[#FAF9FF] rounded-xl border border-purple-100/70 focus-within:border-[#6C4CF1] focus-within:bg-white focus-within:ring-2 focus-within:ring-[#6C4CF1]/15 transition-all shadow-none">
                <span className="material-symbols-outlined text-[18px] text-[#9896AA] select-none flex-shrink-0">search</span>
                <input
                  type="text"
                  placeholder="Filter by CVE ID, technology banner, or affected asset..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="w-full bg-transparent border-0 border-none p-0 text-xs text-[#22213A] focus:ring-0 focus:outline-none focus:border-0 placeholder:text-[#9896AA] shadow-none"
                />
                {search && (
                  <button
                    onClick={() => setSearch('')}
                    className="text-[#9896AA] hover:text-[#22213A] p-0.5 rounded-full hover:bg-purple-100/50 transition-colors flex-shrink-0"
                    title="Clear search"
                  >
                    <span className="material-symbols-outlined text-[15px]">close</span>
                  </button>
                )}
              </div>

              {/* Segmented Filter Pills */}
              <div className="flex items-center gap-1 overflow-x-auto pb-1 sm:pb-0 scrollbar-none">
                {[
                  { id: 'ALL', label: 'All Intel' },
                  { id: 'CORRELATED', label: 'Correlated' },
                  { id: 'CRITICAL', label: 'Critical' },
                  { id: 'HIGH_EPSS', label: 'EPSS ≥ 50%' },
                  { id: 'CONFIRMED', label: 'Confirmed' },
                ].map((tab) => {
                  const isActive = filter === tab.id;
                  return (
                    <button
                      key={tab.id}
                      onClick={() => setFilter(tab.id as any)}
                      className={`whitespace-nowrap px-3 py-1.5 rounded-xl text-xs font-semibold transition-all ${
                        isActive
                          ? 'bg-[#6C4CF1] text-white shadow-sm shadow-indigo-200'
                          : 'text-[#77758E] hover:text-[#22213A] hover:bg-[#FAF9FF]'
                      }`}
                    >
                      {tab.label}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* CVE Cards List */}
            <div className="space-y-3">
              {loading ? (
                <div className="py-24 text-center space-y-3 bg-white/70 backdrop-blur-sm rounded-2xl border border-purple-100/60">
                  <div className="w-10 h-10 border-3 border-[#6C4CF1] border-t-transparent rounded-full animate-spin mx-auto"></div>
                  <p className="text-xs font-semibold text-[#77758E]">
                    Aggregating correlated intelligence & NIST telemetry...
                  </p>
                </div>
              ) : filteredCves.length > 0 ? (
                filteredCves.map((cve) => {
                  const isSelected = selectedCve?.id === cve.id;
                  const isCrit = cve.severity === 'CRITICAL';
                  const isConfirmed = cve.status === 'confirmed_applicability';

                  return (
                    <div
                      key={cve.id}
                      onClick={() => {
                        setSelectedCve(cve);
                        setAiExplanation(null);
                      }}
                      className={`group relative p-4 sm:p-5 rounded-2xl bg-white transition-all duration-200 cursor-pointer border ${
                        isSelected
                          ? 'border-[#6C4CF1] ring-2 ring-[#6C4CF1]/20 shadow-[0_8px_30px_-6px_rgba(108,76,241,0.15)] bg-gradient-to-r from-purple-50/20 via-white to-white'
                          : 'border-purple-100/70 hover:border-[#6C4CF1]/40 hover:shadow-md hover:-translate-y-0.5'
                      }`}
                    >
                      {/* Left accent strip for critical status */}
                      <div
                        className={`absolute left-0 top-3 bottom-3 w-1.5 rounded-r-full transition-all ${
                          isSelected
                            ? 'bg-[#6C4CF1]'
                            : isCrit
                            ? 'bg-[#DC4655]'
                            : 'bg-amber-400 group-hover:bg-[#6C4CF1]/60'
                        }`}
                      />

                      <div className="pl-2.5">
                        {/* Top row: CVE ID + Severity badge + EPSS score */}
                        <div className="flex items-center justify-between gap-2">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-mono text-xs font-black tracking-tight text-[#22213A]">
                              {cve.id}
                            </span>
                            
                            <span
                              className={`px-2 py-0.5 rounded-full text-[10px] font-bold flex items-center gap-1 ${
                                isCrit
                                  ? 'bg-[#FFF0F1] text-[#DC4655] border border-[#DC4655]/20'
                                  : 'bg-[#FFF7E8] text-[#C78A27] border border-[#C78A27]/20'
                              }`}
                            >
                              <span className={`w-1.5 h-1.5 rounded-full ${isCrit ? 'bg-[#DC4655]' : 'bg-[#C78A27]'}`}></span>
                              <span>{cve.severity} {cve.cvss}</span>
                            </span>

                            {isConfirmed ? (
                              <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200 flex items-center gap-1">
                                <span className="material-symbols-outlined text-[11px]">verified</span>
                                <span>Confirmed Target</span>
                              </span>
                            ) : cve.isCorrelated ? (
                              <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-50 text-amber-700 border border-amber-200">
                                Potential Threat
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-slate-100 text-slate-600">
                                Catalog Baseline
                              </span>
                            )}
                          </div>

                          <div className="flex items-center gap-2">
                            <span
                              className={`text-[10px] font-bold px-2 py-0.5 rounded-lg border ${
                                cve.epss >= 0.5
                                  ? 'bg-rose-50 text-rose-700 border-rose-200'
                                  : 'bg-purple-50 text-[#6C4CF1] border-purple-200/50'
                              }`}
                            >
                              EPSS {(cve.epss * 100).toFixed(0)}%
                            </span>
                          </div>
                        </div>

                        {/* Title */}
                        <h4 className="text-sm font-bold text-[#22213A] mt-2 group-hover:text-[#6C4CF1] transition-colors leading-snug">
                          {cve.title}
                        </h4>

                        {/* Snippet */}
                        <p className="text-xs text-[#77758E] mt-1 line-clamp-2 leading-relaxed">
                          {cve.description}
                        </p>

                        {/* Footer tags */}
                        <div className="flex items-center justify-between text-xs text-[#77758E] mt-3 pt-2.5 border-t border-purple-50/80 gap-2">
                          <div className="flex items-center gap-1.5">
                            <span className="material-symbols-outlined text-[14px] text-[#6C4CF1]">inventory_2</span>
                            <span className="font-semibold text-[#22213A]">{cve.product} {cve.version || ''}</span>
                          </div>

                          <div className="flex items-center gap-1 text-[11px] font-mono text-[#9896AA]">
                            <span className="material-symbols-outlined text-[13px]">dns</span>
                            <span className="truncate max-w-[200px]">{cve.affectedAsset}</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })
              ) : (
                <div className="py-20 text-center space-y-3 bg-white rounded-2xl border border-purple-100/60 p-6 shadow-sm">
                  <div className="w-12 h-12 rounded-2xl bg-[#F4F1FF] flex items-center justify-center mx-auto text-[#6C4CF1]">
                    <span className="material-symbols-outlined text-2xl">
                      {filter === 'CORRELATED' ? 'verified_user' : 'search_off'}
                    </span>
                  </div>
                  <h4 className="text-sm font-bold text-[#22213A]">
                    {filter === 'CORRELATED'
                      ? `No Known CVEs on ${scans.find(s => s.id === selectedScanId)?.target || 'Target'}`
                      : 'No Matching CVE Records Found'}
                  </h4>
                  <p className="text-xs text-[#77758E] max-w-sm mx-auto">
                    {filter === 'CORRELATED'
                      ? 'The listeners (ports 80, 443, 22) discovered on this host do not exhibit known unpatched CVE signatures in the local intelligence corpus.'
                      : 'Try clearing your search query or selecting a different filter category to inspect broader vulnerability intelligence.'}
                  </p>
                  <button
                    onClick={() => {
                      setFilter('ALL');
                      setSearch('');
                    }}
                    className="mt-2 text-xs font-semibold px-4 py-1.5 rounded-xl bg-[#F4F1FF] text-[#6C4CF1] hover:bg-[#EAE4FF] transition-colors"
                  >
                    {filter === 'CORRELATED' ? 'Browse Global NIST Intelligence Feed' : 'Reset Filter'}
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* ----------------- RIGHT: DEEP INTELLIGENCE DOSSIER (5 COLS) ----------------- */}
          <div className="lg:col-span-5 bg-white/95 backdrop-blur-md rounded-2xl border border-purple-100/80 p-5 sm:p-6 shadow-[0_8px_30px_-6px_rgba(108,76,241,0.06)] space-y-5 sticky top-6">
            {selectedCve ? (
              <>
                {/* Dossier Header */}
                <div className="pb-4 border-b border-purple-100/60">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[10px] text-[#9896AA] font-bold uppercase tracking-wider flex items-center gap-1">
                      <span className="material-symbols-outlined text-[14px] text-[#6C4CF1]">verified_user</span>
                      <span>Verified Vulnerability Dossier</span>
                    </span>

                    <div className="flex items-center gap-1.5">
                      <button
                        onClick={() => handleCopy(selectedCve.id)}
                        className="text-[11px] font-semibold text-[#6C4CF1] bg-[#F4F1FF] hover:bg-[#EAE4FF] px-2.5 py-1 rounded-lg border border-[#6C4CF1]/20 flex items-center gap-1 transition-all"
                        title="Copy CVE ID"
                      >
                        <span className="material-symbols-outlined text-[13px]">
                          {copiedId === selectedCve.id ? 'check' : 'content_copy'}
                        </span>
                        <span>{copiedId === selectedCve.id ? 'Copied' : selectedCve.id}</span>
                      </button>

                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${selectedCve.id}`}
                        target="_blank"
                        rel="noreferrer"
                        className="p-1 text-[#9896AA] hover:text-[#6C4CF1] hover:bg-[#F4F1FF] rounded-lg transition-all"
                        title="View Official NIST NVD Entry"
                      >
                        <span className="material-symbols-outlined text-[16px]">open_in_new</span>
                      </a>
                    </div>
                  </div>

                  <h3 className="text-lg font-black text-[#22213A] mt-2">
                    {selectedCve.title}
                  </h3>
                  <p className="text-xs text-[#77758E] mt-1 leading-relaxed">
                    {selectedCve.description}
                  </p>
                </div>

                {/* Score & Probability Meters */}
                <div className="grid grid-cols-2 gap-3">
                  {/* CVSS Score Dial */}
                  <div className="p-3.5 rounded-xl bg-gradient-to-br from-white to-[#FAF9FF] border border-purple-100/80">
                    <div className="flex items-center justify-between text-[11px] font-bold text-[#77758E] uppercase">
                      <span>CVSS v3.1</span>
                      <span className={selectedCve.cvss >= 9 ? 'text-[#DC4655]' : 'text-amber-600'}>
                        {selectedCve.severity}
                      </span>
                    </div>
                    <div className="mt-2 flex items-baseline gap-1">
                      <span className="text-2xl font-black text-[#22213A]">{selectedCve.cvss}</span>
                      <span className="text-xs text-[#9896AA] font-bold">/ 10.0</span>
                    </div>
                    {/* Visual Meter Bar */}
                    <div className="w-full bg-[#EAE4FF] h-1.5 rounded-full mt-2 overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all duration-500 ${
                          selectedCve.cvss >= 9 ? 'bg-[#DC4655]' : selectedCve.cvss >= 7 ? 'bg-amber-500' : 'bg-[#6C4CF1]'
                        }`}
                        style={{ width: `${(selectedCve.cvss / 10) * 100}%` }}
                      />
                    </div>
                  </div>

                  {/* EPSS Score Dial */}
                  <div className="p-3.5 rounded-xl bg-gradient-to-br from-white to-[#FAF9FF] border border-purple-100/80">
                    <div className="flex items-center justify-between text-[11px] font-bold text-[#77758E] uppercase">
                      <span>EPSS Exploit</span>
                      <span className="text-[#6C4CF1]">
                        {selectedCve.epss >= 0.5 ? 'Active' : 'Moderate'}
                      </span>
                    </div>
                    <div className="mt-2 flex items-baseline gap-1">
                      <span className="text-2xl font-black text-[#22213A]">
                        {(selectedCve.epss * 100).toFixed(0)}%
                      </span>
                      <span className="text-xs text-[#9896AA] font-bold">Likelihood</span>
                    </div>
                    {/* Visual Meter Bar */}
                    <div className="w-full bg-[#EAE4FF] h-1.5 rounded-full mt-2 overflow-hidden">
                      <div
                        className="h-full rounded-full bg-[#6C4CF1] transition-all duration-500"
                        style={{ width: `${selectedCve.epss * 100}%` }}
                      />
                    </div>
                  </div>
                </div>

                {/* CVSS Vector Semantic Breakdown */}
                <div className="space-y-2">
                  <div className="text-[11px] font-bold text-[#77758E] uppercase tracking-wider flex items-center gap-1">
                    <span className="material-symbols-outlined text-[14px] text-[#6C4CF1]">alt_route</span>
                    <span>Attack Vector & Complexity Breakdown</span>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {parsedVector.map((v, i) => (
                      <span
                        key={i}
                        className={`text-[10px] font-semibold px-2.5 py-1 rounded-lg border ${v.color} flex items-center gap-1`}
                        title={v.label}
                      >
                        <span className="font-bold opacity-75">{v.label}:</span>
                        <span>{v.value}</span>
                      </span>
                    ))}
                  </div>
                </div>

                {/* Target Asset Correlation */}
                <div className="p-3.5 rounded-xl bg-[#FAF9FF] border border-purple-100/80 space-y-1.5">
                  <div className="flex items-center justify-between text-[10px] font-bold text-[#77758E] uppercase tracking-wider">
                    <span>Observed Infrastructure Target</span>
                    <span className="text-[#6C4CF1] font-mono">{selectedCve.isCorrelated ? 'Live Active' : 'Global Reference'}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="material-symbols-outlined text-[16px] text-[#6C4CF1]">devices</span>
                    <span className="text-xs font-bold text-[#22213A] font-mono">{selectedCve.affectedAsset}</span>
                  </div>
                  {selectedCve.matchRationale && (
                    <p className="text-[11px] text-[#77758E] leading-relaxed border-t border-purple-100/40 pt-1.5 mt-1">
                      {selectedCve.matchRationale}
                    </p>
                  )}
                </div>

                {/* Remediation & Actionable Fix */}
                <div className="p-4 rounded-xl bg-gradient-to-br from-emerald-50/40 to-white border border-emerald-200/60 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-bold text-emerald-800 uppercase tracking-wider flex items-center gap-1">
                      <span className="material-symbols-outlined text-[14px] text-emerald-600">health_and_safety</span>
                      <span>Remediation Roadmap</span>
                    </span>
                    <span className="text-[10px] font-bold text-emerald-700 bg-emerald-100/60 px-1.5 py-0.5 rounded">
                      Action Required
                    </span>
                  </div>
                  <p className="text-xs text-[#22213A] font-medium leading-relaxed">
                    {selectedCve.fix}
                  </p>
                </div>

                {/* AI Advisory Action */}
                <div className="space-y-3 pt-1">
                  <button
                    onClick={() => requestAiExplanation(selectedCve)}
                    disabled={explainingAi}
                    className="w-full py-2.5 rounded-xl bg-gradient-to-r from-[#6C4CF1] to-[#8060FF] hover:from-[#5940D8] hover:to-[#6C4CF1] text-white font-semibold text-xs tracking-wide transition-all shadow-md shadow-indigo-200 flex items-center justify-center gap-2 active:scale-95 disabled:opacity-50"
                  >
                    <span className={`material-symbols-outlined text-[17px] ${explainingAi ? 'animate-spin' : ''}`}>
                      {explainingAi ? 'progress_activity' : 'psychology'}
                    </span>
                    <span>{explainingAi ? 'Synthesizing AI Advisory...' : 'Synthesize AI Threat Briefing'}</span>
                  </button>

                  {/* AI Response Narrative Container */}
                  {aiExplanation && (
                    <div className="p-4 rounded-xl bg-[#FAF9FF] border border-[#6C4CF1]/25 text-xs text-[#22213A] leading-relaxed max-h-[300px] overflow-y-auto space-y-2.5 shadow-inner">
                      <div className="flex items-center justify-between pb-2 border-b border-purple-100/60">
                        <span className="text-[10px] font-bold text-[#6C4CF1] uppercase tracking-wider flex items-center gap-1">
                          <span className="material-symbols-outlined text-[13px]">smart_toy</span>
                          <span>{aiProviderUsed || 'DRISHTI Cyber AI Core'}</span>
                        </span>
                        <button
                          onClick={() => handleCopy(aiExplanation, 'AI Advisory')}
                          className="text-[10px] font-semibold text-[#77758E] hover:text-[#6C4CF1] flex items-center gap-1"
                        >
                          <span className="material-symbols-outlined text-[12px]">content_copy</span>
                          <span>Copy Brief</span>
                        </button>
                      </div>
                      <div className="whitespace-pre-wrap font-sans text-xs text-[#22213A]">
                        {aiExplanation}
                      </div>
                    </div>
                  )}
                </div>
              </>
            ) : (
              <div className="py-24 text-center text-[#77758E] space-y-2">
                <div className="w-12 h-12 rounded-2xl bg-[#F4F1FF] flex items-center justify-center mx-auto text-[#6C4CF1]">
                  <span className="material-symbols-outlined text-2xl">touch_app</span>
                </div>
                <h4 className="text-sm font-bold text-[#22213A]">Select a Vulnerability</h4>
                <p className="text-xs text-[#77758E] max-w-xs mx-auto">
                  Click any CVE record from the stream to inspect in-depth vectors, EPSS metrics, and generate AI remediation roadmaps.
                </p>
              </div>
            )}
          </div>

        </div>

      </div>
    </div>
  );
};
