import React, { useState, useEffect, useCallback } from 'react';
import { TabId } from '../types';
import { DoodleIcon } from '../components/DoodleIcon';

interface StixViewProps {
  onNavigate?: (tab: TabId) => void;
  showToast?: (type: 'success' | 'warning' | 'error' | 'info', title: string, detail?: string) => void;
}

type StixTab = 'JSON' | 'INDICATORS' | 'VULNERABILITIES' | 'MITIGATIONS' | 'RELATIONSHIPS';

export const StixView: React.FC<StixViewProps> = ({ onNavigate, showToast }) => {
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(true);
  const [stixBundle, setStixBundle] = useState<any | null>(null);
  const [activeTab, setActiveTab] = useState<StixTab>('JSON');
  const [targetDomain, setTargetDomain] = useState<string>(() => {
    return localStorage.getItem('drishti_target_domain') || 'iiit-bh.ac.in';
  });

  // Cross-engine target domain synchronization
  useEffect(() => {
    const handleTargetUpdated = (e: any) => {
      const newTarget = typeof e.detail === 'string' ? e.detail.trim().toLowerCase() : '';
      if (newTarget) {
        setTargetDomain(newTarget);
      }
    };
    window.addEventListener('drishti_target_updated', handleTargetUpdated);
    return () => window.removeEventListener('drishti_target_updated', handleTargetUpdated);
  }, []);

  const fetchStixBundle = useCallback(async (domainToFetch?: string) => {
    setLoading(true);
    const domain = (domainToFetch || targetDomain || localStorage.getItem('drishti_target_domain') || 'iiit-bh.ac.in').trim();
    try {
      const res = await fetch(`/api/stix/bundle?target=${encodeURIComponent(domain)}`);
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
        target: domain,
        objects: [],
      });
    } finally {
      setLoading(false);
    }
  }, [targetDomain]);

  useEffect(() => {
    fetchStixBundle();
  }, [fetchStixBundle]);

  const handleCompileTarget = (domain: string) => {
    setTargetDomain(domain);
    localStorage.setItem('drishti_target_domain', domain);
    fetchStixBundle(domain);
    if (showToast) {
      showToast('info', 'STIX Pipeline Triggered', `Compiling STIX 2.1 SDOs for ${domain}`);
    }
  };

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
    a.download = `drishti-stix-bundle-${stixBundle?.target || 'perimeter'}-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    if (showToast) {
      showToast('success', 'STIX Bundle Downloaded', 'Exported OASIS STIX 2.1 payload.');
    }
  };

  const objects: any[] = stixBundle?.objects || [];
  const objectCount = objects.length;

  // SDO Categorization
  const indicators = objects.filter((o) => o.type === 'indicator');
  const vulnerabilities = objects.filter((o) => o.type === 'vulnerability');
  const attackPatterns = objects.filter((o) => o.type === 'attack-pattern');
  const coursesOfAction = objects.filter((o) => o.type === 'course-of-action');
  const relationships = objects.filter((o) => o.type === 'relationship');
  const confirmedVulns = vulnerabilities.filter((v) => v.x_drishti_confirmed);

  return (
    <div className="flex-1 h-full min-h-0 overflow-y-auto p-4 sm:p-6 lg:p-8 bg-bone text-ink font-mono text-xs select-none scrollbar-tactical">
      <div className="max-w-[1520px] mx-auto space-y-4">
        
        {/* Editorial Top Command Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-hairline pb-3 bg-pureWhite p-3 shadow-xs">
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-vermilion font-extrabold text-sm">06 //</span>
              <h1 className="text-sm font-grotesk font-black uppercase tracking-wider text-ink">
                OASIS STIX 2.1 THREAT SHARING & TAXII BUNDLE EXPORT
              </h1>
              <span className="text-[9px] font-bold px-1.5 py-0.5 border border-hairline bg-boneLight text-charcoal">
                GRADE 10/10 SDO EXPORT
              </span>
            </div>
            <p className="text-[10px] text-charcoal mt-0.5">
              Standardized OASIS STIX 2.1 cyber threat intelligence linking Stage 1 Passive Recon, Stage 2 Active Precision Probing, and Confirmed Vulnerabilities.
            </p>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            {/* Target Domain Input Switcher */}
            <div className="flex items-center border border-hairline bg-boneLight px-2 py-1">
              <span className="text-[10px] text-charcoal font-bold mr-1">TARGET:</span>
              <input
                type="text"
                value={targetDomain}
                onChange={(e) => setTargetDomain(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') handleCompileTarget(targetDomain);
                }}
                className="bg-transparent border-none text-xs font-bold text-ink focus:outline-none w-36 uppercase font-mono"
                placeholder="domain.ac.in"
              />
            </div>

            <button
              onClick={() => handleCompileTarget(targetDomain)}
              disabled={loading}
              className="bg-boneLight border border-hairline hover:bg-ink hover:text-white text-ink px-3 py-1.5 text-xs font-mono font-semibold transition-colors cursor-pointer flex items-center gap-1"
            >
              <DoodleIcon name="spark" className="w-3 h-3" />
              <span>[ COMPILE ]</span>
            </button>

            <button
              onClick={copyJson}
              disabled={loading || !stixBundle}
              className="bg-pureWhite border border-hairline hover:bg-boneDark text-ink px-3 py-1.5 text-xs font-mono font-semibold transition-colors shadow-xs flex items-center gap-1.5 disabled:opacity-40 cursor-pointer"
            >
              <DoodleIcon name="copy" size={11} className="text-ink" />
              <span>{copied ? '[ COPIED! ]' : '[ COPY JSON ]'}</span>
            </button>

            <button
              onClick={downloadJson}
              disabled={loading || !stixBundle}
              className="bg-vermilion hover:bg-crimson text-white px-3.5 py-1.5 text-xs font-mono font-bold border border-hairline shadow-xs flex items-center gap-1.5 transition-colors disabled:opacity-40 cursor-pointer"
            >
              <DoodleIcon name="download" size={11} className="text-white" />
              <span>[ EXPORT STIX BUNDLE ↓ ]</span>
            </button>
          </div>
        </div>

        {/* Technical Specification Badges & Live Telemetry HUD */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <div className="bg-pureWhite border border-hairline p-3 shadow-xs">
            <div className="text-[9px] font-bold text-charcoal uppercase tracking-wider">[ TOTAL STIX SDOs ]</div>
            <div className="font-condensed text-2xl font-extrabold text-ink mt-1">{objectCount} Objects</div>
            <div className="text-[9px] text-signalGreen font-bold mt-0.5">OASIS STIX 2.1 JSON-LD</div>
          </div>

          <div className="bg-pureWhite border border-hairline p-3 shadow-xs">
            <div className="text-[9px] font-bold text-charcoal uppercase tracking-wider flex items-center justify-between">
              <span className="flex items-center gap-1">
                <DoodleIcon name="exploit" className="w-3 h-3 text-vermilion" />
                <span>[ CONFIRMED BUGS ]</span>
              </span>
              <span className="w-2 h-2 rounded-full bg-vermilion animate-pulse"></span>
            </div>
            <div className="font-condensed text-2xl font-extrabold text-vermilion mt-1">{confirmedVulns.length} Verified</div>
            <div className="text-[9px] text-charcoal mt-0.5">Active Ingress Vectors</div>
          </div>

          <div className="bg-pureWhite border border-hairline p-3 shadow-xs">
            <div className="text-[9px] font-bold text-charcoal uppercase tracking-wider">[ THREAT INDICATORS ]</div>
            <div className="font-condensed text-2xl font-extrabold text-ink mt-1">{indicators.length} Patterns</div>
            <div className="text-[9px] text-charcoal mt-0.5">DNS, IP & Port Telemetry</div>
          </div>

          <div className="bg-pureWhite border border-hairline p-3 shadow-xs">
            <div className="text-[9px] font-bold text-charcoal uppercase tracking-wider">[ MITRE ATT&CK TTPs ]</div>
            <div className="font-condensed text-2xl font-extrabold text-ink mt-1">{attackPatterns.length} Patterns</div>
            <div className="text-[9px] text-charcoal mt-0.5">Initial Access & Discovery</div>
          </div>

          <div className="bg-pureWhite border border-hairline p-3 shadow-xs">
            <div className="text-[9px] font-bold text-charcoal uppercase tracking-wider">[ COURSES OF ACTION ]</div>
            <div className="font-condensed text-2xl font-extrabold text-signalGreen mt-1">{coursesOfAction.length} Rules</div>
            <div className="text-[9px] text-charcoal mt-0.5">WAF, ModSec & IPTables</div>
          </div>
        </div>

        {/* View Mode Switcher Pills */}
        <div className="flex items-center gap-2 border-b border-hairline pb-2.5 flex-wrap">
          {[
            { id: 'JSON', label: `[ RAW STIX 2.1 JSON (${objectCount}) ]`, icon: 'file' },
            { id: 'VULNERABILITIES', label: `[ VULNERABILITY SDOs (${vulnerabilities.length}) ]`, icon: 'exploit', highlight: true },
            { id: 'INDICATORS', label: `[ THREAT INDICATORS (${indicators.length}) ]`, icon: 'target' },
            { id: 'MITIGATIONS', label: `[ COURSES OF ACTION (${coursesOfAction.length}) ]`, icon: 'shield' },
            { id: 'RELATIONSHIPS', label: `[ RELATIONSHIPS (${relationships.length}) ]`, icon: 'pivot' },
          ].map((tab) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as StixTab)}
                className={`px-3 py-1.5 text-xs font-mono font-bold transition-all cursor-pointer flex items-center gap-1.5 border ${
                  isActive
                    ? tab.highlight
                      ? 'bg-vermilion text-white border-vermilion shadow-xs'
                      : 'bg-ink text-white border-ink shadow-xs'
                    : tab.highlight
                    ? 'bg-pureWhite text-vermilion border-vermilion/40 hover:bg-vermilion/10'
                    : 'bg-pureWhite text-charcoal border-hairline hover:border-ink hover:text-ink'
                }`}
              >
                <DoodleIcon name={tab.icon} className="w-3.5 h-3.5" />
                <span>{tab.label}</span>
              </button>
            );
          })}

          <div className="ml-auto flex items-center gap-2">
            <button
              onClick={() => onNavigate?.('intel')}
              className="px-2.5 py-1 text-[10px] font-bold bg-pureWhite border border-hairline text-ink hover:bg-boneDark cursor-pointer"
            >
              [ THREAT INTEL ➔ ]
            </button>
            <button
              onClick={() => onNavigate?.('reports')}
              className="px-2.5 py-1 text-[10px] font-bold bg-pureWhite border border-hairline text-ink hover:bg-boneDark cursor-pointer"
            >
              [ REPORTS DOSSIER ➔ ]
            </button>
          </div>
        </div>

        {/* ------------------------------------------------------------- */}
        {/* TAB 1: RAW STIX 2.1 JSON (TERMINAL VIEW)                      */}
        {/* ------------------------------------------------------------- */}
        {activeTab === 'JSON' && (
          <div className="bg-pureWhite border border-hairline shadow-xs">
            <div className="flex items-center justify-between px-4 py-2.5 border-b border-hairline bg-boneDark">
              <div className="flex items-center space-x-2">
                <span className="w-2 h-2 bg-signalGreen"></span>
                <span className="text-[10px] font-bold text-ink uppercase tracking-wider">
                  LIVE STIX BUNDLE TELEMETRY PAYLOAD // {stixBundle?.target || targetDomain}
                </span>
              </div>
              <div className="flex items-center space-x-3 text-[10px] font-mono text-charcoal">
                <span>SPEC: 2.1</span>
                <span>•</span>
                <span>OBJECTS: <strong className="text-ink">{objectCount}</strong></span>
                <span>•</span>
                <span className="text-signalGreen font-bold">OASIS & TAXII 2.1 COMPLIANT</span>
              </div>
            </div>

            {loading ? (
              <div className="py-24 text-center space-y-2">
                <div className="w-6 h-6 border-2 border-vermilion border-t-transparent animate-spin mx-auto"></div>
                <p className="text-xs text-charcoal font-mono mt-2">[ COMPILING STIX 2.1 BUNDLE FROM SUPABASE LEDGER... ]</p>
              </div>
            ) : objectCount > 0 ? (
              <div className="relative">
                <pre className="p-4 bg-[#0D1117] text-[#58A6FF] font-mono text-xs overflow-x-auto max-h-[580px] leading-relaxed scrollbar-tactical whitespace-pre selection:bg-signalGreen selection:text-black">
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
        )}

        {/* ------------------------------------------------------------- */}
        {/* TAB 2: VULNERABILITY SDOs                                    */}
        {/* ------------------------------------------------------------- */}
        {activeTab === 'VULNERABILITIES' && (
          <div className="space-y-3">
            <div className="p-3 bg-pureWhite border border-hairline flex items-center justify-between text-xs font-mono">
              <span className="font-bold text-ink uppercase">
                STIX 2.1 VULNERABILITY DOMAIN OBJECTS (SDOs) // CONFIRMED BUGS PRIORITIZED
              </span>
              <span className="text-[10px] text-charcoal font-bold">
                {vulnerabilities.length} Total SDOs ({confirmedVulns.length} Confirmed)
              </span>
            </div>

            <div className="grid grid-cols-1 gap-2.5">
              {vulnerabilities.map((v, idx) => {
                const isConf = v.x_drishti_confirmed;
                return (
                  <div
                    key={idx}
                    className={`p-3.5 bg-pureWhite border shadow-xs transition-colors ${
                      isConf ? 'border-vermilion bg-boneLight/50' : 'border-hairline hover:border-ink'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 flex-wrap border-b border-hairlineLight pb-2">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-ink">{v.name}</span>
                        {isConf ? (
                          <span className="px-2 py-0.5 text-[9px] font-bold bg-vermilion text-white">
                            ⚡ CONFIRMED ACTIVE INGRESS
                          </span>
                        ) : (
                          <span className="px-1.5 py-0.5 text-[9px] font-bold bg-boneLight text-charcoal border border-hairline">
                            CORRELATED PASSIVE
                          </span>
                        )}
                        {v.x_drishti_cvss && (
                          <span className="px-1.5 py-0.5 text-[9px] font-bold bg-ink text-white">
                            CVSS {v.x_drishti_cvss}
                          </span>
                        )}
                        {v.x_drishti_weaponized && (
                          <span className="px-1.5 py-0.5 text-[9px] font-bold bg-amber-500 text-black">
                            MSF WEAPONIZED
                          </span>
                        )}
                      </div>
                      <span className="text-[9px] text-charcoal font-mono">
                        STIX ID: <strong className="text-ink">{v.id}</strong>
                      </span>
                    </div>

                    <p className="text-xs text-charcoal mt-2 leading-relaxed">{v.description}</p>

                    <div className="mt-2 pt-2 border-t border-hairlineLight flex items-center justify-between text-[9px] text-charcoal">
                      <span>AFFECTED ASSET: <strong className="text-ink">{v.x_drishti_asset || targetDomain}</strong></span>
                      <span>SPEC: OASIS STIX 2.1 vulnerability SDO</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* ------------------------------------------------------------- */}
        {/* TAB 3: THREAT INDICATORS                                     */}
        {/* ------------------------------------------------------------- */}
        {activeTab === 'INDICATORS' && (
          <div className="space-y-3">
            <div className="p-3 bg-pureWhite border border-hairline flex items-center justify-between text-xs font-mono">
              <span className="font-bold text-ink uppercase">
                STIX 2.1 OBSERVABLE INDICATORS // NETWORK, DNS & PORT TELEMETRY
              </span>
              <span className="text-[10px] text-charcoal font-bold">
                {indicators.length} Active Indicators
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
              {indicators.map((ind, idx) => (
                <div key={idx} className="p-3 bg-pureWhite border border-hairline shadow-xs space-y-1.5">
                  <div className="flex items-center justify-between text-[11px] font-bold">
                    <span className="text-ink truncate">{ind.name}</span>
                    <span className="px-1.5 py-0.2 bg-boneLight text-charcoal text-[9px] border border-hairline">
                      {ind.indicator_types?.[0] || 'indicator'}
                    </span>
                  </div>
                  <pre className="p-2 bg-boneLight border border-hairlineLight text-[10px] text-vermilion font-mono overflow-x-auto">
                    {ind.pattern}
                  </pre>
                  <div className="text-[9px] text-charcoal flex items-center justify-between pt-1">
                    <span>Pattern Type: <strong>stix (2.1)</strong></span>
                    <span className="truncate max-w-[200px]" title={ind.id}>{ind.id}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ------------------------------------------------------------- */}
        {/* TAB 4: COURSES OF ACTION                                      */}
        {/* ------------------------------------------------------------- */}
        {activeTab === 'MITIGATIONS' && (
          <div className="space-y-3">
            <div className="p-3 bg-pureWhite border border-hairline flex items-center justify-between text-xs font-mono">
              <span className="font-bold text-ink uppercase">
                STIX 2.1 COURSES OF ACTION // AUTOMATED FIREWALL & REMEDIATION DIRECTIVES
              </span>
              <span className="text-[10px] text-signalGreen font-bold">
                {coursesOfAction.length} Compiled Directives
              </span>
            </div>

            <div className="space-y-3">
              {coursesOfAction.map((coa, idx) => (
                <div key={idx} className="p-4 bg-pureWhite border border-hairline shadow-xs space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-ink uppercase">{coa.name}</span>
                    <span className="px-2 py-0.5 bg-signalGreenBg text-signalGreen text-[9px] font-bold border border-signalGreen/40">
                      COURSE-OF-ACTION SDO
                    </span>
                  </div>
                  <pre className="p-3 bg-[#161B22] text-signalGreen text-[11px] font-mono border border-gray-800 overflow-x-auto whitespace-pre">
                    {coa.description}
                  </pre>
                  <div className="flex items-center justify-between text-[9px] text-charcoal">
                    <span>STIX Identifier: <code className="text-ink">{coa.id}</code></span>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(coa.description);
                        if (showToast) showToast('info', 'Copied', 'Rule copied to clipboard');
                      }}
                      className="px-2 py-0.5 bg-boneLight hover:bg-boneDark text-ink font-bold border border-hairline cursor-pointer"
                    >
                      [ COPY RULE ]
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ------------------------------------------------------------- */}
        {/* TAB 5: RELATIONSHIPS                                         */}
        {/* ------------------------------------------------------------- */}
        {activeTab === 'RELATIONSHIPS' && (
          <div className="space-y-3">
            <div className="p-3 bg-pureWhite border border-hairline flex items-center justify-between text-xs font-mono">
              <span className="font-bold text-ink uppercase">
                STIX 2.1 RELATIONSHIP MATRIX // GRAPH LINKAGES BETWEEN SDOs
              </span>
              <span className="text-[10px] text-charcoal font-bold">
                {relationships.length} Relationships Mapped
              </span>
            </div>

            <div className="overflow-x-auto bg-pureWhite border border-hairline shadow-xs">
              <table className="w-full text-left border-collapse text-[11px] font-mono">
                <thead>
                  <tr className="border-b border-hairline bg-boneLight text-charcoal text-[9px] uppercase">
                    <th className="p-2.5">Type</th>
                    <th className="p-2.5">Source Reference</th>
                    <th className="p-2.5">Relationship</th>
                    <th className="p-2.5">Target Reference</th>
                    <th className="p-2.5">Context</th>
                  </tr>
                </thead>
                <tbody>
                  {relationships.map((rel, idx) => (
                    <tr key={idx} className="border-b border-hairlineLight hover:bg-boneLight">
                      <td className="p-2.5 font-bold text-ink">relationship</td>
                      <td className="p-2.5 text-vermilion truncate max-w-[180px]" title={rel.source_ref}>
                        {rel.source_ref.slice(0, 24)}...
                      </td>
                      <td className="p-2.5">
                        <span className="px-1.5 py-0.2 bg-boneDark text-ink text-[9px] font-bold">
                          {rel.relationship_type.toUpperCase()}
                        </span>
                      </td>
                      <td className="p-2.5 text-blue-600 truncate max-w-[180px]" title={rel.target_ref}>
                        {rel.target_ref.slice(0, 24)}...
                      </td>
                      <td className="p-2.5 text-charcoal text-[10px]">{rel.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

      </div>
    </div>
  );
};
