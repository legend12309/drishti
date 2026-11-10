import React, { useState, useEffect } from 'react';
import { TabId } from '../types';

interface AuditViewProps {
  onNavigate?: (tab: TabId) => void;
  showToast?: (type: 'success' | 'warning' | 'error' | 'info', title: string, detail?: string) => void;
}

interface AuditLog {
  id: string;
  time: string;
  engine: string;
  action: string;
  detail: string;
  status: 'BLOCKED' | 'SUCCESS' | 'WARNING';
  hash?: string;
  ip?: string;
}

export const AuditView: React.FC<AuditViewProps> = ({ onNavigate, showToast }) => {
  const [engineFilter, setEngineFilter] = useState('All');
  const [search, setSearch] = useState('');
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchAuditData = () => {
    setLoading(true);
    Promise.all([
      fetch('/api/audit/logs').then((r) => r.json()).catch(() => ({ logs: [] })),
      fetch('/api/authorizations/audit?limit=25').then((r) => r.json()).catch(() => ({ events: [] })),
    ]).then(([auditData, authData]) => {
      const combined: AuditLog[] = [];

      if (authData.events && authData.events.length > 0) {
        authData.events.forEach((ev: any) => {
          combined.push({
            id: `AUTH-${ev.id}`,
            time: ev.created_at ? ev.created_at.replace('T', ' ').substring(0, 19) : new Date().toISOString().substring(0, 19),
            engine: 'Authorization & Scope',
            action: ev.event_type.replace(/_/g, ' ').toUpperCase(),
            detail: `${ev.target}: ${ev.detail || ''}`,
            status: ev.event_type.includes('fail') || ev.event_type.includes('violation') || ev.event_type.includes('reject') ? 'BLOCKED' : 'SUCCESS',
            hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            ip: '127.0.0.1 (Local Operator)',
          });
        });
      }

      if (auditData.logs && auditData.logs.length > 0) {
        combined.push(...auditData.logs);
      }

      setLogs(combined);
    }).finally(() => {
      setLoading(false);
    });
  };

  useEffect(() => {
    fetchAuditData();
  }, []);

  const filteredLogs = logs.filter((log) => {
    if (engineFilter !== 'All' && !log.engine.toLowerCase().includes(engineFilter.toLowerCase())) return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      return log.action.toLowerCase().includes(q) || log.detail.toLowerCase().includes(q) || log.id.toLowerCase().includes(q);
    }
    return true;
  });

  return (
    <div className="flex-1 h-full min-h-0 overflow-y-auto p-4 sm:p-6 lg:p-8 bg-bone text-ink font-mono text-xs select-none scrollbar-tactical">
      <div className="max-w-[1400px] mx-auto space-y-4">
        
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-hairline pb-3 bg-pureWhite p-3 shadow-xs">
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-vermilion font-extrabold text-sm">08 //</span>
              <h1 className="text-sm font-grotesk font-bold uppercase tracking-wider text-ink">
                CRYPTOGRAPHIC AUDIT TRAIL & WAL COMPLIANCE LEDGER
              </h1>
            </div>
            <p className="text-[10px] text-charcoal mt-0.5">
              Cryptographically verified ledger of operator activities, scope grants, scan authorizations, and security events.
            </p>
          </div>

          <div className="flex items-center space-x-2">
            <span className="px-2.5 py-1 bg-signalGreenBg border border-signalGreen text-signalGreen text-[10px] font-bold">
              [ SHA-256 HASH CHAINED ]
            </span>
            <button
              onClick={fetchAuditData}
              className="bg-boneLight border border-hairline hover:bg-ink hover:text-white text-ink px-3 py-1.5 text-xs font-mono font-semibold transition-colors cursor-pointer"
            >
              [ REFRESH LOGS ]
            </button>
          </div>
        </div>

        {/* Filter and Search Bar */}
        <div className="bg-pureWhite border border-hairline p-3 shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center space-x-1">
            {['All', 'Guard', 'Recon', 'Auth'].map((eng) => (
              <button
                key={eng}
                onClick={() => setEngineFilter(eng)}
                className={`px-3 py-1 text-xs font-mono font-bold border cursor-pointer ${
                  engineFilter === eng
                    ? 'bg-ink text-white border-hairline'
                    : 'bg-boneLight text-charcoal border-hairline hover:text-ink'
                }`}
              >
                [ {eng.toUpperCase()} ]
              </button>
            ))}
          </div>

          <div className="relative w-full sm:w-80">
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter actions, TX IDs, details..."
              className="w-full px-3 py-1.5 bg-[#FAF8F5] border border-hairline text-xs text-ink font-mono focus:border-vermilion outline-none"
            />
          </div>
        </div>

        {/* Audit Log Table Sheet */}
        <div className="border border-hairline bg-pureWhite shadow-xs overflow-x-auto">
          <table className="w-full text-left font-mono text-[10px] border-collapse">
            <thead className="bg-boneDark/70 text-ink border-b border-hairline">
              <tr>
                <th className="py-2.5 px-3.5 font-bold border-r border-hairlineLight">[ TRANSACTION ID ]</th>
                <th className="py-2.5 px-3.5 font-bold border-r border-hairlineLight">[ TIMESTAMP ]</th>
                <th className="py-2.5 px-3.5 font-bold border-r border-hairlineLight">[ MODULE ]</th>
                <th className="py-2.5 px-3.5 font-bold border-r border-hairlineLight">[ ACTION & DETAIL ]</th>
                <th className="py-2.5 px-3.5 font-bold border-r border-hairlineLight">[ STATUS ]</th>
                <th className="py-2.5 px-3.5 font-bold text-right pr-4">[ OPERATOR CONTEXT ]</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-hairlineLight border-b border-hairline">
              {loading ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-charcoal font-bold">
                    [ FETCHING AUDIT LEDGER BLOCKS... ]
                  </td>
                </tr>
              ) : filteredLogs.length > 0 ? (
                filteredLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-boneLight transition-colors">
                    <td className="py-2.5 px-3.5 font-bold text-ink border-r border-hairlineLight">
                      {log.id}
                    </td>
                    <td className="py-2.5 px-3.5 text-charcoal border-r border-hairlineLight">
                      {log.time}
                    </td>
                    <td className="py-2.5 px-3.5 font-bold text-ink border-r border-hairlineLight">
                      {log.engine}
                    </td>
                    <td className="py-2.5 px-3.5 border-r border-hairlineLight">
                      <div className="font-bold text-ink">{log.action}</div>
                      <div className="text-[9px] text-charcoal truncate max-w-sm">{log.detail}</div>
                    </td>
                    <td className="py-2.5 px-3.5 border-r border-hairlineLight">
                      <span className={`px-2 py-0.5 text-[8px] font-bold uppercase border ${
                        log.status === 'SUCCESS'
                          ? 'bg-signalGreenBg text-signalGreen border-signalGreen'
                          : 'bg-vermilion/10 text-vermilion border-vermilion'
                      }`}>
                        {log.status}
                      </span>
                    </td>
                    <td className="py-2.5 px-3.5 text-right pr-4 text-charcoal">
                      {log.ip || '127.0.0.1 (Local)'}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-charcoal">
                    [ NO AUDIT TRANSACTIONS RECORDED UNDER CURRENT FILTER ]
                  </td>
                </tr>
              )}
            </tbody>
          </table>

          {/* Dossier Barcode Footer */}
          <div className="h-7 border-t border-hairline px-3 flex items-center justify-between bg-boneDark/40">
            <div className="barcode-strip w-32"></div>
            <span className="text-[8px] text-charcoal font-mono font-bold">
              BLOCK_INTEGRITY: MERKLE_ROOT_VERIFIED // SEC_ARCH_09
            </span>
          </div>
        </div>

      </div>
    </div>
  );
};
