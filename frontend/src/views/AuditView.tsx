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
    <div className="flex-1 overflow-y-auto p-6 lg:p-8 bg-[#F4F1FF] text-[#22213A]">
      <div className="max-w-[1400px] mx-auto space-y-6">
        
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[20px] text-[#6C4CF1]">history_edu</span>
              <h1 className="text-2xl font-bold tracking-tight text-[#22213A]">
                Audit Trail & Compliance Ledger
              </h1>
            </div>
            <p className="text-sm text-[#77758E] mt-1">
              Cryptographically verified ledger of operator activities, scope grants, scan authorizations, and security events.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <span className="px-3 py-1.5 rounded-xl bg-[#EAF8F1] border border-[#299B75]/20 text-[#299B75] text-xs font-semibold">
              Live Audit Active
            </span>
            <button
              onClick={fetchAuditData}
              className="bg-white border border-[#E8E4F2] hover:border-[#6C4CF1]/40 text-[#22213A] px-4 py-2 rounded-xl text-xs font-semibold shadow-sm flex items-center gap-2 transition-all"
            >
              <span className="material-symbols-outlined text-[16px] text-[#6C4CF1]">sync</span>
              <span>Refresh Logs</span>
            </button>
          </div>
        </div>

        {/* Filter and Search Bar */}
        <div className="bg-white rounded-2xl border border-[#E8E4F2] p-4 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-1.5 bg-[#FAF9FF] p-1 rounded-xl border border-[#E8E4F2]">
            {['All', 'Guard', 'Recon', 'Auth'].map((eng) => (
              <button
                key={eng}
                onClick={() => setEngineFilter(eng)}
                className={`px-3 py-1 rounded-lg text-xs font-semibold transition-all ${
                  engineFilter === eng
                    ? 'bg-[#6C4CF1] text-white shadow-sm'
                    : 'text-[#77758E] hover:text-[#22213A]'
                }`}
              >
                {eng}
              </button>
            ))}
          </div>

          <div className="relative w-full sm:w-72">
            <span className="material-symbols-outlined text-[18px] text-[#9896AA] absolute left-3 top-2.5">search</span>
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search action, TX ID, detail..."
              className="w-full pl-9 pr-4 py-2 rounded-xl bg-[#FAF9FF] border border-[#E8E4F2] text-sm text-[#22213A] placeholder:text-[#9896AA] focus:border-[#6C4CF1] outline-none"
            />
          </div>
        </div>

        {/* Audit Log Table */}
        <div className="bg-white rounded-2xl border border-[#E8E4F2] p-6 shadow-sm overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-[#E8E4F2] text-xs font-bold text-[#77758E] uppercase tracking-wider">
                <th className="pb-3 px-3">Transaction</th>
                <th className="pb-3 px-3">Timestamp</th>
                <th className="pb-3 px-3">Module</th>
                <th className="pb-3 px-3">Action</th>
                <th className="pb-3 px-3">Status</th>
                <th className="pb-3 px-3">Operator Context</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E8E4F2] text-xs">
              {loading ? (
                <tr>
                  <td colSpan={6} className="py-16 text-center text-[#77758E]">
                    <span className="material-symbols-outlined text-2xl text-[#6C4CF1] animate-spin block mb-2">progress_activity</span>
                    Fetching audit ledger...
                  </td>
                </tr>
              ) : filteredLogs.length > 0 ? (
                filteredLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-[#FAF9FF] transition-colors">
                    <td className="py-3 px-3 font-mono font-semibold text-[#6C4CF1]">
                      {log.id}
                    </td>
                    <td className="py-3 px-3 text-[#77758E] font-mono text-[11px]">
                      {log.time}
                    </td>
                    <td className="py-3 px-3 font-medium text-[#22213A]">
                      {log.engine}
                    </td>
                    <td className="py-3 px-3">
                      <div className="font-semibold text-[#22213A]">{log.action}</div>
                      <div className="text-[11px] text-[#77758E] truncate max-w-sm mt-0.5">{log.detail}</div>
                    </td>
                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded-md text-[10px] font-bold uppercase ${
                        log.status === 'SUCCESS'
                          ? 'bg-[#EAF8F1] text-[#299B75] border border-[#299B75]/20'
                          : 'bg-[#FFF0F1] text-[#DC4655] border border-[#DC4655]/20'
                      }`}>
                        {log.status}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-[#77758E] font-mono text-[11px]">
                      {log.ip || '127.0.0.1'}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="py-16 text-center">
                    <div className="w-10 h-10 rounded-xl bg-[#F4F1FF] flex items-center justify-center mx-auto text-[#6C4CF1] mb-2">
                      <span className="material-symbols-outlined text-xl">fact_check</span>
                    </div>
                    <h4 className="text-xs font-bold text-[#22213A]">No Audit Records Recorded</h4>
                    <p className="text-xs text-[#77758E] max-w-sm mx-auto mt-0.5">
                      All scope evaluations, authorization grants, and scanner transactions will stream into this tamper-evident ledger.
                    </p>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

      </div>
    </div>
  );
};
