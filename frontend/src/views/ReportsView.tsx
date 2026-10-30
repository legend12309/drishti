import React, { useState, useEffect, useCallback } from 'react';
import { TabId } from '../types';

interface ReportsViewProps {
  onNavigate?: (tab: TabId) => void;
  showToast?: (type: 'success' | 'warning' | 'error' | 'info', title: string, detail?: string) => void;
}

interface ReportRecord {
  id: string;
  workflow_id: string;
  scan_id: string;
  target: string;
  status: string;
  file_path: string;
  file_size: number;
  generated_at: string;
  error_message?: string;
}

const getStatusBadgeClass = (status: string): string => {
  switch (status?.toLowerCase()) {
    case 'completed': return 'bg-[#EAF8F1] text-[#299B75] border border-[#299B75]/20';
    case 'partially_completed': return 'bg-[#FFF7E8] text-[#C78A27] border border-[#C78A27]/20';
    case 'failed': return 'bg-[#FFF0F1] text-[#DC4655] border border-[#DC4655]/20';
    case 'running': return 'bg-[#EAE4FF] text-[#6C4CF1] border border-[#6C4CF1]/20';
    case 'queued': return 'bg-[#FFF7E8] text-[#C78A27] border border-[#C78A27]/20';
    default: return 'bg-[#FAF9FF] text-[#77758E] border border-[#E8E4F2]';
  }
};

export const ReportsView: React.FC<ReportsViewProps> = ({ onNavigate, showToast }) => {
  const [reports, setReports] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [generating, setGenerating] = useState<Record<string, boolean>>({});
  const [downloading, setDownloading] = useState<Record<string, boolean>>({});

  const fetchReports = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/scans/orchestrator/workflows');
      if (!res.ok) throw new Error('Failed to fetch reports');
      const data = await res.json();
      if (data.workflows) {
        const reportsWithData = data.workflows
          .filter((w: any) => w.status === 'completed' || w.status === 'partially_completed')
          .map((w: any) => ({
            id: `rpt-${w.workflow_id}`,
            workflow_id: w.workflow_id,
            scan_id: w.workflow_id,
            target: w.target,
            status: w.overall_status,
            file_path: '',
            file_size: w.total_findings || 0,
            generated_at: w.completed_at || w.updated_at,
            error_message: w.error_summary,
          }));
        setReports(reportsWithData);
      }
    } catch (err) {
      setError('Failed to load reports');
      if (showToast) showToast('error', 'Failed to load reports', err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  }, [showToast]);

  useEffect(() => {
    fetchReports();
  }, [fetchReports]);

  const generateReport = async (workflowId: string) => {
    setGenerating(prev => ({ ...prev, [workflowId]: true }));
    try {
      const res = await fetch(`/api/scans/orchestrator/workflows/${workflowId}/report`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ include_ai: true }),
      });
      if (!res.ok) throw new Error('Failed to generate report');
      const result = await res.json();
      if (showToast) showToast('success', 'Report Generated', 'PDF report has been generated successfully');
      fetchReports();
    } catch (err) {
      if (showToast) showToast('error', 'Generation Failed', err instanceof Error ? err.message : 'Failed to generate report');
    } finally {
      setGenerating(prev => ({ ...prev, [workflowId]: false }));
    }
  };

  const downloadReport = async (workflowId: string, filename: string) => {
    setDownloading(prev => ({ ...prev, [workflowId]: true }));
    try {
      const res = await fetch(`/api/scans/orchestrator/workflows/${workflowId}/report/download`);
      if (!res.ok) throw new Error('Download failed');
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename || `drishti-security-report-${workflowId}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      if (showToast) showToast('success', 'Download Started', 'PDF report is downloading');
    } catch (err) {
      if (showToast) showToast('error', 'Download Failed', err instanceof Error ? err.message : 'Failed to download report');
    } finally {
      setDownloading(prev => ({ ...prev, [workflowId]: false }));
    }
  };

  const renderLoading = () => (
    <div className="flex-1 overflow-y-auto p-6 lg:p-8 select-none font-sans">
      <div className="max-w-[1400px] mx-auto space-y-6">
        <div className="flex items-center gap-3">
          <span className="material-symbols-outlined text-[22px] text-[#6C4CF1] animate-spin">progress_activity</span>
          <div>
            <div className="text-[14px] font-bold text-[#22213A]">Loading Reports</div>
            <div className="text-[12px] text-[#9896AA]">Fetching your security assessment reports...</div>
          </div>
        </div>
      </div>
    </div>
  );

  const renderError = () => (
    <div className="flex-1 overflow-y-auto p-6 lg:p-8 select-none font-sans">
      <div className="max-w-[1400px] mx-auto space-y-6">
        <div className="p-5 rounded-2xl bg-rose-50 border border-rose-200 text-rose-700 text-[12px] flex items-start gap-2">
          <span className="material-symbols-outlined text-[17px] shrink-0 mt-0.5">error</span>
          <div>
            <div className="font-bold">Failed to Load Reports</div>
            <div className="text-[11px] text-rose-600 mt-0.5">{error}</div>
          </div>
        </div>
        <button
          onClick={fetchReports}
          className="px-4 py-2 rounded-2xl bg-[#6C4CF1] hover:bg-[#5940D8] text-white text-[12px] font-semibold shadow-xs flex items-center gap-1.5 transition-all active:scale-95 mx-auto"
        >
          <span className="material-symbols-outlined text-[16px]">refresh</span>
          <span>Retry</span>
        </button>
      </div>
    </div>
  );

  const renderEmptyState = () => (
    <div className="py-16 text-center space-y-3">
      <span className="material-symbols-outlined text-4xl text-[#E8E4F2]">picture_as_pdf</span>
      <p className="text-[13px] text-[#9896AA]">
        No reports available yet. Complete a security assessment scan to generate a PDF report.
      </p>
      <button
        onClick={() => onNavigate?.('recon')}
        className="mt-4 px-5 py-2.5 rounded-2xl bg-gradient-to-r from-[#5A45FF] to-[#6C5CE7] hover:opacity-95 text-white text-[13px] font-semibold shadow-xs flex items-center gap-2 transition-all active:scale-95"
      >
        <span className="material-symbols-outlined text-[16px]">radar</span>
        <span>Start New Scan</span>
      </button>
    </div>
  );

  const renderReportsTable = () => (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b border-[#E8E4F2]">
            <th className="px-4 py-3 text-left text-[11px] font-bold text-[#77758E] uppercase tracking-wider">Report</th>
            <th className="px-4 py-3 text-left text-[11px] font-bold text-[#77758E] uppercase tracking-wider">Target</th>
            <th className="px-4 py-3 text-left text-[11px] font-bold text-[#77758E] uppercase tracking-wider">Scan Status</th>
            <th className="px-4 py-3 text-left text-[11px] font-bold text-[#77758E] uppercase tracking-wider">Generated</th>
            <th className="px-4 py-3 text-left text-[11px] font-bold text-[#77758E] uppercase tracking-wider">Size</th>
            <th className="px-4 py-3 text-right text-[11px] font-bold text-[#77758E] uppercase tracking-wider pr-4">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[#E8E4F2]">
          {reports.map((report: any, idx: number) => (
            <tr key={report.id} className="hover:bg-[#FAF9FF] transition-colors">
              <td className="px-4 py-3">
                <div className="flex items-center gap-3">
                  <span className="material-symbols-outlined text-[22px] text-[#5A45FF]">picture_as_pdf</span>
                  <div>
                    <div className="text-[14px] font-bold text-[#22213A] font-mono">{report.id}</div>
                    <div className="text-[11px] text-[#9896AA]">{report.workflow_id}</div>
                  </div>
                </div>
              </td>
              <td className="px-4 py-3">
                <div className="text-[13px] font-bold text-[#22213A]">{report.target}</div>
                <div className="text-[11px] text-[#9896AA] font-mono">{report.scan_id}</div>
              </td>
              <td className="px-4 py-3">
                <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase ${getStatusBadgeClass(report.status)}`}>
                  {report.status}
                </span>
              </td>
              <td className="px-4 py-3 text-[12px] text-[#77758E] font-mono">
                {report.generated_at ? new Date(report.generated_at).toLocaleString() : '—'}
              </td>
              <td className="px-4 py-3 text-[12px] text-[#77758E] font-mono">
                {report.file_size ? `${report.file_size} findings` : '—'}
              </td>
              <td className="px-4 py-3 text-right pr-4">
                <div className="flex items-center justify-end gap-2">
                  <button
                    onClick={() => downloadReport(report.workflow_id, `drishti-security-report-${report.workflow_id}.pdf`)}
                    disabled={downloading[report.workflow_id] || !report.file_path}
                    className="px-3 py-1.5 rounded-xl bg-[#6C4CF1] hover:bg-[#5940D8] text-white text-[11px] font-semibold shadow-xs flex items-center gap-1.5 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <span className="material-symbols-outlined text-[14px]">download</span>
                    <span>Download</span>
                  </button>
                  <button
                    onClick={() => generateReport(report.workflow_id)}
                    disabled={generating[report.workflow_id]}
                    className="px-3 py-1.5 rounded-xl border border-[#E8E4F2] text-[#77758E] hover:text-[#22213A] hover:bg-[#FAF9FF] text-[11px] font-semibold hover:border-[#6C4CF1] transition-all"
                  >
                    <span className="material-symbols-outlined text-[14px]">refresh</span>
                    <span>Regenerate</span>
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );

  if (loading) return renderLoading();
  if (error) return renderError();

  return (
    <div className="flex-1 overflow-y-auto p-6 lg:p-8 select-none font-sans">
      <div className="max-w-[1400px] mx-auto space-y-6">
        {/* Page Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[12px] font-bold uppercase tracking-wider text-[#5A45FF] bg-indigo-50 px-2.5 py-0.5 rounded-full border border-indigo-100">
                PDF Reports
              </span>
            </div>
            <h1 className="text-[26px] lg:text-[28px] font-extrabold text-slate-900 tracking-tight mt-1">
              PDF Security Assessment Reports
            </h1>
            <p className="text-[13px] text-slate-500 mt-0.5">
              Access, download, and review your DRISHTI security assessment reports.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={fetchReports}
              disabled={loading}
              className="bg-white border border-slate-200 hover:border-[#5A45FF]/50 text-slate-700 px-4 py-2.5 rounded-2xl text-[13px] font-semibold shadow-xs flex items-center gap-2 transition-all hover:bg-slate-50 active:scale-95"
            >
              <span className="material-symbols-outlined text-[17px] text-[#5A45FF]">refresh</span>
              <span>Refresh</span>
            </button>

            <button
              className="bg-gradient-to-r from-[#5A45FF] to-[#6C5CE7] hover:opacity-95 text-white px-6 py-2.5 rounded-2xl text-[13px] font-semibold shadow-[0_4px_16px_rgba(90,69,255,0.25)] flex items-center gap-2 transition-all active:scale-95"
            >
              <span className="material-symbols-outlined text-[18px]">picture_as_pdf</span>
              <span>Generate New Report</span>
            </button>
          </div>
        </div>

        {/* Summary Indicators */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="p-4 rounded-2xl bg-white border border-[#E8E4F2] shadow-[0_8px_24px_rgba(108,76,241,0.04)]">
            <div className="text-[11px] font-bold text-[#77758E] uppercase tracking-wider mb-1">Total Reports</div>
            <div className="text-[24px] font-extrabold text-[#22213A]">{reports.length}</div>
          </div>
          <div className="p-4 rounded-2xl bg-white border border-[#E8E4F2] shadow-[0_8px_24px_rgba(108,76,241,0.04)]">
            <div className="text-[11px] font-bold text-[#77758E] uppercase tracking-wider mb-1">Completed Scans</div>
            <div className="text-[24px] font-extrabold text-[#299B75]">
              {reports.filter(r => r.status === 'completed').length}
            </div>
          </div>
          <div className="p-4 rounded-2xl bg-white border border-[#E8E4F2] shadow-[0_8px_24px_rgba(108,76,241,0.04)]">
            <div className="text-[11px] font-bold text-[#77758E] uppercase tracking-wider mb-1">Partial Completion</div>
            <div className="text-[24px] font-extrabold text-[#C78A27]">
              {reports.filter(r => r.status === 'partially_completed').length}
            </div>
          </div>
          <div className="p-4 rounded-2xl bg-white border border-[#E8E4F2] shadow-[0_8px_24px_rgba(108,76,241,0.04)]">
            <div className="text-[11px] font-bold text-[#77758E] uppercase tracking-wider mb-1">Failed Scans</div>
            <div className="text-[24px] font-extrabold text-[#DC4655]">
              {reports.filter(r => r.status === 'failed').length}
            </div>
          </div>
        </div>

        {/* Reports Table */}
        <div className="bg-white rounded-3xl border border-[#E8E4F2] p-6 sm:p-7 shadow-[0_8px_24px_rgba(108,76,241,0.04)]">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 mb-6 pb-4 border-b border-[#E8E4F2]">
            <div>
              <h3 className="text-[16px] font-bold text-[#22213A] tracking-tight">
                Security Assessment Reports
              </h3>
              <p className="text-[12px] text-[#77758E] mt-0.5">
                Generated PDF reports from completed security assessments
              </p>
            </div>

            <span className="px-3.5 py-1 rounded-full bg-[#EAE4FF] border border-[#E8E4F2] text-[#6C4CF1] text-[11px] font-bold uppercase">
              {reports.length} Reports
            </span>
          </div>

          {reports.length === 0 ? renderEmptyState() : renderReportsTable()}
        </div>
      </div>
    </div>
  );
};