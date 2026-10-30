import React from 'react';

export interface ToastMessage {
  id: string;
  type: 'success' | 'warning' | 'error' | 'info';
  title: string;
  detail?: string;
}

interface ToastContainerProps {
  toasts: ToastMessage[];
  onDismiss: (id: string) => void;
}

export const ToastContainer: React.FC<ToastContainerProps> = ({ toasts, onDismiss }) => {
  if (toasts.length === 0) return null;

  return (
    <div className="fixed bottom-6 right-6 z-50 flex flex-col gap-2.5 max-w-sm w-full pointer-events-none select-none">
      {toasts.map((toast) => {
        const typeConfig = {
          success: { bg: 'bg-[#0E1B14] border-emerald-500/30 text-emerald-400', iconBg: 'bg-emerald-500 text-white shadow-[0_0_10px_rgba(52,211,153,0.5)]', icon: 'check_circle' },
          error: { bg: 'bg-[#1C0A0D] border-red-500/30 text-red-400', iconBg: 'bg-[#E51A34] text-white shadow-[0_0_10px_rgba(229,26,52,0.5)]', icon: 'error' },
          warning: { bg: 'bg-[#1C1608] border-amber-500/30 text-amber-400', iconBg: 'bg-amber-500 text-black shadow-[0_0_10px_rgba(245,158,11,0.5)]', icon: 'warning' },
          info: { bg: 'bg-[#0E121B] border-white/10 text-slate-300', iconBg: 'bg-slate-700 text-slate-200 border border-white/20', icon: 'info' },
        }[toast.type];

        return (
          <div
            key={toast.id}
            onClick={() => onDismiss(toast.id)}
            className="pointer-events-auto bg-[#0E121B] rounded-xl border border-white/10 p-3.5 shadow-[0_0_30px_rgba(0,0,0,0.8),0_0_15px_rgba(229,26,52,0.15)] flex items-start gap-3 cursor-pointer transition-all hover:scale-[1.01] active:scale-[0.99] font-mono"
          >
            <div className={`w-6 h-6 rounded-lg flex items-center justify-center shrink-0 ${typeConfig.iconBg}`}>
              <span className="material-symbols-outlined text-[14px]">{typeConfig.icon}</span>
            </div>
            <div className="flex-1 pr-1 min-w-0">
              <div className="text-[12px] font-bold text-white leading-tight">
                {toast.title}
              </div>
              {toast.detail && (
                <div className="text-[11px] text-slate-400 mt-0.5 leading-snug break-words">
                  {toast.detail}
                </div>
              )}
            </div>
            <button
              onClick={(e) => {
                e.stopPropagation();
                onDismiss(toast.id);
              }}
              className="text-slate-500 hover:text-white"
            >
              <span className="material-symbols-outlined text-[14px]">close</span>
            </button>
          </div>
        );
      })}
    </div>
  );
};
