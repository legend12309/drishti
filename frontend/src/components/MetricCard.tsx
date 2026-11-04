import React from 'react';
import { DoodleIcon } from './DoodleIcon';

interface MetricCardProps {
  label: string;
  value: string | number;
  subtitle?: string;
  badge?: {
    text: string;
    type: 'positive' | 'negative' | 'neutral' | 'critical';
  };
  icon: string;
  chartType?: 'bars' | 'sparkline' | 'badge-status' | 'image-preview';
  chartData?: number[];
  onClick?: () => void;
}

export const MetricCard: React.FC<MetricCardProps> = ({
  label,
  value,
  subtitle,
  badge,
  icon,
  chartType = 'bars',
  chartData = [35, 60, 45, 80, 55, 95, 75],
  onClick,
}) => {
  return (
    <div
      onClick={onClick}
      className={`bg-white rounded-3xl p-5 sm:p-6 border border-[#E8E4F2] shadow-[0_8px_24px_rgba(108,76,241,0.04)] hover:shadow-[0_12px_32px_rgba(108,76,241,0.08)] hover:border-[#6C4CF1]/30 transition-all duration-300 flex flex-col justify-between relative overflow-hidden group ${
        onClick ? 'cursor-pointer' : ''
      }`}
    >
      {/* Top Header Row with label and rounded icon */}
      <div className="flex items-center justify-between">
        <span className="text-[12px] font-semibold text-[#77758E] uppercase tracking-wider font-mono">
          {label}
        </span>
        <div className="w-10 h-10 rounded-2xl bg-[#EAE4FF] border border-[#E8E4F2] text-[#6C4CF1] group-hover:bg-[#6C4CF1] group-hover:text-white transition-all duration-200 flex items-center justify-center shadow-xs">
          <span className="material-symbols-outlined text-[19px]">{icon}</span>
        </div>
      </div>

      {/* Main Metric Value */}
      <div className="mt-3">
        <div className="text-[28px] font-extrabold text-[#22213A] tracking-tight leading-none font-mono">
          {value}
        </div>
        {subtitle && (
          <div className="flex items-center gap-1.5 mt-2.5 text-[12px] font-medium text-[#77758E]">
            {badge && (
              <span
                className={`font-semibold inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono ${
                  badge.type === 'critical'
                    ? 'bg-[#FFF0F1] text-[#DC4655] border border-[#DC4655]/20'
                    : badge.type === 'positive'
                    ? 'bg-[#EAF8F1] text-[#299B75] border border-[#299B75]/20'
                    : badge.type === 'negative'
                    ? 'bg-[#FFF7E8] text-[#C78A27] border border-[#C78A27]/20'
                    : 'bg-[#EAE4FF] text-[#6C4CF1] border border-[#E8E4F2]'
                }`}
              >
                {badge.type === 'positive' ? (
                  <span>▲</span>
                ) : badge.type === 'critical' ? (
                  <DoodleIcon name="spark" className="w-2.5 h-2.5" />
                ) : (
                  <span>•</span>
                )}
                <span>{badge.text}</span>
              </span>
            )}
            <span className="truncate">{subtitle}</span>
          </div>
        )}
      </div>

      {/* Embedded Micro-Visualization */}
      <div className="mt-4 pt-3 border-t border-[#E8E4F2] flex items-end justify-between min-h-[44px]">
        {chartType === 'bars' && (
          <div className="w-full flex items-end justify-between gap-1.5 h-8">
            {chartData.map((h, idx) => (
              <div
                key={idx}
                className="w-full bg-[#FAF9FF] border border-[#E8E4F2]/50 rounded-t-sm hover:bg-[#6C4CF1] transition-colors relative group/bar"
                style={{ height: `${Math.max(15, h)}%` }}
              >
                <div className="opacity-0 group-hover/bar:opacity-100 absolute -top-6 left-1/2 -translate-x-1/2 bg-[#22213A] text-white text-[9px] font-mono font-semibold px-1 py-0.5 rounded shadow pointer-events-none transition-opacity">
                  {h}%
                </div>
              </div>
            ))}
          </div>
        )}

        {chartType === 'badge-status' && (
          <div className="w-full flex items-center justify-between text-[11px] font-mono text-[#77758E]">
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-[#299B75] animate-pulse"></span>
              Real-time Active
            </span>
            <span className="text-[#6C4CF1] font-bold">ARMED</span>
          </div>
        )}
      </div>
    </div>
  );
};
