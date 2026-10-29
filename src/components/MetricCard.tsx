import React from 'react';
import { LucideIcon } from 'lucide-react';

interface MetricCardProps {
  label: string;
  value: string | number;
  sublabel?: string;
  icon?: LucideIcon;
  accent?: boolean;
}

export const MetricCard: React.FC<MetricCardProps> = ({
  label,
  value,
  sublabel,
  icon: Icon,
  accent = false
}) => {
  return (
    <div className="bg-[#0c152e] border border-slate-800 rounded-lg p-5 flex flex-col justify-between transition-colors">
      <div className="flex items-center justify-between text-xs font-medium text-slate-400">
        <span>{label}</span>
        {Icon && (
          <Icon className={`w-4 h-4 ${accent ? 'text-cyan-400' : 'text-slate-400'}`} />
        )}
      </div>

      <div className="mt-3">
        <div className={`text-2xl sm:text-3xl font-semibold font-mono tracking-tight tabular-nums ${accent ? 'text-cyan-300' : 'text-white'}`}>
          {value}
        </div>
      </div>

      {sublabel && (
        <div className="mt-2 text-xs text-slate-400 font-mono">
          {sublabel}
        </div>
      )}
    </div>
  );
};
