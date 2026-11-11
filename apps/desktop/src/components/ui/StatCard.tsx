import React from 'react';
import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  variant?: 'cyan' | 'emerald' | 'amber' | 'rose' | 'default';
  onClick?: () => void;
}

export function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  variant = 'cyan',
  onClick,
}: StatCardProps) {
  const variantStyles = {
    cyan: 'border-cyan-500/20 bg-slate-900/60 hover:border-cyan-500/40 text-cyan-400',
    emerald: 'border-emerald-500/20 bg-slate-900/60 hover:border-emerald-500/40 text-emerald-400',
    amber: 'border-amber-500/20 bg-slate-900/60 hover:border-amber-500/40 text-amber-400',
    rose: 'border-rose-500/20 bg-slate-900/60 hover:border-rose-500/40 text-rose-400',
    default: 'border-slate-800 bg-slate-900/60 hover:border-slate-700 text-slate-400',
  };

  return (
    <div
      onClick={onClick}
      className={`relative p-5 rounded-xl border backdrop-blur-md transition-all duration-200 ${
        variantStyles[variant]
      } ${onClick ? 'cursor-pointer' : ''}`}
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-slate-400">{title}</p>
          <p className="mt-2 text-2xl font-bold tracking-tight text-white">{value}</p>
          {subtitle && <p className="mt-1 text-xs text-slate-400">{subtitle}</p>}
        </div>
        <div className={`p-3 rounded-lg bg-slate-800/80 ${variantStyles[variant].split(' ').pop()}`}>
          <Icon className="w-6 h-6" />
        </div>
      </div>
    </div>
  );
}

