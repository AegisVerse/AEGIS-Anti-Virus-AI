import React from 'react';
import type { ModuleState, Severity, Reputation } from '../../types/aegis';
import { useAppStore } from '../../stores/useAppStore';

export function ModuleBadge({ state }: { state: ModuleState }) {
  const t = useAppStore((s) => s.t);
  const colorMap: Record<ModuleState, string> = {
    active: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    disabled: 'bg-slate-500/15 text-slate-400 border-slate-500/30',
    unavailable: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    not_installed: 'bg-indigo-500/15 text-indigo-400 border-indigo-500/30',
    experimental: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
    error: 'bg-rose-500/15 text-rose-400 border-rose-500/30',
  };

  const label = t(`status.${state}`);

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold tracking-wider uppercase border ${
        colorMap[state] || colorMap.disabled
      }`}
    >
      {label}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const colorMap: Record<Severity, string> = {
    info: 'bg-sky-500/15 text-sky-400 border-sky-500/30',
    low: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    medium: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
    critical: 'bg-rose-500/20 text-rose-400 border-rose-500/40 animate-pulse',
  };

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold uppercase border ${
        colorMap[severity] || colorMap.info
      }`}
    >
      {severity}
    </span>
  );
}

export function ReputationBadge({ reputation }: { reputation: Reputation }) {
  const map: Record<Reputation, { bg: string; text: string; label: string }> = {
    known_malicious: { bg: 'bg-rose-500/20 text-rose-400 border-rose-500/40', text: 'Zararlı', label: 'KNOWN MALICIOUS' },
    suspicious: { bg: 'bg-amber-500/20 text-amber-400 border-amber-500/40', text: 'Şüpheli', label: 'SUSPICIOUS' },
    unknown: { bg: 'bg-slate-500/20 text-slate-400 border-slate-500/40', text: 'Bilinmeyen', label: 'UNKNOWN' },
    trusted: { bg: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40', text: 'Güvenilir', label: 'TRUSTED' },
  };

  const item = map[reputation] || map.unknown;

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold border ${item.bg}`}>
      {item.label}
    </span>
  );
}

