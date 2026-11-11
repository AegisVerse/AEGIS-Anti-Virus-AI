import React from 'react';
import {
  Shield,
  Search,
  Activity,
  AlertOctagon,
  Archive,
  Eye,
  Cpu,
  Lock,
  Wifi,
  Globe,
  Sliders,
  Usb,
  FileCheck2,
  Bot,
  History,
  RefreshCw,
  Settings,
  HelpCircle,
} from 'lucide-react';
import { useAppStore } from '../../stores/useAppStore';

interface NavItem {
  id: string;
  labelKey: string;
  icon: React.ComponentType<{ className?: string }>;
}

export function Sidebar() {
  const { activePage, setActivePage, t } = useAppStore();

  const groups: { titleKey: string; items: NavItem[] }[] = [
    {
      titleKey: 'nav.overview',
      items: [
        { id: 'dashboard', labelKey: 'nav.dashboard', icon: Shield },
        { id: 'scan', labelKey: 'nav.scan', icon: Search },
        { id: 'history', labelKey: 'nav.history', icon: History },
      ],
    },
    {
      titleKey: 'nav.protection',
      items: [
        { id: 'realtime', labelKey: 'nav.realtime', icon: Activity },
        { id: 'threats', labelKey: 'nav.threats', icon: AlertOctagon },
        { id: 'quarantine', labelKey: 'nav.quarantine', icon: Archive },
        { id: 'ransomware', labelKey: 'nav.ransomware', icon: Lock },
        { id: 'rat', labelKey: 'nav.rat', icon: Eye },
        { id: 'memory', labelKey: 'nav.memory', icon: Cpu },
      ],
    },
    {
      titleKey: 'nav.intelligence',
      items: [
        { id: 'network', labelKey: 'nav.network', icon: Wifi },
        { id: 'web', labelKey: 'nav.web', icon: Globe },
        { id: 'ai', labelKey: 'nav.ai', icon: Bot },
      ],
    },
    {
      titleKey: 'nav.system',
      items: [
        { id: 'startup', labelKey: 'nav.startup', icon: Sliders },
        { id: 'usb', labelKey: 'nav.usb', icon: Usb },
        { id: 'audit', labelKey: 'nav.audit', icon: FileCheck2 },
        { id: 'updates', labelKey: 'nav.updates', icon: RefreshCw },
        { id: 'settings', labelKey: 'nav.settings', icon: Settings },
        { id: 'about', labelKey: 'nav.about', icon: HelpCircle },
      ],
    },
  ];

  return (
    <aside className="w-64 flex flex-col border-r border-slate-800/80 bg-slate-950/90 backdrop-blur-xl h-screen select-none">
      {/* Brand */}
      <div className="flex items-center gap-3 px-4 py-4 border-b border-slate-800/80">
        <img
          src="./logo.png"
          alt="AEGIS AI Logo"
          className="w-11 h-11 object-contain drop-shadow-[0_0_12px_rgba(6,182,212,0.5)] shrink-0"
        />
        <div>
          <h1 className="text-sm font-bold tracking-wider text-white">AEGIS AI</h1>
          <p className="text-[10px] uppercase font-semibold text-cyan-400 tracking-widest">
            Security Core
          </p>
        </div>
      </div>

      {/* Navigation List */}
      <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-6 scrollbar-thin scrollbar-thumb-slate-800">
        {groups.map((group) => (
          <div key={group.titleKey}>
            <p className="px-3 mb-2 text-[10px] font-bold uppercase tracking-wider text-slate-500">
              {t(group.titleKey)}
            </p>
            <div className="space-y-0.5">
              {group.items.map((item) => {
                const Icon = item.icon;
                const active = activePage === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => setActivePage(item.id)}
                    className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition-all ${
                      active
                        ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-sm shadow-cyan-500/10'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                    }`}
                  >
                    <Icon className={`w-4 h-4 ${active ? 'text-cyan-400' : 'text-slate-500'}`} />
                    <span>{t(item.labelKey)}</span>
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* Footer Version */}
      <div className="p-3 border-t border-slate-800/80 text-center">
        <span className="text-[11px] text-slate-500 font-mono">v0.1.0 • Windows 10/11</span>
      </div>
    </aside>
  );
}

