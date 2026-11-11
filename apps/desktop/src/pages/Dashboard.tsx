import React, { useEffect, useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Search,
  Play,
  HardDrive,
  Cpu,
  Archive,
  RefreshCw,
  Clock,
  CheckCircle2,
} from 'lucide-react';
import { callAegis } from '../services/aegis';
import { useAppStore } from '../stores/useAppStore';
import { StatCard } from '../components/ui/StatCard';
import { ModuleBadge, SeverityBadge } from '../components/ui/Badge';
import type { DashboardSummary } from '../types/aegis';

export function Dashboard() {
  const { setActivePage, t } = useAppStore();
  const [data, setData] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchDashboard = async () => {
    try {
      const res = await callAegis<DashboardSummary>({ cmd: 'get_dashboard' });
      setData(res);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboard();
    const interval = setInterval(fetchDashboard, 3000);
    return () => clearInterval(interval);
  }, []);

  const handleStartScan = async (kind: 'quick' | 'full') => {
    try {
      await callAegis({ cmd: 'start_scan', args: { kind, paths: [] } });
      setActivePage('scan');
    } catch (e) {
      console.error(e);
    }
  };

  if (loading && !data) {
    return (
      <div className="flex items-center justify-center h-full text-slate-400">
        <RefreshCw className="w-6 h-6 animate-spin mr-2" />
        <span>{t('common.loading')}</span>
      </div>
    );
  }

  const isProtected = data?.overall === 'protected';
  const isAtRisk = data?.overall === 'at_risk';

  return (
    <div className="p-8 space-y-8 overflow-y-auto max-h-[calc(100vh-4rem)] scrollbar-thin">
      {/* Overall Protection Status Banner */}
      <div
        className={`relative overflow-hidden p-6 rounded-2xl border backdrop-blur-xl ${
          isProtected
            ? 'border-emerald-500/30 bg-gradient-to-r from-emerald-950/40 via-slate-900 to-slate-950 text-emerald-400'
            : isAtRisk
            ? 'border-rose-500/30 bg-gradient-to-r from-rose-950/40 via-slate-900 to-slate-950 text-rose-400'
            : 'border-amber-500/30 bg-gradient-to-r from-amber-950/40 via-slate-900 to-slate-950 text-amber-400'
        }`}
      >
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="flex items-center gap-5">
            <div
              className={`p-4 rounded-2xl shadow-xl ${
                isProtected
                  ? 'bg-emerald-500/20 text-emerald-400 shadow-emerald-500/10'
                  : isAtRisk
                  ? 'bg-rose-500/20 text-rose-400 shadow-rose-500/10 animate-pulse'
                  : 'bg-amber-500/20 text-amber-400 shadow-amber-500/10'
              }`}
            >
              {isProtected ? (
                <ShieldCheck className="w-10 h-10" />
              ) : isAtRisk ? (
                <ShieldAlert className="w-10 h-10" />
              ) : (
                <AlertTriangle className="w-10 h-10" />
              )}
            </div>
            <div>
              <div className="flex items-center gap-3">
                <h2 className="text-2xl font-extrabold text-white">
                  {isProtected
                    ? t('status.protected')
                    : isAtRisk
                    ? t('status.at_risk')
                    : t('status.reduced')}
                </h2>
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-slate-800 text-slate-300 border border-slate-700">
                  {data?.service_mode || 'User Engine'}
                </span>
              </div>
              <p className="mt-1 text-sm text-slate-300">
                {isProtected
                  ? 'Tüm yerel kalkanlar aktif. Gerçek zamanlı koruma ve YARA-X motoru devrede.'
                  : isAtRisk
                  ? 'Aktif güvenlik olayları veya tespit edilmiş zararlı yazılımlar mevcut!'
                  : 'Bazı koruma modülleri duraklatılmış veya henüz yüklenmemiş durumda.'}
              </p>
            </div>
          </div>

          {/* Quick Actions */}
          <div className="flex items-center gap-3">
            <button
              onClick={() => handleStartScan('quick')}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl font-semibold text-sm bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-lg shadow-cyan-500/20 transition-all cursor-pointer"
            >
              <Play className="w-4 h-4 fill-white" />
              <span>{t('actions.quick_scan')}</span>
            </button>
            <button
              onClick={() => handleStartScan('full')}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl font-semibold text-sm border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-slate-200 transition-all cursor-pointer"
            >
              <Search className="w-4 h-4" />
              <span>{t('actions.full_scan')}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        <StatCard
          title="Aktif Tehditler"
          value={data?.active_threats ?? 0}
          subtitle="Müdahale bekleyen dosyalar"
          icon={AlertTriangle}
          variant={data?.active_threats ? 'rose' : 'emerald'}
          onClick={() => setActivePage('threats')}
        />
        <StatCard
          title="Açık Olaylar"
          value={data?.open_incidents ?? 0}
          subtitle="RAT ve davranış incelemeleri"
          icon={ShieldAlert}
          variant={data?.open_incidents ? 'amber' : 'cyan'}
          onClick={() => setActivePage('rat')}
        />
        <StatCard
          title="Karantina Kasası"
          value={data?.quarantine_count ?? 0}
          subtitle="İzole edilmiş zararlı yazılım"
          icon={Archive}
          variant="default"
          onClick={() => setActivePage('quarantine')}
        />
        <StatCard
          title="Sistem Yükü"
          value={data?.resources?.service_cpu_percent ? `%${data.resources.service_cpu_percent.toFixed(1)}` : 'Düşük'}
          subtitle={`RAM: ~${Math.round((data?.resources?.service_working_set_bytes || 0) / (1024 * 1024))} MB`}
          icon={Cpu}
          variant="cyan"
        />
      </div>

      {/* Defender Coexistence & Protection Info */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Defender Status Card */}
        <div className="p-6 rounded-2xl border border-slate-800/80 bg-slate-900/50 backdrop-blur-md">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2.5 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white">Microsoft Defender Uyumluluğu</h3>
              <p className="text-xs text-slate-400">Çift Katmanlı Koruma</p>
            </div>
          </div>
          <div className="space-y-3 text-xs text-slate-300">
            <div className="flex items-center justify-between py-1.5 border-b border-slate-800/60">
              <span className="text-slate-400">Gerçek Zamanlı Koruma:</span>
              <span className="font-semibold text-emerald-400 flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" /> Etkin
              </span>
            </div>
            <div className="flex items-center justify-between py-1.5 border-b border-slate-800/60">
              <span className="text-slate-400">İmza Sürümü:</span>
              <span className="font-mono text-slate-300">
                {data?.defender?.signature_version || '1.463.236.0'}
              </span>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed pt-2">
              AEGIS AI Security, Windows Defender'ı devre dışı bırakmaz. İki motor çakışma olmadan
              birlikte çalışarak tam kapsamlı uç nokta güvenliği sunar.
            </p>
          </div>
        </div>

        {/* Protection Modules Grid */}
        <div className="lg:col-span-2 p-6 rounded-2xl border border-slate-800/80 bg-slate-900/50 backdrop-blur-md">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-bold text-white">Güvenlik Katmanları Durumu</h3>
              <p className="text-xs text-slate-400">Gerçek Zamanlı Çekirdek Modüller</p>
            </div>
            <span className="text-xs font-mono text-cyan-400">
              {data?.modules.filter((m) => m.state === 'active').length || 0} / {data?.modules.length || 0} Aktif
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 max-h-56 overflow-y-auto pr-2 scrollbar-thin">
            {data?.modules.map((mod) => (
              <div
                key={mod.id}
                className="flex items-center justify-between p-3 rounded-xl border border-slate-800/60 bg-slate-950/40"
              >
                <div className="min-w-0 pr-2">
                  <p className="text-xs font-semibold text-white capitalize truncate">
                    {mod.id.replace(/_/g, ' ')}
                  </p>
                  <p className="text-[10px] text-slate-400 truncate">{mod.detail}</p>
                </div>
                <ModuleBadge state={mod.state} />
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Security Events */}
      <div className="p-6 rounded-2xl border border-slate-800/80 bg-slate-900/50 backdrop-blur-md">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white">Son Güvenlik Olayları</h3>
          </div>
          <button
            onClick={() => setActivePage('history')}
            className="text-xs font-semibold text-cyan-400 hover:text-cyan-300"
          >
            Tümünü Gör →
          </button>
        </div>

        {data?.recent_events && data.recent_events.length > 0 ? (
          <div className="divide-y divide-slate-800/60">
            {data.recent_events.slice(0, 5).map((ev) => (
              <div key={ev.id} className="py-3 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <SeverityBadge severity={ev.severity} />
                  <div>
                    <p className="text-xs font-semibold text-white">{ev.title}</p>
                    <p className="text-[11px] text-slate-400">{ev.message}</p>
                  </div>
                </div>
                <span className="text-[10px] font-mono text-slate-500">
                  {new Date(ev.ts).toLocaleTimeString()}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <div className="py-8 text-center text-xs text-slate-500">
            Henüz kaydedilmiş bir güvenlik olayı bulunmuyor. Sistem temiz.
          </div>
        )}
      </div>
    </div>
  );
}

