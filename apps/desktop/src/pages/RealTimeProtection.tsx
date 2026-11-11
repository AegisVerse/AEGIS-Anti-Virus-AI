import React, { useState, useEffect } from 'react';
import { Activity, ShieldCheck, ShieldAlert, PauseCircle, PlayCircle, Clock, AlertTriangle } from 'lucide-react';
import { callAegis } from '../services/aegis';
import { useAppStore } from '../stores/useAppStore';
import { SeverityBadge } from '../components/ui/Badge';
import type { SecurityEvent, Settings } from '../types/aegis';

export function RealTimeProtection() {
  const t = useAppStore((s) => s.t);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    try {
      const s = await callAegis<Settings>({ cmd: 'get_settings' });
      setSettings(s);
      const evs = await callAegis<SecurityEvent[]>({
        cmd: 'list_events',
        args: { category: 'real_time', min_severity: null, before_id: null, limit: 15 },
      });
      setEvents(evs);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleToggle = async (enabled: boolean, pauseMinutes?: number) => {
    try {
      const updated = await callAegis<Settings>({
        cmd: 'set_realtime',
        args: { enabled, pause_minutes: pauseMinutes ?? null },
      });
      setSettings(updated);
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="p-8 space-y-8 overflow-y-auto max-h-[calc(100vh-4rem)] scrollbar-thin">
      {/* Control Banner */}
      <div className="p-6 rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-md flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div className="flex items-center gap-4">
          <div
            className={`p-3.5 rounded-2xl ${
              settings?.realtime_enabled
                ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
            }`}
          >
            <Activity className="w-8 h-8" />
          </div>
          <div>
            <div className="flex items-center gap-3">
              <h3 className="text-lg font-bold text-white">Gerçek Zamanlı Dosya Kalkanı</h3>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                  settings?.realtime_enabled
                    ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                    : 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                }`}
              >
                {settings?.realtime_enabled ? 'AKTİF' : 'DEVRE DIŞI'}
              </span>
            </div>
            <p className="mt-1 text-xs text-slate-300">
              Kullanıcı indirmeleri, geçici dosyalar ve başlangıç dizinlerini yazma anında tarar.
            </p>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-3">
          {settings?.realtime_enabled ? (
            <>
              <button
                onClick={() => handleToggle(true, 15)}
                className="flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-medium border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors cursor-pointer"
              >
                <Clock className="w-3.5 h-3.5 text-amber-400" />
                <span>15 Dk Duraklat</span>
              </button>
              <button
                onClick={() => handleToggle(false)}
                className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white transition-colors cursor-pointer"
              >
                <PauseCircle className="w-4 h-4" />
                <span>Kapat</span>
              </button>
            </>
          ) : (
            <button
              onClick={() => handleToggle(true)}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white transition-colors cursor-pointer"
            >
              <PlayCircle className="w-4 h-4" />
              <span>Korumayı Etkinleştir</span>
            </button>
          )}
        </div>
      </div>

      {/* Honest Technical Limitation Disclosure */}
      <div className="p-5 rounded-2xl border border-amber-500/20 bg-amber-950/20 text-amber-300 text-xs flex gap-3 leading-relaxed">
        <AlertTriangle className="w-5 h-5 flex-shrink-0 text-amber-400 mt-0.5" />
        <div>
          <p className="font-semibold text-amber-200">Teknik Çalışma Prensibi ve Bildirim</p>
          <p className="mt-1 text-slate-300">
            Mevcut gerçek zamanlı dosya izleme mekanizması, Windows ReadDirectoryChangesW dosya sistemi olaylarını
            kullanır. Dosya diske yazıldığı anda (post-write) hemen taranır ve karantinaya alınır. Çekirdek seviyesinde
            (Kernel Minifilter Driver) yürütme öncesi senkron engelleme, imzasız sürücü yükleme riskini önlemek
            amacıyla bu ilk sürümde ayrılmıştır ve Microsoft Defender ile güvenli şekilde eşzamanlı çalışır.
          </p>
        </div>
      </div>

      {/* Recent Intercepted Events */}
      <div className="p-6 rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-md space-y-4">
        <h4 className="text-sm font-bold text-white flex items-center gap-2">
          <Clock className="w-4 h-4 text-cyan-400" />
          <span>Gerçek Zamanlı Müdahale Olayları</span>
        </h4>

        {events.length > 0 ? (
          <div className="divide-y divide-slate-800/60">
            {events.map((ev) => (
              <div key={ev.id} className="py-3 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <SeverityBadge severity={ev.severity} />
                  <div>
                    <p className="text-xs font-semibold text-white">{ev.title}</p>
                    <p className="text-[11px] text-slate-400">{ev.message}</p>
                  </div>
                </div>
                <span className="text-[10px] font-mono text-slate-500">
                  {new Date(ev.ts).toLocaleString()}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <div className="py-8 text-center text-xs text-slate-500">
            Gerçek zamanlı kalkan tarafından son zamanlarda engellenen bir tehdit bulunmuyor.
          </div>
        )}
      </div>
    </div>
  );
}

