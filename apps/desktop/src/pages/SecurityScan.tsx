import React, { useState, useEffect } from 'react';
import {
  Play,
  Pause,
  Square,
  Search,
  FolderOpen,
  CheckCircle2,
  AlertTriangle,
  Clock,
  FileText,
  RotateCcw,
} from 'lucide-react';
import { callAegis } from '../services/aegis';
import { useAppStore } from '../stores/useAppStore';
import type { ScanProgress, ScanJobSummary, ScanKind } from '../types/aegis';

export function SecurityScan() {
  const t = useAppStore((s) => s.t);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [history, setHistory] = useState<ScanJobSummary[]>([]);
  const [customPath, setCustomPath] = useState('');
  const [loading, setLoading] = useState(false);

  const fetchProgress = async () => {
    try {
      const res = await callAegis<ScanProgress | null>({ cmd: 'get_scan_progress', args: { job_id: null } });
      setProgress(res);
    } catch (e) {
      console.error(e);
    }
  };

  const fetchHistory = async () => {
    try {
      const res = await callAegis<ScanJobSummary[]>({ cmd: 'list_scan_jobs', args: { limit: 10 } });
      setHistory(res);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchProgress();
    fetchHistory();
    const interval = setInterval(() => {
      fetchProgress();
      fetchHistory();
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  const handleStart = async (kind: ScanKind) => {
    setLoading(true);
    try {
      const paths = kind === 'custom' && customPath ? [customPath] : [];
      await callAegis({ cmd: 'start_scan', args: { kind, paths } });
      fetchProgress();
    } catch (e: any) {
      alert(e.message || String(e));
    } finally {
      setLoading(false);
    }
  };

  const handlePause = async () => {
    if (!progress) return;
    try {
      await callAegis({ cmd: 'pause_scan', args: { job_id: progress.job_id } });
      fetchProgress();
    } catch (e) {
      console.error(e);
    }
  };

  const handleResume = async () => {
    if (!progress) return;
    try {
      await callAegis({ cmd: 'resume_scan', args: { job_id: progress.job_id } });
      fetchProgress();
    } catch (e) {
      console.error(e);
    }
  };

  const handleCancel = async () => {
    if (!progress) return;
    try {
      await callAegis({ cmd: 'cancel_scan', args: { job_id: progress.job_id } });
      fetchProgress();
    } catch (e) {
      console.error(e);
    }
  };

  const isScanning = progress && (progress.state === 'running' || progress.state === 'paused');

  return (
    <div className="p-8 space-y-8 overflow-y-auto max-h-[calc(100vh-4rem)] scrollbar-thin">
      {/* Active Scan Progress Card */}
      {isScanning ? (
        <div className="p-6 rounded-2xl border border-cyan-500/30 bg-gradient-to-b from-slate-900 to-slate-950 backdrop-blur-xl shadow-2xl space-y-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-3 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                <Search className="w-6 h-6 animate-pulse" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-white capitalize">
                  {progress.kind} Scan {progress.state === 'paused' ? '(Duraklatıldı)' : 'Çalışıyor'}
                </h3>
                <p className="text-xs text-slate-400 font-mono">Job ID: {progress.job_id}</p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              {progress.state === 'running' ? (
                <button
                  onClick={handlePause}
                  className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30 hover:bg-amber-500/20 transition-all cursor-pointer"
                >
                  <Pause className="w-4 h-4" />
                  <span>{t('actions.pause')}</span>
                </button>
              ) : (
                <button
                  onClick={handleResume}
                  className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/20 transition-all cursor-pointer"
                >
                  <Play className="w-4 h-4" />
                  <span>{t('actions.resume')}</span>
                </button>
              )}
              <button
                onClick={handleCancel}
                className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30 hover:bg-rose-500/20 transition-all cursor-pointer"
              >
                <Square className="w-4 h-4" />
                <span>{t('actions.cancel')}</span>
              </button>
            </div>
          </div>

          {/* Progress bar */}
          <div className="space-y-2">
            <div className="flex justify-between text-xs text-slate-400">
              <span className="truncate max-w-lg font-mono">
                {progress.current_target || 'Dosyalar hazırlanıyor...'}
              </span>
              <span>
                {progress.counters.files_scanned} / {progress.files_discovered || '?'} Dosya
              </span>
            </div>
            <div className="w-full h-2.5 rounded-full bg-slate-800 overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-300"
                style={{
                  width: `${
                    progress.enumeration_complete && progress.files_discovered > 0
                      ? Math.min(100, Math.round((progress.counters.files_scanned / progress.files_discovered) * 100))
                      : 45
                  }%`,
                }}
              />
            </div>
          </div>

          {/* Real-time counters */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="p-3 rounded-xl border border-slate-800 bg-slate-950/60">
              <p className="text-[10px] uppercase font-bold text-slate-500">Taranan Dosyalar</p>
              <p className="mt-1 text-xl font-bold text-white">{progress.counters.files_scanned}</p>
            </div>
            <div className="p-3 rounded-xl border border-slate-800 bg-slate-950/60">
              <p className="text-[10px] uppercase font-bold text-slate-500">Tespit Edilen Tehdit</p>
              <p className="mt-1 text-xl font-bold text-rose-400">{progress.counters.threats_found}</p>
            </div>
            <div className="p-3 rounded-xl border border-slate-800 bg-slate-950/60">
              <p className="text-[10px] uppercase font-bold text-slate-500">Şüpheli Dosyalar</p>
              <p className="mt-1 text-xl font-bold text-amber-400">{progress.counters.suspicious_found}</p>
            </div>
            <div className="p-3 rounded-xl border border-slate-800 bg-slate-950/60">
              <p className="text-[10px] uppercase font-bold text-slate-500">Geçen Süre</p>
              <p className="mt-1 text-xl font-bold text-cyan-400 font-mono">
                {Math.round(progress.elapsed_ms / 1000)}s
              </p>
            </div>
          </div>
        </div>
      ) : null}

      {/* Start Scan Options */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Quick Scan Card */}
        <div className="p-6 rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-md flex flex-col justify-between space-y-4 hover:border-slate-700 transition-all">
          <div>
            <div className="p-3 rounded-xl w-fit bg-cyan-500/10 text-cyan-400 mb-3">
              <Search className="w-6 h-6" />
            </div>
            <h3 className="text-base font-bold text-white">{t('actions.quick_scan')}</h3>
            <p className="mt-1 text-xs text-slate-400 leading-relaxed">
              Downloads, Temp, Başlangıç klasörleri ve yüksek riskli sistem konumlarını hızlıca tarar.
            </p>
          </div>
          <button
            disabled={isScanning || loading}
            onClick={() => handleStart('quick')}
            className="w-full py-2.5 rounded-xl text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white transition-all cursor-pointer"
          >
            {t('actions.quick_scan')} Başlat
          </button>
        </div>

        {/* Full Scan Card */}
        <div className="p-6 rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-md flex flex-col justify-between space-y-4 hover:border-slate-700 transition-all">
          <div>
            <div className="p-3 rounded-xl w-fit bg-blue-500/10 text-blue-400 mb-3">
              <CheckCircle2 className="w-6 h-6" />
            </div>
            <h3 className="text-base font-bold text-white">{t('actions.full_scan')}</h3>
            <p className="mt-1 text-xs text-slate-400 leading-relaxed">
              Tüm bağlı sabit sürücülerdeki tüm erişilebilir dosyaları derinlemesine analiz eder.
            </p>
          </div>
          <button
            disabled={isScanning || loading}
            onClick={() => handleStart('full')}
            className="w-full py-2.5 rounded-xl text-xs font-semibold border border-slate-700 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 transition-all cursor-pointer"
          >
            {t('actions.full_scan')} Başlat
          </button>
        </div>

        {/* Custom Scan Card */}
        <div className="p-6 rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-md flex flex-col justify-between space-y-4 hover:border-slate-700 transition-all">
          <div>
            <div className="p-3 rounded-xl w-fit bg-purple-500/10 text-purple-400 mb-3">
              <FolderOpen className="w-6 h-6" />
            </div>
            <h3 className="text-base font-bold text-white">{t('actions.custom_scan')}</h3>
            <p className="mt-1 text-xs text-slate-400 leading-relaxed">
              Kullanıcı tarafından belirlenen özel bir klasör veya dosya yolunu tarar.
            </p>
            <input
              type="text"
              placeholder="C:\Users\..."
              value={customPath}
              onChange={(e) => setCustomPath(e.target.value)}
              className="mt-3 w-full px-3 py-2 rounded-lg text-xs bg-slate-950 border border-slate-800 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <button
            disabled={isScanning || loading || !customPath}
            onClick={() => handleStart('custom')}
            className="w-full py-2.5 rounded-xl text-xs font-semibold bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white transition-all cursor-pointer"
          >
            {t('actions.custom_scan')} Başlat
          </button>
        </div>
      </div>

      {/* Historical Scans Table */}
      <div className="p-6 rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-md space-y-4">
        <div className="flex items-center gap-2">
          <Clock className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-bold text-white">Geçmiş Tarama Kayıtları</h3>
        </div>

        {history.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-500">
                <tr>
                  <th className="py-2.5">Tür</th>
                  <th className="py-2.5">Durum</th>
                  <th className="py-2.5">Taranan Dosya</th>
                  <th className="py-2.5">Tehdit</th>
                  <th className="py-2.5">Başlangıç</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {history.map((job) => (
                  <tr key={job.job_id} className="hover:bg-slate-900/60">
                    <td className="py-3 font-semibold text-white capitalize">{job.kind}</td>
                    <td className="py-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          job.state === 'completed'
                            ? 'bg-emerald-500/10 text-emerald-400'
                            : job.state === 'cancelled'
                            ? 'bg-amber-500/10 text-amber-400'
                            : 'bg-rose-500/10 text-rose-400'
                        }`}
                      >
                        {job.state}
                      </span>
                    </td>
                    <td className="py-3 font-mono">{job.counters.files_scanned}</td>
                    <td className="py-3 font-mono">
                      {job.counters.threats_found > 0 ? (
                        <span className="text-rose-400 font-bold">{job.counters.threats_found}</span>
                      ) : (
                        <span className="text-emerald-400">0</span>
                      )}
                    </td>
                    <td className="py-3 text-slate-400 font-mono">
                      {new Date(job.started_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-8 text-center text-xs text-slate-500">
            Henüz tamamlanmış tarama kaydı bulunmuyor.
          </div>
        )}
      </div>
    </div>
  );
}

