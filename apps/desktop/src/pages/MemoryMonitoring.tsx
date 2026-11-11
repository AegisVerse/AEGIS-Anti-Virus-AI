import React, { useState, useEffect } from 'react';
import { Cpu, ShieldCheck, ShieldAlert, Pause, Play, AlertTriangle, Search } from 'lucide-react';
import { callAegis } from '../services/aegis';
import { ConfirmDialog } from '../components/ui/ConfirmDialog';
import type { ProcessInfo, MemoryOverview } from '../types/aegis';

export function MemoryMonitoring() {
  const [overview, setOverview] = useState<MemoryOverview | null>(null);
  const [search, setSearch] = useState('');
  const [suspendTarget, setSuspendTarget] = useState<ProcessInfo | null>(null);

  const fetchOverview = async () => {
    try {
      const res = await callAegis<MemoryOverview>({ cmd: 'get_memory_overview' });
      setOverview(res);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchOverview();
    const interval = setInterval(fetchOverview, 4000);
    return () => clearInterval(interval);
  }, []);

  const handleSuspend = async () => {
    if (!suspendTarget) return;
    try {
      await callAegis({
        cmd: 'suspend_process',
        args: { pid: suspendTarget.pid, incident_id: null, confirm: true },
      });
      setSuspendTarget(null);
      fetchOverview();
    } catch (e: any) {
      alert(e.message || String(e));
    }
  };

  const handleResume = async (pid: number) => {
    try {
      await callAegis({ cmd: 'resume_process', args: { pid } });
      fetchOverview();
    } catch (e: any) {
      alert(e.message || String(e));
    }
  };

  const filteredProcesses = (overview?.processes || []).filter(
    (p) =>
      p.name.toLowerCase().includes(search.toLowerCase()) ||
      String(p.pid).includes(search) ||
      (p.parent_name && p.parent_name.toLowerCase().includes(search.toLowerCase()))
  );

  return (
    <div className="p-8 space-y-8 overflow-y-auto max-h-[calc(100vh-4rem)] scrollbar-thin">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <Cpu className="w-6 h-6 text-cyan-400" />
          <span>Bellek Denetçisi ve İşlem İzleme</span>
        </h2>
        <p className="text-xs text-slate-400">
          Çalışan Windows işlemleri, bellek ayak izi, kod imzalama doğrulaması ve güvenli işlem askıya alma.
        </p>
      </div>

      {/* Limitations note */}
      <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/60 text-xs text-slate-300 space-y-1">
        <p className="font-semibold text-white flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-cyan-400" />
          <span>Sistem Bütünlüğü ve Koruma İlkesi</span>
        </p>
        <p className="text-slate-400 leading-relaxed">
          AEGIS Memory Guardian, işlemlere zararlı kod enjekte etmez veya güvenli çekirdek korumalarını
          (Protected Process Light / PPL) baypas etmeye çalışmaz. Kritik Windows işlemleri otomatik olarak
          koruma altına alınır ve sistem çökmesini önlemek için asla askıya alınamaz.
        </p>
      </div>

      {/* Processes Table */}
      <div className="p-6 rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-md space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <h3 className="text-sm font-bold text-white">
            Aktif İşlemler ({filteredProcesses.length})
          </h3>
          <div className="relative">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="İşlem adı veya PID ara..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9 pr-3 py-1.5 rounded-lg text-xs bg-slate-950 border border-slate-800 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-64"
            />
          </div>
        </div>

        <div className="overflow-x-auto max-h-96 overflow-y-auto scrollbar-thin">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="sticky top-0 bg-slate-900 border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-500">
              <tr>
                <th className="py-2.5">İşlem Adı</th>
                <th className="py-2.5">PID</th>
                <th className="py-2.5">Üst İşlem</th>
                <th className="py-2.5">Bellek (RAM)</th>
                <th className="py-2.5">İmza Durumu</th>
                <th className="py-2.5 text-right">Eylemler</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredProcesses.map((p) => (
                <tr key={p.pid} className="hover:bg-slate-900/60">
                  <td className="py-3 font-semibold text-white flex items-center gap-2">
                    <span>{p.name}</span>
                    {p.critical && (
                      <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-blue-500/10 text-blue-400 border border-blue-500/20">
                        SİSTEM
                      </span>
                    )}
                  </td>
                  <td className="py-3 font-mono text-slate-400">{p.pid}</td>
                  <td className="py-3 text-slate-400">{p.parent_name || 'N/A'}</td>
                  <td className="py-3 font-mono">
                    {p.working_set_bytes ? `${Math.round(p.working_set_bytes / (1024 * 1024))} MB` : 'N/A'}
                  </td>
                  <td className="py-3">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        p.signature?.status === 'valid'
                          ? 'bg-emerald-500/10 text-emerald-400'
                          : 'bg-slate-500/10 text-slate-400'
                      }`}
                    >
                      {p.signature?.status || 'Bilinmiyor'}
                    </span>
                  </td>
                  <td className="py-3 text-right">
                    {!p.critical && (
                      <div className="space-x-1.5">
                        <button
                          onClick={() => setSuspendTarget(p)}
                          className="px-2.5 py-1 rounded bg-amber-600/20 text-amber-400 hover:bg-amber-600/30 border border-amber-500/30 text-[11px] font-semibold cursor-pointer"
                        >
                          Askıya Al
                        </button>
                        <button
                          onClick={() => handleResume(p.pid)}
                          className="px-2.5 py-1 rounded bg-emerald-600/20 text-emerald-400 hover:bg-emerald-600/30 border border-emerald-500/30 text-[11px] font-semibold cursor-pointer"
                        >
                          Sürdür
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Suspend Confirmation Dialog */}
      <ConfirmDialog
        isOpen={Boolean(suspendTarget)}
        title="İşlemi Askıya Al"
        description={`'${suspendTarget?.name}' (PID ${suspendTarget?.pid}) işleminin tüm iş parçacıkları askıya alınacaktır. İşlem yanıt vermeyi durduracak ancak hafızası korunacaktır.`}
        danger={true}
        confirmText="İşlemi Askıya Al"
        onConfirm={handleSuspend}
        onCancel={() => setSuspendTarget(null)}
      />
    </div>
  );
}

