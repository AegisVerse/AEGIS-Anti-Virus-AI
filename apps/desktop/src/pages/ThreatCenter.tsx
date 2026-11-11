import React, { useState, useEffect } from 'react';
import { AlertOctagon, ShieldAlert, Archive, Check, EyeOff, Search, Info, FolderOpen, Copy, FileText } from 'lucide-react';
import { callAegis, openPath } from '../services/aegis';
import { useAppStore } from '../stores/useAppStore';
import { SeverityBadge } from '../components/ui/Badge';
import { ConfirmDialog } from '../components/ui/ConfirmDialog';
import type { ThreatRecord, ThreatAction, ThreatStatus, Incident } from '../types/aegis';

export function ThreatCenter() {
  const t = useAppStore((s) => s.t);
  const [threats, setThreats] = useState<ThreatRecord[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [statusFilter, setStatusFilter] = useState<ThreatStatus | 'all'>('active');
  const [selectedThreat, setSelectedThreat] = useState<ThreatRecord | null>(null);
  const [actionPrompt, setActionPrompt] = useState<{ threat: ThreatRecord; action: ThreatAction } | null>(null);

  const fetchData = async () => {
    try {
      const statusArg = statusFilter === 'all' ? null : statusFilter;
      const ths = await callAegis<ThreatRecord[]>({
        cmd: 'list_threats',
        args: { status: statusArg, limit: 50 },
      });
      setThreats(ths);

      const incs = await callAegis<Incident[]>({
        cmd: 'list_incidents',
        args: { status: null, limit: 20 },
      });
      setIncidents(incs);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchData();
  }, [statusFilter]);

  const executeAction = async () => {
    if (!actionPrompt) return;
    try {
      await callAegis({
        cmd: 'threat_action',
        args: { threat_id: actionPrompt.threat.id, action: actionPrompt.action },
      });
      setActionPrompt(null);
      fetchData();
    } catch (e: any) {
      alert(e.message || String(e));
    }
  };

  return (
    <div className="p-8 space-y-8 overflow-y-auto max-h-[calc(100vh-4rem)] scrollbar-thin">
      {/* Header and Filter */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <AlertOctagon className="w-6 h-6 text-rose-400" />
            <span>Tehdit ve Müdahale Merkezi</span>
          </h2>
          <p className="text-xs text-slate-400">
            Tespit edilen zararlı yazılımlar, sezgisel bulgular ve davranışsal güvenlik olayları.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {(['active', 'quarantined', 'allowed', 'all'] as const).map((filter) => (
            <button
              key={filter}
              onClick={() => setStatusFilter(filter)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold capitalize transition-all cursor-pointer ${
                statusFilter === filter
                  ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                  : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              {filter}
            </button>
          ))}
        </div>
      </div>

      {/* Threats Table */}
      <div className="p-6 rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-md space-y-4">
        <h3 className="text-sm font-bold text-white">Tespit Edilen Dosyalar ({threats.length})</h3>

        {threats.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-500">
                <tr>
                  <th className="py-2.5">Tehdit Adı</th>
                  <th className="py-2.5">Önem</th>
                  <th className="py-2.5">Dosya Yolu</th>
                  <th className="py-2.5">Durum</th>
                  <th className="py-2.5 text-right">Eylemler</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {threats.map((t) => {
                  const fileName = t.path ? t.path.split('\\').pop() : '';
                  return (
                    <tr key={t.id} className="hover:bg-slate-900/60 transition-colors">
                      <td className="py-3 font-semibold text-white">
                        <div className="flex items-center gap-1.5">
                          <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30">
                            {t.name}
                          </span>
                        </div>
                      </td>
                      <td className="py-3">
                        <SeverityBadge severity={t.severity} />
                      </td>
                      <td className="py-3 max-w-xs">
                        <div className="space-y-0.5">
                          <div className="font-bold text-slate-200 text-xs flex items-center gap-1 truncate" title={t.path}>
                            <FileText className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                            <span className="truncate">{fileName || t.path}</span>
                          </div>
                          <div className="font-mono text-[10px] text-slate-500 truncate" title={t.path}>
                            {t.path}
                          </div>
                        </div>
                      </td>
                      <td className="py-3">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-slate-800 text-slate-300">
                          {t.status}
                        </span>
                      </td>
                      <td className="py-3 text-right space-x-1.5 whitespace-nowrap">
                        {t.path && (
                          <button
                            type="button"
                            onClick={() => openPath(t.path)}
                            className="px-2.5 py-1 rounded-lg bg-cyan-600/20 text-cyan-300 hover:bg-cyan-600 hover:text-white border border-cyan-500/30 text-[11px] font-semibold cursor-pointer inline-flex items-center gap-1 transition-all"
                            title="Dosya Konumunu Windows Gezgininde Aç"
                          >
                            <FolderOpen className="w-3.5 h-3.5" />
                            <span>Konumu Aç</span>
                          </button>
                        )}
                        {t.status === 'active' && (
                          <>
                            <button
                              onClick={() => setActionPrompt({ threat: t, action: 'quarantine' })}
                              className="px-2.5 py-1 rounded bg-rose-600/20 text-rose-400 hover:bg-rose-600/30 border border-rose-500/30 text-[11px] font-semibold cursor-pointer"
                            >
                              Karantina
                            </button>
                            <button
                              onClick={() => setActionPrompt({ threat: t, action: 'allow' })}
                              className="px-2.5 py-1 rounded bg-emerald-600/20 text-emerald-400 hover:bg-emerald-600/30 border border-emerald-500/30 text-[11px] font-semibold cursor-pointer"
                            >
                              İzin Ver
                            </button>
                          </>
                        )}
                        <button
                          onClick={() => setSelectedThreat(t)}
                          className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700 text-[11px] font-medium cursor-pointer"
                        >
                          Detaylar
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-8 text-center text-xs text-slate-500">
            Bu filtreye uygun herhangi bir tehdit kaydı bulunmamaktadır.
          </div>
        )}
      </div>

      {/* Correlated Incidents Section */}
      <div className="p-6 rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-md space-y-4">
        <h3 className="text-sm font-bold text-white flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-amber-400" />
          <span>Korelasyonlu Davranış Olayları ({incidents.length})</span>
        </h3>

        {incidents.length > 0 ? (
          <div className="space-y-3">
            {incidents.map((inc) => (
              <div
                key={inc.id}
                className="p-4 rounded-xl border border-slate-800 bg-slate-950/60 flex flex-col md:flex-row md:items-center justify-between gap-4"
              >
                <div>
                  <div className="flex items-center gap-3">
                    <SeverityBadge severity={inc.severity} />
                    <h4 className="text-sm font-bold text-white">{inc.title}</h4>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                      Güven: %{inc.confidence}
                    </span>
                  </div>
                  <p className="mt-1 text-xs text-slate-400">{inc.summary}</p>
                  {inc.evidence && inc.evidence.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-2">
                      {inc.evidence.map((ev, idx) => (
                        <span key={idx} className="text-[10px] px-2 py-0.5 rounded bg-slate-900 text-cyan-400 border border-slate-800 font-mono">
                          {ev.indicator} ({ev.weight}p)
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                <span className="px-2.5 py-1 rounded text-xs font-bold uppercase tracking-wider bg-slate-900 text-slate-300 border border-slate-800 self-start md:self-auto">
                  {inc.status}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <div className="py-6 text-center text-xs text-slate-500">
            Açık güvenlik olayı bulunmamaktadır.
          </div>
        )}
      </div>

      {/* Confirmation Dialog */}
      <ConfirmDialog
        isOpen={Boolean(actionPrompt)}
        title={actionPrompt?.action === 'quarantine' ? 'Dosyayı Karantinaya Al' : 'Dosyaya İzin Ver'}
        description={
          actionPrompt?.action === 'quarantine'
            ? `'${actionPrompt?.threat.name}' dosyası güvenli XOR kasasına taşınacak ve orijinal konumundan kaldırılacaktır.`
            : `'${actionPrompt?.threat.name}' dosyasının hash değeri beyaz listeye eklenecek ve gelecekteki taramalarda yoksayılacaktır.`
        }
        danger={actionPrompt?.action === 'quarantine'}
        confirmText={actionPrompt?.action === 'quarantine' ? 'Karantinaya Taşı' : 'İzin Ver'}
        onConfirm={executeAction}
        onCancel={() => setActionPrompt(null)}
      />

      {/* Threat Details Modal */}
      {selectedThreat && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="w-full max-w-2xl p-6 rounded-2xl border border-slate-800 bg-slate-900 space-y-4">
            <div className="flex justify-between items-start">
              <div>
                <h3 className="text-base font-bold text-white">{selectedThreat.name}</h3>
                <p className="text-xs text-slate-400 font-mono">ID: {selectedThreat.id}</p>
              </div>
              <button
                onClick={() => setSelectedThreat(null)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="p-3.5 rounded-xl bg-slate-950 border border-cyan-500/30 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400 font-semibold flex items-center gap-1.5">
                    <FileText className="w-4 h-4 text-cyan-400" />
                    <span>Dosya Konumu:</span>
                  </span>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => navigator.clipboard.writeText(selectedThreat.path)}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold flex items-center gap-1 transition-all cursor-pointer"
                    >
                      <Copy className="w-3.5 h-3.5" />
                      <span>Kopyala</span>
                    </button>
                    {selectedThreat.path && (
                      <button
                        type="button"
                        onClick={() => openPath(selectedThreat.path)}
                        className="px-3 py-1 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold flex items-center gap-1.5 cursor-pointer shadow-lg shadow-cyan-600/20 transition-all"
                      >
                        <FolderOpen className="w-3.5 h-3.5" />
                        <span>Dosya Konumunu Aç (Gezgin)</span>
                      </button>
                    )}
                  </div>
                </div>
                <p className="font-mono text-cyan-300 bg-slate-900/90 p-2.5 rounded-lg break-all select-all border border-slate-800">
                  {selectedThreat.path}
                </p>
              </div>

              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <p className="text-slate-400 font-semibold mb-1">SHA-256 Özeti:</p>
                <p className="font-mono text-slate-300 break-all">{selectedThreat.sha256 || 'N/A'}</p>
              </div>

              <div className="mt-4">
                <h4 className="font-semibold text-white mb-2">Eşleşen Kurallar ve Göstergeler:</h4>
                <div className="space-y-2">
                  {selectedThreat.detections.map((det, i) => (
                    <div key={i} className="p-3 rounded-lg border border-slate-800 bg-slate-950/60">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-rose-400">{det.rule_id}</span>
                        <SeverityBadge severity={det.severity} />
                      </div>
                      <p className="mt-1 text-slate-300">{det.description}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedThreat(null)}
                className="px-4 py-2 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-white"
              >
                Kapat
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

