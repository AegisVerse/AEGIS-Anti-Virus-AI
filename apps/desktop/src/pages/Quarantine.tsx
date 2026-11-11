import React, { useState, useEffect } from 'react';
import { Archive, RotateCcw, Trash2, AlertTriangle, ShieldCheck, CheckCircle2, FolderOpen } from 'lucide-react';
import { callAegis, openPath } from '../services/aegis';
import { useAppStore } from '../stores/useAppStore';
import { SeverityBadge } from '../components/ui/Badge';
import { ConfirmDialog } from '../components/ui/ConfirmDialog';
import type { QuarantineItem } from '../types/aegis';

export function Quarantine() {
  const t = useAppStore((s) => s.t);
  const [items, setItems] = useState<QuarantineItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [restoreItem, setRestoreItem] = useState<QuarantineItem | null>(null);
  const [deleteItem, setDeleteItem] = useState<QuarantineItem | null>(null);
  const [acceptRisk, setAcceptRisk] = useState(false);

  const fetchQuarantine = async () => {
    try {
      const res = await callAegis<QuarantineItem[]>({ cmd: 'list_quarantine' });
      setItems(res);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchQuarantine();
  }, []);

  const executeRestore = async () => {
    if (!restoreItem) return;
    try {
      await callAegis({
        cmd: 'restore_quarantine',
        args: { id: restoreItem.id, accept_risk: acceptRisk, destination_dir: null },
      });
      setRestoreItem(null);
      setAcceptRisk(false);
      fetchQuarantine();
    } catch (e: any) {
      alert(e.message || String(e));
    }
  };

  const executeDelete = async () => {
    if (!deleteItem) return;
    try {
      await callAegis({
        cmd: 'delete_quarantine',
        args: { id: deleteItem.id },
      });
      setDeleteItem(null);
      fetchQuarantine();
    } catch (e: any) {
      alert(e.message || String(e));
    }
  };

  return (
    <div className="p-8 space-y-8 overflow-y-auto max-h-[calc(100vh-4rem)] scrollbar-thin">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <Archive className="w-6 h-6 text-cyan-400" />
          <span>Karantina Kasası</span>
        </h2>
        <p className="text-xs text-slate-400">
          Zararlı veya şüpheli dosyalar rastgele XOR anahtarı ile şifrelenerek izole edilmiştir.
          Sistem üzerinde çalıştırılamaz veya tehlike oluşturamazlar.
        </p>
      </div>

      {/* Items Table */}
      <div className="p-6 rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-md space-y-4">
        <h3 className="text-sm font-bold text-white">İzole Edilen Dosyalar ({items.length})</h3>

        {items.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-500">
                <tr>
                  <th className="py-2.5">Tehdit</th>
                  <th className="py-2.5">Önem</th>
                  <th className="py-2.5">Orijinal Konum</th>
                  <th className="py-2.5">Boyut</th>
                  <th className="py-2.5">Tarih</th>
                  <th className="py-2.5">Durum</th>
                  <th className="py-2.5 text-right">Eylemler</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {items.map((item) => (
                  <tr key={item.id} className="hover:bg-slate-900/60">
                    <td className="py-3 font-semibold text-white">{item.threat_name}</td>
                    <td className="py-3">
                      <SeverityBadge severity={item.severity} />
                    </td>
                    <td className="py-3 font-mono text-[11px] text-slate-400 truncate max-w-xs" title={item.original_path}>
                      {item.original_path}
                    </td>
                    <td className="py-3 font-mono">
                      {Math.round(item.size / 1024)} KB
                    </td>
                    <td className="py-3 text-slate-400 font-mono text-[11px]">
                      {new Date(item.quarantined_at).toLocaleDateString()}
                    </td>
                    <td className="py-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                          item.state === 'stored'
                            ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                            : item.state === 'restored'
                            ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                            : 'bg-slate-500/10 text-slate-400 border border-slate-500/20'
                        }`}
                      >
                        {item.state}
                      </span>
                    </td>
                    <td className="py-3 text-right space-x-1.5 whitespace-nowrap">
                      {item.original_path && (
                        <button
                          type="button"
                          onClick={() => openPath(item.original_path)}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-medium inline-flex items-center gap-1 transition-all cursor-pointer"
                          title="Orijinal Dosya Konumunu Windows Gezgininde Aç"
                        >
                          <FolderOpen className="w-3.5 h-3.5 text-cyan-400" />
                          <span>Konumu Aç</span>
                        </button>
                      )}
                      {item.state === 'stored' && (
                        <>
                          <button
                            onClick={() => {
                              setRestoreItem(item);
                              setAcceptRisk(false);
                            }}
                            className="px-2.5 py-1 rounded bg-cyan-600/20 text-cyan-400 hover:bg-cyan-600/30 border border-cyan-500/30 text-[11px] font-semibold cursor-pointer"
                          >
                            Geri Yükle
                          </button>
                          <button
                            onClick={() => setDeleteItem(item)}
                            className="px-2.5 py-1 rounded bg-rose-600/20 text-rose-400 hover:bg-rose-600/30 border border-rose-500/30 text-[11px] font-semibold cursor-pointer"
                          >
                            Kalıcı Sil
                          </button>
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-8 text-center text-xs text-slate-500">
            Karantina kasasında izole edilmiş herhangi bir dosya bulunmamaktadır.
          </div>
        )}
      </div>

      {/* Restore Risk Modal */}
      {restoreItem && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="w-full max-w-md p-6 rounded-2xl border border-slate-800 bg-slate-900 space-y-4">
            <div className="flex items-center gap-3">
              <div className="p-3 rounded-xl bg-amber-500/10 text-amber-400">
                <AlertTriangle className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white">Dosyayı Geri Yükle</h3>
                <p className="text-xs text-slate-400 font-mono">{restoreItem.threat_name}</p>
              </div>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              Bu dosya orijinal konumuna (<span className="text-cyan-400 font-mono">{restoreItem.original_path}</span>)
              geri çözülerek yazılacaktır.
            </p>

            {(restoreItem.severity === 'high' || restoreItem.severity === 'critical') && (
              <div className="p-3 rounded-lg border border-rose-500/30 bg-rose-950/30 text-rose-300 text-xs flex items-start gap-2">
                <input
                  type="checkbox"
                  id="acceptRiskCheck"
                  checked={acceptRisk}
                  onChange={(e) => setAcceptRisk(e.target.checked)}
                  className="mt-1"
                />
                <label htmlFor="acceptRiskCheck" className="cursor-pointer">
                  <span className="font-bold">Güvenlik Riskini Kabul Ediyorum:</span> Bu dosya yüksek/kritik
                  seviyede zararlı olarak işaretlenmiştir. Geri yüklemenin oluşturabileceği güvenlik tehditlerini
                  onaylıyorum.
                </label>
              </div>
            )}

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => setRestoreItem(null)}
                className="px-4 py-2 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-white"
              >
                İptal
              </button>
              <button
                disabled={
                  (restoreItem.severity === 'high' || restoreItem.severity === 'critical') && !acceptRisk
                }
                onClick={executeRestore}
                className="px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white"
              >
                Geri Yüklemeyi Onayla
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation */}
      <ConfirmDialog
        isOpen={Boolean(deleteItem)}
        title="Karantinadaki Dosyayı Kalıcı Olarak Sil"
        description={`'${deleteItem?.threat_name}' dosyası karantina kasasından tamamen silinecektir. Bu işlem geri alınamaz.`}
        danger={true}
        confirmText="Kalıcı Olarak Sil"
        onConfirm={executeDelete}
        onCancel={() => setDeleteItem(null)}
      />
    </div>
  );
}

