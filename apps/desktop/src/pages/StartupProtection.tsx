import React, { useState, useEffect } from 'react';
import { Sliders, ShieldCheck, ShieldAlert, RotateCcw, Ban, CheckCircle2, History } from 'lucide-react';
import { callAegis } from '../services/aegis';
import { ConfirmDialog } from '../components/ui/ConfirmDialog';
import type { StartupItem, StartupBackup } from '../types/aegis';

export function StartupProtection() {
  const [items, setItems] = useState<StartupItem[]>([]);
  const [backups, setBackups] = useState<StartupBackup[]>([]);
  const [disableTarget, setDisableTarget] = useState<StartupItem | null>(null);

  const fetchData = async () => {
    try {
      const its = await callAegis<StartupItem[]>({ cmd: 'list_startup_items' });
      setItems(its);
      const bks = await callAegis<StartupBackup[]>({ cmd: 'list_startup_backups' });
      setBackups(bks);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleDisable = async () => {
    if (!disableTarget) return;
    try {
      await callAegis({
        cmd: 'disable_startup_item',
        args: { id: disableTarget.id, confirm: true },
      });
      setDisableTarget(null);
      fetchData();
    } catch (e: any) {
      alert(e.message || String(e));
    }
  };

  const handleRestore = async (backupId: string) => {
    try {
      await callAegis({ cmd: 'restore_startup_item', args: { backup_id: backupId } });
      fetchData();
    } catch (e: any) {
      alert(e.message || String(e));
    }
  };

  return (
    <div className="p-8 space-y-8 overflow-y-auto max-h-[calc(100vh-4rem)] scrollbar-thin">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <Sliders className="w-6 h-6 text-cyan-400" />
          <span>Başlangıç ve Kalıcılık Koruyucusu (Startup Guardian)</span>
        </h2>
        <p className="text-xs text-slate-400">
          Windows açılışında otomatik çalışan kayıt defteri Run/RunOnce anahtarları ve Başlangıç klasörü öğeleri.
        </p>
      </div>

      {/* Items Table */}
      <div className="p-6 rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-md space-y-4">
        <h3 className="text-sm font-bold text-white">Başlangıç Kayıtları ({items.length})</h3>

        {items.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-500">
                <tr>
                  <th className="py-2.5">Ad</th>
                  <th className="py-2.5">Kapsam</th>
                  <th className="py-2.5">Komut / Dosya Yolu</th>
                  <th className="py-2.5">İmza</th>
                  <th className="py-2.5">Değerlendirme</th>
                  <th className="py-2.5 text-right">Eylem</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {items.map((item) => (
                  <tr key={item.id} className="hover:bg-slate-900/60">
                    <td className="py-3 font-semibold text-white">{item.name}</td>
                    <td className="py-3 font-mono text-[11px] text-slate-400">{item.scope}</td>
                    <td className="py-3 font-mono text-[11px] text-slate-400 truncate max-w-xs" title={item.command}>
                      {item.command}
                    </td>
                    <td className="py-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          item.signature?.status === 'valid'
                            ? 'bg-emerald-500/10 text-emerald-400'
                            : 'bg-slate-500/10 text-slate-400'
                        }`}
                      >
                        {item.signature?.status || 'Bilinmiyor'}
                      </span>
                    </td>
                    <td className="py-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          item.assessment === 'trusted'
                            ? 'bg-emerald-500/10 text-emerald-400'
                            : 'bg-amber-500/10 text-amber-400'
                        }`}
                      >
                        {item.assessment}
                      </span>
                    </td>
                    <td className="py-3 text-right">
                      {item.can_disable && (
                        <button
                          onClick={() => setDisableTarget(item)}
                          className="px-2.5 py-1 rounded bg-amber-600/20 text-amber-400 hover:bg-amber-600/30 border border-amber-500/30 text-[11px] font-semibold cursor-pointer"
                        >
                          Devre Dışı Bırak
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-8 text-center text-xs text-slate-500">
            Kayıtlı başlangıç öğesi bulunamadı.
          </div>
        )}
      </div>

      {/* Backups / Safe Recovery */}
      <div className="p-6 rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-md space-y-4">
        <h3 className="text-sm font-bold text-white flex items-center gap-2">
          <History className="w-4 h-4 text-cyan-400" />
          <span>Güvenli Geri Yükleme Yedekleri ({backups.length})</span>
        </h3>

        {backups.length > 0 ? (
          <div className="space-y-3">
            {backups.map((b) => (
              <div
                key={b.id}
                className="p-3.5 rounded-xl border border-slate-800 bg-slate-950/60 flex items-center justify-between gap-4"
              >
                <div>
                  <div className="flex items-center gap-2">
                    <p className="text-xs font-bold text-white">{b.item_name}</p>
                    <span className="text-[10px] font-mono text-slate-500">
                      {new Date(b.created_at).toLocaleString()}
                    </span>
                  </div>
                  <p className="text-[11px] font-mono text-slate-400 truncate max-w-lg mt-0.5">
                    {b.value}
                  </p>
                </div>
                <div>
                  {b.restored ? (
                    <span className="text-[11px] font-semibold text-emerald-400 flex items-center gap-1">
                      <CheckCircle2 className="w-3.5 h-3.5" /> Geri Yüklendi
                    </span>
                  ) : (
                    <button
                      onClick={() => handleRestore(b.id)}
                      className="px-3 py-1 rounded-lg bg-cyan-600/20 text-cyan-400 hover:bg-cyan-600/30 border border-cyan-500/30 text-xs font-semibold cursor-pointer flex items-center gap-1.5"
                    >
                      <RotateCcw className="w-3.5 h-3.5" />
                      <span>Geri Yükle</span>
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="py-6 text-center text-xs text-slate-500">
            Henüz devre dışı bırakılmış ve yedeklenmiş bir başlangıç girdisi bulunmuyor.
          </div>
        )}
      </div>

      {/* Disable Confirmation */}
      <ConfirmDialog
        isOpen={Boolean(disableTarget)}
        title="Başlangıç Girdisini Devre Dışı Bırak"
        description={`'${disableTarget?.name}' girdisi kayıt defterinden kaldırılmadan önce otomatik olarak yedeklenecektir. İstediğiniz zaman bu sayfadan geri yükleyebilirsiniz.`}
        danger={false}
        confirmText="Devre Dışı Bırak ve Yedekle"
        onConfirm={handleDisable}
        onCancel={() => setDisableTarget(null)}
      />
    </div>
  );
}

