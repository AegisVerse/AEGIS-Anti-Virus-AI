import React, { useState, useEffect } from 'react';
import { RefreshCw, CheckCircle2, ShieldCheck, AlertTriangle, FileCode2, KeyRound, Clock, FolderOpen } from 'lucide-react';
import { callAegis } from '../services/aegis';
import type { UpdateStatus } from '../types/aegis';

export function Updates() {
  const [status, setStatus] = useState<UpdateStatus | null>(null);
  const [packPath, setPackPath] = useState('');
  const [loading, setLoading] = useState(false);

  const fetchStatus = async () => {
    try {
      const res = await callAegis<UpdateStatus>({ cmd: 'get_update_status' });
      setStatus(res);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const handleReload = async () => {
    setLoading(true);
    try {
      const res = await callAegis<UpdateStatus>({ cmd: 'reload_rules' });
      setStatus(res);
      alert('YARA kuralları başarıyla yeniden derlendi ve yüklendi.');
    } catch (e: any) {
      alert(e.message || String(e));
    } finally {
      setLoading(false);
    }
  };

  const handleApplyPack = async () => {
    if (!packPath) return;
    setLoading(true);
    try {
      const res = await callAegis<UpdateStatus>({ cmd: 'apply_rule_pack', args: { path: packPath } });
      setStatus(res);
      setPackPath('');
      alert('Kural paketi doğrulandı ve başarıyla uygulandı.');
    } catch (e: any) {
      alert(e.message || String(e));
    } finally {
      setLoading(false);
    }
  };

  const handleClamAvUpdate = async () => {
    try {
      const res = await callAegis<{ message: string }>({ cmd: 'update_clamav_database' });
      alert(res.message);
    } catch (e: any) {
      alert(e.message || String(e));
    }
  };

  return (
    <div className="p-8 space-y-8 overflow-y-auto max-h-[calc(100vh-4rem)] scrollbar-thin">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <RefreshCw className="w-6 h-6 text-cyan-400" />
            <span>Güncellemeler ve İmza Veritabanı</span>
          </h2>
          <p className="text-xs text-slate-400">
            YARA-X tespit kuralları, yerel hash itibar veritabanı ve isteğe bağlı ClamAV entegrasyonu.
          </p>
        </div>

        <button
          disabled={loading}
          onClick={handleReload}
          className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white transition-all cursor-pointer"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Kuralları Yeniden Derle</span>
        </button>
      </div>

      {/* Rules & Hash Status Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <div className="p-5 rounded-2xl border border-slate-800 bg-slate-900/40">
          <p className="text-[10px] uppercase font-bold text-slate-500">YARA Kuralları Sürümü</p>
          <p className="mt-1 text-2xl font-bold text-cyan-400 font-mono">
            {status?.rules_version || '2026.11.1'}
          </p>
          <p className="mt-1 text-xs text-slate-400">
            Son Yükleme: {status?.rules_loaded_at ? new Date(status.rules_loaded_at).toLocaleDateString() : 'Bugün'}
          </p>
        </div>

        <div className="p-5 rounded-2xl border border-slate-800 bg-slate-900/40">
          <p className="text-[10px] uppercase font-bold text-slate-500">Yerel Hash Veritabanı</p>
          <p className="mt-1 text-2xl font-bold text-emerald-400 font-mono">
            {status?.hash_db_entries ?? 0} Kayıt
          </p>
          <p className="mt-1 text-xs text-slate-400">Çevrimdışı doğrulanmış SHA-256 imzaları</p>
        </div>

        <div className="p-5 rounded-2xl border border-slate-800 bg-slate-900/40 flex flex-col justify-between">
          <div>
            <p className="text-[10px] uppercase font-bold text-slate-500">ClamAV İsteğe Bağlı Motor</p>
            <p className="mt-1 text-sm font-bold text-white capitalize">{status?.clamav_state || 'Not Installed'}</p>
            <p className="mt-1 text-[11px] text-slate-400 truncate">{status?.clamav_detail}</p>
          </div>
          <button
            onClick={handleClamAvUpdate}
            className="mt-2 w-fit px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 font-medium cursor-pointer"
          >
            Veritabanını Kontrol Et
          </button>
        </div>
      </div>

      {/* Apply Rule Pack */}
      <div className="p-6 rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-md space-y-4">
        <h3 className="text-sm font-bold text-white flex items-center gap-2">
          <FolderOpen className="w-4 h-4 text-cyan-400" />
          <span>Harici Kural Paketi Uygula</span>
        </h3>
        <p className="text-xs text-slate-400">
          Yeni .yar dosyaları içeren bir klasör yolunu girerek sözdizimini doğrulayın ve aktif kural kütüphanesine ekleyin.
        </p>

        <div className="flex gap-2">
          <input
            type="text"
            placeholder="Kural paketi klasör yolu (örnek: C:\Downloads\aegis-rules-pack)..."
            value={packPath}
            onChange={(e) => setPackPath(e.target.value)}
            className="flex-1 px-3 py-2 rounded-lg text-xs bg-slate-950 border border-slate-800 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
          <button
            disabled={loading || !packPath}
            onClick={handleApplyPack}
            className="px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white transition-all cursor-pointer"
          >
            Paketi Doğrula ve Uygula
          </button>
        </div>
      </div>

      {/* Active Rule Sets Table */}
      <div className="p-6 rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-md space-y-4">
        <h3 className="text-sm font-bold text-white">Yüklü YARA-X Kural Setleri ({status?.rule_sets.length || 0})</h3>

        {status?.rule_sets && status.rule_sets.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-500">
                <tr>
                  <th className="py-2.5">Kural Dosyası</th>
                  <th className="py-2.5">Kaynak</th>
                  <th className="py-2.5">Lisans</th>
                  <th className="py-2.5">Sürüm</th>
                  <th className="py-2.5">Kural Sayısı</th>
                  <th className="py-2.5 text-right">Derleme Durumu</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {status.rule_sets.map((rs, idx) => (
                  <tr key={idx} className="hover:bg-slate-900/60">
                    <td className="py-3 font-semibold text-white font-mono">{rs.file}</td>
                    <td className="py-3 text-slate-400">{rs.source}</td>
                    <td className="py-3 font-mono text-[11px] text-slate-400">{rs.license}</td>
                    <td className="py-3 font-mono text-cyan-400">{rs.version}</td>
                    <td className="py-3 font-mono">{rs.rule_count}</td>
                    <td className="py-3 text-right">
                      {rs.compiled_ok ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-500/10 text-emerald-400">
                          Başarılı
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-rose-500/10 text-rose-400" title={rs.error || ''}>
                          Hata
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-8 text-center text-xs text-slate-500">
            Yüklü kural seti bulunmuyor.
          </div>
        )}
      </div>

      {/* Update History */}
      <div className="p-6 rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-md space-y-4">
        <h3 className="text-sm font-bold text-white flex items-center gap-2">
          <Clock className="w-4 h-4 text-cyan-400" />
          <span>Güncelleme Geçmişi</span>
        </h3>

        {status?.history && status.history.length > 0 ? (
          <div className="divide-y divide-slate-800/60 text-xs">
            {status.history.map((h) => (
              <div key={h.id} className="py-2.5 flex items-center justify-between">
                <div>
                  <span className="font-semibold text-white capitalize">{h.component}: </span>
                  <span className="text-slate-400">{h.message}</span>
                </div>
                <span className="font-mono text-[11px] text-slate-500">
                  {new Date(h.ts).toLocaleString()}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <div className="py-6 text-center text-xs text-slate-500">
            Henüz güncelleme geçmişi kaydedilmedi.
          </div>
        )}
      </div>
    </div>
  );
}

