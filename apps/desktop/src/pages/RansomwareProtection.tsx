import React, { useState, useEffect } from 'react';
import { Lock, ShieldAlert, FolderLock, Plus, Trash2, AlertTriangle, FileCode } from 'lucide-react';
import { callAegis } from '../services/aegis';
import type { RansomwareStatus, Settings } from '../types/aegis';

export function RansomwareProtection() {
  const [status, setStatus] = useState<RansomwareStatus | null>(null);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [newFolder, setNewFolder] = useState('');

  const fetchData = async () => {
    try {
      const st = await callAegis<RansomwareStatus>({ cmd: 'get_ransomware_status' });
      setStatus(st);
      const set = await callAegis<Settings>({ cmd: 'get_settings' });
      setSettings(set);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const addFolder = async () => {
    if (!newFolder || !settings) return;
    try {
      const updated = { ...settings, protected_folders: [...settings.protected_folders, newFolder] };
      await callAegis({ cmd: 'update_settings', args: { settings: updated } });
      setNewFolder('');
      fetchData();
    } catch (e: any) {
      alert(e.message || String(e));
    }
  };

  const removeFolder = async (folder: string) => {
    if (!settings) return;
    try {
      const updated = { ...settings, protected_folders: settings.protected_folders.filter((f) => f !== folder) };
      await callAegis({ cmd: 'update_settings', args: { settings: updated } });
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
          <Lock className="w-6 h-6 text-emerald-400" />
          <span>Fidye Yazılımı Kalkanı (Ransomware Shield)</span>
        </h2>
        <p className="text-xs text-slate-400">
          Korumalı klasörlerdeki ani ve kitlesel dosya değişikliklerini, şifreleme uzantılarını ve fidye notlarını tespit eder.
        </p>
      </div>

      {/* Burst Detection Info Card */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="p-6 rounded-2xl border border-slate-800 bg-slate-900/40 space-y-3">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-emerald-500/10 text-emerald-400">
              <FolderLock className="w-6 h-6" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white">Akıllı Değişiklik Frekans İzleyicisi</h3>
              <p className="text-xs text-slate-400">5 Saniyelik Kayan Zaman Penceresi</p>
            </div>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            5 saniye içinde bir klasörde 25'ten fazla kitlesel dosya değişikliği veya tipik fidye notu
            (README_DECRYPT, HOW_TO_RESTORE) oluşturulduğunda sistem acil alarm üretir.
          </p>
        </div>

        <div className="p-6 rounded-2xl border border-slate-800 bg-slate-900/40 space-y-3">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 text-cyan-400">
              <FileCode className="w-6 h-6" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white">Geliştirici & Yedekleme Koruması</h3>
              <p className="text-xs text-slate-400">Yanlış Alarmlara Karşı Beyaz Liste</p>
            </div>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            Git, Visual Studio, derleyiciler ve Windows yedekleme araçları güvenilir işlem listesindedir.
            Böylece yüksek hacimli derleme ve yedekleme işlemleriniz kesintiye uğramaz.
          </p>
        </div>
      </div>

      {/* Protected Folders Management */}
      <div className="p-6 rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-md space-y-4">
        <h3 className="text-sm font-bold text-white">Korumalı Klasörler Listesi</h3>

        <div className="flex gap-2">
          <input
            type="text"
            placeholder="Klasör yolu ekle (örnek: D:\ProjeBelgeleri)..."
            value={newFolder}
            onChange={(e) => setNewFolder(e.target.value)}
            className="flex-1 px-3 py-2 rounded-lg text-xs bg-slate-950 border border-slate-800 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
          <button
            onClick={addFolder}
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white transition-all cursor-pointer"
          >
            <Plus className="w-4 h-4" />
            <span>Ekle</span>
          </button>
        </div>

        {settings?.protected_folders && settings.protected_folders.length > 0 ? (
          <div className="space-y-2 pt-2">
            {settings.protected_folders.map((f, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between p-3 rounded-xl border border-slate-800 bg-slate-950/60"
              >
                <span className="text-xs font-mono text-cyan-400">{f}</span>
                <button
                  onClick={() => removeFolder(f)}
                  className="p-1 rounded text-slate-500 hover:text-rose-400 transition-colors"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>
        ) : (
          <div className="py-6 text-center text-xs text-slate-500">
            Özel korumalı klasör tanımlanmadı. Standart kullanıcı belgeleri otomatik izlenmektedir.
          </div>
        )}
      </div>

      {/* Honest Backup Disclosure */}
      <div className="p-5 rounded-2xl border border-amber-500/20 bg-amber-950/20 text-amber-300 text-xs flex gap-3 leading-relaxed">
        <AlertTriangle className="w-5 h-5 flex-shrink-0 text-amber-400 mt-0.5" />
        <div>
          <p className="font-semibold text-amber-200">Geri Alma (Rollback) Şeffaflık Bildirimi</p>
          <p className="mt-1 text-slate-300">
            Fidye yazılımı koruması, şüpheli işlemleri tespit ederek yayılmayı durdurmaya odaklanır.
            Gerçek bir dosya geri alma işlemi, Windows Birim Gölge Kopyaları (VSS) veya önceden yapılandırılmış
            harici bir yedekleme bulunmadıkça garanti edilemez. AEGIS, var olmayan bir geri alma yeteneğini asla vaat etmez.
          </p>
        </div>
      </div>
    </div>
  );
}

