import React, { useState, useEffect } from 'react';
import { HelpCircle, Shield, CheckCircle2, AlertTriangle, FileText, Database, HardDrive, Cpu } from 'lucide-react';
import { callAegis } from '../services/aegis';
import { ModuleBadge } from '../components/ui/Badge';
import type { Diagnostics } from '../types/aegis';

export function AboutDiagnostics() {
  const [diag, setDiag] = useState<Diagnostics | null>(null);

  const fetchDiag = async () => {
    try {
      const res = await callAegis<Diagnostics>({ cmd: 'get_diagnostics' });
      setDiag(res);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchDiag();
  }, []);

  return (
    <div className="p-8 space-y-8 overflow-y-auto max-h-[calc(100vh-4rem)] scrollbar-thin">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <HelpCircle className="w-6 h-6 text-cyan-400" />
          <span>Hakkında & Sistem Tanılama (Diagnostics)</span>
        </h2>
        <p className="text-xs text-slate-400">
          Uygulama çalışma modları, veritabanı bütünlüğü, dosya konumları ve açık kaynak lisans bildirimleri.
        </p>
      </div>

      {/* Main Info Card */}
      <div className="p-6 rounded-2xl border border-slate-800 bg-slate-900/40 backdrop-blur-md space-y-6">
        <div className="flex items-center gap-5">
          <div className="w-16 h-16 relative flex items-center justify-center shrink-0">
            <img
              src="./logo.png"
              alt="AEGIS AI Security Logo"
              className="w-full h-full object-contain drop-shadow-[0_0_20px_rgba(6,182,212,0.6)]"
            />
          </div>
          <div>
            <h3 className="text-xl font-black text-white tracking-wide font-mono flex items-center gap-2">
              <span>AEGIS AI Security</span>
              <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-sans">
                Official Release
              </span>
            </h3>
            <p className="text-xs text-cyan-400 font-mono mt-0.5">
              Sürüm {diag?.version || '0.1.0'} • Protokol v{diag?.protocol_version || '1'} • {diag?.build_profile || 'Release'} (x86_64)
            </p>
            <p className="text-[11px] text-slate-400 mt-1">
              Yeni Nesil Yerel Uç Nokta Güvenliği ve Çok Katmanlı Antivirüs Koruması • Telif Hakkı © 2026 AEGIS AI Security
            </p>
          </div>
        </div>

        {/* Diagnostic Metadata Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 text-xs">
          <div className="p-3.5 rounded-xl border border-slate-800 bg-slate-950/60">
            <span className="text-[10px] uppercase font-bold text-slate-500">Çalışma Modu</span>
            <p className="mt-1 font-semibold text-white capitalize">{diag?.service_mode || 'User Engine'}</p>
          </div>
          <div className="p-3.5 rounded-xl border border-slate-800 bg-slate-950/60">
            <span className="text-[10px] uppercase font-bold text-slate-500">Yönetici Yetkisi</span>
            <p className="mt-1 font-semibold text-white">{diag?.elevated ? 'Evet (SYSTEM/Admin)' : 'Kullanıcı Seviyesi'}</p>
          </div>
          <div className="p-3.5 rounded-xl border border-slate-800 bg-slate-950/60">
            <span className="text-[10px] uppercase font-bold text-slate-500">Veritabanı Bütünlüğü</span>
            <p className="mt-1 font-semibold text-emerald-400 flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> {diag?.db_integrity_ok ? 'Doğrulandı (OK)' : 'Bilinmiyor'}
            </p>
          </div>
          <div className="p-3.5 rounded-xl border border-slate-800 bg-slate-950/60">
            <span className="text-[10px] uppercase font-bold text-slate-500">Platform</span>
            <p className="mt-1 font-semibold text-white font-mono">{diag?.os || 'Windows 10/11 x86_64'}</p>
          </div>
        </div>
      </div>

      {/* Storage and Data Paths */}
      <div className="p-6 rounded-2xl border border-slate-800 bg-slate-900/40 backdrop-blur-md space-y-4">
        <h3 className="text-sm font-bold text-white flex items-center gap-2">
          <Database className="w-4 h-4 text-cyan-400" />
          <span>Veri Depolama ve Kasa Yolları</span>
        </h3>

        <div className="space-y-2 text-xs">
          <div className="p-3 rounded-xl border border-slate-800 bg-slate-950/60 flex flex-col sm:flex-row justify-between sm:items-center gap-1">
            <span className="text-slate-400">SQLite Veritabanı Yolu:</span>
            <span className="font-mono text-cyan-400 break-all">{diag?.db_path || 'aegis.db'}</span>
          </div>
          <div className="p-3 rounded-xl border border-slate-800 bg-slate-950/60 flex flex-col sm:flex-row justify-between sm:items-center gap-1">
            <span className="text-slate-400">Veritabanı Boyutu:</span>
            <span className="font-mono text-white">{Math.round((diag?.db_size_bytes || 0) / 1024)} KB</span>
          </div>
          <div className="p-3 rounded-xl border border-slate-800 bg-slate-950/60 flex flex-col sm:flex-row justify-between sm:items-center gap-1">
            <span className="text-slate-400">Karantina Kasası Konumu:</span>
            <span className="font-mono text-slate-300">{diag?.quarantine_dir || 'Quarantine'}</span>
          </div>
        </div>
      </div>

      {/* Code Signing Notice */}
      <div className="p-5 rounded-2xl border border-slate-800 bg-slate-900/40 text-xs text-slate-300 space-y-2">
        <h4 className="font-bold text-white flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-amber-400" />
          <span>Kod İmzalama ve SmartScreen Bildirimi</span>
        </h4>
        <p className="text-slate-400 leading-relaxed">
          Bu sürüm yerel açık kaynak geliştirme ortamında derlenmiştir. Ticari bir EV (Extended Validation)
          kod imzalama sertifikası yapılandırılmadığı takdirde Windows SmartScreen uyarısı görüntülenebilir.
          AEGIS, sahte bir imza durumu beyan etmez ve sistemde imzasız geliştirme derlemesi olarak şeffaf biçimde çalışır.
        </p>
      </div>

      {/* Licensing and Third-Party Compliance */}
      <div className="p-5 rounded-2xl border border-slate-800 bg-slate-900/40 text-xs text-slate-400 space-y-2">
        <h4 className="font-bold text-white flex items-center gap-2">
          <FileText className="w-4 h-4 text-cyan-400" />
          <span>Lisans ve Üçüncü Taraf Uyumluluğu</span>
        </h4>
        <p className="leading-relaxed">
          AEGIS AI Security, Apache License 2.0 altında dağıtılmaktadır. YARA-X motoru BSD-3-Clause,
          Tauri ve Rust kütüphaneleri MIT/Apache-2.0 lisanslarına tabidir. İsteğe bağlı ClamAV tarayıcı
          entegrasyonu harici CLI olarak çağrılır ve GPLv2 gereksinimlerine tam saygı gösterir.
        </p>
      </div>
    </div>
  );
}

