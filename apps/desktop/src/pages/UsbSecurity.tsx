import React, { useState, useEffect } from 'react';
import { Usb, Search, AlertTriangle, CheckCircle2, ShieldCheck, HardDrive } from 'lucide-react';
import { callAegis } from '../services/aegis';
import { useAppStore } from '../stores/useAppStore';
import type { UsbDrive, Settings } from '../types/aegis';

export function UsbSecurity() {
  const { setActivePage } = useAppStore();
  const [drives, setDrives] = useState<UsbDrive[]>([]);
  const [settings, setSettings] = useState<Settings | null>(null);

  const fetchData = async () => {
    try {
      const drs = await callAegis<UsbDrive[]>({ cmd: 'list_usb_drives' });
      setDrives(drs);
      const s = await callAegis<Settings>({ cmd: 'get_settings' });
      setSettings(s);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 4000);
    return () => clearInterval(interval);
  }, []);

  const handleScan = async (root: string) => {
    try {
      await callAegis({ cmd: 'scan_usb', args: { root } });
      setActivePage('scan');
    } catch (e: any) {
      alert(e.message || String(e));
    }
  };

  const handleToggleAutoScan = async () => {
    if (!settings) return;
    try {
      const updated = { ...settings, usb_scan_on_insert: !settings.usb_scan_on_insert };
      await callAegis({ cmd: 'update_settings', args: { settings: updated } });
      setSettings(updated);
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="p-8 space-y-8 overflow-y-auto max-h-[calc(100vh-4rem)] scrollbar-thin">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <Usb className="w-6 h-6 text-cyan-400" />
          <span>USB & Çıkarılabilir Bellek Güvenliği</span>
        </h2>
        <p className="text-xs text-slate-400">
          USB bellekler, harici diskler ve çıkarılabilir depolama ortamlarında autorun.inf ve gizli zararlı denetimi.
        </p>
      </div>

      {/* Auto-Scan Setting Card */}
      <div className="p-6 rounded-2xl border border-slate-800 bg-slate-900/40 flex items-center justify-between">
        <div>
          <h3 className="text-sm font-bold text-white">USB Takıldığında Otomatik Tara</h3>
          <p className="mt-1 text-xs text-slate-400">
            Yeni bir çıkarılabilir bellek takıldığında kök dizinini ve autorun girdilerini otomatik inceler.
          </p>
        </div>
        <button
          onClick={handleToggleAutoScan}
          className={`px-4 py-2 rounded-xl text-xs font-semibold border transition-all cursor-pointer ${
            settings?.usb_scan_on_insert
              ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
              : 'bg-slate-800 text-slate-400 border-slate-700'
          }`}
        >
          {settings?.usb_scan_on_insert ? 'ETKİN' : 'DEVRE DIŞI'}
        </button>
      </div>

      {/* Connected Drives */}
      <div className="p-6 rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-md space-y-4">
        <h3 className="text-sm font-bold text-white">Bağlı Çıkarılabilir Sürücüler ({drives.length})</h3>

        {drives.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {drives.map((d) => (
              <div
                key={d.root}
                className="p-5 rounded-xl border border-slate-800 bg-slate-950/60 space-y-4"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="p-3 rounded-lg bg-cyan-500/10 text-cyan-400">
                      <HardDrive className="w-6 h-6" />
                    </div>
                    <div>
                      <h4 className="text-sm font-bold text-white">{d.label || d.root}</h4>
                      <p className="text-xs font-mono text-cyan-400">{d.root} ({d.filesystem || 'FAT32'})</p>
                    </div>
                  </div>
                  <button
                    onClick={() => handleScan(d.root)}
                    className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white transition-all cursor-pointer"
                  >
                    <Search className="w-4 h-4" />
                    <span>Sürücüyü Tara</span>
                  </button>
                </div>

                {d.autorun_inf ? (
                  <div className="p-3 rounded-lg border border-rose-500/30 bg-rose-950/30 text-rose-300 text-xs flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
                    <span>Şüpheli autorun.inf dosyası mevcut! Sürücüyü taramanız önerilir.</span>
                  </div>
                ) : (
                  <div className="p-3 rounded-lg border border-slate-800 bg-slate-900/40 text-slate-400 text-xs flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                    <span>Autorun tehdidi tespit edilmedi.</span>
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="py-8 text-center text-xs text-slate-500">
            Şu anda sisteme takılı herhangi bir çıkarılabilir USB sürücü bulunmamaktadır.
          </div>
        )}
      </div>
    </div>
  );
}

