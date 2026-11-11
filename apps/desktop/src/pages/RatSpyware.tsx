import React, { useState, useEffect } from 'react';
import { Eye, ShieldAlert, Terminal, AlertTriangle, CheckCircle, FileCode2 } from 'lucide-react';
import { callAegis } from '../services/aegis';
import { SeverityBadge } from '../components/ui/Badge';
import type { Incident, IncidentStatus } from '../types/aegis';

export function RatSpyware() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchIncidents = async () => {
    try {
      const res = await callAegis<Incident[]>({
        cmd: 'list_incidents',
        args: { status: null, limit: 50 },
      });
      const filtered = res.filter((i) =>
        ['remote_access_trojan', 'spyware', 'suspicious_script', 'security_tampering'].includes(i.kind)
      );
      setIncidents(filtered);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, []);

  const updateStatus = async (id: string, status: IncidentStatus) => {
    try {
      await callAegis({ cmd: 'update_incident', args: { id, status } });
      fetchIncidents();
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="p-8 space-y-8 overflow-y-auto max-h-[calc(100vh-4rem)] scrollbar-thin">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <Eye className="w-6 h-6 text-purple-400" />
          <span>RAT & Casus Yazılım Avcısı</span>
        </h2>
        <p className="text-xs text-slate-400">
          Ofis ve tarayıcı işlemlerinden başlatılan gizli scriptler, PowerShell indirme tuzakları ve bellek tahrifatı analizi.
        </p>
      </div>

      {/* Heuristics Capabilities Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <div className="p-5 rounded-2xl border border-slate-800 bg-slate-900/40">
          <div className="p-2.5 rounded-xl bg-purple-500/10 text-purple-400 w-fit mb-3">
            <Terminal className="w-5 h-5" />
          </div>
          <h4 className="text-sm font-bold text-white">Anormal İşlem Soybağı</h4>
          <p className="mt-1 text-xs text-slate-400 leading-relaxed">
            Word, Excel veya Acrobat gibi uygulamaların gizli komut istemi veya PowerShell başlatmasını yakalar.
          </p>
        </div>
        <div className="p-5 rounded-2xl border border-slate-800 bg-slate-900/40">
          <div className="p-2.5 rounded-xl bg-cyan-500/10 text-cyan-400 w-fit mb-3">
            <FileCode2 className="w-5 h-5" />
          </div>
          <h4 className="text-sm font-bold text-white">Kodlanmış Script Tespiti</h4>
          <p className="mt-1 text-xs text-slate-400 leading-relaxed">
            Base64 ile şifrelenmiş veya pencere gizleme parametreleri (-w hidden) içeren betik çalışmalarını analiz eder.
          </p>
        </div>
        <div className="p-5 rounded-2xl border border-slate-800 bg-slate-900/40">
          <div className="p-2.5 rounded-xl bg-rose-500/10 text-rose-400 w-fit mb-3">
            <AlertTriangle className="w-5 h-5" />
          </div>
          <h4 className="text-sm font-bold text-white">Kimlik Bilgisi Avcılığı</h4>
          <p className="mt-1 text-xs text-slate-400 leading-relaxed">
            LSASS tahrifatı veya tarayıcı şifre depolarına yönelik yetkisiz bellek okuma girişimlerini tespit eder.
          </p>
        </div>
      </div>

      {/* Incident List */}
      <div className="p-6 rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-md space-y-4">
        <h3 className="text-sm font-bold text-white">Tespit Edilen Olaylar ({incidents.length})</h3>

        {incidents.length > 0 ? (
          <div className="space-y-4">
            {incidents.map((inc) => (
              <div
                key={inc.id}
                className="p-5 rounded-xl border border-slate-800 bg-slate-950/60 space-y-3"
              >
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-2">
                  <div className="flex items-center gap-3">
                    <SeverityBadge severity={inc.severity} />
                    <h4 className="text-sm font-bold text-white">{inc.title}</h4>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-purple-400 border border-purple-500/20">
                      Güven: %{inc.confidence}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => updateStatus(inc.id, 'resolved')}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-semibold cursor-pointer"
                    >
                      Çözüldü Olarak İşaretle
                    </button>
                    <button
                      onClick={() => updateStatus(inc.id, 'false_positive')}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 text-[11px] font-semibold cursor-pointer"
                    >
                      Yanlış Alarm
                    </button>
                  </div>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed">{inc.summary}</p>

                {inc.process && (
                  <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800 text-[11px] font-mono text-slate-300 flex flex-wrap gap-4">
                    <span>PID: <strong className="text-white">{inc.process.pid}</strong></span>
                    <span>İşlem: <strong className="text-cyan-400">{inc.process.name}</strong></span>
                    <span>Üst İşlem: <strong className="text-amber-400">{inc.process.parent_name || 'N/A'}</strong></span>
                  </div>
                )}

                {/* Evidence List */}
                <div className="space-y-1.5 pt-1">
                  <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Kanıt Göstergeleri</p>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    {inc.evidence.map((ev, i) => (
                      <div key={i} className="p-2.5 rounded-lg bg-slate-900/50 border border-slate-800/80 text-[11px]">
                        <div className="flex justify-between items-center text-cyan-400 font-mono text-[10px]">
                          <span>{ev.indicator}</span>
                          <span>Ağırlık: {ev.weight}</span>
                        </div>
                        <p className="mt-1 text-slate-400">{ev.detail}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="py-8 text-center text-xs text-slate-500">
            Aktif RAT veya casus yazılım olayı tespit edilmedi. Sistem telemetrisi temiz.
          </div>
        )}
      </div>
    </div>
  );
}

