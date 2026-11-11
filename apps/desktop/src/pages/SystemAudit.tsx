import React, { useState, useEffect } from 'react';
import { FileCheck2, CheckCircle2, AlertTriangle, XCircle, RefreshCw, ExternalLink, ShieldCheck } from 'lucide-react';
import { callAegis } from '../services/aegis';
import type { AuditReport, AuditStatus } from '../types/aegis';

export function SystemAudit() {
  const [report, setReport] = useState<AuditReport | null>(null);
  const [loading, setLoading] = useState(false);

  const fetchAudit = async () => {
    setLoading(true);
    try {
      const res = await callAegis<AuditReport>({ cmd: 'run_audit' });
      setReport(res);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAudit();
  }, []);

  const statusIcon = (st: AuditStatus) => {
    switch (st) {
      case 'pass':
        return <CheckCircle2 className="w-5 h-5 text-emerald-400" />;
      case 'warning':
        return <AlertTriangle className="w-5 h-5 text-amber-400" />;
      case 'fail':
        return <XCircle className="w-5 h-5 text-rose-400" />;
      default:
        return <AlertTriangle className="w-5 h-5 text-slate-400" />;
    }
  };

  return (
    <div className="p-8 space-y-8 overflow-y-auto max-h-[calc(100vh-4rem)] scrollbar-thin">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <FileCheck2 className="w-6 h-6 text-cyan-400" />
            <span>Sistem Güvenlik Denetimi (System Audit)</span>
          </h2>
          <p className="text-xs text-slate-400">
            Windows Defender durumu, Güvenlik Duvarı profilleri, UAC seviyesi ve Güvenli Önyükleme (Secure Boot) yapılandırması.
          </p>
        </div>

        <button
          disabled={loading}
          onClick={fetchAudit}
          className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white transition-all cursor-pointer"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Denetimi Yenile</span>
        </button>
      </div>

      {/* Audit Meta Banner */}
      <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40 text-xs text-slate-300 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ShieldCheck className="w-5 h-5 text-emerald-400" />
          <span>İşletim Sistemi: <strong className="text-white">{report?.os_caption || 'Windows 10/11'}</strong></span>
        </div>
        <span className="font-mono text-slate-400">
          Son Denetim: {report?.generated_at ? new Date(report.generated_at).toLocaleTimeString() : 'N/A'}
        </span>
      </div>

      {/* Audit Checks List */}
      <div className="space-y-4">
        {report?.checks.map((chk) => (
          <div
            key={chk.id}
            className="p-5 rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-md space-y-3"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                {statusIcon(chk.status)}
                <div>
                  <h4 className="text-sm font-bold text-white">{chk.title}</h4>
                  <span className="text-[10px] uppercase font-bold text-cyan-400 tracking-wider">
                    {chk.category}
                  </span>
                </div>
              </div>
              <span
                className={`px-2.5 py-0.5 rounded text-[10px] font-bold uppercase ${
                  chk.status === 'pass'
                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                    : chk.status === 'warning'
                    ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                    : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                }`}
              >
                {chk.status}
              </span>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">{chk.detail}</p>

            {chk.recommendation && (
              <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 text-[11px] text-slate-400">
                <strong className="text-white">Öneri:</strong> {chk.recommendation}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

