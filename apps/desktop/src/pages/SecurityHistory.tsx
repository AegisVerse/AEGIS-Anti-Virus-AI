import React, { useState, useEffect } from 'react';
import {
  History,
  Download,
  Trash2,
  BarChart3,
  FolderOpen,
  Info,
  X,
  ShieldAlert,
  FileText,
  CheckCircle2,
  Copy,
  ExternalLink,
  AlertTriangle,
  Folder,
} from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { callAegis, openPath } from '../services/aegis';
import { SeverityBadge } from '../components/ui/Badge';
import { ConfirmDialog } from '../components/ui/ConfirmDialog';
import type { SecurityEvent, HistoryStats, EventCategory, Severity } from '../types/aegis';

interface ParsedEvent {
  filePath: string | null;
  fileName: string | null;
  folderPath: string | null;
  threatName: string | null;
  displayTitle: string;
}

function parseEventInfo(ev: SecurityEvent): ParsedEvent {
  let filePath: string | null = null;
  if (ev.data && typeof ev.data === 'object') {
    const d = ev.data as Record<string, any>;
    if (d.path) filePath = String(d.path);
    else if (d.target_path) filePath = String(d.target_path);
    else if (d.file) filePath = String(d.file);
  }
  if (!filePath && ev.message) {
    const match = ev.message.match(/(?:File|Path):\s*([a-zA-Z]:\\[^\r\n]+)/i);
    if (match && match[1]) {
      filePath = match[1].trim();
    } else {
      const winMatch = ev.message.match(/([a-zA-Z]:\\[a-zA-Z0-9_\-\.\s\\]+\.[a-zA-Z0-9]+)/);
      if (winMatch && winMatch[1]) {
        filePath = winMatch[1].trim();
      }
    }
  }

  let fileName: string | null = null;
  let folderPath: string | null = null;
  if (filePath) {
    const clean = filePath.replace(/\\+$/, '');
    const lastSlash = clean.lastIndexOf('\\');
    if (lastSlash >= 0) {
      fileName = clean.substring(lastSlash + 1);
      folderPath = clean.substring(0, lastSlash);
    } else {
      fileName = clean;
    }
  }

  let threatName: string | null = null;
  if (ev.title) {
    const m = ev.title.match(/(?:Threat Detected|Real-Time Detection|Detection|Malware|Trojan):\s*([a-zA-Z0-9_\-\.]+)/i);
    if (m && m[1]) {
      threatName = m[1].trim();
    }
  }

  return {
    filePath,
    fileName,
    folderPath,
    threatName,
    displayTitle: ev.title,
  };
}

export function SecurityHistory() {
  const [stats, setStats] = useState<HistoryStats | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [categoryFilter, setCategoryFilter] = useState<EventCategory | 'all'>('all');
  const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all');
  const [days, setDays] = useState(7);
  const [deleteConfirm, setDeleteConfirm] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [copiedPath, setCopiedPath] = useState(false);
  const [justOpenedId, setJustOpenedId] = useState<number | null>(null);

  const fetchData = async () => {
    try {
      const st = await callAegis<HistoryStats>({ cmd: 'get_history_stats', args: { days } });
      setStats(st);

      const catArg = categoryFilter === 'all' ? null : categoryFilter;
      const sevArg = severityFilter === 'all' ? null : severityFilter;
      const evs = await callAegis<SecurityEvent[]>({
        cmd: 'list_events',
        args: { category: catArg, min_severity: sevArg, before_id: null, limit: 100 },
      });
      setEvents(evs);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchData();
  }, [days, categoryFilter, severityFilter]);

  const handleExport = async () => {
    try {
      const res = await callAegis<{ path: string }>({ cmd: 'export_report' });
      alert(`Rapor başarıyla kaydedildi: ${res.path}`);
    } catch (e: any) {
      alert(e.message || String(e));
    }
  };

  const handleDeleteOld = async () => {
    try {
      const res = await callAegis<{ deleted: number }>({
        cmd: 'delete_history',
        args: { older_than_days: 30 },
      });
      setDeleteConfirm(false);
      alert(`${res.deleted} eski kayıt temizlendi.`);
      fetchData();
    } catch (e: any) {
      alert(e.message || String(e));
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedPath(true);
    setTimeout(() => setCopiedPath(false), 2000);
  };

  const handleOpenFolder = async (pathStr: string, evId?: number) => {
    if (evId !== undefined) {
      setJustOpenedId(evId);
      setTimeout(() => setJustOpenedId(null), 2500);
    }
    await openPath(pathStr);
  };

  return (
    <div className="p-8 space-y-8 overflow-y-auto max-h-[calc(100vh-4rem)] scrollbar-thin">
      {/* Header and Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <History className="w-6 h-6 text-cyan-400" />
            <span>Güvenlik Olay Geçmişi ve İstatistikler</span>
          </h2>
          <p className="text-xs text-slate-400">
            Zaman serisi güvenlik telemetrisi, tespit edilen dosyalar ve adli inceleme kayıtları.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleExport}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white transition-all cursor-pointer shadow-lg shadow-cyan-600/20"
          >
            <Download className="w-4 h-4" />
            <span>Rapor Dışa Aktar</span>
          </button>
          <button
            onClick={() => setDeleteConfirm(true)}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold border border-rose-500/30 bg-rose-600/10 text-rose-400 hover:bg-rose-600/20 transition-all cursor-pointer"
          >
            <Trash2 className="w-4 h-4" />
            <span>Eski Kayıtları Temizle</span>
          </button>
        </div>
      </div>

      {/* Chart Section */}
      <div className="p-6 rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-md space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <BarChart3 className="w-4 h-4 text-cyan-400" />
            <span>Günlük Güvenlik Olayları Eğilimi</span>
          </h3>
          <div className="flex items-center gap-1">
            {[7, 14, 30].map((d) => (
              <button
                key={d}
                onClick={() => setDays(d)}
                className={`px-2.5 py-1 rounded text-xs font-mono font-semibold transition-all cursor-pointer ${
                  days === d
                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                    : 'text-slate-500 hover:text-slate-300'
                }`}
              >
                {d}G
              </button>
            ))}
          </div>
        </div>

        <div className="h-56 w-full pt-4">
          {stats && stats.days && stats.days.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={stats.days} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="eventGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis
                  dataKey="day"
                  stroke="#475569"
                  fontSize={10}
                  tickLine={false}
                  axisLine={false}
                />
                <YAxis
                  stroke="#475569"
                  fontSize={10}
                  tickLine={false}
                  axisLine={false}
                  allowDecimals={false}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '11px',
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="events"
                  stroke="#06b6d4"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#eventGrad)"
                  name="Güvenlik Olayları"
                />
                <Area
                  type="monotone"
                  dataKey="threats"
                  stroke="#f43f5e"
                  strokeWidth={2}
                  fillOpacity={0}
                  name="Tehditler"
                />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-full text-xs text-slate-500">
              Yeterli grafik verisi bulunamadı.
            </div>
          )}
        </div>
      </div>

      {/* Events Log Table */}
      <div className="p-6 rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-md space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h3 className="text-sm font-bold text-white">Detaylı Olay Günlüğü ({events.length})</h3>
            <p className="text-[11px] text-slate-400">
              Tespit edilen dosyaların konumunu tek tıkla Windows Gezgininde açabilirsiniz.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value as any)}
              className="px-3 py-1.5 rounded-lg text-xs bg-slate-950 border border-slate-800 text-white"
            >
              <option value="all">Tüm Kategoriler</option>
              <option value="scan">Tarama (Scan)</option>
              <option value="threat">Tehdit (Threat)</option>
              <option value="quarantine">Karantina (Quarantine)</option>
              <option value="real_time">Gerçek Zamanlı (RealTime)</option>
              <option value="behavior">Davranış (Behavior)</option>
              <option value="ransomware">Fidye (Ransomware)</option>
            </select>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value as any)}
              className="px-3 py-1.5 rounded-lg text-xs bg-slate-950 border border-slate-800 text-white"
            >
              <option value="all">Tüm Önem Dereceleri</option>
              <option value="info">Info</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>
        </div>

        <div className="overflow-x-auto max-h-[550px] overflow-y-auto scrollbar-thin rounded-xl border border-slate-800/60">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="sticky top-0 bg-slate-950 border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-400 z-10 shadow-sm">
              <tr>
                <th className="py-3 px-3">Zaman</th>
                <th className="py-3 px-3">Kategori</th>
                <th className="py-3 px-3">Önem</th>
                <th className="py-3 px-3">Bulgu / Tehdit Adı</th>
                <th className="py-3 px-3">Tespit Edilen Dosya & Konum</th>
                <th className="py-3 px-3 text-right">İşlemler</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {events.map((ev) => {
                const info = parseEventInfo(ev);
                const isJustOpened = justOpenedId === ev.id;

                return (
                  <tr
                    key={ev.id}
                    onClick={() => setSelectedEvent(ev)}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer group"
                  >
                    {/* Timestamp */}
                    <td className="py-3 px-3 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                      {new Date(ev.ts).toLocaleString()}
                    </td>

                    {/* Category */}
                    <td className="py-3 px-3 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded-md text-[10px] font-bold uppercase tracking-wider bg-slate-800/80 text-cyan-300 border border-cyan-500/20">
                        {ev.category}
                      </span>
                    </td>

                    {/* Severity */}
                    <td className="py-3 px-3 whitespace-nowrap">
                      <SeverityBadge severity={ev.severity} />
                    </td>

                    {/* Threat / Finding */}
                    <td className="py-3 px-3 whitespace-nowrap max-w-xs">
                      {info.threatName ? (
                        <div className="flex items-center gap-1.5">
                          <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-rose-500/15 text-rose-300 border border-rose-500/30">
                            {info.threatName}
                          </span>
                        </div>
                      ) : (
                        <span className="font-semibold text-white truncate block">
                          {info.displayTitle}
                        </span>
                      )}
                    </td>

                    {/* File Path & Name */}
                    <td className="py-3 px-3 max-w-md">
                      {info.filePath ? (
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-1.5 font-bold text-white text-xs">
                            <FileText className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                            <span className="truncate">{info.fileName || info.filePath}</span>
                          </div>
                          {info.folderPath && (
                            <div className="flex items-center gap-1 text-[10px] font-mono text-slate-500 truncate" title={info.filePath}>
                              <Folder className="w-3 h-3 shrink-0 text-slate-600" />
                              <span className="truncate">{info.folderPath}</span>
                            </div>
                          )}
                        </div>
                      ) : (
                        <span className="truncate block text-slate-400" title={ev.message}>
                          {ev.message}
                        </span>
                      )}
                    </td>

                    {/* Action Buttons */}
                    <td className="py-3 px-3 text-right whitespace-nowrap space-x-2">
                      {info.filePath && (
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleOpenFolder(info.filePath!, ev.id);
                          }}
                          className={`px-3 py-1.5 rounded-lg text-xs font-semibold inline-flex items-center gap-1.5 transition-all cursor-pointer shadow-sm ${
                            isJustOpened
                              ? 'bg-emerald-600/30 text-emerald-300 border border-emerald-500/50'
                              : 'bg-cyan-600/20 hover:bg-cyan-600 text-cyan-300 hover:text-white border border-cyan-500/40 hover:border-cyan-400'
                          }`}
                          title="Dosya Konumunu Windows Gezgininde Aç"
                        >
                          <FolderOpen className="w-3.5 h-3.5" />
                          <span>{isJustOpened ? 'Gezginde Açıldı ✓' : 'Konumu Aç'}</span>
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedEvent(ev);
                        }}
                        className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium inline-flex items-center gap-1 transition-all cursor-pointer border border-slate-700/60"
                      >
                        <Info className="w-3.5 h-3.5 text-slate-400" />
                        <span>Detay</span>
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Detailed Event Inspection Modal */}
      {selectedEvent && (() => {
        const info = parseEventInfo(selectedEvent);
        return (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
            <div className="w-full max-w-2xl p-6 rounded-2xl border border-slate-800 bg-slate-900 shadow-2xl space-y-4 animate-in fade-in zoom-in-95">
              <div className="flex justify-between items-start border-b border-slate-800 pb-3">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-xl bg-slate-800 border border-slate-700 text-cyan-400">
                    <ShieldAlert className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-base font-bold text-white">{selectedEvent.title}</h3>
                    <p className="text-xs text-slate-400 font-mono">
                      Kayıt ID: #{selectedEvent.id} | Zaman: {new Date(selectedEvent.ts).toLocaleString()}
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setSelectedEvent(null)}
                  className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition-colors cursor-pointer"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="space-y-3 text-xs">
                {/* Status & Category Bar */}
                <div className="grid grid-cols-3 gap-3 p-3 rounded-xl bg-slate-950 border border-slate-800">
                  <div>
                    <span className="text-slate-500 font-semibold block text-[10px] uppercase">Kategori</span>
                    <span className="font-bold text-cyan-400 capitalize">{selectedEvent.category}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 font-semibold block text-[10px] uppercase">Önem Derecesi</span>
                    <SeverityBadge severity={selectedEvent.severity} />
                  </div>
                  <div>
                    <span className="text-slate-500 font-semibold block text-[10px] uppercase">Olay Türü</span>
                    <span className="font-mono text-slate-300">{selectedEvent.kind}</span>
                  </div>
                </div>

                {/* Threat Banner if threat */}
                {info.threatName && (
                  <div className="p-3 rounded-xl bg-rose-950/30 border border-rose-500/30 flex items-center justify-between">
                    <div>
                      <span className="text-rose-400 font-bold block text-[10px] uppercase tracking-wider">
                        Tespit Edilen Zararlı Yazılım / Kural
                      </span>
                      <span className="text-sm font-mono font-bold text-rose-300">{info.threatName}</span>
                    </div>
                    <span className="px-2.5 py-1 rounded bg-rose-500/20 text-rose-300 text-xs font-bold border border-rose-500/40">
                      YARA-X Eşleşmesi
                    </span>
                  </div>
                )}

                {/* File Path with Prominent Open Location Button */}
                {info.filePath ? (
                  <div className="p-4 rounded-xl bg-slate-950 border border-cyan-500/40 space-y-3 shadow-inner">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <FileText className="w-4 h-4 text-cyan-400 shrink-0" />
                        <div>
                          <span className="text-xs font-bold text-white block">
                            {info.fileName || 'Dosya'}
                          </span>
                          <span className="text-[10px] text-slate-500 font-mono">
                            Windows Dosya Sistemi Yolu
                          </span>
                        </div>
                      </div>

                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => handleCopy(info.filePath!)}
                          className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold flex items-center gap-1 transition-all cursor-pointer"
                        >
                          <Copy className="w-3.5 h-3.5" />
                          <span>{copiedPath ? 'Kopyalandı!' : 'Yolu Kopyala'}</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => handleOpenFolder(info.filePath!)}
                          className="px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold flex items-center gap-1.5 cursor-pointer shadow-lg shadow-cyan-600/30 transition-all"
                        >
                          <FolderOpen className="w-4 h-4" />
                          <span>Dosya Konumunu Aç (Gezgin)</span>
                        </button>
                      </div>
                    </div>

                    <div className="font-mono text-xs text-cyan-300 bg-slate-900/90 p-3 rounded-lg break-all select-all border border-slate-800 leading-relaxed">
                      {info.filePath}
                    </div>
                  </div>
                ) : null}

                {/* Message / Description */}
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
                  <span className="text-slate-500 font-semibold block text-[10px] uppercase">Olay Açıklaması / Detay</span>
                  <p className="text-slate-300 font-mono text-xs leading-relaxed break-words whitespace-pre-wrap">
                    {selectedEvent.message}
                  </p>
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  onClick={() => setSelectedEvent(null)}
                  className="px-4 py-2 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-white transition-colors cursor-pointer"
                >
                  Kapat
                </button>
              </div>
            </div>
          </div>
        );
      })()}

      {/* Delete Confirmation */}
      <ConfirmDialog
        isOpen={deleteConfirm}
        title="30 Günden Eski Olayları Temizle"
        description="30 günden eski tamamlanmış tarama kayıtları ve olay günlükleri SQLite veritabanından kalıcı olarak silinecektir."
        danger={true}
        confirmText="Eski Kayıtları Temizle"
        onConfirm={handleDeleteOld}
        onCancel={() => setDeleteConfirm(false)}
      />
    </div>
  );
}