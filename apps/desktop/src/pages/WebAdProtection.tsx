import React, { useState, useEffect } from 'react';
import {
  Globe,
  ShieldCheck,
  ShieldAlert,
  Plus,
  Trash2,
  Search,
  CheckCircle2,
  AlertTriangle,
  ExternalLink,
  FolderOpen,
  Zap,
  Layers,
  Sparkles,
} from 'lucide-react';
import { callAegis, openPath, installBrowserExtension } from '../services/aegis';
import { ReputationBadge } from '../components/ui/Badge';
import type { DomainProtectionStatus, DomainCheck } from '../types/aegis';

export function WebAdProtection() {
  const [status, setDomainStatus] = useState<DomainProtectionStatus | null>(null);
  const [testDomain, setTestDomain] = useState('');
  const [checkResult, setCheckResult] = useState<DomainCheck | null>(null);
  const [newDomain, setNewDomain] = useState('');
  const [newList, setNewList] = useState<'allow' | 'block'>('block');
  const [installMsg, setInstallMsg] = useState<{ text: string; isError?: boolean } | null>(null);
  const [loadingBrowser, setLoadingBrowser] = useState<string | null>(null);
  const [guideModal, setGuideModal] = useState<{ browser: string; path?: string } | null>(null);
  const [copied, setCopied] = useState(false);

  const fetchData = async () => {
    try {
      const res = await callAegis<DomainProtectionStatus>({ cmd: 'get_domain_status' });
      setDomainStatus(res);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleInstallExtension = async (browser: string) => {
    setLoadingBrowser(browser);
    try {
      const res = await installBrowserExtension(browser);
      setInstallMsg({ text: res.message, isError: !res.success });
      if (res.success) {
        setGuideModal({ browser, path: (res as any).path });
      }
    } catch (err: any) {
      setInstallMsg({ text: err.message || 'Yükleme başlatılamadı.', isError: true });
    } finally {
      setLoadingBrowser(null);
    }
  };

  const handleOpenFolder = async () => {
    await openPath('browser-extension');
  };

  const handleCopyPath = () => {
    if (guideModal?.path) {
      navigator.clipboard.writeText(guideModal.path);
    } else {
      navigator.clipboard.writeText('browser-extension');
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleCheck = async () => {
    if (!testDomain) return;
    try {
      const res = await callAegis<DomainCheck>({ cmd: 'check_domain', args: { domain: testDomain } });
      setCheckResult(res);
    } catch (e: any) {
      alert(e.message || String(e));
    }
  };

  const handleAddRule = async () => {
    if (!newDomain) return;
    try {
      const res = await callAegis<DomainProtectionStatus>({
        cmd: 'add_domain_rule',
        args: { domain: newDomain, list: newList, note: 'Kullanıcı kuralı' },
      });
      setDomainStatus(res);
      setNewDomain('');
    } catch (e: any) {
      alert(e.message || String(e));
    }
  };

  const handleRemoveRule = async (domain: string) => {
    try {
      const res = await callAegis<DomainProtectionStatus>({
        cmd: 'remove_domain_rule',
        args: { domain },
      });
      setDomainStatus(res);
    } catch (e: any) {
      alert(e.message || String(e));
    }
  };

  return (
    <div className="p-8 space-y-8 overflow-y-auto max-h-[calc(100vh-4rem)] scrollbar-thin">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <Globe className="w-6 h-6 text-cyan-400" />
          <span>Web, Reklam & Pop-up Kalkanı</span>
        </h2>
        <p className="text-xs text-slate-400">
          Zararlı alan adı engelleme, izinsiz açılan yeni sekmeleri durdurma, AdBlock ve oltalama koruması.
        </p>
      </div>

      {/* ONE-CLICK BROWSER EXTENSION HERO CARD */}
      <div className="p-6 rounded-2xl border border-cyan-500/30 bg-gradient-to-r from-cyan-950/40 via-slate-900 to-slate-950 backdrop-blur-xl shadow-xl space-y-5 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-80 h-80 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-start gap-4">
            <div className="w-14 h-14 rounded-2xl bg-slate-900 border border-cyan-500/30 p-2 flex items-center justify-center shrink-0 shadow-lg shadow-cyan-500/10">
              <img
                src="./logo.png"
                alt="AEGIS Web Shield"
                className="w-full h-full object-contain drop-shadow-[0_0_12px_rgba(6,182,212,0.6)]"
              />
            </div>
            <div className="space-y-1">
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-base font-bold text-white">AEGIS AI Web & Ad Shield Eklentisi</h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 font-mono">
                  Manifest V3 • Sıfır Pil Tüketimi
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-500/15 text-purple-300 border border-purple-500/30 font-mono">
                  Anti-Popunder & AdBlock
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/15 text-rose-300 border border-rose-500/30 font-mono">
                  YouTube Video Reklam Kalkanı
                </span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed max-w-2xl">
                <strong className="text-rose-400">YouTube video reklamlarını</strong> ve araya giren tanıtımları anında atlar,
                sitelerde arkada gizlice açılan <strong className="text-cyan-400">tüm izinsiz sekmeleri</strong>,
                sahte "Virüs Bulaştı" uyarılarını ve rahatsız edici reklam afişlerini tarayıcınızda tek tıkla durdurur.
              </p>
            </div>
          </div>
        </div>

        {/* 1-Click Action Buttons */}
        <div className="pt-2 border-t border-slate-800/80 flex flex-wrap items-center gap-3">
          <button
            type="button"
            disabled={loadingBrowser !== null}
            onClick={() => handleInstallExtension('edge')}
            className="px-4 py-2 rounded-xl text-xs font-bold bg-cyan-600 hover:bg-cyan-500 text-white flex items-center gap-2 cursor-pointer shadow-lg shadow-cyan-600/20 transition-all hover:scale-[1.02] active:scale-[0.98]"
          >
            <Zap className="w-4 h-4 text-cyan-200" />
            <span>Microsoft Edge'de Etkinleştir</span>
          </button>

          <button
            type="button"
            disabled={loadingBrowser !== null}
            onClick={() => handleInstallExtension('brave')}
            className="px-4 py-2 rounded-xl text-xs font-bold bg-orange-600/20 hover:bg-orange-600 text-orange-300 hover:text-white border border-orange-500/30 flex items-center gap-2 cursor-pointer transition-all hover:scale-[1.02] active:scale-[0.98]"
          >
            <Sparkles className="w-4 h-4 text-orange-400" />
            <span>Brave'de Etkinleştir</span>
          </button>

          <button
            type="button"
            disabled={loadingBrowser !== null}
            onClick={() => handleInstallExtension('chrome')}
            className="px-4 py-2 rounded-xl text-xs font-bold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 flex items-center gap-2 cursor-pointer transition-all hover:scale-[1.02] active:scale-[0.98]"
          >
            <Globe className="w-4 h-4 text-cyan-400" />
            <span>Google Chrome'da Etkinleştir</span>
          </button>

          <button
            type="button"
            onClick={handleOpenFolder}
            className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 flex items-center gap-1.5 cursor-pointer transition-all ml-auto"
            title="Eklenti kaynak klasörünü Windows Gezgininde açar"
          >
            <FolderOpen className="w-4 h-4 text-cyan-400" />
            <span>Eklenti Klasörünü Aç (Sürükle-Bırak)</span>
          </button>
        </div>

        {/* Feedback Message */}
        {installMsg && (
          <div
            className={`p-3 rounded-xl text-xs font-semibold flex items-center gap-2 transition-all ${
              installMsg.isError
                ? 'bg-rose-950/40 text-rose-300 border border-rose-500/30'
                : 'bg-emerald-950/40 text-emerald-300 border border-emerald-500/30'
            }`}
          >
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            <span>{installMsg.text}</span>
          </div>
        )}
      </div>

      {/* Domain Lookup Tool */}
      <div className="p-6 rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-md space-y-4">
        <h3 className="text-sm font-bold text-white">Alan Adı İtibar ve Tehdit Sorgulama</h3>
        <div className="flex gap-2">
          <input
            type="text"
            placeholder="Alan adı yazın (örnek: test-malware.invalid veya google.com)..."
            value={testDomain}
            onChange={(e) => setTestDomain(e.target.value)}
            className="flex-1 px-3 py-2 rounded-lg text-xs bg-slate-950 border border-slate-800 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
          <button
            onClick={handleCheck}
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white transition-all cursor-pointer"
          >
            <Search className="w-4 h-4" />
            <span>Sorgula</span>
          </button>
        </div>

        {checkResult && (
          <div className="p-4 rounded-xl border border-slate-800 bg-slate-950/60 flex items-center justify-between">
            <div>
              <p className="text-xs font-mono text-cyan-400 font-semibold">{checkResult.domain}</p>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Kategori: {checkResult.category || 'Genel İnternet'} • Kaynak: {checkResult.source || 'Standart DNS'}
              </p>
            </div>
            <ReputationBadge reputation={checkResult.reputation} />
          </div>
        )}
      </div>

      {/* Active Threat Lists Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {status?.lists.map((l, idx) => (
          <div key={idx} className="p-5 rounded-2xl border border-slate-800 bg-slate-900/40">
            <div className="flex justify-between items-start">
              <h4 className="text-xs font-bold text-white">{l.name}</h4>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 text-cyan-400 border border-slate-800">
                {l.entries} Kayıt
              </span>
            </div>
            <p className="mt-2 text-[11px] text-slate-400">{l.source}</p>
            <div className="mt-4 flex items-center justify-between pt-2 border-t border-slate-800/60">
              <span className="text-[10px] text-slate-500 font-mono">Lisans: {l.license}</span>
              <span className="text-[10px] font-bold text-emerald-400">AKTİF</span>
            </div>
          </div>
        ))}
      </div>

      {/* User Custom Rules */}
      <div className="p-6 rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-md space-y-4">
        <h3 className="text-sm font-bold text-white">Özel Alan Adı Filtre Kuralları</h3>

        <div className="flex gap-2">
          <input
            type="text"
            placeholder="Engellemek veya izin vermek istediğiniz alan adı (örn: shady-popup.com)..."
            value={newDomain}
            onChange={(e) => setNewDomain(e.target.value)}
            className="flex-1 px-3 py-2 rounded-lg text-xs bg-slate-950 border border-slate-800 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
          <select
            value={newList}
            onChange={(e) => setNewList(e.target.value as any)}
            className="px-3 py-2 rounded-lg text-xs bg-slate-950 border border-slate-800 text-white"
          >
            <option value="block">Engelle (Kara Liste)</option>
            <option value="allow">İzin Ver (Beyaz Liste)</option>
          </select>
          <button
            onClick={handleAddRule}
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white transition-all cursor-pointer"
          >
            <Plus className="w-4 h-4" />
            <span>Kural Ekle</span>
          </button>
        </div>

        {status && status.user_rules.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-500">
                <tr>
                  <th className="py-2">Alan Adı</th>
                  <th className="py-2">Liste</th>
                  <th className="py-2">Not</th>
                  <th className="py-2 text-right">Eylem</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {status.user_rules.map((r, idx) => (
                  <tr key={idx} className="hover:bg-slate-900/60">
                    <td className="py-2.5 font-mono text-cyan-400">{r.domain}</td>
                    <td className="py-2.5">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          r.list === 'allow'
                            ? 'bg-emerald-500/10 text-emerald-400'
                            : 'bg-rose-500/10 text-rose-400'
                        }`}
                      >
                        {r.list}
                      </span>
                    </td>
                    <td className="py-2.5 text-slate-400">{r.note || '-'}</td>
                    <td className="py-2.5 text-right">
                      <button
                        onClick={() => handleRemoveRule(r.domain)}
                        className="p-1 rounded text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-4 text-center text-xs text-slate-500">
            Tanımlanmış herhangi bir özel kural bulunmamaktadır.
          </div>
        )}
      </div>

      {/* BRAVE / EDGE / CHROME 1-STEP VISUAL ACTIVATION MODAL */}
      {guideModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="w-full max-w-xl p-6 rounded-2xl border border-cyan-500/40 bg-slate-900 shadow-2xl space-y-5 animate-in fade-in zoom-in-95">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 p-2 flex items-center justify-center text-cyan-400">
                  <Globe className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white capitalize">
                    {guideModal.browser.toUpperCase()} Eklentisini Tamamlama
                  </h3>
                  <p className="text-xs text-cyan-400 font-mono">
                    Eklentiler sekmesi tarayıcınızda açıldı!
                  </p>
                </div>
              </div>
              <button
                onClick={() => setGuideModal(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors"
              >
                ✕
              </button>
            </div>

            <div className="space-y-4 text-xs text-slate-300">
              <div className="p-3 rounded-xl bg-cyan-950/30 border border-cyan-500/20 text-cyan-200/90 leading-relaxed text-[11px]">
                🛡️ <strong>Güvenlik Bilgisi:</strong> Chromium (Brave / Chrome / Edge), hiçbir programın tarayıcınıza gizlice eklenti enjekte edip şifrelerinizi ve çerezlerinizi çalamaması için sessiz arka plan kurulumunu kasıtlı olarak engeller. Bu nedenle yerel eklentiler için aşağıdaki <strong>2 basit adım</strong> uygulanır (yalnızca 3 saniye sürer):
              </div>

              {/* Step 1 */}
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex items-start gap-3">
                <span className="w-6 h-6 rounded-full bg-cyan-600/30 text-cyan-300 border border-cyan-500/40 font-bold flex items-center justify-center shrink-0">
                  1
                </span>
                <div>
                  <span className="font-bold text-white block">
                    Geliştirici Modunu Açın
                  </span>
                  <span className="text-slate-400 text-[11px] leading-relaxed">
                    Açılan {guideModal.browser.toUpperCase()} sayfasının sağ üst köşesindeki <strong>"Geliştirici Modu" (Developer Mode)</strong> anahtarını aktif edin.
                  </span>
                </div>
              </div>

              {/* Step 2 */}
              <div className="p-3.5 rounded-xl bg-slate-950 border border-cyan-500/30 flex items-start gap-3 shadow-inner">
                <span className="w-6 h-6 rounded-full bg-emerald-600/30 text-emerald-300 border border-emerald-500/40 font-bold flex items-center justify-center shrink-0">
                  2
                </span>
                <div>
                  <span className="font-bold text-white block">
                    Klasörü Sürükleyin veya Yükleyin
                  </span>
                  <span className="text-slate-400 text-[11px] leading-relaxed block mb-2">
                    Gezginde açılan <strong>browser-extension</strong> klasörünü doğrudan tarayıcı penceresine sürükleyip bırakın (veya sol üstteki <strong>"Paketlenmemiş Öğe Yükle"</strong> butonuna tıklayın).
                  </span>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={handleCopyPath}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-semibold transition-all cursor-pointer"
                    >
                      {copied ? 'Yol Kopyalandı ✓' : 'Klasör Yolunu Kopyala'}
                    </button>
                    <button
                      type="button"
                      onClick={handleOpenFolder}
                      className="px-2.5 py-1 rounded bg-cyan-600/20 text-cyan-400 hover:bg-cyan-600/30 border border-cyan-500/30 text-[11px] font-semibold flex items-center gap-1 transition-all cursor-pointer"
                    >
                      <FolderOpen className="w-3 h-3" />
                      <span>Klasörü Tekrar Göster</span>
                    </button>
                  </div>
                </div>
              </div>
            </div>

            <div className="flex justify-end pt-2 border-t border-slate-800">
              <button
                onClick={() => setGuideModal(null)}
                className="px-5 py-2 rounded-xl text-xs font-bold bg-cyan-600 hover:bg-cyan-500 text-white cursor-pointer shadow-lg shadow-cyan-600/20 transition-all"
              >
                Tamam, Anladım
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
